"""Hardware-health tier.

The tier is deliberately best-effort.  Every source is independent and records
``ok``, ``partial``, ``needs-root`` or ``unavailable`` instead of failing the
routine cycle.  The layer-1 systemd unit already runs the operator account with
CAP_DAC_READ_SEARCH, CAP_SYS_PTRACE, CAP_SYS_RAWIO and CAP_PERFMON; the optional
``root/install-hardware.sh`` timer grants the wider set needed by SMART/NVMe,
IPMI and uncore counters.

Nothing here runs a shell.  External commands are fixed argv with timeouts.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import time
import urllib.error
import urllib.request
from pathlib import Path
from xml.etree import ElementTree

from . import config, db, detect
from .util import iso, redact, read_text, run, utcnow

PERMISSION_HINTS = (
    "permission denied", "operation not permitted", "must be root",
    "insufficient privilege", "not permitted", "access denied",
)
CRITICAL_SEL = re.compile(
    r"(?i)\b(critical|non-recoverable|fatal|uncorrectable|failed|failure)\b"
)
WARNING_SEL = re.compile(r"(?i)\b(upper|warning|degraded|predictive failure)\b")
ERROR_LOG = re.compile(r"(?i)\b(critical|fatal|uncorrectable|failed|failure|panic)\b")
APEI_LOG = re.compile(r"(?i)\b(APEI|GHES|BERT|HEST|ERST|MCE|machine check|hardware error)\b")


def _clip(text: str, limit: int | None = None) -> str:
    limit = limit or min(config.HARDWARE_RAW_LIMIT, 20000)
    return (text or "")[:limit]


def _which(name: str) -> str | None:
    return shutil.which(name)


def _perm_error(text: str) -> bool:
    return any(hint in (text or "").lower() for hint in PERMISSION_HINTS)


def _run(args: list[str], timeout: int | None = None) -> tuple[int, str, str]:
    return run(args, timeout=timeout or config.HARDWARE_TIMEOUT_S)


def _finding(source: str, rule: str, severity: str, subject: str, detail: str) -> dict:
    ts = iso()
    return {
        "fingerprint": f"hardware|{source}|{rule}|{subject}",
        "ts": ts,
        "last_ts": ts,
        "rule": rule,
        "severity": severity,
        "subject": subject,
        "detail": redact(detail)[:1500],
        "case_id": None,
    }


def _result(status: str, items=None, findings=None, raw: str = "", reason: str = "") -> dict:
    return {
        "status": status,
        "items": items or [],
        "findings": findings or [],
        "raw": _clip(raw),
        "reason": reason[:500],
    }


def _combine(statuses: list[str]) -> str:
    if statuses and all(s == "ok" for s in statuses):
        return "ok"
    if any(s in ("ok", "partial") for s in statuses):
        return "partial"
    if any(s == "needs-root" for s in statuses):
        return "needs-root"
    return "unavailable"


def _read_int(path: Path, default: int = 0) -> int:
    try:
        return int(path.read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return default


# ---------------------------------------------------------------- parsers
def parse_aer_text(text: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for line in (text or "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[-1].isdigit():
            counts[parts[0]] = counts.get(parts[0], 0) + int(parts[-1])
    return counts


def parse_edac(root: str | Path = "/sys/devices/system/edac/mc") -> tuple[dict[str, int], list[dict]]:
    base = Path(root)
    items: dict[str, int] = {}
    findings: list[dict] = []
    total_ue = 0
    total_ce = 0
    for mc in sorted(base.glob("mc*")):
        for key in ("ce_count", "ue_count", "ce_noinfo_count", "ue_noinfo_count"):
            value = _read_int(mc / key)
            items[f"{mc.name}/{key}"] = value
            if key.startswith("ue"):
                total_ue += value
            else:
                total_ce += value
        for dimm in sorted(mc.glob("dimm*")):
            label = read_text(dimm / "dimm_label") or dimm.name
            ue = _read_int(dimm / "dimm_ue_count")
            ce = _read_int(dimm / "dimm_ce_count")
            items[f"{mc.name}/{label}/ue"] = ue
            items[f"{mc.name}/{label}/ce"] = ce
            if ue:
                findings.append(_finding(
                    "ras", "hardware.edac.dimm_ue", "critical", f"{mc.name}/{label}",
                    f"EDAC DIMM {label} uncorrected errors={ue}",
                ))
    if total_ue:
        findings.append(_finding(
            "ras", "hardware.edac.ue", "critical", "EDAC",
            f"EDAC uncorrected errors={total_ue}",
        ))
    if total_ce >= config.HARDWARE_CE_ALERT:
        findings.append(_finding(
            "ras", "hardware.edac.ce", "warning", "EDAC",
            f"EDAC corrected errors={total_ce} (threshold {config.HARDWARE_CE_ALERT})",
        ))
    return items, findings


def _celsius(value):
    try:
        number = float(str(value).split()[0])
    except (TypeError, ValueError):
        return value
    # NVMe SMART logs report Kelvin; ATA/SMART reports Celsius.
    if number > 200:
        number -= 273.15
    return round(number, 1)


def parse_smart_json(data: dict) -> dict:
    smart = data.get("smart_status") or {}
    ata = data.get("ata_smart_attributes", {}).get("table", []) or []
    attrs = {}
    for entry in ata:
        name = entry.get("name") or str(entry.get("id"))
        raw = entry.get("raw") or {}
        attrs[name] = raw.get("value", entry.get("value"))
    nvme = data.get("nvme_smart_health_information_log") or {}
    return {
        "model": data.get("model_name"),
        "smart_passed": smart.get("passed"),
        "temperature_c": _celsius(
            (data.get("temperature") or {}).get("current") or nvme.get("temperature")
        ),
        "reallocated": attrs.get("Reallocated_Sector_Ct"),
        "pending": attrs.get("Current_Pending_Sector"),
        "uncorrectable": attrs.get("Offline_Uncorrectable"),
        "media_errors": nvme.get("media_errors"),
        "percentage_used": nvme.get("percentage_used"),
        "available_spare": nvme.get("available_spare"),
        "critical_warning": nvme.get("critical_warning"),
        "num_err_log_entries": nvme.get("num_err_log_entries"),
    }


def parse_nvme_json(data: dict) -> dict:
    return {
        "critical_warning": data.get("critical_warning"),
        "temperature_c": _celsius(data.get("temperature")),
        "available_spare": data.get("available_spare"),
        "percentage_used": data.get("percentage_used"),
        "media_errors": data.get("media_errors"),
        "num_err_log_entries": data.get("num_err_log_entries"),
        "unsafe_shutdowns": data.get("unsafe_shutdowns"),
    }


def _xml_text(node, path: str):
    found = node.find(path)
    return found.text.strip() if found is not None and found.text else None


def parse_nvidia_xml(text: str) -> list[dict]:
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError:
        return []
    gpus = []
    for gpu in root.iter("gpu"):
        ecc_uncorrected = 0
        ecc_corrected = 0
        for node in gpu.iter():
            tag = node.tag.lower()
            if not node.text or not node.text.strip().isdigit():
                continue
            value = int(node.text.strip())
            if "uncorrectable" in tag or "uncorrected" in tag:
                ecc_uncorrected += value
            elif "corrected" in tag or "correctable" in tag:
                ecc_corrected += value
        throttle_tags = (
            "thermal_slowdown", "hw_slowdown", "power_brake",
            "hw_power_cap", "sw_power_cap",
        )
        throttle = any(
            (node.text or "").strip().lower() in ("active", "true", "1")
            for node in gpu.iter()
            if any(token in node.tag.lower() for token in throttle_tags)
        )
        gpus.append({
            "name": _xml_text(gpu, "product_name"),
            "temperature_c": _xml_text(gpu, "temperature/gpu_temp"),
            "utilization_pct": _xml_text(gpu, "utilization/gpu_util"),
            "memory_used": _xml_text(gpu, "fb_memory_usage/used"),
            "memory_total": _xml_text(gpu, "fb_memory_usage/total"),
            "ecc_uncorrected": ecc_uncorrected,
            "ecc_corrected": ecc_corrected,
            "retired_pages_pending": _xml_text(gpu, "retired_pages/pending"),
            "throttle_active": throttle,
            "power_draw": _xml_text(gpu, "power_readings/power_draw"),
            "power_limit": _xml_text(gpu, "power_readings/power_limit"),
        })
    return gpus


def parse_ipmi_sel(text: str) -> list[str]:
    return [line for line in (text or "").splitlines() if line.strip()]


def parse_sensors_json(data: dict) -> dict[str, float]:
    out: dict[str, float] = {}

    def walk(node, prefix=""):
        if isinstance(node, dict):
            for key, value in node.items():
                walk(value, f"{prefix}/{key}" if prefix else key)
        elif isinstance(node, (int, float)):
            out[prefix] = float(node)
        elif isinstance(node, str):
            try:
                out[prefix] = float(node)
            except ValueError:
                pass

    walk(data)
    return out


def sensor_alerts(items: dict[str, float]) -> list[dict]:
    findings = []
    for key, value in items.items():
        if not key.endswith("_input"):
            continue
        base = key[: -len("_input")]
        if "temp" not in base.lower() and "temperature" not in base.lower():
            continue
        crit = items.get(base + "_crit") or items.get(base + "_max")
        if crit is not None and value >= min(crit, config.HARDWARE_SENSOR_TEMP_ALERT_C):
            findings.append(_finding(
                "sensors", "hardware.thermal.sensor", "warning", base,
                f"sensor {base}={value:.1f} C, limit={crit:.1f} C",
            ))
    return findings


def parse_uncore_events(text: str, limit: int = 6) -> list[str]:
    events: list[str] = []
    prefixes = (
        "uncore_", "amd_iommu_", "amd_df_", "amd_l3_", "amd_umc_", "amd_ccx_",
    )
    for line in (text or "").splitlines():
        token = line.strip().split()[0] if line.strip() else ""
        if token.startswith(prefixes) and token not in events:
            events.append(token)
        if len(events) >= limit:
            break
    return events


# ---------------------------------------------------------------- adapters
def _collect_ras() -> dict:
    items = []
    findings = []
    statuses = []
    tools = _which("ras-mc-ctl")
    raw = []
    handoff = _storage_handoff() or {}
    root_ras = handoff.get("ras") if isinstance(handoff.get("ras"), dict) else {}
    if tools:
        for arg in ("--summary", "--errors"):
            cached = root_ras.get(arg) if isinstance(root_ras.get(arg), dict) else {}
            if cached:
                rc = cached.get("rc", 1)
                out = str(cached.get("out") or "")
                err = str(cached.get("error") or "")
            else:
                rc, out, err = _run([tools, arg])
            raw.append(f"# ras-mc-ctl {arg}\n{out}\n{err}".strip())
            if rc == 0:
                statuses.append("ok")
            elif _perm_error(out + err):
                statuses.append("needs-root")
            else:
                statuses.append("unavailable")
    else:
        statuses.append("unavailable")
    rc, out, _err = _run(["systemctl", "is-active", "rasdaemon"])
    items.append(("rasdaemon/active", (out or "unknown").strip()))
    if rc != 0 and not tools:
        statuses.append("unavailable")

    edac_items, edac_findings = parse_edac()
    for key, value in edac_items.items():
        items.append((f"edac/{key}", value))
    findings.extend(edac_findings)
    if edac_items:
        statuses.append("ok")

    aer_values: dict[str, int] = {}
    for device in sorted(Path("/sys/bus/pci/devices").glob("*")):
        for name in ("aer_dev_correctable", "aer_dev_nonfatal", "aer_dev_fatal"):
            path = device / name
            if not path.exists():
                continue
            try:
                counts = parse_aer_text(path.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue
            for key, value in counts.items():
                aer_values[f"{device.name}/{name}/{key}"] = value
    for key, value in aer_values.items():
        items.append((f"aer/{key}", value))
    aer_fatal = sum(v for k, v in aer_values.items() if "fatal" in k.lower() and "nonfatal" not in k.lower())
    aer_nonfatal = sum(v for k, v in aer_values.items() if "nonfatal" in k.lower())
    aer_ce = sum(v for k, v in aer_values.items() if "correctable" in k.lower())
    if aer_fatal:
        findings.append(_finding("ras", "hardware.aer.fatal", "critical", "AER",
                                 f"PCIe AER fatal errors={aer_fatal}"))
    if aer_nonfatal:
        findings.append(_finding("ras", "hardware.aer.nonfatal", "critical", "AER",
                                 f"PCIe AER non-fatal errors={aer_nonfatal}"))
    if aer_ce >= config.HARDWARE_AER_CE_ALERT:
        findings.append(_finding("ras", "hardware.aer.correctable", "warning", "AER",
                                 f"PCIe AER correctable errors={aer_ce}"))
    if aer_values:
        statuses.append("ok")

    tables = Path("/sys/firmware/acpi/tables")
    if tables.is_dir():
        for table in sorted(tables.iterdir()):
            if not table.is_file():
                continue
            try:
                data = table.read_bytes()[:4096]
                digest = hashlib.sha256(data).hexdigest()[:16]
                items.append((f"apei/table/{table.name}", f"sha256:{digest} size={table.stat().st_size}"))
            except OSError:
                continue
        statuses.append("ok")

    pstore = config.PSTORE_EXPORT_DIR
    if pstore.is_dir():
        summaries = sorted(pstore.glob("*/summary.txt"))
        if summaries:
            latest = read_text(summaries[-1])
            items.append(("pstore/summary", _clip(latest, 4000)))
            if ERROR_LOG.search(latest):
                findings.append(_finding(
                    "ras", "hardware.apei.pstore", "warning", "pstore",
                    f"pstore summary contains an error signature: {latest[:300]}",
                ))
            statuses.append("ok")

    rc, out, _err = _run(
        ["journalctl", "-k", "--since", "6 hours ago", "--no-pager"],
        timeout=max(10, config.HARDWARE_TIMEOUT_S),
    )
    if rc == 0:
        lines = [line for line in out.splitlines() if APEI_LOG.search(line)]
        if lines:
            items.append(("apei/journal", _clip("\n".join(lines[-20:]), 8000)))
            if any(ERROR_LOG.search(line) for line in lines):
                findings.append(_finding(
                    "ras", "hardware.apei.journal", "warning", "journal",
                    "APEI/GHES/MCE journal contains an error signature: " + lines[-1][:300],
                ))
            statuses.append("ok")

    return _result(_combine(statuses), items, findings, "\n".join(raw))


def _storage_status(device: str) -> bool:
    return device.startswith(("sd", "nvme", "vd", "xvd"))


def _storage_add(device: str, metrics: dict, prefix: str,
                 items: list, findings: list) -> None:
    for key, value in metrics.items():
        if value is not None:
            items.append((f"{prefix}/{device}/{key}", value))
    if metrics.get("smart_passed") is False:
        findings.append(_finding("storage", "hardware.storage.smart", "critical",
                                 device, f"{device}: SMART overall health FAILED"))
    temp = metrics.get("temperature_c")
    try:
        temp_value = int(str(temp).split()[0])
    except (ValueError, TypeError):
        temp_value = None
    if temp_value is not None and temp_value >= config.HARDWARE_STORAGE_TEMP_ALERT_C:
        findings.append(_finding("storage", "hardware.storage.temperature", "warning",
                                 device, f"{device}: temperature={temp_value} C"))
    media = metrics.get("media_errors")
    if isinstance(media, int) and media > 0:
        findings.append(_finding("storage", "hardware.storage.media", "critical",
                                 device, f"{device}: media errors={media}"))
    used = metrics.get("percentage_used")
    if isinstance(used, int) and used >= config.HARDWARE_NVME_USED_ALERT:
        findings.append(_finding("storage", "hardware.storage.wear", "warning",
                                 device, f"{device}: percentage_used={used}%"))
    spare = metrics.get("available_spare")
    if isinstance(spare, int) and spare < config.HARDWARE_NVME_SPARE_ALERT:
        findings.append(_finding("storage", "hardware.storage.spare", "warning",
                                 device, f"{device}: available_spare={spare}%"))
    if metrics.get("critical_warning") not in (None, 0, "0"):
        findings.append(_finding("storage", "hardware.storage.critical_warning",
                                 "critical", device,
                                 f"{device}: critical_warning={metrics['critical_warning']}"))
    for key, rule, severity in (
        ("reallocated", "hardware.storage.reallocated", "warning"),
        ("pending", "hardware.storage.pending", "warning"),
        ("uncorrectable", "hardware.storage.uncorrectable", "critical"),
    ):
        value = metrics.get(key)
        if isinstance(value, int) and value > 0:
            findings.append(_finding("storage", rule, severity, device,
                                     f"{device}: {key}={value}"))


def _storage_handoff() -> dict | None:
    path = config.HARDWARE_STORAGE_HANDOFF
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        from .util import parse_iso
        age = (utcnow() - parse_iso(data.get("generated"))).total_seconds()
    except (OSError, ValueError, TypeError):
        return None
    if age > config.HARDWARE_STORAGE_HANDOFF_MAX_AGE_S:
        return None
    if not isinstance(data.get("devices"), dict):
        return None
    return data


def _collect_storage() -> dict:
    handoff = _storage_handoff()
    items = []
    findings = []
    statuses = []
    raw = []
    if handoff:
        for device, entry in sorted(handoff["devices"].items()):
            for key, parser in (("smartctl", parse_smart_json), ("nvme", parse_nvme_json)):
                payload = entry.get(key)
                if payload is None:
                    continue
                if not isinstance(payload, dict):
                    statuses.append("unavailable")
                    continue
                err = str(payload.get("error") or payload.get("stderr") or "")
                messages = " ".join(
                    str(item.get("string") or "")
                    for item in (payload.get("smartctl") or {}).get("messages", [])
                )
                metrics = parser(payload)
                if not any(value is not None for value in metrics.values()):
                    # No SMART attributes is normal for USB bridges and card
                    # readers.  Permission failures remain visible; genuinely
                    # unsupported devices must not fail the required source.
                    if _perm_error(err + messages):
                        statuses.append("needs-root")
                    continue
                if _perm_error(messages):
                    statuses.append("needs-root")
                    continue
                _storage_add(device, metrics, key, items, findings)
                statuses.append(
                    "ok" if payload.get("rc") in (0, None) else "partial"
                )
        if statuses:
            return _result(_combine(statuses), items, findings, json.dumps(handoff)[:20000])

    devices = []
    for path in sorted(Path("/sys/block").iterdir()):
        if _storage_status(path.name):
            devices.append(path.name)
    devices = devices[:8]
    smartctl = _which("smartctl")
    nvme = _which("nvme")
    for device in devices:
        if smartctl:
            rc, out, err = _run([smartctl, "-a", "-j", f"/dev/{device}"])
            raw.append(f"# smartctl {device}\n{out}\n{err}".strip())
            try:
                data = json.loads(out) if out.strip().startswith("{") else None
            except ValueError:
                data = None
            if data:
                messages = " ".join(
                    str(item.get("string") or "")
                    for item in (data.get("smartctl") or {}).get("messages", [])
                )
                if _perm_error(messages):
                    statuses.append("needs-root")
                    continue
                _storage_add(device, parse_smart_json(data), "storage", items, findings)
                statuses.append("ok")
            elif rc == 0:
                statuses.append("partial")
            elif _perm_error(out + err):
                statuses.append("needs-root")
            else:
                statuses.append("unavailable")
        if nvme and device.startswith("nvme"):
            rc, out, err = _run([nvme, "smart-log", f"/dev/{device}", "-o", "json"])
            raw.append(f"# nvme smart-log {device}\n{out}\n{err}".strip())
            try:
                data = json.loads(out) if out.strip().startswith("{") else None
            except ValueError:
                data = None
            if data:
                _storage_add(device, parse_nvme_json(data), "nvme", items, findings)
                statuses.append("ok")
            elif rc == 0:
                statuses.append("partial")
            elif _perm_error(out + err):
                statuses.append("needs-root")
            else:
                statuses.append("unavailable")
    if not devices:
        statuses.append("unavailable")
    return _result(_combine(statuses), items, findings, "\n".join(raw))


def _collect_gpu() -> dict:
    smi = _which("nvidia-smi")
    if not smi:
        return _result("unavailable", reason="nvidia-smi not installed")
    rc, out, err = _run([smi, "-q", "-x"], timeout=max(10, config.HARDWARE_TIMEOUT_S))
    if rc != 0:
        status = "needs-root" if _perm_error(out + err) else "unavailable"
        return _result(status, reason=(out + err)[:300])
    gpus = parse_nvidia_xml(out)
    items = []
    findings = []
    for index, gpu in enumerate(gpus):
        subject = gpu.get("name") or f"gpu{index}"
        for key, value in gpu.items():
            if value is not None:
                items.append((f"gpu/{index}/{key}", value))
        uncorrected = gpu.get("ecc_uncorrected") or 0
        if uncorrected:
            findings.append(_finding("gpu", "hardware.gpu.ecc_uncorrected", "critical",
                                     subject, f"{subject}: uncorrected ECC={uncorrected}"))
        retired = str(gpu.get("retired_pages_pending") or "0")
        if retired not in ("0", "N/A", "None"):
            findings.append(_finding("gpu", "hardware.gpu.retired_pages", "critical",
                                     subject, f"{subject}: retired pages pending={retired}"))
        temp = gpu.get("temperature_c")
        try:
            temp_value = int(str(temp).split()[0])
        except (ValueError, TypeError):
            temp_value = None
        if temp_value is not None and temp_value >= config.HARDWARE_GPU_TEMP_ALERT_C:
            findings.append(_finding("gpu", "hardware.gpu.temperature", "warning",
                                     subject, f"{subject}: GPU temperature={temp_value} C"))
        if gpu.get("throttle_active"):
            findings.append(_finding("gpu", "hardware.gpu.throttle", "warning",
                                     subject, f"{subject}: GPU throttle active"))
    return _result("ok" if gpus else "unavailable", items, findings, out)


def _load_sources() -> dict:
    path = config.HARDWARE_SOURCES_PATH
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def required_sources() -> tuple[str, ...]:
    """Return the per-host required-source contract.

    An explicit environment override wins.  Otherwise the host's scoped
    contract in hardware-sources.json is authoritative, so platforms without
    IPMI or Intel PCM can record why those sources are not applicable instead
    of failing forever on hardware they do not have.
    """
    override = os.environ.get("QA_HARDWARE_REQUIRED_SOURCES")
    if override is not None:
        scoped = tuple(item.strip() for item in override.split(",") if item.strip())
        if scoped:
            return scoped if "vendor" in scoped else scoped + ("vendor",)
    configured = _load_sources().get("required_sources")
    if isinstance(configured, list):
        scoped = tuple(str(item).strip() for item in configured if str(item).strip())
        if scoped:
            # Vendor identity is mandatory and cannot be scoped away.
            return scoped if "vendor" in scoped else scoped + ("vendor",)
    return tuple(config.HARDWARE_REQUIRED_SOURCES)


def _redfish_sel() -> dict:
    cfg = (_load_sources().get("redfish") or {})
    if not cfg.get("enabled"):
        return _result("unavailable", reason="Redfish disabled")
    url = (cfg.get("base_url") or "").rstrip("/")
    token_env = cfg.get("token_env") or "QA_REDFISH_TOKEN"
    token = os.environ.get(token_env)
    if not url or not token:
        return _result("unavailable", reason="Redfish URL/token not configured")
    endpoint = url + "/redfish/v1/Systems/1/LogServices/SEL/Entries"
    request = urllib.request.Request(endpoint, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    })
    try:
        with urllib.request.urlopen(request, timeout=config.HARDWARE_TIMEOUT_S) as response:
            data = json.loads(response.read().decode("utf-8", "replace"))
    except (OSError, ValueError, urllib.error.URLError) as exc:
        return _result("unavailable", reason=f"Redfish read failed: {exc}")
    members = data.get("Members") or []
    items = []
    findings = []
    for index, entry in enumerate(members[:50]):
        severity = str(entry.get("Severity") or entry.get("severity") or "")
        message = str(entry.get("Message") or entry.get("Name") or "")
        items.append((f"bmc/redfish/{index}", f"{severity}: {message}"))
        if severity.lower() in ("critical", "warning"):
            findings.append(_finding(
                "bmc", "hardware.bmc.sel", "critical" if severity.lower() == "critical" else "warning",
                f"redfish/{index}", f"Redfish SEL {severity}: {message}",
            ))
    return _result("ok", items, findings, json.dumps(data)[:20000])


def _collect_bmc() -> dict:
    ipmi = _which("ipmitool")
    redfish = _redfish_sel()
    if not ipmi:
        return redfish
    rc, out, err = _run([ipmi, "sel", "elist"])
    if rc != 0:
        if _perm_error(out + err):
            return _result("needs-root", reason=(out + err)[:300])
        return redfish if redfish["status"] == "ok" else _result("unavailable", reason=(out + err)[:300])
    lines = parse_ipmi_sel(out)
    items = [(f"bmc/ipmi/{index}", line) for index, line in enumerate(lines[-50:])]
    findings = []
    for line in lines:
        if CRITICAL_SEL.search(line):
            findings.append(_finding("bmc", "hardware.bmc.sel", "critical", "ipmi",
                                     line[:500]))
        elif WARNING_SEL.search(line):
            findings.append(_finding("bmc", "hardware.bmc.sel", "warning", "ipmi",
                                     line[:500]))
    return _result("ok", items, findings, out)


def _collect_sensors() -> dict:
    sensors = _which("sensors")
    if not sensors:
        return _result("unavailable", reason="lm-sensors not installed")
    rc, out, err = _run([sensors, "-j"])
    if rc != 0:
        status = "needs-root" if _perm_error(out + err) else "unavailable"
        return _result(status, reason=(out + err)[:300])
    try:
        data = json.loads(out)
    except ValueError:
        return _result("unavailable", reason="sensors returned non-JSON")
    values = parse_sensors_json(data)
    items = [(f"sensors/{key}", value) for key, value in list(values.items())[:300]]
    return _result("ok", items, sensor_alerts(values), out)


def _collect_turbostat() -> dict:
    handoff = _storage_handoff()
    if handoff and isinstance(handoff.get("turbostat"), dict):
        result = handoff["turbostat"]
        out = str(result.get("out") or "")
        err = str(result.get("error") or "")
        if result.get("rc") == 0 and out:
            return _result(
                "ok", [("turbostat/summary", _clip(out, 8000))], raw=out
            )
        status = "needs-root" if _perm_error(out + err) else "unavailable"
        return _result(status, reason=(out + err)[:300])
    exe = _which("turbostat")
    if not exe:
        return _result("unavailable", reason="turbostat not installed")
    rc, out, err = _run([exe, "--Summary", "--quiet", "--interval", "1", "--num_iterations", "1"])
    if rc != 0:
        rc, out, err = _run([exe, "-S", "-q", "-i", "1", "-n", "1"])
    if rc != 0:
        status = "needs-root" if _perm_error(out + err) else "unavailable"
        return _result(status, reason=(out + err)[:300])
    return _result("ok", [("turbostat/summary", _clip(out, 8000))], raw=out)


def _collect_pcm() -> dict:
    exe = _which("pcm") or _which("pcm.x")
    if not exe:
        return _result("unavailable", reason="Intel PCM not installed")
    rc, out, err = _run([exe, "1"], timeout=max(10, config.HARDWARE_TIMEOUT_S))
    if rc != 0:
        status = "needs-root" if _perm_error(out + err) else "unavailable"
        return _result(status, reason=(out + err)[:300])
    return _result("ok", [("pcm/summary", _clip(out, 8000))], raw=out)


def _collect_uncore() -> dict:
    perf = _which("perf")
    if not perf:
        return _result("unavailable", reason="perf not installed")
    rc, out, err = _run([perf, "list"], timeout=max(10, config.HARDWARE_TIMEOUT_S))
    if rc != 0:
        status = "needs-root" if _perm_error(out + err) else "unavailable"
        return _result(status, reason=(out + err)[:300])
    events = parse_uncore_events(out)
    if not events:
        return _result("unavailable", reason="no uncore PMU events exposed")
    args = [perf, "stat", "-a"]
    for event in events:
        args += ["-e", event]
    args += ["--", "sleep", "1"]
    rc, out, err = _run(args)
    if rc != 0:
        status = "needs-root" if _perm_error(out + err) else "unavailable"
        return _result(status, reason=(out + err)[:300])
    return _result("ok", [("uncore/events", ",".join(events)),
                          ("uncore/stat", _clip(out, 8000))], raw=out)


def _collect_vendor() -> dict:
    cfg = _load_sources()
    paths = cfg.get("vendor_logs") or []
    if not isinstance(paths, list):
        return _result("unavailable", reason="vendor_logs is not a list")
    items = []
    findings = []
    statuses = []
    for raw_path in paths:
        path = Path(str(raw_path))
        if not path.is_file():
            statuses.append("unavailable")
            continue
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            statuses.append("needs-root")
            continue
        tail = "\n".join(lines[-config.HARDWARE_VENDOR_LINES:])
        items.append((f"vendor/{path}", _clip(tail, 8000)))
        statuses.append("ok")
        if ERROR_LOG.search(tail):
            findings.append(_finding(
                "vendor", "hardware.vendor.log", "warning", str(path),
                f"{path}: firmware/BMC log contains an error signature",
            ))
    return _result(_combine(statuses), items, findings)



def _dmi_info() -> dict:
    fields = (
        "sys_vendor", "product_name", "product_version", "board_vendor",
        "board_name", "board_version", "bios_vendor", "bios_version",
        "bios_date", "chassis_vendor", "chassis_type",
    )
    out = {}
    for field in fields:
        value = read_text(Path("/sys/class/dmi/id") / field)
        if value:
            out[field] = value
    return out


def _gpu_info() -> list[dict]:
    smi = _which("nvidia-smi")
    if smi:
        rc, out, _err = _run(
            [smi, "--query-gpu=name,driver_version", "--format=csv,noheader"]
        )
        if rc == 0:
            return [
                {"name": line.split(",", 1)[0].strip(),
                 "driver": line.split(",", 1)[1].strip() if "," in line else ""}
                for line in out.splitlines() if line.strip()
            ]
    rc, out, _err = _run(["lspci", "-nn"])
    if rc == 0:
        return [{"pci": line.strip()} for line in out.splitlines()
                if re.search(r"VGA|3D|Display", line, re.I)]
    return []


def _storage_info() -> list[dict]:
    out = []
    for dev in sorted(Path("/sys/block").iterdir()):
        if not dev.name.startswith(("sd", "nvme", "vd", "xvd")):
            continue
        out.append({
            "device": dev.name,
            "vendor": read_text(dev / "device" / "vendor"),
            "model": read_text(dev / "device" / "model"),
            "firmware": read_text(dev / "device" / "firmware_rev")
            or read_text(dev / "device" / "rev"),
        })
    return out


def _bmc_info() -> dict:
    ipmi = _which("ipmitool")
    if not ipmi:
        return {"available": False, "reason": "ipmitool not installed"}
    rc, out, err = _run([ipmi, "mc", "info"])
    if rc != 0:
        return {"available": False, "reason": _clip((out + err)[:500])}
    info = {}
    for line in out.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            info[key.strip()] = value.strip()
    return {"available": True, **info}


def _vendor_log_candidates() -> list[str]:
    candidates = []
    for path in (
        Path("/var/log/fwupd.log"),
        Path("/var/log/vendor-firmware.log"),
        Path("/var/log/firmware.log"),
        Path("/var/log/ipmi.log"),
        Path("/var/log/rasdaemon.log"),
    ):
        candidates.append(path)
    for directory in (Path("/var/log/fwupd"), Path("/var/log")):
        if directory.is_dir():
            candidates.extend(sorted(directory.glob("*.log"))[:200])
    selected = []
    seen = set()
    for path in candidates:
        name = path.name.lower()
        if not any(token in name for token in (
            "vendor", "firmware", "bios", "bmc", "ipmi", "redfish",
            "fwupd", "rasdaemon", "mcelog",
        )):
            continue
        try:
            if path.is_file() and os.access(path, os.R_OK):
                resolved = str(path.resolve())
                if resolved not in seen:
                    seen.add(resolved)
                    selected.append(resolved)
        except OSError:
            continue
    return selected


def discover_vendor() -> dict:
    """Fetch platform vendor identity and seed config/hardware-sources.json."""
    existing = _load_sources()
    dmi = _dmi_info()
    cpu = ""
    cpu_vendor = ""
    for line in read_text("/proc/cpuinfo").splitlines():
        lowered = line.lower()
        if lowered.startswith("model name") and not cpu:
            cpu = line.split(":", 1)[1].strip()
        elif lowered.startswith("vendor_id") and not cpu_vendor:
            cpu_vendor = line.split(":", 1)[1].strip()
    bmc = _bmc_info()
    inventory = {
        "generated": iso(),
        "generator": "qa hardware discover-vendor",
        "host": read_text("/proc/sys/kernel/hostname"),
        "kernel": read_text("/proc/sys/kernel/osrelease"),
        "dmi": dmi,
        "cpu": cpu,
        "cpu_vendor": cpu_vendor,
        "gpu": _gpu_info(),
        "storage": _storage_info(),
        "bmc": bmc,
    }
    inventory_path = config.VAR / "vendor-inventory.json"
    inventory_path.parent.mkdir(parents=True, exist_ok=True)
    inventory_path.write_text(json.dumps(inventory, indent=2, sort_keys=True) + "\n")
    os.chmod(inventory_path, 0o600)

    logs = list(existing.get("vendor_logs") or [])
    for path in _vendor_log_candidates():
        if path not in logs:
            logs.append(path)
    if str(inventory_path) not in logs:
        logs.append(str(inventory_path))
    data = dict(existing)
    data["vendor"] = {
        "sys_vendor": dmi.get("sys_vendor", ""),
        "product_name": dmi.get("product_name", ""),
        "board_vendor": dmi.get("board_vendor", ""),
        "board_name": dmi.get("board_name", ""),
        "bios_vendor": dmi.get("bios_vendor", ""),
        "bios_version": dmi.get("bios_version", ""),
        "bios_date": dmi.get("bios_date", ""),
    }
    data["vendor_logs"] = logs
    data["detected_at"] = iso()
    redfish = data.setdefault("redfish", {
        "enabled": False, "base_url": "", "token_env": "QA_REDFISH_TOKEN",
    })
    not_applicable = {}
    if "intel" not in cpu_vendor.lower():
        not_applicable["pcm"] = (
            f"Intel PCM is not applicable to CPU vendor {cpu_vendor or 'unknown'}"
        )
    if not (bmc.get("available") or (redfish or {}).get("enabled")):
        not_applicable["bmc"] = (
            "no IPMI/BMC or configured Redfish endpoint was detected"
        )
    all_sources = (
        "ras", "storage", "gpu", "bmc", "sensors",
        "turbostat", "pcm", "uncore", "vendor",
    )
    data["required_sources"] = [
        source for source in all_sources if source not in not_applicable
    ]
    data["not_applicable"] = not_applicable
    config.HARDWARE_SOURCES_PATH.parent.mkdir(parents=True, exist_ok=True)
    config.HARDWARE_SOURCES_PATH.write_text(
        json.dumps(data, indent=2, sort_keys=True) + "\n"
    )
    os.chmod(config.HARDWARE_SOURCES_PATH, 0o600)
    return {
        "config": str(config.HARDWARE_SOURCES_PATH),
        "inventory": str(inventory_path),
        "vendor": data["vendor"],
        "vendor_logs": logs,
        "required_sources": data["required_sources"],
        "not_applicable": not_applicable,
    }


ADAPTERS = (
    ("ras", _collect_ras),
    ("storage", _collect_storage),
    ("gpu", _collect_gpu),
    ("bmc", _collect_bmc),
    ("sensors", _collect_sensors),
    ("turbostat", _collect_turbostat),
    ("pcm", _collect_pcm),
    ("uncore", _collect_uncore),
    ("vendor", _collect_vendor),
)
KEY_SOURCES = {"ras", "storage", "gpu", "bmc", "sensors"}


def is_due(conn) -> bool:
    last = db.meta_get(conn, "last_hardware_ts")
    if not config.HARDWARE_ENABLE:
        return False
    if not last:
        return True
    try:
        from .util import parse_iso
        return (utcnow() - parse_iso(last)).total_seconds() >= config.HARDWARE_INTERVAL_S
    except ValueError:
        return True


def _ensure_vendor_config() -> None:
    """Seed vendor identity/log sources once, while keeping the source mandatory."""
    cfg = _load_sources()
    if cfg.get("vendor_logs") and cfg.get("required_sources"):
        return
    try:
        discover_vendor()
    except (OSError, ValueError):
        # check()/collect() still fail closed when discovery cannot produce a
        # readable vendor source.
        return


def collect(conn, sources: set[str] | None = None) -> dict:
    _ensure_vendor_config()
    started = time.monotonic()
    chosen = [(name, fn) for name, fn in ADAPTERS if not sources or name in sources]
    statuses: dict[str, str] = {}
    items: list[tuple[str, str, object]] = []
    findings: list[dict] = []
    raws: list[str] = []
    for name, fn in chosen:
        try:
            result = fn()
        except Exception as exc:  # noqa: BLE001
            result = _result("unavailable", reason=f"{type(exc).__name__}: {exc}")
        statuses[name] = result["status"]
        for key, value in result["items"]:
            items.append((name, str(key), value))
        findings.extend(result["findings"])
        if result.get("raw"):
            raws.append(f"# {name}\n{result['raw']}")

    required = set(sources) if sources else set(required_sources())
    failed_sources = sorted(
        name for name in required
        if statuses.get(name) != "ok"
    )

    missing = sorted(
        name for name, status in statuses.items()
        if name in required and name in KEY_SOURCES
        and status in ("needs-root", "unavailable")
    )
    if "vendor" in failed_sources:
        findings.append(_finding(
            "vendor", "hardware.vendor.missing", "critical", "vendor",
            "vendor source is mandatory; configure config/hardware-sources.json "
            "with at least one readable vendor_logs entry before the cycle can pass",
        ))
    else:
        conn.execute(
            "UPDATE findings SET status='resolved' "
            "WHERE rule='hardware.vendor.missing' AND status='open'"
        )

    if missing:
        findings.append(_finding(
            "coverage", "hardware.coverage", "warning", "hardware-sources",
            "hardware sources limited: " + ", ".join(
                f"{name}={statuses[name]}" for name in missing
            ),
        ))
    else:
        conn.execute(
            "UPDATE findings SET status='resolved' "
            "WHERE rule='hardware.coverage' AND status='open'"
        )

    overall = _combine([statuses[name] for name in required if name in statuses])
    duration_ms = int((time.monotonic() - started) * 1000)
    cur = conn.execute(
        "INSERT INTO hardware_runs(ts,status,sources,duration_ms,detail) VALUES(?,?,?,?,?)",
        (iso(), overall, json.dumps(statuses, sort_keys=True), duration_ms,
         _clip("\n".join(raws), config.HARDWARE_RAW_LIMIT)),
    )
    run_id = cur.lastrowid
    conn.executemany(
        "INSERT OR REPLACE INTO hardware_items(run_id,source,item,value) VALUES(?,?,?,?)",
        [(run_id, source, item, _clip(str(value), 8000))
         for source, item, value in items],
    )
    new = []
    for finding in findings:
        created = detect.upsert(conn, finding)
        if created:
            new.append(created)
    if not sources:
        db.meta_set(conn, "last_hardware_ts", iso())
    counts: dict[str, int] = {}
    for finding in new:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    return {
        "run_id": run_id,
        "status": overall,
        "failed": bool(failed_sources),
        "failed_sources": failed_sources,
        "sources": statuses,
        "items": len(items),
        "duration_ms": duration_ms,
        "new": len(new),
        "by_severity": counts,
        "findings": new,
    }


def latest(conn, complete: bool = False) -> dict:
    if complete:
        run = conn.execute(
            "SELECT * FROM hardware_runs ORDER BY LENGTH(sources) DESC, id DESC LIMIT 1"
        ).fetchone()
    else:
        run = conn.execute("SELECT * FROM hardware_runs ORDER BY id DESC LIMIT 1").fetchone()
    if not run:
        return {}
    items = [
        dict(row) for row in conn.execute(
            "SELECT source,item,value FROM hardware_items WHERE run_id=? ORDER BY source,item",
            (run["id"],),
        )
    ]
    return {"run": dict(run), "items": items}


def check() -> dict:
    _ensure_vendor_config()
    cap_eff = ""
    try:
        for line in Path("/proc/self/status").read_text(encoding="ascii").splitlines():
            if line.startswith("CapEff:"):
                cap_eff = line.split(":", 1)[1].strip()
                break
    except OSError:
        pass
    tools = {}
    for name in ("ras-mc-ctl", "smartctl", "nvme", "nvidia-smi", "ipmitool",
                 "sensors", "turbostat", "pcm", "pcm.x", "perf"):
        tools[name] = shutil.which(name)
    missing = sorted(name for name, path in tools.items() if not path)
    sources_config = _load_sources()
    required = required_sources()
    tool_sources = {
        "ras": ("ras-mc-ctl",),
        "storage": ("smartctl", "nvme"),
        "gpu": ("nvidia-smi",),
        "bmc": ("ipmitool",),
        "sensors": ("sensors",),
        "turbostat": ("turbostat",),
        "pcm": ("pcm", "pcm.x"),
        "uncore": ("perf",),
        "vendor": (),
    }
    failed_sources = []
    missing_required_tools = []
    for source in required:
        missing_for_source = [
            tool for tool in tool_sources.get(source, ()) if not tools.get(tool)
        ]
        if missing_for_source:
            failed_sources.append(source)
            missing_required_tools.extend(missing_for_source)
    missing_required_tools = sorted(set(missing_required_tools))
    vendor_logs = sources_config.get("vendor_logs") or []
    vendor_configured = bool(vendor_logs)
    if "vendor" in required and not vendor_configured:
        failed_sources.append("vendor")
    return {
        "euid": os.geteuid(),
        "cap_eff": cap_eff,
        "tools": tools,
        "missing_tools": missing_required_tools,
        "missing_tools_all": missing,
        "missing_required_tools": missing_required_tools,
        "missing_sources": sorted(set(failed_sources)),
        "required_sources": list(required),
        "not_applicable": sources_config.get("not_applicable") or {},
        "redfish_configured": bool((sources_config.get("redfish") or {}).get("enabled")),
        "vendor_configured": vendor_configured,
        "vendor_logs": vendor_logs,
        "notes": {
            "needs-root": "run as the capability-scoped hardware service or with sudo",
            "needs-CAP_PERFMON": "uncore/perf counters require CAP_PERFMON",
            "needs-CAP_SYS_RAWIO": "SMART/NVMe raw device access requires CAP_SYS_RAWIO",
        },
    }
