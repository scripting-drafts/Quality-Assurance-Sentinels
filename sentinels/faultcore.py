"""Fault-core topology and isolation state.

The monitored core is the logical CPU set configured by faultlab
(``FAULT_CPUS``) or ``QA_FAULT_CORE_CPUS``.  A retired core is identified by
that CPU set, not by a hard-coded physical core number: sysfs stops exposing
the physical core id while its CPUs are offline.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import config, db
from .util import iso, read_text, redact, sha256_text


def _read_cpu_topology(root: Path) -> tuple[
    dict[int, tuple[str, str]], dict[int, set[int]], set[int], dict[int, str],
    set[tuple[str, str]],
]:
    records: dict[int, tuple[str, str]] = {}
    siblings: dict[int, set[int]] = {}
    present: set[int] = set()
    online: dict[int, str] = {}
    physical: set[tuple[str, str]] = set()
    for cpu in sorted(root.glob("cpu[0-9]*")):
        try:
            number = int(cpu.name[3:])
        except ValueError:
            continue
        present.add(number)
        online[number] = read_text(cpu / "online").strip()
        thread_list = parse_cpu_list(
            read_text(cpu / "topology" / "thread_siblings_list")
        )
        if thread_list:
            siblings[number] = thread_list
        core_id = read_text(cpu / "topology" / "core_id").strip()
        if not core_id:
            continue
        package_id = read_text(cpu / "topology" / "physical_package_id").strip()
        records[number] = (package_id, core_id)
        physical.add((package_id, core_id))
    return records, siblings, present, online, physical


def _siblings(number: int, siblings: dict[int, set[int]]) -> set[int]:
    """Sibling threads, using any readable CPU when the CPU is offline."""
    if siblings.get(number):
        return siblings[number]
    for cpus in siblings.values():
        if number in cpus:
            return cpus
    return {number}


def _mode(mode_path: str | Path | None = None) -> tuple[str, str]:
    """Return the effective faultlab mode and the mode written on disk."""
    configured = read_text(mode_path or config.FAULT_CORE_MODE_FILE).strip().lower()
    enforce = (config.FAULT_CORE_ENFORCE or "auto").lower()
    if enforce in ("lab", "retired", "off"):
        return enforce, configured
    return (configured if configured in ("lab", "retired") else ""), configured


def _physical_id(value: str) -> int | str:
    try:
        return int(value)
    except (TypeError, ValueError):
        return value


def topology(cpu_root: str | Path = "/sys/devices/system/cpu",
             cpus: tuple[int, ...] | list[int] | None = None,
             mode_path: str | Path | None = None) -> dict:
    """Capture the configured fault core without assuming its physical id.

    ``present`` is True only when sysfs proves the mapping.  A core whose CPUs
    are offline and whose topology directory is gone is ``retired`` or
    ``offline`` with ``present=None``; an optional configured physical id is
    only used to validate or label a mapping, never to guess one.
    """
    root = Path(cpu_root)
    configured = tuple(sorted(set(
        config.FAULT_CORE_CPUS if cpus is None else cpus
    )))
    records, siblings, present, online, physical = _read_cpu_topology(root)
    logical_cpus = len(present) or None

    if not configured:
        return {
            "present": None,
            "state": "unconfigured",
            "physical_id": None,
            "logical": [],
            "configured": [],
            "degraded": [],
            "physical_cores": None,
            "logical_cpus": logical_cpus,
            "source": "unconfigured",
        }

    if not present:
        return {
            "present": None,
            "state": "unknown",
            "physical_id": None,
            "logical": [],
            "configured": list(configured),
            "degraded": [],
            "physical_cores": None,
            "logical_cpus": None,
            "source": "unknown",
        }

    resolved: dict[int, tuple[str, str]] = {}
    used_siblings = False
    for number in configured:
        if number in records:
            resolved[number] = records[number]
            continue
        candidate = _siblings(number, siblings)
        known = {records[cpu] for cpu in candidate if cpu in records}
        if len(known) == 1:
            resolved[number] = known.pop()
            used_siblings = True

    unresolved = [cpu for cpu in configured if cpu not in resolved]
    degraded = [cpu for cpu in configured if cpu not in records and cpu in present]
    missing = [cpu for cpu in configured if cpu not in present]
    expected_mode, configured_mode = _mode(mode_path)
    expected_id = config.FAULT_CORE_PHYSICAL_ID

    if not resolved:
        if unresolved and not missing:
            state = "retired" if expected_mode == "retired" else "offline"
            if any(online.get(cpu) not in ("0", "") for cpu in degraded):
                state = "unknown"
            return {
                "present": None,
                "state": state,
                "physical_id": None,
                "logical": [],
                "configured": list(configured),
                "degraded": degraded,
                "physical_cores": None,
                "logical_cpus": logical_cpus,
                "mode": expected_mode,
                "configured_mode": configured_mode,
                "source": "faultlab-retired" if state == "retired" else state,
            }
        if missing and not degraded:
            return {
                "present": False,
                "state": "absent",
                "physical_id": None,
                "logical": [],
                "configured": list(configured),
                "degraded": [],
                "physical_cores": len(physical),
                "logical_cpus": logical_cpus,
                "mode": expected_mode,
                "configured_mode": configured_mode,
                "source": "sysfs",
            }
        return {
            "present": None,
            "state": "unknown",
            "physical_id": None,
            "logical": [],
            "configured": list(configured),
            "degraded": degraded,
            "physical_cores": None,
            "logical_cpus": logical_cpus,
            "mode": expected_mode,
            "configured_mode": configured_mode,
            "source": "unknown",
        }

    keys = set(resolved.values())
    logical = {cpu for cpu, record in records.items() if record in keys}
    for number in resolved:
        logical.update(siblings.get(number, {number}))
    logical = sorted(cpu for cpu in logical if cpu in present)

    changed = len(keys) != 1 or logical != sorted(configured)
    physical_id = None
    if len(keys) == 1:
        physical_id = _physical_id(next(iter(keys))[1])
        if expected_id is not None and physical_id != expected_id:
            changed = True

    state = "changed" if changed else "present"
    return {
        "present": True,
        "state": state,
        "physical_id": physical_id,
        "logical": logical,
        "configured": list(configured),
        "degraded": degraded,
        "physical_cores": len(physical),
        "logical_cpus": logical_cpus,
        "mode": expected_mode,
        "configured_mode": configured_mode,
        "source": "sysfs+siblings" if used_siblings else "sysfs",
    }


def label(topo: dict) -> str:
    """Name the fault core without inventing a physical id."""
    physical_id = topo.get("physical_id")
    if physical_id is not None:
        return f"physical core {physical_id}"
    cpus = topo.get("configured") or list(config.FAULT_CORE_CPUS)
    if cpus:
        return "fault core (CPUs " + ",".join(str(cpu) for cpu in cpus) + ")"
    return "fault core"


def display_label(topo: dict) -> str:
    """Capitalised label that preserves the CPU-list spelling."""
    text = label(topo)
    return text[:1].upper() + text[1:]


def presence(topo: dict) -> str:
    """Short human-readable presence state for a heading or environment line."""
    state = topo.get("state")
    cpus = ",".join(str(cpu) for cpu in topo.get("configured") or [])
    if state == "unconfigured":
        return "not configured (set FAULT_CPUS in /etc/faultlab/config or QA_FAULT_CORE_CPUS)"
    if state == "retired":
        return f"retired (physical core undetermined; CPUs {cpus} are offline)"
    if state == "offline":
        return f"offline (physical core undetermined; CPUs {cpus} are offline)"
    if topo.get("present") is True:
        logical = ", ".join(str(cpu) for cpu in topo.get("logical") or [])
        total = topo.get("physical_cores")
        logical_count = topo.get("logical_cpus")
        suffix = ""
        if total and logical_count:
            suffix = f"; {total} physical cores / {logical_count} logical CPUs"
        return f"present (logical CPUs {logical or 'unknown'}{suffix})"
    if topo.get("present") is False:
        total = topo.get("physical_cores")
        logical_count = topo.get("logical_cpus")
        suffix = ""
        if total and logical_count:
            suffix = f"; {total} physical cores / {logical_count} logical CPUs"
        return f"absent (the host does not expose {label(topo)}{suffix})"
    return "unknown (CPU topology is unavailable)"


def theme_tag(topo: dict) -> str:
    state = topo.get("state")
    if state in ("retired", "offline"):
        return f"{label(topo)} {state} (undetermined)"
    if state == "changed":
        return f"{label(topo)} mapping changed"
    if topo.get("present") is True:
        return f"{label(topo)} present"
    if topo.get("present") is False:
        return f"{label(topo)} absent"
    if state == "unconfigured":
        return "fault core not configured"
    return f"{label(topo)} unknown"


def available_cpus(topo: dict) -> list[int]:
    """Logical CPUs to use when a control run is needed."""
    if topo.get("present") is True and topo.get("logical"):
        return list(topo["logical"])
    return [0]



# --- isolation policy -------------------------------------------------------
#
# A degrading core is only safe while the policy that fenced it still holds.
# The fault-lab project (fault-injection-rig) sets one of two modes in
# /etc/faultlab/mode:
#   retired - the configured fault CPUs are offlined; nothing runs there.
#   lab     - CPUs are online but isolated and cgroup-fenced for test work.
# Any drift from that state is a security-relevant finding: a process may be
# executing on unreliable silicon without the operator noticing.

FAULT_CORE_BOOT_PARAMS = ("isolcpus", "nohz_full", "rcu_nocbs", "irqaffinity")


def parse_cpu_list(text: str) -> set[int]:
    """Parse a kernel CPU list such as ``0-1,3,8-9``. Invalid tokens are ignored."""
    cpus: set[int] = set()
    for part in (text or "").replace(" ", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            first, _, last = part.partition("-")
            try:
                cpus.update(range(int(first), int(last) + 1))
            except ValueError:
                continue
        else:
            try:
                cpus.add(int(part))
            except ValueError:
                continue
    return cpus


def boot_params(path: str | Path = "/proc/cmdline") -> dict[str, str]:
    params: dict[str, str] = {}
    for token in read_text(path).split():
        key, _, value = token.partition("=")
        params[key] = value or "1"
    return params


def _online(cpu_root: Path, cpus: set[int]) -> set[int]:
    online: set[int] = set()
    for cpu in cpus:
        state = read_text(cpu_root / f"cpu{cpu}" / "online")
        if state in ("", "1"):
            online.add(cpu)
    return online


def _cpuset(root: Path, name: str) -> str:
    return read_text(root / name / "cpuset.cpus")


def _irq_hits(irq_root: str | Path, core: set[int]) -> list[str]:
    hits: list[str] = []
    for path in sorted(Path(irq_root).glob("[0-9]*/smp_affinity_list")):
        if parse_cpu_list(read_text(path)) & core:
            hits.append(path.parent.name)
    return hits


def isolation(*, cpu_root: str | Path | None = None,
              cgroup_root: str | Path | None = None,
              cmdline_path: str | Path = "/proc/cmdline",
              mode_path: str | Path | None = None,
              irq_root: str | Path = "/proc/irq") -> dict:
    """Snapshot the fault-core isolation policy and the state it is meant to hold."""
    cpu_root = Path(cpu_root or config.FAULT_CORE_CPU_ROOT)
    cgroup_root = Path(cgroup_root or config.FAULT_CORE_CGROUP_ROOT)
    mode_path = Path(mode_path or config.FAULT_CORE_MODE_FILE)
    core = set(config.FAULT_CORE_CPUS)

    mode, configured = _mode(mode_path)

    params = boot_params(cmdline_path)
    param_cpus = {
        name: parse_cpu_list(params.get(name, ""))
        for name in FAULT_CORE_BOOT_PARAMS
    }
    slices = {
        name: _cpuset(cgroup_root, name)
        for name in ("system.slice", "user.slice", "faultlab.slice")
    }
    return {
        "mode": mode,
        "configured_mode": configured,
        "core_cpus": sorted(core),
        "online": sorted(_online(cpu_root, core)),
        "params": params,
        "param_cpus": {name: sorted(cpus) for name, cpus in param_cpus.items()},
        "isolated": sorted(parse_cpu_list(
            read_text(cpu_root / "isolated"))),
        "nohz_full": sorted(parse_cpu_list(
            read_text(cpu_root / "nohz_full"))),
        "slices": slices,
        "irq_hits": _irq_hits(irq_root, core) if "irqaffinity" in params else [],
        "topology": topology(cpu_root, mode_path=mode_path),
    }


def _finding(rule: str, severity: str, subject: str, detail: str,
             fingerprint: str) -> dict:
    ts = iso()
    return {
        "fingerprint": fingerprint,
        "ts": ts,
        "last_ts": ts,
        "rule": rule,
        "severity": severity,
        "subject": subject,
        "detail": redact(detail),
        "case_id": None,
    }


def _ab_findings(conn, path: str | Path | None = None) -> list[dict]:
    """Consume new faultlab-ab verdicts from the append-only JSONL log."""
    path = Path(path or config.FAULT_CORE_AB_RESULTS)
    if not path.is_file():
        return []
    try:
        stat = path.stat()
    except OSError:
        return []
    size = stat.st_size
    try:
        cursor = int(db.meta_get(conn, "faultcore_ab_offset", "0") or "0")
    except (TypeError, ValueError):
        cursor = 0
    try:
        prior_mtime = int(db.meta_get(conn, "faultcore_ab_mtime", "0") or "0")
    except (TypeError, ValueError):
        prior_mtime = 0
    # A rewrite or truncation invalidates the byte cursor.
    if size < cursor or (size <= cursor and stat.st_mtime_ns != prior_mtime):
        cursor = 0
    if size == cursor:
        return []

    with path.open("rb") as fh:
        fh.seek(cursor)
        chunk = fh.read(1_048_576)
        end = fh.tell()
    if len(chunk) == 1_048_576:
        cut = chunk.rfind(b"\n")
        if cut >= 0:
            chunk = chunk[:cut + 1]
            end = cursor + len(chunk)
    db.meta_set(conn, "faultcore_ab_offset", str(end))
    db.meta_set(conn, "faultcore_ab_mtime", str(stat.st_mtime_ns))

    levels = {
        "DIVERGENCE": ("faultcore.ab.divergence", "critical"),
        "HW-SUSPECT": ("faultcore.ab.hw_suspect", "warning"),
        "CONTROL-UNSTABLE": ("faultcore.ab.control_unstable", "warning"),
    }
    out: list[dict] = []
    for raw in chunk.splitlines():
        try:
            record = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            continue
        verdict = str(record.get("verdict", "")).upper()
        if verdict not in levels:
            continue
        rule, severity = levels[verdict]
        command = str(record.get("command", "")).strip()
        ts = str(record.get("ts", "")) or iso()
        detail = (
            f"verdict={verdict} exit={record.get('exit')} "
            f"runs={record.get('runs')} mode={record.get('mode')} "
            f"command={command[:200]}"
        )
        out.append(_finding(
            rule, severity, "faultlab-ab", detail,
            f"faultcore|ab|{verdict.lower()}|{ts}|{sha256_text(command)[:16]}",
        ))
    return out


def findings(conn, *, cpu_root: str | Path | None = None,
             cgroup_root: str | Path | None = None,
             cmdline_path: str | Path = "/proc/cmdline",
             mode_path: str | Path | None = None,
             irq_root: str | Path = "/proc/irq",
             ab_path: str | Path | None = None) -> list[dict]:
    """Layer-1 findings for fault-core isolation drift and fault-lab verdicts."""
    if not config.FAULT_CORE_ENABLE or not config.FAULT_CORE_CPUS:
        return []
    try:
        state = isolation(cpu_root=cpu_root, cgroup_root=cgroup_root,
                          cmdline_path=cmdline_path, mode_path=mode_path,
                          irq_root=irq_root)
    except OSError:
        state = None

    out: list[dict] = []
    if state is not None:
        core = set(state["core_cpus"])
        online = set(state["online"])
        mode = state["mode"]
        topo = state["topology"]
        if topo.get("present") is False:
            out.append(_finding(
                "faultcore.topology.absent", "warning", "topology",
                f"{label(topo)} is no longer present",
                "faultcore|topology|absent",
            ))
        elif topo.get("present") is True and (
            topo.get("state") == "changed"
            or set(topo.get("logical") or []) != core
        ):
            out.append(_finding(
                "faultcore.topology.changed", "warning", "topology",
                f"{label(topo)} maps to logical {topo.get('logical')} "
                f"(expected {sorted(core)})",
                "faultcore|topology|changed",
            ))

        if mode == "retired":
            live = sorted(online & core)
            if live:
                out.append(_finding(
                    "faultcore.retired.online", "critical", "cpu",
                    f"mode=retired but CPUs {live} are online; the faulty core "
                    "is accepting work",
                    "faultcore|retired|online|" + ",".join(str(c) for c in live),
                ))
        elif mode == "lab":
            if not online & core:
                out.append(_finding(
                    "faultcore.lab.offline", "warning", "cpu",
                    "mode=lab but CPUs " + ",".join(str(c) for c in sorted(core))
                    + " are offline",
                    "faultcore|lab|offline",
                ))
            missing = [
                name for name in ("isolcpus", "nohz_full", "rcu_nocbs")
                if not (set(state["param_cpus"].get(name, [])) & core)
            ]
            if not core <= set(state["isolated"]):
                missing.append("sysfs:isolated")
            if not core <= set(state["nohz_full"]):
                missing.append("sysfs:nohz_full")
            if missing:
                out.append(_finding(
                    "faultcore.isolation.missing", "warning", "boot",
                    "missing or incomplete isolation: " + ", ".join(missing),
                    "faultcore|isolation|missing|lab",
                ))
            for name in ("system.slice", "user.slice"):
                cpus = parse_cpu_list(state["slices"].get(name, ""))
                if not cpus or cpus & core:
                    out.append(_finding(
                        "faultcore.isolation.unfenced", "critical", name,
                        f"{name} cpuset '{state['slices'].get(name, '')}' still "
                        "allows the faulty core",
                        f"faultcore|isolation|unfenced|{name}",
                    ))
            lab_cpus = parse_cpu_list(state["slices"].get("faultlab.slice", ""))
            if not lab_cpus & core:
                out.append(_finding(
                    "faultcore.lab.slice_missing", "warning", "faultlab.slice",
                    "faultlab.slice is missing or does not contain CPUs "
                    + ",".join(str(c) for c in sorted(core)),
                    "faultcore|lab|slice|faultlab",
                ))
            if "irqaffinity" in state["params"] and state["irq_hits"]:
                out.append(_finding(
                    "faultcore.irq.affinity", "warning", "irq",
                    "IRQ affinity still includes the faulty core: "
                    + ", ".join(state["irq_hits"][:12]),
                    "faultcore|irq|affinity",
                ))

    out.extend(_ab_findings(conn, ab_path))
    return out
