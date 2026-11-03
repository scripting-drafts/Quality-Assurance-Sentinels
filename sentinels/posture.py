"""Record the sentinel's own privilege posture.

The QA job must observe without widening the attack surface: no root, no
effective capabilities, no passwordless sudo, no lockdown change, and the
kernel's perf_event_paranoid untouched. This module proves that at runtime
and stores the result next to the evidence.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone

from . import config, db
from .util import iso, read_text, run, write_json

POSTURE_PATH = config.VAR / "posture.json"
BASELINE_PATH = config.VAR / "posture-baseline.json"
SUDO_CACHE_PATH = config.VAR / "sudo-probe.json"
BASELINE_KEYS = ("perf_event_paranoid", "lockdown_active", "secure_boot")


def _active_lockdown(raw: str) -> str:
    match = re.search(r"\[([^\]]+)\]", raw or "")
    return match.group(1) if match else (raw or "unknown")


def _baseline() -> dict:
    try:
        return json.loads(read_text(str(BASELINE_PATH)) or "{}")
    except json.JSONDecodeError:
        return {}


def _cap_eff() -> int:
    for line in read_text("/proc/self/status").splitlines():
        if line.startswith("CapEff:"):
            try:
                return int(line.split(":", 1)[1].strip(), 16)
            except ValueError:
                return -1
    return -1


def _sudo_nopasswd(fresh: bool = False) -> bool:
    """Probe once per hour; invoking sudo on every report pollutes the journal."""
    try:
        cached = json.loads(read_text(str(SUDO_CACHE_PATH)) or "{}")
    except json.JSONDecodeError:
        cached = {}
    if not fresh and cached.get("value") is not None:
        try:
            from .util import parse_iso

            age = (datetime.now(timezone.utc) - parse_iso(cached["ts"])).total_seconds()
            if 0 <= age < 3600:
                return bool(cached["value"])
        except (KeyError, ValueError):
            pass
    value = run(["sudo", "-n", "true"], timeout=10)[0] == 0
    write_json(SUDO_CACHE_PATH, {"ts": iso(), "value": value})
    return value


def collect(fresh: bool = False) -> dict:
    euid = os.geteuid()
    uid = os.getuid()
    groups = sorted(os.getgroups())
    cap_eff = _cap_eff()
    sudo_nopasswd = _sudo_nopasswd(fresh)
    lockdown = read_text("/sys/kernel/security/lockdown").strip() or "unknown"
    secure_boot_raw = read_text(
        "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
    )
    secure_boot = "unknown"
    if secure_boot_raw:
        try:
            secure_boot = str(int.from_bytes(secure_boot_raw.encode("latin-1")[4:5], "little"))
        except Exception:  # noqa: BLE001
            pass
    cron = run(["crontab", "-l"], timeout=10)[1]
    data = {
        "ts": iso(),
        "uid": uid,
        "euid": euid,
        "groups": groups,
        "cap_eff": f"0x{cap_eff:016x}" if cap_eff >= 0 else "unknown",
        "cap_eff_zero": cap_eff == 0,
        "no_new_privs": "NoNewPrivs" in read_text("/proc/self/status")
        and read_text("/proc/self/status").split("NoNewPrivs:")[1].split()[0] == "1",
        "sudo_nopasswd": sudo_nopasswd,
        "perf_event_paranoid": read_text("/proc/sys/kernel/perf_event_paranoid") or "unknown",
        "lockdown": lockdown,
        "lockdown_active": _active_lockdown(lockdown),
        "secure_boot": secure_boot,
        "kernel_taint": read_text("/proc/sys/kernel/tainted") or "unknown",
        "system_service_installed": os.path.exists("/etc/systemd/system/qa-sentinel.service"),
        "cron_installed": "qa-sentinels" in cron,
    }
    baseline = _baseline()
    data["baseline"] = baseline
    data["baseline_changed"] = [
        key for key in BASELINE_KEYS
        if baseline.get(key) is not None and baseline.get(key) != data.get(key)
    ]
    privileged = (
        euid == 0
        or (cap_eff not in (0, -1))
        or sudo_nopasswd
    )
    data["verdict"] = "privileged" if privileged else "unprivileged"
    data["reasons"] = [
        reason
        for reason, hit in (
            ("running as root", euid == 0),
            ("effective capabilities are not empty", cap_eff not in (0, -1)),
            ("passwordless sudo is available", sudo_nopasswd),
        )
        if hit
    ]
    return data


def record(conn, force: bool = False, rebaseline: bool = False) -> dict:
    data = collect(fresh=True)
    config.VAR.mkdir(parents=True, exist_ok=True)
    if rebaseline or not BASELINE_PATH.exists():
        write_json(BASELINE_PATH, {key: data.get(key) for key in BASELINE_KEYS})
        data["baseline"] = {key: data.get(key) for key in BASELINE_KEYS}
        data["baseline_changed"] = []
    write_json(POSTURE_PATH, data)
    previous = db.meta_get(conn, "posture_verdict")
    db.meta_set(conn, "posture_ts", data["ts"])
    db.meta_set(conn, "posture_verdict", data["verdict"])
    if data["baseline_changed"]:
        db.meta_set(conn, "posture_drift", ",".join(data["baseline_changed"]))
    if force or previous != data["verdict"] or data["baseline_changed"]:
        from . import report

        report.append_journal(
            conn,
            f"Privilege posture: {data['verdict']}"
            + (f" (drift: {', '.join(data['baseline_changed'])})" if data["baseline_changed"] else ""),
            "\n".join(
                [
                    f"- uid/euid: {data['uid']}/{data['euid']}",
                    f"- CapEff: `{data['cap_eff']}`",
                    f"- passwordless sudo: {data['sudo_nopasswd']}",
                    f"- perf_event_paranoid: {data['perf_event_paranoid']} "
                    f"(baseline {data['baseline'].get('perf_event_paranoid')})",
                    f"- lockdown active: {data['lockdown_active']} "
                    f"(baseline {data['baseline'].get('lockdown_active')})",
                    f"- secure boot: {data['secure_boot']} "
                    f"(baseline {data['baseline'].get('secure_boot')})",
                    f"- reasons: {', '.join(data['reasons']) or 'none'}",
                ]
            )
            + "\n",
            "posture",
        )
    return data


def line(data: dict | None = None) -> str:
    data = data or collect()
    drift = (
        f", DRIFT: {', '.join(data['baseline_changed'])}"
        if data.get("baseline_changed")
        else ""
    )
    return (
        f"{data['verdict']} (uid {data['uid']}, CapEff `{data['cap_eff']}`, "
        f"sudo passwordless: {data['sudo_nopasswd']}, "
        f"perf_event_paranoid {data['perf_event_paranoid']}, "
        f"lockdown {data.get('lockdown_active', data['lockdown'])}{drift})"
    )
