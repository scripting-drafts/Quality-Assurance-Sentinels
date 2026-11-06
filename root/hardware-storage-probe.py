#!/usr/bin/env python3
"""Root-only SMART/NVMe probe with a read-only handoff to the operator.

Installed root-owned by root/install-hardware.sh.  The helper never imports the
user-writable project and never executes a shell.  It writes raw JSON to
$ROOT/var/hardware-storage-root.json, owned root:<operator-group>, mode 0640.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

DEVICE_PREFIXES = ("sd", "nvme", "vd", "xvd")
MAX_DEVICES = 8


def run_json(args: list[str], timeout: int = 20):
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, errors="replace",
            timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"error": str(exc), "rc": 124}
    text = result.stdout.strip()
    if text.startswith("{"):
        try:
            data = json.loads(text)
        except ValueError:
            pass
        else:
            # smartctl uses a bitmask exit status and still returns valid JSON
            # for unsupported USB bridges.  Preserve the data and its rc so the
            # collector can distinguish unsupported from unreadable devices.
            if isinstance(data, dict):
                data.setdefault("rc", result.returncode)
            return data
    return {
        "rc": result.returncode,
        "error": (result.stdout + result.stderr)[:4000],
    }



def run_text(args: list[str], timeout: int = 30) -> dict:
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, errors="replace",
            timeout=timeout, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"rc": 124, "out": "", "error": str(exc)}
    return {
        "rc": result.returncode,
        "out": result.stdout[-20000:],
        "error": result.stderr[-4000:],
    }


def _text(path: Path, errors: list[str], label: str) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        if path.exists():
            errors.append(f"{label} unreadable")
        return ""


def _sha(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", "replace")).hexdigest()


def lsm_state() -> dict:
    securityfs = Path("/sys/kernel/security")
    selinux = Path("/sys/fs/selinux")
    errors: list[str] = []
    active = [item.strip() for item in _text(securityfs / "lsm", errors, "lsm list").split(",") if item.strip()]
    profiles_text = _text(securityfs / "apparmor" / "profiles", errors, "apparmor profiles")
    profiles = [line for line in profiles_text.splitlines() if line.strip()]
    apparmor_enabled = _text(
        Path("/sys/module/apparmor/parameters/enabled"), errors, "apparmor enabled"
    )
    apparmor = {
        "enabled": apparmor_enabled,
        "present": bool(apparmor_enabled or profiles),
        "profiles": {
            "total": len(profiles),
            "enforce": sum(1 for line in profiles if "(enforce)" in line),
            "complain": sum(1 for line in profiles if "(complain)" in line),
            "digest": _sha("\n".join(profiles))[:16] if profiles else "",
        },
    }
    enforce = _text(selinux / "enforce", errors, "selinux enforce")
    selinux_state = {
        "present": selinux.exists(),
        "enforce": enforce,
        "policyvers": _text(selinux / "policyvers", errors, "selinux policyvers"),
    }
    lockdown_text = _text(securityfs / "lockdown", errors, "lockdown")
    lockdown_selected = "unknown"
    lockdown_options = []
    for token in lockdown_text.split():
        if token.startswith("[") and token.endswith("]"):
            lockdown_selected = token.strip("[]")
        else:
            lockdown_options.append(token)
    yama_scope = _text(
        Path("/proc/sys/kernel/yama/ptrace_scope"), errors, "yama ptrace_scope"
    )
    ima_policy = securityfs / "ima" / "policy"
    if not ima_policy.exists():
        ima_policy = securityfs / "integrity" / "ima" / "policy"
    ima_present = ima_policy.exists()
    ima_readable = False
    if ima_present:
        try:
            # Some kernels expose the IMA policy write-only (mode 0200) even to
            # root.  That is a kernel interface property, not unreadable state.
            ima_readable = bool(ima_policy.stat().st_mode & 0o444)
        except OSError:
            ima_readable = False
    ima_text = _text(ima_policy, errors, "ima policy") if ima_readable else ""
    cmdline_lsm = []
    for token in _text(Path("/proc/cmdline"), errors, "kernel cmdline").split():
        if token.startswith("lsm="):
            cmdline_lsm = token.split("=", 1)[1].split(",")
    return {
        "active": active,
        "kernel_cmdline_lsm": cmdline_lsm,
        "securityfs": securityfs.is_dir(),
        "apparmor": apparmor,
        "selinux": selinux_state,
        "smack": {"present": Path("/sys/fs/smackfs").is_dir()},
        "tomoyo": {"present": (securityfs / "tomoyo").is_dir()},
        "yama": {"ptrace_scope": yama_scope, "present": bool(yama_scope)},
        "lockdown": {"selected": lockdown_selected, "options": lockdown_options},
        "ima": {
            "present": ima_present,
            "readable": ima_readable,
            "policy_sha256": _sha(ima_text)[:16] if ima_text else "",
            "policy_bytes": len(ima_text),
        },
        "bpf_lsm": "bpf" in active,
        "audit_lsm": "audit" in active,
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--user", required=True)
    args = parser.parse_args()
    root = Path(args.root).resolve()
    account = pwd.getpwnam(args.user)
    var = root / "var"
    var.mkdir(parents=True, exist_ok=True)
    target = var / "hardware-storage-root.json"

    smartctl = shutil.which("smartctl")
    nvme = shutil.which("nvme")
    devices = []
    for entry in sorted(Path("/sys/block").iterdir()):
        if entry.name.startswith(DEVICE_PREFIXES):
            devices.append(entry.name)
    devices = devices[:MAX_DEVICES]

    payload = {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "smartctl": smartctl,
        "nvme": nvme,
        "lsm": lsm_state(),
        "devices": {},
    }
    for device in devices:
        entry = {}
        if smartctl:
            entry["smartctl"] = run_json([smartctl, "-a", "-j", f"/dev/{device}"])
        else:
            entry["smartctl"] = {"error": "smartctl not installed", "rc": 127}
        if nvme and device.startswith("nvme"):
            entry["nvme"] = run_json(
                [nvme, "smart-log", f"/dev/{device}", "-o", "json"]
            )
        payload["devices"][device] = entry

    ras = shutil.which("ras-mc-ctl")
    if ras:
        # The rasdaemon database is root-only (0700).  Collect the summaries
        # here so the unprivileged collector never needs that directory.
        payload["ras"] = {
            arg: run_text([ras, arg], timeout=20)
            for arg in ("--summary", "--errors")
        }
    else:
        payload["ras"] = {"error": "ras-mc-ctl not installed", "rc": 127}

    turbostat = shutil.which("turbostat")
    if turbostat:
        # turbostat calls access(R_OK) on /dev/cpu/*/msr, which ignores the
        # hardware service's ambient capabilities.  Run it here, as the only
        # root process, and hand the summary to the unprivileged collector.
        payload["turbostat"] = run_text([
            turbostat, "-S", "-q", "-i", "1", "-n", "1",
        ])
    else:
        payload["turbostat"] = {"rc": 127, "out": "", "error": "turbostat not installed"}

    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=var, prefix=".hardware-storage-", delete=False
    ) as handle:
        json.dump(payload, handle, separators=(",", ":"))
        temp_name = handle.name
    os.chmod(temp_name, 0o640)
    if os.geteuid() == 0:
        os.chown(temp_name, 0, account.pw_gid)
    os.replace(temp_name, target)
    # A written handoff is success even when an individual device has no SMART
    # support; the collector classifies unsupported versus unreadable devices.
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
