#!/usr/bin/env python3
"""Root-only LSM state reader with a read-only handoff to the operator.

Installed root-owned by root/install-lsm-read.sh.  The helper never imports the
user-writable project and never executes a shell.  It writes the LSM state to
$ROOT/var/lsm-state-root.json, owned root:<operator-group>, mode 0640.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def _text(path: Path, errors: list[str], label: str) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        if path.exists():
            errors.append(f"{label} unreadable")
        return ""


def _sha(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", "replace")).hexdigest()


def _ima_text(policy: Path, errors: list[str]) -> tuple[str, bool]:
    """Read IMA policy only when the kernel exposes it readably.

    Some kernels expose the policy write-only (mode 0200) even to root.  That
    is an interface property, not unreadable state.
    """
    try:
        readable = bool(policy.stat().st_mode & 0o444)
    except OSError:
        return "", False
    if not readable:
        return "", False
    return _text(policy, errors, "ima policy"), True


def lsm_state() -> dict:
    securityfs = Path("/sys/kernel/security")
    selinux = Path("/sys/fs/selinux")
    errors: list[str] = []
    active = [
        item.strip()
        for item in _text(securityfs / "lsm", errors, "lsm list").split(",")
        if item.strip()
    ]
    if not active:
        errors.append("lsm list unreadable")

    profiles_text = _text(
        securityfs / "apparmor" / "profiles", errors, "apparmor profiles"
    )
    profiles = [line for line in profiles_text.splitlines() if line.strip()]
    apparmor_enabled = _text(
        Path("/sys/module/apparmor/parameters/enabled"),
        errors,
        "apparmor enabled",
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
    smack = Path("/sys/fs/smackfs")
    tomoyo = securityfs / "tomoyo"

    ima_policy = securityfs / "ima" / "policy"
    if not ima_policy.exists():
        ima_policy = securityfs / "integrity" / "ima" / "policy"
    ima_present = ima_policy.exists()
    ima_text, ima_readable = _ima_text(ima_policy, errors) if ima_present else ("", False)

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
        "smack": {"present": smack.is_dir()},
        "tomoyo": {"present": tomoyo.is_dir()},
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
    target = var / "lsm-state-root.json"

    payload = {
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "lsm": lsm_state(),
    }
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", dir=var, prefix=".lsm-state-", delete=False
    ) as handle:
        json.dump(payload, handle, separators=(",", ":"))
        temp_name = handle.name
    os.chmod(temp_name, 0o640)
    if os.geteuid() == 0:
        os.chown(temp_name, 0, account.pw_gid)
    os.replace(temp_name, target)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
