"""Linux Security Module state and denial monitoring.

Tracks the active LSM stack (AppArmor, SELinux, Smack, TOMOYO, Yama, lockdown,
IMA, BPF), detects configuration drift, and summarizes recent AppArmor/SELinux
denials from the kernel journal.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from datetime import timedelta
from pathlib import Path

from . import config, db, detect
from .util import iso, parse_iso, read_text, redact, run, utcnow

DENIAL_APPARMOR = re.compile(r'apparmor="DENIED"', re.I)
DENIAL_SELINUX = re.compile(r"avc:\s+denied|selinux.*denied", re.I)


def _sha(text: str) -> str:
    return hashlib.sha256((text or "").encode("utf-8", "replace")).hexdigest()


def _state_digest(state: dict) -> str:
    payload = {
        key: value for key, value in state.items()
        if key not in ("digest", "errors")
    }
    # Profile contents and IMA policy bytes are privilege-dependent: the root
    # probe can read them while the operator cannot.  Monitor their coverage
    # via lsm.state_unreadable; do not let visibility flip the drift baseline.
    if isinstance(payload.get("apparmor"), dict):
        payload["apparmor"] = {
            key: value for key, value in payload["apparmor"].items()
            if key != "profiles"
        }
    if isinstance(payload.get("ima"), dict):
        payload["ima"] = {
            key: value for key, value in payload["ima"].items()
            if key not in ("policy_sha256", "policy_bytes")
        }
    return _sha(json.dumps(payload, sort_keys=True, separators=(",", ":")))[:32]


def _read_lsm(path: Path, errors: list[str], label: str) -> str:
    try:
        # securityfs exposes some interfaces write-only even to root (notably
        # the IMA policy on kernels built without read-policy support).  Do not
        # report that kernel interface as unreadable state.
        if path.exists() and not (path.stat().st_mode & 0o444):
            return ""
    except OSError:
        pass
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except PermissionError:
        if path.exists():
            errors.append(f"{label} unreadable")
    except OSError:
        if path.exists():
            errors.append(f"{label} unreadable")
    return ""


def parse_lsm_list(text: str) -> list[str]:
    return [item.strip() for item in (text or "").replace("\n", ",").split(",") if item.strip()]


def parse_lockdown(text: str) -> dict:
    selected = "unknown"
    options = []
    for token in (text or "").split():
        if token.startswith("[") and token.endswith("]"):
            selected = token.strip("[]")
        else:
            options.append(token)
    return {"selected": selected, "options": options}


def parse_apparmor_profiles(text: str) -> dict:
    lines = [line for line in (text or "").splitlines() if line.strip()]
    enforce = sum(1 for line in lines if "(enforce)" in line)
    complain = sum(1 for line in lines if "(complain)" in line)
    return {
        "total": len(lines),
        "enforce": enforce,
        "complain": complain,
        "digest": _sha("\n".join(lines))[:16] if lines else "",
    }


def parse_denials(lines: list[str]) -> dict:
    out = {"apparmor": [], "selinux": [], "other": []}
    for line in lines:
        if DENIAL_APPARMOR.search(line):
            out["apparmor"].append(line[:500])
        elif DENIAL_SELINUX.search(line):
            out["selinux"].append(line[:500])
    return out


def collect_state(
    securityfs: str | Path = "/sys/kernel/security",
    selinux: str | Path = "/sys/fs/selinux",
    proc_sys: str | Path = "/proc/sys/kernel",
) -> dict:
    securityfs = Path(securityfs)
    selinux = Path(selinux)
    proc_sys = Path(proc_sys)
    errors = []
    active = parse_lsm_list(_read_lsm(securityfs / "lsm", errors, "lsm list"))
    if not active:
        errors.append("lsm list unreadable")

    apparmor_enabled = read_text(Path("/sys/module/apparmor/parameters/enabled")).strip()
    apparmor_profiles = parse_apparmor_profiles(
        _read_lsm(securityfs / "apparmor" / "profiles", errors, "apparmor profiles")
    )
    apparmor = {
        "enabled": apparmor_enabled,
        "profiles": apparmor_profiles,
        "present": bool(apparmor_enabled or apparmor_profiles["total"]),
    }

    selinux_enforce = _read_lsm(selinux / "enforce", errors, "selinux enforce")
    selinux = {
        "present": selinux.exists(),
        "enforce": selinux_enforce,
        "policyvers": _read_lsm(selinux / "policyvers", errors, "selinux policyvers"),
    }

    lockdown = parse_lockdown(_read_lsm(securityfs / "lockdown", errors, "lockdown"))
    yama_scope = _read_lsm(proc_sys / "yama" / "ptrace_scope", errors, "yama ptrace_scope")
    smack = Path("/sys/fs/smackfs")
    tomoyo = securityfs / "tomoyo"
    ima_policy = securityfs / "ima" / "policy"
    if not ima_policy.exists():
        ima_policy = securityfs / "integrity" / "ima" / "policy"
    ima_present = ima_policy.exists()
    ima_readable = False
    if ima_present:
        try:
            ima_readable = bool(ima_policy.stat().st_mode & 0o444)
        except OSError:
            ima_readable = False
    ima_text = _read_lsm(ima_policy, errors, "ima policy") if ima_readable else ""
    state = {
        "active": active,
        "kernel_cmdline_lsm": _kernel_cmdline_lsm(),
        "securityfs": securityfs.is_dir(),
        "apparmor": apparmor,
        "selinux": selinux,
        "smack": {"present": smack.is_dir()},
        "tomoyo": {"present": tomoyo.is_dir()},
        "yama": {"ptrace_scope": yama_scope, "present": bool(yama_scope)},
        "lockdown": lockdown,
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
    state["digest"] = _state_digest(state)
    return state


def _kernel_cmdline_lsm() -> list[str]:
    for token in read_text("/proc/cmdline").split():
        if token.startswith("lsm="):
            return token.split("=", 1)[1].split(",")
    return []


def collect_denials(conn) -> dict:
    last = db.meta_get(conn, "last_lsm_denial_ts")
    now = utcnow()
    since = parse_iso(last) if last else now - timedelta(hours=1)
    if since > now - timedelta(minutes=5):
        since = now - timedelta(minutes=5)
    if since < now - timedelta(hours=6):
        since = now - timedelta(hours=6)
    rc, out, _err = run(
        ["journalctl", "-k", "--since", iso(since), "--no-pager"],
        timeout=max(10, config.LSM_TIMEOUT_S),
    )
    lines = out.splitlines() if rc == 0 else []
    denials = parse_denials(lines)
    denials["since"] = iso(since)
    denials["counts"] = {key: len(value) for key, value in denials.items() if isinstance(value, list)}
    return denials


def _finding(rule: str, severity: str, subject: str, detail: str) -> dict:
    ts = iso()
    return {
        "fingerprint": f"lsm|{rule}|{subject}",
        "ts": ts,
        "last_ts": ts,
        "rule": rule,
        "severity": severity,
        "subject": subject,
        "detail": redact(detail)[:1500],
        "case_id": None,
    }


def _state_findings(state: dict) -> list[dict]:
    out = []
    active = set(state.get("active") or [])
    if not active:
        out.append(_finding("lsm.none", "critical", "lsm",
                            "no active LSM list is available"))
    if state["apparmor"].get("present") and state["apparmor"].get("enabled") not in ("Y", "1", "yes", "true"):
        out.append(_finding("lsm.apparmor.disabled", "warning", "apparmor",
                            f"AppArmor enabled={state['apparmor'].get('enabled')!r}"))
    if (
        state["apparmor"].get("present")
        and (state["apparmor"].get("profiles") or {}).get("total") == 0
        and not any("apparmor" in error for error in state.get("errors") or [])
    ):
        out.append(_finding("lsm.apparmor.no_profiles", "warning", "apparmor",
                            "AppArmor is present but no profiles were readable"))
    if state["selinux"].get("present") and state["selinux"].get("enforce") not in ("1", "enforcing"):
        out.append(_finding("lsm.selinux.permissive", "warning", "selinux",
                            f"SELinux enforce={state['selinux'].get('enforce')!r}"))
    if state["yama"].get("present") and state["yama"].get("ptrace_scope") == "0":
        out.append(_finding("lsm.yama.ptrace_scope", "warning", "yama",
                            "kernel.yama.ptrace_scope=0 permits unrestricted ptrace"))
    if state["lockdown"].get("selected") == "none" and "lockdown" in active:
        out.append(_finding("lsm.lockdown.none", "warning", "lockdown",
                            "lockdown LSM is active but selected mode is none"))
    if "integrity" in active and not state["ima"].get("present"):
        out.append(_finding("lsm.ima.policy_missing", "warning", "ima",
                            "integrity LSM is active but no IMA policy was found"))
    if state.get("errors"):
        out.append(_finding("lsm.state_unreadable", "warning", "lsm",
                            "; ".join(state["errors"])))
    return out


def _denial_findings(denials: dict) -> list[dict]:
    out = []
    day = iso()[:10]
    for kind in ("apparmor", "selinux"):
        entries = denials.get(kind) or []
        if len(entries) >= config.LSM_DENIAL_ALERT:
            out.append(_finding(
                f"lsm.{kind}.denial", "warning", f"{kind}:{day}",
                f"{len(entries)} {kind} denial(s); latest: {entries[-1][:500]}",
            ))
    return out


def is_due(conn) -> bool:
    if not config.LSM_ENABLE:
        return False
    last = db.meta_get(conn, "last_lsm_ts")
    if not last:
        return True
    try:
        return (utcnow() - parse_iso(last)).total_seconds() >= config.LSM_INTERVAL_S
    except ValueError:
        return True


def scan(conn, state: dict | None = None) -> dict:
    state = state or collect_state()
    denials = collect_denials(conn)
    baseline = db.meta_get(conn, "lsm_baseline_digest")
    findings = _state_findings(state)
    if baseline and baseline != state["digest"]:
        findings.append(_finding(
            "lsm.state_changed", "warning", "lsm",
            f"LSM state changed {baseline[:12]} -> {state['digest'][:12]}; "
            f"active={','.join(state.get('active') or [])}",
        ))
    if not baseline:
        db.meta_set(conn, "lsm_baseline_digest", state["digest"])
    elif baseline != state["digest"]:
        db.meta_set(conn, "lsm_baseline_digest", state["digest"])
    findings.extend(_denial_findings(denials))
    current_rules = {finding["rule"] for finding in findings}
    for rule in (
        "lsm.state_unreadable", "lsm.lockdown.none", "lsm.apparmor.disabled",
        "lsm.apparmor.no_profiles", "lsm.selinux.permissive",
        "lsm.yama.ptrace_scope", "lsm.ima.policy_missing",
    ):
        if rule not in current_rules:
            conn.execute(
                "UPDATE findings SET status='resolved' WHERE rule=? AND status='open'",
                (rule,),
            )

    cur = conn.execute(
        "INSERT INTO lsm_runs(ts,digest,state,denials,status) VALUES(?,?,?,?,?)",
        (iso(), state["digest"], json.dumps(state, sort_keys=True),
         json.dumps(denials, sort_keys=True), "partial" if state.get("errors") else "ok"),
    )
    new = []
    for finding in findings:
        created = detect.upsert(conn, finding)
        if created:
            new.append(created)
    db.meta_set(conn, "last_lsm_ts", iso())
    db.meta_set(conn, "last_lsm_denial_ts", iso())
    counts: dict[str, int] = {}
    for finding in new:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    return {
        "run_id": cur.lastrowid,
        "digest": state["digest"],
        "state": state,
        "denials": denials,
        "new": len(new),
        "by_severity": counts,
        "findings": new,
    }


def latest(conn) -> dict:
    row = conn.execute("SELECT * FROM lsm_runs ORDER BY id DESC LIMIT 1").fetchone()
    if not row:
        return {}
    data = dict(row)
    for key in ("state", "denials"):
        try:
            data[key] = json.loads(data.get(key) or "{}")
        except ValueError:
            data[key] = {}
    return data


def baseline(conn) -> str:
    state = collect_state()
    db.meta_set(conn, "lsm_baseline_digest", state["digest"])
    conn.execute(
        "UPDATE findings SET status='resolved' "
        "WHERE rule='lsm.state_changed' AND status='open'"
    )
    return state["digest"]
