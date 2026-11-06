"""Security provenance detection for unexpected user and root code execution.

Detection is deliberately layered:

* a live ``/proc`` provenance scan for persistent processes;
* a filesystem scan for root-owned files in user-writable QA state;
* optional auditd records for short-lived ``execve`` and privilege changes.

The audit path is the authoritative event source.  Without auditd the module
reports that strict event coverage is unavailable instead of pretending the
snapshot scan can see every short-lived command.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import stat
from datetime import datetime, timezone
from pathlib import Path

from . import config, db, detect
from .util import iso, redact, run, sha256_text, utcnow

DEFAULT_POLICY: dict = {
    "version": 1,
    "allowed_uids": [0, 1000],
    "user_writable_prefixes": [
        "/home/", "/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/",
        "/media/", "/mnt/", "/run/media/",
    ],
    "allowed_root_exe_prefixes": [
        "/usr/", "/lib/", "/lib64/", "/bin/", "/sbin/", "/snap/",
    ],
    "allowed_root_cmd_prefixes": [
        "/usr/", "/lib/", "/lib64/", "/bin/", "/sbin/", "/snap/",
    ],
    "allowed_elevation_parents": [
        "systemd", "sudo", "pkexec", "cron", "crond", "sshd", "login",
        "gdm", "gdm-session-worker", "polkitd", "dbus-daemon",
        "containerd", "dockerd", "kubelet", "systemd-journald",
        "systemd-udevd",
    ],
    "allowed_setuid_exes": [
        "/usr/bin/sudo", "/usr/bin/su", "/usr/bin/passwd",
        "/usr/bin/pkexec", "/usr/bin/mount", "/usr/bin/umount",
        "/usr/bin/fusermount3",
    ],
    "allowed_setuid_comms": ["fusermount3"],
    "allowed_root_loginuid_exes": [
        "/usr/bin/sudo", "/usr/bin/pkexec", "/usr/bin/su",
        "/usr/lib/gdm3/gdm-session-worker",
        "/usr/libexec/gdm-session-worker",
    ],
    "allowed_root_loginuid_comms": ["gdm-session-worker", "gdm-session-wor"],
    "allowed_cap_cgroups": ["qa-sentinel-deep.service", "system.slice"],
    "allowed_cap_exes": [
        "/usr/bin/ping", "/usr/bin/ping6", "/usr/bin/dumpcap",
        "/usr/bin/tcpdump",
    ],
    "allow_root_user_path": [],
    "allowed_root_owned_paths": ["src/qa_sample", "bin/qa_sample"],
    "audit_log": "/var/log/audit/audit.log",
    "audit_keys": ["qa_security_exec", "qa_security_priv"],
    "requested_audit": True,
}
POLICY_FILENAME = "security-policy.json"

_FIELD_RE = re.compile(r'(\w+)=("([^"]*)"|(\S+))')
_AUDIT_MSG_RE = re.compile(r"audit\(([^)]*)\)")
_AUDIT_SERIAL_RE = re.compile(r"audit\([^:]+:(\d+)\)")


def policy_path(path: str | Path | None = None) -> Path:
    return Path(path) if path else config.CONFIG_DIR / POLICY_FILENAME


def load_policy(path: str | Path | None = None) -> dict:
    """Load policy, with a conservative built-in fallback."""
    source = policy_path(path)
    data: dict = {}
    if source.exists():
        try:
            loaded = json.loads(source.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data = loaded
        except (OSError, ValueError):
            data = {}
    policy = json.loads(json.dumps(DEFAULT_POLICY))
    policy.update(data)
    return policy


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def _readlink(path: Path) -> str:
    try:
        return os.readlink(path)
    except OSError:
        return ""


def _cmdline(path: Path) -> list[str]:
    try:
        raw = path.read_bytes()
    except OSError:
        return []
    return [part.decode("utf-8", "replace") for part in raw.split(b"\0") if part]


def _fields(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for match in _FIELD_RE.finditer(text or ""):
        result[match.group(1)] = match.group(3) if match.group(3) is not None else match.group(4)
    return result


def _hex_int(value: str | None, default: int = 0) -> int:
    try:
        return int(value or "0", 16)
    except ValueError:
        return default


def _int(value: str | None, default: int = -1) -> int:
    try:
        return int(value or default)
    except ValueError:
        return default


def _under(path: str, prefixes: list[str]) -> bool:
    if not path:
        return False
    for prefix in prefixes:
        if prefix and (path == prefix.rstrip("/") or path.startswith(prefix)):
            return True
    return False


def _is_container(cgroup: str) -> bool:
    markers = ("docker-", "kubepods", "cri-containerd", "libpod", "lxc")
    return any(marker in cgroup for marker in markers)


def _starttime(path: Path) -> str:
    text = _read(path)
    try:
        tail = text.rpartition(")")[2].split()
        return tail[19]
    except (IndexError, ValueError):
        return ""


def read_proc(pid: int | str, proc_root: str | Path = "/proc") -> dict | None:
    """Read one process without requiring ptrace access to root-owned /proc files."""
    base = Path(proc_root) / str(pid)
    status = _read(base / "status")
    if not status:
        return None
    values: dict[str, str] = {}
    for line in status.splitlines():
        if ":" in line:
            key, value = line.split(":", 1)
            values[key] = value.strip()
    uid = values.get("Uid", "").split()
    gid = values.get("Gid", "").split()
    if not uid:
        return None
    cmd = _cmdline(base / "cmdline")
    exe = _readlink(base / "exe")
    if not exe and cmd:
        exe = cmd[0]
    cwd = _readlink(base / "cwd")
    cgroup = " ".join(_read(base / "cgroup").split())
    loginuid = _int(_read(base / "loginuid").strip(), -1)
    return {
        "pid": int(pid),
        "ppid": _int(values.get("PPid")),
        "comm": values.get("Name", ""),
        "state": values.get("State", ""),
        "uid": _int(uid[0] if uid else "-1"),
        "euid": _int(uid[1] if len(uid) > 1 else (uid[0] if uid else "-1")),
        "gid": _int(gid[0] if gid else "-1"),
        "egid": _int(gid[1] if len(gid) > 1 else (gid[0] if gid else "-1")),
        "cap_eff": _hex_int(values.get("CapEff")),
        "cmdline": cmd,
        "exe": exe,
        "cwd": cwd,
        "cgroup": cgroup,
        "container": _is_container(cgroup),
        "loginuid": loginuid,
        "starttime": _starttime(base / "stat"),
    }


def _finding(proc: dict, rule: str, severity: str, detail: str) -> dict:
    ts = iso()
    # Aggregate repeated executions of the same command (for example the root
    # cron running a user-path qa cycle every minute) instead of creating a new
    # finding for every PID.
    command = " ".join(proc.get("cmdline") or []) or (proc.get("exe") or "")
    command_key = sha256_text(command)[:24]
    return {
        "fingerprint": (
            f"security|{rule}|{proc.get('exe') or proc.get('comm') or 'process'}|{command_key}"
        ),
        "ts": ts,
        "last_ts": ts,
        "rule": rule,
        "severity": severity,
        "subject": f"{proc.get('comm') or 'unknown'}[{proc.get('pid')}]",
        "detail": redact(detail)[:1500],
        "case_id": None,
    }


def _exe_stat(path: str):
    if not path or path.startswith("(") or path.startswith("/memfd:"):
        return None
    try:
        return os.stat(path)
    except OSError:
        return None


def classify_process(proc: dict, parent: dict | None, policy: dict) -> list[dict]:
    """Classify one process.  Container processes are outside this host boundary."""
    if proc.get("container") or _is_container(proc.get("cgroup") or ""):
        return []
    if not proc.get("cmdline") and not proc.get("exe"):
        return []

    user_prefixes = list(policy.get("user_writable_prefixes") or [])
    allowed_uids = {int(item) for item in policy.get("allowed_uids") or []}
    elevation_parents = set(policy.get("allowed_elevation_parents") or [])
    setuid_exes = set(policy.get("allowed_setuid_exes") or [])
    setuid_comms = set(policy.get("allowed_setuid_comms") or [])
    allowed_loginuid_exes = set(policy.get("allowed_root_loginuid_exes") or [])
    allowed_loginuid_comms = set(policy.get("allowed_root_loginuid_comms") or [])
    allowed_cmd = [
        str(item) for item in policy.get("allow_root_user_path") or [] if item
    ]
    exe = proc.get("exe") or ""
    cwd = proc.get("cwd") or ""
    cmd = proc.get("cmdline") or []
    joined = " ".join(cmd)
    command0 = cmd[0].split()[0] if cmd else ""
    setuid_helper = (
        exe in setuid_exes
        or proc.get("comm") in setuid_comms
        or command0 in setuid_comms
    )
    loginuid_allowed = (
        exe in allowed_loginuid_exes
        or proc.get("comm") in allowed_loginuid_comms
        or command0 in allowed_loginuid_comms
    )
    user_tokens = [token for token in cmd if _under(token, user_prefixes)]
    exe_user = _under(exe, user_prefixes)
    cwd_user = _under(cwd, user_prefixes)
    allowed_user_cmd = any(joined.startswith(prefix) for prefix in allowed_cmd)
    root = proc.get("euid") == 0 or proc.get("uid") == 0
    out: list[dict] = []

    def add(rule: str, severity: str, detail: str) -> None:
        out.append(_finding(proc, rule, severity, detail))

    if root:
        if (exe_user or cwd_user) and not setuid_helper and not allowed_user_cmd:
            add(
                "security.root_user_path",
                "critical",
                f"uid 0 process exe={exe or '?'} cwd={cwd or '?'} is in a user-writable path",
            )
        if user_tokens and not setuid_helper and not allowed_user_cmd:
            add(
                "security.root_cmdline_user_path",
                "critical",
                f"uid 0 command line references user-writable path: {joined[:1000]}",
            )
        stat_result = _exe_stat(exe)
        if stat_result and (stat_result.st_uid != 0 or stat_result.st_mode & 0o022):
            add(
                "security.root_writable_exe",
                "critical",
                f"uid 0 executable is writable by a non-root user: {exe}",
            )
        if (
            parent
            and parent.get("uid") != 0
            and parent.get("comm") not in elevation_parents
            and not setuid_helper
        ):
            add(
                "security.root_from_user_parent",
                "critical",
                f"uid 0 process parent is {parent.get('comm')}[{parent.get('pid')}] "
                f"uid={parent.get('uid')}",
            )
        if exe.endswith(" (deleted)") or exe.startswith("/memfd:"):
            add(
                "security.deleted_exe",
                "critical",
                f"uid 0 process runs from a deleted or anonymous executable: {exe}",
            )
        if (
            proc.get("loginuid") not in (-1, 0, 4294967295)
            and proc.get("loginuid") != proc.get("uid")
            and not setuid_helper
            and not loginuid_allowed
        ):
            add(
                "security.root_elevated_session",
                "warning",
                f"uid 0 process has login uid {proc.get('loginuid')} (user session elevation)",
            )
    else:
        if proc.get("uid") not in allowed_uids and (exe_user or user_tokens):
            add(
                "security.unexpected_uid_user_path",
                "critical",
                f"uid={proc.get('uid')} executes user-writable code: {exe or joined[:500]}",
            )
        if (
            proc.get("uid") not in allowed_uids
            and _under(exe, ["/tmp/", "/var/tmp/", "/dev/shm/"])
        ):
            add(
                "security.user_code_tmp",
                "warning",
                f"uid={proc.get('uid')} executes from temporary storage: {exe}",
            )
        cap_eff = int(proc.get("cap_eff") or 0)
        if (
            cap_eff
            and not any(
                item in (proc.get("cgroup") or "")
                for item in policy.get("allowed_cap_cgroups") or []
            )
            and exe not in set(policy.get("allowed_cap_exes") or [])
        ):
            add(
                "security.nonroot_caps",
                "warning",
                f"non-root process has CapEff=0x{cap_eff:x}: {exe or joined[:500]}",
            )
        if exe.endswith(" (deleted)") or exe.startswith("/memfd:"):
            add(
                "security.deleted_exe",
                "warning",
                f"process runs from a deleted or anonymous executable: {exe}",
            )
    return out


def scan_procs(proc_root: str | Path = "/proc", policy: dict | None = None) -> tuple[list[dict], int]:
    policy = policy or load_policy()
    root = Path(proc_root)
    try:
        pids = sorted(int(item.name) for item in root.iterdir() if item.name.isdigit())
    except OSError:
        return [], 0
    cache: dict[int, dict | None] = {}
    findings: list[dict] = []
    for pid in pids:
        proc = read_proc(pid, root)
        if not proc:
            continue
        parent = None
        ppid = proc.get("ppid")
        if ppid and ppid > 0:
            if ppid not in cache:
                cache[ppid] = read_proc(ppid, root)
            parent = cache[ppid]
        findings.extend(classify_process(proc, parent, policy))
    return findings, len(pids)


def files_due(conn) -> bool:
    last = db.meta_get(conn, "last_security_file_scan")
    if not last:
        return True
    try:
        age = (utcnow() - datetime.fromisoformat(last.replace("Z", "+00:00"))).total_seconds()
    except ValueError:
        return True
    return age >= max(30, config.SECURITY_FILE_SCAN_S)


def find_root_owned(policy: dict, root_uid: int = 0) -> list[tuple[str, os.stat_result]]:
    """Return root-owned entries under QA state paths, excluding explicit allows."""
    candidates = [
        config.ROOT / "tickets",
        config.ROOT / "evidence",
        config.ROOT / "var",
        config.ROOT / "journal",
        config.ROOT / "triage",
        config.ROOT / "reports",
        config.ROOT / "src",
        config.ROOT / "bin",
        config.ROOT / "config",
    ]
    allowed = [
        config.ROOT / str(item) for item in policy.get("allowed_root_owned_paths") or []
    ]
    found: list[tuple[str, os.stat_result]] = []
    for base in candidates:
        if not base.exists():
            continue
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            dirnames[:] = [
                name for name in dirnames
                if not os.path.islink(os.path.join(dirpath, name))
            ]
            for name in list(dirnames) + filenames:
                path = os.path.join(dirpath, name)
                if any(path == str(item) or path.startswith(str(item) + os.sep) for item in allowed):
                    continue
                try:
                    st = os.lstat(path)
                except OSError:
                    continue
                if st.st_uid == root_uid:
                    found.append((path, st))
    return found


def file_findings(found: list[tuple[str, os.stat_result]]) -> list[dict]:
    """Aggregate root-owned files by top-level state directory.

    A single root cron can create hundreds of root-owned files.  Per-file
    findings are accurate but make the review queue unusable; one finding per
    state area keeps the provenance signal while preserving samples.
    """
    ts = iso()
    groups: dict[str, list[tuple[str, os.stat_result]]] = {}
    for path, st in found:
        rel = os.path.relpath(path, config.ROOT)
        top = rel.split(os.sep)[0]
        groups.setdefault(top, []).append((rel, st))
    out = []
    for top, items in sorted(groups.items()):
        samples = ", ".join(rel for rel, _st in items[:5])
        out.append(
            {
                "fingerprint": f"security|root_owned_user_state|{top}",
                "ts": ts,
                "last_ts": ts,
                "rule": "security.root_owned_user_state",
                "severity": "warning",
                "subject": f"{top}/ ({len(items)} entries)",
                "detail": redact(
                    f"{len(items)} entries with uid=0 under {top}/; "
                    f"samples: {samples}"
                ),
                "case_id": None,
            }
        )
    return out


def parse_audit_line(line: str, policy: dict, default_ts: str | None = None) -> dict | None:
    """Parse one ``ausearch -i``/auditd record into a finding."""
    fields = _fields(line)
    key = (fields.get("key") or "").strip('"')
    if key not in set(policy.get("audit_keys") or []):
        return None
    # ausearch emits SYSCALL plus EXECVE/PROCTITLE/CWD records.  Only the
    # SYSCALL record carries uid/auid/euid; parsing the others creates bogus
    # uid=-1 privilege findings.
    if (fields.get("type") or "").upper() not in ("", "SYSCALL"):
        return None
    uid = _int(fields.get("uid"), -1)
    if uid < 0:
        return None
    euid = _int(fields.get("euid"), uid)
    auid = _int(fields.get("auid"), -1)
    exe = (fields.get("exe") or "").strip('"')
    comm = (fields.get("comm") or "").strip('"')
    proctitle = (fields.get("proctitle") or "").strip('"')
    user_prefixes = list(policy.get("user_writable_prefixes") or [])
    user_path = _under(exe, user_prefixes) or _under(proctitle, user_prefixes)
    serial = ""
    match = _AUDIT_SERIAL_RE.search(line)
    if match:
        serial = match.group(1)
    ts = default_ts or iso()
    msg = _AUDIT_MSG_RE.search(line)
    if msg:
        try:
            ts = datetime.fromtimestamp(float(msg.group(1).split(":")[0]), timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
        except (ValueError, OSError):
            ts = default_ts or iso()
    subject = f"{comm or 'audit'}[{fields.get('pid', '?')}]"
    if key == "qa_security_exec":
        if uid == 0 and (auid not in (-1, 0, 4294967295) or user_path):
            rule, severity = "security.audit_root_exec", "critical"
            detail = (
                f"audit exec: uid=0 auid={auid} exe={exe or '?'} "
                f"proctitle={proctitle or comm or '?'}"
            )
        elif uid not in {int(item) for item in policy.get("allowed_uids") or []} and user_path:
            rule, severity = "security.audit_unexpected_user_exec", "error"
            detail = f"audit exec: uid={uid} auid={auid} exe={exe or '?'}"
        else:
            return None
    else:
        rule = "security.audit_priv_change"
        severity = "critical" if euid == 0 and auid not in (0, -1, 4294967295) else "warning"
        detail = (
            f"audit privilege event: uid={uid} euid={euid} auid={auid} "
            f"exe={exe or '?'} proctitle={proctitle or comm or '?'}"
        )
    return {
        "fingerprint": f"security|audit|{key}|{serial or ts}|{uid}|{exe}",
        "ts": ts,
        "last_ts": ts,
        "rule": rule,
        "severity": severity,
        "subject": subject,
        "detail": redact(detail)[:1500],
        "case_id": None,
    }


def audit_scan(policy: dict) -> tuple[list[dict], bool]:
    """Consume auditd records when available.

    Returns (findings, available).  ``available`` means the audit source could
    actually be read; a missing or failing source is reported as a coverage
    gap rather than silently treated as "no events".
    """
    ausearch = shutil.which("ausearch")
    log_path = Path(str(policy.get("audit_log") or ""))
    lines: list[str] = []
    failed = False
    source = False
    if ausearch:
        source = True
        for key in policy.get("audit_keys") or []:
            rc, out, err = run(
                [ausearch, "-i", "-k", str(key), "-ts", "recent"], timeout=15
            )
            if rc == 0:
                lines.extend(out.splitlines())
            elif "no matches" not in (out + err).lower():
                failed = True
    elif log_path.exists():
        source = True
        rc, out, _err = run(["tail", "-n", "5000", str(log_path)], timeout=10)
        if rc == 0:
            lines.extend(out.splitlines())
        else:
            failed = True

    findings = []
    for line in lines:
        finding = parse_audit_line(line, policy)
        if finding:
            findings.append(finding)
    if findings:
        return findings, True
    if policy.get("requested_audit", True) and (failed or not source):
        ts = iso()
        bucket = ts[:15]  # 10-minute bucket
        reason = (
            "auditd/ausearch is not available"
            if not source
            else "auditd exists but its events could not be read"
        )
        return [
            {
                "fingerprint": f"security|audit_unavailable|{bucket}",
                "ts": ts,
                "last_ts": ts,
                "rule": "security.audit_unavailable",
                "severity": "warning",
                "subject": "audit",
                "detail": (
                    f"{reason}; strict short-lived exec and privilege-change "
                    "coverage is disabled. Install auditd and the QA rules: "
                    f"{config.ROOT / 'root/audit/qa-security.rules'}"
                ),
                "case_id": None,
            }
        ], False
    return [], not failed


def audit_findings(policy: dict) -> list[dict]:
    return audit_scan(policy)[0]


PROCESS_RULES = (
    "security.root_user_path",
    "security.root_cmdline_user_path",
    "security.root_writable_exe",
    "security.root_from_user_parent",
    "security.root_elevated_session",
    "security.deleted_exe",
    "security.unexpected_uid_user_path",
    "security.user_code_tmp",
    "security.nonroot_caps",
)


def _resolve_missing(conn, rule: str, active: set[str]) -> None:
    rows = conn.execute(
        "SELECT id,fingerprint FROM findings WHERE rule=? AND status='open'", (rule,)
    ).fetchall()
    for row in rows:
        if row["fingerprint"] not in active:
            conn.execute("UPDATE findings SET status='resolved' WHERE id=?", (row["id"],))


def scan(
    conn,
    proc_root: str | Path = "/proc",
    include_files: bool | None = None,
    include_audit: bool = True,
    policy: dict | None = None,
) -> dict:
    """Run all security checks and upsert findings into the existing table."""
    policy = policy or load_policy()
    proc_findings, proc_count = scan_procs(proc_root, policy)
    candidates = list(proc_findings)
    active_proc = {finding["fingerprint"] for finding in proc_findings}
    if include_files is None:
        include_files = files_due(conn)
    file_count = 0
    active_files: set[str] = set()
    if include_files:
        files = find_root_owned(policy)
        file_count = len(files)
        file_candidates = file_findings(files)
        active_files = {finding["fingerprint"] for finding in file_candidates}
        candidates.extend(file_candidates)
    audit_count = 0
    audit_available = None
    if include_audit:
        audit, audit_available = audit_scan(policy)
        audit_count = len(audit)
        candidates.extend(audit)

    new = []
    for finding in candidates:
        created = detect.upsert(conn, finding)
        if created:
            new.append(created)
    if proc_count:
        for rule in PROCESS_RULES:
            _resolve_missing(conn, rule, active_proc)
    if include_files:
        _resolve_missing(conn, "security.root_owned_user_state", active_files)
        db.meta_set(conn, "last_security_file_scan", iso())
    if include_audit and audit_available:
        _resolve_missing(conn, "security.audit_unavailable", set())
    counts: dict[str, int] = {}
    for finding in new:
        counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
    return {
        "new": len(new),
        "by_severity": counts,
        "rules": [finding["rule"] for finding in new][:50],
        "processes": proc_count,
        "files": file_count,
        "audit": audit_count,
        "audit_available": audit_available,
        "findings": new,
    }
