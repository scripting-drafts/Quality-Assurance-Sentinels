"""Ingest warnings, errors, kernel messages and crashes into SQLite."""
from __future__ import annotations

import glob
import json
import os
import re
import shutil
from datetime import datetime, timedelta, timezone

from . import classify, config, db, shutdown
from .util import iso, parse_iso, run, sha256_text, utcnow


# ---------------------------------------------------------------- journal
def _journal_args(after: str | None) -> list[str]:
    args = ["journalctl", "--no-pager", "-o", "json", "-p", config.JOURNAL_PRIORITY]
    if after:
        args.append(f"--after-cursor={after}")
    else:
        args += ["--since=-2h"]
    return args


def _message(entry: dict) -> str:
    msg = entry.get("MESSAGE", "")
    if isinstance(msg, list):
        try:
            msg = bytes(msg).decode("utf-8", "replace")
        except Exception:
            msg = str(msg)
    if not msg:
        return ""
    return str(msg).replace("\x00", "")


def ingest_journal(conn) -> int:
    """Pull journal entries at the configured priority since the stored cursor."""
    free = shutil.disk_usage(str(config.VAR)).free
    if free < config.MIN_FREE_MIB * 1024 * 1024:
        raise RuntimeError(
            f"refusing to ingest: only {free / 1024**3:.2f} GiB free "
            f"(QA_MIN_FREE_MIB={config.MIN_FREE_MIB})"
        )
    cursor = db.meta_get(conn, "journal_cursor")
    rc, out, err = run(_journal_args(cursor), timeout=60)
    if rc != 0:
        raise RuntimeError(f"journalctl rc={rc}: {err.strip()[:400]}")

    added = 0
    last_cursor = cursor
    entries = 0
    for line in out.splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        entries += 1
        last_cursor = entry.get("__CURSOR") or last_cursor
        realtime = entry.get("__REALTIME_TIMESTAMP")
        try:
            ts = datetime.fromtimestamp(int(realtime) / 1_000_000, tz=timezone.utc)
            ts_s = ts.strftime("%Y-%m-%dT%H:%M:%SZ")
        except (TypeError, ValueError):
            ts_s = iso()

        unit = entry.get("_SYSTEMD_UNIT") or ""
        if not unit and entry.get("SYSLOG_IDENTIFIER"):
            unit = f"ident:{entry['SYSLOG_IDENTIFIER']}"
        prio = entry.get("PRIORITY")
        try:
            prio = int(prio)
        except (TypeError, ValueError):
            prio = None
        msg = _message(entry)
        sev = classify.classify(msg, prio)
        if sev == "noise":
            continue
        pid = entry.get("_PID")
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            pid = None
        source = "kernel" if not entry.get("_SYSTEMD_UNIT") and (
            entry.get("_TRANSPORT") == "kernel" or entry.get("SYSLOG_IDENTIFIER") == "kernel"
        ) else "journal"
        sig = classify.signature(msg, 200)
        bucket = ts_s[:14] + f"{int(ts_s[14:16]) - int(ts_s[14:16]) % 5:02d}"
        fp = sha256_text(f"{source}|{unit}|{sig}|{bucket}")[:40]

        cur = conn.execute(
            "INSERT INTO events"
            "(ts,boot_id,source,severity,unit,pid,comm,message,fingerprint,raw,count,last_ts)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,1,?)"
            " ON CONFLICT(fingerprint) DO UPDATE SET"
            " count=count+1, last_ts=excluded.last_ts",
            (
                ts_s,
                entry.get("_BOOT_ID"),
                source,
                sev,
                unit,
                pid,
                entry.get("_COMM"),
                msg,
                fp,
                json.dumps(entry, default=str),
                ts_s,
            ),
        )
        added += cur.rowcount

    if last_cursor:
        db.meta_set(conn, "journal_cursor", last_cursor)
    db.meta_set(conn, "last_journal_ingest", iso())
    return added


# ---------------------------------------------------------------- crashes
_LIST_RE = re.compile(
    r"^\S+\s+(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+\S+\s+"
    r"(\d+)\s+(\d+)\s+(\d+)\s+(\S+)\s+(\S+)\s+(.+?)\s+(\S+)\s*$"
)


def parse_cpu_list(spec: str | None) -> set[int] | None:
    """Parse a kernel cpulist ('0-3,8') into ints. None = unknown."""
    if not spec:
        return None
    spec = spec.strip()
    if not spec or spec in ("-", "n/a"):
        return None
    cpus: set[int] = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                lo, hi = part.split("-", 1)
                cpus.update(range(int(lo), int(hi) + 1))
            except ValueError:
                return None
        else:
            try:
                cpus.add(int(part))
            except ValueError:
                return None
    return cpus or None


def core2_verdict(mask: set[int] | None) -> int | None:
    if mask is None:
        return None
    return 1 if any(c in mask for c in config.CORE2_CPUS) else 0


def _nearest_proc(conn, pid: int, ts: str) -> dict | None:
    row = conn.execute(
        "SELECT * FROM proc_snap WHERE pid=? AND ts<=? ORDER BY ts DESC LIMIT 1",
        (pid, ts),
    ).fetchone()
    return dict(row) if row else None


def _journal_context(epoch: float, window: int = 45, lines: int = 120) -> str:
    since = datetime.fromtimestamp(epoch - window, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    until = datetime.fromtimestamp(epoch + window, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    rc, out, _ = run(
        ["journalctl", "--no-pager", "-o", "short-iso", "--since", since,
         "--until", until, "-n", str(lines)],
        timeout=30,
    )
    return out if rc == 0 else ""


def ingest_coredumps(conn, days: int = 30) -> int:
    rc, out, err = run(
        ["coredumpctl", "list", "--no-pager", f"--since=-{days}days"], timeout=45
    )
    if rc != 0:
        # coredumpctl is absent or has no permission; minidumps still count
        return 0

    added = 0
    for line in out.splitlines()[1:]:
        m = _LIST_RE.match(line)
        if not m:
            continue
        local_ts, pid, _uid, _gid, sig, corefile, exe, size = m.groups()
        try:
            dt = datetime.strptime(local_ts, "%Y-%m-%d %H:%M:%S").astimezone()
            dt = dt.astimezone(timezone.utc)
        except ValueError:
            continue
        ts_s = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        pid = int(pid)
        fp = sha256_text(f"coredump|{ts_s}|{pid}|{sig}|{exe}")[:40]
        if conn.execute("SELECT 1 FROM crashes WHERE fingerprint=?", (fp,)).fetchone():
            continue

        proc = _nearest_proc(conn, pid, ts_s)
        mask = parse_cpu_list(proc.get("cpus_allowed") if proc else None)
        verdict = core2_verdict(mask)

        info_rc, info_out, _ = run(
            ["coredumpctl", "info", str(pid), "--no-pager"], timeout=45
        )
        info = info_out if info_rc == 0 else ""
        context = _journal_context(dt.timestamp())

        conn.execute(
            "INSERT OR IGNORE INTO crashes"
            "(ts,pid,comm,exe,sig,corefile,cpus_allowed,core2_involved,context,fingerprint)"
            " VALUES(?,?,?,?,?,?,?,?,?,?)",
            (
                ts_s,
                pid,
                proc.get("comm") if proc else None,
                exe,
                sig,
                corefile,
                (",".join(map(str, sorted(mask))) if mask else None),
                verdict,
                f"size={size}\n" + info + "\n--- journal context ---\n" + context,
                fp,
            ),
        )
        added += 1
    return added


def ingest_minidumps(conn) -> int:
    """Firefox/WebRender minidumps are evidence even without systemd-coredump."""
    patterns = [
        os.path.expanduser("~/.mozilla/firefox/*/minidumps/*.dmp"),
        os.path.expanduser("~/.mozilla/firefox/Crash Reports/pending/*.dmp"),
        os.path.expanduser("~/ff-core2-crashes/**/*.dmp"),
        os.path.expanduser("~/ff-control-crashes/**/*.dmp"),
    ]
    added = 0
    for pattern in patterns:
        for path in glob.glob(pattern, recursive=True):
            try:
                st = os.stat(path)
            except OSError:
                continue
            ts_s = datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"
            )
            fp = sha256_text(f"minidump|{path}|{st.st_mtime_ns}")[:40]
            if conn.execute("SELECT 1 FROM crashes WHERE fingerprint=?", (fp,)).fetchone():
                continue
            tag = "core2-run" if "core2" in path else ("control-run" if "control" in path else "profile")
            conn.execute(
                "INSERT OR IGNORE INTO crashes"
                "(ts,pid,comm,exe,sig,corefile,cpus_allowed,core2_involved,context,fingerprint)"
                " VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    ts_s, None, "firefox-esr",
                    "firefox-esr", "minidump", path,
                    ",".join(map(str, config.CORE2_CPUS)) if tag == "core2-run" else None,
                    1 if tag == "core2-run" else None,
                    f"Firefox minidump ({tag}); size={st.st_size}",
                    fp,
                ),
            )
            added += 1
    return added


def ingest_all(conn) -> dict:
    result = {"journal": 0, "shutdown": 0, "coredumps": 0, "minidumps": 0}
    try:
        result["journal"] = ingest_journal(conn)
    except Exception as exc:  # noqa: BLE001 - one source must not stop the others
        result["journal_error"] = str(exc)[:300]
    try:
        result["shutdown"] = shutdown.replay(conn)
    except Exception as exc:  # noqa: BLE001
        result["shutdown_error"] = str(exc)[:300]
    try:
        result["coredumps"] = ingest_coredumps(conn)
    except Exception as exc:  # noqa: BLE001
        result["coredump_error"] = str(exc)[:300]
    try:
        result["minidumps"] = ingest_minidumps(conn)
    except Exception as exc:  # noqa: BLE001
        result["minidump_error"] = str(exc)[:300]
    return result
