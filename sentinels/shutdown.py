"""Shutdown listener for systemd service and mount failures.

Layer 1 samples a running system, but the final seconds before power-off are
written after the last routine cycle.  A unit can fail to start during boot or
while services are stopped, and a filesystem can fail to unmount.  A volatile
journal then loses the evidence at the next boot.

``qa shutdown --capture`` is installed as a ``final.target`` service.  It runs
after normal services and mounts are gone, reads the current boot's matching
failures, and stores them under ``var/shutdown`` as two phases: ``boot`` and
``shutdown``.  The next routine ingest replays them into the events table,
where the normal layer-1 rules turn them into findings.  On systems without
the unit, the same scan is reconstructed from the previous boot's journal.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timedelta, timezone

from . import classify, config
from .util import iso, parse_iso, redact, run, sha256_text, utcnow

SCHEMA_VERSION = 2
START_GRACE_S = 30

# The logind marker is written before services and mounts are stopped, so it is
# the earliest reliable start of the final shutdown sequence.  The later
# markers are fallbacks for hosts that do not run logind.
LOGIND_GREP = r"^System is (powering down|rebooting|halting|kexecing)\.$"
START_GREP = (
    r"^System is (powering down|rebooting|halting|kexecing)\.$|"
    r"^Shutting down\.$|^Reached target System Shutdown\.$"
)

FAILURE_RULES = [
    ("shutdown.service_start", "service failed to start",
     re.compile(r"(?i)\bFailed to start\b")),
    ("shutdown.unmount", "filesystem failed to unmount",
     re.compile(r"(?i)\bFailed (?:unmounting|to unmount)\b")),
    ("shutdown.unit_stop", "unit failed to stop",
     re.compile(r"(?i)\bFailed to stop\b")),
    ("shutdown.systemd", "shutdown failure",
     re.compile(r"(?i)\bFailed to (?:finalize|kill|send|wait|enqueue|isolate|switch)\b")),
]

# One server-side filter for the journal.  journalctl's --grep uses PCRE, so
# the case-insensitive option is set once at the front.
FAILURE_GREP = (
    r"(?i)(?:\bFailed to start\b|"
    r"\bFailed (?:unmounting|to unmount)\b|"
    r"\bFailed to stop\b|"
    r"\bFailed to (?:finalize|kill|send|wait|enqueue|isolate|switch)\b)"
)

_URL_RE = re.compile(r"https?://\S+")
_PATH_RE = re.compile(r"(?<![\w:])/(?:[\w.@+-]+/)+[\w.@+-]*")
_USER_PATH_RE = re.compile(r"(?<![\w:])(/(?:home|media|Users)/)[^/\s]+")


# ---------------------------------------------------------------- journal
def _message(entry: dict) -> str:
    msg = entry.get("MESSAGE", "")
    if isinstance(msg, list):
        try:
            msg = bytes(msg).decode("utf-8", "replace")
        except Exception:  # noqa: BLE001 - malformed journal fields are skipped
            msg = str(msg)
    return str(msg or "").replace("\x00", "").strip()


def _timestamp(entry: dict) -> str:
    usec = entry.get("__REALTIME_TIMESTAMP")
    try:
        return datetime.fromtimestamp(
            int(usec) / 1_000_000, tz=timezone.utc
        ).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (TypeError, ValueError, OSError):
        return ""


def _epoch(entry: dict) -> float | None:
    try:
        return int(entry["__REALTIME_TIMESTAMP"]) / 1_000_000
    except (KeyError, TypeError, ValueError):
        return None


def _unit(entry: dict) -> str:
    unit = entry.get("_SYSTEMD_UNIT") or ""
    if not unit and entry.get("SYSLOG_IDENTIFIER"):
        unit = f"ident:{entry['SYSLOG_IDENTIFIER']}"
    return str(unit)


def _source(entry: dict) -> str:
    if not entry.get("_SYSTEMD_UNIT") and (
        entry.get("_TRANSPORT") == "kernel"
        or entry.get("SYSLOG_IDENTIFIER") == "kernel"
    ):
        return "kernel"
    return "journal"


def _priority(entry: dict) -> int | None:
    try:
        return int(entry.get("PRIORITY"))
    except (TypeError, ValueError):
        return None


def _bucket(ts: str) -> str:
    try:
        return ts[:14] + f"{int(ts[14:16]) - int(ts[14:16]) % 5:02d}"
    except (TypeError, ValueError):
        return ts[:16]


def _fingerprint(source: str, unit: str, signature: str, ts: str) -> str:
    # Keep this identical to ingest.ingest_journal so a shutdown capture and a
    # later journal read cannot create two rows for the same event.
    return sha256_text(f"{source}|{unit}|{signature}|{_bucket(ts)}")[:40]


def _parse(out: str) -> list[dict]:
    entries = []
    for line in out.splitlines():
        if not line.strip():
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(entry, dict):
            entries.append(entry)
    return entries


def _journal(args: list[str], timeout: int = 60) -> list[dict]:
    rc, out, _err = run(
        ["journalctl", "--no-pager", "-o", "json", *args], timeout=timeout
    )
    return _parse(out) if rc == 0 else []


def _failure_entries(boot_ref: str) -> list[dict]:
    """Matching warning-or-worse entries from the whole boot."""
    rc, out, _err = run(
        ["journalctl", "--no-pager", "-o", "json", "-b", str(boot_ref),
         "-p", "warning", "--grep", FAILURE_GREP],
        timeout=60,
    )
    if rc == 0:
        return _parse(out)
    # Older journalctl without --grep: filter a bounded priority view.
    return _journal(["-b", str(boot_ref), "-p", "warning"])


def _current_boot_id() -> str:
    try:
        with open("/proc/sys/kernel/random/boot_id", encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def _boot_id(boot_ref: str) -> str:
    if str(boot_ref) == "0":
        return _current_boot_id()
    entries = _journal(["-b", str(boot_ref), "-n", "1"])
    return str((entries[-1] if entries else {}).get("_BOOT_ID") or "")


def _systemd_marker(entry: dict) -> bool:
    unit = str(entry.get("_SYSTEMD_UNIT") or "")
    return (
        unit in ("init.scope", "systemd-logind.service")
        or entry.get("SYSLOG_IDENTIFIER") == "systemd"
    )


def _start_time(boot_ref: str) -> str:
    """Latest shutdown marker in one boot, or empty when none is logged."""
    for pattern in (LOGIND_GREP, START_GREP):
        entries = _journal(
            ["-b", str(boot_ref), "--grep", pattern, "--reverse"], timeout=30
        )
        for entry in entries:
            if not _systemd_marker(entry):
                continue
            stamp = _timestamp(entry)
            if stamp:
                return stamp
    return ""


# ---------------------------------------------------------------- redaction
def _redact_message(msg: str, mode: str) -> str:
    if mode == "metadata":
        return ""
    text = _USER_PATH_RE.sub(r"\1<user>", redact(msg))
    if mode == "collapsed":
        text = _URL_RE.sub("<url>", text)
        text = _PATH_RE.sub("<path>", text)
    return text


def _match(entry: dict, phase: str = "shutdown", mode: str | None = None) -> dict | None:
    msg = _message(entry)
    if not msg:
        return None
    for rule, label, pattern in FAILURE_RULES:
        if not pattern.search(msg):
            continue
        ts = _timestamp(entry)
        unit = _unit(entry)
        source = _source(entry)
        signature = classify.signature(msg, 200)
        severity = classify.classify(msg, _priority(entry))
        if severity == "noise":
            return None
        return {
            "phase": phase,
            "ts": ts,
            "last_ts": ts,
            "count": 1,
            "boot_id": str(entry.get("_BOOT_ID") or ""),
            "source": source,
            "unit": unit,
            "severity": severity,
            "rule": rule,
            "label": label,
            "message": _redact_message(msg, mode or config.CAPTURE_REDACTION),
            "fingerprint": _fingerprint(source, unit, signature, ts),
        }
    return None


def _phase(entry: dict, shutdown_epoch: float | None) -> str:
    if shutdown_epoch is None:
        return "boot"
    stamp = _epoch(entry)
    if stamp is not None and stamp >= shutdown_epoch - START_GRACE_S:
        return "shutdown"
    return "boot"


def _summary(items: list[dict], phase: str) -> dict:
    selected = [item for item in items if item["phase"] == phase]
    stamps = [item["ts"] for item in selected if item["ts"]]
    ends = [item["last_ts"] for item in selected if item["last_ts"]]
    return {
        "count": sum(int(item.get("count") or 1) for item in selected),
        "signatures": len(selected),
        "start": min(stamps) if stamps else "",
        "end": max(ends) if ends else "",
    }


def _scan(boot_ref: str, boot_id: str = "") -> dict:
    start = _start_time(boot_ref)
    try:
        shutdown_epoch = parse_iso(start).timestamp() if start else None
    except (TypeError, ValueError):
        shutdown_epoch = None

    grouped: dict[str, dict] = {}
    for entry in _failure_entries(boot_ref):
        phase = _phase(entry, shutdown_epoch)
        if phase == "shutdown" and not start:
            continue
        item = _match(entry, phase=phase)
        if item is None:
            continue
        fingerprint = item["fingerprint"]
        existing = grouped.get(fingerprint)
        if existing is None:
            grouped[fingerprint] = item
        else:
            existing["count"] = int(existing.get("count") or 1) + 1
            if item["ts"] and (
                not existing["ts"] or item["ts"] < existing["ts"]
            ):
                existing["ts"] = item["ts"]
            if item["last_ts"] and (
                not existing["last_ts"] or item["last_ts"] > existing["last_ts"]
            ):
                existing["last_ts"] = item["last_ts"]

    items = list(grouped.values())
    if not config.CAPTURE_BOOT:
        items = [item for item in items if item["phase"] == "shutdown"]

    items.sort(key=lambda item: (item["ts"], item["unit"], item["fingerprint"]))
    shutdown = _summary(items, "shutdown")
    return {
        "schema_version": SCHEMA_VERSION,
        "boot_id": boot_id or _boot_id(boot_ref),
        "captured_ts": iso(),
        "redaction": config.CAPTURE_REDACTION,
        "phases": {
            "boot": _summary(items, "boot"),
            "shutdown": shutdown,
        },
        "count": sum(int(item.get("count") or 1) for item in items),
        "errors": items,
        # Kept for readers of the version-1 record layout.
        "window_start": shutdown["start"],
        "window_end": shutdown["end"],
    }


# ---------------------------------------------------------------- storage
def _path(boot_id: str):
    return config.SHUTDOWN_DIR / f"{boot_id}.json"


def load(boot_id: str) -> dict | None:
    if not boot_id:
        return None
    try:
        record = json.loads(_path(boot_id).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(record, dict) or record.get("boot_id") != boot_id:
        return None
    return record


def _write(record: dict) -> None:
    config.ensure_dirs()
    path = _path(record["boot_id"])
    fd, tmp = tempfile.mkstemp(
        prefix=f".{record['boot_id']}.", suffix=".tmp", dir=str(config.SHUTDOWN_DIR)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(record, fh, indent=2, sort_keys=True)
            fh.write("\n")
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _empty(boot_id: str = "") -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "boot_id": boot_id,
        "captured_ts": "",
        "redaction": config.CAPTURE_REDACTION,
        "phases": {
            "boot": {"count": 0, "signatures": 0, "start": "", "end": ""},
            "shutdown": {"count": 0, "signatures": 0, "start": "", "end": ""},
        },
        "count": 0,
        "errors": [],
        "window_start": "",
        "window_end": "",
    }


def capture(boot_ref: str = "0") -> dict:
    """Scan the current boot and persist its boot and shutdown failures."""
    record = _scan(str(boot_ref), _current_boot_id())
    if record["boot_id"]:
        _write(record)
    return record


def scan_boot(
    boot_ref: str = "-1",
    boot_id: str = "",
    refresh: bool = False,
    journal: bool = True,
) -> dict:
    """Return a capture record, re-reading the journal only when needed."""
    resolved = boot_id or _boot_id(str(boot_ref))
    if not journal:
        return load(resolved) or _empty(resolved)
    if not refresh:
        record = load(resolved)
        if record is not None:
            return record
    return _scan(str(boot_ref), resolved)


def records(limit: int = 20) -> list[dict]:
    try:
        paths = sorted(
            config.SHUTDOWN_DIR.glob("*.json"),
            key=lambda p: p.stat().st_mtime,
            reverse=True,
        )
    except OSError:
        return []
    out = []
    for path in paths[:limit]:
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(record, dict):
            out.append(record)
    return out


def prune() -> int:
    """Drop capture records beyond the event-retention window."""
    if config.SHUTDOWN_RETENTION_DAYS <= 0:
        return 0
    cutoff = utcnow() - timedelta(days=config.SHUTDOWN_RETENTION_DAYS)
    removed = 0
    for path in config.SHUTDOWN_DIR.glob("*.json"):
        try:
            stamp = path.stat().st_mtime
        except OSError:
            continue
        if stamp < cutoff.timestamp():
            try:
                path.unlink()
                removed += 1
            except OSError:
                pass
    return removed


_RULE_PHRASES = {
    "shutdown.service_start": "Failed to start",
    "shutdown.unmount": "Failed to unmount",
    "shutdown.unit_stop": "Failed to stop",
    "shutdown.systemd": "Failed to finalize",
}


def _replay_message(item: dict, record: dict) -> str:
    msg = str(item.get("message") or "").strip()
    if msg:
        return msg
    rule = str(item.get("rule") or "")
    phrase = _RULE_PHRASES.get(rule, "Failed shutdown step")
    unit = str(item.get("unit") or "systemd")
    if record.get("redaction") == "metadata":
        return f"[metadata-only] {phrase} in {unit}"
    return f"{phrase} in {unit}"


def replay(conn) -> int:
    """Insert captured failures as events; safe to call repeatedly."""
    current = _current_boot_id()
    added = 0
    for record in records(limit=200):
        boot_id = str(record.get("boot_id") or "")
        if not boot_id or boot_id == current:
            continue
        for item in record.get("errors") or []:
            if not isinstance(item, dict):
                continue
            msg = _replay_message(item, record)
            if not msg:
                continue
            severity = str(item.get("severity") or "")
            if severity == "noise":
                continue
            ts = str(item.get("ts") or record.get("captured_ts") or iso())
            last_ts = str(item.get("last_ts") or ts)
            unit = str(item.get("unit") or "")
            source = str(item.get("source") or "journal")
            fingerprint = str(item.get("fingerprint") or "")
            if not fingerprint:
                fingerprint = _fingerprint(
                    source, unit, classify.signature(msg, 200), ts
                )
            count = int(item.get("count") or 1)
            cur = conn.execute(
                "INSERT OR IGNORE INTO events"
                "(ts,boot_id,source,severity,unit,pid,comm,message,fingerprint,raw,count,last_ts)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    ts,
                    boot_id,
                    source,
                    severity or "error",
                    unit,
                    None,
                    None,
                    msg,
                    fingerprint,
                    json.dumps(item, sort_keys=True),
                    count,
                    last_ts,
                ),
            )
            added += cur.rowcount
    prune()
    return added
