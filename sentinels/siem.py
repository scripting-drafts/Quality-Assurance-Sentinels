"""Export QA Sentinels findings to a structured SIEM endpoint.

The exporter is deliberately append-only and idempotent: the SIEM deduplicates
by ``event_id``, so overlapping lookback windows and retries are safe.  Raw
evidence stays on the QA host; only redacted summaries and evidence references
are transmitted.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path

from .util import iso, read_text, redact

SCHEMA_VERSION = "1.0"
ALL_TYPES = ("findings", "events", "crashes", "boots", "hardware", "lsm", "tickets")


class SiemError(RuntimeError):
    """Configuration, transport, or response error."""


@lru_cache(maxsize=1)
def host_id() -> str:
    machine = read_text("/etc/machine-id").strip()
    host = read_text("/proc/sys/kernel/hostname").strip() or os.uname().nodename
    digest = hashlib.sha256(f"{machine}|{host}".encode("utf-8")).hexdigest()
    return f"sha256:{digest[:24]}"


def parse_since(value: str | None, now: datetime | None = None) -> str:
    """Accept 24h/7d/2w shorthand or an ISO-8601 timestamp."""
    now = now or datetime.now(timezone.utc)
    if not value:
        value = "24h"
    match = re.fullmatch(r"(\d+)([hdw])", value.strip())
    if match:
        amount = int(match.group(1))
        unit = match.group(2)
        seconds = amount * {"h": 3600, "d": 86400, "w": 604800}[unit]
        return iso(now - timedelta(seconds=seconds))
    return value


def _types(value) -> tuple[str, ...]:
    if not value:
        return ALL_TYPES
    if isinstance(value, str):
        parts = [part.strip() for part in value.split(",") if part.strip()]
    else:
        parts = [str(part).strip() for part in value if str(part).strip()]
    if "all" in parts:
        return ALL_TYPES
    unknown = sorted(set(parts) - set(ALL_TYPES))
    if unknown:
        raise SiemError(f"unknown event types: {', '.join(unknown)}")
    return tuple(parts) or ALL_TYPES


def _text(value, limit: int = 4000) -> str:
    if value is None:
        return ""
    return redact(str(value))[:limit]


def _fingerprint(value) -> str:
    text = str(value or "")
    if len(text) <= 256:
        return text
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def _compact_id(prefix: str, *parts) -> str:
    raw = ":".join(str(part) for part in parts)
    if len(f"{prefix}:{raw}") <= 200:
        return f"{prefix}:{raw}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return f"{prefix}:sha256:{digest}"


def _base(*, event_id: str, ts: str, event_type: str, source: str, rule: str,
          severity: str, status: str, subject: str, detail: str,
          fingerprint: str, count: int, first_seen: str, last_seen: str,
          tags: list[str], evidence_ref: str = "") -> dict:
    return {
        "schema_version": SCHEMA_VERSION,
        "collector": "qa-sentinels",
        "event_id": event_id,
        "ts": ts,
        "host_id": host_id(),
        "event_type": event_type,
        "source": source,
        "rule": rule,
        "severity": severity,
        "status": status,
        "subject": _text(subject, 256),
        "detail": _text(detail),
        "fingerprint": _fingerprint(fingerprint),
        "count": max(1, int(count or 1)),
        "first_seen": first_seen or ts,
        "last_seen": last_seen or ts,
        "tags": [_text(tag, 64) for tag in tags if tag],
        "evidence_ref": _text(evidence_ref, 512),
    }


def _finding_events(conn, since: str, limit: int) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM findings WHERE COALESCE(last_ts, ts)>=? "
        "ORDER BY COALESCE(last_ts, ts), id LIMIT ?",
        (since, limit),
    ).fetchall()
    out = []
    for row in rows:
        rule = row["rule"] or "finding"
        severity = (row["severity"] or "info").lower()
        status = row["status"] or "open"
        last = row["last_ts"] or row["ts"]
        out.append(_base(
            event_id=_compact_id("finding", row['fingerprint'], status, last),
            ts=last,
            event_type="finding",
            source=rule.split(".", 1)[0],
            rule=rule,
            severity=severity,
            status=status,
            subject=row["subject"] or rule,
            detail=row["detail"] or "",
            fingerprint=row["fingerprint"] or f"finding:{row['id']}",
            count=row["count"] or 1,
            first_seen=row["ts"],
            last_seen=last,
            tags=["finding", rule.split(".", 1)[0], severity],
            evidence_ref=row["evidence_path"] or "",
        ))
    return out


def _event_events(conn, since: str, limit: int) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM events WHERE COALESCE(last_ts, ts)>=? "
        "ORDER BY COALESCE(last_ts, ts), id LIMIT ?",
        (since, limit),
    ).fetchall()
    out = []
    for row in rows:
        severity = (row["severity"] or "info").lower()
        last = row["last_ts"] or row["ts"]
        out.append(_base(
            event_id=_compact_id("event", row['fingerprint'], last),
            ts=last,
            event_type="event",
            source="journal",
            rule=f"journal.{severity}",
            severity=severity,
            status="observed",
            subject=row["comm"] or row["unit"] or "journal",
            detail=row["message"] or "",
            fingerprint=row["fingerprint"] or f"event:{row['id']}",
            count=row["count"] or 1,
            first_seen=row["ts"],
            last_seen=last,
            tags=["journal", row["unit"] or "", severity],
        ))
    return out


def _crash_events(conn, since: str, limit: int) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM crashes WHERE ts>=? ORDER BY ts, id LIMIT ?",
        (since, limit),
    ).fetchall()
    out = []
    for row in rows:
        core2 = row["core2_involved"] == 1
        out.append(_base(
            event_id=_compact_id("crash", row['fingerprint']),
            ts=row["ts"],
            event_type="crash",
            source="coredump",
            rule="crash.core2" if core2 else "crash",
            severity="critical" if core2 else "warning",
            status="observed",
            subject=row["comm"] or row["exe"] or "crash",
            detail=row["context"] or row["sig"] or "",
            fingerprint=row["fingerprint"] or f"crash:{row['id']}",
            count=1,
            first_seen=row["ts"],
            last_seen=row["ts"],
            tags=["crash", "core2" if core2 else "affinity"],
        ))
    return out


def _boot_events(conn, since: str, limit: int) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM boots WHERE COALESCE(captured_ts, last_ts)>=? "
        "ORDER BY COALESCE(captured_ts, last_ts), id LIMIT ?",
        (since, limit),
    ).fetchall()
    out = []
    for row in rows:
        ts = row["captured_ts"] or row["last_ts"] or iso()
        unclean = row["ended_clean"] == 0
        out.append(_base(
            event_id=_compact_id("boot", row['boot_id'], ts),
            ts=ts,
            event_type="boot",
            source="boot",
            rule="boot.unclean" if unclean else "boot.clean",
            severity="warning" if unclean else "info",
            status="observed",
            subject=row["boot_id"],
            detail=row["last_message"] or row["span"] or "",
            fingerprint=f"boot:{row['boot_id']}",
            count=1,
            first_seen=ts,
            last_seen=ts,
            tags=["boot", "unclean" if unclean else "clean"],
        ))
    return out


def _hardware_events(conn, since: str, limit: int) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM hardware_runs WHERE ts>=? ORDER BY ts, id LIMIT ?",
        (since, limit),
    ).fetchall()
    out = []
    for row in rows:
        ok = (row["status"] or "") == "ok"
        out.append(_base(
            event_id=f"hardware:{row['id']}",
            ts=row["ts"],
            event_type="hardware",
            source="hardware",
            rule="hardware.run",
            severity="info" if ok else "warning",
            status="observed",
            subject=row["status"] or "unknown",
            detail=row["sources"] or row["detail"] or "",
            fingerprint=f"hardware:{row['id']}",
            count=1,
            first_seen=row["ts"],
            last_seen=row["ts"],
            tags=["hardware", row["status"] or "unknown"],
        ))
    return out


def _lsm_events(conn, since: str, limit: int) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM lsm_runs WHERE ts>=? ORDER BY ts, id LIMIT ?",
        (since, limit),
    ).fetchall()
    out = []
    for row in rows:
        ok = (row["status"] or "") == "ok"
        out.append(_base(
            event_id=f"lsm:{row['id']}",
            ts=row["ts"],
            event_type="lsm",
            source="lsm",
            rule="lsm.run",
            severity="info" if ok else "warning",
            status="observed",
            subject=row["digest"] or row["status"] or "lsm",
            detail=row["state"] or row["denials"] or "",
            fingerprint=f"lsm:{row['id']}",
            count=1,
            first_seen=row["ts"],
            last_seen=row["ts"],
            tags=["lsm", row["status"] or "unknown"],
        ))
    return out


def _ticket_events(conn, since: str, limit: int) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM ticket_drafts WHERE ts>=? ORDER BY ts, id LIMIT ?",
        (since, limit),
    ).fetchall()
    out = []
    for row in rows:
        out.append(_base(
            event_id=f"ticket:{row['id']}:{row['ts']}",
            ts=row["ts"],
            event_type="ticket",
            source="tickets",
            rule="ticket.draft",
            severity="info",
            status="open",
            subject=row["vendor"] or "ticket",
            detail=row["title"] or "",
            fingerprint=row["issue_key"] or f"ticket:{row['id']}",
            count=1,
            first_seen=row["ts"],
            last_seen=row["ts"],
            tags=["ticket", row["vendor"] or ""],
            evidence_ref=row["path"] or "",
        ))
    return out


_BUILDERS = {
    "findings": _finding_events,
    "events": _event_events,
    "crashes": _crash_events,
    "boots": _boot_events,
    "hardware": _hardware_events,
    "lsm": _lsm_events,
    "tickets": _ticket_events,
}


def build_events(conn, since: str = "24h", types=None, limit: int = 5000) -> list[dict]:
    """Build normalized, redacted SIEM envelopes from the local database."""
    since_iso = parse_since(since)
    selected = _types(types)
    limit = max(1, min(int(limit), 50000))
    out: list[dict] = []
    for name in selected:
        builder = _BUILDERS.get(name)
        if not builder:
            continue
        out.extend(builder(conn, since_iso, limit))
        if len(out) >= limit:
            break
    return out[:limit]


def write_jsonl(events: list[dict], stream=None) -> None:
    stream = stream or sys.stdout
    for event in events:
        stream.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")


def _loopback(host: str | None) -> bool:
    if not host:
        return False
    return host in ("localhost", "127.0.0.1", "::1")


def load_config(path: str | Path) -> dict:
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise SiemError(f"cannot read {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise SiemError("SIEM config must be a JSON object")
    endpoint = str(data.get("endpoint") or "").strip()
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise SiemError("endpoint must be an http(s) URL")
    if parsed.scheme == "http" and not _loopback(parsed.hostname) and not data.get("allow_insecure_http"):
        raise SiemError("refusing plaintext HTTP to a non-loopback SIEM endpoint")
    token = ""
    token_env = str(data.get("token_env") or "QA_SIEM_TOKEN")
    if os.environ.get(token_env):
        token = os.environ[token_env].strip()
    elif data.get("token_file"):
        token_path = Path(str(data["token_file"]))
        try:
            token = token_path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise SiemError(f"cannot read token file {token_path}: {exc}") from exc
        try:
            if token_path.stat().st_mode & 0o007:
                print(f"warning: {token_path} is group/world-accessible", file=sys.stderr)
        except OSError:
            pass
    if not token:
        raise SiemError(f"no SIEM token in ${token_env} or token_file")
    batch_size = int(data.get("batch_size") or 200)
    timeout_s = int(data.get("timeout_s") or 15)
    lookback_hours = int(data.get("lookback_hours") or 24)
    if not 1 <= batch_size <= 1000:
        raise SiemError("batch_size must be 1..1000")
    if not 1 <= timeout_s <= 120:
        raise SiemError("timeout_s must be 1..120")
    if not 1 <= lookback_hours <= 720:
        raise SiemError("lookback_hours must be 1..720")
    return {
        "endpoint": endpoint,
        "token": token,
        "batch_size": batch_size,
        "timeout_s": timeout_s,
        "lookback_hours": lookback_hours,
        "types": _types(data.get("types")),
        "verify_tls": bool(data.get("verify_tls", True)),
        "ca_file": str(data.get("ca_file") or ""),
    }


def _post_batch(cfg: dict, events: list[dict]) -> dict:
    body = json.dumps(events, separators=(",", ":")).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {cfg['token']}",
        "User-Agent": f"qa-sentinels/{SCHEMA_VERSION}",
    }
    request = urllib.request.Request(
        cfg["endpoint"], data=body, headers=headers, method="POST"
    )
    context = None
    if cfg["endpoint"].startswith("https://"):
        context = ssl.create_default_context(cafile=cfg["ca_file"] or None)
        if not cfg["verify_tls"]:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
    try:
        with urllib.request.urlopen(
            request, timeout=cfg["timeout_s"], context=context
        ) as response:
            payload = response.read(1024 * 1024).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read(4096).decode("utf-8", "replace")
        raise SiemError(f"SIEM HTTP {exc.code}: {detail[:300]}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise SiemError(f"SIEM transport: {exc}") from exc
    try:
        result = json.loads(payload)
    except ValueError as exc:
        raise SiemError("SIEM returned non-JSON") from exc
    if not isinstance(result, dict):
        raise SiemError("SIEM returned an unexpected response")
    return result


def forward(conn, cfg: dict, *, since: str | None = None, types=None,
            limit: int = 5000, dry_run: bool = False) -> dict:
    since_value = since or f"{cfg['lookback_hours']}h"
    events = build_events(conn, since_value, types or cfg["types"], limit)
    if dry_run:
        write_jsonl(events)
        return {
            "events": len(events), "batches": 0, "accepted": 0,
            "duplicates": 0, "dry_run": True, "since": parse_since(since_value),
        }
    accepted = duplicates = rejected = 0
    batches = 0
    for start in range(0, len(events), cfg["batch_size"]):
        batch = events[start:start + cfg["batch_size"]]
        result = _post_batch(cfg, batch)
        batches += 1
        accepted += int(result.get("accepted") or 0)
        duplicates += int(result.get("duplicates") or 0)
        rejected += int(result.get("rejected") or 0)
        if rejected:
            errors = result.get("errors") or []
            raise SiemError(f"SIEM rejected {rejected} events: {errors[:3]}")
    return {
        "events": len(events), "batches": batches, "accepted": accepted,
        "duplicates": duplicates, "rejected": rejected,
        "since": parse_since(since_value), "endpoint": cfg["endpoint"],
    }
