"""Layer 1: real-time bug detection and evidence escalation.

Cheap rules run on every tick over new crashes, new journal events and the
latest kernel/memory/CPU sample. Findings are deduplicated and stored so the
deep layer (layer 2) can be triggered deliberately, not blindly.
"""
from __future__ import annotations

import re
from datetime import timedelta

from . import boot, classify, config, faultcore, db, holds, triage
from .util import iso, parse_iso, sha256_text, utcnow

# journal rules, highest severity first
EVENT_RULES = [
    ("kernel.hardware", "critical",
     re.compile(r"(?i)\b(?:mce|machine check|hardware error|edac|ras)\b")),
    ("kernel.oops", "critical",
     re.compile(r"(?i)kernel panic|\boops\b|BUG:|general protection fault|"
                r"soft lockup|hard lockup|hung task|watchdog: BUG")),
    ("memory.oom", "critical", re.compile(r"(?i)out of memory|oom-kill")),
    ("gpu.xid", "critical", re.compile(r"(?i)\bXid\b|GPU has fallen off the bus")),
    ("nvrm.error", "error",
     re.compile(r"(?i)NVRM: .*(?:error|fatal|assert|video memory|out of memory)")),
    # Service start and unmount failures are ordinary error-priority journal
    # messages.  They are the shutdown listener's main payload, but the same
    # rule also tracks a start failure that happens during normal boot.
    ("systemd.service_start", "error",
     re.compile(r"(?i)\bFailed to start\b")),
    ("systemd.unmount", "error",
     re.compile(r"(?i)\bFailed (?:unmounting|to unmount)\b")),
    ("systemd.unit_stop", "error",
     re.compile(r"(?i)\bFailed to stop\b")),
    ("systemd.shutdown", "error",
     re.compile(r"(?i)\bFailed to (?:finalize|kill|send|wait|enqueue|isolate|switch)\b")),
]


SELF_NOISE = re.compile(
    r"(?i)qa-sentinels|quality assurance sentinels|quality-assurance-sentinels|"
    r"sudo:auth|auth could not identify password|"
    r"a password is required\s*;|COMMAND=/usr/bin/true"
)

# Recurring service and mount failures are one issue, not one finding per
# five-minute journal bucket.  Group them by stable signature.
GROUPED_EVENT_RULES = {
    "systemd.service_start", "systemd.unmount", "systemd.unit_stop",
    "systemd.shutdown",
}


def _case_id(conn, subject: str, signature: str | None = None) -> int | None:
    for case in triage.cases(conn, limit=200):
        if subject and subject == case["process"]:
            return case["id"]
        if signature and signature[:60] and signature[:60] in (case["signature"] or ""):
            return case["id"]
    return None


def _upsert(conn, finding: dict) -> dict | None:
    now = iso()
    existing = conn.execute(
        "SELECT * FROM findings WHERE fingerprint=?", (finding["fingerprint"],)
    ).fetchone()
    if existing:
        status = "open" if existing["status"] == "resolved" else existing["status"]
        conn.execute(
            "UPDATE findings SET last_ts=?, count=count+1, detail=?, case_id=COALESCE(?, case_id),"
            " status=? WHERE id=?",
            (finding["last_ts"], finding["detail"], finding.get("case_id"),
             status, existing["id"]),
        )
        return None
    cur = conn.execute(
        "INSERT INTO findings(fingerprint,ts,last_ts,rule,severity,subject,detail,count,"
        "status,case_id) VALUES(?,?,?,?,?,?,?,1,'open',?)",
        (
            finding["fingerprint"], finding["ts"], finding["last_ts"], finding["rule"],
            finding["severity"], finding["subject"], finding["detail"], finding.get("case_id"),
        ),
    )
    created = dict(finding)
    created["id"] = cur.lastrowid
    return created


def upsert(conn, finding: dict) -> dict | None:
    """Public wrapper used by security and other layer-1 rule sets."""
    return _upsert(conn, finding)


def _crash_findings(conn, since: str) -> list[dict]:
    out = []
    for row in conn.execute(
        "SELECT * FROM crashes WHERE ts>=? ORDER BY ts DESC", (since,)
    ):
        row = dict(row)
        subject = row["comm"] or row["exe"] or "unknown"
        if row["faultcore_involved"] == 1:
            rule, severity = "crash.faultcore", "critical"
        elif row["faultcore_involved"] is None and triage._browserish(row):
            rule, severity = "crash.affinity_unknown", "warning"
        else:
            continue
        hold = holds.relevant(row["exe"])
        held_note = ""
        if hold["outdated"]:
            held_note = "; held-outdated " + ", ".join(
                f"{h['package']} {h['installed']}->{h['candidate']}"
                for h in hold["outdated"][:3]
            )
        elif hold["mass_hold"]:
            held_note = f"; global hold ({hold['held_total']} packages pinned)"
        out.append(
            {
                "held": hold,
                "fingerprint": "crash|" + (row["fingerprint"] or sha256_text(str(row))[:32]),
                "ts": row["ts"],
                "last_ts": row["ts"],
                "rule": rule,
                "severity": severity,
                "subject": subject,
                "detail": f"{row['sig']} affinity={row['cpus_allowed'] or 'unknown'} "
                          f"fault_core={row['faultcore_involved']}{held_note}",
                "case_id": _case_id(conn, subject),
            }
        )
    return out


def _event_findings(conn, since: str) -> list[dict]:
    out = []
    grouped: dict[tuple[str, str], dict] = {}
    for row in conn.execute(
        "SELECT * FROM events WHERE ts>=? AND severity IN ('critical','error')"
        " ORDER BY ts DESC LIMIT 5000",
        (since,),
    ):
        msg = row["message"] or ""
        if SELF_NOISE.search(msg):
            continue
        matched = False
        for rule, severity, pattern in EVENT_RULES:
            if pattern.search(msg):
                matched = True
                break
        if not matched:
            if row["severity"] != "critical":
                continue
            rule, severity = "journal.critical", "warning"
        unit = (row["unit"] or "").split(".")[0]
        if rule in GROUPED_EVENT_RULES:
            signature = classify.signature(msg, 200)
            key = (rule, signature)
            item = grouped.get(key)
            if item is None:
                grouped[key] = {
                    "fingerprint": f"event|{rule}|{sha256_text(signature)[:32]}",
                    "ts": row["ts"],
                    "last_ts": row["last_ts"] or row["ts"],
                    "rule": rule,
                    "severity": severity,
                    "subject": unit or "kernel",
                    "detail": msg,
                    "count": int(row["count"] or 1),
                    "case_id": _case_id(conn, unit, msg),
                }
            else:
                item["ts"] = min(item["ts"], row["ts"])
                item["last_ts"] = max(
                    item["last_ts"], row["last_ts"] or row["ts"]
                )
                item["count"] += int(row["count"] or 1)
                item["detail"] = msg
                item["subject"] = unit or item["subject"]
            continue
        out.append(
            {
                "fingerprint": f"event|{rule}|{row['fingerprint']}",
                "ts": row["ts"],
                "last_ts": row["last_ts"] or row["ts"],
                "rule": rule,
                "severity": severity,
                "subject": unit or "kernel",
                "detail": msg,
                "case_id": _case_id(conn, unit, msg),
            }
        )
    for item in grouped.values():
        item["detail"] = (
            f"{item['detail']} ({item['count']} occurrence(s) in window)"
        )
        item.pop("count", None)
        out.append(item)
    return out


def _sample_findings(conn) -> list[dict]:
    row = conn.execute("SELECT ts, payload FROM samples ORDER BY ts DESC LIMIT 1").fetchone()
    if not row:
        return []
    import json

    data = json.loads(row["payload"])
    ts = row["ts"]
    bucket = ts[:15]  # 10-minute buckets
    mem = data.get("mem", {})
    total = mem.get("MemTotal") or 0
    avail = mem.get("MemAvailable")
    out = []

    def add(rule, severity, subject, detail, fingerprint_rule=None):
        fingerprint_rule = fingerprint_rule or rule
        out.append(
            {
                "fingerprint": f"sample|{fingerprint_rule}|{bucket}",
                "ts": ts,
                "last_ts": ts,
                "rule": rule,
                "severity": severity,
                "subject": subject,
                "detail": detail,
                "case_id": None,
            }
        )

    if total and avail is not None:
        pct = 100.0 * avail / total
        if pct < config.MEM_AVAILABLE_ALERT_PCT:
            add("memory.low", "critical", "memory",
                f"MemAvailable {pct:.1f}% ({avail} kB of {total} kB)")

    mem_psi = data.get("psi", {}).get("memory", {}).get("full", {}).get("avg300")
    if mem_psi is not None and mem_psi >= config.PSI_MEMORY_FULL_ALERT:
        add("memory.pressure", "warning", "memory", f"PSI memory full avg300={mem_psi}")

    io_psi = data.get("psi", {}).get("io", {}).get("some", {}).get("avg300")
    if io_psi is not None and io_psi >= config.IO_PRESSURE_ALERT:
        add("io.pressure", "warning", "io", f"PSI io some avg300={io_psi}")

    hottest = None
    for t in data.get("thermal", []):
        c = t.get("millideg_c", 0) / 1000.0
        if hottest is None or c > hottest[1]:
            hottest = (t.get("type"), c)
    if hottest and hottest[1] >= config.TEMP_ALERT_C:
        add("thermal.high", "warning", str(hottest[0]),
            f"thermal zone {hottest[0]} at {hottest[1]:.1f} C")
    return out


def scan(conn, hours: int = 24) -> list[dict]:
    """Run layer-1 rules; return only newly created findings."""
    last = db.meta_get(conn, "last_finding_scan")
    now = utcnow()
    since = (
        (parse_iso(last) - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        if last
        else (now - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    )
    # New rule sets must see the events that predate their deployment.  The
    # one-time backfill also updates existing findings instead of duplicating
    # them, because every rule fingerprints by its own evidence.
    backfill = not db.meta_get(conn, "event_rules_backfill_v1")
    if backfill:
        window = (now - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
        since = min(since, window)
    candidates = (
        _crash_findings(conn, since)
        + _event_findings(conn, since)
        + _sample_findings(conn)
        + faultcore.findings(conn)
        + boot.findings(conn, since)
    )
    new = []
    for finding in candidates:
        created = _upsert(conn, finding)
        if created:
            new.append(created)
    db.meta_set(conn, "last_finding_scan", iso(now))
    if backfill:
        db.meta_set(conn, "event_rules_backfill_v1", iso(now))
    return new


def queue_escalations(conn, findings: list[dict], cooldown_s: int | None = None) -> list[str]:
    """Queue layer-2 deep runs for critical findings, respecting a cooldown."""
    from . import deep

    cooldown = config.DEEP_REQUEST_COOLDOWN_S if cooldown_s is None else cooldown_s
    queued = []
    for finding in findings:
        if finding["severity"] != "critical" or not config.DEEP_AUTO:
            continue
        # layer 2 traces a live process; a boot that already ended cannot be traced
        if finding["rule"].startswith("boot."):
            continue
        key = "deep_req|" + finding["fingerprint"]
        last_req = db.meta_get(conn, key)
        age = (utcnow() - parse_iso(last_req)).total_seconds() if last_req else 1e9
        if age < cooldown:
            continue
        # a crash in a held, outdated module may already be fixed upstream
        hold = finding.get("held") or {}
        queued.append(
            deep.enqueue(
                conn, case_id=finding.get("case_id"), finding_id=finding["id"],
                reason=f"auto:{finding['rule']}", comm=finding["subject"],
                held_packages=hold.get("relevant"), hold_summary=hold or None,
            )
        )
        db.meta_set(conn, key, iso())
    return queued


def list_findings(conn, limit: int = 100, status: str | None = None) -> list[dict]:
    sql = "SELECT * FROM findings"
    args: list = []
    if status:
        sql += " WHERE status=?"
        args.append(status)
    sql += " ORDER BY ts DESC LIMIT ?"
    args.append(limit)
    return [dict(r) for r in conn.execute(sql, args)]


def set_status(conn, finding_id: int, status: str) -> bool:
    if status not in ("open", "investigating", "resolved", "dismissed"):
        raise ValueError("bad finding status")
    cur = conn.execute(
        "UPDATE findings SET status=? WHERE id=?", (status, finding_id)
    )
    return cur.rowcount > 0
