"""Fault-core triage side queue.

Fault-core-related evidence is not deleted or hidden: confirmed, suspected,
control and unresolved-affinity cases are copied into a separate working
dossier under triage/faultcore/ so they can be investigated on their own.

They remain part of the main QA record and vendor evidence.
"""
from __future__ import annotations

import json
import re
from datetime import timedelta

from . import config, db
from .util import iso, parse_iso, read_text, redact, sha256_text, utcnow

VERDICT_ORDER = {"confirmed": 0, "suspected": 1, "unresolved": 2, "control": 3}
STATUSES = ("open", "investigating", "confirmed", "dismissed")


def _event_cpus() -> list[int]:
    cpus = set(config.FAULT_CORE_CPUS)
    if config.FAULT_CORE_PHYSICAL_ID is not None:
        cpus.add(config.FAULT_CORE_PHYSICAL_ID)
    return sorted(cpus)


def event_is_faultcore(message: str) -> bool:
    cpus = _event_cpus()
    if not cpus:
        return False
    numbers = "|".join(str(cpu) for cpu in cpus)
    pattern = re.compile(
        r"(?i)\b(?:physical\s+core|core|cpu)[# _-]?0*(?:" + numbers + r")\b"
    )
    return bool(pattern.search(message or ""))


def _crash_verdict(faultcore_involved) -> str:
    if faultcore_involved == 1:
        return "confirmed"
    if faultcore_involved == 0:
        return "control"
    return "unresolved"


def _candidate_from_crash(row) -> dict:
    proc = row["comm"] or row["exe"] or "unknown"
    return {
        "case_key": sha256_text(f"crash|{row['fingerprint']}")[:24],
        "kind": "crash",
        "verdict": _crash_verdict(row["faultcore_involved"]),
        "process": proc,
        "signature": f"{proc} {row['sig']}",
        "detail": row["context"] or "",
        "affinity": row["cpus_allowed"] or "unknown",
        "event_ts": row["ts"],
    }


def _candidate_from_event(row) -> dict:
    unit = (row["unit"] or "").split(".")[0]
    return {
        "case_key": sha256_text(f"event|{row['fingerprint']}")[:24],
        "kind": "event",
        "verdict": "suspected",
        "process": unit or "kernel",
        "signature": (row["message"] or "")[:160],
        "detail": row["message"] or "",
        "affinity": "n/a (journal event)",
        "event_ts": row["ts"],
    }


def _browserish(row) -> bool:
    blob = " ".join(str(row.get(k) or "") for k in ("comm", "exe", "corefile")).lower()
    return any(tag in blob for tag in (
        "firefox", "webrender", "gecko", "faultcore-run", "core2-run",
    ))


def refresh(conn, days: int = 30, persist_files: bool = True) -> dict:
    """Rebuild candidates, upsert cases, then optionally rewrite the dossier."""
    since = (utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    candidates: list[dict] = []

    crash_rows = [dict(r) for r in conn.execute(
        "SELECT * FROM crashes WHERE ts>=? ORDER BY ts DESC", (since,)
    )]
    confirmed = [r for r in crash_rows if r["faultcore_involved"] == 1]
    confirmed_procs = {r["comm"] or r["exe"] or "unknown" for r in confirmed}

    for row in crash_rows:
        verdict = _crash_verdict(row["faultcore_involved"])
        proc = row["comm"] or row["exe"] or "unknown"
        # Confirmed cases always; unresolved affinity always (it cannot be ruled
        # out); controls only for the same workload as a confirmed case.
        if verdict in ("confirmed", "unresolved"):
            pass
        elif confirmed and proc in confirmed_procs:
            pass
        else:
            continue
        candidates.append(_candidate_from_crash(row))

    for row in conn.execute(
        "SELECT * FROM events WHERE ts>=? AND severity IN ('critical','error','warning')"
        " ORDER BY ts DESC LIMIT 20000",
        (since,),
    ):
        if event_is_faultcore(row["message"] or ""):
            candidates.append(_candidate_from_event(dict(row)))

    now = iso()
    new = 0
    touched = 0
    for cand in candidates:
        existing = conn.execute(
            "SELECT id FROM faultcore_cases WHERE case_key=?", (cand["case_key"],)
        ).fetchone()
        if existing:
            conn.execute(
                "UPDATE faultcore_cases SET updated=?, detail=?, affinity=?, event_ts=?,"
                " process=?, signature=? WHERE id=?",
                (now, cand["detail"], cand["affinity"], cand["event_ts"],
                 cand["process"], cand["signature"], existing["id"]),
            )
            touched += 1
        else:
            conn.execute(
                "INSERT INTO faultcore_cases"
                "(case_key,created,updated,kind,verdict,process,signature,detail,"
                " affinity,event_ts,status) VALUES(?,?,?,?,?,?,?,?,?,?,'open')",
                (cand["case_key"], now, now, cand["kind"], cand["verdict"],
                 cand["process"], cand["signature"], cand["detail"],
                 cand["affinity"], cand["event_ts"]),
            )
            new += 1

    if persist_files:
        _write_dossier(conn)
    if new and persist_files:
        from . import report

        report.append_journal(
            conn,
            f"Fault-core triage: {new} new case(s)",
            f"- Total cases: {_count(conn)}\n- Dossier: `{config.TRIAGE_DIR / 'index.md'}`\n"
            f"- Status is preserved for existing cases; new ones start as `open`.\n",
            "triage",
        )
    db.meta_set(conn, "last_triage_run", now)
    return {"new": new, "touched": touched, "total": _count(conn), "path": str(config.TRIAGE_DIR)}


def _count(conn) -> int:
    return conn.execute("SELECT COUNT(*) FROM faultcore_cases").fetchone()[0]


def cases(conn, status: str | None = None, limit: int = 200) -> list[dict]:
    sql = "SELECT * FROM faultcore_cases"
    args: list = []
    if status:
        sql += " WHERE status=?"
        args.append(status)
    sql += " ORDER BY event_ts DESC LIMIT ?"
    args.append(limit)
    return [dict(r) for r in conn.execute(sql, args)]


def _dossier_digest(conn) -> str:
    rows = conn.execute(
        "SELECT case_key,status,verdict,process,signature,event_ts FROM faultcore_cases"
        " ORDER BY case_key"
    ).fetchall()
    return sha256_text(json.dumps([list(r) for r in rows], sort_keys=True))


def _write_dossier(conn) -> None:
    config.TRIAGE_DIR.mkdir(parents=True, exist_ok=True)
    rows = cases(conn, limit=10000)
    rows.sort(key=lambda r: (VERDICT_ORDER.get(r["verdict"], 9), r["event_ts"] or ""))
    cpus = ",".join(str(cpu) for cpu in config.FAULT_CORE_CPUS) or "unconfigured"
    control = ",".join(str(cpu) for cpu in config.CONTROL_CPUS) or "another core"
    index = [
        "# Fault-core triage queue",
        "",
        "Side dossier for fault-core investigation. Cases stay here for review;",
        "they are still included in the main evidence and vendor tickets.",
        "",
        "| case | verdict | status | process | last event |",
        "|---|---|---|---|---|",
    ]
    for row in rows:
        index.append(
            f"| [{row['id']}](case-{row['id']:04d}.md) | {row['verdict']} | "
            f"{row['status']} | `{row['process']}` | {row['event_ts']} |"
        )
    if not rows:
        index.append("| — | — | — | _no fault-core cases recorded yet_ | — |")
    (config.TRIAGE_DIR / "index.md").write_text("\n".join(index) + "\n", encoding="utf-8")
    (config.TRIAGE_DIR / "cases.json").write_text(
        json.dumps(rows, indent=2, sort_keys=True, default=str) + "\n", encoding="utf-8"
    )

    for row in rows:
        path = config.TRIAGE_DIR / f"case-{row['id']:04d}.md"
        body = [
            f"# Fault-core triage case {row['id']}: {row['signature'][:120]}",
            "",
            f"- Verdict: **{row['verdict']}**",
            f"- Status: **{row['status']}**",
            f"- Kind: {row['kind']}",
            f"- Process/unit: `{row['process']}`",
            f"- Allowed CPUs at the event: `{row['affinity']}`",
            f"- Event time (UTC): `{row['event_ts']}`",
            f"- First seen: `{row['created']}`; last refreshed: `{row['updated']}`",
            "",
            "## What was observed",
            "",
            "```",
            redact((row["detail"] or "(no detail captured)")[:6000]),
            "```",
            "",
            "## Why this is in the side queue",
            "",
            {
                "confirmed": "The affinity mask at the last sample before the event included "
                             f"fault-core CPUs {cpus}.",
                "suspected": f"The journal message names fault-core CPU(s) {cpus}; correlation "
                             "still needs a reproducer and an affinity-controlled comparison.",
                "control": f"The affinity mask excluded fault-core CPUs {cpus}. Keep as the "
                           "control arm; it makes the fault-core comparison meaningful.",
                "unresolved": "The affinity mask could not be recovered (sentinel was not sampling "
                              "yet or the process had already exited). This is not evidence of absence.",
            }.get(row["verdict"], ""),
            "",
            "## Investigation checklist",
            "",
            f"- [ ] Re-run with affinity pinned to `{cpus}` and a fresh profile/session.",
            f"- [ ] Re-run the same workload pinned to a control physical core (for example `{control}`).",
            "- [ ] Compare crash counts, timings and thermal/frequency data between both arms.",
            "- [ ] Capture `journalctl -k`, `coredumpctl info`, and the latest evidence bundle.",
            "- [ ] If the same workload is stable off the fault core, escalate to the hardware vendor.",
            "",
            "## Guardrail",
            "",
            "This case is **not omitted** from reports or vendor evidence. The side queue only",
            "adds a focused workspace for further investigation.",
        ]
        path.write_text("\n".join(body) + "\n", encoding="utf-8")
        conn.execute("UPDATE faultcore_cases SET path=? WHERE id=?", (str(path), row["id"]))

    db.meta_set(conn, "triage_digest", _dossier_digest(conn))


def set_status(conn, case_id: int, status: str, note: str | None = None) -> dict | None:
    if status not in STATUSES:
        raise ValueError(f"status must be one of {', '.join(STATUSES)}")
    row = conn.execute("SELECT * FROM faultcore_cases WHERE id=?", (case_id,)).fetchone()
    if not row:
        return None
    conn.execute(
        "UPDATE faultcore_cases SET status=?, updated=?, notes=COALESCE(?, notes) WHERE id=?",
        (status, iso(), note, case_id),
    )
    _write_dossier(conn)
    from . import report

    report.append_journal(
        conn,
        f"Fault-core case {case_id}: status → {status}",
        f"- Note: {note or '(none)'}\n- Case file: `{config.TRIAGE_DIR / f'case-{case_id:04d}.md'}`\n",
        "triage",
    )
    return dict(conn.execute("SELECT * FROM faultcore_cases WHERE id=?", (case_id,)).fetchone())


def summary(conn) -> dict:
    rows = conn.execute(
        "SELECT status, verdict, COUNT(*) n FROM faultcore_cases GROUP BY status, verdict"
    ).fetchall()
    out = {"total": _count(conn), "by_status": {}, "by_verdict": {}}
    for r in rows:
        out["by_status"][r["status"]] = out["by_status"].get(r["status"], 0) + r["n"]
        out["by_verdict"][r["verdict"]] = out["by_verdict"].get(r["verdict"], 0) + r["n"]
    return out
