"""Regular cross-checks: does the record still say what it said before?

Everything upstream drifts. Journals rotate, signatures re-bucket, a boot gets
re-scanned by an improved scanner, a draft outlives the evidence that justified
it. A sentinel that never re-checks itself slowly turns into folklore.

This job compares three things and reports only differences:
  * drafts on disk            vs issues the current evidence reproduces
  * correlations marked ready vs the recomputed readiness
  * stored boot verdicts      vs a fresh scan (only with --deep; it is expensive)
"""
from __future__ import annotations

import json

from . import boot, config, correlate, notify, report, tickets
from .util import iso, sha256_text


def _staged_issue_keys() -> set[str]:
    """Issue keys already staged as ticket records, even without a live draft.

    Historical tickets can outlive the routine draft window. They remain valid
    staged records and must not be reported as missing drafts.
    """
    keys: set[str] = set()
    for root in (config.RAISE_DIR, config.STANDBY_DIR, config.REJECT_DIR):
        if not root.exists():
            continue
        for manifest in root.glob("*/evidence/manifest.json"):
            try:
                data = json.loads(manifest.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            key = data.get("issue_key")
            if key:
                keys.add(str(key))
    return keys


def _drift_key(stale: list[dict], missing: list[dict],
               ready_without_draft: list[dict]) -> str:
    """One key per drift composition, so an unchanged problem is one alert."""
    parts = sorted(d["issue_key"] for d in stale)
    parts += sorted(i["key"] for i in missing)
    parts += sorted(c["key"] for c in ready_without_draft)
    return "crosscheck|" + sha256_text("|".join(parts))[:16]


def run(conn, days: int = 30, deep: bool = False, notify_drift: bool = True) -> dict:
    if deep:
        boot.collect(conn, limit=12, refresh=True)
        correlate.correlate(conn, days=days, notify=False)

    current = {issue["key"]: issue for issue in tickets.collect_issues(conn, days)}
    drafts = [dict(r) for r in conn.execute("SELECT * FROM ticket_drafts ORDER BY ts")]
    draft_keys = {d["issue_key"] for d in drafts} | _staged_issue_keys()
    selected = {
        issue["key"] for issue in tickets.select_issues(
            list(current.values()), config.MAX_TICKETS
        )
    }

    stale = [d for d in drafts if d["issue_key"] not in current]
    capped = [
        issue for key, issue in current.items()
        if key not in selected and issue["vendor"] != "local"
    ]
    missing = [
        issue for key, issue in current.items()
        if key not in draft_keys and key in selected and issue["vendor"] != "local"
    ]
    ready = [c for c in correlate.aggregate(conn, days) if c["ready"]]
    unready_drafts = [
        c for c in ready if c["key"] not in draft_keys
    ]

    drift = len(stale) + len(missing) + len(unready_drafts)
    detail = {
        "drafts": len(drafts),
        "reproducible_issues": len(current),
        "stale_drafts": [
            {"key": d["issue_key"], "title": d["title"], "path": d["path"]}
            for d in stale
        ],
        "unraised_issues": [
            {"key": i["key"], "vendor": i["vendor"],
             "signature": (i.get("display") or i["signature"])[:120]}
            for i in missing
        ],
        "capped_issues": [
            {"key": i["key"], "vendor": i["vendor"],
             "signature": (i.get("display") or i["signature"])[:120]}
            for i in capped
        ],
        "ready_without_draft": [
            {"key": c["key"], "vendor": c["vendor"],
             "signature": (c.get("display") or c["signature"])[:120]}
            for c in unready_drafts
        ],
        "deep": deep,
    }
    conn.execute(
        "INSERT INTO crosschecks(ts, checked, drift, detail) VALUES(?,?,?,?)",
        (iso(), len(drafts), drift, _json(detail)),
    )

    conn.execute(
        "DELETE FROM crosschecks WHERE id NOT IN"
        " (SELECT id FROM crosschecks ORDER BY id DESC LIMIT 200)"
    )

    if drift:
        body = _body(detail)
        report.append_journal(conn, f"Cross-check drift: {drift} item(s)", body, "crosscheck")
        if notify_drift:
            notify.enqueue(
                conn, "crosscheck", _drift_key(stale, missing, unready_drafts),
                f"QA cross-check: {drift} drift item(s)",
                body[:400],
                detail=str(detail)[:1500],
                supersede=True,
            )
    elif notify_drift:
        # Drift was resolved before its alert reached the desktop.
        notify.clear_pending(conn, "crosscheck")
    return {
        "drafts": len(drafts),
        "reproducible_issues": len(current),
        "stale_drafts": [d["issue_key"] for d in stale],
        "unraised_issues": [i["key"] for i in missing],
        "capped_issues": [i["key"] for i in capped],
        "ready_without_draft": [c["key"] for c in unready_drafts],
        "drift": drift,
    }


def _json(value) -> str:
    import json

    return json.dumps(value, indent=2, sort_keys=True, default=str)[:20000]


def _body(detail: dict) -> str:
    lines = []
    for key, label in (
        ("stale_drafts", "Drafts no longer reproduced by current evidence"),
        ("unraised_issues", "Issues reproducible now but missing a draft"),
        ("ready_without_draft", "Correlations ready but not drafted"),
    ):
        items = detail.get(key) or []
        if not items:
            continue
        lines.append(f"**{label}** ({len(items)})")
        for item in items[:20]:
            lines.append(
                f"- `{item.get('key')}` {item.get('vendor', '')} "
                f"{(item.get('signature') or item.get('title') or '')[:140]}"
            )
        lines.append("")
    return "\n".join(lines) or "no drift\n"


def history(conn, limit: int = 10) -> list[dict]:
    return [
        dict(r) for r in conn.execute(
            "SELECT * FROM crosschecks ORDER BY id DESC LIMIT ?", (limit,)
        )
    ]
