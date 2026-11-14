"""Trace one signature across every layer that touched it.

An event is a line, a correlation is a convergence, a draft is an outgoing claim.
Traceability means being able to walk from any one of them to the others, so a
ticket can always be answered with "these are the exact observations behind it".

Resolution is deliberately query-shaped: a cluster key, a boot id prefix, an
event fingerprint, or a phrase from a message all land on the same record set.
"""
from __future__ import annotations

from . import boot


def _like(query: str) -> str:
    return f"%{query}%"


def resolve(conn, query: str, limit: int = 200) -> dict:
    q = (query or "").strip()
    like = _like(q)
    out: dict = {
        "query": q, "correlations": [], "events": [], "crashes": [],
        "boots": [], "drafts": [], "findings": [],
    }
    if not q:
        return out

    clusters: dict[tuple[str, str], dict] = {}
    for row in conn.execute(
        "SELECT * FROM correlations WHERE vendor LIKE ? OR signature LIKE ?"
        " OR boot_id LIKE ? OR component LIKE ?",
        (like, like, f"{q}%", like),
    ):
        row = dict(row)
        key = (row["vendor"], row["signature"])
        item = clusters.setdefault(
            key, {"vendor": row["vendor"], "signature": row["signature"],
                  "boots": [], "occurrences": 0, "crashes": 0}
        )
        item["boots"].append(row["boot_id"])
        item["occurrences"] += int(row["occurrences"] or 0)
        item["crashes"] += int(row["crashes"] or 0)
    out["correlations"] = list(clusters.values())

    out["events"] = [
        dict(r) for r in conn.execute(
            "SELECT ts, boot_id, severity, unit, message, fingerprint, count"
            " FROM events WHERE message LIKE ? OR fingerprint LIKE ? OR boot_id LIKE ?"
            " ORDER BY ts DESC LIMIT ?",
            (like, f"{q}%", f"{q}%", limit),
        )
    ]
    out["crashes"] = [
        dict(r) for r in conn.execute(
            "SELECT ts, comm, exe, sig, cpus_allowed, faultcore_involved, fingerprint"
            " FROM crashes WHERE sig LIKE ? OR comm LIKE ? OR exe LIKE ?"
            " ORDER BY ts DESC LIMIT ?",
            (like, like, like, limit),
        )
    ]
    out["boots"] = [
        dict(r) for r in conn.execute(
            "SELECT * FROM boots WHERE boot_id LIKE ? OR last_message LIKE ?"
            " ORDER BY last_ts DESC LIMIT ?",
            (f"{q}%", like, limit),
        )
    ]
    out["drafts"] = [
        dict(r) for r in conn.execute(
            "SELECT * FROM ticket_drafts WHERE issue_key LIKE ? OR title LIKE ?"
            " OR vendor LIKE ?",
            (f"{q}%", like, like),
        )
    ]
    out["findings"] = [
        dict(r) for r in conn.execute(
            "SELECT id, ts, rule, severity, subject, detail, status, count"
            " FROM findings WHERE rule LIKE ? OR subject LIKE ? OR detail LIKE ?"
            " OR fingerprint LIKE ? ORDER BY ts DESC LIMIT ?",
            (like, like, like, f"event|%{q}%", limit),
        )
    ]
    return out


def render(conn, query: str, limit: int = 50) -> list[str]:
    record = resolve(conn, query, limit)
    if not any(record[k] for k in ("correlations", "events", "crashes", "boots",
                                   "drafts", "findings")):
        return [f"nothing recorded for {query!r}"]

    lines = [f"trace: {record['query']}", ""]
    if record["correlations"]:
        lines.append(f"## Correlations ({len(record['correlations'])})")
        for c in record["correlations"]:
            lines.append(
                f"- {c['vendor']}: {c['signature'][:110]} "
                f"({len(c['boots'])} stop(s), {c['occurrences']} occurrence(s), "
                f"{c['crashes']} crash(es))"
            )
            for boot_id in c["boots"]:
                lines.append(f"    - stop `{boot_id[:8]}`")
        lines.append("")

    if record["boots"]:
        lines.append(f"## Silent stops ({len(record['boots'])})")
        for b in record["boots"]:
            lines.append(
                f"- `{b['boot_id'][:8]}` {boot.verdict(b)} last={b['last_ts']} "
                f"pstore={'yes' if (b['pstore'] or '[]') != '[]' else 'empty'} "
                f"kexec={b['kexec_loaded']} vmcores={b['vmcores']}"
            )
            lines.append(f"    last message: {(b['last_message'] or '')[:140]}")
        lines.append("")

    if record["events"]:
        lines.append(f"## Events sharing the signature ({len(record['events'])})")
        for e in record["events"]:
            lines.append(
                f"- {e['ts']} `{e['severity']}` {e['unit'] or '-'} "
                f"x{e['count']} :: {(e['message'] or '')[:130]}"
            )
        lines.append("")

    if record["crashes"]:
        lines.append(f"## Crashes ({len(record['crashes'])})")
        for c in record["crashes"]:
            lines.append(
                f"- {c['ts']} {c['comm'] or c['exe']} {c['sig']} "
                f"cpus={c['cpus_allowed'] or 'unknown'} fault_core={c['faultcore_involved']}"
            )
        lines.append("")

    if record["findings"]:
        lines.append(f"## Findings ({len(record['findings'])})")
        for f in record["findings"]:
            lines.append(
                f"- [{f['id']}] {f['severity']} {f['rule']} {f['status']} "
                f"x{f['count']} :: {(f['detail'] or '')[:120]}"
            )
        lines.append("")

    if record["drafts"]:
        lines.append(f"## Drafts raised from this ({len(record['drafts'])})")
        for d in record["drafts"]:
            lines.append(f"- {d['vendor']} `{d['issue_key']}` -> {d['path']}")
        lines.append("")

    return lines
