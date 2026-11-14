"""Correlate silent stops with the errors that preceded them.

A silent stop on its own names no component: it only says the machine stopped
writing. This module looks backwards from the moment the journal ends, groups
what was happening by *owner*, and asks a different question than layer 1 does:

    does this same component signature recur across separate silent stops?

Recurrence is the consistency test. One stop with many warnings is a bad
afternoon; the same signature in the death window of two independent stops is a
pattern worth a vendor's time. Only patterns that pass the threshold and name a
specific component become ticket candidates. Nothing is submitted here.

Runs as its own scheduled job, not inside the 1-minute tick: correlation is a
different cadence and must not slow the sampler down.
"""
from __future__ import annotations

import re
from datetime import timedelta

from . import classify, config, db, report
from .util import iso, parse_iso, redact, sha256_text, utcnow


# ---------------------------------------------------------------- ownership
def component_for_event(unit: str | None, message: str | None) -> tuple[str, str]:
    """Return (vendor, component-label) for one event."""
    vendor = classify.vendor_for(unit or "", message or "")
    meta = classify.VENDOR_META.get(vendor, classify.VENDOR_META["local"])
    label = (unit or "").split(".")[0] or meta["component"]
    return vendor, label


def component_for_crash(row: dict) -> tuple[str, str]:
    blob = " ".join(
        str(row.get(key) or "") for key in ("comm", "exe", "sig", "context")
    )
    vendor = classify.vendor_for(blob)
    if row.get("faultcore_involved") == 1 and vendor == "local":
        vendor = "hardware"  # affinity evidence names the platform, not a package
    return vendor, (row.get("comm") or row.get("exe") or "unknown")


def _window(boot: dict) -> tuple[str, str]:
    end = parse_iso(boot["last_ts"])
    start = end - timedelta(seconds=config.CORRELATE_WINDOW_S)
    return (
        start.strftime("%Y-%m-%dT%H:%M:%SZ"),
        end.strftime("%Y-%m-%dT%H:%M:%SZ"),
    )


_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _display_text(value: str, fallback: str) -> str:
    text = (value or "").strip().splitlines()
    text = _ANSI.sub("", text[0] if text else "")
    text = re.sub(r"\s+", " ", text).strip()
    return redact(text)[:200] or fallback


# ---------------------------------------------------------------- clustering
def clusters_for_boot(conn, boot: dict) -> list[dict]:
    start, end = _window(boot)
    clusters: dict[tuple[str, str], dict] = {}

    def bump(vendor: str, component: str, signature: str, ts: str, rows: list[dict],
             occurrences: int, is_crash: bool, display: str) -> None:
        key = (vendor, signature)
        item = clusters.setdefault(
            key,
            {
                "boot_id": boot["boot_id"], "vendor": vendor, "component": component,
                "signature": signature, "display": display,
                "occurrences": 0, "crashes": 0,
                "window_start": start, "window_end": end,
                "first": ts, "last": ts, "rows": [],
            },
        )
        if not item.get("display"):
            item["display"] = display
        item["occurrences"] += occurrences
        if is_crash:
            item["crashes"] += 1
        item["first"] = min(item["first"], ts)
        item["last"] = max(item["last"], ts)
        if len(item["rows"]) < 25:
            item["rows"].append({"ts": ts, **rows})

    for row in conn.execute(
        "SELECT * FROM events WHERE boot_id=? AND ts>=? AND ts<=?"
        " AND severity IN ('critical','error','warning')",
        (boot["boot_id"], start, end),
    ):
        row = dict(row)
        view = row.get("last_ts") or row.get("ts")
        if view is None or not (start <= view <= end):
            continue
        vendor, component = component_for_event(row.get("unit"), row.get("message"))
        message = row.get("message") or ""
        signature = classify.signature(message)
        bump(
            vendor, component, signature,
            row["ts"], {"message": message,
                        "unit": row.get("unit"), "severity": row.get("severity")},
            int(row.get("count") or 1), False,
            _display_text(message, signature),
        )

    for row in conn.execute(
        "SELECT * FROM crashes WHERE ts>=? AND ts<=?", (start, end)
    ):
        row = dict(row)
        vendor, component = component_for_crash(row)
        signature = f"{component} {row.get('sig')}"
        bump(
            vendor, component, signature,
            row["ts"],
            {"sig": row.get("sig"), "comm": row.get("comm"),
             "cpus_allowed": row.get("cpus_allowed"),
             "faultcore_involved": row.get("faultcore_involved")},
            1, True,
            _display_text(signature, signature),
        )

    return list(clusters.values())


def correlate(conn, days: int = 30, notify: bool = True) -> dict:
    """Rebuild correlation rows for every unclean boot in the window."""
    since = (utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    boots = [
        dict(r) for r in conn.execute(
            "SELECT * FROM boots WHERE ended_clean=0 AND last_ts>=? ORDER BY last_ts", (since,)
        )
    ]
    written = 0
    for boot in boots:
        conn.execute("DELETE FROM correlations WHERE boot_id=?", (boot["boot_id"],))
        for cluster in clusters_for_boot(conn, boot):
            conn.execute(
                "INSERT OR REPLACE INTO correlations"
                "(boot_id, vendor, component, signature, display, occurrences, crashes,"
                " window_start, window_end, created) VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    cluster["boot_id"], cluster["vendor"], cluster["component"],
                    cluster["signature"], cluster["display"],
                    cluster["occurrences"], cluster["crashes"],
                    cluster["window_start"], cluster["window_end"], iso(),
                ),
            )
            written += 1

    ready = [c for c in aggregate(conn, days) if c["ready"]]
    if notify:
        _notify_new(conn, ready)
    return {
        "unclean_boots": len(boots),
        "clusters": written,
        "ticket_ready": len(ready),
        "ready": [
            {"vendor": c["vendor"], "signature": c["display"][:120],
             "boots": c["boots"], "occurrences": c["occurrences"]}
            for c in ready
        ],
        "window_s": config.CORRELATE_WINDOW_S,
    }


def _notify_new(conn, ready: list[dict]) -> None:
    for cluster in ready:
        key = "correlate_notified|" + cluster["key"]
        if db.meta_get(conn, key):
            continue
        db.meta_set(conn, key, iso())
        shown = cluster.get("display") or cluster["signature"]
        report.append_journal(
            conn,
            f"Correlated pattern for {cluster['vendor']}: {shown[:80]}",
            f"- Silent stops involved: **{cluster['boots']}**\n"
            f"- Occurrences in their death windows: **{cluster['occurrences']}** "
            f"(crashes {cluster['crashes']})\n"
            f"- Window: {config.CORRELATE_WINDOW_S} s before each stop\n"
            f"- Consistency score: **{cluster['score']}** "
            f"(threshold: {cluster['threshold']})\n"
            f"- Owner: `{cluster['vendor']}` / {cluster['component']}\n",
            "correlate",
        )


# ---------------------------------------------------------------- aggregation
def aggregate(conn, days: int = 30) -> list[dict]:
    """Group correlation rows across boots and score each component signature."""
    since = (utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    total_unclean = conn.execute(
        "SELECT COUNT(*) FROM boots WHERE ended_clean=0 AND last_ts>=?", (since,)
    ).fetchone()[0]
    groups: dict[tuple[str, str], dict] = {}
    for row in conn.execute(
        "SELECT c.*, b.last_ts AS stop_ts FROM correlations c"
        " JOIN boots b ON b.boot_id=c.boot_id"
        " WHERE b.ended_clean=0 AND b.last_ts>=?"
        " ORDER BY b.last_ts",
        (since,),
    ):
        row = dict(row)
        key = (row["vendor"], row["signature"])
        item = groups.setdefault(
            key,
            {
                "vendor": row["vendor"], "component": row["component"],
                "signature": row["signature"],
                "display": row.get("display") or row["signature"],
                "boots": 0, "occurrences": 0,
                "crashes": 0, "first": row["stop_ts"], "last": row["stop_ts"],
                "stop_ts": [],
            },
        )
        if not item.get("display"):
            item["display"] = row["display"] or row["signature"]
        item["boots"] += 1
        item["occurrences"] += int(row["occurrences"] or 0)
        item["crashes"] += int(row["crashes"] or 0)
        item["first"] = min(item["first"], row["stop_ts"])
        item["last"] = max(item["last"], row["stop_ts"])
        item["stop_ts"].append(row["stop_ts"])

    out = []
    for item in groups.values():
        # recurrence dominates; volume and a real crash add weight. A single stop
        # must show a crash plus volume before it counts as consistency.
        score = 3 * item["boots"] + min(item["occurrences"], 10) + 3 * (item["crashes"] > 0)
        threshold = 3 * config.CORRELATE_MIN_BOOTS + config.CORRELATE_MIN_COUNT
        ready = (
            item["vendor"] != "local"
            and classify.ticketworthy(item["signature"], "event", "critical", item["occurrences"])
            and (
                (item["boots"] >= config.CORRELATE_MIN_BOOTS
                 and item["occurrences"] >= config.CORRELATE_MIN_COUNT)
                or (item["crashes"] >= 1
                    and item["occurrences"] >= config.CORRELATE_SINGLE_BOOT_MIN)
            )
        )
        item["score"] = score
        item["threshold"] = threshold
        item["ready"] = ready
        item["total_unclean"] = total_unclean
        item["key"] = sha256_text(f"{item['vendor']}|correlation|{item['signature']}")[:20]
        item["repeat_rate"] = round(item["boots"] / total_unclean, 3) if total_unclean else 0.0
        out.append(item)
    out.sort(key=lambda c: (not c["ready"], -c["boots"], -c["occurrences"]))
    return out


def rows_for_signature(conn, signature: str) -> list[dict]:
    """Correlation rows for one signature, across every silent stop."""
    return [
        dict(r) for r in conn.execute(
            "SELECT * FROM correlations WHERE signature=? ORDER BY boot_id", (signature,)
        )
    ]


def ticket_candidates(conn, days: int = 30) -> list[dict]:
    """Issue-shaped clusters eligible for a vendor draft."""
    out = []
    for cluster in aggregate(conn, days):
        if not cluster["ready"]:
            continue
        shown = cluster.get("display") or cluster["signature"]
        rows = [
            {
                "ts": cluster["last"],
                "comm": cluster["component"],
                "sig": shown[:120],
                "message": (
                    f"{shown} (seen in {cluster['boots']} silent stop(s) "
                    f"before shutdown, {cluster['occurrences']} occurrence(s))"
                ),
            }
        ]
        out.append(
            {
                "key": cluster["key"],
                "vendor": cluster["vendor"],
                "signature": cluster["signature"],
                "display": shown,
                "kind": "correlation",
                "rows": rows,
                "count": cluster["occurrences"],
                "severity": "critical",
                "first": cluster["first"],
                "last": cluster["last"],
                "notes": (
                    f"This signature appeared in the final "
                    f"{config.CORRELATE_WINDOW_S // 60} min before **{cluster['boots']}** "
                    f"of {cluster['total_unclean']} silent stop(s) "
                    f"({cluster['repeat_rate']:.0%} repeat rate), "
                    f"{cluster['occurrences']} occurrence(s), {cluster['crashes']} crash(es). "
                    f"Consistency score {cluster['score']} vs threshold "
                    f"{cluster['threshold']}. **Attribution is inferred** from the "
                    "message content; the stop itself has no logged cause."
                ),
            }
        )
    return out
