"""Read-only query engine for sentinels.db.

The desktop Database and the CLI share one category catalog so the buttons
cannot drift from the command line.  Arbitrary SQL is accepted only after it is
proven to be a single read-only statement; a connection authorizer then denies
every action that is not a read.
"""
from __future__ import annotations

import json
import re
import sqlite3
import time
from typing import Any

DEFAULT_LIMIT = 200
MAX_LIMIT = 10000
MAX_SQL_CHARS = 20000
MAX_QUERY_SECONDS = 8.0
MAX_CELL_CHARS = 12000
MAX_RESULT_CHARS = 3_000_000

FINDING_CATEGORIES = ("inbox", "errors", "findings")
SEVERITIES = ("critical", "error", "warning", "info")
STATUSES = ("open", "investigating", "resolved", "dismissed")
_SINCE_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2}(?:\.\d+)?)?Z?)?$")

_FINDING_SEVERITY_ORDER = (
    "CASE severity WHEN 'critical' THEN 0 WHEN 'error' THEN 1 "
    "WHEN 'warning' THEN 2 ELSE 3 END"
)

CATEGORIES: dict[str, dict[str, str]] = {
    "inbox": {
        "label": "Inbox",
        "description": "Open critical, error and warning findings, most severe first.",
        "sql": (
            "SELECT id, ts, last_ts, severity, status, rule, subject, count, detail, "
            "case_id, fingerprint, evidence_path FROM findings "
            "WHERE status IN ('open', 'investigating') "
            "AND severity IN ('critical', 'error', 'warning') "
            f"ORDER BY {_FINDING_SEVERITY_ORDER}, last_ts DESC, id DESC LIMIT {{limit}}"
        ),
    },
    "errors": {
        "label": "Errors",
        "description": "Open critical and error findings, most severe first.",
        "sql": (
            "SELECT id, ts, last_ts, severity, status, rule, subject, count, detail, "
            "case_id, fingerprint, evidence_path FROM findings "
            "WHERE status IN ('open', 'investigating') "
            "AND severity IN ('critical', 'error') "
            f"ORDER BY {_FINDING_SEVERITY_ORDER}, last_ts DESC, id DESC LIMIT {{limit}}"
        ),
    },
    "findings": {
        "label": "Findings",
        "description": "Every layer-1 finding, including resolved and dismissed.",
        "sql": (
            "SELECT id, ts, last_ts, severity, status, rule, subject, count, detail, "
            "case_id, fingerprint, evidence_path FROM findings "
            f"ORDER BY {_FINDING_SEVERITY_ORDER}, last_ts DESC, id DESC LIMIT {{limit}}"
        ),
    },
    "cycles": {
        "label": "Cycles",
        "description": "Cycle summaries, including each cycle's layer1_findings block.",
        "sql": (
            "SELECT id, ts, detail FROM runs WHERE task='cycle' "
            "ORDER BY id DESC LIMIT {limit}"
        ),
    },
    "new-findings": {
        "label": "Cycle findings",
        "description": "Findings created by a cycle, linked back to the cycle time.",
        "sql": (
            "SELECT cf.ts AS cycle_ts, f.id, f.ts, f.last_ts, f.severity, f.status, "
            "f.rule, f.subject, f.count, f.detail, f.case_id, f.fingerprint, "
            "f.evidence_path FROM cycle_findings cf "
            "JOIN findings f ON f.id=cf.finding_id "
            "ORDER BY cf.ts DESC, CASE f.severity WHEN 'critical' THEN 0 "
            "WHEN 'error' THEN 1 WHEN 'warning' THEN 2 ELSE 3 END, "
            "f.last_ts DESC LIMIT {limit}"
        ),
    },
    "events": {
        "label": "Events",
        "description": "Ingested journal warnings, errors and critical events.",
        "sql": (
            "SELECT id, ts, last_ts, severity, count, source, unit, comm, message, "
            "boot_id, pid, fingerprint, length(raw) AS raw_bytes "
            "FROM events ORDER BY last_ts DESC, ts DESC, id DESC LIMIT {limit}"
        ),
    },
    "crashes": {
        "label": "Crashes",
        "description": "Captured crashes and whether the fault core was involved.",
        "sql": (
            "SELECT id, ts, comm, sig, faultcore_involved, cpus_allowed, exe, "
            "fingerprint, context, pid, corefile "
            "FROM crashes ORDER BY ts DESC, id DESC LIMIT {limit}"
        ),
    },
    "boots": {
        "label": "Boots",
        "description": "Boot boundaries classified as clean, unclean or unknown.",
        "sql": (
            "SELECT id, boot_id, seq, last_ts, ended_clean, vmcores, pstore, "
            "last_message, span, markers, scans, kexec_loaded, crashkernel, "
            "captured_ts FROM boots ORDER BY last_ts DESC, id DESC LIMIT {limit}"
        ),
    },
    "samples": {
        "label": "Samples",
        "description": "Kernel, memory, CPU and process samples without the raw payload.",
        "sql": (
            "SELECT id, ts, boot_id, length(payload) AS payload_bytes "
            "FROM samples ORDER BY ts DESC, id DESC LIMIT {limit}"
        ),
    },
    "processes": {
        "label": "Process snapshots",
        "description": "Per-sample process table with affinity, memory and state.",
        "sql": (
            "SELECT ts, pid, ppid, comm, state, threads, rss_kb, cpu_ticks, "
            "last_cpu, cpus_allowed, exe FROM proc_snap "
            "ORDER BY ts DESC, pid LIMIT {limit}"
        ),
    },
    "inventory": {
        "label": "Inventory runs",
        "description": "Software inventory snapshots and their changed-item counts.",
        "sql": (
            "SELECT id, ts, digest, counts, note FROM inventory_runs "
            "ORDER BY ts DESC, id DESC LIMIT {limit}"
        ),
    },
    "inventory-items": {
        "label": "Inventory items",
        "description": "Recorded software and configuration items for each inventory run.",
        "sql": (
            "SELECT i.run_id, r.ts, i.layer, i.item, i.value "
            "FROM inventory i LEFT JOIN inventory_runs r ON r.id = i.run_id "
            "ORDER BY i.run_id DESC, i.layer, i.item LIMIT {limit}"
        ),
    },
    "inventory-diffs": {
        "label": "Inventory changes",
        "description": "Items added, removed or changed between inventory runs.",
        "sql": (
            "SELECT id, ts, run_id, layer, change, item, old_value, new_value "
            "FROM inventory_diffs ORDER BY ts DESC, id DESC LIMIT {limit}"
        ),
    },
    "hardware": {
        "label": "Hardware runs",
        "description": "Hardware-health runs across RAS, EDAC, AER, APEI and SMART.",
        "sql": (
            "SELECT id, ts, status, sources, duration_ms, detail FROM hardware_runs "
            "ORDER BY ts DESC, id DESC LIMIT {limit}"
        ),
    },
    "hardware-items": {
        "label": "Hardware items",
        "description": "Hardware components recorded by each hardware-health run.",
        "sql": (
            "SELECT i.run_id, r.ts, i.source, i.item, i.value "
            "FROM hardware_items i LEFT JOIN hardware_runs r ON r.id = i.run_id "
            "ORDER BY i.run_id DESC, i.source, i.item LIMIT {limit}"
        ),
    },
    "lsm": {
        "label": "LSM runs",
        "description": "Linux Security Modules state, denials and drift.",
        "sql": (
            "SELECT id, ts, status, digest, denials, state FROM lsm_runs "
            "ORDER BY ts DESC, id DESC LIMIT {limit}"
        ),
    },
    "correlations": {
        "label": "Correlations",
        "description": "Recurring signatures grouped across boots.",
        "sql": (
            "SELECT id, boot_id, vendor, component, signature, occurrences, crashes, "
            "window_start, window_end, display, created FROM correlations "
            "ORDER BY window_end DESC, id DESC LIMIT {limit}"
        ),
    },
    "tickets": {
        "label": "Ticket drafts",
        "description": "Drafted vendor tickets and their issue keys.",
        "sql": (
            "SELECT id, ts, vendor, title, issue_key, path FROM ticket_drafts "
            "ORDER BY ts DESC, id DESC LIMIT {limit}"
        ),
    },
    "deep": {
        "label": "Deep runs",
        "description": "Layer-2 deep tracing runs and their status.",
        "sql": (
            "SELECT id, ts, case_id, finding_id, status, reason, duration_s, comm, "
            "pid, path, sha256, summary FROM deep_runs "
            "ORDER BY ts DESC, id DESC LIMIT {limit}"
        ),
    },
    "bundles": {
        "label": "Bundles",
        "description": "Hash-chained evidence bundles.",
        "sql": (
            "SELECT id, ts, sha256, prev_sha256, path, contents FROM bundles "
            "ORDER BY ts DESC, id DESC LIMIT {limit}"
        ),
    },
    "runs": {
        "label": "Runs",
        "description": "Internal task runs and failures.",
        "sql": (
            "SELECT id, ts, task, ok, detail FROM runs "
            "ORDER BY ts DESC, id DESC LIMIT {limit}"
        ),
    },
    "faultcore": {
        "label": "Fault-core cases",
        "description": "Fault-core triage cases, verdicts and evidence paths.",
        "sql": (
            "SELECT id, case_key, created, updated, kind, verdict, process, "
            "signature, status, event_ts, affinity, notes, path, detail "
            "FROM faultcore_cases ORDER BY updated DESC, id DESC LIMIT {limit}"
        ),
    },
    "crosschecks": {
        "label": "Crosschecks",
        "description": "Draft and correlation crosscheck runs, with drift detail.",
        "sql": (
            "SELECT id, ts, checked, drift, detail FROM crosschecks "
            "ORDER BY ts DESC, id DESC LIMIT {limit}"
        ),
    },
    "notifications": {
        "label": "Notifications",
        "description": "Queued and delivered notifications with retry state.",
        "sql": (
            "SELECT id, ts, kind, key, title, delivered, attempts, last_attempt, "
            "last_error, path, body, detail FROM notifications "
            "ORDER BY ts DESC, id DESC LIMIT {limit}"
        ),
    },
    "reports": {
        "label": "Reports",
        "description": "Generated startup and daily reports with their paths.",
        "sql": (
            "SELECT id, ts, kind, path, summary FROM reports "
            "ORDER BY ts DESC, id DESC LIMIT {limit}"
        ),
    },
    "meta": {
        "label": "Metadata",
        "description": "Internal state and scheduling markers stored by the engine.",
        "sql": (
            "SELECT key, value FROM meta ORDER BY key LIMIT {limit}"
        ),
    },
}

CATEGORY_SOURCES = {
    "inbox": "findings",
    "errors": "findings",
    "findings": "findings",
    "cycles": "runs",
    "new-findings": "cycle_findings",
    "events": "events",
    "crashes": "crashes",
    "boots": "boots",
    "samples": "samples",
    "processes": "proc_snap",
    "inventory": "inventory_runs",
    "inventory-items": "inventory",
    "inventory-diffs": "inventory_diffs",
    "hardware": "hardware_runs",
    "hardware-items": "hardware_items",
    "lsm": "lsm_runs",
    "correlations": "correlations",
    "tickets": "ticket_drafts",
    "deep": "deep_runs",
    "bundles": "bundles",
    "runs": "runs",
    "faultcore": "faultcore_cases",
    "crosschecks": "crosschecks",
    "notifications": "notifications",
    "reports": "reports",
    "meta": "meta",
}

CATEGORY_ORDER = tuple(CATEGORIES)


class QueryError(ValueError):
    """A query was rejected or could not be executed safely."""


_ALLOWED_ACTIONS = {
    value
    for name in ("SQLITE_SELECT", "SQLITE_READ", "SQLITE_FUNCTION", "SQLITE_RECURSIVE")
    if (value := getattr(sqlite3, name, None)) is not None
}


def catalog() -> list[dict[str, str]]:
    """Return the public category catalog in display order."""
    return [
        {
            "id": name,
            "label": CATEGORIES[name]["label"],
            "description": CATEGORIES[name]["description"],
            "source": CATEGORY_SOURCES.get(name, ""),
        }
        for name in CATEGORY_ORDER
    ]


def _quote_identifier(name: str) -> str:
    return '"' + str(name).replace('"', '""') + '"'


def schema(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    """Return every user table with its row count and columns."""
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "AND name NOT LIKE 'sqlite_%' ORDER BY name"
    ).fetchall()
    out: list[dict[str, Any]] = []
    for row in tables:
        name = str(row[0])
        quoted = _quote_identifier(name)
        columns = [
            {"name": str(column["name"]), "type": str(column["type"] or "")}
            for column in conn.execute(f"PRAGMA table_info({quoted})")
        ]
        count = conn.execute(f"SELECT COUNT(*) FROM {quoted}").fetchone()[0]
        out.append({"name": name, "rows": int(count), "columns": columns})
    return out


def normalize_limit(limit: Any) -> int:
    try:
        value = int(limit)
    except (TypeError, ValueError) as exc:
        raise QueryError("limit must be a whole number") from exc
    if value < 1 or value > MAX_LIMIT:
        raise QueryError(f"limit must be between 1 and {MAX_LIMIT}")
    return value


def _category_sql(name: str, limit: int) -> str:
    spec = CATEGORIES.get(str(name or "").lower())
    if not spec:
        raise QueryError(
            f"unknown category; choose one of: {', '.join(CATEGORY_ORDER)}")
    return spec["sql"].format(limit=limit)


def _option_list(value: Any, allowed: tuple[str, ...], label: str) -> list[str]:
    if value is None or value == "":
        return []
    raw = value.split(",") if isinstance(value, str) else list(value)
    out: list[str] = []
    for item in raw:
        normalized = str(item).strip().lower()
        if not normalized:
            continue
        if normalized not in allowed:
            raise QueryError(
                f"{label} must be one of: {', '.join(allowed)}")
        if normalized not in out:
            out.append(normalized)
    return out


def normalize_severity(value: Any) -> list[str]:
    return _option_list(value, SEVERITIES, "severity")


def normalize_status(value: Any) -> list[str]:
    return _option_list(value, STATUSES, "status")


def normalize_since(value: Any) -> str | None:
    if value is None or str(value).strip() == "":
        return None
    text = str(value).strip()
    if not _SINCE_RE.match(text):
        raise QueryError("since must look like 2026-11-10T08:14:45Z")
    return text


def normalize_search(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    if not text:
        return None
    if len(text) > 200:
        raise QueryError("search is longer than 200 characters")
    return text


def _like(value: str) -> str:
    escaped = (value.replace("\\", "\\\\")
               .replace("%", "\\%")
               .replace("_", "\\_"))
    return f"%{escaped}%"


def _placeholder_list(values: list[str]) -> str:
    return ", ".join("?" for _ in values)


def _sql_literal(value: Any) -> str:
    if value is None:
        return "NULL"
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (int, float)):
        return str(value)
    return "'" + str(value).replace("'", "''") + "'"


def _display_sql(sql: str, params: list[Any]) -> str:
    """Render bound values into the SQL shown to the operator."""
    if not params:
        return sql
    out: list[str] = []
    index = 0
    for char in sql:
        if char == "?" and index < len(params):
            out.append(_sql_literal(params[index]))
            index += 1
        else:
            out.append(char)
    return "".join(out)


def _finding_sql(
    name: str,
    limit: int,
    search: str | None,
    severity: list[str],
    status: list[str],
    since: str | None,
) -> tuple[str, list[Any]]:
    clauses: list[str] = []
    params: list[Any] = []
    if name == "inbox":
        clauses.append(
            "status IN ('open', 'investigating') "
            "AND severity IN ('critical', 'error', 'warning')")
    elif name == "errors":
        clauses.append(
            "status IN ('open', 'investigating') "
            "AND severity IN ('critical', 'error')")
    if search:
        clauses.append(
            "(rule LIKE ? ESCAPE '\\' OR subject LIKE ? ESCAPE '\\' "
            "OR detail LIKE ? ESCAPE '\\' OR fingerprint LIKE ? ESCAPE '\\')")
        pattern = _like(search)
        params.extend([pattern, pattern, pattern, pattern])
    if severity:
        clauses.append(f"severity IN ({_placeholder_list(severity)})")
        params.extend(severity)
    if status:
        clauses.append(
            "(" + " AND ".join("status = ?" for _ in status) + ")")
        params.extend(status)
    if since:
        clauses.append("ts >= ?")
        params.append(since)
    where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
    sql = (
        "SELECT id, ts, last_ts, severity, status, rule, subject, count, detail, "
        "case_id, fingerprint, evidence_path FROM findings"
        f"{where} ORDER BY {_FINDING_SEVERITY_ORDER}, last_ts DESC, id DESC "
        f"LIMIT {limit}"
    )
    return sql, params


def _filtered_category_sql(
    name: str,
    limit: int,
    search: str | None,
    severity: list[str],
    status: list[str],
    since: str | None,
) -> tuple[str, list[Any]]:
    if name in FINDING_CATEGORIES:
        return _finding_sql(name, limit, search, severity, status, since)
    if name == "events":
        if status:
            raise QueryError("status filtering applies only to findings")
        clauses: list[str] = []
        params: list[Any] = []
        if search:
            clauses.append(
                "(message LIKE ? ESCAPE '\\' OR unit LIKE ? ESCAPE '\\' "
                "OR comm LIKE ? ESCAPE '\\' OR fingerprint LIKE ? ESCAPE '\\')")
            pattern = _like(search)
            params.extend([pattern, pattern, pattern, pattern])
        if severity:
            clauses.append(f"severity IN ({_placeholder_list(severity)})")
            params.extend(severity)
        if since:
            clauses.append("ts >= ?")
            params.append(since)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        return (
            "SELECT id, ts, last_ts, severity, count, source, unit, comm, message, "
            "boot_id, pid, fingerprint, length(raw) AS raw_bytes "
            f"FROM events{where} ORDER BY last_ts DESC, ts DESC, id DESC LIMIT {limit}",
            params,
        )
    if name == "crashes":
        if severity or status:
            raise QueryError(
                "severity and status filtering apply only to findings and events")
        clauses = []
        params = []
        if search:
            clauses.append(
                "(comm LIKE ? ESCAPE '\\' OR sig LIKE ? ESCAPE '\\' "
                "OR exe LIKE ? ESCAPE '\\' OR context LIKE ? ESCAPE '\\' "
                "OR fingerprint LIKE ? ESCAPE '\\')")
            pattern = _like(search)
            params.extend([pattern, pattern, pattern, pattern, pattern])
        if since:
            clauses.append("ts >= ?")
            params.append(since)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        return (
            "SELECT id, ts, comm, sig, faultcore_involved, cpus_allowed, exe, "
            "fingerprint, context, pid, corefile "
            f"FROM crashes{where} "
            f"ORDER BY ts DESC, id DESC LIMIT {limit}",
            params,
        )
    if search or severity or status or since:
        raise QueryError(f"filters are not supported for category {name}")
    return _category_sql(name, limit), []


def _skip_space_and_comments(sql: str, index: int) -> int:
    """Advance over whitespace and SQL comments."""
    length = len(sql)
    while index < length:
        char = sql[index]
        if char.isspace():
            index += 1
            continue
        if char == "-" and index + 1 < length and sql[index + 1] == "-":
            newline = sql.find("\n", index + 2)
            index = length if newline < 0 else newline + 1
            continue
        if char == "/" and index + 1 < length and sql[index + 1] == "*":
            end = sql.find("*/", index + 2)
            if end < 0:
                raise QueryError("unterminated comment")
            index = end + 2
            continue
        break
    return index


def _semicolon_positions(sql: str) -> list[int]:
    """Find top-level semicolons while ignoring quoted text and comments."""
    positions: list[int] = []
    index = 0
    length = len(sql)
    quote = ""
    while index < length:
        char = sql[index]
        if quote:
            if char == quote:
                if index + 1 < length and sql[index + 1] == quote:
                    index += 2
                    continue
                quote = ""
            index += 1
            continue
        if char in ("'", '"', "`", "["):
            quote = "]" if char == "[" else char
            index += 1
            continue
        if char == "-" and index + 1 < length and sql[index + 1] == "-":
            newline = sql.find("\n", index + 2)
            index = length if newline < 0 else newline + 1
            continue
        if char == "/" and index + 1 < length and sql[index + 1] == "*":
            end = sql.find("*/", index + 2)
            if end < 0:
                raise QueryError("unterminated comment")
            index = end + 2
            continue
        if char == ";":
            positions.append(index)
        index += 1
    if quote:
        raise QueryError("unterminated quoted string")
    return positions


def _assert_single_read_statement(sql: str) -> None:
    if "\x00" in sql:
        raise QueryError("query contains a NUL byte")
    if len(sql) > MAX_SQL_CHARS:
        raise QueryError(f"query is longer than {MAX_SQL_CHARS} characters")

    positions = _semicolon_positions(sql)
    if positions:
        trailing = sql[positions[-1] + 1:]
        if _skip_space_and_comments(trailing, 0) != len(trailing):
            raise QueryError("only one statement is allowed")
        if len(positions) > 1:
            raise QueryError("only one statement is allowed")
        sql = sql[:positions[-1]].rstrip()

    start = _skip_space_and_comments(sql, 0)
    match = ""
    index = start
    while index < len(sql) and (sql[index].isalpha() or sql[index] == "_"):
        match += sql[index]
        index += 1
    if match.upper() not in ("SELECT", "WITH", "EXPLAIN"):
        raise QueryError("only read-only SELECT, WITH or EXPLAIN queries are allowed")


def _cycle_rows(conn: sqlite3.Connection, limit: int) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT id, ts, detail FROM runs WHERE task='cycle' "
        "ORDER BY id DESC LIMIT ?", (max(1, limit),)
    ).fetchall()
    out: list[dict[str, Any]] = []
    for row in rows:
        detail = row["detail"] or ""
        summary: dict[str, Any] = {}
        try:
            parsed = json.loads(detail)
            if isinstance(parsed, dict):
                candidate = parsed.get("layer1_findings")
                if isinstance(candidate, dict):
                    summary = candidate
        except (TypeError, ValueError):
            pass
        try:
            new_count = int(summary.get("new") or 0)
        except (TypeError, ValueError):
            new_count = 0
        by_severity = summary.get("by_severity")
        if not isinstance(by_severity, dict):
            by_severity = {}
        rules = summary.get("rules")
        if not isinstance(rules, list):
            rules = []
        ids = summary.get("ids")
        if not isinstance(ids, list):
            ids = []
        out.append({
            "run_id": int(row["id"]),
            "run_ts": row["ts"],
            "ts": summary.get("ts") or row["ts"],
            "new": new_count,
            "by_severity": by_severity,
            "rules": [str(rule) for rule in rules],
            "ids": ids,
            "detail": detail,
        })
    return out


def _structured_cycle(conn: sqlite3.Connection) -> dict[str, Any] | None:
    """Read the newest cycle from cycle_findings, independent of run detail."""
    try:
        row = conn.execute(
            "SELECT ts, COUNT(*) AS new FROM cycle_findings "
            "GROUP BY ts ORDER BY ts DESC LIMIT 1"
        ).fetchone()
    except sqlite3.OperationalError as exc:
        if "no such table" in str(exc).lower():
            return None
        raise
    if not row:
        return None
    ts = row["ts"]
    findings = conn.execute(
        "SELECT finding_id, rule, severity, subject FROM cycle_findings "
        "WHERE ts=? ORDER BY finding_id", (ts,)
    ).fetchall()
    by_severity: dict[str, int] = {}
    rules: list[str] = []
    ids: list[int] = []
    for finding in findings:
        severity = finding["severity"] or "info"
        by_severity[severity] = by_severity.get(severity, 0) + 1
        if finding["rule"] and finding["rule"] not in rules:
            rules.append(finding["rule"])
        ids.append(int(finding["finding_id"]))
    run = conn.execute(
        "SELECT id FROM runs WHERE task='cycle' AND ts >= ? "
        "ORDER BY ts ASC LIMIT 1", (ts,)
    ).fetchone()
    return {
        "run_id": int(run["id"]) if run else None,
        "run_ts": ts,
        "ts": ts,
        "new": int(row["new"]),
        "by_severity": by_severity,
        "rules": rules,
        "ids": ids,
        "detail": "",
    }


def latest_cycle(conn: sqlite3.Connection) -> dict[str, Any]:
    """Return the newest cycle and the newest cycle that created findings."""
    rows = _cycle_rows(conn, 200)
    latest = rows[0] if rows else None
    last_new = next((row for row in rows if row.get("new", 0) > 0), None)
    structured = _structured_cycle(conn)
    if structured and (last_new is None or structured["ts"] >= last_new["ts"]):
        last_new = structured
    return {
        "latest": latest,
        "last_new": last_new,
        "cycles_scanned": len(rows),
    }


def _authorizer(action, _arg1, _arg2, _dbname, _trigger):
    return sqlite3.SQLITE_OK if action in _ALLOWED_ACTIONS else sqlite3.SQLITE_DENY


def _allow_all(_action, _arg1, _arg2, _dbname, _trigger):
    # Python's set_authorizer(None) does not clear an installed callback on
    # every supported version; a permissive callback is the portable reset.
    return sqlite3.SQLITE_OK


def _cell(value: Any, truncated: list[bool]) -> Any:
    if value is None or isinstance(value, (int, float)):
        return value
    if isinstance(value, bytes):
        value = value.hex()
    if isinstance(value, str) and len(value) > MAX_CELL_CHARS:
        truncated[0] = True
        return value[:MAX_CELL_CHARS] + "…"
    return value


def run_sql(
    conn: sqlite3.Connection,
    statement: str,
    limit: Any = DEFAULT_LIMIT,
    *,
    category: str | None = None,
    label: str | None = None,
    params: list[Any] | None = None,
) -> dict[str, Any]:
    """Execute exactly one read-only statement and return a JSON-safe result."""
    sql = str(statement or "").strip()
    if not sql:
        raise QueryError("query is empty")
    max_rows = normalize_limit(limit)
    _assert_single_read_statement(sql)

    started = time.monotonic()
    deadline = started + MAX_QUERY_SECONDS
    cells_truncated = [False]
    conn.set_authorizer(_authorizer)
    conn.set_progress_handler(
        lambda: 1 if time.monotonic() > deadline else 0, 10000)
    try:
        cursor = conn.execute(sql, params or ())
        columns = [item[0] for item in (cursor.description or [])]
        raw_rows = cursor.fetchmany(max_rows + 1)
        truncated = len(raw_rows) > max_rows
        if truncated:
            raw_rows = raw_rows[:max_rows]
        rows = []
        result_chars = 0
        for row in raw_rows:
            values = [_cell(value, cells_truncated) for value in row]
            result_chars += sum(
                len(value) if isinstance(value, str) else 8 for value in values)
            rows.append(values)
            if result_chars > MAX_RESULT_CHARS:
                truncated = True
                break
    except sqlite3.OperationalError as exc:
        if "interrupted" in str(exc).lower():
            raise QueryError(
                f"query exceeded the {MAX_QUERY_SECONDS:g} second limit") from exc
        raise QueryError(str(exc)) from exc
    except sqlite3.DatabaseError as exc:
        raise QueryError(str(exc)) from exc
    finally:
        conn.set_progress_handler(None, 0)
        conn.set_authorizer(_allow_all)

    elapsed_ms = round((time.monotonic() - started) * 1000, 1)
    return {
        "category": category,
        "label": label,
        "sql": sql,
        "columns": columns,
        "rows": rows,
        "count": len(rows),
        "limit": max_rows,
        "truncated": truncated or cells_truncated[0],
        "elapsed_ms": elapsed_ms,
    }


def run_category(
    conn: sqlite3.Connection,
    name: str,
    limit: Any = DEFAULT_LIMIT,
    *,
    search: Any = None,
    severity: Any = None,
    status: Any = None,
    since: Any = None,
) -> dict[str, Any]:
    """Run one catalog category, with optional safe filters."""
    key = str(name or "").lower()
    max_rows = normalize_limit(limit)
    spec = CATEGORIES.get(key)
    if not spec:
        raise QueryError(
            f"unknown category; choose one of: {', '.join(CATEGORY_ORDER)}")
    search_text = normalize_search(search)
    severity_values = normalize_severity(severity)
    status_values = normalize_status(status)
    since_value = normalize_since(since)
    filters = {
        "search": search_text,
        "severity": severity_values,
        "status": status_values,
        "since": since_value,
    }

    if key == "cycles":
        if any(filters.values()):
            raise QueryError("filters are not supported for category cycles")
        started = time.monotonic()
        cycles = _cycle_rows(conn, max_rows + 1)
        truncated = len(cycles) > max_rows
        if truncated:
            cycles = cycles[:max_rows]
        rows = [
            [
                row["run_id"],
                row["ts"],
                row["new"],
                json.dumps(row["by_severity"], sort_keys=True,
                           separators=(",", ":")),
                ", ".join(row["rules"]),
                ", ".join(str(item) for item in row["ids"]),
                row["detail"],
            ]
            for row in cycles
        ]
        return {
            "category": key,
            "label": spec["label"],
            "sql": _category_sql(key, max_rows),
            "columns": ["run_id", "ts", "new", "by_severity", "rules", "ids",
                        "detail"],
            "rows": rows,
            "count": len(rows),
            "limit": max_rows,
            "truncated": truncated,
            "elapsed_ms": round((time.monotonic() - started) * 1000, 1),
            "filters": filters,
        }

    sql, params = _filtered_category_sql(
        key, max_rows + 1, search_text, severity_values, status_values,
        since_value)
    result = run_sql(
        conn, sql, max_rows, category=key, label=spec["label"], params=params)
    # The extra row only proves that the category is truncated; display the
    # limit the operator actually asked for.
    display_sql, display_params = _filtered_category_sql(
        key, max_rows, search_text, severity_values, status_values, since_value)
    result["sql"] = _display_sql(display_sql, display_params)
    result["filters"] = filters
    return result


def _one_line(value: Any) -> str:
    if value is None:
        return "NULL"
    text = str(value).replace("\r", " ").replace("\n", " ")
    return text


def format_table(result: dict[str, Any], max_width: int = 60) -> str:
    """Small dependency-free table renderer for the CLI."""
    columns = result.get("columns") or []
    rows = result.get("rows") or []
    if not columns:
        return "(no columns)"
    cells = [[_one_line(value) for value in row] for row in rows]
    widths = []
    for index, column in enumerate(columns):
        width = len(str(column))
        for row in cells:
            if index < len(row):
                width = max(width, len(row[index]))
        widths.append(min(width, max_width))

    def clip(text: str, width: int) -> str:
        return text if len(text) <= width else text[: max(1, width - 1)] + "…"

    header = "  ".join(clip(str(column), widths[i]).ljust(widths[i])
                       for i, column in enumerate(columns))
    rule = "  ".join("-" * width for width in widths)
    lines = [header, rule]
    for row in cells:
        lines.append("  ".join(
            clip(row[i] if i < len(row) else "", widths[i]).ljust(widths[i])
            for i in range(len(columns))
        ))
    meta = f"{result.get('count', len(rows))} row(s) in {result.get('elapsed_ms', 0)} ms"
    if result.get("truncated"):
        meta += f" (limit {result.get('limit')})"
    lines.extend(["", meta])
    return "\n".join(lines)
