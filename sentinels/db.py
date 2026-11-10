"""SQLite store. WAL mode so the sampler, ingester and reports never block."""
from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager

from . import config

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE IF NOT EXISTS samples (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL UNIQUE,
    boot_id TEXT,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_samples_ts ON samples(ts);
CREATE TABLE IF NOT EXISTS proc_snap (
    ts TEXT NOT NULL,
    pid INTEGER NOT NULL,
    ppid INTEGER,
    comm TEXT,
    state TEXT,
    threads INTEGER,
    rss_kb INTEGER,
    cpu_ticks INTEGER,
    last_cpu INTEGER,
    cpus_allowed TEXT,
    exe TEXT,
    PRIMARY KEY (ts, pid)
);
CREATE INDEX IF NOT EXISTS idx_proc_pid ON proc_snap(pid, ts);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    boot_id TEXT,
    source TEXT,
    severity TEXT,
    unit TEXT,
    pid INTEGER,
    comm TEXT,
    message TEXT,
    fingerprint TEXT UNIQUE,
    raw TEXT,
    count INTEGER NOT NULL DEFAULT 1,
    last_ts TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_sev ON events(severity, ts);
CREATE TABLE IF NOT EXISTS crashes (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    pid INTEGER,
    comm TEXT,
    exe TEXT,
    sig TEXT,
    corefile TEXT,
    cpus_allowed TEXT,
    core2_involved INTEGER,
    context TEXT,
    fingerprint TEXT UNIQUE
);
CREATE INDEX IF NOT EXISTS idx_crashes_ts ON crashes(ts);
CREATE TABLE IF NOT EXISTS boots (
    id INTEGER PRIMARY KEY,
    boot_id TEXT NOT NULL UNIQUE,
    seq INTEGER,
    span TEXT,
    last_ts TEXT,
    ended_clean INTEGER,
    markers TEXT,
    last_message TEXT,
    scans TEXT,
    pstore TEXT,
    kexec_loaded INTEGER,
    crashkernel TEXT,
    vmcores INTEGER,
    captured_ts TEXT
);
CREATE INDEX IF NOT EXISTS idx_boots_last ON boots(last_ts);
CREATE TABLE IF NOT EXISTS correlations (
    id INTEGER PRIMARY KEY,
    boot_id TEXT NOT NULL,
    vendor TEXT NOT NULL,
    component TEXT,
    signature TEXT NOT NULL,
    display TEXT,
    occurrences INTEGER NOT NULL DEFAULT 0,
    crashes INTEGER NOT NULL DEFAULT 0,
    window_start TEXT,
    window_end TEXT,
    created TEXT,
    UNIQUE(boot_id, vendor, signature)
);
CREATE INDEX IF NOT EXISTS idx_corr_sig ON correlations(vendor, signature);
CREATE TABLE IF NOT EXISTS notifications (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    kind TEXT,
    key TEXT NOT NULL UNIQUE,
    title TEXT,
    body TEXT,
    delivered INTEGER NOT NULL DEFAULT 0,
    detail TEXT,
    path TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    last_attempt TEXT,
    last_error TEXT
);
CREATE INDEX IF NOT EXISTS idx_notify_pending ON notifications(delivered, ts);
CREATE TABLE IF NOT EXISTS crosschecks (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    checked INTEGER NOT NULL DEFAULT 0,
    drift INTEGER NOT NULL DEFAULT 0,
    detail TEXT
);
CREATE TABLE IF NOT EXISTS inventory_runs (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    counts TEXT,
    digest TEXT,
    note TEXT
);
CREATE TABLE IF NOT EXISTS inventory (
    run_id INTEGER NOT NULL,
    layer TEXT NOT NULL,
    item TEXT NOT NULL,
    value TEXT,
    PRIMARY KEY (run_id, layer, item)
);
CREATE TABLE IF NOT EXISTS inventory_diffs (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    run_id INTEGER,
    layer TEXT,
    change TEXT,
    item TEXT,
    old_value TEXT,
    new_value TEXT
);
CREATE TABLE IF NOT EXISTS hardware_runs (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    status TEXT,
    sources TEXT,
    duration_ms INTEGER,
    detail TEXT
);
CREATE INDEX IF NOT EXISTS idx_hardware_ts ON hardware_runs(ts);
CREATE TABLE IF NOT EXISTS hardware_items (
    run_id INTEGER NOT NULL,
    source TEXT NOT NULL,
    item TEXT NOT NULL,
    value TEXT,
    PRIMARY KEY (run_id, source, item)
);
CREATE TABLE IF NOT EXISTS lsm_runs (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    digest TEXT,
    state TEXT,
    denials TEXT,
    status TEXT
);
CREATE INDEX IF NOT EXISTS idx_lsm_ts ON lsm_runs(ts);
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    kind TEXT,
    path TEXT,
    summary TEXT
);
CREATE TABLE IF NOT EXISTS bundles (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    path TEXT,
    sha256 TEXT,
    prev_sha256 TEXT,
    contents TEXT
);
CREATE TABLE IF NOT EXISTS ticket_drafts (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    vendor TEXT,
    path TEXT,
    title TEXT,
    issue_key TEXT UNIQUE
);
CREATE TABLE IF NOT EXISTS core2_cases (
    id INTEGER PRIMARY KEY,
    case_key TEXT UNIQUE,
    created TEXT NOT NULL,
    updated TEXT NOT NULL,
    kind TEXT,
    verdict TEXT,
    process TEXT,
    signature TEXT,
    detail TEXT,
    affinity TEXT,
    event_ts TEXT,
    status TEXT NOT NULL DEFAULT 'open',
    notes TEXT,
    path TEXT
);
CREATE INDEX IF NOT EXISTS idx_core2_status ON core2_cases(status, verdict);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY,
    fingerprint TEXT UNIQUE,
    ts TEXT NOT NULL,
    last_ts TEXT,
    rule TEXT,
    severity TEXT,
    subject TEXT,
    detail TEXT,
    count INTEGER NOT NULL DEFAULT 1,
    status TEXT NOT NULL DEFAULT 'open',
    case_id INTEGER,
    evidence_path TEXT
);
CREATE INDEX IF NOT EXISTS idx_findings_ts ON findings(ts);
CREATE TABLE IF NOT EXISTS cycle_findings (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    finding_id INTEGER NOT NULL,
    rule TEXT,
    severity TEXT,
    subject TEXT,
    UNIQUE(ts, finding_id)
);
CREATE INDEX IF NOT EXISTS idx_cycle_findings_ts ON cycle_findings(ts);
CREATE TABLE IF NOT EXISTS deep_runs (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    case_id INTEGER,
    finding_id INTEGER,
    status TEXT,
    reason TEXT,
    duration_s INTEGER,
    pid INTEGER,
    comm TEXT,
    path TEXT,
    sha256 TEXT,
    summary TEXT
);
CREATE INDEX IF NOT EXISTS idx_deep_case ON deep_runs(case_id, ts);
CREATE TABLE IF NOT EXISTS runs (
    id INTEGER PRIMARY KEY,
    ts TEXT NOT NULL,
    task TEXT,
    ok INTEGER,
    detail TEXT
);
"""


def connect() -> sqlite3.Connection:
    config.ensure_dirs()
    conn = sqlite3.connect(str(config.DB_PATH), timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute("PRAGMA busy_timeout=30000")
    return conn


def connect_readonly() -> sqlite3.Connection:
    """Open sentinels.db without write permission for the query engine."""
    config.ensure_dirs()
    uri = f"file:{config.DB_PATH}?mode=ro"
    conn = sqlite3.connect(uri, uri=True, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA query_only=ON")
    conn.execute("PRAGMA busy_timeout=10000")
    return conn


def init() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(events)")}
        if "count" not in cols:
            conn.execute("ALTER TABLE events ADD COLUMN count INTEGER NOT NULL DEFAULT 1")
        if "last_ts" not in cols:
            conn.execute("ALTER TABLE events ADD COLUMN last_ts TEXT")
        ccols = {r["name"] for r in conn.execute("PRAGMA table_info(correlations)")}
        if ccols and "display" not in ccols:
            conn.execute("ALTER TABLE correlations ADD COLUMN display TEXT")
        ncols = {r["name"] for r in conn.execute("PRAGMA table_info(notifications)")}
        for column, ddl in (
            ("path", "TEXT"),
            ("attempts", "INTEGER NOT NULL DEFAULT 0"),
            ("last_attempt", "TEXT"),
            ("last_error", "TEXT"),
        ):
            if ncols and column not in ncols:
                conn.execute(f"ALTER TABLE notifications ADD COLUMN {column} {ddl}")
        conn.execute("INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version','1')")
        try:
            os.chmod(config.DB_PATH, 0o600)
        except OSError:
            pass


@contextmanager
def session():
    init()
    conn = connect()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def meta_get(conn, key: str, default: str | None = None) -> str | None:
    row = conn.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def meta_set(conn, key: str, value: str) -> None:
    conn.execute(
        "INSERT INTO meta(key, value) VALUES(?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (key, str(value)),
    )


def record_run(conn, task: str, ok: bool, detail: str = "") -> None:
    from .util import iso

    conn.execute(
        "INSERT INTO runs(ts, task, ok, detail) VALUES(?,?,?,?)",
        (iso(), task, 1 if ok else 0, detail[:2000]),
    )


def record_cycle_findings(conn, ts: str, findings: list[dict]) -> int:
    """Persist the findings newly created by one cycle for the Inbox."""
    rows = [
        (
            ts,
            int(finding["id"]),
            finding.get("rule"),
            finding.get("severity"),
            finding.get("subject"),
        )
        for finding in findings
        if finding.get("id") is not None
    ]
    if not rows:
        return 0
    conn.executemany(
        "INSERT OR IGNORE INTO cycle_findings(ts, finding_id, rule, severity, subject) "
        "VALUES(?,?,?,?,?)",
        rows,
    )
    return len(rows)
