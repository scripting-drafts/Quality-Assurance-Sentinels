"""SQLite store. WAL mode so the sampler, ingester and reports never block."""
from __future__ import annotations

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


def init() -> None:
    with connect() as conn:
        conn.executescript(SCHEMA)
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(events)")}
        if "count" not in cols:
            conn.execute("ALTER TABLE events ADD COLUMN count INTEGER NOT NULL DEFAULT 1")
        if "last_ts" not in cols:
            conn.execute("ALTER TABLE events ADD COLUMN last_ts TEXT")
        conn.execute("INSERT OR IGNORE INTO meta(key, value) VALUES('schema_version','1')")


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
