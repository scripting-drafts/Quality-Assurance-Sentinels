"""Run the C sampler and persist its measurements."""
from __future__ import annotations

import json

from . import config, db
from .util import iso, run


class SampleError(RuntimeError):
    pass


def take_sample(conn) -> dict:
    rc, out, err = run([str(config.SAMPLE_BIN)], timeout=30)
    if rc != 0 or not out.strip():
        raise SampleError(f"qa_sample failed rc={rc}: {err.strip()[:400]}")
    data = json.loads(out)
    ts = data.get("ts") or iso()

    conn.execute(
        "INSERT OR IGNORE INTO samples(ts, boot_id, payload) VALUES(?,?,?)",
        (ts, data.get("boot_id"), json.dumps(data, separators=(",", ":"))),
    )

    rows = []
    for p in data.get("procs", []):
        rows.append(
            (
                ts,
                p.get("pid"),
                p.get("ppid"),
                p.get("comm"),
                p.get("state"),
                p.get("threads"),
                p.get("rss_kb"),
                p.get("cpu_ticks"),
                p.get("last_cpu"),
                p.get("cpus_allowed"),
                p.get("exe"),
            )
        )
    conn.executemany(
        "INSERT OR REPLACE INTO proc_snap"
        "(ts,pid,ppid,comm,state,threads,rss_kb,cpu_ticks,last_cpu,cpus_allowed,exe)"
        " VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        rows,
    )

    prune(conn)
    db.meta_set(conn, "last_sample_ts", ts)
    db.meta_set(conn, "last_boot_id", data.get("boot_id") or "")
    return data


def latest(conn) -> dict | None:
    row = conn.execute("SELECT payload FROM samples ORDER BY ts DESC LIMIT 1").fetchone()
    return json.loads(row["payload"]) if row else None


def boot_id(conn) -> str | None:
    row = conn.execute(
        "SELECT boot_id FROM samples ORDER BY ts DESC LIMIT 1"
    ).fetchone()
    return row["boot_id"] if row else None


def cpu_deltas(conn, limit: int = 2) -> list[dict]:
    """Busy percentage per logical CPU between the last two samples."""
    rows = conn.execute(
        "SELECT ts, payload FROM samples ORDER BY ts DESC LIMIT ?", (limit,)
    ).fetchall()
    if len(rows) < 2:
        return []
    newer = json.loads(rows[0]["payload"])
    older = json.loads(rows[1]["payload"])
    prev = {c["cpu"]: c for c in older.get("cpus", [])}
    result = []
    for cur in newer.get("cpus", []):
        old = prev.get(cur["cpu"])
        if not old:
            continue
        fields = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal")
        delta = {f: max(0, cur.get(f, 0) - old.get(f, 0)) for f in fields}
        total = sum(delta.values())
        busy = total - delta["idle"] - delta["iowait"]
        result.append(
            {
                "cpu": cur["cpu"],
                "total": total,
                "busy_pct": round(100.0 * busy / total, 1) if total else 0.0,
                "iowait_pct": round(100.0 * delta["iowait"] / total, 1) if total else 0.0,
                "system_pct": round(100.0 * delta["system"] / total, 1) if total else 0.0,
            }
        )
    return result


def prune(conn) -> None:
    if config.KEEP_FOREVER:
        return
    for table, days in (
        ("samples", config.SAMPLE_RETENTION_DAYS),
        ("proc_snap", config.PROC_RETENTION_DAYS),
        ("events", config.EVENT_RETENTION_DAYS),
    ):
        if days <= 0:
            continue
        conn.execute(
            f"DELETE FROM {table} WHERE ts < datetime('now', ?)",
            (f"-{days} days",),
        )
    if config.INVENTORY_RETENTION_DAYS > 0:
        cutoff = f"-{config.INVENTORY_RETENTION_DAYS} days"
        conn.execute(
            "DELETE FROM inventory WHERE run_id IN "
            "(SELECT id FROM inventory_runs WHERE ts < datetime('now', ?))",
            (cutoff,),
        )
        conn.execute(
            "DELETE FROM inventory_diffs WHERE ts < datetime('now', ?)", (cutoff,)
        )
        conn.execute(
            "DELETE FROM inventory_runs WHERE ts < datetime('now', ?)", (cutoff,)
        )
    hw_cutoff = f"-{config.HARDWARE_RETENTION_DAYS} days"
    conn.execute(
        "DELETE FROM hardware_items WHERE run_id IN "
        "(SELECT id FROM hardware_runs WHERE ts < datetime('now', ?))",
        (hw_cutoff,),
    )
    conn.execute("DELETE FROM hardware_runs WHERE ts < datetime('now', ?)", (hw_cutoff,))
    lsm_cutoff = f"-{config.LSM_RETENTION_DAYS} days"
    conn.execute("DELETE FROM lsm_runs WHERE ts < datetime('now', ?)", (lsm_cutoff,))
