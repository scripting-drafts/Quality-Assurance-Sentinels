"""Startup, daily and on-demand QA reports plus the running journal."""
from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timedelta, timezone

from . import boot, config, db, deep, detect, posture, triage
from .util import fmt_duration, human_bytes, iso, parse_iso, read_text, redact

SEV_ORDER = {"critical": 0, "error": 1, "warning": 2, "info": 3}


# --------------------------------------------------------------- queries
def events_since(conn, since_iso: str, severities=("critical", "error", "warning")):
    marks = ",".join("?" for _ in severities)
    return conn.execute(
        f"SELECT * FROM events WHERE ts>=? AND severity IN ({marks}) "
        "ORDER BY ts DESC",
        (since_iso, *severities),
    ).fetchall()


def crashes_since(conn, since_iso: str):
    return conn.execute(
        "SELECT * FROM crashes WHERE ts>=? ORDER BY ts DESC", (since_iso,)
    ).fetchall()


def _event_groups(rows) -> list[dict]:
    from .classify import signature

    groups: dict[tuple[str, str], dict] = {}
    for row in rows:
        sig = signature(row["message"])
        unit = (row["unit"] or "").split(".")[0]
        key = (unit, sig)
        n = int(row["count"] or 1) if "count" in row.keys() else 1
        g = groups.setdefault(
            key,
            {
                "unit": unit,
                "signature": sig,
                "count": 0,
                "first": row["ts"],
                "last": row["ts"],
                "severity": row["severity"],
                "example": row["message"],
            },
        )
        g["count"] += n
        g["first"] = min(g["first"], row["ts"])
        g["last"] = max(g["last"], row["ts"])
        if SEV_ORDER.get(row["severity"], 9) < SEV_ORDER.get(g["severity"], 9):
            g["severity"] = row["severity"]
    return sorted(groups.values(), key=lambda g: (-g["count"], g["unit"]))


def _sample_stats(conn, since_iso: str) -> dict:
    rows = conn.execute(
        "SELECT ts, payload FROM samples WHERE ts>=? ORDER BY ts", (since_iso,)
    ).fetchall()
    stats = {
        "samples": len(rows),
        "cpu": {"mean_busy": None, "max_busy": None, "mean_iowait": None, "max_iowait": None},
        "core2": {"mean_busy": None, "max_busy": None},
        "mem_available_min_kb": None,
        "swap_free_min_kb": None,
        "psi": {"cpu_max": None, "io_max": None, "memory_max": None, "memory_full_max": None},
        "temp_max_c": None,
        "oom_kills": 0,
        "load_max": None,
    }
    if not rows:
        return stats

    payloads = [json.loads(r["payload"]) for r in rows]
    busy_all, iowait_all, core2_busy = [], [], []
    mem_min = swap_min = temp_max = load_max = None
    oom_first = oom_last = None

    for prev, cur in zip(payloads, payloads[1:]):
        prev_cpus = {c["cpu"]: c for c in prev.get("cpus", [])}
        for c in cur.get("cpus", []):
            p = prev_cpus.get(c["cpu"])
            if not p:
                continue
            fields = ("user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal")
            d = {f: max(0, c.get(f, 0) - p.get(f, 0)) for f in fields}
            total = sum(d.values())
            if not total:
                continue
            busy = 100.0 * (total - d["idle"] - d["iowait"]) / total
            iow = 100.0 * d["iowait"] / total
            busy_all.append(busy)
            iowait_all.append(iow)
            if c["cpu"] in config.CORE2_CPUS:
                core2_busy.append(busy)

    for p in payloads:
        mem = p.get("mem", {})
        if mem.get("MemAvailable") is not None:
            mem_min = mem["MemAvailable"] if mem_min is None else min(mem_min, mem["MemAvailable"])
        if mem.get("SwapFree") is not None:
            swap_min = mem["SwapFree"] if swap_min is None else min(swap_min, mem["SwapFree"])
        for t in p.get("thermal", []):
            v = t.get("millideg_c", 0) / 1000.0
            if -20 < v < 200:
                temp_max = v if temp_max is None else max(temp_max, v)
        load = p.get("loadavg") or []
        if len(load) >= 3:
            load_max = load[0] if load_max is None else max(load_max, load[0])
        if oom_first is None:
            oom_first = p.get("oom_kill")
        oom_last = p.get("oom_kill")

    def _psi_max(key: str, kind: str):
        vals = []
        for p in payloads:
            try:
                vals.append(p["psi"][key][kind]["avg300"])
            except (KeyError, TypeError):
                continue
        return max(vals) if vals else None

    stats.update(
        {
            "cpu": {
                "mean_busy": round(sum(busy_all) / len(busy_all), 1) if busy_all else None,
                "max_busy": round(max(busy_all), 1) if busy_all else None,
                "mean_iowait": round(sum(iowait_all) / len(iowait_all), 1) if iowait_all else None,
                "max_iowait": round(max(iowait_all), 1) if iowait_all else None,
            },
            "core2": {
                "mean_busy": round(sum(core2_busy) / len(core2_busy), 1) if core2_busy else None,
                "max_busy": round(max(core2_busy), 1) if core2_busy else None,
            },
            "mem_available_min_kb": mem_min,
            "swap_free_min_kb": swap_min,
            "psi": {
                "cpu_max": _psi_max("cpu", "some"),
                "io_max": _psi_max("io", "some"),
                "memory_max": _psi_max("memory", "some"),
                "memory_full_max": _psi_max("memory", "full"),
            },
            "temp_max_c": round(temp_max, 1) if temp_max is not None else None,
            "load_max": load_max,
            "oom_kills": (oom_last - oom_first) if (oom_last is not None and oom_first is not None) else 0,
        }
    )
    return stats


def _core2_section(conn, since_iso: str) -> str:
    crashes = crashes_since(conn, since_iso)
    yes = [c for c in crashes if c["core2_involved"] == 1]
    no = [c for c in crashes if c["core2_involved"] == 0]
    unknown = [c for c in crashes if c["core2_involved"] is None]

    row = conn.execute("SELECT payload FROM samples ORDER BY ts DESC LIMIT 1").fetchone()
    current_line = "no sample yet"
    firefox_line = "no Firefox ESR process in the latest sample"
    if row:
        data = json.loads(row["payload"])
        current_line = (
            f"online CPUs `{data.get('online_cpus')}`; "
            f"core {config.CORE2_PHYSICAL_ID} logical CPUs `{data.get('core2', {}).get('logical')}`"
        )
        ff = [p for p in data.get("procs", [])
              if "firefox" in (p.get("comm") or "").lower()
              or "firefox" in (p.get("exe") or "").lower()]
        if ff:
            masks = Counter(p.get("cpus_allowed") or "unknown" for p in ff)
            firefox_line = "; ".join(f"`{m}` x{n}" for m, n in masks.most_common())

    lines = [
        "## Physical core 2 evidence",
        "",
        f"- Topology now: {current_line}.",
        f"- Firefox ESR affinity in latest sample: {firefox_line}.",
        f"- Crashes in window: **{len(crashes)}** | affinity included core 2: **{len(yes)}** "
        f"| excluded core 2: **{len(no)}** | unknown affinity: **{len(unknown)}**.",
    ]
    if yes:
        lines.append("")
        lines.append("| time (UTC) | process | signal | allowed CPUs |")
        lines.append("|---|---|---|---|")
        for c in yes[:15]:
            lines.append(
                f"| {c['ts']} | `{c['comm'] or c['exe']}` | {c['sig']} | `{c['cpus_allowed']}` |"
            )
    lines += [
        "",
        "Correlation, not proof: affinity is read from the last `/proc/<pid>/status` "
        "snapshot before the crash. Unknown affinity is reported as unknown, never dropped. "
        "These rows are part of the QA record and are not omitted from vendor tickets.",
    ]
    return "\n".join(lines)


# --------------------------------------------------------------- reports
# Deprecated shims: the implementation lives in boot.py now.
def _boot_info() -> dict:
    return boot.boot_info()


def _boot_journal(boot_ref: str, limit: int = 40, tail_only: bool = False
                  ) -> tuple[int, list[str]]:
    return boot.journal_tail(boot_ref, limit=limit, tail_only=tail_only)


def _num(value, suffix: str = "", digits: int = 1) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, float):
        return f"{value:.{digits}f}{suffix}"
    return f"{value}{suffix}"


def _environment_block() -> list[str]:
    cpu = ""
    for line in read_text("/proc/cpuinfo").splitlines():
        if line.lower().startswith("model name"):
            cpu = line.split(":", 1)[1].strip()
            break
    os_name = ""
    for line in read_text("/etc/os-release").splitlines():
        if line.startswith("PRETTY_NAME="):
            os_name = line.split("=", 1)[1].strip('"')
            break
    return [
        f"- Kernel: `{read_text('/proc/sys/kernel/osrelease')}`",
        f"- OS: `{os_name}`",
        f"- CPU: `{cpu}`",
    ]


def build_report(conn, kind: str = "daily", hours: int = 24) -> tuple[str, str]:
    now = datetime.now(timezone.utc)
    since = (now - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    events = events_since(conn, since)
    groups = _event_groups(events)
    crashes = crashes_since(conn, since)
    stats = _sample_stats(conn, since)
    inv = conn.execute("SELECT * FROM inventory_runs ORDER BY id DESC LIMIT 1").fetchone()
    inv_diffs = []
    if inv:
        inv_diffs = conn.execute(
            "SELECT * FROM inventory_diffs WHERE run_id=? ORDER BY layer, change, item",
            (inv["id"],),
        ).fetchall()

    counts = Counter()
    total_events = 0
    for e in events:
        n = int(e["count"] or 1) if "count" in e.keys() else 1
        counts[e["severity"]] += n
        total_events += n
    title = f"{kind.capitalize()} QA report — {now.strftime('%Y-%m-%d %H:%M UTC')}"
    body = [f"# {title}", ""]
    body += _environment_block()
    body.append(f"- Posture: {posture.line()}")
    body.append(f"- Window: last {hours} h (`{since}` → `{iso(now)}`)")
    body += [
        "",
        "## Headline",
        "",
        f"- Events: **{total_events}** (critical {counts.get('critical', 0)}, "
        f"error {counts.get('error', 0)}, warning {counts.get('warning', 0)}); "
        f"{len(groups)} distinct signatures",
        f"- Crashes/coredumps/minidumps: **{len(crashes)}** "
        f"(core-2 affinity {sum(1 for c in crashes if c['core2_involved'] == 1)})",
        f"- CPU busy mean/max: **{_num(stats['cpu']['mean_busy'], '%')} / "
        f"{_num(stats['cpu']['max_busy'], '%')}**, iowait max {_num(stats['cpu']['max_iowait'], '%')}",
        f"- Memory available min: **{human_bytes(stats['mem_available_min_kb']) if stats['mem_available_min_kb'] is not None else 'n/a'}**; "
        f"swap free min {human_bytes(stats['swap_free_min_kb']) if stats['swap_free_min_kb'] is not None else 'n/a'}",
        f"- PSI max (avg300): cpu {_num(stats['psi']['cpu_max'])}, io {_num(stats['psi']['io_max'])}, "
        f"memory {_num(stats['psi']['memory_max'])} (full {_num(stats['psi']['memory_full_max'])})",
        f"- Hottest sensor: **{_num(stats['temp_max_c'], ' °C')}**; load max {_num(stats['load_max'])}; "
        f"OOM kills in window {stats['oom_kills']}",
    ]

    if kind == "startup":
        boot_info = boot.boot_info()
        body += [
            "",
            "## Boot",
            "",
            f"- Current boot: `{boot_info['boot_time']}` (uptime {boot_info['uptime']} s)",
        ]
        boundary = boot.latest(conn)
        if boundary:
            line = (
                f"- Previous boot boundary: **{boot.verdict(boundary)}** "
                f"(`{boundary['boot_id'][:8]}`, last entry {boundary['last_ts']})"
            )
            if boundary.get("ended_clean") == 0:
                line += (
                    " — the journal ends without `systemd-shutdown`, so the machine "
                    "stopped before a shutdown sequence began"
                )
            body.append(line)
            counts = boot.scan_counts(boundary)
            hits = ", ".join(
                f"{v['label']} {v['count']}" for v in counts.values() if v.get("count")
            )
            body.append(
                f"- Boot evidence: {hits or 'no failure signatures'}; "
                f"pstore {boundary.get('pstore')}, "
                f"kexec_crash_loaded {boundary.get('kexec_loaded')}"
            )
        prev_count, prev_lines = boot.journal_tail("-1")
        _cur_count, cur_lines = boot.journal_tail("0", tail_only=True)
        cur_flag = conn.execute(
            "SELECT severity, COALESCE(SUM(count),0) n FROM events WHERE ts>=? GROUP BY severity",
            (boot_info["boot_time"],),
        ).fetchall()
        cur_total = sum(int(r["n"]) for r in cur_flag)
        cur_detail = ", ".join(f"{r['severity']} {r['n']}" for r in cur_flag) or "none"
        body += [
            f"- Previous boot raw warnings-or-worse (journal priority): **{prev_count}**",
            f"- Current boot flagged events (sentinel classifier): **{cur_total}** ({cur_detail})",
            "",
            "### Previous boot tail (oldest → newest, redacted)",
            "",
            "```",
            redact("\n".join(prev_lines)) or "(none)",
            "```",
            "",
            "### Current boot tail",
            "",
            "```",
            redact("\n".join(cur_lines)) or "(none)",
            "```",
        ]

    body += ["", "## Top recurring events", ""]
    if groups:
        body += ["| count | severity | unit | signature |", "|---:|---|---|---|"]
        for g in groups[:20]:
            sig = g["signature"].replace("|", "\\|")[:140]
            body.append(f"| {g['count']} | {g['severity']} | `{g['unit']}` | {sig} |")
    else:
        body.append("_No warning-or-worse events in this window._")

    body += ["", "## Crashes", ""]
    if crashes:
        body += ["| time (UTC) | process | signal | allowed CPUs | core 2 in mask |",
                 "|---|---|---|---|---|"]
        for c in crashes[:25]:
            verdict = {1: "yes", 0: "no", None: "unknown"}[c["core2_involved"]]
            body.append(
                f"| {c['ts']} | `{c['comm'] or c['exe']}` | {c['sig']} | "
                f"`{c['cpus_allowed'] or 'unknown'}` | {verdict} |"
            )
    else:
        body.append("_No crashes recorded in this window._")

    body += ["", _core2_section(conn, since)]

    tri = triage.summary(conn)
    tri_rows = triage.cases(conn, limit=12)
    body += [
        "",
        "## Core-2 triage side queue",
        "",
        f"- Cases: **{tri['total']}** — by status `{tri['by_status']}`, "
        f"by verdict `{tri['by_verdict']}`",
        f"- Dossier: [`../../triage/core2/index.md`](../../triage/core2/index.md) "
        f"(one file per case, kept for investigation)",
        "",
    ]
    if tri_rows:
        body += ["| case | verdict | status | process | last event |", "|---|---|---|---|---|"]
        for row in tri_rows:
            body.append(
                f"| [{row['id']}](../../triage/core2/case-{row['id']:04d}.md) | {row['verdict']} | "
                f"{row['status']} | `{row['process']}` | {row['event_ts']} |"
            )
    else:
        body.append(
            "_No core-2 cases recorded yet. Confirmed, suspected, control and "
            "unresolved-affinity events will appear here automatically._"
        )
    body += [
        "",
        "Side-queue policy: core-2 cases are separated for focused investigation, "
        "not removed from the main record or from vendor evidence.",
    ]

    findings = detect.list_findings(conn, limit=12, status="open")
    fcounts = {
        r["severity"]: r["n"]
        for r in conn.execute(
            "SELECT severity, COUNT(*) n FROM findings WHERE status='open' GROUP BY severity"
        )
    }
    body += [
        "",
        "## Phase 1 — real-time detection",
        "",
        f"- Open findings: **{sum(fcounts.values())}** {fcounts or ''}",
    ]
    if findings:
        body += ["| id | severity | rule | subject | count | detail |",
                 "|---:|---|---|---|---:|---|"]
        for row in findings:
            detail = redact(row["detail"] or "").replace("|", "\\|")[:110]
            body.append(
                f"| {row['id']} | {row['severity']} | `{row['rule']}` | `{row['subject']}` | "
                f"{row['count']} | {detail} |"
            )
    else:
        body.append("_No open phase-1 findings._")

    deep_rows = [
        dict(r) for r in conn.execute(
            "SELECT * FROM deep_runs ORDER BY id DESC LIMIT 8"
        )
    ]
    body += [
        "",
        "## Phase 2 — deep investigation",
        "",
        f"- Pending requests: **{len(deep.pending_requests())}** "
        f"(`triage/core2/deep-requests/`)",
        f"- Deep runs: **{conn.execute('SELECT COUNT(*) FROM deep_runs').fetchone()[0]}** "
        f"(`triage/core2/deep/index.md`)",
    ]
    if deep_rows:
        body += ["| run | case | status | trace lines | core-2 % | path |",
                 "|---:|---|---|---:|---:|---|"]
        for row in deep_rows:
            try:
                summary = json.loads(row["summary"] or "{}")
            except json.JSONDecodeError:
                summary = {}
            body.append(
                f"| {row['id']} | {row['case_id'] or '—'} | {row['status']} | "
                f"{summary.get('trace_lines', '—')} | {summary.get('core2_pct', '—')} | "
                f"`{row['path']}` |"
            )
    else:
        body.append("_No deep runs yet. Phase 1 queues one for critical findings; "
                    "install the phase-2 path unit with `sudo root/install-system.sh`._")

    body += ["", "## Inventory (every ~3 h)", ""]
    if inv:
        interval = db.meta_get(conn, "inventory_interval_s")
        next_ts = db.meta_get(conn, "next_inventory_ts")
        body += [
            f"- Latest run: `{inv['ts']}` (run {inv['id']}), digest `{inv['digest'][:16]}…`",
            f"- Items per layer: `{inv['counts']}`",
            f"- Changes vs previous run: **{len(inv_diffs)}**",
            f"- Adaptive renewal: next `{next_ts or 'n/a'}` "
            f"(interval {fmt_duration(int(interval)) if interval else 'n/a'}, note `{inv['note']}`)",
        ]
        if inv_diffs:
            body += ["", "| layer | change | item |", "|---|---|---|"]
            for d in inv_diffs[:40]:
                body.append(f"| {d['layer']} | {d['change']} | `{d['item']}` |")
    else:
        body.append("_No inventory yet._")

    body += ["", "## Sentinel health", ""]
    last_sample = db.meta_get(conn, "last_sample_ts") or "never"
    last_ingest = db.meta_get(conn, "last_journal_ingest") or "never"
    failed_runs = conn.execute(
        "SELECT task, ts, detail FROM runs WHERE ok=0 ORDER BY id DESC LIMIT 5"
    ).fetchall()
    body += [
        f"- Last sample: `{last_sample}`",
        f"- Last journal ingest: `{last_ingest}`",
        f"- Last inventory: `{inv['ts'] if inv else 'never'}`",
        f"- Next inventory: `{db.meta_get(conn, 'next_inventory_ts') or 'n/a'}` "
        f"(adaptive interval {db.meta_get(conn, 'inventory_interval_s') or config.INVENTORY_INTERVAL_S}s)",
        f"- Privilege posture: {posture.line()}",
    ]
    if failed_runs:
        body.append("- Recent failed sentinel runs:")
        for r in failed_runs:
            body.append(f"  - `{r['ts']}` {r['task']}: {r['detail'][:160]}")
    else:
        body.append("- Recent failed sentinel runs: none")

    return title, "\n".join(body) + "\n"


def append_journal(conn, title: str, body: str, kind: str) -> None:
    day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    path = config.JOURNAL_DIR / f"{day}.md"
    stamp = iso()
    if not path.exists():
        path.write_text(
            f"# QA sentinel journal — {day}\n\n"
            "Append-only record. Newest entry at the bottom. Times are UTC.\n",
            encoding="utf-8",
        )
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(f"\n---\n\n## {stamp} · {kind} · {title}\n\n{body}\n")
    db.meta_set(conn, "last_journal_entry", f"{stamp}|{kind}|{title}")


def write_report(conn, kind: str = "daily", hours: int = 24) -> dict:
    title, body = build_report(conn, kind, hours)
    config.REPORT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    path = config.REPORT_DIR / f"{kind}-{stamp}.md"
    path.write_text(body, encoding="utf-8")
    append_journal(conn, title, body, kind)
    summary = next(
        (ln for ln in body.splitlines() if ln.startswith("- Events:")), title
    )
    conn.execute(
        "INSERT INTO reports(ts, kind, path, summary) VALUES(?,?,?,?)",
        (iso(), kind, str(path), summary[:500]),
    )
    return {"title": title, "path": str(path), "body": body, "summary": summary}


def latest_inventory_age(conn) -> float | None:
    last = db.meta_get(conn, "last_inventory_ts")
    if not last:
        return None
    return (datetime.now(timezone.utc) - parse_iso(last)).total_seconds()
