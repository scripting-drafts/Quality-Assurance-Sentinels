"""Command line entry point: qa <command>."""
from __future__ import annotations

import argparse
import json
import os
import pathlib
import shlex
import shutil
import subprocess
import sys
import time
from datetime import datetime

from . import (
    boot, compat, config, correlate, crosscheck, db, deep, detect, evidence, hardware,
    holds, ingest, inventory, logs, lsm, notify, posture, raise_ticket, report, sampler,
    security, shutdown, siem, tickets, trace, triage,
)
from .util import fmt_duration, iso, parse_iso, read_text, run, sha256_file, utcnow

CRON_BEGIN = "# >>> qa-sentinels >>>"
CRON_END = "# <<< qa-sentinels <<<"


def _cron_block() -> str:
    root = shlex.quote(str(config.ROOT))
    command = (
        f"cd {root} && umask 077 && "
        "flock -n var/cycle.lock ./bin/qa cycle >>var/cron.log 2>&1"
    )
    return "\n".join(
        [
            CRON_BEGIN,
            f"* * * * * {command}",
            f"@reboot sleep 30 && {command}",
            CRON_END,
        ]
    )


def cmd_init(args) -> int:
    config.ensure_dirs()
    db.init()
    rc, out, err = run([str(config.SAMPLE_BIN)], timeout=30)
    ok = rc == 0 and out.strip().startswith("{")
    print(f"root      : {config.ROOT}")
    print(f"database  : {config.DB_PATH}")
    print(f"sampler   : {'ok' if ok else 'FAILED: ' + err.strip()[:200]}")
    print(f"cron      : {'present' if shutil.which('crontab') else 'missing'}")
    return 0 if ok else 1


def cmd_sample(args) -> int:
    with db.session() as conn:
        data = sampler.take_sample(conn)
        print(
            json.dumps(
                {
                    "ts": data.get("ts"),
                    "boot_id": data.get("boot_id"),
                    "processes": len(data.get("procs", [])),
                    "cpus": len(data.get("cpus", [])),
                    "core2_logical": data.get("core2", {}).get("logical"),
                    "mem_available_kb": data.get("mem", {}).get("MemAvailable"),
                    "psi_cpu": data.get("psi", {}).get("cpu"),
                },
                indent=2,
            )
        )
    return 0


def cmd_ingest(args) -> int:
    with db.session() as conn:
        print(json.dumps(ingest.ingest_all(conn), indent=2))
    return 0


def _journal_inventory(conn, inv: dict) -> None:
    from . import report as report_mod

    diffs = inv.get("diffs") or []
    body = [
        f"- Run: {inv['run_id']} at {inv['ts']}",
        f"- Trigger: {inv.get('reason', 'manual')}",
        f"- Digest: `{inv['digest']}`",
        f"- Items per layer: `{json.dumps(inv['counts'], sort_keys=True)}`",
        f"- Changes: {len(diffs)}",
        f"- Adaptive renewal: next run at `{inv.get('next_ts', 'n/a')}` "
        f"(interval {fmt_duration(inv.get('interval_s', config.INVENTORY_INTERVAL_S))})",
    ]
    if diffs:
        body += ["", "| layer | change | item |", "|---|---|---|"]
        for _ts, _run, layer, change, item, _old, _new in diffs[:120]:
            body.append(f"| {layer} | {change} | `{item}` |")
        if len(diffs) > 120:
            body.append(f"| … | … | {len(diffs) - 120} more changes in the database |")
    report_mod.append_journal(
        conn,
        f"Inventory snapshot · run {inv['run_id']}",
        "\n".join(body) + "\n",
        "inventory",
    )


def cmd_inventory(args) -> int:
    with db.session() as conn:
        result = inventory.run_inventory(conn, reason="manual")
        _journal_inventory(conn, result)
        print(json.dumps({k: v for k, v in result.items() if k != "diffs"}, indent=2))
        if result["diffs"]:
            print(f"changes: {len(result['diffs'])} (recorded in the journal)")
    return 0


def cmd_report(args) -> int:
    with db.session() as conn:
        hours = args.hours or 24
        result = report.write_report(conn, args.kind, hours)
        if args.kind == "daily":
            db.meta_set(conn, "last_daily_report_date", datetime.now().astimezone().strftime("%Y-%m-%d"))
        print(result["path"])
        made = tickets.generate(conn, days=7)
        print(f"tickets: {len(made)} drafts")
    return 0


def cmd_evidence(args) -> int:
    with db.session() as conn:
        result = evidence.make_bundle(conn, reason=args.reason, hours=args.hours)
        print(json.dumps(result, indent=2))
    return 0


def cmd_verify(args) -> int:
    result = evidence.verify_bundle(args.path)
    print(json.dumps(result, indent=2))
    return 0 if result.get("ok") else 1


def cmd_tickets(args) -> int:
    with db.session() as conn:
        if args.list:
            rows = conn.execute(
                "SELECT ts, vendor, path, title FROM ticket_drafts ORDER BY id DESC"
            ).fetchall()
            for r in rows:
                print(f"{r['ts']}  {r['vendor']:<18} {r['title']}")
                print(f"    {r['path']}")
            return 0
        made = tickets.generate(conn, days=args.days, include_local=args.include_local)
        generated = 0
        for item in made:
            print(f"[{item['vendor']}] {item['title']}")
            print(f"    {item['path']}  ({item['count']} occurrences)")
            generated += 1
        if not generated:
            print("no vendor clusters in the window; nothing drafted")
    return 0


def cmd_findings(args) -> int:
    with db.session() as conn:
        if args.set_status:
            if args.id is None:
                print("--set-status requires --id N", file=sys.stderr)
                return 2
            ok = detect.set_status(conn, args.id, args.set_status)
            print("updated" if ok else "finding not found")
            return 0 if ok else 1
        rows = detect.list_findings(conn, limit=args.limit, status=args.only)
        for row in rows:
            print(
                f"[{row['id']:>3}] {row['severity']:<8} {row['status']:<13} "
                f"{row['rule']:<24} x{row['count']:<3} {row['subject']}  {row['ts']}"
            )
            print(f"      {row['detail'][:140]}")
        if not rows:
            print("no findings")
    return 0


def cmd_lsm(args) -> int:
    with db.session() as conn:
        if args.action == "baseline":
            print(lsm.baseline(conn))
            return 0
        if args.action == "show":
            print(json.dumps(lsm.latest(conn), indent=2, default=str))
            return 0
        if args.action == "check":
            state = lsm.collect_state()
            print(json.dumps(state, indent=2, sort_keys=True))
            return 0
        result = lsm.scan(conn)
        print(json.dumps({
            "run_id": result["run_id"],
            "digest": result["digest"],
            "active": result["state"].get("active"),
            "status": "partial" if result["state"].get("errors") else "ok",
            "new": result["new"],
            "by_severity": result["by_severity"],
            "denials": result["denials"].get("counts", {}),
        }, indent=2))
        for finding in result["findings"][: args.limit]:
            print(f"[{finding['severity']}] {finding['rule']} {finding['subject']}")
            print(f"  {finding['detail'][:200]}")
        return 0


def cmd_hardware(args) -> int:
    with db.session() as conn:
        if args.action in ("discover", "discover-vendor"):
            print(json.dumps(hardware.discover_vendor(), indent=2, sort_keys=True))
            return 0
        if args.action == "check":
            data = hardware.check()
            print(json.dumps(data, indent=2, sort_keys=True))
            return 1 if (data.get("missing_required_tools") or data.get("missing_sources")) else 0
        if args.action == "show":
            data = hardware.latest(conn)
            if data.get("run"):
                data["run"].pop("detail", None)
            print(json.dumps(data, indent=2, default=str))
            return 0
        sources = {item.strip() for item in (args.sources or "").split(",") if item.strip()}
        result = hardware.collect(conn, sources=sources or None)
        print(json.dumps({key: value for key, value in result.items() if key != "findings"},
                         indent=2))
        for finding in result["findings"][: args.limit]:
            print(f"[{finding['severity']}] {finding['rule']} {finding['subject']}")
            print(f"  {finding['detail'][:200]}")
        return 1 if result.get("failed") else 0


def cmd_security(args) -> int:
    with db.session() as conn:
        if args.action == "policy":
            print(json.dumps(security.load_policy(), indent=2, sort_keys=True))
            return 0
        if args.action == "audit-rules":
            print(config.ROOT / "root/audit/qa-security.rules")
            return 0
        result = security.scan(
            conn,
            include_files=not args.no_files,
            include_audit=not args.no_audit,
        )
        print(
            json.dumps(
                {key: value for key, value in result.items() if key != "findings"},
                indent=2,
            )
        )
        for finding in result["findings"][: args.limit]:
            print(f"[{finding['severity']}] {finding['rule']} {finding['subject']}")
            print(f"  {finding['detail'][:200]}")
    return 0


def cmd_deep(args) -> int:
    with db.session() as conn:
        if args.consume:
            results = deep.consume(
                conn, duration=args.duration, dry_run=args.dry_run,
                perf_record=args.perf_record,
            )
            print(json.dumps(results, indent=2))
            return 0 if all(r.get("status") != "needs-root" for r in results) else 3

        if args.list:
            rows = conn.execute(
                "SELECT id,ts,case_id,status,path,sha256 FROM deep_runs ORDER BY id DESC LIMIT 50"
            ).fetchall()
            for row in rows:
                print(f"[{row['id']:>3}] {row['ts']} case={row['case_id']} "
                      f"{row['status']:<10} {row['path']}")
            print(f"pending requests: {len(deep.pending_requests())}")
            return 0

        request = {
            "id": utcnow().strftime("%Y%m%dT%H%M%S%f"),
            "created": iso(),
            "case_id": args.case,
            "finding_id": args.finding,
            "reason": args.reason,
            "pid": args.pid,
            "comm": args.comm,
            "event_ts": args.since,
            "duration_s": args.duration,
            "perf_record": args.perf_record,
        }
        if args.case and not args.comm:
            case = conn.execute(
                "SELECT * FROM core2_cases WHERE id=?", (args.case,)
            ).fetchone()
            if case:
                request["comm"] = case["process"]
                request["event_ts"] = request["event_ts"] or case["event_ts"]

        if args.enqueue:
            path = deep.enqueue(
                conn, case_id=args.case, finding_id=args.finding, reason=args.reason,
                pid=args.pid, comm=request["comm"], ts=request["event_ts"],
                duration=args.duration, perf_record=args.perf_record,
            )
            print(path)
            return 0

        priv = deep.privilege()
        if not priv["ok"] and not args.dry_run:
            path = deep.enqueue(
                conn, case_id=args.case, finding_id=args.finding, reason=args.reason,
                pid=args.pid, comm=request["comm"], ts=request["event_ts"],
                duration=args.duration, perf_record=args.perf_record,
            )
            print(f"queued: {path}")
            print(f"privilege: euid={priv['euid']} CapEff={priv['cap_eff']} "
                  f"(need CAP_SYS_ADMIN + CAP_PERFMON)")
            print("run one of:")
            print(f"  sudo {config.BIN / 'qa'} deep --consume")
            print(f"  bin/qa deploy-layer2   # installs the layer-2 path unit")
            return 0

        result = deep.run_request(
            conn, request, duration=args.duration, dry_run=args.dry_run,
            perf_record=args.perf_record,
        )
        print(json.dumps(result, indent=2, default=str))
        return 0 if result.get("status") in ("complete", "dry-run") else 3


def cmd_triage(args) -> int:
    with db.session() as conn:
        if args.set_status:
            if args.case is None:
                print("--set-status requires --case N", file=sys.stderr)
                return 2
            row = triage.set_status(conn, args.case, args.set_status, args.note)
            if not row:
                print(f"case {args.case} not found", file=sys.stderr)
                return 1
            print(f"case {row['id']}: {row['status']}")
            return 0
        if args.case is not None:
            row = conn.execute("SELECT * FROM core2_cases WHERE id=?", (args.case,)).fetchone()
            if not row:
                print(f"case {args.case} not found", file=sys.stderr)
                return 1
            print((row["path"] and read_text(row["path"])) or "(case file missing)")
            return 0
        if not args.list:
            print(json.dumps(triage.refresh(conn), indent=2))
        summary = triage.summary(conn)
        print(json.dumps(summary, indent=2))
        for row in triage.cases(conn, status=args.only, limit=args.limit):
            print(
                f"[{row['id']:>3}] {row['verdict']:<10} {row['status']:<13} "
                f"{row['process']:<22} {row['event_ts']}  {row['signature'][:80]}"
            )
        print(f"dossier: {config.TRIAGE_DIR / 'index.md'}")
    return 0


def cmd_boots(args) -> int:
    with db.session() as conn:
        if args.detail:
            row = conn.execute(
                "SELECT * FROM boots WHERE boot_id LIKE ? ORDER BY last_ts DESC LIMIT 1",
                (args.detail + "%",),
            ).fetchone()
            if not row:
                print(f"no recorded boot matching {args.detail!r}")
                return 1
            row = dict(row)
            print(f"boot {row['boot_id']}  ->  {boot.verdict(row)}")
            print(f"  span       : {row['span']}")
            print(f"  last entry : {row['last_ts']}")
            print(f"  last msg   : {row['last_message']}")
            print(f"  crashkernel: {row['crashkernel'] or 'none'}  "
                  f"kexec_crash_loaded={row['kexec_loaded']}  vmcores={row['vmcores']}")
            print(f"  pstore     : {row['pstore']}")
            counts = boot.scan_counts(row)
            for key, value in sorted(counts.items()):
                print(f"  {key:<10} : {value['count']}")
                for sample in value.get("sample", []):
                    print(f"      {sample[:200]}")
            return 0

        fresh = boot.collect(conn, limit=args.limit, refresh=args.refresh)
        if fresh["new"] or fresh["updated"] or fresh["pstore_updated"]:
            print(f"recorded {fresh['new']} new, refreshed {fresh['updated']} boot(s), "
                  f"{fresh['pstore_updated']} pstore record(s); "
                  f"{len(fresh['unclean'])} unclean")
        rows = boot.rows(conn, limit=args.limit)
        if not rows:
            print("no boots recorded yet")
            return 0
        print(f"{'boot':<10} {'verdict':<8} {'last entry':<20} last message")
        for row in rows:
            print(
                f"{row['boot_id'][:8]:<10} {boot.verdict(row):<8} "
                f"{(row['last_ts'] or '')[:19]:<20} {(row['last_message'] or '')[:70]}"
            )
    return 0


def _print_shutdown(record: dict) -> None:
    boot_id = (record.get("boot_id") or "")[:8] or "unknown"
    phases = record.get("phases") or {}
    if phases:
        boot_count = int((phases.get("boot") or {}).get("count") or 0)
        stop = phases.get("shutdown") or {}
        stop_count = int(stop.get("count") or 0)
        detail = f"{boot_count} boot-phase, {stop_count} shutdown-phase occurrence(s)"
        if stop.get("start"):
            detail += f"; shutdown window {stop['start']} → {stop.get('end') or '?'}"
    else:
        detail = f"{int(record.get('count') or 0)} shutdown error(s)"
    mode = record.get("redaction") or config.CAPTURE_REDACTION
    print(f"boot {boot_id}: {detail}; redaction={mode}")
    for item in (record.get("errors") or [])[:50]:
        phase = item.get("phase") or "shutdown"
        count = int(item.get("count") or 1)
        message = str(item.get("message") or "").strip()
        if not message:
            message = "(message withheld)"
        suffix = f" (x{count})" if count > 1 else ""
        print(
            f"  [{phase:<8}] {item.get('ts', '')} "
            f"{str(item.get('severity') or ''):<7} "
            f"{item.get('unit') or 'systemd'}: {message[:180]}{suffix}"
        )


def cmd_shutdown(args) -> int:
    config.ensure_dirs()
    if args.redaction and (args.capture or args.scan):
        config.CAPTURE_REDACTION = args.redaction
    if args.capture:
        record = shutdown.capture("0")
        if args.quiet:
            phases = record.get("phases") or {}
            print(
                f"captured {int((phases.get('boot') or {}).get('count') or 0)} boot + "
                f"{int((phases.get('shutdown') or {}).get('count') or 0)} shutdown "
                f"error(s) for boot {(record.get('boot_id') or '')[:8]}"
            )
        else:
            _print_shutdown(record)
        return 0
    if args.scan:
        _print_shutdown(shutdown.scan_boot(args.boot, refresh=True))
        return 0
    if args.replay:
        with db.session() as conn:
            added = shutdown.replay(conn)
        print(f"replayed {added} shutdown event(s)")
        return 0

    rows = shutdown.records(limit=args.limit)
    if not rows:
        print("no shutdown captures recorded yet")
        print("capture the current boot with: bin/qa shutdown --capture")
        return 0
    for record in rows:
        _print_shutdown(record)
    return 0


def cmd_correlate(args) -> int:
    with db.session() as conn:
        summary = correlate.correlate(conn, days=args.days, notify=not args.quiet)
        clusters = correlate.aggregate(conn, days=args.days)
        if args.drafts:
            drafts = tickets.generate(conn, days=args.days)
            summary["drafts"] = len(drafts)
        print(json.dumps(summary, indent=2))
        if not clusters:
            print("\nno component signature appeared in the death window of a silent stop")
            return 0
        print(f"\n{'vendor':<17} {'boots':>5} {'occ':>5} {'crash':>5} "
              f"{'score':>9}  ready  signature")
        for cluster in clusters[:20]:
            print(
                f"{cluster['vendor']:<17} {cluster['boots']:>5} {cluster['occurrences']:>5} "
                f"{cluster['crashes']:>5} {cluster['score']:>4}/{cluster['threshold']:<4} "
                f"{'yes' if cluster['ready'] else ' no':<6} {cluster['signature'][:70]}"
            )
    return 0


def cmd_holds(args) -> int:
    if args.package:
        print(json.dumps({"package": args.package, **holds.policy(args.package)}, indent=2))
        return 0
    print(json.dumps(holds.counts(), indent=2))
    return 0


def cmd_raise(args) -> int:
    with db.session() as conn:
        result = raise_ticket.run(
            conn, days=args.days, min_count=args.min_count,
            notify_ready=not args.no_notify,
        )
        print(json.dumps(result, indent=2))
    return 0


def cmd_notify(args) -> int:
    with db.session() as conn:
        result = {}
        ok, why = notify.available()
        result["available"] = {"ok": ok, "detail": why}
        if args.test:
            ok, why = notify.send(
                "QA sentinels", "Test notification from the sentinel", "normal"
            )
            result["test"] = {"ok": ok, "detail": why}
        result.update(notify.collect(conn))
        if args.drain:
            result.update(notify.drain(conn))
        else:
            result["pending"] = notify.pending_count(conn)
        conn.commit()
        print(json.dumps(result, indent=2))
        if result.get("test") and not result["test"]["ok"]:
            return 1
        if result.get("failed"):
            return 1
    return 0


def cmd_trace(args) -> int:
    with db.session() as conn:
        print("\n".join(trace.render(conn, args.query, limit=args.limit)))
    return 0


def cmd_crosscheck(args) -> int:
    with db.session() as conn:
        if args.history:
            for row in crosscheck.history(conn, limit=args.limit):
                print(f"{row['ts']}  checked={row['checked']}  drift={row['drift']}")
            return 0
        result = crosscheck.run(
            conn, days=args.days, deep=args.deep, notify_drift=args.notify
        )
        print(json.dumps(result, indent=2))
    return 1 if result["drift"] else 0


def cmd_logs(args) -> int:
    if args.install_autostart:
        print(json.dumps(logs.install_autostart(), indent=2))
        return 0
    if args.rotate:
        print(json.dumps(logs.rotate(), indent=2))
        return 0
    color = (not args.no_color) and (args.force_color or logs.supports_color())
    path = config.VAR / "cron.log"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)
    with db.session() as conn:
        for line in logs.header(conn):
            print(line, flush=True)
    if args.all_layers:
        logs.all_layers(path, lines=args.lines, color=color,
                        follow_mode=args.follow)
    elif args.follow:
        logs.follow(path, lines=args.lines, color=color)
    else:
        for line in logs.tail_lines(path, args.lines):
            print(logs.format_line(line, color), flush=True)
    return 0


def cmd_export(args) -> int:
    try:
        with db.session() as conn:
            events = siem.build_events(
                conn, args.since, args.types, args.limit
            )
    except siem.SiemError as exc:
        print(f"qa export: {exc}", file=sys.stderr)
        return 2
    lines = "".join(
        json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n"
        for event in events
    )
    if args.output:
        target = pathlib.Path(args.output)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(lines, encoding="utf-8")
        try:
            target.chmod(0o600)
        except OSError:
            pass
    else:
        sys.stdout.write(lines)
    return 0


def cmd_forward(args) -> int:
    try:
        cfg = siem.load_config(args.config)
        with db.session() as conn:
            result = siem.forward(
                conn, cfg, since=args.since, types=args.types,
                limit=args.limit, dry_run=args.dry_run,
            )
    except siem.SiemError as exc:
        print(f"qa forward: {exc}", file=sys.stderr)
        return 2
    if not args.dry_run:
        print(json.dumps(result, indent=2, sort_keys=True))
    return 0


def cmd_posture(args) -> int:
    with db.session() as conn:
        data = posture.record(conn, force=True, rebaseline=args.rebaseline)
    print(json.dumps(data, indent=2))
    return 0 if data["verdict"] == "unprivileged" and not data["baseline_changed"] else 1


def cmd_status(args) -> int:
    with db.session() as conn:
        def scalar(sql, args=()):
            return conn.execute(sql, args).fetchone()[0]

        samples = scalar("SELECT COUNT(*) FROM samples")
        events = scalar("SELECT COUNT(*) FROM events")
        critical = scalar("SELECT COUNT(*) FROM events WHERE severity='critical'")
        crashes = scalar("SELECT COUNT(*) FROM crashes")
        core2 = scalar("SELECT COUNT(*) FROM crashes WHERE core2_involved=1")
        inv = conn.execute("SELECT * FROM inventory_runs ORDER BY id DESC LIMIT 1").fetchone()
        hw = conn.execute("SELECT * FROM hardware_runs ORDER BY id DESC LIMIT 1").fetchone()
        lsm_row = conn.execute("SELECT * FROM lsm_runs ORDER BY id DESC LIMIT 1").fetchone()
        bundles = scalar("SELECT COUNT(*) FROM bundles")
        drafts = scalar("SELECT COUNT(*) FROM ticket_drafts")
        chain_head = ""
        chain = config.EVIDENCE_DIR / "chain.log"
        if chain.exists():
            lines = chain.read_text().strip().splitlines()
            chain_head = lines[-1] if lines else ""

        print(f"{config.PROJECT_NAME} status")
        print(f"  last sample   : {db.meta_get(conn, 'last_sample_ts') or 'never'}")
        print(f"  last ingest   : {db.meta_get(conn, 'last_journal_ingest') or 'never'}")
        print(f"  last inventory: {db.meta_get(conn, 'last_inventory_ts') or 'never'}")
        print(f"  last hardware : {db.meta_get(conn, 'last_hardware_ts') or 'never'}")
        print(f"  last lsm      : {db.meta_get(conn, 'last_lsm_ts') or 'never'}")
        if lsm_row:
            print(f"  lsm           : digest={str(lsm_row['digest'] or '')[:12]} "
                  f"status={lsm_row['status']}")
        if hw:
            print(f"  hardware tier : run {hw['id']} {hw['status']} "
                  f"({hw['duration_ms']} ms) sources={hw['sources']}")
        else:
            print("  hardware tier : no runs yet (qa hardware collect)")
        print(f"  database      : {samples} samples, {events} events, {crashes} crashes")
        print(f"  critical      : {critical} events; core-2-correlated crashes: {core2}")
        if inv:
            print(f"  inventory     : run {inv['id']} at {inv['ts']} ({inv['counts']})")
            print(
                f"  next inventory: {db.meta_get(conn, 'next_inventory_ts') or 'n/a'} "
                f"(interval {db.meta_get(conn, 'inventory_interval_s') or config.INVENTORY_INTERVAL_S}s)"
            )
        print(f"  evidence      : {bundles} bundles; chain head {chain_head[:90] or 'none'}")
        print(f"  ticket drafts : {drafts} (never auto-submitted)")
        tri = triage.summary(conn)
        print(f"  core2 triage  : {tri['total']} cases {tri['by_status']} -> {config.TRIAGE_DIR}")
        fcounts = conn.execute(
            "SELECT severity, COUNT(*) n FROM findings WHERE status='open' GROUP BY severity"
        ).fetchall()
        fsum = ", ".join(f"{r['severity']}={r['n']}" for r in fcounts) or "none"
        print(f"  layer1        : open findings: {fsum}")
        bcounts = conn.execute(
            "SELECT COUNT(*) n,"
            " COALESCE(SUM(CASE WHEN ended_clean=0 THEN 1 ELSE 0 END),0) u FROM boots"
        ).fetchone()
        print(f"  boots         : {bcounts['n']} recorded, {bcounts['u']} unclean")
        captures = shutdown.records(limit=1)
        if captures:
            latest = captures[0]
            phases = latest.get("phases") or {}
            if phases:
                counts = (
                    f"{int((phases.get('boot') or {}).get('count') or 0)} boot + "
                    f"{int((phases.get('shutdown') or {}).get('count') or 0)} shutdown"
                )
            else:
                counts = str(int(latest.get("count") or 0))
            print(
                f"  shutdown      : {counts} error(s) in latest capture "
                f"({str(latest.get('boot_id') or '')[:8]})"
            )
        else:
            print("  shutdown      : no captures yet (systemd: qa-shutdown-capture.service)")
        ccounts = conn.execute("SELECT COUNT(*) AS n FROM correlations").fetchone()
        ready_clusters = sum(1 for c in correlate.aggregate(conn) if c["ready"])
        print(f"  correlate     : {ccounts['n']} cluster rows, {ready_clusters} ticket-ready")
        nd = conn.execute(
            "SELECT COUNT(*) FROM notifications WHERE delivered=0"
        ).fetchone()[0]
        cc = conn.execute(
            "SELECT ts, drift FROM crosschecks ORDER BY id DESC LIMIT 1"
        ).fetchone()
        staged = len([p for p in config.RAISE_DIR.iterdir() if p.is_dir()]) if config.RAISE_DIR.exists() else 0
        standby = len([p for p in config.STANDBY_DIR.iterdir() if p.is_dir()]) if config.STANDBY_DIR.exists() else 0
        print(f"  raise         : {staged} staged, {standby} in standby")
        hc = holds.counts()
        print(f"  holds         : {hc['held_total']} held, {hc['held_installed']} installed"
              f"{' (GLOBAL HOLD)' if hc['mass_hold'] else ''}")
        delivery_ok, delivery_why = notify.available()
        delivery = "ready" if delivery_ok else f"unavailable: {delivery_why}"
        print(f"  notify        : {nd} undelivered; delivery {delivery}; crosscheck: "
              f"{cc['ts'] + ' drift=' + str(cc['drift']) if cc else 'never'}")
        drows = conn.execute(
            "SELECT status, COUNT(*) n FROM deep_runs GROUP BY status"
        ).fetchall()
        dsum = ", ".join(f"{r['status']}={r['n']}" for r in drows) or "none"
        p2 = _layer2_state()
        print(
            f"  layer2        : deep runs: {dsum}; "
            f"pending requests: {len(deep.pending_requests())}; "
            f"path unit: {'armed' if p2['deployed'] else 'not deployed'}"
        )
        ebpf_ok, ebpf_detail = _ebpf_state()
        print(f"  eBPF          : {'built' if ebpf_ok else 'stale/missing'} ({ebpf_detail})")
        print(f"  posture       : {posture.line()}")
        print(f"  journal       : {config.JOURNAL_DIR}")
    return 0


def cmd_compat(args) -> int:
    data = compat.report()
    print(json.dumps(data, indent=2, sort_keys=True))
    return 0 if data["supported"] or not args.strict else 1


def cmd_preflight(args) -> int:
    checks = []
    rc, out, err = run([str(config.SAMPLE_BIN)], timeout=30)
    checks.append(("C sampler", rc == 0 and out.startswith("{"), (err or "")[:120]))
    rc, out, err = run(["journalctl", "-n", "1", "--no-pager"], timeout=20)
    checks.append(("journal read access", rc == 0, (err or "")[:120]))
    rc, out, err = run(["coredumpctl", "list", "--no-pager", "--since=-1day"], timeout=30)
    checks.append(("coredump access", rc == 0, (err or "")[:120]))
    checks.append(("crontab", shutil.which("crontab") is not None, ""))
    free = shutil.disk_usage(str(config.ROOT)).free
    checks.append(("disk > 2 GiB free", free > 2 * 1024**3, f"{free / 1024**3:.1f} GiB"))
    checks.append(
        (
            f"physical core {config.CORE2_PHYSICAL_ID} present",
            bool(config.CORE2_CPUS),
            f"logical CPUs {config.CORE2_CPUS}",
        )
    )
    compatibility = compat.report()
    checks.append(
        (
            "Ubuntu compatibility",
            compatibility["supported"],
            compatibility["summary"],
        )
    )
    post = posture.collect()
    checks.append(
        (
            "unprivileged posture",
            post["verdict"] == "unprivileged" and not post["baseline_changed"],
            ", ".join(post["reasons"] + [f"drift: {k}" for k in post["baseline_changed"]])
            or "capabilities/sudo/root clean and baseline unchanged",
        )
    )
    checks.append(("core2 triage dossier", config.TRIAGE_DIR.exists(), str(config.TRIAGE_DIR)))
    failed = 0
    for name, ok, detail in checks:
        print(f"[{'ok' if ok else 'FAIL'}] {name}" + (f" — {detail}" if detail and not ok else ""))
        failed += 0 if ok else 1
    priv = deep.privilege()
    state = _layer2_state()
    if priv["ok"]:
        layer2 = "ready"
    elif state["deployed"]:
        layer2 = "armed via qa-sentinel-deep.path (shell itself unprivileged)"
    elif state["active"]:
        layer2 = f"path unit is active but not for {config.ROOT}; run: bin/qa deploy-layer2 --force"
    else:
        layer2 = (
            f"not privileged (euid={priv['euid']}, CapEff={priv['cap_eff']}); "
            "arm with: bin/qa deploy-layer2"
        )
    print(f"[info] layer-2 tracing: {layer2}")
    print(
        "[info] eBPF tracer: "
        + ("built" if (config.BIN / "qa_ebpf").exists() else
           "not built; run root/ebpf/bootstrap-ebpf.sh then root/ebpf/build.sh")
    )
    return 1 if failed else 0


DEEP_SERVICE_UNIT = pathlib.Path("/etc/systemd/system/qa-sentinel-deep.service")
DEEP_PATH_UNIT = pathlib.Path("/etc/systemd/system/qa-sentinel-deep.path")


def _layer2_state() -> dict:
    root = config.ROOT
    service = read_text(DEEP_SERVICE_UNIT)
    path_unit = read_text(DEEP_PATH_UNIT)
    installed = (
        f"ExecStart={root}/bin/qa deep --consume" in service
        and f"PathExistsGlob={root}/triage/core2/deep-requests/*.json" in path_unit
    )
    rc, out, _ = run(["systemctl", "is-active", "qa-sentinel-deep.path"], timeout=10)
    active = rc == 0 and out.strip() == "active"
    return {"installed": installed, "active": active, "deployed": installed and active}


def _privilege_failure(stderr: str) -> bool:
    text = stderr.lower()
    return any(
        marker in text
        for marker in (
            "password is required",
            "a terminal is required",
            "no tty present",
            "not allowed",
        )
    )


def _run_layer2_installer(user: str | None = None) -> tuple[int, str, str]:
    cmd = [str(config.ROOT / "root" / "install-system.sh"), "--layer2-only"]
    if user:
        cmd += ["--user", user]
    if os.geteuid() == 0:
        return run(cmd, timeout=300)
    if shutil.which("sudo"):
        rc, out, err = run(["sudo", "-n", *cmd], timeout=300)
        if rc == 0 or not _privilege_failure(err):
            return rc, out, err
    if sys.stdin.isatty():
        return run(["sudo", *cmd], timeout=300)
    if shutil.which("pkexec") and (
        os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")
    ):
        return run(["pkexec", *cmd], timeout=600)
    return 126, "", "no non-interactive privilege path; run as root or: sudo " + " ".join(cmd)


def _ebpf_state() -> tuple[bool, str]:
    binary = config.BIN / "qa_ebpf"
    obj = config.BIN / "qa_trace.bpf.o"
    if not binary.exists() or not obj.exists():
        return False, "missing"
    try:
        stamp = json.loads(read_text(config.BIN / "qa_ebpf.build.json"))
    except ValueError:
        return False, "missing build stamp"
    if stamp.get("kernel_release") != os.uname().release:
        return False, f"built for {stamp.get('kernel_release', '?')}, host is {os.uname().release}"
    if stamp.get("binary_sha256") != sha256_file(binary):
        return False, "loader changed since build"
    if stamp.get("object_sha256") != sha256_file(obj):
        return False, "BPF object changed since build"
    return True, "built for this kernel"


def _ensure_ebpf(skip: bool) -> tuple[bool, str]:
    current, detail = _ebpf_state()
    if current:
        return True, detail
    if skip:
        return False, f"{detail} (skipped)"
    build = config.ROOT / "root" / "ebpf" / "build.sh"
    rc, out, err = run([str(build)], timeout=600)
    if rc == 0:
        current, detail = _ebpf_state()
        if current:
            return True, detail
    bootstrap = config.ROOT / "root" / "ebpf" / "bootstrap-ebpf.sh"
    rc2, out2, err2 = run([str(bootstrap)], timeout=900)
    if rc2 == 0:
        rc3, out3, err3 = run([str(build)], timeout=600)
        if rc3 == 0:
            current, detail = _ebpf_state()
            if current:
                return True, detail
        return False, (err3 or out3 or err or out).strip()[-300:]
    return False, (err2 or out2 or err or out).strip()[-300:]


def cmd_deploy_layer2(args) -> int:
    if args.check:
        state = _layer2_state()
        ebpf, ebpf_detail = _ebpf_state()
        print("layer 2 deployment")
        print(
            "  units     : "
            + ("match this checkout" if state["installed"] else f"not installed for {config.ROOT}")
        )
        print(f"  path unit : {'active' if state['active'] else 'inactive'}")
        print(f"  eBPF      : {'built' if ebpf else 'stale/missing'} ({ebpf_detail})")
        print(f"  pending   : {len(deep.pending_requests())}")
        return 0 if state["deployed"] else 1
    ok, detail = _ensure_ebpf(args.skip_ebpf)
    print(f"eBPF tracer: {'ok' if ok else 'unavailable'} ({detail})")
    state = _layer2_state()
    if state["deployed"] and not args.force:
        print(f"layer 2 already deployed for {config.ROOT}")
        print(f"path unit: active; pending requests: {len(deep.pending_requests())}")
        return 0
    print("installing layer-2 systemd path unit (privilege prompt may follow)...")
    rc, out, err = _run_layer2_installer(args.user)
    if out.strip():
        print(out.strip())
    if rc != 0:
        if err.strip():
            print(err.strip(), file=sys.stderr)
        return rc
    state = _layer2_state()
    if not state["deployed"]:
        print(
            "installer finished but the path unit is not active; "
            "check: systemctl status qa-sentinel-deep.path",
            file=sys.stderr,
        )
        return 1
    pending = len(deep.pending_requests())
    print(f"layer 2 deployed and active for {config.ROOT}")
    print(f"pending requests: {pending}")
    return 0


def cmd_install_cron(args) -> int:
    config.ensure_dirs()
    try:
        cur = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        existing = cur.stdout if cur.returncode == 0 else ""
    except FileNotFoundError:
        print("crontab is not installed; use the systemd units or run `qa cycle` from your scheduler")
        return 1
    lines = existing.splitlines()
    if CRON_BEGIN in lines:
        start = lines.index(CRON_BEGIN)
        end = lines.index(CRON_END) if CRON_END in lines else len(lines) - 1
        lines = lines[:start] + lines[end + 1 :]
    text = "\n".join([ln for ln in lines if ln.strip()])
    if args.remove:
        text = (text + "\n" if text else "")
        proc = subprocess.run(["crontab", "-"], input=text, text=True, capture_output=True)
        if proc.returncode != 0:
            print(f"failed to update crontab: {proc.stderr.strip()}")
            return 1
        print(f"removed {config.PROJECT_NAME} cron block")
        return 0
    text = (text + "\n\n" if text else "") + _cron_block() + "\n"
    proc = subprocess.run(["crontab", "-"], input=text, text=True, capture_output=True)
    if proc.returncode != 0:
        print(f"failed to install crontab: {proc.stderr.strip()}")
        return 1
    print("installed cron block:")
    print(_cron_block())
    return 0


def _ensure_delta_baseline(conn) -> None:
    """Reports need two samples to turn raw counters into percentages."""
    n = conn.execute("SELECT COUNT(*) FROM samples").fetchone()[0]
    if n == 1:
        time.sleep(2)
        try:
            sampler.take_sample(conn)
        except Exception:  # noqa: BLE001 - report can still render with n/a
            pass


def _cycle_due(conn, key: str, seconds: int) -> bool:
    last = db.meta_get(conn, f"cycle|{key}")
    return not last or (utcnow() - parse_iso(last)).total_seconds() >= seconds


def _cycle_mark(conn, key: str) -> None:
    db.meta_set(conn, f"cycle|{key}", iso())


def cmd_cycle(args) -> int:
    config.ensure_dirs()
    result: dict = {"ts": iso()}
    findings_dirty = False
    failed = 0
    try:
        rotated = logs.rotate()
        if rotated:
            result["log_rotated"] = rotated
    except OSError as exc:  # noqa: BLE001 - a log rotation must not stop a cycle
        result["log_rotate_error"] = str(exc)[:200]
    with db.session() as conn:
        prev_boot = db.meta_get(conn, "last_boot_id")
        try:
            data = sampler.take_sample(conn)
            result["sample"] = {
                "boot_id": data.get("boot_id"),
                "procs": len(data.get("procs", [])),
            }
        except Exception as exc:  # noqa: BLE001
            failed += 1
            result["sample_error"] = str(exc)[:300]
            db.record_run(conn, "cycle/sample", False, str(exc))
            data = None

        try:
            result["ingest"] = ingest.ingest_all(conn)
        except Exception as exc:  # noqa: BLE001
            failed += 1
            result["ingest_error"] = str(exc)[:300]
            db.record_run(conn, "cycle/ingest", False, str(exc))

        # Boot boundary: classify the boots that ended since the last cycle. This
        # is the only layer that can see a hard reset, because it runs after it.
        try:
            boundary = boot.collect(conn)
            result["boots"] = {k: boundary[k] for k in ("scanned", "new")}
            if boundary["new"]:
                unclean = [r for r in boundary["records"] if r["ended_clean"] == 0]
                body = "\n".join(
                    f"- **{boot.verdict(r)}** `{r['boot_id'][:8]}` "
                    f"last entry {r['last_ts']} — {(r['last_message'] or '')[:160]}"
                    for r in boundary["records"]
                ) + "\n"
                report.append_journal(
                    conn, f"Boot boundary: {len(unclean)} unclean of {boundary['new']}",
                    body, "boot",
                )
                result["boots"]["unclean"] = [r["boot_id"][:8] for r in unclean]
        except Exception as exc:  # noqa: BLE001
            failed += 1
            result["boot_error"] = str(exc)[:300]
            db.record_run(conn, "cycle/boot", False, str(exc))

        due, why = inventory.is_due(conn)
        if due:
            try:
                inv = inventory.run_inventory(conn, reason=why)
                _journal_inventory(conn, inv)
                result["inventory"] = {
                    "run_id": inv["run_id"],
                    "counts": inv["counts"],
                    "diffs": len(inv["diffs"]),
                    "reason": inv["reason"],
                    "next": inv["next_ts"],
                }
            except Exception as exc:  # noqa: BLE001
                failed += 1
                result["inventory_error"] = str(exc)[:300]
                db.record_run(conn, "cycle/inventory", False, str(exc))

        current_boot = (data or {}).get("boot_id") or ""
        startup_done_for = db.meta_get(conn, "startup_report_boot")
        if current_boot and (prev_boot != current_boot or startup_done_for != current_boot):
            try:
                _ensure_delta_baseline(conn)
                posture.record(conn, force=True)
                triage.refresh(conn)
                rep = report.write_report(conn, "startup", 24)
                bun = evidence.make_bundle(conn, reason="startup", hours=24)
                tickets.generate(conn, days=7)
                result["startup_report"] = {"path": rep["path"], "bundle": bun["sha256"]}
                db.meta_set(conn, "startup_report_boot", current_boot)
            except Exception as exc:  # noqa: BLE001
                failed += 1
                result["startup_error"] = str(exc)[:300]
                db.record_run(conn, "cycle/startup", False, str(exc))

        # New crash or new critical event: seal evidence and refresh drafts now,
        # not at the next daily report.
        last_ticket = db.meta_get(conn, "last_ticket_run") or "1970-01-01T00:00:00Z"
        new_crashes = conn.execute(
            "SELECT COUNT(*) FROM crashes WHERE ts > ?", (last_ticket,)
        ).fetchone()[0]
        new_critical = conn.execute(
            "SELECT COUNT(*) FROM events WHERE ts > ? AND severity='critical'", (last_ticket,)
        ).fetchone()[0]
        if new_crashes or new_critical:
            try:
                if new_crashes:
                    evidence.make_bundle(conn, reason="crash", hours=24)
                made = tickets.generate(conn, days=7)
                result["auto_tickets"] = {
                    "crashes": new_crashes,
                    "critical_events": new_critical,
                    "drafts": len(made),
                }
            except Exception as exc:  # noqa: BLE001
                failed += 1
                result["auto_ticket_error"] = str(exc)[:300]
                db.record_run(conn, "cycle/tickets", False, str(exc))

        # Core-2 side queue: refresh after new evidence or at least every 10 min.
        last_tri = db.meta_get(conn, "last_triage_run")
        tri_age = (utcnow() - parse_iso(last_tri)).total_seconds() if last_tri else 1e9
        if new_crashes or new_critical or tri_age >= 600:
            try:
                tri = triage.refresh(conn)
                result["triage"] = tri
            except Exception as exc:  # noqa: BLE001
                failed += 1
                result["triage_error"] = str(exc)[:300]
                db.record_run(conn, "cycle/triage", False, str(exc))

        # Linux Security Modules: state drift and denial monitoring.
        if config.LSM_ENABLE and lsm.is_due(conn):
            try:
                lr = lsm.scan(conn)
                result["lsm"] = {
                    "run_id": lr["run_id"],
                    "digest": lr["digest"],
                    "active": lr["state"].get("active"),
                    "new": lr["new"],
                    "by_severity": lr["by_severity"],
                    "denials": lr["denials"].get("counts", {}),
                }
                if lr["state"].get("errors"):
                    failed += 1
                    result["lsm_state_errors"] = lr["state"]["errors"]
                if lr["new"]:
                    findings_dirty = True
                    from . import report as report_mod

                    report_mod.append_journal(
                        conn,
                        f"LSM findings: {lr['new']} new",
                        "\n".join(
                            f"- **{finding['severity']}** `{finding['rule']}` "
                            f"{finding['subject']}: {finding['detail'][:180]}"
                            for finding in lr["findings"][:20]
                        ) + "\n",
                        "lsm",
                    )
            except Exception as exc:  # noqa: BLE001
                failed += 1
                result["lsm_error"] = str(exc)[:300]
                db.record_run(conn, "cycle/lsm", False, str(exc))

        # Hardware-health tier: slow, best-effort, privilege-aware.
        if config.HARDWARE_ENABLE and hardware.is_due(conn):
            try:
                hw = hardware.collect(conn)
                result["hardware"] = {
                    "run_id": hw["run_id"],
                    "status": hw["status"],
                    "failed": hw["failed"],
                    "failed_sources": hw["failed_sources"],
                    "sources": hw["sources"],
                    "items": hw["items"],
                    "new": hw["new"],
                    "by_severity": hw["by_severity"],
                }
                if hw["failed"]:
                    failed += 1
                    result["hardware_failed_sources"] = hw["failed_sources"]
                if hw["new"]:
                    findings_dirty = True
                    from . import report as report_mod

                    report_mod.append_journal(
                        conn,
                        f"Hardware findings: {hw['new']} new",
                        "\n".join(
                            f"- **{finding['severity']}** `{finding['rule']}` "
                            f"{finding['subject']}: {finding['detail'][:180]}"
                            for finding in hw["findings"][:20]
                        ) + "\n",
                        "hardware",
                    )
            except Exception as exc:  # noqa: BLE001
                failed += 1
                result["hardware_error"] = str(exc)[:300]
                db.record_run(conn, "cycle/hardware", False, str(exc))

        # Security provenance: live process/root-owned-file/audit checks.
        try:
            sec = security.scan(
                conn,
                include_files=security.files_due(conn),
                include_audit=config.SECURITY_AUDIT,
            )
            result["security"] = {
                "new": sec["new"],
                "by_severity": sec["by_severity"],
                "rules": sec["rules"][:20],
                "processes": sec["processes"],
                "files": sec["files"],
                "audit": sec["audit"],
            }
            if sec["new"]:
                findings_dirty = True
                from . import report as report_mod

                report_mod.append_journal(
                    conn,
                    f"Security findings: {sec['new']} new",
                    "\n".join(
                        f"- **{finding['severity']}** `{finding['rule']}` "
                        f"{finding['subject']}: {finding['detail'][:180]}"
                        for finding in sec["findings"][:20]
                    ) + "\n",
                    "security",
                )
        except Exception as exc:  # noqa: BLE001
            failed += 1
            result["security_error"] = str(exc)[:300]
            db.record_run(conn, "cycle/security", False, str(exc))

        # Layer 1 detection: turn new raw evidence into explicit findings and,
        # when severe, queue layer-2 deep tracing and seal a layer-1 bundle.
        try:
            new_findings = detect.scan(conn)
            if new_findings:
                findings_dirty = True
                counts: dict[str, int] = {}
                for finding in new_findings:
                    counts[finding["severity"]] = counts.get(finding["severity"], 0) + 1
                result["layer1_findings"] = {
                    "new": len(new_findings), "by_severity": counts,
                    "rules": [f["rule"] for f in new_findings][:20],
                }
                from . import report as report_mod

                report_mod.append_journal(
                    conn,
                    f"Layer 1 findings: {len(new_findings)} new",
                    "\n".join(
                        f"- **{f['severity']}** `{f['rule']}` {f['subject']}: {f['detail'][:180]}"
                        for f in new_findings[:20]
                    ) + "\n",
                    "layer1",
                )

                critical = [f for f in new_findings if f["severity"] == "critical"]
                queued = detect.queue_escalations(conn, new_findings)
                if queued:
                    result["deep_queued"] = queued

                last_bundle = db.meta_get(conn, "last_layer1_bundle")
                b_age = (utcnow() - parse_iso(last_bundle)).total_seconds() if last_bundle else 1e9
                if critical and b_age >= 180:
                    bun = evidence.make_bundle(conn, reason="layer1-finding", hours=6)
                    db.meta_set(conn, "last_layer1_bundle", iso())
                    result["layer1_bundle"] = bun["sha256"]
        except Exception as exc:  # noqa: BLE001
            failed += 1
            result["layer1_error"] = str(exc)[:300]
            db.record_run(conn, "cycle/layer1", False, str(exc))

        if findings_dirty:
            try:
                made = tickets.generate(conn, days=7)
                result["finding_tickets"] = {"drafts": len(made)}
            except Exception as exc:  # noqa: BLE001
                failed += 1
                result["finding_ticket_error"] = str(exc)[:300]
                db.record_run(conn, "cycle/finding-tickets", False, str(exc))

        # Layer 1 owns the whole routine loop: correlation refresh, the raise
        # gate, cross-check and notification delivery are due-based and
        # persisted, so cron and systemd only need to run this one command.
        if _cycle_due(conn, "correlate", config.CYCLE_CORRELATE_S):
            try:
                corr = correlate.correlate(conn, days=30, notify=True)
                made = tickets.generate(conn, days=7)
                result["correlate"] = {
                    "unclean_boots": corr["unclean_boots"],
                    "clusters": corr["clusters"],
                    "ticket_ready": corr["ticket_ready"],
                    "drafts": len(made),
                }
            except Exception as exc:  # noqa: BLE001
                failed += 1
                result["correlate_error"] = str(exc)[:300]
                db.record_run(conn, "cycle/correlate", False, str(exc))
            _cycle_mark(conn, "correlate")

        if _cycle_due(conn, "raise", config.CYCLE_RAISE_S):
            try:
                gate = raise_ticket.run(conn, days=config.RAISE_LOOKBACK_DAYS)
                result["raise"] = {
                    "viable": gate["viable"],
                    "rejected": gate["rejected"],
                    "rejected_staged": len(gate["rejected_staged"]),
                }
            except Exception as exc:  # noqa: BLE001
                failed += 1
                result["raise_error"] = str(exc)[:300]
                db.record_run(conn, "cycle/raise", False, str(exc))
            _cycle_mark(conn, "raise")

        if _cycle_due(conn, "crosscheck", config.CYCLE_CROSSCHECK_S):
            try:
                check = crosscheck.run(conn, days=30, deep=True, notify_drift=True)
                result["crosscheck"] = {
                    "drafts": check["drafts"],
                    "drift": check["drift"],
                }
            except Exception as exc:  # noqa: BLE001
                failed += 1
                result["crosscheck_error"] = str(exc)[:300]
                db.record_run(conn, "cycle/crosscheck", False, str(exc))
            _cycle_mark(conn, "crosscheck")

        if _cycle_due(conn, "notify", config.CYCLE_CORRELATE_S):
            try:
                collected = notify.collect(conn)
                drained = notify.drain(conn)
                result["notify"] = {"collected": collected["queued"], **drained}
            except Exception as exc:  # noqa: BLE001
                failed += 1
                result["notify_error"] = str(exc)[:300]
                db.record_run(conn, "cycle/notify", False, str(exc))
            _cycle_mark(conn, "notify")

        now_local = datetime.now().astimezone()
        today = now_local.strftime("%Y-%m-%d")
        if (now_local.hour >= config.CYCLE_DAILY_HOUR
                and db.meta_get(conn, "last_daily_report_date") != today):
            try:
                _ensure_delta_baseline(conn)
                rep = report.write_report(conn, "daily", 24)
                tickets.generate(conn, days=7)
                db.meta_set(conn, "last_daily_report_date", today)
                result["daily_report"] = rep["path"]
            except Exception as exc:  # noqa: BLE001
                failed += 1
                result["daily_error"] = str(exc)[:300]
                db.record_run(conn, "cycle/daily", False, str(exc))

        db.record_run(conn, "cycle", failed == 0, json.dumps(result)[:1500])

    print(json.dumps(result, indent=2))
    return 1 if failed else 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="qa",
        description=(
            f"{config.PROJECT_NAME} — {config.PROJECT_DESCRIPTION}: "
            "kernel, memory, CPU and process evidence."
        ),
    )
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("init", help="create directories/database and validate the sampler")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("cycle", help="one routine pass: sample, ingest and every due layer-1 task")
    s.set_defaults(func=cmd_cycle)

    s = sub.add_parser("tick", help="legacy alias for cycle")
    s.set_defaults(func=cmd_cycle)

    s = sub.add_parser("sample", help="take one kernel/memory/CPU sample")
    s.set_defaults(func=cmd_sample)

    s = sub.add_parser("ingest", help="ingest journal warnings/errors and crashes")
    s.set_defaults(func=cmd_ingest)

    s = sub.add_parser("inventory", help="snapshot every software layer")
    s.set_defaults(func=cmd_inventory)

    s = sub.add_parser("report", help="write a startup or daily report")
    s.add_argument("--kind", choices=("startup", "daily"), default="daily")
    s.add_argument("--hours", type=int, default=24)
    s.set_defaults(func=cmd_report)

    s = sub.add_parser("evidence", help="build a hash-chained evidence bundle")
    s.add_argument("--reason", default="manual")
    s.add_argument("--hours", type=int, default=24)
    s.set_defaults(func=cmd_evidence)

    s = sub.add_parser("verify", help="verify a bundle manifest and file hashes")
    s.add_argument("path")
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("tickets", help="draft per-vendor tickets (never submits)")
    s.add_argument("--days", type=int, default=7)
    s.add_argument("--include-local", action="store_true")
    s.add_argument("--list", action="store_true")
    s.set_defaults(func=cmd_tickets)

    s = sub.add_parser("status", help="show sentinel state")
    s.set_defaults(func=cmd_status)

    s = sub.add_parser("boots", help="classify previous boots: clean shutdown vs silent stop")
    s.add_argument("--limit", type=int, default=10)
    s.add_argument("--detail", help="show one recorded boot by id prefix")
    s.add_argument("--refresh", action="store_true", help="re-scan boots already recorded")
    s.set_defaults(func=cmd_boots)

    s = sub.add_parser(
        "shutdown", help="track service start and unmount failures from boot and shutdown"
    )
    group = s.add_mutually_exclusive_group()
    group.add_argument(
        "--capture", action="store_true",
        help="scan and persist the current boot's failures (systemd final.target)",
    )
    group.add_argument(
        "--scan", action="store_true",
        help="scan one boot journal without writing a capture",
    )
    group.add_argument(
        "--replay", action="store_true",
        help="insert stored shutdown errors into the events table now",
    )
    group.add_argument(
        "--list", action="store_true", help="list stored shutdown captures (default)",
    )
    s.add_argument("--boot", default="-1", help="boot reference for --scan (default: -1)")
    s.add_argument("--limit", type=int, default=20)
    s.add_argument("--quiet", action="store_true",
                   help="with --capture, print only the phase summary")
    s.add_argument(
        "--redaction", choices=("strict", "collapsed", "metadata"),
        help="override QA_CAPTURE_REDACTION for --capture/--scan",
    )
    s.set_defaults(func=cmd_shutdown)

    s = sub.add_parser(
        "correlate", help="pair silent stops with the component errors that preceded them"
    )
    s.add_argument("--days", type=int, default=30)
    s.add_argument("--drafts", action="store_true",
                   help="regenerate vendor drafts, including ready correlations")
    s.add_argument("--quiet", action="store_true", help="no journal entry")
    s.set_defaults(func=cmd_correlate)

    s = sub.add_parser("holds", help="held packages and whether they are outdated")
    s.add_argument("--package", help="show apt policy for one package")
    s.set_defaults(func=cmd_holds)

    s = sub.add_parser("raise", help="stage viable tickets under raise/, held-outdated ones under rejected/")
    s.add_argument("--days", type=int, default=config.RAISE_LOOKBACK_DAYS)
    s.add_argument("--min-count", type=int)
    s.add_argument("--no-notify", action="store_true")
    s.set_defaults(func=cmd_raise)

    s = sub.add_parser("notify", help="queue and deliver desktop pop-ups for ready tickets")
    s.add_argument("--drain", action="store_true", help="deliver queued notifications now")
    s.add_argument("--test", action="store_true", help="send one test notification")
    s.set_defaults(func=cmd_notify)

    s = sub.add_parser("trace", help="follow a signature, boot or cluster across every layer")
    s.add_argument("query", help="cluster key, boot id prefix, fingerprint, or message text")
    s.add_argument("--limit", type=int, default=50)
    s.set_defaults(func=cmd_trace)

    s = sub.add_parser("crosscheck", help="re-verify drafts, verdicts and correlations")
    s.add_argument("--days", type=int, default=30)
    s.add_argument("--deep", action="store_true", help="re-scan boots and rebuild correlations first")
    s.add_argument("--notify", action="store_true", help="pop a notification when drift is found")
    s.add_argument("--history", action="store_true", help="list past cross-check runs")
    s.add_argument("--limit", type=int, default=10)
    s.set_defaults(func=cmd_crosscheck)

    s = sub.add_parser("export", help="export redacted events as JSONL for a SIEM")
    s.add_argument("--since", default="24h", help="24h, 7d, or ISO-8601 timestamp")
    s.add_argument("--types", help="comma-separated: findings,events,crashes,boots,hardware,lsm,tickets")
    s.add_argument("--limit", type=int, default=5000)
    s.add_argument("--format", choices=("jsonl",), default="jsonl")
    s.add_argument("--output", help="write JSONL to a file instead of stdout")
    s.set_defaults(func=cmd_export)

    s = sub.add_parser("forward", help="forward redacted events to a QA SIEM endpoint")
    s.add_argument("--config", default="config/siem.json")
    s.add_argument("--since", help="override the configured lookback")
    s.add_argument("--types", help="comma-separated event types")
    s.add_argument("--limit", type=int, default=5000)
    s.add_argument("--dry-run", action="store_true", help="print JSONL without sending")
    s.set_defaults(func=cmd_forward)

    s = sub.add_parser("logs", help="live coloured sentinel log with timestamps")
    s.add_argument("-f", "--follow", action="store_true")
    s.add_argument("--lines", type=int, default=20)
    s.add_argument("--all-layers", action="store_true",
                   help="include layer 2 from the qa-sentinel-deep journal")
    s.add_argument("--no-color", action="store_true")
    s.add_argument("--force-color", action="store_true")
    s.add_argument("--install-autostart", action="store_true",
                   help="open this monitor in a terminal at login")
    s.add_argument("--rotate", action="store_true",
                   help="rotate var/cron.log now if it reached the size cap")
    s.set_defaults(func=cmd_logs)

    s = sub.add_parser("triage", help="core-2 side queue: refresh/list/update cases")
    s.add_argument("--list", action="store_true", help="list without refreshing from sources")
    s.add_argument("--case", type=int, help="show one case file")
    s.add_argument("--set-status", choices=triage.STATUSES, help="update a case status")
    s.add_argument("--note", help="note to store with the status change")
    s.add_argument("--only", choices=triage.STATUSES, help="filter the listing")
    s.add_argument("--limit", type=int, default=50)
    s.set_defaults(func=cmd_triage)

    s = sub.add_parser("posture", help="prove the sentinel has no root/capabilities/sudo")
    s.add_argument("--rebaseline", action="store_true", help="reset the drift baseline after an intentional change")
    s.set_defaults(func=cmd_posture)

    s = sub.add_parser("layer1", help="alias for cycle (layer 1)")
    s.set_defaults(func=cmd_cycle)

    s = sub.add_parser("phase1", help="legacy alias for cycle")
    s.set_defaults(func=cmd_cycle)

    s = sub.add_parser("findings", help="list layer-1 findings and update their status")
    s.add_argument("--limit", type=int, default=50)
    s.add_argument("--only", choices=("open", "investigating", "resolved", "dismissed"))
    s.add_argument("--id", type=int)
    s.add_argument("--set-status", choices=("open", "investigating", "resolved", "dismissed"))
    s.set_defaults(func=cmd_findings)

    s = sub.add_parser(
        "lsm",
        help="monitor Linux Security Modules, drift and AppArmor/SELinux denials",
    )
    s.add_argument("action", nargs="?", choices=("scan", "show", "check", "baseline"), default="scan")
    s.add_argument("--limit", type=int, default=50)
    s.set_defaults(func=cmd_lsm)

    s = sub.add_parser(
        "hardware",
        help="collect the hardware-health tier (RAS, storage, GPU, BMC, sensors, PMU, APEI)",
    )
    s.add_argument("action", nargs="?", choices=("collect", "show", "check", "discover", "discover-vendor"), default="collect")
    s.add_argument("--sources", help="comma-separated source list: ras,storage,gpu,bmc,sensors,turbostat,pcm,uncore,vendor")
    s.add_argument("--limit", type=int, default=50)
    s.set_defaults(func=cmd_hardware)

    s = sub.add_parser(
        "security",
        help="detect unauthorized user/root code execution and unexpected root permissions",
    )
    s.add_argument(
        "action", nargs="?", choices=("scan", "policy", "audit-rules"), default="scan"
    )
    s.add_argument("--no-files", action="store_true", help="skip root-owned file scan")
    s.add_argument("--no-audit", action="store_true", help="skip auditd records")
    s.add_argument("--limit", type=int, default=50)
    s.set_defaults(func=cmd_security)

    s = sub.add_parser("deep", help="layer 2: root-level tracefs/perf investigation")
    s.add_argument("--consume", action="store_true", help="process queued requests (systemd path unit)")
    s.add_argument("--list", action="store_true", help="list deep runs and pending requests")
    s.add_argument("--case", type=int, help="triage case id")
    s.add_argument("--finding", type=int, help="layer-1 finding id")
    s.add_argument("--pid", type=int, help="process id to inspect")
    s.add_argument("--comm", help="process name for context")
    s.add_argument("--since", help="event timestamp (ISO) for the journal window")
    s.add_argument("--reason", default="manual")
    s.add_argument("--duration", type=int, default=config.DEEP_DURATION_S)
    s.add_argument("--perf-record", action="store_true", help="also capture perf.data + report")
    s.add_argument("--dry-run", action="store_true", help="collect what is allowed and list skips")
    s.add_argument("--enqueue", action="store_true", help="queue only; do not execute")
    s.set_defaults(func=cmd_deep)

    s = sub.add_parser("compat", help="report Ubuntu/Python/SQLite/systemd upgrade compatibility")
    s.add_argument("--strict", action="store_true", help="exit non-zero outside the documented baseline")
    s.set_defaults(func=cmd_compat)

    s = sub.add_parser(
        "preflight",
        help="check sampler, journal, coredump, disk, core-2 and layer-2 prerequisites",
    )
    s.set_defaults(func=cmd_preflight)

    for deploy_name, deploy_help in (
        ("deploy-layer2", "install/verify the per-host layer-2 path unit (idempotent)"),
        ("deploy-phase2", "legacy alias for deploy-layer2"),
    ):
        s = sub.add_parser(deploy_name, help=deploy_help)
        s.add_argument("--check", action="store_true", help="report deployment state only")
        s.add_argument("--force", action="store_true", help="reinstall even if already active")
        s.add_argument("--skip-ebpf", action="store_true", help="do not build the eBPF tracer")
        s.add_argument("--user", help="operator account for the systemd unit (default: this user)")
        s.set_defaults(func=cmd_deploy_layer2)

    s = sub.add_parser("install-cron", help="install the user schedule (1 min cycle, all layer-1 duties inside)")
    s.add_argument("--remove", action="store_true", help="remove the qa-sentinels cron block")
    s.set_defaults(func=cmd_install_cron)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return 130
    except Exception as exc:  # noqa: BLE001
        print(f"qa {args.command}: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
