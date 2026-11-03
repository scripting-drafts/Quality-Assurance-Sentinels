"""Phase 2: deep, root-level investigation.

Phase 1 writes a small JSON request when a finding is severe enough. A systemd
path unit (installed by root/install-system.sh) runs `qa deep --consume` with
CAP_SYS_ADMIN/CAP_PERFMON, so tracing is real but still not a root shell.

The collector uses tracefs/ftrace events and perf counters. eBPF is used when a
prebuilt object is supplied; this host has no clang/libbpf, so ftrace and perf
are the built-in paths.
"""
from __future__ import annotations

import glob
import json
import os
import re
import time
from datetime import timedelta

from . import config, db
from .util import iso, parse_iso, read_text, run, sha256_file, sha256_text, utcnow, write_json

CAP_BITS = {
    "CAP_DAC_OVERRIDE": 1,
    "CAP_DAC_READ_SEARCH": 2,
    "CAP_SYS_RAWIO": 17,
    "CAP_SYS_PTRACE": 19,
    "CAP_SYS_ADMIN": 21,
    "CAP_PERFMON": 38,
    "CAP_BPF": 39,
}

TRACE_EVENTS = (
    "sched/sched_switch",
    "sched/sched_wakeup",
    "exceptions/page_fault_user",
    "exceptions/page_fault_kernel",
    "irq/irq_handler_entry",
    "irq/irq_handler_exit",
    "thermal/thermal_temperature",
    "power/cpu_frequency",
    "mce/mc_event",
)

TRACE_LINE_RE = re.compile(
    r"^(?P<comm>.+)-(?P<pid>\d+)\s+\[(?P<cpu>\d+)\]\s+\S+\s+[\d.]+\s*:\s*"
    r"(?P<event>[a-z_:]+):\s*(?P<rest>.*)$"
)


def _cap_eff() -> int:
    for line in read_text("/proc/self/status").splitlines():
        if line.startswith("CapEff:"):
            try:
                return int(line.split(":", 1)[1].strip(), 16)
            except ValueError:
                return 0
    return 0


def privilege() -> dict:
    caps = _cap_eff()
    euid = os.geteuid()
    have = {name: bool(euid == 0 or (caps >> bit) & 1) for name, bit in CAP_BITS.items()}
    return {
        "euid": euid,
        "cap_eff": f"0x{caps:016x}",
        "caps": have,
        "can_trace": have["CAP_SYS_ADMIN"],
        "can_perf": have["CAP_PERFMON"],
        "can_bpf": have["CAP_BPF"],
        "can_raw_hw": have["CAP_SYS_RAWIO"],
        "can_read_all": have["CAP_DAC_READ_SEARCH"],
        "ok": euid == 0 or (
            have["CAP_SYS_ADMIN"] and have["CAP_PERFMON"] and have["CAP_DAC_OVERRIDE"]
        ),
    }


# --------------------------------------------------------------- requests
def enqueue(conn, case_id=None, finding_id=None, reason="manual", pid=None,
            comm=None, ts=None, duration=None, perf_record=False,
            packages=None, package_owner=None,
            held_packages=None, hold_summary=None) -> str:
    config.DEEP_REQUEST_DIR.mkdir(parents=True, exist_ok=True)
    stamp = utcnow().strftime("%Y%m%dT%H%M%S%f")
    request = {
        "id": stamp,
        "created": iso(),
        "case_id": case_id,
        "finding_id": finding_id,
        "reason": reason,
        "pid": pid,
        "comm": comm,
        "event_ts": ts,
        "duration_s": int(duration or config.DEEP_DURATION_S),
        "perf_record": bool(perf_record),
        # crash escalation context: which build was running when it died
        "package_owner": package_owner or {},
        "package_count": len(packages or []),
        "packages": list(packages or []),
        # a crash in a held, outdated module may already be fixed upstream
        "held_packages": list(held_packages or []),
        "hold_summary": hold_summary or {},
    }
    path = config.DEEP_REQUEST_DIR / f"{stamp}-case{case_id or 'na'}.json"
    write_json(path, request)
    db.meta_set(conn, "last_deep_request", iso())
    return str(path)


def pending_requests() -> list[str]:
    if not config.DEEP_REQUEST_DIR.exists():
        return []
    return sorted(str(p) for p in config.DEEP_REQUEST_DIR.glob("*.json"))


# --------------------------------------------------------------- helpers
def _trace_root() -> str | None:
    for root in ("/sys/kernel/tracing", "/sys/kernel/debug/tracing"):
        if os.path.exists(os.path.join(root, "tracing_on")):
            return root
    target = "/sys/kernel/tracing"
    rc, _out, _err = run(["mount", "-t", "tracefs", "nodev", target], timeout=10)
    if rc == 0 and os.path.exists(os.path.join(target, "tracing_on")):
        return target
    return None


def summarize_trace(text: str) -> dict:
    by_cpu: dict[int, int] = {}
    by_event: dict[str, int] = {}
    comms_core2: dict[str, int] = {}
    lines = 0
    page_faults = 0
    for line in text.splitlines():
        match = TRACE_LINE_RE.match(line.strip())
        if not match:
            continue
        lines += 1
        cpu = int(match.group("cpu"))
        event = match.group("event")
        comm = match.group("comm").strip()
        by_cpu[cpu] = by_cpu.get(cpu, 0) + 1
        by_event[event] = by_event.get(event, 0) + 1
        if "page_fault" in event:
            page_faults += 1
        if cpu in config.CORE2_CPUS:
            comms_core2[comm] = comms_core2.get(comm, 0) + 1
    total = sum(by_cpu.values()) or 1
    return {
        "lines": lines,
        "by_cpu": {str(k): v for k, v in sorted(by_cpu.items())},
        "by_event": by_event,
        "page_faults": page_faults,
        "core2_event_pct": round(100.0 * sum(
            v for c, v in by_cpu.items() if c in config.CORE2_CPUS
        ) / total, 1),
        "top_core2_comms": sorted(comms_core2.items(), key=lambda kv: (-kv[1], kv[0]))[:15],
    }


def _write(outdir, name: str, content) -> str:
    path = outdir / name
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, (dict, list)):
        write_json(path, content)
    else:
        path.write_text(str(content), encoding="utf-8")
    return str(path)


# --------------------------------------------------------------- collectors
def _collect_context(conn, outdir, request: dict) -> None:
    event_ts = request.get("event_ts")
    if event_ts:
        try:
            dt = parse_iso(event_ts)
            since = (dt - timedelta(seconds=60)).strftime("%Y-%m-%d %H:%M:%S")
            until = (dt + timedelta(seconds=60)).strftime("%Y-%m-%d %H:%M:%S")
            rc, out, _ = run(
                ["journalctl", "--no-pager", "-o", "short-iso", "--since", since,
                 "--until", until, "-n", "500"], timeout=30
            )
            _write(outdir, "journal-window.txt", out if rc == 0 else "(journal unavailable)")
        except ValueError:
            pass
    rc, out, _ = run(["journalctl", "-b", "-p", "warning", "-n", "300", "--no-pager"], timeout=30)
    _write(outdir, "journal-boot.txt", out if rc == 0 else "(journal unavailable)")

    samples = [
        json.loads(r["payload"]) for r in conn.execute(
            "SELECT payload FROM samples ORDER BY ts DESC LIMIT 60"
        )
    ]
    _write(outdir, "samples-window.json", samples)

    inv = conn.execute("SELECT * FROM inventory_runs ORDER BY id DESC LIMIT 1").fetchone()
    if inv:
        items = [
            dict(r) for r in conn.execute(
                "SELECT layer,item,value FROM inventory WHERE run_id=?", (inv["id"],)
            )
        ]
        _write(outdir, "inventory.json", {"run": dict(inv), "items": items})

    if request.get("case_id"):
        case = conn.execute(
            "SELECT * FROM core2_cases WHERE id=?", (request["case_id"],)
        ).fetchone()
        if case:
            _write(outdir, "case.json", dict(case))
            if case["path"]:
                _write(outdir, "case.md", read_text(case["path"]))

    pid = request.get("pid")
    if pid:
        rc, out, _ = run(["coredumpctl", "info", str(pid), "--no-pager"], timeout=45)
        if rc == 0:
            _write(outdir, "coredump-info.txt", out)


def _collect_proc(outdir, pid: int | None) -> list[str]:
    if not pid or not os.path.isdir(f"/proc/{pid}"):
        return []
    base = f"/proc/{pid}"
    captured = []
    for name in ("status", "cmdline", "schedstat", "sched", "stack", "wchan",
                 "maps", "smaps_rollup", "limits", "cgroup", "io", "stat"):
        try:
            data = open(f"{base}/{name}", "rb").read()
        except OSError:
            continue
        target = outdir / f"proc-{name}.txt"
        target.write_bytes(data)
        captured.append(str(target))
    try:
        tasks = sorted(os.listdir(f"{base}/task"))
    except OSError:
        tasks = []
    for tid in tasks:
        for name in ("stat", "status", "stack", "schedstat"):
            try:
                data = open(f"{base}/task/{tid}/{name}", "rb").read()
            except OSError:
                continue
            target = outdir / f"proc-task-{tid}-{name}.txt"
            target.write_bytes(data)
            captured.append(str(target))
    return captured


def _collect_ftrace(outdir, duration: int) -> dict:
    root = _trace_root()
    if not root:
        return {"available": False, "reason": "tracefs not mounted and mount failed"}
    instance = os.path.join(root, "instances", f"qa-deep-{os.getpid()}-{int(time.time())}")
    try:
        os.makedirs(instance, exist_ok=True)
    except OSError as exc:
        return {"available": False, "reason": f"cannot create instance: {exc}"}

    enabled = []
    for event in TRACE_EVENTS:
        path = os.path.join(instance, "events", event, "enable")
        if os.path.exists(path):
            try:
                with open(path, "w") as fh:
                    fh.write("1")
                enabled.append(event)
            except OSError:
                continue
    for control, value in (("buffer_size_kb", "2048"), ("tracing_on", "1")):
        try:
            with open(os.path.join(instance, control), "w") as fh:
                fh.write(value)
        except OSError:
            pass
    time.sleep(max(1, duration))
    try:
        with open(os.path.join(instance, "tracing_on"), "w") as fh:
            fh.write("0")
    except OSError:
        pass
    trace_path = os.path.join(instance, "trace")
    trace = read_text(trace_path)
    _write(outdir, "trace.txt", trace)
    metrics = summarize_trace(trace)
    metrics["available"] = True
    metrics["events_enabled"] = enabled
    # tracefs instances are virtual: rmdir removes the instance and its events.
    try:
        os.rmdir(instance)
    except OSError:
        pass
    return metrics


def _collect_ebpf(outdir, duration: int) -> dict:
    binary = config.BIN / "qa_ebpf"
    obj = config.BIN / "qa_trace.bpf.o"
    if not binary.exists() or not obj.exists():
        return {"available": False, "reason": "not built; run root/ebpf/build.sh"}
    rc, out, err = run(
        [str(binary), "--object", str(obj), "--duration", str(max(1, duration))],
        timeout=max(30, duration + 30),
    )
    _write(outdir, "ebpf-raw.txt", out + ("\n--- stderr ---\n" + err if err else ""))
    data = None
    for line in reversed(out.strip().splitlines()):
        try:
            data = json.loads(line)
            break
        except json.JSONDecodeError:
            continue
    return {
        "available": rc == 0 and data is not None,
        "rc": rc,
        "data": data,
        "stderr": err.strip()[:500],
    }


def _collect_perf(outdir, duration: int, record: bool = False) -> dict:
    events = ("cycles,instructions,cache-misses,cache-references,branch-misses,"
              "bus-cycles,stalled-cycles-frontend")
    rc, out, err = run(
        ["perf", "stat", "-a", "-A", "-e", events, "--", "sleep", str(max(1, duration))],
        timeout=max(30, duration + 30),
    )
    _write(outdir, "perf-stat.txt", out + ("\n--- stderr ---\n" + err if err else ""))
    result = {"available": rc == 0, "stat_rc": rc, "stderr": err.strip()[:500]}
    if record and rc == 0:
        data = outdir / "perf.data"
        rc2, out2, err2 = run(
            ["perf", "record", "-a", "-g", "-F", "99", "-o", str(data),
             "--", "sleep", str(max(1, duration))],
            timeout=max(60, duration * 4 + 30),
        )
        if rc2 == 0:
            rc3, report, err3 = run(
                ["perf", "report", "--stdio", "--percent-limit", "1", "-i", str(data)],
                timeout=90,
            )
            _write(outdir, "perf-report.txt", report if rc3 == 0 else err3)
            result["recorded"] = True
        else:
            result["record_error"] = err2.strip()[:500]
    return result


def _collect_hardware(outdir, duration: int) -> dict:
    probes = {
        "dmidecode.txt": ["dmidecode", "-t", "bios", "-t", "baseboard", "-t", "memory"],
        "lspci.txt": ["lspci", "-vv"],
        "cpupower.txt": ["cpupower", "frequency-info"],
        "ras-mc-ctl.txt": ["ras-mc-ctl", "--errors"],
        "nvidia-smi.txt": ["nvidia-smi", "-q"],
        "smart.txt": ["smartctl", "-a", (glob.glob("/dev/nvme*n1") or ["/dev/nvme0"])[0]],
        "dmesg.txt": ["dmesg", "-T"],
    }
    result = {}
    for name, cmd in probes.items():
        rc, out, err = run(cmd, timeout=30)
        if rc == 0 or out:
            _write(outdir, name, out or err)
            result[name] = rc == 0
    edac = {}
    for path in (
        "/sys/devices/system/edac/mc/mc0/ce_count",
        "/sys/devices/system/edac/mc/mc0/ue_count",
    ):
        edac[os.path.basename(path)] = read_text(path)
    throttle = {}
    for path in sorted(glob.glob(
        "/sys/devices/system/cpu/cpu[0-9]*/thermal_throttle/*"
    )):
        throttle[path] = read_text(path)
    _write(outdir, "edac.json", edac)
    _write(outdir, "thermal-throttle.json", throttle)
    result["edac"] = edac
    result["throttle"] = throttle
    return result


# --------------------------------------------------------------- run
def run_request(conn, request: dict, duration: int | None = None,
                dry_run: bool = False, perf_record: bool = False) -> dict:
    duration = min(int(duration or request.get("duration_s") or config.DEEP_DURATION_S),
                   config.DEEP_MAX_DURATION_S)
    stamp = utcnow().strftime("%Y%m%d-%H%M%S")
    case_id = request.get("case_id")
    outdir = config.DEEP_DIR / f"{stamp}-case{case_id or 'na'}-{str(request.get('id', ''))[:6]}"
    outdir.mkdir(parents=True, exist_ok=True)

    priv = privilege()
    skipped: list[str] = []
    if not priv["ok"] and not dry_run:
        status = "needs-root"
        report_text = (
            "# Deep investigation blocked\n\n"
            "This run needs root or the capability set installed by "
            "`sudo root/install-system.sh`.\n\n"
            f"- euid: {priv['euid']}\n"
            f"- CapEff: `{priv['cap_eff']}`\n"
            "- Required: CAP_SYS_ADMIN (tracefs) + CAP_PERFMON (counters)\n\n"
            "Re-run manually with:\n\n"
            f"    sudo {config.BIN / 'qa'} deep --case {case_id or ''} --duration {duration}\n"
        )
        _write(outdir, "REPORT.md", report_text)
        _write(outdir, "deep.json", {"status": status, "privilege": priv, "request": request})
        conn.execute(
            "INSERT INTO deep_runs(ts,case_id,finding_id,status,reason,duration_s,pid,comm,path)"
            " VALUES(?,?,?,?,?,?,?,?,?)",
            (iso(), case_id, request.get("finding_id"), status, request.get("reason"),
             duration, request.get("pid"), request.get("comm"), str(outdir)),
        )
        return {"status": status, "path": str(outdir), "privilege": priv}

    status = "dry-run" if dry_run else "complete"
    _collect_context(conn, outdir, request)

    proc_files = _collect_proc(outdir, request.get("pid"))
    if dry_run:
        trace = {"available": False, "reason": "dry-run"}
        perf = {"available": False, "reason": "dry-run"}
        ebpf = {"available": False, "reason": "dry-run"}
    else:
        from concurrent.futures import ThreadPoolExecutor

        with ThreadPoolExecutor(max_workers=3) as pool:
            f_trace = pool.submit(_collect_ftrace, outdir, duration) if priv["can_trace"] else None
            f_perf = pool.submit(_collect_perf, outdir, duration, perf_record) if priv["can_perf"] else None
            f_bpf = pool.submit(_collect_ebpf, outdir, duration) if priv["can_bpf"] else None
            trace = f_trace.result() if f_trace else {
                "available": False, "reason": "CAP_SYS_ADMIN missing"}
            perf = f_perf.result() if f_perf else {
                "available": False, "reason": "CAP_PERFMON missing"}
            ebpf = f_bpf.result() if f_bpf else {
                "available": False, "reason": "CAP_BPF missing"}
    hardware = _collect_hardware(outdir, duration) if not dry_run else {}
    if dry_run:
        skipped += ["ftrace (dry-run)", "perf counters (dry-run)",
                    "eBPF (dry-run)", "firmware/SMART/MCE (dry-run)"]
    if not priv["can_trace"]:
        skipped.append("ftrace: CAP_SYS_ADMIN missing")
    if not priv["can_perf"]:
        skipped.append("perf: CAP_PERFMON missing")
    if not priv["can_bpf"]:
        skipped.append("eBPF: CAP_BPF missing")
    if not priv["can_raw_hw"]:
        skipped.append("SMART/raw hardware: CAP_SYS_RAWIO missing")

    summary = {
        "status": status,
        "request": request,
        "duration_s": duration,
        "privilege": priv,
        "trace": trace,
        "perf": perf,
        "ebpf": ebpf,
        "hardware": hardware,
        "proc_files": len(proc_files),
        "skipped": skipped,
        "generated": iso(),
    }
    _write(outdir, "deep.json", summary)

    report_lines = [
        f"# Deep investigation — case {case_id or 'n/a'}",
        "",
        f"- Status: **{status}**",
        f"- Reason: {request.get('reason')}",
        f"- Duration: {duration}s",
        f"- euid: {priv['euid']}; CapEff `{priv['cap_eff']}`",
        f"- Process: `{request.get('comm') or 'n/a'}` (pid {request.get('pid') or 'n/a'})",
        f"- Event time: `{request.get('event_ts') or 'n/a'}`",
        "",
        "## Trace (ftrace)",
        "",
    ]
    if trace.get("available"):
        report_lines += [
            f"- Lines captured: **{trace['lines']}**; page faults: **{trace['page_faults']}**",
            f"- Share of events on core-2 CPUs {config.CORE2_CPUS}: **{trace['core2_event_pct']}%**",
            f"- Events enabled: {', '.join(trace.get('events_enabled') or []) or 'none'}",
            "",
            "| CPU | events |",
            "|---|---:|",
        ]
        for cpu, count in trace.get("by_cpu", {}).items():
            report_lines.append(f"| {cpu} | {count} |")
        report_lines += ["", "Top comms on core-2 CPUs:", ""]
        for comm, count in trace.get("top_core2_comms", [])[:10]:
            report_lines.append(f"- `{comm}`: {count}")
    else:
        report_lines.append(f"_Unavailable: {trace.get('reason')}_")
    report_lines += ["", "## Performance counters", ""]
    if perf.get("available"):
        report_lines.append("```")
        report_lines.append(read_text(outdir / "perf-stat.txt")[:6000])
        report_lines.append("```")
    else:
        report_lines.append(f"_Unavailable: {perf.get('reason') or perf.get('stderr')}_")
    report_lines += ["", "## eBPF", ""]
    ebpf_data = (ebpf or {}).get("data") or {}
    if ebpf.get("available") and ebpf_data:
        totals = ebpf_data.get("totals", {})
        per_cpu = ebpf_data.get("per_cpu") or []
        core2_rows = [r for r in per_cpu if r.get("cpu") in config.CORE2_CPUS]
        core2_switches = sum(r.get("switches", 0) for r in core2_rows)
        total_switches = totals.get("switches", 0) or 0
        share = round(100.0 * core2_switches / total_switches, 1) if total_switches else 0
        report_lines += [
            f"- Scheduler switches: **{totals.get('switches', 0)}**; "
            f"wakeups: **{totals.get('wakeups', 0)}**; "
            f"page faults: **{totals.get('page_faults', 0)}**",
            f"- Core-2 CPUs {config.CORE2_CPUS}: **{core2_switches}** switches "
            f"(**{share}%** of all)",
            f"- Programs attached: {ebpf_data.get('attached', 0)}; CPUs: {ebpf_data.get('cpus', 0)}",
            "",
            "| comm | kind | count |",
            "|---|---|---:|",
        ]
        kinds = {0: "switch", 1: "wakeup", 2: "page-fault"}
        for row in (ebpf_data.get("top_comms") or [])[:10]:
            report_lines.append(
                f"| `{row.get('comm')}` | {kinds.get(row.get('kind'), row.get('kind'))} | "
                f"{row.get('count')} |"
            )
    else:
        report_lines.append(f"_Unavailable: {ebpf.get('reason') or ebpf.get('stderr')}_")
    if hardware:
        report_lines += ["", "## Hardware health", ""]
        for key, value in hardware.items():
            if key in ("edac", "throttle"):
                report_lines.append(f"- {key}: `{json.dumps(value)[:800]}`")
            else:
                report_lines.append(f"- {key}: {'captured' if value else 'failed'}")
    report_lines += ["", "## Skipped", ""]
    report_lines += [f"- {item}" for item in skipped] or ["- none"]
    report_lines += ["", "## Next steps", "",
                     "- Compare this trace with a control run pinned to another core.",
                     "- Attach the directory to the triage case and the evidence bundle.",
                     "- Escalate to the hardware vendor only with the control comparison."]
    _write(outdir, "REPORT.md", "\n".join(report_lines) + "\n")

    manifest_files = {}
    for path in sorted(outdir.rglob("*")):
        if path.is_file() and path.name not in ("manifest.json", "SHA256SUMS"):
            manifest_files[str(path.relative_to(outdir))] = sha256_file(path)

    files_sha = sha256_text("\n".join(
        f"{name}:{digest}" for name, digest in sorted(manifest_files.items())
    ))
    manifest = {
        "files": manifest_files,
        "files_sha256": files_sha,
        "bundle_sha256": files_sha,
        "request": request,
        "summary": {
            "status": status,
            "trace": trace.get("lines"),
            "core2_event_pct": trace.get("core2_event_pct"),
            "page_faults": trace.get("page_faults"),
            "ebpf_totals": (ebpf or {}).get("data", {}).get("totals"),
        },
    }
    bundle_sha = files_sha
    _write(outdir, "SHA256SUMS", "\n".join(
        f"{v}  {k}" for k, v in manifest_files.items()
    ) + "\n")
    write_json(outdir / "manifest.json", manifest)

    conn.execute(
        "INSERT INTO deep_runs(ts,case_id,finding_id,status,reason,duration_s,pid,comm,"
        "path,sha256,summary) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
        (iso(), case_id, request.get("finding_id"), status, request.get("reason"), duration,
         request.get("pid"), request.get("comm"), str(outdir), bundle_sha,
         json.dumps({"trace_lines": trace.get("lines"),
                     "core2_pct": trace.get("core2_event_pct"),
                     "ebpf_switches": (ebpf or {}).get("data", {}).get("totals", {}).get("switches"),
                     "skipped": skipped})),
    )
    conn.execute(
        "UPDATE findings SET status='investigating' WHERE id=?", (request.get("finding_id"),)
    )
    if case_id:
        _attach_to_case(conn, case_id, outdir, bundle_sha, trace)
    _write_deep_index(conn)
    return {"status": status, "path": str(outdir), "sha256": bundle_sha, "trace": trace,
            "perf": perf, "skipped": skipped}


def _attach_to_case(conn, case_id: int, outdir, sha: str, trace: dict) -> None:
    case = conn.execute("SELECT * FROM core2_cases WHERE id=?", (case_id,)).fetchone()
    if not case or not case["path"]:
        return
    section = (
        f"\n\n## Deep investigation {iso()}\n\n"
        f"- Artifacts: `{outdir}`\n"
        f"- SHA-256: `{sha}`\n"
        f"- Trace lines: {trace.get('lines', 0)}; core-2 event share: "
        f"{trace.get('core2_event_pct', 'n/a')}%\n"
        f"- Read `{outdir / 'REPORT.md'}` before drawing conclusions.\n"
    )
    path = case["path"]
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(section)


def _write_deep_index(conn) -> None:
    rows = conn.execute(
        "SELECT * FROM deep_runs ORDER BY id DESC LIMIT 200"
    ).fetchall()
    lines = [
        "# Deep investigation runs",
        "",
        "| run | case | status | trace lines | core-2 % | path |",
        "|---|---|---|---|---|---|",
    ]
    for row in rows:
        try:
            summary = json.loads(row["summary"] or "{}")
        except json.JSONDecodeError:
            summary = {}
        lines.append(
            f"| {row['id']} | {row['case_id'] or '—'} | {row['status']} | "
            f"{summary.get('trace_lines', '—')} | {summary.get('core2_pct', '—')} | "
            f"`{row['path']}` |"
        )
    config.DEEP_DIR.mkdir(parents=True, exist_ok=True)
    (config.DEEP_DIR / "index.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def consume(conn, duration: int | None = None, dry_run: bool = False,
            perf_record: bool = False) -> list[dict]:
    config.DEEP_ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    results = []
    for path in pending_requests():
        try:
            request = json.loads(read_text(path))
        except json.JSONDecodeError:
            continue
        result = run_request(conn, request, duration, dry_run, perf_record)
        results.append(result)
        if result.get("status") == "needs-root":
            continue
        try:
            os.replace(path, config.DEEP_ARCHIVE_DIR / os.path.basename(path))
        except OSError:
            pass
    return results
