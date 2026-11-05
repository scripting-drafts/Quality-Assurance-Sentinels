"""Unit tests for the parts where a mistake would falsify QA evidence."""
import json
import unittest

from sentinels import classify
from sentinels.ingest import core2_verdict, parse_cpu_list
from sentinels.util import redact


class CpuMaskTests(unittest.TestCase):
    def test_ranges_and_lists(self):
        self.assertEqual(parse_cpu_list("0-3,8"), {0, 1, 2, 3, 8})
        self.assertEqual(parse_cpu_list("2"), {2})
        self.assertEqual(parse_cpu_list("0,6"), {0, 6})

    def test_unknown_is_none_not_zero(self):
        self.assertIsNone(parse_cpu_list(None))
        self.assertIsNone(parse_cpu_list(""))
        self.assertIsNone(parse_cpu_list("n/a"))

    def test_core2_verdict(self):
        self.assertEqual(core2_verdict({2, 8}), 1)
        self.assertEqual(core2_verdict({0, 6}), 0)
        self.assertIsNone(core2_verdict(None))


class ClassificationTests(unittest.TestCase):
    def test_kernel_panic_is_critical(self):
        self.assertEqual(classify.classify("kernel panic - not syncing: Fatal exception"), "critical")

    def test_segv_is_critical(self):
        self.assertEqual(classify.classify("firefox-esr[123]: segfault at 0 ip 0000"), "critical")

    def test_nvrm_loading_is_noise(self):
        self.assertEqual(
            classify.classify("NVRM: loading NVIDIA UNIX x86_64 Kernel Module 550.163.01"),
            "noise",
        )

    def test_xorg_info_is_noise(self):
        self.assertEqual(classify.classify("(--) NVIDIA(GPU-0): DFP-0: disconnected"), "noise")

    def test_plain_failure_is_error(self):
        self.assertEqual(classify.classify("Failed to start unit: input/output error"), "error")

    def test_priority_fallback(self):
        self.assertEqual(classify.priority_to_severity(3), "error")
        self.assertEqual(classify.priority_to_severity(4), "warning")


class SignatureTests(unittest.TestCase):
    def test_numbers_and_addresses_collapse(self):
        a = classify.signature("crash at 0xdeadbeef pid 4321 after 900 ms")
        b = classify.signature("crash at 0xcafebabe pid 7654 after 12 ms")
        self.assertEqual(a, b)

    def test_vendor_routing(self):
        self.assertEqual(classify.vendor_for("mozilla::gfx::WebRender error"), "mozilla")
        self.assertEqual(classify.vendor_for("NVRM: Xid (PCI:0000:0a:00): 79"), "nvidia")
        self.assertEqual(classify.vendor_for("kernel: BUG: unable to handle page fault"), "canonical-kernel")

    def test_ticket_filter(self):
        self.assertFalse(classify.ticketworthy("not generating service for xdg-autostart", "event", "warning", 50))
        self.assertTrue(classify.ticketworthy("anything", "crash", "critical", 1))
        self.assertTrue(classify.ticketworthy("real error", "event", "error", 5))
        self.assertFalse(classify.ticketworthy("noise", "event", "error", 2))


class RedactionTests(unittest.TestCase):
    def test_operator_identity_is_removed(self):
        from sentinels import util

        old_user, old_host = util._USER, util._HOSTNAME
        util._USER, util._HOSTNAME = "alex", "test-host"
        try:
            raw = (
                "user alex at /home/alex/ff-profile host test-host "
                "mail alex@example.com mac aa:bb:cc:dd:ee:ff serial: XYZ123 "
                "ip 198.51.100.20 uuid 123e4567-e89b-12d3-a456-426614174000"
            )
            out = redact(raw)
        finally:
            util._USER, util._HOSTNAME = old_user, old_host
        for secret in ("alex", "test-host", "example.com", "aa:bb:cc", "XYZ123", "198.51.100.20"):
            self.assertNotIn(secret, out)
        self.assertIn("/home/<user>", out)
        self.assertIn("<serial>", out)


class ReportAggregationTests(unittest.TestCase):
    def test_counts_are_weighted(self):
        from sentinels.report import _event_groups

        rows = [
            {"unit": "kernel", "message": "BUG: soft lockup - CPU#2 stuck for 22s", "ts": "t1",
             "last_ts": "t2", "severity": "critical", "count": 3},
        ]
        groups = _event_groups(rows)
        self.assertEqual(groups[0]["count"], 3)


class TicketCorrelationTests(unittest.TestCase):
    def _conn(self):
        import sqlite3
        from sentinels import db

        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(db.SCHEMA)
        conn.execute(
            "INSERT INTO crashes(ts,pid,comm,exe,sig,corefile,cpus_allowed,core2_involved,context,fingerprint)"
            " VALUES(?,?,?,?,?,?,?,?,?,?)",
            ("2026-11-02T20:00:00Z", 4242, "firefox-esr", "firefox-esr", "SIGSEGV",
             "present", "2,8", 1, "WebRender crash", "test-fp"),
        )
        return conn

    def test_core2_crash_reaches_both_owner_and_hardware_vendor(self):
        from sentinels import tickets

        issues = tickets._collect_issues(self._conn(), days=7)
        vendors = {i["vendor"] for i in issues}
        self.assertIn("mozilla", vendors)
        self.assertIn("hardware", vendors)

    def test_draft_keeps_core2_rows_and_withholds_identity(self):
        from sentinels import tickets

        issues = tickets._collect_issues(self._conn(), days=7)
        issue = next(i for i in issues if i["vendor"] == "hardware")
        title, body = tickets._draft(issue, None, {}, False)
        self.assertIn("core 2", body.lower())
        self.assertIn("| yes |", body)
        self.assertIn("withheld", body)
        self.assertNotIn("linkedin.com", body.lower())


class Core2TriageTests(unittest.TestCase):
    def _conn(self):
        import sqlite3
        from sentinels import db

        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(db.SCHEMA)
        return conn

    def _crash(self, conn, fp, comm, mask, involved):
        conn.execute(
            "INSERT INTO crashes(ts,pid,comm,exe,sig,corefile,cpus_allowed,core2_involved,context,fingerprint)"
            " VALUES(?,?,?,?,?,?,?,?,?,?)",
            ("2026-11-02T20:00:00Z", 1, comm, comm, "SIGSEGV", "present",
             mask, involved, "ctx", fp),
        )

    def test_event_regex_matches_core2_only(self):
        from sentinels.triage import event_is_core2

        self.assertTrue(event_is_core2("mce: [Hardware Error]: CPU 2: Machine Check"))
        self.assertTrue(event_is_core2("watchdog: BUG: soft lockup - CPU#2 stuck"))
        self.assertTrue(event_is_core2("physical core 2 failed"))
        self.assertFalse(event_is_core2("CPU 12 timed out"))
        self.assertFalse(event_is_core2("event16 mouse lag"))

    def test_side_queue_keeps_confirmed_and_matching_controls(self):
        from sentinels import triage

        conn = self._conn()
        self._crash(conn, "a", "firefox-esr", "2,8", 1)
        self._crash(conn, "b", "firefox-esr", "0,6", 0)
        self._crash(conn, "c", "nvidia-settings", "0,6", 0)
        result = triage.refresh(conn, days=30, persist_files=False)
        rows = triage.cases(conn, limit=20)
        verdicts = {(r["process"], r["verdict"]) for r in rows}
        self.assertIn(("firefox-esr", "confirmed"), verdicts)
        self.assertIn(("firefox-esr", "control"), verdicts)
        self.assertNotIn(("nvidia-settings", "control"), verdicts)
        self.assertEqual(result["total"], 2)

    def test_unresolved_browser_crash_is_kept_before_confirmation(self):
        from sentinels import triage

        conn = self._conn()
        self._crash(conn, "d", "firefox-esr", None, None)
        triage.refresh(conn, days=30, persist_files=False)
        rows = triage.cases(conn, limit=20)
        self.assertEqual(rows[0]["verdict"], "unresolved")

    def test_unknown_affinity_is_kept_as_unresolved_not_dropped(self):
        from sentinels import triage

        conn = self._conn()
        self._crash(conn, "e", "nvidia-settings", None, None)
        triage.refresh(conn, days=30, persist_files=False)
        rows = triage.cases(conn, limit=20)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["verdict"], "unresolved")


class PostureTests(unittest.TestCase):
    def test_live_posture_is_unprivileged(self):
        from sentinels import posture

        data = posture.collect()
        self.assertEqual(data["euid"], __import__("os").geteuid())
        self.assertIn(data["verdict"], ("unprivileged", "privileged"))
        self.assertFalse(data["sudo_nopasswd"])
        self.assertTrue(str(data["perf_event_paranoid"]).isdigit())
        self.assertIn("lockdown_active", data)
        self.assertIsInstance(data["baseline_changed"], list)


class LayerTests(unittest.TestCase):
    def _conn(self):
        import sqlite3
        from sentinels import db

        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(db.SCHEMA)
        return conn

    def test_layer1_rules_find_crash_event_and_resource_pressure(self):
        import json
        from sentinels import detect

        conn = self._conn()
        conn.execute(
            "INSERT INTO crashes(ts,pid,comm,exe,sig,corefile,cpus_allowed,core2_involved,context,fingerprint)"
            " VALUES(datetime('now'),1,'firefox-esr','firefox-esr','SIGSEGV','present','2,8',1,'ctx','fp1')"
        )
        conn.execute(
            "INSERT INTO events(ts,boot_id,source,severity,unit,pid,comm,message,fingerprint,raw)"
            " VALUES(datetime('now'),'b','kernel','critical','kernel',1,'kernel',"
            "'mce: [Hardware Error]: CPU 2: Machine Check','fp2','{}')"
        )
        payload = {
            "mem": {"MemTotal": 1000000, "MemAvailable": 1000},
            "psi": {"memory": {"full": {"avg300": 50}}, "io": {"some": {"avg300": 80}}},
            "thermal": [{"type": "Tctl", "millideg_c": 95000}],
        }
        conn.execute(
            "INSERT INTO samples(ts,boot_id,payload) VALUES(datetime('now'),'b',?)",
            (json.dumps(payload),),
        )
        rules = {f["rule"] for f in detect.scan(conn)}
        for expected in ("crash.core2", "kernel.hardware", "memory.low",
                         "memory.pressure", "io.pressure", "thermal.high"):
            self.assertIn(expected, rules)

    def test_layer1_dedupes_repeated_findings(self):
        from sentinels import detect

        conn = self._conn()
        payload = {"mem": {"MemTotal": 1000000, "MemAvailable": 1000}}
        conn.execute(
            "INSERT INTO samples(ts,boot_id,payload) VALUES(datetime('now'),'b',?)",
            (__import__("json").dumps(payload),),
        )
        self.assertEqual(len(detect.scan(conn)), 1)
        self.assertEqual(detect.scan(conn), [])

    def test_trace_summary(self):
        from sentinels import deep

        text = (
            "swapper/2-0 [002] d..2. 123.456: sched_switch: prev_comm=swapper/2\n"
            "firefox-42 [002] d..2. 123.500: exceptions:page_fault_user: address=0x0\n"
            "bash-7 [000] d..2. 123.600: sched_switch: prev_comm=bash\n"
        )
        summary = deep.summarize_trace(text)
        self.assertEqual(summary["lines"], 3)
        self.assertEqual(summary["by_cpu"]["2"], 2)
        self.assertEqual(summary["page_faults"], 1)
        self.assertGreater(summary["core2_event_pct"], 60)
        self.assertEqual(summary["top_core2_comms"][0][0], "firefox")

    def test_layer2_reports_privilege_honestly(self):
        from sentinels import deep

        priv = deep.privilege()
        self.assertIn("ok", priv)
        self.assertIn("CAP_SYS_ADMIN", priv["caps"])
        self.assertIn("CAP_BPF", priv["caps"])
        self.assertIn("can_bpf", priv)
        self.assertEqual(priv["ok"], priv["euid"] == 0 or (
            priv["caps"]["CAP_SYS_ADMIN"] and priv["caps"]["CAP_PERFMON"]
            and priv["caps"]["CAP_DAC_OVERRIDE"]
        ))

    def test_critical_findings_queue_deep_runs_with_cooldown(self):
        import pathlib
        import tempfile
        from sentinels import config, detect

        conn = self._conn()
        finding = {
            "id": 1, "fingerprint": "f1", "severity": "critical",
            "rule": "kernel.hardware", "subject": "kernel", "case_id": None,
        }
        old = config.DEEP_REQUEST_DIR
        with tempfile.TemporaryDirectory() as tmp:
            config.DEEP_REQUEST_DIR = pathlib.Path(tmp)
            try:
                first = detect.queue_escalations(conn, [finding], cooldown_s=1800)
                second = detect.queue_escalations(conn, [finding], cooldown_s=1800)
                self.assertEqual(len(first), 1)
                self.assertEqual(second, [])
                self.assertEqual(len(list(pathlib.Path(tmp).glob("*.json"))), 1)
            finally:
                config.DEEP_REQUEST_DIR = old


class EbpfTests(unittest.TestCase):
    def test_binary_and_object_are_present(self):
        from sentinels import config

        binary = config.BIN / "qa_ebpf"
        obj = config.BIN / "qa_trace.bpf.o"
        if not binary.exists() or not obj.exists():
            self.skipTest("eBPF not built; run root/ebpf/bootstrap-ebpf.sh && build.sh")
        import subprocess

        result = subprocess.run([str(binary), "--help"], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn("--duration", result.stdout)
        self.assertGreater(obj.stat().st_size, 1000)

    def test_unprivileged_loader_fails_cleanly(self):
        import os
        from sentinels import config

        binary = config.BIN / "qa_ebpf"
        if not binary.exists():
            self.skipTest("eBPF not built")
        if os.geteuid() == 0:
            self.skipTest("running as root")
        import subprocess

        result = subprocess.run(
            [str(binary), "--duration", "1"], capture_output=True, text=True, timeout=20
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Operation not permitted", result.stderr)


class DeploymentTests(unittest.TestCase):
    def test_installer_watches_the_real_deep_request_queue(self):
        from sentinels import config

        script = (config.ROOT / "root" / "install-system.sh").read_text()
        self.assertIn("PathExistsGlob=$ROOT/triage/core2/deep-requests/*.json", script)
        self.assertEqual(config.DEEP_REQUEST_DIR, config.TRIAGE_DIR / "deep-requests")

    def test_single_installer_is_interactive_and_covers_both_layers(self):
        import os
        import subprocess
        from sentinels import config

        script = config.ROOT / "install.sh"
        text = script.read_text()
        self.assertIn('dirname "${BASH_SOURCE[0]}")"', text)
        self.assertNotIn('BASH_SOURCE[0]}")/..', text)
        for needle in ("--layer1", "--no-layer1", "--layer2", "--no-layer2",
                       "--dry-run", "--check", "--yes", "ask ", "audit_install"):
            self.assertIn(needle, text)
        self.assertTrue(os.access(script, os.X_OK))
        check = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
        self.assertEqual(check.returncode, 0, check.stderr)

    def test_installer_dry_run_selects_each_layer_without_changing_anything(self):
        import subprocess
        from sentinels import config

        script = str(config.ROOT / "install.sh")
        both = subprocess.run(
            [script, "--dry-run", "--yes", "--layer1", "--layer2"],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(both.returncode, 0, both.stderr)
        self.assertIn("layer 1: build sampler", both.stdout)
        self.assertIn("layer 2: deep-trace", both.stdout)
        self.assertIn("   $ make -C src install", both.stdout)
        self.assertIn("   $ ./bin/qa deploy-layer2", both.stdout)
        self.assertIn("   $ ./bin/qa install-cron", both.stdout)
        self.assertIn("dry run complete", both.stdout)
        self.assertIn("not executed", both.stdout)

        layer2_only = subprocess.run(
            [script, "--dry-run", "--yes", "--no-layer1", "--layer2"],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(layer2_only.returncode, 0, layer2_only.stderr)
        self.assertIn("layer 1: skipped", layer2_only.stdout)
        self.assertIn("   $ ./bin/qa deploy-layer2", layer2_only.stdout)

        systemd = subprocess.run(
            [script, "--dry-run", "--yes", "--layer1", "--no-layer2", "--systemd"],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(systemd.returncode, 0, systemd.stderr)
        self.assertIn("$ sudo root/install-system.sh --takeover", systemd.stdout)

        nothing = subprocess.run(
            [script, "--yes", "--no-layer1", "--no-layer2"],
            capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(nothing.returncode, 2)
        self.assertIn("nothing selected", nothing.stderr)

    def test_installer_check_reports_leftovers_without_changing_anything(self):
        import subprocess
        from sentinels import config

        script = config.ROOT / "install.sh"
        before = {p: p.stat().st_mtime for p in (
            config.BIN / "qa_sample", config.ROOT / "README.md"
        ) if p.exists()}
        proc = subprocess.run(
            [str(script), "--check"], capture_output=True, text=True, timeout=120,
        )
        self.assertIn(proc.returncode, (0, 1), proc.stderr)
        self.assertIn("installation check", proc.stdout)
        self.assertIn("schedulers", proc.stdout)
        self.assertIn("leftovers", proc.stdout)
        self.assertTrue(
            "nothing was changed" in proc.stdout or "no leftovers" in proc.stdout,
            proc.stdout,
        )
        self.assertNotIn("Proceed?", proc.stdout)
        for path, stamp in before.items():
            self.assertEqual(path.stat().st_mtime, stamp, path)

    def test_deploy_layer2_keeps_the_phase_alias(self):
        from sentinels import cli

        parser = cli.build_parser()
        for name in ("deploy-layer2", "deploy-phase2"):
            args = parser.parse_args([name, "--check"])
            self.assertIs(args.func, cli.cmd_deploy_layer2)

    def test_uninstaller_keeps_gathered_data_by_default(self):
        import os
        import subprocess
        from sentinels import config

        script = config.ROOT / "uninstall.sh"
        text = script.read_text()
        self.assertIn('dirname "${BASH_SOURCE[0]}")"', text)
        self.assertNotIn('BASH_SOURCE[0]}")/..', text)
        for needle in ("--dry-run", "--keep-build", "--purge-data", "--yes",
                       "will keep", "config/identity.env"):
            self.assertIn(needle, text)
        self.assertTrue(os.access(script, os.X_OK))
        check = subprocess.run(["bash", "-n", str(script)], capture_output=True, text=True)
        self.assertEqual(check.returncode, 0, check.stderr)

        sampler = config.BIN / "qa_sample"
        existed = sampler.exists()
        proc = subprocess.run(
            [str(script), "--dry-run", "--yes"],
            capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("will keep", proc.stdout)
        self.assertIn("var/", proc.stdout)
        self.assertIn("dry run complete", proc.stdout)
        self.assertIn("nothing was removed", proc.stdout)
        self.assertEqual(sampler.exists(), existed)

    def test_uninstaller_refuses_to_purge_without_confirmation(self):
        import subprocess
        from sentinels import config

        names = ("var", "journal", "evidence", "tickets", "triage")
        before = {name: (config.ROOT / name).exists() for name in names}
        proc = subprocess.run(
            [str(config.ROOT / "uninstall.sh"), "--purge-data"],
            input="no\n", capture_output=True, text=True, timeout=120,
        )
        self.assertEqual(proc.returncode, 2, proc.stderr)
        self.assertIn("aborted; no data was deleted", proc.stderr)
        for name in names:
            self.assertEqual((config.ROOT / name).exists(), before[name])

    def test_privilege_failure_markers(self):
        from sentinels.cli import _privilege_failure

        self.assertTrue(_privilege_failure("sudo: a password is required"))
        self.assertTrue(_privilege_failure("sudo: a terminal is required"))
        self.assertFalse(_privilege_failure("Job for qa-sentinel-deep.path failed"))

    def test_ebpf_build_stamp_matches_the_running_kernel(self):
        from sentinels import config

        if not (config.BIN / "qa_ebpf.build.json").exists():
            self.skipTest("eBPF not built")
        from sentinels.cli import _ebpf_state

        ok, detail = _ebpf_state()
        self.assertTrue(ok, detail)


class CycleTests(unittest.TestCase):
    """Layer 1 runs every due duty from one scheduled command."""

    def _conn(self):
        import sqlite3
        from sentinels import db

        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(db.SCHEMA)
        return conn

    def test_cycle_and_legacy_aliases_share_one_command(self):
        from sentinels import cli

        parser = cli.build_parser()
        for name in ("cycle", "tick", "layer1", "phase1"):
            args = parser.parse_args([name])
            self.assertIs(args.func, cli.cmd_cycle, name)

    def test_due_tasks_persist_their_last_run(self):
        from sentinels import cli

        conn = self._conn()
        self.assertTrue(cli._cycle_due(conn, "raise", 3600))
        cli._cycle_mark(conn, "raise")
        self.assertFalse(cli._cycle_due(conn, "raise", 3600))
        self.assertTrue(cli._cycle_due(conn, "raise", 0))

    def test_cron_block_schedules_only_cycle(self):
        from sentinels import cli

        block = cli._cron_block()
        self.assertEqual(block.count("qa cycle"), 2)  # every minute + @reboot
        self.assertIn("var/cycle.lock", block)
        for gone in ("qa tick", "--drafts", "crosscheck", "report --kind daily"):
            self.assertNotIn(gone, block)

    def test_systemd_timer_runs_the_locked_cycle(self):
        from sentinels import config

        script = (config.ROOT / "root" / "install-system.sh").read_text()
        self.assertIn("flock -n $ROOT/var/cycle.lock $ROOT/bin/qa cycle", script)
        self.assertNotIn("ExecStart=$ROOT/bin/qa tick", script)


class LogRotationTests(unittest.TestCase):
    """cron.log must stay bounded without breaking the live viewer."""

    def test_policy_defaults_stay_within_the_agreed_budget(self):
        from sentinels import config

        self.assertGreaterEqual(config.LOG_MAX_MB, 10)
        self.assertLessEqual(config.LOG_MAX_MB, 25)
        self.assertGreaterEqual(config.LOG_KEEP, 10)
        self.assertLessEqual(config.LOG_KEEP, 20)
        self.assertLessEqual(config.LOG_MAX_MB * config.LOG_KEEP, 500)

    def test_rotation_copies_truncates_and_drops_the_oldest(self):
        import pathlib
        import tempfile
        from sentinels import logs

        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "cron.log"
            path.write_bytes(b"a" * 200)
            result = logs.rotate(path=path, max_bytes=100, keep=2)
            self.assertEqual(result["bytes"], 200)
            self.assertEqual(path.read_bytes(), b"")
            self.assertEqual((path.parent / "cron.log.1").read_bytes(), b"a" * 200)

            path.write_bytes(b"b" * 200)
            logs.rotate(path=path, max_bytes=100, keep=2)
            self.assertEqual((path.parent / "cron.log.1").read_bytes(), b"b" * 200)
            self.assertEqual((path.parent / "cron.log.2").read_bytes(), b"a" * 200)

            path.write_bytes(b"c" * 200)
            logs.rotate(path=path, max_bytes=100, keep=2)
            self.assertEqual((path.parent / "cron.log.1").read_bytes(), b"c" * 200)
            self.assertEqual((path.parent / "cron.log.2").read_bytes(), b"b" * 200)
            self.assertFalse((path.parent / "cron.log.3").exists())

    def test_small_or_missing_log_is_left_alone(self):
        import pathlib
        import tempfile
        from sentinels import logs

        with tempfile.TemporaryDirectory() as tmp:
            path = pathlib.Path(tmp) / "cron.log"
            self.assertEqual(logs.rotate(path=path, max_bytes=100, keep=2), {})
            path.write_bytes(b"x" * 99)
            self.assertEqual(logs.rotate(path=path, max_bytes=100, keep=2), {})
            self.assertEqual(path.read_bytes(), b"x" * 99)


class NotificationFlowTests(unittest.TestCase):
    """Queued notifications retry fairly, back off, and expire."""

    def _conn(self):
        import sqlite3
        from sentinels import db

        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(db.SCHEMA)
        return conn

    def _add(self, conn, key, ts=None):
        from sentinels.util import iso

        conn.execute(
            "INSERT INTO notifications(ts,kind,key,title,body,delivered)"
            " VALUES(?,?,?,?,?,0)",
            (ts or iso(), "draft", key, key, "body"),
        )

    def _rows(self, conn):
        return {r["key"]: dict(r) for r in conn.execute("SELECT * FROM notifications")}

    def test_schema_carries_retry_bookkeeping(self):
        conn = self._conn()
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(notifications)")}
        for name in ("attempts", "last_attempt", "last_error"):
            self.assertIn(name, cols)

    def test_failed_rows_back_off_while_fresh_rows_go_first(self):
        from unittest import mock
        from sentinels import notify

        conn = self._conn()
        for key in ("a", "b", "c"):
            self._add(conn, key)
        with mock.patch.object(notify, "send",
                               side_effect=[(False, "no session"), (True, "sent")]):
            first = notify.drain(conn, limit=2)
        self.assertEqual(first["sent"], 1)
        self.assertEqual([f["key"] for f in first["failed"]], ["a"])
        self.assertEqual(first["failed"][0]["attempts"], 1)
        rows = self._rows(conn)
        self.assertEqual(rows["a"]["attempts"], 1)
        self.assertEqual(rows["a"]["last_error"], "no session")
        self.assertEqual(rows["b"]["delivered"], 1)

        # c is unattempted and goes first; a is still inside its backoff window
        with mock.patch.object(notify, "send", return_value=(True, "sent")):
            second = notify.drain(conn, limit=2)
        self.assertEqual(second["sent"], 1)
        rows = self._rows(conn)
        self.assertEqual(rows["c"]["delivered"], 1)
        self.assertEqual(rows["a"]["delivered"], 0)

    def test_row_retries_after_backoff_expires(self):
        from datetime import timedelta
        from unittest import mock
        from sentinels import notify
        from sentinels.util import iso, utcnow

        conn = self._conn()
        self._add(conn, "a")
        conn.execute(
            "UPDATE notifications SET attempts=1, last_attempt=? WHERE key='a'",
            (iso(utcnow() - timedelta(seconds=notify._backoff_seconds(1) + 1)),),
        )
        with mock.patch.object(notify, "send", return_value=(True, "sent")):
            result = notify.drain(conn)
        self.assertEqual(result["sent"], 1)
        self.assertEqual(self._rows(conn)["a"]["delivered"], 1)

    def test_undelivered_rows_expire(self):
        from datetime import timedelta
        from unittest import mock
        from sentinels import config, notify
        from sentinels.util import iso, utcnow

        conn = self._conn()
        old = iso(utcnow() - timedelta(days=config.NOTIFY_TTL_DAYS + 1))
        self._add(conn, "old", ts=old)
        self._add(conn, "new")
        with mock.patch.object(notify, "send", return_value=(False, "dead")):
            notify.drain(conn)
        rows = self._rows(conn)
        self.assertNotIn("old", rows)
        self.assertIn("new", rows)

    def test_new_draft_digest_supersedes_pending_ones(self):
        import pathlib
        import tempfile
        from unittest import mock
        from sentinels import notify

        conn = self._conn()
        conn.executescript(
            "CREATE TABLE IF NOT EXISTS ticket_drafts ("
            " id INTEGER PRIMARY KEY, ts TEXT, vendor TEXT, path TEXT,"
            " title TEXT, issue_key TEXT UNIQUE)"
        )
        self._add(conn, "drafts|old")
        conn.execute(
            "INSERT INTO ticket_drafts(ts,vendor,path,title,issue_key)"
            " VALUES('2026-11-04T00:00:00Z','nvidia','/tmp/d.md','d','k1')"
        )
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(notify.config, "DRAFT_DIR", pathlib.Path(tmp)), \
             mock.patch.object(notify, "_drafts_index", return_value=None), \
             mock.patch("sentinels.correlate.aggregate", return_value=[]):
            result = notify.collect(conn)
        self.assertEqual(result["queued"], 1)
        drafts = [r for r in conn.execute(
            "SELECT * FROM notifications WHERE kind='draft' AND delivered=0"
        )]
        self.assertEqual(len(drafts), 1)
        self.assertNotEqual(drafts[0]["key"], "drafts|old")

    def test_crosscheck_key_depends_on_drift_composition(self):
        from sentinels import crosscheck

        stale = [{"issue_key": "a"}]
        missing = [{"key": "b"}]
        ready = []
        first = crosscheck._drift_key(stale, missing, ready)
        self.assertEqual(first, crosscheck._drift_key(stale, missing, ready))
        self.assertNotEqual(first, crosscheck._drift_key(stale, missing, [{"key": "c"}]))

    def test_available_uses_the_session_bus_not_display(self):
        from unittest import mock
        from sentinels import notify

        with mock.patch.object(notify.shutil, "which", return_value="/usr/bin/notify-send"), \
             mock.patch.object(notify, "_gi_available", return_value=False), \
             mock.patch.object(notify, "_session_bus",
                               return_value="unix:path=/run/user/1000/bus"), \
             mock.patch.dict(notify.os.environ,
                             {"DISPLAY": "", "WAYLAND_DISPLAY": ""}):
            self.assertEqual(notify.available(), (True, "ok"))

    def test_available_requires_a_session_bus(self):
        from unittest import mock
        from sentinels import notify

        with mock.patch.object(notify.shutil, "which", return_value="/usr/bin/notify-send"), \
             mock.patch.object(notify, "_gi_available", return_value=False), \
             mock.patch.object(notify, "_session_bus", return_value=None):
            ok, why = notify.available()
        self.assertFalse(ok)
        self.assertIn("session bus", why)

    def test_pygobject_is_a_notification_backend_without_notify_send(self):
        from unittest import mock
        from sentinels import notify

        with mock.patch.object(notify.shutil, "which", return_value=None), \
             mock.patch.object(notify, "_gi_available", return_value=True), \
             mock.patch.object(notify, "_session_bus", return_value="unix:path=bus"):
            self.assertEqual(notify.available(), (True, "ok"))

    def test_plain_send_falls_back_to_pygobject(self):
        from unittest import mock
        from sentinels import notify

        with mock.patch.object(notify.shutil, "which", return_value=None), \
             mock.patch.object(notify, "_gi_available", return_value=True), \
             mock.patch.object(notify, "_gi_send",
                               return_value=(True, "sent (D-Bus)")) as gi_send:
            result = notify._plain_send("t", "b", "normal")
        self.assertEqual(result, (True, "sent (D-Bus)"))
        gi_send.assert_called_once()

    def test_headless_delivery_keeps_the_message(self):
        from unittest import mock
        from sentinels import notify

        with mock.patch.object(notify, "available", return_value=(True, "ok")), \
             mock.patch.object(notify, "_gi_available", return_value=True), \
             mock.patch.object(notify, "_graphical_session", return_value=False), \
             mock.patch.object(notify, "_spawn_click_helper") as spawn, \
             mock.patch.object(notify, "_plain_send",
                               return_value=(True, "sent")) as plain:
            ok, detail = notify.send("t", "b", path="/tmp/x.md")
        self.assertTrue(ok)
        self.assertIn("no graphical session", detail)
        plain.assert_called_once()
        spawn.assert_not_called()

    def test_env_prepends_the_repository_to_pythonpath(self):
        import os
        from unittest import mock
        from sentinels import notify

        with mock.patch.dict(notify.os.environ,
                             {"PYTHONPATH": "/somewhere/else"}, clear=True):
            env = notify._env()
        parts = env["PYTHONPATH"].split(os.pathsep)
        self.assertEqual(parts[0], str(notify.config.ROOT))
        self.assertEqual(parts[-1], "/somewhere/else")

    def test_click_helper_startup_failure_is_not_delivery(self):
        import subprocess
        from unittest import mock
        from sentinels import notify

        class Dead:
            def wait(self, timeout=None):
                return 1

        class Alive:
            def wait(self, timeout=None):
                raise subprocess.TimeoutExpired("helper", timeout)

        with mock.patch.object(notify.subprocess, "Popen", return_value=Dead()):
            self.assertFalse(notify._spawn_click_helper(
                "/tmp/x.md", "t", "b", "normal"
            ))
        with mock.patch.object(notify.subprocess, "Popen", return_value=Alive()):
            self.assertTrue(notify._spawn_click_helper(
                "/tmp/x.md", "t", "b", "normal"
            ))

    def test_claim_has_exactly_one_owner(self):
        from sentinels import notify

        conn = self._conn()
        self._add(conn, "a")
        row = dict(conn.execute(
            "SELECT * FROM notifications WHERE key='a'"
        ).fetchone())
        self.assertTrue(notify._claim(conn, row, "2026-11-05T12:00:00Z"))
        self.assertFalse(notify._claim(conn, row, "2026-11-05T12:00:00Z"))
        current = conn.execute(
            "SELECT attempts FROM notifications WHERE key='a'"
        ).fetchone()
        self.assertEqual(current["attempts"], 1)

    def test_supersede_replaces_only_undelivered_older_rows(self):
        from sentinels import notify

        conn = self._conn()
        self._add(conn, "old")
        conn.execute(
            "INSERT INTO notifications(ts,kind,key,title,body,delivered)"
            " VALUES('2026-11-05T00:00:00Z','draft','done','t','b',1)"
        )
        self.assertTrue(notify.enqueue(
            conn, "draft", "new", "t", "b", supersede=True
        ))
        keys = {r["key"] for r in conn.execute("SELECT key FROM notifications")}
        self.assertEqual(keys, {"new", "done"})

    def test_no_drafts_clears_a_pending_digest(self):
        from unittest import mock
        from sentinels import notify

        conn = self._conn()
        self._add(conn, "drafts|old")
        with mock.patch("sentinels.correlate.aggregate", return_value=[]):
            result = notify.collect(conn)
        self.assertEqual(result["queued"], 0)
        self.assertEqual(notify.pending_count(conn), 0)

    def test_notify_cli_fails_when_drain_has_failures(self):
        from contextlib import contextmanager
        from types import SimpleNamespace
        from unittest import mock
        from sentinels import cli, notify

        conn = self._conn()
        self._add(conn, "a")

        @contextmanager
        def session():
            yield conn

        import contextlib
        import io

        with mock.patch.object(cli.db, "session", session), \
             mock.patch.object(notify, "available", return_value=(False, "no session")), \
             mock.patch.object(notify, "collect", return_value={"queued": 0, "pending": 1}), \
             mock.patch.object(notify, "send", return_value=(False, "no session")), \
             contextlib.redirect_stdout(io.StringIO()):
            rc = cli.cmd_notify(SimpleNamespace(test=False, drain=True))
        self.assertEqual(rc, 1)


class HeldPackageTests(unittest.TestCase):
    """A crash in a held, outdated module may already be fixed upstream."""

    def _conn(self):
        import sqlite3
        from sentinels import db

        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(db.SCHEMA)
        return conn

    def test_only_the_owner_family_is_matched_and_outdated_is_flagged(self):
        from unittest import mock
        from sentinels import holds, packages

        holds.held.cache_clear()
        holds._policies.cache_clear()
        installed = (
            ("nvidia-settings", "610.43.02"), ("nvidia-driver-550", "550.163.01"),
            ("vim", "9.0"),
        )
        try:
            with mock.patch.object(packages, "installed", return_value=installed), \
                 mock.patch.object(packages, "owner",
                                   return_value={"package": "nvidia-settings"}), \
                 mock.patch.object(holds, "held", return_value=(
                     "nvidia-settings", "nvidia-driver-550", "vim", "nvidia-driver-595")), \
                 mock.patch.object(holds, "_policies", return_value={
                     "nvidia-settings": {"installed": "610.43.02", "candidate": "615.71.10"},
                     "nvidia-driver-550": {"installed": "550.163.01",
                                           "candidate": "550.163.01"},
                 }):
                result = holds.relevant("/usr/bin/nvidia-settings")
        finally:
            holds.held.cache_clear()
            holds._policies.cache_clear()
        matched = {row["package"] for row in result["relevant"]}
        self.assertIn("nvidia-settings", matched)
        self.assertIn("nvidia-driver-550", matched)
        self.assertNotIn("vim", matched)              # unrelated hold
        self.assertNotIn("nvidia-driver-595", matched)  # not installed
        self.assertEqual([r["package"] for r in result["outdated"]], ["nvidia-settings"])

    def test_global_hold_is_flagged(self):
        from unittest import mock
        from sentinels import holds, packages

        holds.held.cache_clear()
        try:
            with mock.patch.object(holds, "held",
                                   return_value=tuple(f"p{i}" for i in range(1000))), \
                 mock.patch.object(packages, "installed",
                                   return_value=tuple((f"p{i}", "1") for i in range(100))):
                result = holds.counts()
        finally:
            holds.held.cache_clear()
        self.assertTrue(result["mass_hold"])
        self.assertEqual(result["held_installed"], 100)

    def test_crash_finding_names_the_held_outdated_package(self):
        from unittest import mock
        from sentinels import detect

        conn = self._conn()
        conn.execute(
            "INSERT INTO crashes(ts,pid,comm,exe,sig,corefile,cpus_allowed,"
            "core2_involved,context,fingerprint) VALUES(datetime('now'),7,'nvidia-settings',"
            "'/usr/bin/nvidia-settings','SIGABRT','present','2,8',1,'ctx','fp-hold')"
        )
        hold = {"relevant": [], "mass_hold": False, "outdated": [
            {"package": "nvidia-settings", "installed": "610.43.02",
             "candidate": "615.71.10", "outdated": True},
        ]}
        with mock.patch.object(detect.holds, "relevant", return_value=hold):
            findings = detect._crash_findings(conn, "2000-01-01T00:00:00Z")
        self.assertIn("held-outdated", findings[0]["detail"])
        self.assertIn("610.43.02->615.71.10", findings[0]["detail"])

    def test_deep_request_records_held_packages(self):
        import json
        import pathlib
        import tempfile
        from unittest import mock
        from sentinels import config, deep

        conn = self._conn()
        held = [{"package": "nvidia-settings", "installed": "610", "candidate": "615",
                 "outdated": True}]
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(config, "DEEP_REQUEST_DIR", pathlib.Path(tmp)):
                path = deep.enqueue(conn, reason="auto:crash.core2", pid=1, comm="x",
                                    held_packages=held, hold_summary={"mass_hold": False})
                request = json.loads(pathlib.Path(path).read_text())
        self.assertEqual(request["held_packages"], held)
        self.assertEqual(request["hold_summary"]["mass_hold"], False)


class InventoryCadenceTests(unittest.TestCase):
    def test_baseline_uses_base_interval(self):
        from sentinels import config
        from sentinels.inventory import next_interval

        self.assertEqual(next_interval(0, 3000, baseline=True), config.INVENTORY_INTERVAL_S)

    def test_churn_shortens_and_stability_lengthens(self):
        from sentinels import config
        from sentinels.inventory import next_interval

        base = config.INVENTORY_INTERVAL_S
        self.assertEqual(next_interval(100, 3000), base // 4)   # >2% churn
        self.assertEqual(next_interval(20, 3000), base // 2)    # >0.5%
        self.assertEqual(next_interval(1, 3000), base * 2)      # <0.05%
        self.assertEqual(next_interval(3, 3000), base)          # steady

    def test_interval_is_clamped(self):
        from sentinels import config
        from sentinels.inventory import next_interval

        self.assertGreaterEqual(next_interval(3000, 3000), config.INVENTORY_MIN_S)
        self.assertLessEqual(next_interval(0, 3000), config.INVENTORY_MAX_S)


class BootBoundaryTests(unittest.TestCase):
    """A boot verdict decides whether a crash is even investigable."""

    def _conn(self):
        import sqlite3
        from sentinels import db

        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(db.SCHEMA)
        return conn

    def _boot(self, conn, boot_id="b1", clean=0, ts=None):
        if ts is None:
            from sentinels.util import utcnow

            ts = utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
        conn.execute(
            "INSERT INTO boots(boot_id, seq, span, last_ts, ended_clean, markers,"
            " last_message, scans, pstore, kexec_loaded, crashkernel, vmcores, captured_ts)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (boot_id, -1, "span", ts, clean, "", "last line", "{}",
             "[]", 0, "", 0, ts),
        )

    def test_only_clean_boots_are_quiet(self):
        from sentinels import boot

        conn = self._conn()
        self._boot(conn, "clean", clean=1)
        self.assertEqual(boot.findings(conn, "2026-11-01T00:00:00Z"), [])
        self.assertEqual(boot.verdict({"ended_clean": 1}), "CLEAN")
        self.assertEqual(boot.verdict({"ended_clean": 0}), "UNCLEAN")
        self.assertEqual(boot.verdict({"ended_clean": None}), "UNKNOWN")

    def test_unclean_boot_becomes_one_critical_finding(self):
        from sentinels import boot, detect

        conn = self._conn()
        self._boot(conn)
        new = detect.scan(conn)
        rules = [f["rule"] for f in new]
        self.assertEqual(rules, ["boot.unclean"])
        self.assertEqual(new[0]["severity"], "critical")
        self.assertIn("b1", new[0]["fingerprint"])
        # same boot never re-alerts
        self.assertEqual(detect.scan(conn), [])

    def test_classification_reads_shutdown_marker_only(self):
        from unittest import mock
        from sentinels import boot

        record = {"index": -1, "boot_id": "abc", "span": "span"}
        with mock.patch.object(boot, "_journal", return_value="line\nsystemd-shutdown[1]: done\n"), \
             mock.patch.object(boot, "_last_epoch", return_value="2026-11-03T09:00:00Z"):
            self.assertEqual(boot.scan_boot(record)["ended_clean"], 1)
        with mock.patch.object(boot, "_journal", return_value="line\nlast nvidia line\n"), \
             mock.patch.object(boot, "_last_epoch", return_value="2026-11-03T09:00:00Z"):
            self.assertEqual(boot.scan_boot(record)["ended_clean"], 0)

    def test_bug_pattern_does_not_match_xorg_noise(self):
        import re
        from sentinels import boot

        panic = {key: pattern for key, _label, pattern in boot.SCANS}["panic"]
        regex = re.compile(panic)
        self.assertIsNone(regex.search("(EE) event16 - Mouse: client bug: lagging behind"))
        self.assertIsNotNone(regex.search("kernel BUG at mm/slub.c:1"))


class CorrelationTests(unittest.TestCase):
    """Consistency is recurrence across stops, not volume inside one."""

    def _conn(self):
        import sqlite3
        from sentinels import db

        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(db.SCHEMA)
        return conn

    def _boot(self, conn, boot_id, last_ts):
        conn.execute(
            "INSERT INTO boots(boot_id, seq, span, last_ts, ended_clean, markers,"
            " last_message, scans, pstore, kexec_loaded, crashkernel, vmcores, captured_ts)"
            " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (boot_id, -1, "span", last_ts, 0, "", "last line", "{}", "[]", 0, "", 0, last_ts),
        )

    def _event(self, conn, boot_id, ts, message, fingerprint, count=1, unit="kernel"):
        conn.execute(
            "INSERT INTO events(ts,boot_id,source,severity,unit,pid,comm,message,"
            "fingerprint,raw,count,last_ts) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (ts, boot_id, "journal", "critical", unit, 1, "x", message, fingerprint,
             "{}", count, ts),
        )

    def _stops(self, conn):
        from datetime import timedelta
        from sentinels.util import iso, utcnow

        now = utcnow()
        first = iso(now - timedelta(hours=6))
        second = iso(now - timedelta(hours=2))
        self._boot(conn, "bootA", first)
        self._boot(conn, "bootB", second)
        return first, second

    def test_recurring_signature_across_stops_is_ready(self):
        from datetime import timedelta
        from sentinels import correlate
        from sentinels.util import parse_iso

        conn = self._conn()
        first, second = self._stops(conn)
        for i, stop in enumerate((first, second)):
            ts = (parse_iso(stop) - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
            self._event(
                conn, f"boot{'AB'[i]}", ts,
                "NVRM: Xid (PCI:0000:01:00): 79, GPU has fallen off the bus",
                f"fp{i}", count=2,
            )
        summary = correlate.correlate(conn, days=30, notify=False)
        self.assertEqual(summary["unclean_boots"], 2)
        ready = correlate.aggregate(conn, days=30)
        nvidia = [c for c in ready if c["vendor"] == "nvidia" and c["ready"]]
        self.assertTrue(nvidia, ready)
        self.assertEqual(nvidia[0]["boots"], 2)
        self.assertEqual(nvidia[0]["repeat_rate"], 1.0)

    def test_single_stop_is_not_consistent_enough(self):
        from datetime import timedelta
        from sentinels import correlate
        from sentinels.util import parse_iso

        conn = self._conn()
        first, _second = self._stops(conn)
        conn.execute("DELETE FROM boots WHERE boot_id='bootB'")
        ts = (parse_iso(first) - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self._event(conn, "bootA", ts, "NVRM: Xid 79", "fp", count=4)
        correlate.correlate(conn, days=30, notify=False)
        clusters = correlate.aggregate(conn, days=30)
        self.assertTrue(clusters)
        self.assertFalse(any(c["ready"] for c in clusters))

    def test_events_outside_the_death_window_do_not_count(self):
        from datetime import timedelta
        from sentinels import correlate
        from sentinels.util import parse_iso

        conn = self._conn()
        first, _second = self._stops(conn)
        conn.execute("DELETE FROM boots WHERE boot_id='bootB'")
        ts = (parse_iso(first) - timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self._event(conn, "bootA", ts, "NVRM: Xid 79", "fp", count=9)
        self.assertEqual(correlate.clusters_for_boot(
            conn, dict(conn.execute("SELECT * FROM boots").fetchone())), [])

    def test_unattributed_component_never_becomes_a_draft(self):
        from datetime import timedelta
        from sentinels import correlate
        from sentinels.util import parse_iso

        conn = self._conn()
        first, second = self._stops(conn)
        for i, stop in enumerate((first, second)):
            ts = (parse_iso(stop) - timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
            self._event(conn, f"boot{'AB'[i]}", ts,
                        "something odd happened, no owner named", f"fp{i}", count=5,
                        unit="mystery-widget")
        correlate.correlate(conn, days=30, notify=False)
        self.assertEqual(correlate.ticket_candidates(conn, days=30), [])

    def test_candidate_carries_inferred_attribution_note(self):
        from datetime import timedelta
        from sentinels import correlate
        from sentinels.util import parse_iso

        conn = self._conn()
        first, second = self._stops(conn)
        for i, stop in enumerate((first, second)):
            ts = (parse_iso(stop) - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
            self._event(conn, f"boot{'AB'[i]}", ts,
                        "NVRM: Xid (PCI:0000:01:00): 79", f"fp{i}", count=2)
        correlate.correlate(conn, days=30, notify=False)
        candidates = correlate.ticket_candidates(conn, days=30)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0]["vendor"], "nvidia")
        self.assertIn("inferred", candidates[0]["notes"])
        self.assertEqual(candidates[0]["kind"], "correlation")


class RaiseGateTests(unittest.TestCase):
    """Only defensible tickets get staged, and each carries its own evidence."""

    def _conn(self):
        import sqlite3
        from sentinels import db

        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(db.SCHEMA)
        return conn

    def _issue(self, key="k1", vendor="nvidia", count=5, kind="event"):
        from sentinels.util import iso

        return {
            "key": key, "vendor": vendor, "signature": "NVRM: Xid (PCI:0000:01:00): 79",
            "kind": kind, "count": count,
            "first": iso(), "last": iso(),
            "rows": [{"ts": iso(), "message": "NVRM: Xid 79", "boot_id": "bootA",
                      "severity": "critical"}],
        }

    def test_stale_draft_is_not_viable(self):
        from sentinels import raise_ticket

        conn = self._conn()
        verdict = raise_ticket.assess(conn, {"issue_key": "gone", "vendor": "nvidia"}, None)
        self.assertFalse(verdict["viable"])
        self.assertIn("no current evidence", " ".join(verdict["reasons"]))

    def test_volume_below_threshold_is_not_viable(self):
        from sentinels import raise_ticket

        conn = self._conn()
        verdict = raise_ticket.assess(
            conn, {"issue_key": "k1", "vendor": "nvidia"}, self._issue(count=1)
        )
        self.assertFalse(verdict["viable"])
        self.assertIn("substantiated", [c["check"] for c in verdict["checks"] if not c["ok"]])

    def test_environmental_failure_is_not_viable(self):
        from sentinels import raise_ticket
        from sentinels.util import iso

        conn = self._conn()
        issue = {
            "key": "k1", "vendor": "mozilla",
            "signature": "Failed to fetch https://ppa.launchpadcontent.net/x",
            "kind": "event", "count": 9, "first": iso(), "last": iso(),
            "rows": [{"ts": iso(), "message": "Failed to fetch https://x", "severity": "critical"}],
        }
        verdict = raise_ticket.assess(conn, {"issue_key": "k1", "vendor": "mozilla"}, issue)
        self.assertFalse(verdict["viable"])
        self.assertIn("actionable", [c["check"] for c in verdict["checks"] if not c["ok"]])

    def test_unattributed_component_is_not_viable(self):
        from sentinels import raise_ticket

        conn = self._conn()
        verdict = raise_ticket.assess(
            conn, {"issue_key": "k1", "vendor": "local"}, self._issue(vendor="local")
        )
        self.assertFalse(verdict["viable"])

    def test_viable_draft_is_staged_with_evidence_and_redaction(self):
        import pathlib
        import socket
        import tempfile
        from unittest import mock
        from sentinels import config, raise_ticket

        conn = self._conn()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            draft_path = root / "draft.md"
            draft_path.write_text(
                f"# draft\nhost {socket.gethostname()} path {config.HOME}/x\n", encoding="utf-8"
            )
            conn.execute(
                "INSERT INTO ticket_drafts(ts,vendor,path,title,issue_key)"
                " VALUES(datetime('now'),'nvidia',?,?,'k1')",
                (str(draft_path), "NVRM: Xid 79"),
            )
            issue = self._issue()
            raised = root / "raise"
            rejected = root / "rejected"
            with mock.patch.object(config, "RAISE_DIR", raised), \
                 mock.patch.object(config, "REJECT_DIR", rejected), \
                 mock.patch.object(raise_ticket.tickets, "collect_issues",
                                   return_value=[issue]), \
                 mock.patch.object(raise_ticket.report, "append_journal"):
                result = raise_ticket.run(conn, notify_ready=False)
            self.assertEqual(result["viable"], 1, result)
            directory = pathlib.Path(result["staged"][0])
            self.assertTrue((directory / "ticket.md").exists())
            self.assertTrue((directory / "evidence" / "rows.json").exists())
            self.assertTrue((directory / "evidence" / "trace.md").exists())
            self.assertTrue((directory / "evidence" / "manifest.json").exists())
            self.assertTrue((directory / "HOWTO.md").exists())
            self.assertNotIn(socket.gethostname(), (directory / "ticket.md").read_text())
            import json

            manifest = json.loads((directory / "evidence" / "manifest.json").read_text())
            self.assertEqual(manifest["issue_key"], "k1")
            self.assertNotIn(str(config.HOME), (directory / "evidence" / "manifest.json").read_text())
            import hashlib

            digest = hashlib.sha256((directory / "ticket.md").read_bytes()).hexdigest()
            self.assertEqual(manifest["evidence_files"]["ticket.md"], digest)
            self.assertEqual(manifest["viability"]["score"], 6)

    def test_staged_ticket_is_never_deleted_and_records_history(self):
        import json
        import pathlib
        import tempfile
        from unittest import mock
        from sentinels import config, raise_ticket

        conn = self._conn()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            draft_path = root / "draft.md"
            draft_path.write_text("# draft\n", encoding="utf-8")
            conn.execute(
                "INSERT INTO ticket_drafts(ts,vendor,path,title,issue_key)"
                " VALUES(datetime('now'),'nvidia',?,?,'k1')",
                (str(draft_path), "NVRM: Xid 79"),
            )
            issue = self._issue()
            raised = root / "tickets" / "raise"
            standby = root / "tickets" / "standby"
            rejected = root / "tickets" / "rejected"
            marker = raised / "nvidia-old-deadbeef" / "KEEP.txt"
            marker.parent.mkdir(parents=True)
            marker.write_text("staged earlier\n")
            with mock.patch.object(config, "RAISE_DIR", raised), \
                 mock.patch.object(config, "STANDBY_DIR", standby), \
                 mock.patch.object(config, "REJECT_DIR", rejected), \
                 mock.patch.object(raise_ticket.tickets, "collect_issues",
                                   return_value=[issue]), \
                 mock.patch.object(raise_ticket.report, "append_journal"):
                raise_ticket.run(conn, notify_ready=False)
                first = raise_ticket.run(conn, notify_ready=False)
            # nothing is deleted: the non-viable directory is parked in standby
            self.assertFalse(marker.exists())
            self.assertTrue((standby / "nvidia-old-deadbeef" / "KEEP.txt").exists())
            self.assertEqual(first["viable"], 1)
            directory = pathlib.Path(first["staged"][0])
            history = directory / "evidence" / "history.jsonl"
            self.assertTrue(history.exists())
            lines = [ln for ln in history.read_text().splitlines() if ln.strip()]
            self.assertEqual(len(lines), 1)  # identical re-run stays quiet
            self.assertIn("state", json.loads(lines[0]))
            manifest = json.loads((directory / "evidence" / "manifest.json").read_text())
            self.assertIn("last_checked", manifest)

    def test_ticket_returns_to_raise_when_viable_again(self):
        import json
        import pathlib
        import tempfile
        from unittest import mock
        from sentinels import config, raise_ticket

        conn = self._conn()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            draft_path = root / "draft.md"
            draft_path.write_text("# draft\n", encoding="utf-8")
            conn.execute(
                "INSERT INTO ticket_drafts(ts,vendor,path,title,issue_key)"
                " VALUES(datetime('now'),'nvidia',?,?,'k1')",
                (str(draft_path), "NVRM: Xid 79"),
            )
            raised, standby = root / "raise", root / "standby"
            rejected = root / "rejected"
            issue = self._issue()
            with mock.patch.object(config, "RAISE_DIR", raised), \
                 mock.patch.object(config, "STANDBY_DIR", standby), \
                 mock.patch.object(config, "REJECT_DIR", rejected), \
                 mock.patch.object(raise_ticket.report, "append_journal"), \
                 mock.patch.object(raise_ticket.tickets, "collect_issues",
                                   side_effect=[[issue], [], [issue]]):
                first = raise_ticket.run(conn, notify_ready=False)
                self.assertEqual(first["viable"], 1)
                name = pathlib.Path(first["staged"][0]).name
                second = raise_ticket.run(conn, notify_ready=False)
                self.assertEqual(second["viable"], 0)
                self.assertFalse((raised / name).exists())
                self.assertTrue((standby / name).exists())
                third = raise_ticket.run(conn, notify_ready=False)
                self.assertEqual(third["viable"], 1)
                self.assertTrue((raised / name).exists())
                self.assertFalse((standby / name).exists())
                self.assertEqual(third["reactivated"], [name])
            events = [
                json.loads(line)["event"]
                for line in (raised / name / "evidence" / "standby.jsonl")
                .read_text().splitlines() if line.strip()
            ]
            self.assertEqual(events, ["standby", "reactivated"])

    def test_standby_index_lists_parked_tickets(self):
        import pathlib
        import tempfile
        from unittest import mock
        from sentinels import config, raise_ticket

        conn = self._conn()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            raised, standby = root / "raise", root / "standby"
            (raised / "nvidia-gone-abc").mkdir(parents=True)
            with mock.patch.object(config, "RAISE_DIR", raised), \
                 mock.patch.object(config, "STANDBY_DIR", standby), \
                 mock.patch.object(config, "REJECT_DIR", root / "rejected"), \
                 mock.patch.object(raise_ticket.tickets, "collect_issues", return_value=[]), \
                 mock.patch.object(raise_ticket.report, "append_journal"):
                raise_ticket.run(conn, notify_ready=False)
            index = (standby / "INDEX.md").read_text()
            self.assertIn("nvidia-gone-abc", index)
            self.assertIn("kept for traceability", index)

    def test_new_draft_set_triggers_triage_once(self):
        import pathlib
        import tempfile
        from unittest import mock
        from sentinels import config, raise_ticket, tickets
        from sentinels.util import iso

        conn = self._conn()
        issue = {
            "key": "k1", "vendor": "nvidia", "signature": "NVRM: Xid 79",
            "kind": "event", "count": 5, "first": iso(), "last": iso(),
            "rows": [{"ts": iso(), "message": "m", "severity": "critical"}],
        }
        with tempfile.TemporaryDirectory() as tmp, \
             mock.patch.object(config, "DRAFT_DIR", pathlib.Path(tmp)), \
             mock.patch.object(tickets, "collect_issues", return_value=[issue]), \
             mock.patch.object(tickets, "_draft", return_value=("t", "b")), \
             mock.patch.object(raise_ticket, "run",
                               return_value={"viable": 1, "rejected": 0}) as run:
            tickets.generate(conn, days=1)
            self.assertEqual(run.call_count, 1)
            tickets.generate(conn, days=1)
            self.assertEqual(run.call_count, 1)  # same draft set, no second triage


class RejectedReportTests(unittest.TestCase):
    """Held, outdated builds produce a rejected report, never a vendor ticket."""

    def _conn(self):
        import sqlite3
        from sentinels import db

        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(db.SCHEMA)
        return conn

    def _held(self):
        row = {"package": "nvidia-settings", "installed": "610.43.02",
               "candidate": "615.71.10", "outdated": True}
        return {"held_total": 1, "held_installed": 1, "mass_hold": False,
                "owner": "nvidia-settings", "relevant": [row], "outdated": [row]}

    def _issue(self, key="k1", held=True):
        from sentinels.util import iso

        ts = iso()
        issue = {
            "key": key, "vendor": "nvidia",
            "signature": "nvidia-settings SIGABRT", "kind": "crash", "count": 3,
            "first": ts, "last": ts, "severity": "critical",
            "rows": [{
                "ts": ts, "pid": 7, "comm": "nvidia-settings",
                "exe": "/usr/bin/nvidia-settings", "sig": "SIGABRT",
                "cpus_allowed": "2,8", "core2_involved": 1, "context": "ctx",
                "boot_id": "bootA", "severity": "critical",
            }],
        }
        if held:
            issue["held"] = self._held()
        return issue

    def _draft(self, conn, root):
        path = root / "draft.md"
        path.write_text("# draft\n", encoding="utf-8")
        conn.execute(
            "INSERT INTO ticket_drafts(ts,vendor,path,title,issue_key)"
            " VALUES(datetime('now'),'nvidia',?,?,'k1')",
            (str(path), "nvidia-settings SIGABRT"),
        )

    def test_gate_flags_a_held_outdated_build(self):
        from sentinels import raise_ticket

        conn = self._conn()
        verdict = raise_ticket.assess(
            conn, {"issue_key": "k1", "vendor": "nvidia"}, self._issue()
        )
        self.assertFalse(verdict["viable"])
        self.assertTrue(verdict["hold_explained"])
        failed = [c["check"] for c in verdict["checks"] if not c["ok"]]
        self.assertIn("build-current", failed)
        self.assertIn("held-outdated", " ".join(verdict["reasons"]))

    def test_held_outdated_crash_is_filed_under_rejected(self):
        import json
        import pathlib
        import tempfile
        from unittest import mock
        from sentinels import config, raise_ticket

        conn = self._conn()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self._draft(conn, root)
            raised, rejected = root / "raise", root / "rejected"
            with mock.patch.object(config, "RAISE_DIR", raised), \
                 mock.patch.object(config, "STANDBY_DIR", root / "standby"), \
                 mock.patch.object(config, "REJECT_DIR", rejected), \
                 mock.patch.object(raise_ticket.tickets, "collect_issues",
                                   return_value=[self._issue()]), \
                 mock.patch.object(raise_ticket.report, "append_journal"):
                result = raise_ticket.run(conn, notify_ready=False)
            self.assertEqual(result["viable"], 0, result)
            self.assertEqual(len(result["rejected_staged"]), 1, result)
            directory = pathlib.Path(result["rejected_staged"][0])
            self.assertEqual(directory.parent, rejected)
            self.assertTrue((directory / "ticket.md").exists())
            self.assertTrue((directory / "evidence" / "manifest.json").exists())
            note = (directory / "REJECTED.md").read_text()
            self.assertIn("held-outdated", note)
            self.assertIn("nvidia-settings", note)
            manifest = json.loads((directory / "evidence" / "manifest.json").read_text())
            self.assertEqual(manifest["bucket"], "rejected")
            index = (rejected / "INDEX.md").read_text()
            self.assertIn(directory.name, index)
            self.assertIn("held-outdated", index)

    def test_rejected_report_returns_to_raise_when_build_is_current(self):
        import json
        import pathlib
        import tempfile
        from unittest import mock
        from sentinels import config, raise_ticket

        conn = self._conn()
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self._draft(conn, root)
            raised, rejected = root / "raise", root / "rejected"
            with mock.patch.object(config, "RAISE_DIR", raised), \
                 mock.patch.object(config, "STANDBY_DIR", root / "standby"), \
                 mock.patch.object(config, "REJECT_DIR", rejected), \
                 mock.patch.object(raise_ticket.report, "append_journal"), \
                 mock.patch.object(raise_ticket.tickets, "collect_issues",
                                   side_effect=[[self._issue()],
                                                [self._issue(held=False)]]):
                first = raise_ticket.run(conn, notify_ready=False)
                self.assertEqual(first["viable"], 0)
                name = pathlib.Path(first["rejected_staged"][0]).name
                second = raise_ticket.run(conn, notify_ready=False)
            self.assertEqual(second["viable"], 1, second)
            self.assertTrue((raised / name / "ticket.md").exists())
            self.assertFalse((rejected / name).exists())
            self.assertIn(name, second["reactivated"])
            events = [
                json.loads(line)["event"]
                for line in (raised / name / "evidence" / "rejected.jsonl")
                .read_text().splitlines() if line.strip()
            ]
            self.assertEqual(events, ["rejected", "cleared"])

    def test_held_context_only_resolves_absolute_crash_paths(self):
        from unittest import mock
        from sentinels import tickets

        self.assertEqual(tickets.held_context(self._issue(held=False) | {"kind": "event"}), {})
        relative = self._issue(held=False)
        relative["rows"][0]["exe"] = "nvidia-settings"
        self.assertEqual(tickets.held_context(relative), {})
        absolute = self._issue(held=False)
        with mock.patch.object(tickets.holds, "relevant", return_value={"outdated": [1]}) as rel:
            self.assertEqual(tickets.held_context(absolute), {"outdated": [1]})
        rel.assert_called_once_with("/usr/bin/nvidia-settings")


class NotificationTraceCrosscheckTests(unittest.TestCase):
    """The parts that decide whether a human is ever told, and whether the
    record can still be defended later."""

    def _conn(self):
        import sqlite3
        from sentinels import db

        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(db.SCHEMA)
        return conn

    def test_notification_queue_dedupes_per_key(self):
        from sentinels import notify

        conn = self._conn()
        self.assertTrue(notify.enqueue(conn, "draft", "draft|k1", "t", "b"))
        self.assertFalse(notify.enqueue(conn, "draft", "draft|k1", "t", "b"))
        self.assertEqual(notify.pending_count(conn), 1)

    def test_drain_marks_delivered_only_on_success(self):
        from unittest import mock
        from sentinels import notify

        conn = self._conn()
        notify.enqueue(conn, "draft", "k1", "t", "b")
        with mock.patch.object(notify, "send", return_value=(False, "no session")):
            result = notify.drain(conn)
        self.assertEqual(result["sent"], 0)
        self.assertEqual(notify.pending_count(conn), 1)
        # the failure sets a backoff; move the clock past it to retry
        from datetime import timedelta
        from sentinels.util import iso, utcnow

        conn.execute(
            "UPDATE notifications SET last_attempt=?",
            (iso(utcnow() - timedelta(seconds=notify._backoff_seconds(1) + 1)),),
        )
        with mock.patch.object(notify, "send", return_value=(True, "sent")):
            result = notify.drain(conn)
        self.assertEqual(result["sent"], 1)
        self.assertEqual(notify.pending_count(conn), 0)

    def test_drafts_are_batched_into_one_digest(self):
        from sentinels import notify

        conn = self._conn()
        for i, vendor in enumerate(("nvidia", "canonical-kernel", "nvidia")):
            conn.execute(
                "INSERT INTO ticket_drafts(ts,vendor,path,title,issue_key)"
                " VALUES(datetime('now'),?,?,?,?)",
                (vendor, f"/tmp/d{i}.md", f"title {i}", f"key{i}"),
            )
        import pathlib
        import tempfile
        from unittest import mock
        from sentinels import config

        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(config, "DRAFT_DIR", pathlib.Path(tmp)):
                notify.collect(conn)
                self.assertEqual(notify.pending_count(conn), 1)
                notify.collect(conn)  # identical draft set must not re-notify
                self.assertEqual(notify.pending_count(conn), 1)
                row = notify.pending(conn)[0]
                self.assertTrue(row["path"].endswith("INDEX.md"))
                self.assertTrue(pathlib.Path(row["path"]).exists())

    def test_click_opens_the_markdown_it_refers_to(self):
        import pathlib
        import tempfile
        from unittest import mock
        from sentinels import notify

        with tempfile.TemporaryDirectory() as tmp:
            target = pathlib.Path(tmp) / "draft.md"
            target.write_text("# draft\n")
            with mock.patch.object(notify.subprocess, "Popen") as popen:
                ok, detail = notify.open_target(str(target))
            self.assertTrue(ok)
            argv = popen.call_args.args[0]
            self.assertIn("xdg-open", argv[0])
            self.assertEqual(argv[-1], str(target))

    def test_send_uses_click_helper_only_when_a_path_is_given(self):
        from unittest import mock
        from sentinels import notify

        with mock.patch.object(notify, "available", return_value=(True, "ok")), \
             mock.patch.object(notify, "_gi_available", return_value=True), \
             mock.patch.object(notify, "_graphical_session", return_value=True), \
             mock.patch.object(notify, "_spawn_click_helper", return_value=True) as spawn, \
             mock.patch.object(notify, "_plain_send", return_value=(True, "sent")) as plain:
            ok, _ = notify.send("t", "b", path="/tmp/x.md")
            self.assertTrue(ok)
            spawn.assert_called_once()
            plain.assert_not_called()
            ok, _ = notify.send("t", "b")
            self.assertTrue(ok)
            plain.assert_called_once()

    def test_draft_regeneration_keeps_the_index_page(self):
        import pathlib
        import tempfile
        from unittest import mock
        from sentinels import config, tickets

        with tempfile.TemporaryDirectory() as tmp:
            d = pathlib.Path(tmp)
            (d / "INDEX.md").write_text("# index\n")
            stale = d / "stale-draft.md"
            stale.write_text("old\n")
            with mock.patch.object(config, "DRAFT_DIR", d), \
                 mock.patch.object(config, "MAX_TICKETS", 10), \
                 mock.patch.object(tickets, "collect_issues", return_value=[]):
                conn = self._conn()
                tickets.generate(conn, days=1)
            self.assertTrue((d / "INDEX.md").exists())
            self.assertFalse(stale.exists())

    def test_correlation_report_is_written_as_markdown(self):
        import pathlib
        import tempfile
        from unittest import mock
        from sentinels import config, notify

        cluster = {
            "key": "abc123", "vendor": "nvidia", "signature": "NVRM: Xid 79",
            "boots": 2, "total_unclean": 3, "occurrences": 5, "crashes": 1,
            "score": 11, "threshold": 9, "ready": True,
        }
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(config, "REPORT_DIR", pathlib.Path(tmp)):
                path = notify._correlation_report(self._conn(), cluster)
            self.assertTrue(path.endswith("correlation-abc123.md"))
            text = pathlib.Path(path).read_text()
            self.assertIn("NVRM: Xid 79", text)
            self.assertIn("Attribution is inferred", text)

    def test_missing_markdown_is_reported_not_invented(self):
        from sentinels import notify

        ok, detail = notify.open_target("/tmp/definitely-not-here-qa.md")
        self.assertFalse(ok)
        self.assertIn("missing target", detail)

    def test_trace_finds_event_boot_and_draft_by_one_query(self):
        from sentinels import trace

        conn = self._conn()
        conn.execute(
            "INSERT INTO boots(boot_id,seq,span,last_ts,ended_clean,markers,last_message,"
            "scans,pstore,kexec_loaded,crashkernel,vmcores,captured_ts)"
            " VALUES('bootrace',-1,'s','2026-11-03T08:33:14Z',0,'','end','{}','[]',0,'',0,'x')"
        )
        conn.execute(
            "INSERT INTO events(ts,boot_id,source,severity,unit,pid,comm,message,"
            "fingerprint,raw,count,last_ts) VALUES('2026-11-03T08:33:00Z','bootrace',"
            "'journal','critical','kernel',1,'k','NVRM: Xid 79 bootrace','fp-race','{}',2,"
            "'2026-11-03T08:33:00Z')"
        )
        record = trace.resolve(conn, "bootrace")
        self.assertTrue(record["events"])
        self.assertTrue(record["boots"])
        rendered = "\n".join(trace.render(conn, "bootrace"))
        self.assertIn("Silent stops", rendered)
        self.assertIn("Events sharing the signature", rendered)

    def test_trace_reports_absence_instead_of_inventing(self):
        from sentinels import trace

        conn = self._conn()
        self.assertEqual(trace.render(conn, "nothing-here"), ["nothing recorded for 'nothing-here'"])

    def test_crosscheck_flags_a_draft_the_evidence_no_longer_backs(self):
        from unittest import mock
        from sentinels import crosscheck

        conn = self._conn()
        conn.execute(
            "INSERT INTO ticket_drafts(ts,vendor,path,title,issue_key)"
            " VALUES('2026-11-03T00:00:00Z','nvidia','/tmp/x.md','gone','deadbeef')"
        )
        with mock.patch.object(crosscheck.report, "append_journal"):
            result = crosscheck.run(conn, days=30, notify_drift=False)
        self.assertIn("deadbeef", result["stale_drafts"])
        self.assertGreater(result["drift"], 0)

    def test_crosscheck_flags_reproducible_issue_without_draft(self):
        from unittest import mock
        from sentinels import crosscheck

        conn = self._conn()
        conn.execute(
            "INSERT INTO events(ts,boot_id,source,severity,unit,pid,comm,message,"
            "fingerprint,raw,count,last_ts) VALUES(datetime('now'),'b','journal',"
            "'critical','kernel',1,'k','NVRM: Xid (PCI:0000:01:00): 79','fp-cc','{}',3,"
            "datetime('now'))"
        )
        with mock.patch.object(crosscheck.report, "append_journal"):
            result = crosscheck.run(conn, days=30, notify_drift=False)
        self.assertTrue(result["unraised_issues"])

    def test_log_line_gets_timestamp_and_severity_colour(self):
        from sentinels import logs

        plain = logs.format_line("boots: 1 unclean", color=False, stamp="12:00:00")
        self.assertTrue(plain.startswith("[12:00:00]"))
        coloured = logs.format_line("kernel panic - not syncing", color=True, stamp="12:00:00")
        self.assertIn(logs.COLORS["critical"], coloured)
        self.assertEqual(logs.classify_line("Kernel panic"), "critical")
        self.assertEqual(logs.classify_line("service failed to start"), "error")
        self.assertEqual(logs.classify_line("warning: retry"), "warning")

    def test_colour_is_optional_for_pipes(self):
        import os
        from sentinels import logs

        class FakeTTY:
            def isatty(self):
                return True

        saved = os.environ.pop("NO_COLOR", None)
        try:
            self.assertTrue(logs.supports_color(stream=FakeTTY()))
            os.environ["NO_COLOR"] = "1"
            self.assertFalse(logs.supports_color(stream=FakeTTY()))
        finally:
            os.environ.pop("NO_COLOR", None)
            if saved is not None:
                os.environ["NO_COLOR"] = saved


if __name__ == "__main__":
    unittest.main()
