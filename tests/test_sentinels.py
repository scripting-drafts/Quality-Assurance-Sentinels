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


class PhaseTests(unittest.TestCase):
    def _conn(self):
        import sqlite3
        from sentinels import db

        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(db.SCHEMA)
        return conn

    def test_phase1_rules_find_crash_event_and_resource_pressure(self):
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

    def test_phase1_dedupes_repeated_findings(self):
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

    def test_phase2_reports_privilege_honestly(self):
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


if __name__ == "__main__":
    unittest.main()
