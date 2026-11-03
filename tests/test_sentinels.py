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


class BootBoundaryTests(unittest.TestCase):
    """A boot verdict decides whether a crash is even investigable."""

    def _conn(self):
        import sqlite3
        from sentinels import db

        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(db.SCHEMA)
        return conn

    def _boot(self, conn, boot_id="b1", clean=0, ts="2026-11-03T09:33:14Z"):
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
            with mock.patch.object(config, "RAISE_DIR", raised), \
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
            self.assertEqual(manifest["viability"]["score"], 5)

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
            standby = root / "tickets" / "in-standby"
            marker = raised / "nvidia-old-deadbeef" / "KEEP.txt"
            marker.parent.mkdir(parents=True)
            marker.write_text("staged earlier\n")
            with mock.patch.object(config, "RAISE_DIR", raised), \
                 mock.patch.object(config, "STANDBY_DIR", standby), \
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
            issue = self._issue()
            with mock.patch.object(config, "RAISE_DIR", raised), \
                 mock.patch.object(config, "STANDBY_DIR", standby), \
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
