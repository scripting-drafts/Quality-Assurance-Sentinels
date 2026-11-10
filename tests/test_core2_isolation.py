"""Tests for core-2 isolation policy and faultlab verdict ingestion."""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from sentinels import config, core2

CMDLINE = ("BOOT_IMAGE=/vmlinuz ro quiet "
           "isolcpus=managed_irq,2,8 nohz_full=2,8 rcu_nocbs=2,8 "
           "irqaffinity=0-1,3-7,9-11")


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT)")
    return conn


def _env(root: Path, mode: str, *, online=(2, 8), params=CMDLINE,
         system="0-1,3-7,9-11", user="0-1,3-7,9-11", lab="2,8",
         irq_mask="0-1,3-7,9-11"):
    cpu = root / "cpu"
    for number in range(12):
        core_id = 2 if number in (2, 8) else number
        _write(cpu / f"cpu{number}" / "topology" / "core_id", str(core_id))
        _write(cpu / f"cpu{number}" / "topology" / "physical_package_id", "0")
        state = "1"
        if number in (2, 8) and number not in online:
            state = "0"
        _write(cpu / f"cpu{number}" / "online", state)
    isolated = "2,8" if "isolcpus" in params else ""
    nohz = "2,8" if "nohz_full" in params else ""
    _write(cpu / "isolated", isolated)
    _write(cpu / "nohz_full", nohz)

    cgroup = root / "cgroup"
    _write(cgroup / "system.slice" / "cpuset.cpus", system)
    _write(cgroup / "user.slice" / "cpuset.cpus", user)
    _write(cgroup / "faultlab.slice" / "cpuset.cpus", lab)

    _write(root / "irq" / "24" / "smp_affinity_list", irq_mask)
    _write(root / "cmdline", params)
    _write(root / "mode", mode)
    return {
        "cpu_root": cpu,
        "cgroup_root": cgroup,
        "cmdline_path": root / "cmdline",
        "mode_path": root / "mode",
        "irq_root": root / "irq",
        "ab_path": root / "ab.jsonl",
    }


class CpuListTests(unittest.TestCase):
    def test_ranges_and_flags(self):
        self.assertEqual(core2.parse_cpu_list("0-1,3,8-9"), {0, 1, 3, 8, 9})
        self.assertEqual(core2.parse_cpu_list("managed_irq,2,8"), {2, 8})
        self.assertEqual(core2.parse_cpu_list("(null)"), set())


class IsolationFindingTests(unittest.TestCase):
    def test_retired_offline_is_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = _env(Path(tmp), "retired", online=())
            self.assertEqual(core2.findings(_conn(), **paths), [])

    def test_retired_online_is_critical(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = _env(Path(tmp), "retired")
            found = core2.findings(_conn(), **paths)
        rules = {(f["rule"], f["severity"]) for f in found}
        self.assertIn(("core2.retired.online", "critical"), rules)

    def test_lab_unfenced_slice_is_critical(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = _env(Path(tmp), "lab", system="0-11")
            found = core2.findings(_conn(), **paths)
        rules = {f["rule"] for f in found}
        self.assertIn("core2.isolation.unfenced", rules)

    def test_lab_fenced_is_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = _env(Path(tmp), "lab")
            self.assertEqual(core2.findings(_conn(), **paths), [])

    def test_lab_missing_params_warns(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = _env(Path(tmp), "lab", params="quiet splash")
            found = core2.findings(_conn(), **paths)
        rules = {f["rule"] for f in found}
        self.assertIn("core2.isolation.missing", rules)

    def test_lab_irq_affinity_warns(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = _env(Path(tmp), "lab", irq_mask="0-11")
            found = core2.findings(_conn(), **paths)
        rules = {f["rule"] for f in found}
        self.assertIn("core2.irq.affinity", rules)

    def test_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = _env(Path(tmp), "retired")
            old = config.CORE2_ENABLE
            config.CORE2_ENABLE = False
            try:
                self.assertEqual(core2.findings(_conn(), **paths), [])
            finally:
                config.CORE2_ENABLE = old


class AbVerdictTests(unittest.TestCase):
    def _record(self, verdict: str) -> str:
        return json.dumps({
            "schema": "faultlab.ab/1",
            "ts": "2026-11-10T12:00:00Z",
            "verdict": verdict,
            "exit": 2,
            "runs": 3,
            "command": "python3 tools/sdc_probe.py",
            "mode": "lab",
        })

    def test_divergence_is_ingested_once(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = _env(Path(tmp), "retired", online=())
            Path(paths["ab_path"]).write_text(self._record("DIVERGENCE") + "\n")
            conn = _conn()
            first = core2.findings(conn, **paths)
            second = core2.findings(conn, **paths)
        self.assertEqual([f["rule"] for f in first], ["core2.ab.divergence"])
        self.assertEqual(first[0]["severity"], "critical")
        self.assertEqual(second, [])

    def test_pass_verdict_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = _env(Path(tmp), "retired", online=())
            Path(paths["ab_path"]).write_text(self._record("PASS") + "\n")
            self.assertEqual(core2.findings(_conn(), **paths), [])

    def test_cursor_resets_after_truncation(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = _env(Path(tmp), "retired", online=())
            ab = Path(paths["ab_path"])
            ab.write_text(self._record("DIVERGENCE") + "\n")
            conn = _conn()
            core2.findings(conn, **paths)
            ab.write_text(self._record("HW-SUSPECT") + "\n")
            found = core2.findings(conn, **paths)
        self.assertEqual([f["rule"] for f in found], ["core2.ab.hw_suspect"])


class EventRuleTests(unittest.TestCase):
    def test_core2_mce_rule_removed_but_kernel_rule_covers_mce(self):
        from sentinels import detect
        rules = {rule[0] for rule in detect.EVENT_RULES}
        self.assertNotIn("core2.mce", rules)
        self.assertIn("kernel.hardware", rules)


if __name__ == "__main__":
    unittest.main()
