"""Tests for fault-core isolation policy and faultlab verdict ingestion."""
import json
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sentinels import config, faultcore


def _csv(values) -> str:
    return ",".join(str(value) for value in sorted(values))


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


def _conn():
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT)")
    return conn


def _env(root: Path, mode: str, *, cpus=(2, 8), physical_id=2, online=None,
         params=None, system=None, user=None, lab=None, irq_mask=None):
    cpus = tuple(cpus)
    if online is None:
        online = cpus
    safe = [number for number in range(12) if number not in cpus]
    if params is None:
        params = (
            f"BOOT_IMAGE=/vmlinuz ro quiet isolcpus=managed_irq,{_csv(cpus)} "
            f"nohz_full={_csv(cpus)} rcu_nocbs={_csv(cpus)} "
            f"irqaffinity={_csv(safe)}"
        )
    if system is None:
        system = _csv(safe)
    if user is None:
        user = _csv(safe)
    if lab is None:
        lab = _csv(cpus)
    if irq_mask is None:
        irq_mask = _csv(safe)

    cpu = root / "cpu"
    for number in range(12):
        state = "1"
        if number in cpus and number not in online:
            state = "0"
        else:
            core_id = physical_id if number in cpus else 100 + number
            _write(cpu / f"cpu{number}" / "topology" / "core_id", str(core_id))
            _write(cpu / f"cpu{number}" / "topology" / "physical_package_id", "0")
        _write(cpu / f"cpu{number}" / "online", state)
    isolated = _csv(cpus) if "isolcpus" in params else ""
    nohz = _csv(cpus) if "nohz_full" in params else ""
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
        self.assertEqual(faultcore.parse_cpu_list("0-1,3,8-9"), {0, 1, 3, 8, 9})
        self.assertEqual(faultcore.parse_cpu_list("managed_irq,2,8"), {2, 8})
        self.assertEqual(faultcore.parse_cpu_list("(null)"), set())


class IsolationFindingTests(unittest.TestCase):
    def setUp(self):
        self._cpus = mock.patch.object(config, "FAULT_CORE_CPUS", (2, 8))
        self._cpus.start()
        self._enable = mock.patch.object(config, "FAULT_CORE_ENABLE", True)
        self._enable.start()

    def tearDown(self):
        self._enable.stop()
        self._cpus.stop()

    def test_retired_offline_is_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = _env(Path(tmp), "retired", online=())
            self.assertEqual(faultcore.findings(_conn(), **paths), [])

    def test_retired_other_core_is_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = _env(Path(tmp), "retired", cpus=(3, 9), physical_id=4,
                         online=())
            with mock.patch.object(config, "FAULT_CORE_CPUS", (3, 9)):
                self.assertEqual(faultcore.findings(_conn(), **paths), [])

    def test_lab_other_core_fenced_is_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = _env(Path(tmp), "lab", cpus=(3, 9), physical_id=4)
            with mock.patch.object(config, "FAULT_CORE_CPUS", (3, 9)):
                self.assertEqual(faultcore.findings(_conn(), **paths), [])

    def test_retired_online_is_critical(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = _env(Path(tmp), "retired")
            found = faultcore.findings(_conn(), **paths)
        rules = {(f["rule"], f["severity"]) for f in found}
        self.assertIn(("faultcore.retired.online", "critical"), rules)

    def test_lab_unfenced_slice_is_critical(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = _env(Path(tmp), "lab", system="0-11")
            found = faultcore.findings(_conn(), **paths)
        rules = {f["rule"] for f in found}
        self.assertIn("faultcore.isolation.unfenced", rules)

    def test_lab_fenced_is_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = _env(Path(tmp), "lab")
            self.assertEqual(faultcore.findings(_conn(), **paths), [])

    def test_lab_missing_params_warns(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = _env(Path(tmp), "lab", params="quiet splash")
            found = faultcore.findings(_conn(), **paths)
        rules = {f["rule"] for f in found}
        self.assertIn("faultcore.isolation.missing", rules)

    def test_lab_irq_affinity_warns(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = _env(Path(tmp), "lab", irq_mask="0-11")
            found = faultcore.findings(_conn(), **paths)
        rules = {f["rule"] for f in found}
        self.assertIn("faultcore.irq.affinity", rules)

    def test_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = _env(Path(tmp), "retired")
            old = config.FAULT_CORE_ENABLE
            config.FAULT_CORE_ENABLE = False
            try:
                self.assertEqual(faultcore.findings(_conn(), **paths), [])
            finally:
                config.FAULT_CORE_ENABLE = old


class AbVerdictTests(unittest.TestCase):
    def setUp(self):
        self._cpus = mock.patch.object(config, "FAULT_CORE_CPUS", (2, 8))
        self._cpus.start()
        self._enable = mock.patch.object(config, "FAULT_CORE_ENABLE", True)
        self._enable.start()

    def tearDown(self):
        self._enable.stop()
        self._cpus.stop()

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
            first = faultcore.findings(conn, **paths)
            second = faultcore.findings(conn, **paths)
        self.assertEqual([f["rule"] for f in first], ["faultcore.ab.divergence"])
        self.assertEqual(first[0]["severity"], "critical")
        self.assertEqual(second, [])

    def test_pass_verdict_is_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = _env(Path(tmp), "retired", online=())
            Path(paths["ab_path"]).write_text(self._record("PASS") + "\n")
            self.assertEqual(faultcore.findings(_conn(), **paths), [])

    def test_cursor_resets_after_truncation(self):
        with tempfile.TemporaryDirectory() as tmp:
            paths = _env(Path(tmp), "retired", online=())
            ab = Path(paths["ab_path"])
            ab.write_text(self._record("DIVERGENCE") + "\n")
            conn = _conn()
            faultcore.findings(conn, **paths)
            ab.write_text(self._record("HW-SUSPECT") + "\n")
            found = faultcore.findings(conn, **paths)
        self.assertEqual([f["rule"] for f in found], ["faultcore.ab.hw_suspect"])


class EventRuleTests(unittest.TestCase):
    def test_faultcore_mce_rule_removed_but_kernel_rule_covers_mce(self):
        from sentinels import detect
        rules = {rule[0] for rule in detect.EVENT_RULES}
        self.assertNotIn("faultcore.mce", rules)
        self.assertIn("kernel.hardware", rules)


if __name__ == "__main__":
    unittest.main()
