"""Tests for fault-core topology and ticket presence reporting."""
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sentinels import config, faultcore, tickets


class ConfigParsingTests(unittest.TestCase):
    def test_faultlab_config_is_parsed_as_data(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config"
            path.write_text(
                "# generated\n"
                "FAULT_CPU=3\n"
                "FAULT_CPUS=3,9\n"
                "CONTROL_CPUS=1-2,7\n"
                "IGNORED='quoted'\n"
            )
            values = config._faultlab_values(path)
        self.assertEqual(values["FAULT_CPU"], "3")
        self.assertEqual(values["FAULT_CPUS"], "3,9")
        self.assertEqual(values["IGNORED"], "quoted")

    def test_cpu_tuple_accepts_ranges(self):
        self.assertEqual(config._cpu_tuple("0-1,3,8-9"), (0, 1, 3, 8, 9))


class TopologyTests(unittest.TestCase):
    def setUp(self):
        self._cpus = mock.patch.object(config, "FAULT_CORE_CPUS", (2, 8))
        self._cpus.start()
        self._physical = mock.patch.object(config, "FAULT_CORE_PHYSICAL_ID", None)
        self._physical.start()
        self._enforce = mock.patch.object(config, "FAULT_CORE_ENFORCE", "auto")
        self._enforce.start()

    def tearDown(self):
        self._enforce.stop()
        self._physical.stop()
        self._cpus.stop()

    def _cpu(self, root: Path, number: int, core: int, package: int = 0,
             siblings: str | None = None):
        path = root / f"cpu{number}" / "topology"
        path.mkdir(parents=True)
        (path / "core_id").write_text(str(core))
        (path / "physical_package_id").write_text(str(package))
        if siblings is not None:
            (path / "thread_siblings_list").write_text(siblings)

    def _offline(self, root: Path, number: int):
        path = root / f"cpu{number}"
        path.mkdir(parents=True)
        (path / "online").write_text("0")

    def _mode(self, root: Path, mode: str) -> Path:
        path = root / "mode"
        path.write_text(mode)
        return path

    def test_faultcore_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._cpu(root, 0, 0)
            self._cpu(root, 1, 1)
            self._cpu(root, 2, 2, siblings="2,8")
            self._cpu(root, 8, 2, siblings="2,8")
            self._cpu(root, 3, 3)
            topo = faultcore.topology(root)
        self.assertTrue(topo["present"])
        self.assertEqual(topo["state"], "present")
        self.assertEqual(topo["logical"], [2, 8])
        self.assertEqual(topo["physical_id"], 2)
        self.assertEqual(topo["physical_cores"], 4)
        self.assertEqual(topo["logical_cpus"], 5)

    def test_faultcore_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._cpu(root, 0, 0)
            self._cpu(root, 1, 1)
            self._cpu(root, 3, 3)
            topo = faultcore.topology(root)
        self.assertFalse(topo["present"])
        self.assertEqual(topo["state"], "absent")
        self.assertEqual(topo["logical"], [])

    def test_topology_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            topo = faultcore.topology(Path(tmp))
        self.assertIsNone(topo["present"])
        self.assertEqual(topo["state"], "unknown")

    def test_retired_core_is_undetermined(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._cpu(root, 0, 0)
            self._cpu(root, 1, 1)
            self._cpu(root, 3, 3)
            self._offline(root, 2)
            self._offline(root, 8)
            topo = faultcore.topology(root, mode_path=self._mode(root, "retired"))
        self.assertIsNone(topo["present"])
        self.assertEqual(topo["state"], "retired")
        self.assertIsNone(topo["physical_id"])
        self.assertEqual(topo["degraded"], [2, 8])
        self.assertEqual(topo["logical"], [])
        self.assertEqual(topo["source"], "faultlab-retired")

    def test_offline_core_outside_retired_mode_is_undetermined(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._cpu(root, 0, 0)
            self._cpu(root, 1, 1)
            self._offline(root, 2)
            self._offline(root, 8)
            topo = faultcore.topology(root, mode_path=self._mode(root, "lab"))
        self.assertIsNone(topo["present"])
        self.assertEqual(topo["state"], "offline")

    def test_partial_offline_core_uses_sibling_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._cpu(root, 0, 0)
            self._cpu(root, 1, 1)
            self._cpu(root, 8, 2, siblings="2,8")
            self._offline(root, 2)
            topo = faultcore.topology(root, mode_path=self._mode(root, "retired"))
        self.assertTrue(topo["present"])
        self.assertEqual(topo["state"], "present")
        self.assertEqual(topo["logical"], [2, 8])
        self.assertEqual(topo["physical_id"], 2)
        self.assertEqual(topo["degraded"], [2])

    def test_non_two_fault_core_is_derived_from_sysfs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._cpu(root, 0, 0)
            self._cpu(root, 1, 1)
            self._cpu(root, 3, 4, siblings="3,9")
            self._cpu(root, 9, 4, siblings="3,9")
            with mock.patch.object(config, "FAULT_CORE_CPUS", (3, 9)):
                topo = faultcore.topology(root, mode_path=self._mode(root, "lab"))
        self.assertTrue(topo["present"])
        self.assertEqual(topo["state"], "present")
        self.assertEqual(topo["physical_id"], 4)
        self.assertEqual(topo["logical"], [3, 9])

    def test_split_core_mapping_is_changed(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._cpu(root, 2, 2)
            self._cpu(root, 8, 3)
            topo = faultcore.topology(root, mode_path=self._mode(root, "lab"))
        self.assertTrue(topo["present"])
        self.assertEqual(topo["state"], "changed")
        self.assertIsNone(topo["physical_id"])
        self.assertEqual(topo["logical"], [2, 8])

    def test_unconfigured_core_is_disabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._cpu(root, 0, 0)
            with mock.patch.object(config, "FAULT_CORE_CPUS", ()):
                topo = faultcore.topology(root)
        self.assertIsNone(topo["present"])
        self.assertEqual(topo["state"], "unconfigured")
        self.assertEqual(topo["configured"], [])

    def test_labels(self):
        present = {"present": True, "state": "present", "logical": [2, 8],
                   "physical_cores": 6, "logical_cpus": 12, "physical_id": 2,
                   "configured": [2, 8]}
        absent = {"present": False, "state": "absent", "logical": [],
                  "physical_cores": 4, "logical_cpus": 8, "physical_id": None,
                  "configured": [2, 8]}
        unknown = {"present": None, "state": "unknown", "logical": [],
                   "physical_id": None, "configured": [2, 8]}
        retired = {"present": None, "state": "retired", "logical": [],
                   "physical_id": None, "configured": [2, 8]}
        self.assertIn("present", faultcore.presence(present))
        self.assertIn("absent", faultcore.presence(absent))
        self.assertIn("unknown", faultcore.presence(unknown))
        self.assertIn("retired", faultcore.presence(retired))
        self.assertIn("undetermined", faultcore.presence(retired))
        self.assertEqual(faultcore.theme_tag(present), "physical core 2 present")
        self.assertEqual(faultcore.theme_tag(absent), "fault core (CPUs 2,8) absent")
        self.assertIn("undetermined", faultcore.theme_tag(retired))


class EventMatchingTests(unittest.TestCase):
    def test_event_matching_uses_the_configured_core(self):
        from sentinels import triage

        with mock.patch.object(config, "FAULT_CORE_CPUS", (3, 9)), \
             mock.patch.object(config, "FAULT_CORE_PHYSICAL_ID", 4):
            self.assertTrue(triage.event_is_faultcore("CPU 3: Machine Check"))
            self.assertTrue(triage.event_is_faultcore("physical core 4 failed"))
            self.assertFalse(triage.event_is_faultcore("CPU 2: Machine Check"))


class TicketThemeTests(unittest.TestCase):
    def setUp(self):
        self._cpus = mock.patch.object(config, "FAULT_CORE_CPUS", (2, 8))
        self._cpus.start()

    def tearDown(self):
        self._cpus.stop()

    def _issue(self):
        return {
            "key": "faultcore", "vendor": "hardware",
            "signature": "crashes correlated with fault-core affinity",
            "display": "crashes correlated with fault-core affinity",
            "kind": "correlation", "count": 1, "severity": "critical",
            "first": "2026-11-07T00:00:00Z", "last": "2026-11-07T00:00:00Z",
            "rows": [{
                "ts": "2026-11-07T00:00:00Z", "comm": "firefox-esr",
                "sig": "SIGSEGV", "cpus_allowed": "2,8", "faultcore_involved": 1,
            }],
        }

    def _present(self):
        return {"present": True, "state": "present", "logical": [2, 8],
                "physical_cores": 6, "logical_cpus": 12, "physical_id": 2,
                "configured": [2, 8], "degraded": []}

    def _absent(self):
        return {"present": False, "state": "absent", "logical": [],
                "physical_cores": 4, "logical_cpus": 8, "physical_id": None,
                "configured": [2, 8], "degraded": []}

    def _retired(self):
        return {"present": None, "state": "retired", "logical": [],
                "physical_id": None, "configured": [2, 8], "degraded": [2, 8]}

    def test_title_and_environment_state_presence(self):
        with mock.patch.object(tickets.faultcore, "topology", return_value=self._present()):
            title, body = tickets._draft(self._issue(), None, {}, False)
        self.assertIn("[physical core 2 present]", title)
        self.assertIn("- Physical core 2: present", body)
        self.assertIn("## Physical core 2 correlation — present", body)
        self.assertIn("`2,8`", body)

    def test_title_and_environment_state_absence(self):
        with mock.patch.object(tickets.faultcore, "topology", return_value=self._absent()):
            title, body = tickets._draft(self._issue(), None, {}, False)
        self.assertIn("[fault core (CPUs 2,8) absent]", title)
        self.assertIn("- Fault core (CPUs 2,8): absent", body)
        self.assertIn("## Fault core (CPUs 2,8) correlation — absent", body)
        self.assertIn("fault-core comparison was absent", body)

    def test_title_and_environment_state_retired(self):
        with mock.patch.object(tickets.faultcore, "topology", return_value=self._retired()):
            title, body = tickets._draft(self._issue(), None, {}, False)
        self.assertIn("[fault core (CPUs 2,8) retired (undetermined)]", title)
        self.assertIn("- Fault core (CPUs 2,8): retired", body)
        self.assertIn("fault-core comparison was undetermined", body)


if __name__ == "__main__":
    unittest.main()
