"""Tests for physical-core topology and ticket presence reporting."""
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from sentinels import core2, tickets


class TopologyTests(unittest.TestCase):
    def _cpu(self, root: Path, number: int, core: int, package: int = 0):
        path = root / f"cpu{number}" / "topology"
        path.mkdir(parents=True)
        (path / "core_id").write_text(str(core))
        (path / "physical_package_id").write_text(str(package))

    def test_core2_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._cpu(root, 0, 0)
            self._cpu(root, 1, 1)
            self._cpu(root, 2, 2)
            self._cpu(root, 8, 2)
            self._cpu(root, 3, 3)
            topo = core2.topology(root)
        self.assertTrue(topo["present"])
        self.assertEqual(topo["logical"], [2, 8])
        self.assertEqual(topo["physical_cores"], 4)
        self.assertEqual(topo["logical_cpus"], 5)

    def test_core2_absent(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._cpu(root, 0, 0)
            self._cpu(root, 1, 1)
            self._cpu(root, 3, 3)
            topo = core2.topology(root)
        self.assertFalse(topo["present"])
        self.assertEqual(topo["logical"], [])

    def test_topology_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            topo = core2.topology(Path(tmp))
        self.assertIsNone(topo["present"])

    def test_labels(self):
        present = {"present": True, "logical": [2, 8], "physical_cores": 6,
                   "logical_cpus": 12, "physical_id": 2}
        absent = {"present": False, "logical": [], "physical_cores": 4,
                  "logical_cpus": 8, "physical_id": 2}
        unknown = {"present": None, "logical": [], "physical_id": 2}
        self.assertIn("present", core2.presence(present))
        self.assertIn("absent", core2.presence(absent))
        self.assertIn("unknown", core2.presence(unknown))
        self.assertEqual(core2.theme_tag(present), "physical core 2 present")
        self.assertEqual(core2.theme_tag(absent), "physical core 2 absent")
        self.assertEqual(core2.theme_tag(unknown), "physical core 2 unknown")


class TicketThemeTests(unittest.TestCase):
    def _issue(self):
        return {
            "key": "core2", "vendor": "hardware",
            "signature": "crashes correlated with physical core 2 affinity",
            "display": "crashes correlated with physical core 2 affinity",
            "kind": "correlation", "count": 1, "severity": "critical",
            "first": "2026-11-07T00:00:00Z", "last": "2026-11-07T00:00:00Z",
            "rows": [{
                "ts": "2026-11-07T00:00:00Z", "comm": "firefox-esr",
                "sig": "SIGSEGV", "cpus_allowed": "2,8", "core2_involved": 1,
            }],
        }

    def _present(self):
        return {"present": True, "logical": [2, 8], "physical_cores": 6,
                "logical_cpus": 12, "physical_id": 2}

    def _absent(self):
        return {"present": False, "logical": [], "physical_cores": 4,
                "logical_cpus": 8, "physical_id": 2}

    def _unknown(self):
        return {"present": None, "logical": [], "physical_id": 2}

    def test_title_and_environment_state_presence(self):
        with mock.patch.object(tickets.core2, "topology", return_value=self._present()):
            title, body = tickets._draft(self._issue(), None, {}, False)
        self.assertIn("[physical core 2 present]", title)
        self.assertIn("- Physical core 2: present", body)
        self.assertIn("## Physical core 2 correlation — present", body)
        self.assertIn("`2,8`", body)

    def test_title_and_environment_state_absence(self):
        with mock.patch.object(tickets.core2, "topology", return_value=self._absent()):
            title, body = tickets._draft(self._issue(), None, {}, False)
        self.assertIn("[physical core 2 absent]", title)
        self.assertIn("- Physical core 2: absent", body)
        self.assertIn("## Physical core 2 correlation — absent", body)
        self.assertIn("record the absence", body)

    def test_title_and_environment_state_unknown(self):
        with mock.patch.object(tickets.core2, "topology", return_value=self._unknown()):
            title, body = tickets._draft(self._issue(), None, {}, False)
        self.assertIn("[physical core 2 unknown]", title)
        self.assertIn("- Physical core 2: unknown", body)


if __name__ == "__main__":
    unittest.main()
