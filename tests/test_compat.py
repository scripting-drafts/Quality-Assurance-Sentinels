"""Tests for Ubuntu upgrade compatibility reporting."""
import unittest

from sentinels import compat


class CompatTests(unittest.TestCase):
    def test_supported_matrix(self):
        for version in ("22.04", "24.04", "24.10", "25.04", "25.10", "26.04", "26.10"):
            result = compat.evaluate(
                "ubuntu", version, "3.10.12", "3.37.2", "249", "6.8.0"
            )
            self.assertTrue(result["supported"], version)

    def test_old_or_unlisted_release_is_unsupported(self):
        for version in ("20.04", "23.04", "27.04"):
            result = compat.evaluate(
                "ubuntu", version, "3.10.12", "3.37.2", "249", "6.8.0"
            )
            self.assertFalse(result["supported"], version)

    def test_component_minimums(self):
        result = compat.evaluate(
            "ubuntu", "22.04", "3.9.0", "3.36.0", "248", "5.14.0"
        )
        self.assertFalse(result["supported"])
        failed = {check["name"] for check in result["checks"] if not check["ok"]}
        self.assertEqual(
            failed,
            {"Python >= 3.10", "SQLite >= 3.37", "systemd >= 249", "kernel >= 5.15"},
        )

    def test_current_host_is_supported(self):
        self.assertTrue(compat.report()["supported"])


if __name__ == "__main__":
    unittest.main()
