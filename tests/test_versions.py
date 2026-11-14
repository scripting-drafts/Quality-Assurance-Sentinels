"""Tests for installed-software version reporting in ticket drafts."""
import unittest
from unittest import mock

from sentinels import tickets


class SoftwareVersionTests(unittest.TestCase):
    def _issue(self, context_version="Firefox ESR 140.17.0, build 20260922124338"):
        return {
            "key": "moz", "vendor": "mozilla",
            "signature": "firefox-esr SIGSEGV",
            "display": "firefox-esr SIGSEGV",
            "kind": "crash", "count": 1, "severity": "critical",
            "first": "2026-10-26T09:08:36Z", "last": "2026-10-26T09:08:36Z",
            "rows": [{
                "ts": "2026-10-26T09:08:36Z", "comm": "firefox-esr",
                "exe": "/usr/lib/firefox-esr/firefox-bin",
                "sig": "SIGSEGV",
                "context": f"Crash report\nVersion: {context_version}\n",
            }],
            "held": {},
        }

    def test_installed_version_and_crash_context_are_distinguished(self):
        owner = {"package": "firefox-esr", "version": "153.6.0esr~build2"}
        topo = {"present": True, "logical": [2, 8], "physical_cores": 6,
                "logical_cpus": 12, "physical_id": 2}
        with mock.patch.object(tickets.packages, "owner", return_value=owner), \
             mock.patch.object(tickets.faultcore, "topology", return_value=topo):
            title, body = tickets._draft(self._issue(), None, {}, False)
        self.assertIn("[firefox-esr 153.6.0esr~build2]", title)
        self.assertIn("- Software: `firefox-esr` 153.6.0esr~build2", body)
        self.assertIn("Version note", body)
        self.assertIn("140.17.0", body)
        self.assertIn("153.6.0esr~build2", body)
        self.assertIn("Use the installed version", body)

    def test_no_note_when_crash_context_matches_installed(self):
        owner = {"package": "firefox-esr", "version": "153.6.0esr~build2"}
        topo = {"present": True, "logical": [2, 8], "physical_cores": 6,
                "logical_cpus": 12, "physical_id": 2}
        with mock.patch.object(tickets.packages, "owner", return_value=owner), \
             mock.patch.object(tickets.faultcore, "topology", return_value=topo):
            _, body = tickets._draft(
                self._issue("Firefox ESR 153.6.0esr~build2"), None, {}, False
            )
        self.assertNotIn("Version note", body)


if __name__ == "__main__":
    unittest.main()
