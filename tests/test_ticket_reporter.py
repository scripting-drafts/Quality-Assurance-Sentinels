"""Tests for the ticket Reporter section."""
import unittest

from sentinels import tickets


class ReporterTests(unittest.TestCase):
    def test_consent_line_is_not_rendered(self):
        issue = {
            "key": "reporter", "vendor": "local",
            "signature": "reporter test", "display": "reporter test",
            "kind": "event", "count": 1, "severity": "warning",
            "first": "2026-11-08T00:00:00Z", "last": "2026-11-08T00:00:00Z",
            "rows": [],
        }
        identity = {
            "FULL_NAME": "Test Reporter",
            "LINKEDIN": "https://example.invalid/reporter",
            "GITHUB": "https://example.invalid/github",
        }
        _, body = tickets._draft(issue, None, identity, True)
        self.assertIn("## Reporter", body)
        self.assertIn("- Name: Test Reporter", body)
        self.assertNotIn("Consent:", body)


if __name__ == "__main__":
    unittest.main()
