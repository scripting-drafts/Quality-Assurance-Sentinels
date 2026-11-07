"""Tests for Linux Security Modules parsing and rules."""
import tempfile
import unittest
from pathlib import Path

from sentinels import lsm


class LsmParseTests(unittest.TestCase):
    def test_lsm_list(self):
        self.assertEqual(
            lsm.parse_lsm_list("lockdown,yama,integrity,apparmor"),
            ["lockdown", "yama", "integrity", "apparmor"],
        )

    def test_lockdown_selection(self):
        parsed = lsm.parse_lockdown("[none] integrity confidentiality")
        self.assertEqual(parsed["selected"], "none")
        self.assertIn("integrity", parsed["options"])

    def test_apparmor_profiles(self):
        text = "/usr/bin/firefox (enforce)\n/usr/bin/foo (complain)\n"
        parsed = lsm.parse_apparmor_profiles(text)
        self.assertEqual(parsed["total"], 2)
        self.assertEqual(parsed["enforce"], 1)
        self.assertEqual(parsed["complain"], 1)

    def test_denials(self):
        parsed = lsm.parse_denials([
            'audit: type=1400 apparmor="DENIED" profile="foo" comm="bar"',
            "audit: avc:  denied  { read } for comm=\"baz\"",
            "normal line",
        ])
        self.assertEqual(len(parsed["apparmor"]), 1)
        self.assertEqual(len(parsed["selinux"]), 1)

    def test_write_only_interface_is_not_unreadable(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy"
            path.write_text("")
            path.chmod(0o200)
            errors = []
            self.assertEqual(lsm._read_lsm(path, errors, "ima policy"), "")
        self.assertEqual(errors, [])


class LsmRuleTests(unittest.TestCase):
    def _state(self, **overrides):
        state = {
            "active": ["lockdown", "yama", "apparmor"],
            "securityfs": True,
            "apparmor": {"present": True, "enabled": "Y"},
            "selinux": {"present": False, "enforce": ""},
            "yama": {"present": True, "ptrace_scope": "1"},
            "lockdown": {"selected": "integrity"},
            "ima": {"present": True},
            "errors": [],
        }
        state.update(overrides)
        return state

    def test_insecure_state_rules(self):
        state = self._state(
            active=[],
            securityfs=False,
            apparmor={"present": True, "enabled": "N"},
            selinux={"present": True, "enforce": "0"},
            yama={"present": True, "ptrace_scope": "0"},
            lockdown={"selected": "none"},
            ima={"present": False},
        )
        rules = {finding["rule"] for finding in lsm._state_findings(state)}
        for expected in (
            "lsm.none", "lsm.apparmor.disabled", "lsm.selinux.permissive",
            "lsm.yama.ptrace_scope",
        ):
            self.assertIn(expected, rules)

    def test_lockdown_none_is_reported_when_lsm_active(self):
        rules = {finding["rule"] for finding in lsm._state_findings(
            self._state(active=["lockdown"], lockdown={"selected": "none"})
        )}
        self.assertIn("lsm.lockdown.none", rules)

    def test_healthy_state_has_no_findings(self):
        self.assertEqual(lsm._state_findings(self._state()), [])

    def test_denial_threshold(self):
        findings = lsm._denial_findings({
            "apparmor": ["denied one"], "selinux": [],
        })
        self.assertEqual(findings[0]["rule"], "lsm.apparmor.denial")


if __name__ == "__main__":
    unittest.main()
