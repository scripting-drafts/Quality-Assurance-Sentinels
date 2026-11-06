"""Tests for security provenance detection rules."""
import json
import os
import sqlite3
import tempfile
import unittest
from pathlib import Path

from sentinels import db, security


class PolicyTests(unittest.TestCase):
    def test_default_policy_is_conservative(self):
        policy = security.load_policy("/nonexistent/security-policy.json")
        self.assertIn("/home/", policy["user_writable_prefixes"])
        self.assertEqual(policy["allow_root_user_path"], [])
        self.assertTrue(policy["requested_audit"])

    def test_policy_file_overrides_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "policy.json"
            path.write_text(json.dumps({"allowed_uids": [0, 1000, 1001]}))
            self.assertEqual(security.load_policy(path)["allowed_uids"], [0, 1000, 1001])


class ProcessRuleTests(unittest.TestCase):
    def _proc(self, **overrides):
        proc = {
            "pid": 4242,
            "ppid": 1,
            "comm": "python3",
            "uid": 0,
            "euid": 0,
            "cap_eff": 0,
            "cmdline": ["python3", "/home/operator/project/run.py"],
            "exe": "/usr/bin/python3",
            "cwd": "/home/operator/project",
            "cgroup": "0::/system.slice/test.service",
            "container": False,
            "loginuid": 0,
            "starttime": "12345",
        }
        proc.update(overrides)
        return proc

    def test_root_code_from_user_writable_path_is_critical(self):
        rules = {f["rule"] for f in security.classify_process(
            self._proc(), None, security.load_policy())
        }
        self.assertIn("security.root_user_path", rules)
        self.assertIn("security.root_cmdline_user_path", rules)

    def test_expected_root_system_process_is_not_flagged(self):
        proc = self._proc(
            comm="cron", cmdline=["/usr/sbin/cron", "-f"],
            exe="/usr/sbin/cron", cwd="/",
        )
        self.assertEqual(security.classify_process(proc, None, security.load_policy()), [])

    def test_container_root_is_outside_host_boundary(self):
        proc = self._proc(cgroup="0::/docker-abc/kubepods/pod1/container")
        self.assertEqual(security.classify_process(proc, None, security.load_policy()), [])

    def test_unexpected_uid_from_user_path_is_flagged(self):
        proc = self._proc(
            uid=65534, euid=65534, comm="evil",
            cmdline=["/tmp/evil"], exe="/tmp/evil", cwd="/tmp",
            loginuid=-1,
        )
        rules = {f["rule"] for f in security.classify_process(
            proc, None, security.load_policy()
        )}
        self.assertIn("security.unexpected_uid_user_path", rules)

    def test_authorized_setuid_helper_is_not_treated_as_user_root(self):
        proc = self._proc(
            comm="fusermount3", uid=0, euid=0,
            cmdline=["fusermount3", "-o", "rw", "--", "/run/user/1000/doc"],
            exe="/usr/bin/fusermount3", cwd="/run/user/1000/doc",
            loginuid=1000,
        )
        self.assertEqual(security.classify_process(proc, None, security.load_policy()), [])


class AuditRuleTests(unittest.TestCase):
    def test_root_exec_from_user_session(self):
        line = (
            'type=SYSCALL msg=audit(1793979000.1:42): arch=c000003e syscall=59 '
            'uid=0 auid=1000 exe="/usr/bin/python3" comm="python3" '
            'proctitle="/home/operator/repo/run.py" key="qa_security_exec"'
        )
        finding = security.parse_audit_line(line, security.load_policy())
        self.assertEqual(finding["rule"], "security.audit_root_exec")
        self.assertEqual(finding["severity"], "critical")

    def test_non_syscall_audit_record_is_ignored(self):
        line = (
            'type=EXECVE msg=audit(1793979000.1:44): argc=2 '
            'a0="sudo" a1="true" key="qa_security_priv"'
        )
        self.assertIsNone(security.parse_audit_line(line, security.load_policy()))

    def test_privilege_change_event(self):
        line = (
            'type=SYSCALL msg=audit(1793979000.1:43): uid=1000 euid=0 auid=1000 '
            'exe="/usr/bin/sudo" comm="sudo" key="qa_security_priv"'
        )
        finding = security.parse_audit_line(line, security.load_policy())
        self.assertEqual(finding["rule"], "security.audit_priv_change")
        self.assertIn(finding["severity"], ("warning", "critical"))


class FileRuleTests(unittest.TestCase):
    def test_root_owned_state_is_aggregated(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "tickets" / "draft.md"
            path.parent.mkdir()
            path.write_text("x")
            st = os.lstat(path)
            findings = security.file_findings([(str(path), st)])
            self.assertEqual(len(findings), 1)
            self.assertEqual(findings[0]["rule"], "security.root_owned_user_state")
            self.assertIn("1 entries", findings[0]["detail"])


class AuditCoverageTests(unittest.TestCase):
    def test_missing_audit_source_is_reported_as_unavailable(self):
        from unittest.mock import patch
        policy = security.load_policy("/nonexistent/security-policy.json")
        policy["audit_log"] = "/nonexistent/audit.log"
        with patch("sentinels.security.shutil.which", return_value=None):
            findings, available = security.audit_scan(policy)
        self.assertFalse(available)
        self.assertEqual(findings[0]["rule"], "security.audit_unavailable")


class AuditRulesSourceTests(unittest.TestCase):
    def test_rules_and_installer_are_present(self):
        from sentinels import config

        rules = config.ROOT / "root" / "audit" / "qa-security.rules"
        installer = config.ROOT / "root" / "audit" / "install-audit-rules.sh"
        self.assertTrue(rules.exists())
        self.assertTrue(installer.exists())
        text = rules.read_text()
        self.assertIn("key=qa_security_exec", text)
        self.assertIn("key=qa_security_priv", text)
        self.assertIn("execve", text)


class ResolveTests(unittest.TestCase):
    def test_resolved_state_finding_is_closed_when_condition_disappears(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(db.SCHEMA)
        conn.execute(
            "INSERT INTO findings(fingerprint,ts,last_ts,rule,severity,subject,detail,count,status)"
            " VALUES(?,?,?,?,?,?,?,1,'open')",
            ("security|root_owned_user_state|tickets", "t", "t",
             "security.root_owned_user_state", "warning", "tickets/", "x"),
        )
        security._resolve_missing(conn, "security.root_owned_user_state", set())
        status = conn.execute(
            "SELECT status FROM findings WHERE fingerprint=?",
            ("security|root_owned_user_state|tickets",),
        ).fetchone()["status"]
        self.assertEqual(status, "resolved")


class ScanIntegrationTests(unittest.TestCase):
    def test_scan_upserts_process_finding(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(db.SCHEMA)
        with tempfile.TemporaryDirectory() as tmp:
            proc = Path(tmp) / "4242"
            proc.mkdir()
            (proc / "status").write_text(
                "Name:\ttest\nState:\tR\nPPid:\t1\n"
                "Uid:\t0\t0\t0\t0\nGid:\t0\t0\t0\t0\nCapEff:\t0\n"
            )
            (proc / "cmdline").write_bytes(
                b"python3\0/home/operator/project/run.py\0"
            )
            (proc / "cgroup").write_text("0::/system.slice/test.service\n")
            (proc / "loginuid").write_text("0\n")
            (proc / "stat").write_text(
                "4242 (test) R 1 1 1 0 -1 0 0 0 0 0 0 0 0 0 0 0 0 12345 0\n"
            )
            (proc / "cwd").symlink_to("/home/operator")
            result = security.scan(
                conn, proc_root=tmp, include_files=False, include_audit=False
            )
        self.assertGreaterEqual(result["new"], 1)
        row = conn.execute(
            "SELECT rule FROM findings WHERE rule='security.root_user_path'"
        ).fetchone()
        self.assertIsNotNone(row)


if __name__ == "__main__":
    unittest.main()
