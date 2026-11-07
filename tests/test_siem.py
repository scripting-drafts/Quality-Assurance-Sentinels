"""Tests for the SIEM exporter."""
import json
import os
import sqlite3
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from sentinels import db, siem


class SiemBuildTests(unittest.TestCase):
    def setUp(self):
        self.conn = sqlite3.connect(":memory:")
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(db.SCHEMA)
        self.conn.execute(
            "INSERT INTO findings(fingerprint,ts,last_ts,rule,severity,subject,detail,"
            "count,status,evidence_path) VALUES(?,?,?,?,?,?,?,?,?,?)",
            ("fp-1", "2026-11-07T10:00:00Z", "2026-11-07T10:05:00Z",
             "lsm.state_unreadable", "warning", "lsm",
             "failed under /home/gerard/project", 3, "open", "evidence/one"),
        )
        self.conn.execute(
            "INSERT INTO events(ts,last_ts,severity,unit,comm,message,fingerprint,count)"
            " VALUES(?,?,?,?,?,?,?,?)",
            ("2026-11-07T10:01:00Z", "2026-11-07T10:02:00Z", "error",
             "kernel", "nvme", "I/O error", "evt-fp", 2),
        )
        self.conn.execute(
            "INSERT INTO crashes(ts,pid,comm,exe,sig,context,core2_involved,fingerprint)"
            " VALUES(?,?,?,?,?,?,?,?)",
            ("2026-11-07T10:03:00Z", 42, "crash", "/usr/bin/crash",
             "SIGSEGV", "core2=1", 1, "crash-fp"),
        )
        self.conn.execute(
            "INSERT INTO boots(boot_id,ended_clean,last_ts,captured_ts,last_message)"
            " VALUES(?,?,?,?,?)",
            ("boot-1", 0, "2026-11-07T09:00:00Z", "2026-11-07T09:01:00Z",
             "unexpected stop"),
        )
        self.conn.execute(
            "INSERT INTO hardware_runs(ts,status,sources,duration_ms,detail)"
            " VALUES(?,?,?,?,?)",
            ("2026-11-07T10:04:00Z", "ok", '{"storage":"ok"}', 10, ""),
        )
        self.conn.execute(
            "INSERT INTO lsm_runs(ts,digest,state,denials,status) VALUES(?,?,?,?,?)",
            ("2026-11-07T10:06:00Z", "abc", "{}", "{}", "ok"),
        )
        self.conn.execute(
            "INSERT INTO ticket_drafts(ts,vendor,path,title,issue_key)"
            " VALUES(?,?,?,?,?)",
            ("2026-11-07T10:07:00Z", "hardware", "tickets/x.md", "draft", "issue-1"),
        )
        self.conn.commit()

    def tearDown(self):
        self.conn.close()

    def test_all_types_are_normalized(self):
        events = siem.build_events(
            self.conn, "2000-01-01T00:00:00Z", limit=100
        )
        by_type = {event["event_type"] for event in events}
        self.assertEqual(
            by_type, {"finding", "event", "crash", "boot", "hardware", "lsm", "ticket"}
        )
        finding = next(e for e in events if e["event_type"] == "finding")
        self.assertIn("/home/<user>", finding["detail"])
        self.assertEqual(finding["count"], 3)
        self.assertEqual(finding["evidence_ref"], "evidence/one")
        crash = next(e for e in events if e["event_type"] == "crash")
        self.assertEqual(crash["severity"], "critical")
        self.assertEqual(crash["rule"], "crash.core2")
        boot = next(e for e in events if e["event_type"] == "boot")
        self.assertEqual(boot["rule"], "boot.unclean")
        self.assertEqual(boot["severity"], "warning")
        for event in events:
            self.assertEqual(event["schema_version"], "1.0")
            self.assertTrue(event["event_id"])
            self.assertTrue(event["host_id"].startswith("sha256:"))

    def test_since_shorthand(self):
        now = datetime(2026, 11, 7, 12, 0, tzinfo=timezone.utc)
        self.assertEqual(siem.parse_since("2h", now), "2026-11-07T10:00:00Z")
        self.assertEqual(
            siem.parse_since("2026-01-01T00:00:00Z", now),
            "2026-01-01T00:00:00Z",
        )


class SiemConfigTests(unittest.TestCase):
    def test_loopback_http_and_env_token(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "siem.json"
            path.write_text(json.dumps({
                "endpoint": "http://127.0.0.1:8088/ingest",
                "token_env": "QA_SIEM_TEST_TOKEN",
                "batch_size": 10,
            }))
            os.environ["QA_SIEM_TEST_TOKEN"] = "secret"
            try:
                cfg = siem.load_config(path)
            finally:
                os.environ.pop("QA_SIEM_TEST_TOKEN", None)
        self.assertEqual(cfg["token"], "secret")
        self.assertEqual(cfg["batch_size"], 10)

    def test_remote_plaintext_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "siem.json"
            path.write_text(json.dumps({
                "endpoint": "http://example.invalid/ingest",
                "token_env": "QA_SIEM_TEST_TOKEN",
            }))
            os.environ["QA_SIEM_TEST_TOKEN"] = "secret"
            try:
                with self.assertRaises(siem.SiemError):
                    siem.load_config(path)
            finally:
                os.environ.pop("QA_SIEM_TEST_TOKEN", None)


class PostTests(unittest.TestCase):
    def test_post_batch(self):
        received = {}

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers["Content-Length"])
                received["auth"] = self.headers.get("Authorization")
                received["body"] = json.loads(self.rfile.read(length))
                data = json.dumps({"accepted": len(received["body"])}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()
        cfg = {
            "endpoint": f"http://127.0.0.1:{server.server_port}/ingest",
            "token": "secret",
            "timeout_s": 5,
            "verify_tls": True,
            "ca_file": "",
        }
        result = siem._post_batch(cfg, [{"event_id": "one"}])
        thread.join(timeout=2)
        server.server_close()
        self.assertEqual(result["accepted"], 1)
        self.assertEqual(received["auth"], "Bearer secret")
        self.assertEqual(received["body"][0]["event_id"], "one")


if __name__ == "__main__":
    unittest.main()
