"""Tests for the shutdown listener and captured-issue redaction paths."""
import json
import os
import sqlite3
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from sentinels import boot, config, db, detect, shutdown, util

BOOT_ID = "0123456789abcdef0123456789abcdef"


def _entry(message, unit="init.scope", boot_id="boot-1", priority="3",
           ts="2026-11-07T21:06:01Z"):
    epoch = datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp()
    return {
        "MESSAGE": message,
        "_SYSTEMD_UNIT": unit,
        "_BOOT_ID": boot_id,
        "PRIORITY": priority,
        "__REALTIME_TIMESTAMP": str(int(epoch * 1_000_000)),
    }


def _journal_lines(*entries):
    return "\n".join(json.dumps(entry) for entry in entries) + "\n"


class MatchTests(unittest.TestCase):
    def test_service_start_failure_is_tracked(self):
        item = shutdown._match(
            _entry("Failed to start OpenBSD Secure Shell server.")
        )
        self.assertEqual(item["rule"], "shutdown.service_start")
        self.assertEqual(item["severity"], "error")
        self.assertEqual(item["phase"], "shutdown")
        self.assertTrue(item["fingerprint"])

    def test_unmount_failure_is_tracked(self):
        item = shutdown._match(_entry("Failed unmounting /media/<user>/2."))
        self.assertEqual(item["rule"], "shutdown.unmount")

    def test_successful_start_is_not_tracked(self):
        self.assertIsNone(
            shutdown._match(_entry("Started OpenBSD Secure Shell server."))
        )

    def test_strict_redaction_keeps_path_shape(self):
        with mock.patch.object(util, "_USER", "alice"):
            item = shutdown._match(_entry("Failed to start /home/alice/bin/tool"))
        self.assertNotIn("/home/alice", item["message"])
        self.assertIn("/home/<user>", item["message"])

    def test_collapsed_redaction_removes_paths(self):
        with mock.patch.object(config, "CAPTURE_REDACTION", "collapsed"):
            item = shutdown._match(_entry("Failed to start /home/alice/bin/tool"))
        self.assertNotIn("/home/", item["message"])
        self.assertIn("<path>", item["message"])

    def test_metadata_redaction_withholds_message(self):
        with mock.patch.object(config, "CAPTURE_REDACTION", "metadata"):
            item = shutdown._match(_entry("Failed to start /home/alice/bin/tool"))
        self.assertEqual(item["message"], "")
        self.assertTrue(item["fingerprint"])


class ScanTests(unittest.TestCase):
    def _fake_run(self, marker, failures):
        def fake_run(cmd, timeout=20):
            if "--grep" in cmd:
                pattern = cmd[cmd.index("--grep") + 1]
                if pattern == shutdown.FAILURE_GREP:
                    return 0, _journal_lines(*failures), ""
                return 0, _journal_lines(*marker), ""
            return 0, "", ""
        return fake_run

    def test_scan_splits_boot_and_shutdown_phases(self):
        marker = _entry(
            "System is powering down.", unit="systemd-logind.service",
            priority="6", ts="2026-11-07T21:06:01Z",
        )
        boot_failure = _entry(
            "Failed to start OpenBSD Secure Shell server.",
            ts="2026-11-07T16:29:07Z",
        )
        shutdown_failure = _entry(
            "Failed unmounting /media/<user>/2.",
            ts="2026-11-07T21:06:01Z",
        )
        with mock.patch.object(
            shutdown, "run", side_effect=self._fake_run([marker], [boot_failure, shutdown_failure])
        ):
            record = shutdown._scan("-1", "boot-1")
        self.assertEqual(record["schema_version"], 2)
        self.assertEqual(record["phases"]["boot"]["count"], 1)
        self.assertEqual(record["phases"]["shutdown"]["count"], 1)
        phases = [item["phase"] for item in record["errors"]]
        self.assertEqual(phases, ["boot", "shutdown"])

    def test_no_marker_keeps_boot_phase(self):
        failure = _entry(
            "Failed to start OpenBSD Secure Shell server.",
            ts="2026-11-07T16:29:07Z",
        )
        with mock.patch.object(
            shutdown, "run", side_effect=self._fake_run([], [failure])
        ):
            record = shutdown._scan("-1", "boot-1")
        self.assertEqual(record["phases"]["boot"]["count"], 1)
        self.assertEqual(record["phases"]["shutdown"]["count"], 0)
        self.assertEqual(record["errors"][0]["phase"], "boot")

    def test_capture_without_marker_persists_boot_failures(self):
        failure = _entry(
            "Failed to start OpenBSD Secure Shell server.",
            ts="2026-11-07T16:29:07Z",
        )
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "shutdown"
            directory.mkdir()
            with mock.patch.object(config, "SHUTDOWN_DIR", directory), \
                 mock.patch.object(config, "ensure_dirs", lambda: None), \
                 mock.patch.object(shutdown, "run", side_effect=self._fake_run([], [failure])), \
                 mock.patch.object(shutdown, "_current_boot_id", return_value="boot-1"):
                saved = shutdown.capture("0")
            self.assertEqual(saved["count"], 1)
            self.assertTrue((directory / "boot-1.json").exists())


class CaptureTests(unittest.TestCase):
    def test_capture_is_private_and_round_trips(self):
        record = {
            "schema_version": 2,
            "boot_id": "boot-1",
            "captured_ts": "2026-11-07T21:07:00Z",
            "redaction": "strict",
            "phases": {
                "boot": {"count": 0, "signatures": 0, "start": "", "end": ""},
                "shutdown": {"count": 1, "signatures": 1,
                             "start": "2026-11-07T21:06:01Z",
                             "end": "2026-11-07T21:06:01Z"},
            },
            "count": 1,
            "errors": [shutdown._match(_entry("Failed unmounting /media/<user>/2."))],
            "window_start": "2026-11-07T21:06:01Z",
            "window_end": "2026-11-07T21:06:01Z",
        }
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "shutdown"
            directory.mkdir()
            with mock.patch.object(config, "SHUTDOWN_DIR", directory), \
                 mock.patch.object(config, "ensure_dirs", lambda: None), \
                 mock.patch.object(shutdown, "_scan", return_value=record), \
                 mock.patch.object(shutdown, "_current_boot_id", return_value="boot-1"):
                shutdown.capture("0")
                path = directory / "boot-1.json"
                self.assertTrue(path.exists())
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
                self.assertEqual(shutdown.load("boot-1")["count"], 1)


class PersistTests(unittest.TestCase):
    def _record(self, boot_id=BOOT_ID, count=0):
        return {
            "schema_version": shutdown.SCHEMA_VERSION,
            "boot_id": boot_id,
            "captured_ts": "2026-11-07T21:07:00Z",
            "redaction": "strict",
            "phases": {
                "boot": {"count": 0, "signatures": 0, "start": "", "end": ""},
                "shutdown": {"count": 0, "signatures": 0, "start": "", "end": ""},
            },
            "count": count,
            "errors": [],
            "window_start": "",
            "window_end": "",
        }

    def test_persist_writes_reconstructed_record(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "shutdown"
            directory.mkdir()
            with mock.patch.object(config, "SHUTDOWN_DIR", directory), \
                 mock.patch.object(config, "ensure_dirs", lambda: None):
                self.assertTrue(shutdown.persist(self._record()))
                path = directory / f"{BOOT_ID}.json"
                self.assertTrue(path.exists())
                self.assertEqual(os.stat(path).st_mode & 0o777, 0o600)
                self.assertEqual(shutdown.load(BOOT_ID)["boot_id"], BOOT_ID)

    def test_persist_keeps_existing_listener_capture(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "shutdown"
            directory.mkdir()
            path = directory / f"{BOOT_ID}.json"
            path.write_text(json.dumps(self._record(count=7)))
            with mock.patch.object(config, "SHUTDOWN_DIR", directory), \
                 mock.patch.object(config, "ensure_dirs", lambda: None):
                self.assertFalse(shutdown.persist(self._record()))
                self.assertEqual(shutdown.load(BOOT_ID)["count"], 7)

    def test_persist_requires_a_boot_id(self):
        self.assertFalse(shutdown.persist(self._record(boot_id="")))

    def test_persist_rejects_non_boot_ids(self):
        self.assertFalse(shutdown.persist(self._record(boot_id="abc")))
        self.assertFalse(shutdown.persist(self._record(boot_id="../escape")))


class InstallUnitTests(unittest.TestCase):
    def test_unit_is_ordered_before_final_target(self):
        script = Path(__file__).resolve().parents[1] / "root" / "install-shutdown.sh"
        text = script.read_text(encoding="utf-8")
        self.assertIn("Before=final.target", text)
        self.assertIn("WantedBy=final.target", text)


class ReplayTests(unittest.TestCase):
    def _conn(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(db.SCHEMA)
        return conn

    def test_v2_replay_inserts_both_phases_once(self):
        boot_item = shutdown._match(
            _entry("Failed to start OpenBSD Secure Shell server.",
                   ts="2026-11-07T16:29:07Z"),
            phase="boot",
        )
        stop_item = shutdown._match(
            _entry("Failed unmounting /media/<user>/2.",
                   ts="2026-11-07T21:06:01Z"),
            phase="shutdown",
        )
        record = {
            "schema_version": 2,
            "boot_id": "boot-old",
            "captured_ts": "2026-11-07T21:07:00Z",
            "redaction": "strict",
            "phases": {},
            "count": 2,
            "errors": [boot_item, stop_item],
            "window_start": "2026-11-07T21:06:01Z",
            "window_end": "2026-11-07T21:06:01Z",
        }
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "shutdown"
            directory.mkdir()
            (directory / "boot-old.json").write_text(json.dumps(record))
            conn = self._conn()
            with mock.patch.object(config, "SHUTDOWN_DIR", directory), \
                 mock.patch.object(shutdown, "_current_boot_id", return_value="boot-new"):
                self.assertEqual(shutdown.replay(conn), 2)
                self.assertEqual(shutdown.replay(conn), 0)
            rows = conn.execute("SELECT * FROM events ORDER BY ts").fetchall()
            self.assertEqual(len(rows), 2)
            self.assertIn("OpenBSD", rows[0]["message"])
            self.assertIn("unmounting", rows[1]["message"])
            conn.close()

    def test_v1_capture_is_readable(self):
        item = shutdown._match(_entry("Failed unmounting /media/<user>/2."))
        record = {
            "schema_version": 1,
            "boot_id": "boot-old",
            "captured_ts": "2026-11-07T21:07:00Z",
            "count": 1,
            "errors": [item],
            "window_start": "2026-11-07T21:06:01Z",
            "window_end": "2026-11-07T21:06:01Z",
        }
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "shutdown"
            directory.mkdir()
            (directory / "boot-old.json").write_text(json.dumps(record))
            conn = self._conn()
            with mock.patch.object(config, "SHUTDOWN_DIR", directory), \
                 mock.patch.object(shutdown, "_current_boot_id", return_value="boot-new"):
                self.assertEqual(shutdown.replay(conn), 1)
            conn.close()

    def test_metadata_capture_replays_without_raw_message(self):
        item = shutdown._match(
            _entry("Failed to start /home/alice/bin/tool"),
            mode="metadata",
        )
        record = {
            "schema_version": 2,
            "boot_id": "boot-old",
            "captured_ts": "2026-11-07T21:07:00Z",
            "redaction": "metadata",
            "phases": {},
            "count": 1,
            "errors": [item],
        }
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / "shutdown"
            directory.mkdir()
            (directory / "boot-old.json").write_text(json.dumps(record))
            conn = self._conn()
            with mock.patch.object(config, "SHUTDOWN_DIR", directory), \
                 mock.patch.object(shutdown, "_current_boot_id", return_value="boot-new"):
                shutdown.replay(conn)
            row = conn.execute("SELECT message FROM events").fetchone()
            self.assertIn("[metadata-only]", row["message"])
            self.assertNotIn("/home/alice", row["message"])
            conn.close()


class DetectionTests(unittest.TestCase):
    def test_event_rules_track_start_and_unmount_failures(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(db.SCHEMA)
        conn.execute(
            "INSERT INTO events(ts,severity,unit,message,fingerprint)"
            " VALUES(?,?,?,?,?)",
            ("2026-11-08T07:33:29Z", "error", "init.scope",
             "Failed to start OpenBSD Secure Shell server.", "fp-start"),
        )
        conn.execute(
            "INSERT INTO events(ts,severity,unit,message,fingerprint)"
            " VALUES(?,?,?,?,?)",
            ("2026-11-08T07:40:29Z", "error", "init.scope",
             "Failed to start OpenBSD Secure Shell server.", "fp-start-2"),
        )
        conn.execute(
            "INSERT INTO events(ts,severity,unit,message,fingerprint)"
            " VALUES(?,?,?,?,?)",
            ("2026-11-08T07:33:29Z", "error", "init.scope",
             "Failed unmounting /media/<user>/2.", "fp-unmount"),
        )
        with mock.patch.object(detect, "utcnow", return_value=datetime(
            2026, 11, 8, 8, 0, tzinfo=timezone.utc
        )):
            new = detect.scan(conn)
        rules = {finding["rule"] for finding in new}
        self.assertIn("systemd.service_start", rules)
        self.assertIn("systemd.unmount", rules)
        # Two journal buckets for the same signature are one issue.
        starts = [f for f in new if f["rule"] == "systemd.service_start"]
        self.assertEqual(len(starts), 1)
        self.assertEqual(starts[0]["severity"], "error")
        self.assertIn("2 occurrence(s)", starts[0]["detail"])
        conn.close()


class BootScanTests(unittest.TestCase):
    def test_shutdown_scan_is_part_of_the_boot_evidence(self):
        record = {"index": -1, "boot_id": "boot-1", "span": "span"}
        summary = {
            "count": 2,
            "phases": {
                "boot": {"count": 1, "start": "2026-11-07T16:29:07Z",
                         "end": "2026-11-07T16:29:07Z"},
                "shutdown": {"count": 1, "start": "2026-11-07T21:06:01Z",
                             "end": "2026-11-07T21:06:01Z"},
            },
            "errors": [
                {"phase": "boot", "message": "Failed to start OpenBSD Secure Shell server."},
                {"phase": "shutdown", "message": "Failed unmounting /media/<user>/2."},
            ],
        }
        with mock.patch.object(boot, "_journal", return_value="systemd-shutdown[1]: done"), \
             mock.patch.object(boot, "_scan_output", return_value=""), \
             mock.patch.object(boot, "_last_epoch", return_value="2026-11-07T21:06:07Z"), \
             mock.patch.object(boot.shutdown, "scan_boot", return_value=summary):
            scanned = boot.scan_boot(record)
        scans = json.loads(scanned["scans"])
        self.assertEqual(scans["startup"]["count"], 1)
        self.assertEqual(scans["shutdown"]["count"], 1)
        self.assertEqual(scans["startup"]["sample"],
                         ["Failed to start OpenBSD Secure Shell server."])
        self.assertEqual(scans["shutdown"]["sample"],
                         ["Failed unmounting /media/<user>/2."])

    def test_latest_boot_scan_persists_reconstruction(self):
        record = {"index": -1, "boot_id": "boot-1", "span": "span"}
        summary = {
            "boot_id": "boot-1",
            "count": 0,
            "phases": {},
            "errors": [],
        }
        with mock.patch.object(boot, "_journal", return_value=""), \
             mock.patch.object(boot, "_scan_output", return_value=""), \
             mock.patch.object(boot, "_last_epoch",
                               return_value="2026-11-07T21:06:07Z"), \
             mock.patch.object(boot.shutdown, "scan_boot", return_value=summary), \
             mock.patch.object(boot.shutdown, "persist") as persist:
            boot.scan_boot(record)
        persist.assert_called_once_with(summary)

    def test_older_boot_scan_does_not_persist(self):
        record = {"index": -2, "boot_id": "boot-1", "span": "span"}
        summary = {
            "boot_id": "boot-1",
            "count": 0,
            "phases": {},
            "errors": [],
        }
        with mock.patch.object(boot, "_journal", return_value=""), \
             mock.patch.object(boot, "_scan_output", return_value=""), \
             mock.patch.object(boot, "_last_epoch",
                               return_value="2026-11-07T21:06:07Z"), \
             mock.patch.object(boot.shutdown, "scan_boot", return_value=summary), \
             mock.patch.object(boot.shutdown, "persist") as persist:
            boot.scan_boot(record)
        persist.assert_not_called()


if __name__ == "__main__":
    unittest.main()
