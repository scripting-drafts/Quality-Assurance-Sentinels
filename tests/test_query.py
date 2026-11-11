"""The inbox query engine is read-only and bounded."""
import json
import sqlite3
import unittest

from sentinels import db, query


class QueryEngineTests(unittest.TestCase):
    def _conn(self):
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.executescript(db.SCHEMA)
        for index, (severity, status, rule) in enumerate((
            ("warning", "open", "memory.low"),
            ("error", "open", "systemd.service_start"),
            ("critical", "investigating", "crash.core2"),
            ("error", "resolved", "journal.critical"),
        )):
            conn.execute(
                "INSERT INTO findings(fingerprint,ts,last_ts,rule,severity,subject,"
                "detail,count,status) VALUES(?,?,?,?,?,?,?,?,?)",
                (f"fp{index}", f"2026-11-10T0{index}:00:00Z",
                 f"2026-11-10T0{index}:00:00Z", rule, severity, "subject",
                 f"detail {index}", index + 1, status),
            )
        conn.commit()
        return conn

    def test_catalog_has_inbox_first(self):
        self.assertEqual(query.catalog()[0]["id"], "inbox")
        self.assertIn("errors", query.CATEGORY_ORDER)
        self.assertIn("findings", query.CATEGORY_ORDER)

    def test_catalog_covers_every_data_table(self):
        expected_sources = {
            "processes": "proc_snap",
            "inventory-items": "inventory",
            "inventory-diffs": "inventory_diffs",
            "hardware-items": "hardware_items",
            "core2": "core2_cases",
            "crosschecks": "crosschecks",
            "notifications": "notifications",
            "reports": "reports",
            "meta": "meta",
        }
        for category, source in expected_sources.items():
            self.assertIn(category, query.CATEGORY_ORDER)
            self.assertEqual(query.CATEGORY_SOURCES[category], source)
        for entry in query.catalog():
            self.assertTrue(entry["source"], entry["id"])

    def test_every_catalog_category_runs(self):
        conn = self._conn()
        for category in query.CATEGORY_ORDER:
            with self.subTest(category=category):
                result = query.run_category(conn, category, limit=1)
                self.assertEqual(result["category"], category)
                self.assertIsInstance(result["columns"], list)

    def test_cli_query_parser(self):
        from sentinels import cli

        args = cli.build_parser().parse_args(
            ["query", "--json", "--category", "inbox", "--limit", "25"])
        self.assertIs(args.func, cli.cmd_query)
        self.assertEqual(args.category, "inbox")
        self.assertEqual(args.limit, 25)
        self.assertTrue(args.json)
        schema = cli.build_parser().parse_args(["query", "--json", "--schema"])
        self.assertTrue(schema.schema)

    def test_schema_lists_tables_rows_and_columns(self):
        tables = query.schema(self._conn())
        names = {table["name"] for table in tables}
        self.assertIn("findings", names)
        self.assertIn("events", names)
        findings = next(table for table in tables if table["name"] == "findings")
        self.assertEqual(findings["rows"], 4)
        self.assertIn("severity", [column["name"]
                                   for column in findings["columns"]])

    def test_inbox_orders_by_severity_then_time(self):
        result = query.run_category(self._conn(), "inbox", limit=10)
        self.assertEqual([row[3] for row in result["rows"]],
                         ["critical", "error", "warning"])
        self.assertNotIn("journal.critical", [row[5] for row in result["rows"]])

    def test_errors_excludes_warnings(self):
        result = query.run_category(self._conn(), "errors", limit=10)
        self.assertEqual({row[3] for row in result["rows"]},
                         {"critical", "error"})

    def test_search_and_severity_filters_find_the_example(self):
        result = query.run_category(
            self._conn(), "findings", limit=10,
            search="systemd.service_start", severity="error", status="open")
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["rows"][0][0], 2)
        self.assertEqual(result["filters"]["search"], "systemd.service_start")
        self.assertNotIn("?", result["sql"])
        self.assertIn("systemd.service", result["sql"])

    def test_search_escapes_like_wildcards(self):
        result = query.run_category(
            self._conn(), "findings", limit=10, search="%")
        self.assertEqual(result["count"], 0)

    def test_status_filter_requires_every_selected_value(self):
        conn = self._conn()
        single = query.run_category(conn, "findings", limit=10, status="open")
        self.assertGreater(single["count"], 0)
        self.assertIn("status = 'open'", single["sql"])
        combined = query.run_category(
            conn, "findings", limit=10, status="open,resolved")
        self.assertEqual(combined["count"], 0)
        self.assertIn("status = 'open' AND status = 'resolved'", combined["sql"])

    def test_cycle_summary_and_latest_new(self):
        conn = self._conn()
        detail = json.dumps({
            "layer1_findings": {
                "new": 1, "by_severity": {"error": 1},
                "rules": ["systemd.service_start"], "ids": [1],
            }
        })
        conn.execute(
            "INSERT INTO runs(ts, task, ok, detail) VALUES(?,?,?,?)",
            ("2026-11-10T08:14:45Z", "cycle", 1, detail),
        )
        latest = query.latest_cycle(conn)
        self.assertEqual(latest["latest"]["new"], 1)
        self.assertEqual(latest["latest"]["rules"], ["systemd.service_start"])
        cycles = query.run_category(conn, "cycles", limit=10)
        self.assertEqual(cycles["rows"][0][0], 1)
        self.assertEqual(cycles["rows"][0][2], 1)

    def test_new_findings_category_links_cycle_and_finding(self):
        conn = self._conn()
        db.record_cycle_findings(conn, "2026-11-10T08:14:45Z", [{
            "id": 2, "rule": "systemd.service_start",
            "severity": "error", "subject": "user@1000",
        }])
        result = query.run_category(conn, "new-findings", limit=10)
        self.assertEqual(result["count"], 1)
        self.assertEqual(result["rows"][0][0], "2026-11-10T08:14:45Z")
        self.assertEqual(result["rows"][0][1], 2)
        latest = query.latest_cycle(conn)
        self.assertEqual(latest["last_new"]["new"], 1)
        self.assertEqual(latest["last_new"]["rules"], ["systemd.service_start"])

    def test_limit_truncates_instead_of_erroring(self):
        result = query.run_category(self._conn(), "findings", limit=2)
        self.assertEqual(result["count"], 2)
        self.assertTrue(result["truncated"])

    def test_select_and_cte_are_allowed(self):
        conn = self._conn()
        result = query.run_sql(conn, "SELECT count(*) AS n FROM findings")
        self.assertEqual(result["rows"], [[4]])
        result = query.run_sql(
            conn, "WITH x AS (SELECT 1 AS n) SELECT n FROM x")
        self.assertEqual(result["rows"], [[1]])

    def test_semicolon_inside_a_string_is_not_a_second_statement(self):
        result = query.run_sql(self._conn(), "SELECT ';' AS semi")
        self.assertEqual(result["rows"], [[";"]])

    def test_writes_and_pragmas_are_rejected(self):
        conn = self._conn()
        for statement in (
            "DELETE FROM findings",
            "UPDATE findings SET status='resolved'",
            "PRAGMA table_info(findings)",
            "ATTACH DATABASE '/tmp/x.db' AS x",
            "SELECT 1; SELECT 2",
        ):
            with self.subTest(statement=statement):
                with self.assertRaises(query.QueryError):
                    query.run_sql(conn, statement)
        self.assertEqual(
            conn.execute("SELECT count(*) FROM findings").fetchone()[0], 4)

    def test_limit_validation(self):
        self.assertEqual(query.normalize_limit(query.MAX_LIMIT), 10000)
        for limit in (0, -1, query.MAX_LIMIT + 1, "many"):
            with self.subTest(limit=limit):
                with self.assertRaises(query.QueryError):
                    query.normalize_limit(limit)


if __name__ == "__main__":
    unittest.main()
