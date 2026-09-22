"""Run: python -m unittest discover -s backend/tests  (from project root)"""
import sqlite3
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.query_parser import QueryError, compile_query  # noqa: E402

SCHEMA = (Path(__file__).resolve().parents[2] / "database" / "schema.sql").read_text()
ROWS = [
    ("2025-09-26 17:03:28", "OS", "172.16.20.69", None, "172.16.20.69", None, "H1", "u", "C:\\x\\EDR-Freeze_1.0.exe",
     "run", "Executed", "Image: EDR-Freeze_1.0.exe"),
    ("2025-09-26 17:01:30", "Network", "172.16.20.69", 50000, "140.82.113.4", 443, "H1", "u", "powershell.exe",
     None, "Allowed", "powershell to github"),
    ("2025-01-01 05:00:00", "Firewall", "198.51.100.5", 50001, "172.16.20.10", 22, None, None, None, None,
     "Blocked", "device=FW action=blocked 100%_done"),
]


class QueryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.db = sqlite3.connect(":memory:")
        cls.db.executescript(SCHEMA)
        cls.db.executemany(
            "INSERT INTO logs(timestamp,type,source_address,source_port,destination_address,destination_port,"
            "hostname,username,process,command_line,action,raw_log) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", ROWS)

    def ids(self, q):
        cq = compile_query(q)
        sql = f"SELECT id FROM logs WHERE {cq.where} ORDER BY {cq.order_by}"
        if cq.limit:
            sql += f" LIMIT {cq.limit}"
        return [r[0] for r in self.db.execute(sql, cq.params)]

    def test_empty(self):
        self.assertEqual(self.ids(""), [1, 2, 3])

    def test_equals_case_insensitive(self):
        self.assertEqual(self.ids('type="os"'), [1])

    def test_alias_and_implicit_and(self):
        self.assertEqual(self.ids("src=172.16.20.69 dport=443"), [2])

    def test_or_not_parens(self):
        self.assertEqual(self.ids("(type=OS OR type=Firewall) AND NOT action=Blocked"), [1])
        self.assertEqual(self.ids("!type=OS"), [2, 3])

    def test_not_equals_includes_nulls(self):
        self.assertEqual(self.ids("hostname!=H1"), [3])

    def test_wildcard(self):
        self.assertEqual(self.ids("process=*edr-freeze*"), [1])

    def test_in_and_not_in(self):
        self.assertEqual(self.ids("destination_port IN (22, 443)"), [2, 3])
        self.assertEqual(self.ids("type NOT IN (OS, Network)"), [3])

    def test_contains_and_free_text(self):
        self.assertEqual(self.ids('raw_log CONTAINS "github"'), [2])
        self.assertEqual(self.ids("powershell"), [2])
        self.assertEqual(self.ids("powershell NOT github"), [])

    def test_like_metachars_are_literal(self):
        self.assertEqual(self.ids('"100%_done"'), [3])
        self.assertEqual(self.ids('"1_0"'), [])   # '_' would match "100" if not escaped

    def test_numeric_and_time_compare(self):
        self.assertEqual(self.ids("destination_port >= 443"), [2])
        self.assertEqual(self.ids('timestamp < "2025-06-01"'), [3])

    def test_pipe_commands(self):
        self.assertEqual(self.ids("| sort timestamp asc | head 2"), [3, 2])
        self.assertEqual(self.ids("| sort -destination_port"), [2, 3, 1])

    def test_injection_is_parameterised(self):
        self.assertEqual(self.ids("type=\"OS' OR 1=1 --\""), [])
        with self.assertRaises(QueryError):
            compile_query("type;DROP=1")
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM logs").fetchone()[0], 3)

    def test_errors_have_position(self):
        for q, pos in [("nosuchfield=1", 0), ("type=", 5), ("(type=OS", 8), ('"abc', 0),
                       ("destination_port=abc", 17), ("type > OS", 7), ("| explode", 2), ("AND type=OS", 0)]:
            with self.subTest(q=q):
                with self.assertRaises(QueryError) as ctx:
                    compile_query(q)
                self.assertEqual(ctx.exception.pos, pos)


if __name__ == "__main__":
    unittest.main()
