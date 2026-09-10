import tempfile
import unittest
from pathlib import Path

from sentinelforge.reporting import analyze_file
from sentinelforge.storage import AnalysisRepository, Database


class StorageTests(unittest.TestCase):
    def test_schema_repeated_initialization_and_round_trip(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sentinelforge.db"
            report = analyze_file("fixtures/auth.log", database=str(path))
            with Database(path) as db:
                self.assertEqual(db.schema_version, 1)
                repository = AnalysisRepository(db)
                runs = repository.list_runs()
                self.assertEqual(len(runs), 1)
                self.assertEqual(len(repository.list_alerts_for_run(runs[0]["run_id"])), len(report["alerts"]))
            with Database(path) as db:
                self.assertEqual(db.schema_version, 1)

    def test_transaction_rolls_back(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "rollback.db"
            with Database(path) as db:
                with self.assertRaises(RuntimeError):
                    with db.transaction() as connection:
                        connection.execute("INSERT INTO runs VALUES (?, ?, ?)", ("run", "now", "{}"))
                        raise RuntimeError("rollback")
                self.assertIsNone(db.connection.execute("SELECT run_id FROM runs WHERE run_id='run'").fetchone())

    def test_malicious_content_is_inert(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "content.db"
            report = analyze_file("fixtures/auth.log", database=str(path))
            self.assertTrue(report["alerts"])
            with Database(path) as db:
                repository = AnalysisRepository(db)
                alert = repository.get_alert(report["alerts"][0]["alert_id"])
                self.assertIsNotNone(alert)
