import tempfile
import unittest
from pathlib import Path

from sentinelforge.ingestion.pipeline import ingest_file, ingest_files, ingest_lines


VALID_LINE = (
    "2025-01-01T00:00:00Z host sshd[1]: "
    "Failed password for alice from 192.0.2.1 port 22 ssh2"
)


class IngestionTests(unittest.TestCase):
    def test_ingest_lines_returns_events_and_diagnostics(self):
        result = ingest_lines([VALID_LINE, "malformed input"])
        self.assertEqual(len(result.events), 1)
        self.assertEqual(len(result.diagnostics), 1)
        self.assertEqual(result.events[0].source, "linux-auth")
        self.assertEqual(result.diagnostics[0].line_number, 2)

    def test_ingest_file_reads_local_source_without_parser_duplication(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            source_path = Path(temporary_directory) / "auth.log"
            source_path.write_text(VALID_LINE + "\n", encoding="utf-8")
            result = ingest_file(source_path)
        self.assertEqual(len(result.events), 1)
        self.assertEqual(result.events[0].raw, VALID_LINE)

    def test_ingest_files_preserves_source_order(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            first_path = Path(temporary_directory) / "first.log"
            second_path = Path(temporary_directory) / "second.log"
            first_path.write_text(VALID_LINE + "\n", encoding="utf-8")
            second_path.write_text(VALID_LINE.replace("alice", "bob") + "\n", encoding="utf-8")
            result = ingest_files([first_path, second_path])
        self.assertEqual([event.username for event in result.events], ["alice", "bob"])

    def test_malformed_file_does_not_abort_ingestion(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            source_path = Path(temporary_directory) / "mixed.log"
            source_path.write_text("malformed\n" + VALID_LINE + "\n", encoding="utf-8")
            result = ingest_file(source_path)
        self.assertEqual(len(result.events), 1)
        self.assertEqual(len(result.diagnostics), 1)
