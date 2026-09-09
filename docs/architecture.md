# Architecture

SentinelForge's Phase 1 and Phase 2 foundation is an offline pipeline:

1. The ingestion reader opens explicitly supplied local text files as untrusted input.
2. The ingestion pipeline passes lines to a source-specific parser; it does not interpret log syntax itself.
3. `linux_auth.parse_lines` recognizes the documented ISO-UTC/syslog-like format.
4. Each supported line becomes an immutable `SecurityEvent`, with normalized fields and the exact raw line retained.
5. The pipeline returns events together with non-fatal parser diagnostics.
6. `DetectionEngine` sorts events and evaluates configurable, deterministic rules.
7. `Alert` objects contain stable IDs, evidence events, severity, and evidence-limited wording.

The ingestion boundary is intentionally small: `reader.py` handles local file reading,
`pipeline.py` coordinates readers and parsers, and parsers remain responsible for
source syntax. Multiple files can be supplied to the pipeline in a defined order.

Malformed and unsupported lines become diagnostics and do not stop other lines from being parsed. No command found in a log is executed, and the parser does not access live system logs.
