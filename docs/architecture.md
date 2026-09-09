# Architecture

SentinelForge Phase 1 is an offline pipeline:

1. An explicitly supplied, controlled Linux authentication fixture is read as untrusted text.
2. `linux_auth.parse_lines` recognizes a documented ISO-UTC/syslog-like format.
3. Each supported line becomes an immutable `SecurityEvent`, with normalized fields and the exact raw line retained.
4. `DetectionEngine` sorts events and evaluates configurable, deterministic rules.
5. `Alert` objects contain stable IDs, evidence events, severity, and evidence-limited wording.

Malformed and unsupported lines become diagnostics and do not stop other lines from being parsed. No command found in a log is executed, and the parser does not access live system logs.
