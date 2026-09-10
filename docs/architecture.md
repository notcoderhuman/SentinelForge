# Architecture

SentinelForge's Phase 1 through Phase 3 foundation is an offline pipeline:

```text
Event → Ingestion → Detection → Alert → Incident
```

1. The ingestion reader opens explicitly supplied local text files as untrusted input.
2. The ingestion pipeline passes lines to a source-specific parser; it does not interpret log syntax itself.
3. `linux_auth.parse_lines` recognizes the documented ISO-UTC/syslog-like format.
4. Each supported line becomes an immutable `SecurityEvent`, with normalized fields and the exact raw line retained.
5. The pipeline returns events together with non-fatal parser diagnostics.
6. `DetectionEngine` sorts events and evaluates configurable, deterministic rules.
7. An `Alert` is one detection result. It contains a stable ID, severity, title, description, and evidence.
8. `derive_incidents` groups alerts only when their evidence shares explicit context, such as a username or source IP.
9. An `Incident` preserves related alert IDs and evidence, and starts with status `open`.

## Incident boundary

Incident derivation is intentionally separate from detection. Detection rules continue
to produce the existing alert objects, while the incident engine consumes those
alerts and creates a higher-level correlated security situation. Incident IDs are
deterministic for the same alert set and context. Alert groups and output ordering
are deterministic.

Incident lifecycle transitions are explicit and forward-only:

```text
open → investigating → resolved → closed
open → resolved
```

Invalid, backward, and reopening transitions are rejected. No incident persistence,
case-management UI, automated response, or compromise claim is implemented.

Malformed and unsupported lines become diagnostics and do not stop other lines from being parsed. No command found in a log is executed, and the parser does not access live system logs.
