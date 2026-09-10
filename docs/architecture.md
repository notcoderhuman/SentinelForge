# Architecture

SentinelForge's Phase 1 through Phase 4 foundation is an offline pipeline:

```text
Event → Ingestion → Detection → Alert → Incident → Investigation → Evidence / Timeline
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
10. Explicit ATT&CK mappings are looked up from detection rule IDs; no runtime inference or network download is used.
11. Incidents derive their technique mappings from related alert rules.
12. `create_investigation` creates analytical context for exactly one incident.
13. The investigation converts the incident's actual normalized events into immutable `Evidence` records and derives a chronological timeline.

## ATT&CK mapping boundary

The mapping layer is an explicit reviewed allowlist keyed by detection rule ID.
It is deterministic, offline, source-rule-linked, and evidence-limited. A missing
mapping is intentional when the current evidence does not support a defensible
technique. These mappings are contextual metadata, not proof of adversary behavior
and not full MITRE ATT&CK coverage.

## Investigation and evidence boundary

Investigation creation is separate from detection and incident correlation. An alert
is a single detection result; an incident is a correlated security situation; an
investigation is the structured context used to examine one incident; and evidence
is actual event-derived information supporting that investigation.

Evidence contains a deterministic ID, the normalized event reference, evidence type,
source, timestamp, relevance, and provenance. Evidence cannot be created without a
real `SecurityEvent`, and its timestamp and source must match that event. Duplicate
evidence is removed during investigation creation. Timeline entries reference only
known evidence IDs and are sorted by timestamp and evidence ID.

Analyst notes are append-only from the model's perspective. They are inert caller-
supplied text and are never executed or interpreted as code.

Incident lifecycle transitions are explicit and forward-only:

```text
open → investigating → resolved → closed
open → resolved
```

Investigation statuses are limited to `active` and `completed`. No investigation
persistence, case-management UI, automated response, or compromise claim is
implemented.

Malformed and unsupported lines become diagnostics and do not stop other lines from being parsed. No command found in a log or evidence is executed, and the parser does not access live system logs.
