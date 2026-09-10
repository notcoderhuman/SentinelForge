# Architecture

SentinelForge's Phase 1 through Phase 6 foundation is an offline pipeline:

```text
Event → Observable Extraction → Threat Context → Detection → Alert → Correlation → Risk Assessment → Incident → Investigation → Evidence / Timeline
```

1. The ingestion reader opens explicitly supplied local text files as untrusted input.
2. The ingestion pipeline passes lines to a source-specific parser; it does not interpret log syntax itself.
3. `linux_auth.parse_lines` recognizes the documented ISO-UTC/syslog-like format.
4. Each supported line becomes an immutable `SecurityEvent`, with normalized fields and the exact raw line retained.
5. `extract_observables` conservatively extracts supported IPv4, IPv6, domain, URL, and username values from actual event fields and selected message content.
6. `match_context` performs exact matching against explicitly supplied local context; unknown values remain unknown.
7. The pipeline returns events together with non-fatal parser diagnostics.
8. `DetectionEngine` sorts events and evaluates configurable, deterministic rules.
9. An `Alert` is one detection result. It contains a stable ID, severity, title, description, evidence, and derived observables.
10. Explicit ATT&CK mappings are looked up from detection rule IDs; no runtime inference or network download is used.
11. The rule registry provides validated metadata in deterministic rule-ID order, while detection functions remain explicit Python logic.
12. `correlate_alerts` identifies only supported bounded sequences using matching account context.
13. `assess_risk` calculates a bounded transparent prioritization score from alert severity, correlations, and explicit ATT&CK mappings.
14. `derive_incidents` groups alerts only when their evidence shares explicit context, such as a username or source IP, and attaches matched local threat context.
15. An `Incident` preserves related alert IDs and evidence, and exposes derived correlations, risk, observables, and context.
16. `create_investigation` creates analytical context for exactly one incident and propagates derived data.
17. The investigation converts the incident's actual normalized events into immutable `Evidence` records and derives a chronological timeline.

## Correlation boundary

Correlation findings are not replacements for detection alerts and do not change
incident grouping. The initial findings are bounded to:

- failed authentication followed by successful authentication for the same account within 300 seconds;
- successful authentication followed by sudo activity for the same account within 300 seconds.

Each finding preserves related alert IDs, event-derived evidence IDs, a time range,
and a rationale. Different users or events outside the window do not correlate.
Correlation is an evidence pattern, not proof of compromise or misuse.

## Risk boundary

Risk is a deterministic prioritization score, not probability. The exact formula is:

```text
base = highest alert severity:
  low=10, medium=30, high=50, critical=70

correlation contribution = min(number of findings × 10, 20)
ATT&CK contribution = min(distinct mapped techniques × 5, 10)
final score = min(base + correlation contribution + ATT&CK contribution, 100)
```

Levels are `low` for 0–29, `medium` for 30–59, `high` for 60–79, and `critical`
for 80–100. Unsupported claims are never inferred, and external intelligence is
not used.

## ATT&CK mapping boundary

The mapping layer is an explicit reviewed allowlist keyed by detection rule ID.
It is deterministic, offline, source-rule-linked, and evidence-limited. A missing
mapping is intentional when the current evidence does not support a defensible
technique. These mappings are contextual metadata, not proof of adversary behavior
and not full MITRE ATT&CK coverage.

## Investigation and evidence boundary

Investigation creation is separate from detection, correlation, and incident
correlation. An alert is a single detection result; a correlation is a supported
multi-event evidence pattern; risk is a prioritization score; an incident is a
correlated security situation; an investigation is the structured context used to
examine one incident; and evidence is actual event-derived information supporting
that investigation.

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
