# Architecture

SentinelForge's Phase 1 through Phase 6 foundation is an offline pipeline:

```text
Event → Observable Extraction → Threat Context → Detection → Alert → Correlation → Risk Assessment → Incident → Investigation → Evidence / Timeline
```

1. The ingestion reader opens explicitly supplied local text files as untrusted input.
2. The ingestion pipeline passes lines to a source-specific parser; it does not interpret log syntax itself.
3. `linux_auth.parse_lines` recognizes the documented ISO-UTC/syslog-like format; `windows_security.parse_file` explicitly parses the controlled Windows Security Event XML fixture format.
4. Each supported line becomes an immutable `SecurityEvent`, with normalized fields and the exact raw line retained.
5. `extract_observables` conservatively extracts supported IPv4, IPv6, domain, URL, and username values from actual event fields and selected message content.
6. `match_context` performs exact matching against explicitly supplied local context; unknown values remain unknown.
7. The pipeline returns events together with non-fatal parser diagnostics.
8. `DetectionEngine` sorts events and evaluates configurable, deterministic rules, including bounded source/account relationship detections and the focused Windows 4672 observation rule supported by the normalized telemetry.
9. An `Alert` is one detection result. It contains a stable ID, severity, title, description, evidence, and derived observables.
10. Explicit ATT&CK mappings are looked up from detection rule IDs; no runtime inference or network download is used.
11. The rule registry provides validated metadata in deterministic rule-ID order, while detection functions remain explicit Python logic.
12. `correlate_alerts` identifies only supported bounded sequences using matching account context.
13. `assess_risk` calculates a bounded transparent prioritization score from alert severity, correlations, and explicit ATT&CK mappings.
14. `derive_incidents` groups alerts only when their evidence shares explicit context, such as a username or source IP, and attaches matched local threat context.
15. An `Incident` preserves related alert IDs and evidence, and exposes derived correlations, risk, observables, and context.
16. `create_investigation` creates analytical context for exactly one incident and propagates derived data.
17. The investigation converts the incident's actual normalized events into immutable `Evidence` records and derives a chronological timeline.
18. The `analyze` command orchestrates these existing components and passes their results to the reporting layer.
19. Optional local SQLite persistence stores validated analysis runs and derived alerts, incidents, investigations, evidence, and notes behind a repository boundary.
20. The local HTTP API exposes transport-only routes over the same application orchestration and repository boundary; it does not duplicate security logic.

## Persistence boundary

Phase 13 adds an optional local SQLite boundary. `Database` owns schema
initialization, foreign-key enforcement, schema versioning, and transactions;
`AnalysisRepository` stores domain serialization without placing SQL in detection,
correlation, risk, incident, or investigation logic. Persistence is idempotent by
stable entity IDs and does not perform cross-run correlation. The database path is
always explicitly supplied by `--database`.

## Local HTTP API boundary

Phase 14 adds a standard-library `http.server` interface in `sentinelforge.api`.
`ApiOperations` dispatches validated requests to application functions, while
handlers only perform HTTP transport and JSON encoding. The `serve` command binds
to `127.0.0.1` by default; host and port are explicit options. Endpoints are:

- `GET /health`
- `GET /runs?limit=20`
- `GET /alerts?severity=high`
- `GET /incidents?severity=high`
- `GET /investigations`
- `GET /alerts/{alert_id}`
- `GET /incidents/{incident_id}`
- `GET /investigations/{investigation_id}`
- `POST /analyze`

`POST /analyze` accepts `path`, `source`, and optional `severity`, `incident_id`,
and `database`, returning the same structured report as the existing reporting
layer. Read endpoints use `AnalysisRepository`; no arbitrary SQL, filesystem read,
configuration mutation, or note mutation endpoint exists. Request bodies are
bounded and validated, paths remain local to the working directory, errors are
concise JSON, and broad CORS is intentionally absent. This is a local
development/analyst interface, not an authenticated production service.

## SOC web console boundary

Phase 15 adds a plain HTML/CSS/JavaScript analyst console in `web/`. Only the
known assets `/`, `/index.html`, `/styles.css`, and `/app.js` are served by the
local API server; arbitrary filesystem paths, source files, and databases are
never exposed. The browser uses a small API client for health, runs, alerts,
incidents, investigations, detail views, and POST `/analyze`. It does not read
local files or implement detection, correlation, risk, ATT&CK, or persistence
logic.

The console provides Overview, Alerts, Incidents, Investigations, and Runs pages,
read-only details, filters, empty/error states, API status, and analysis input.
Analyst notes are read-only because no authenticated write API exists. Start it
with `python -m sentinelforge serve --host 127.0.0.1 --port 8765 --database
data/sentinelforge.db`, then open `http://127.0.0.1:8765/`. This is a local
development/analyst interface with no authentication, RBAC, or public deployment
support.

## Analyst reporting boundary

The `analyze` command is a thin orchestration layer over the existing ingestion,
detection, observable/context, incident, and investigation components. Reporting
contains presentation and filtering logic only. Default output is a concise human-
readable summary; `--json` returns deterministic structured results. Severity and
incident filters affect displayed results only and do not alter detection behavior.

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
