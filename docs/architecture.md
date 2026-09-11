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

## Phase 17 network telemetry boundary

The `network_connection` source accepts one JSON object per line with required
`timestamp`, `source_ip`, `source_port`, `destination_ip`, `destination_port`,
and `protocol` fields, plus optional process, username, and direction fields.
Malformed records become diagnostics while valid records continue through the
existing normalized event, detection, alert, incident, investigation, evidence,
and risk pipeline. Network rules use deterministic 120-second windows and report
only observed connection patterns. Suspicious IP matching reuses the existing
local threat-context file; no network access, reputation lookup, malware claim,
or code execution is performed.

## Phase 18 process telemetry boundary

The `process_execution` source accepts one JSON object per line with required
`timestamp`, `hostname`, `process_name`, `process_id`, and `username` fields.
Optional fields include `parent_process_id`, `command_line`, `executable_path`,
and explicit `privilege`. Process IDs are bounded integers and malformed
records become diagnostics. The parser preserves raw JSON and treats command
lines and executable paths strictly as data; it never executes them.

Detections report only explicitly privileged execution, repeated executions,
parent processes associated with many distinct children, and users executing
many distinct process names. These are conservative observations, not malware,
persistence, lateral movement, exploitation, LOLBin, or command-and-control
claims. The source performs no subprocess execution, network access, or
external enrichment.

## Phase 19 cross-source correlation boundary

Cross-source correlation is an additive deterministic stage over normalized
authentication, `network_connection`, and `process_execution` events. It emits
existing `Alert` objects for authentication-to-network, network-to-process,
authentication-to-process, and complete authentication-network-process chains.
Each relationship uses an inclusive 300-second window and requires chronological
ordering. Usernames match only when both sides provide equal usernames;
hostnames match only when both sides provide equal hostnames. Missing identity
values are never treated as matches, and network ownership is never inferred
from process IDs or names. Alerts preserve the original participating events,
flow through existing incidents, investigations, evidence, risk, persistence,
and API output, and make no claim of compromise. IDs and evidence ordering are
stable under input reordering; duplicate relationships are suppressed. No
AI/LLM processing, network enrichment, subprocess execution, or external
service is involved.

## Phase 20 DNS telemetry boundary

The `dns_query` source accepts newline-delimited JSON records with required `timestamp`, `hostname`, `query`, and `query_type` fields. The optional `response_code`, `source_ip`, `source_port`, `answers`, username, and direction fields are validated when present; the first valid address in `answers` may populate `resolved_ip` while all answers remain evidence. DNS query identity is required for detection, and hostname is required for source-based grouping. The source is selected explicitly with `--source dns_query`. Valid records become normalized DNS events with their exact raw JSON retained; malformed or incomplete records become non-fatal diagnostics. DNS detections are four bounded, deterministic observations: exact local-context matches for suspicious domains, repeated queries, one source querying many distinct domains, and one domain queried by many distinct sources. The relationship window is inclusive at 120 seconds and excludes 121 seconds. Missing identities never create matches, reversed input produces stable IDs and evidence ordering, and DNS events do not enter network-connection correlation. No resolver, reputation lookup, network access, or command execution is performed.

## Phase 21 file activity telemetry boundary

The `file_activity` source accepts newline-delimited JSON records with required `timestamp`, `hostname`, `path`, `action`, and `username` fields. Optional `file_hash`, `old_path`, and non-negative integer `size` fields are validated when present. Valid records become normalized `file_activity` events with exact raw JSON retained; malformed, incomplete, timezone-less, or type-invalid records become non-fatal diagnostics. The explicit `file` parser alias is supported at ingestion, while application and API source selection remains explicit.

File detections are four bounded observations: repeated activity on one exact path, one host modifying many distinct paths, creation of an executable-looking path, and exact local suspicious `file_path` context matches. Repeated and distinct-path rules use inclusive 120-second windows and exclude 121 seconds; grouping requires explicit hostname and path values, and duplicate paths do not satisfy distinctness. Sensitive-path matching is exact and executable detection requires the `create` action. File events remain isolated from authentication, DNS, network, and process detections and are never executed, hashed, enriched, or used for filesystem access. File fields round-trip through the existing optional SQLite persistence boundary.

## Phase 22 system-persistence telemetry boundary

The `system_persistence` source accepts newline-delimited JSON with required `timestamp`, `hostname`, `username`, `persistence_type`, `action`, and `name` fields. `persistence_type` is one of `service`, `scheduled_task`, or `cron`; optional command, service manager, task path, process/process-name, executable, privilege, and bounded process-ID fields are validated and normalized. Valid records become `system_persistence` events with exact raw JSON retained. Malformed JSON, incomplete records, timezone-less timestamps, unsupported persistence types, wrong optional types, and invalid numeric IDs are non-fatal diagnostics. Source selection is explicit and does not infer a parser from content.

Phase 22 detections are four deterministic observations over explicit persistence telemetry: `SERVICE_CREATED_OR_UPDATED` matches service create/update events; `SCHEDULED_TASK_CREATED_OR_UPDATED` matches scheduled-task or cron create/update events; `SERVICE_STARTED_AFTER_CREATION` correlates a service create/update with a later matching service start for the same explicit hostname, username, and service name within an inclusive 300-second window; and `SCHEDULED_TASK_CREATED_WITH_COMMAND` matches scheduled-task or cron create/update events with a non-empty command. Missing identities never correlate, duplicate relationships are suppressed, and alert IDs/evidence ordering are stable under input reversal. Persistence events do not participate in Phase 19 authentication/network/process relationships. Commands and paths are inert data and are never executed or used for filesystem access. Normalized persistence fields round-trip through the optional SQLite repository boundary.

## Phase 23 Registry telemetry boundary

The `registry_change` source accepts newline-delimited JSON registry-change records (with a `registry` source alias in routing). Records normalize timestamp, hostname, username, hive, exact key path, registry action, value name/data/type, and preserve the raw JSON. Only `HKCU` and `HKLM` exact `Software\\Microsoft\\Windows\\CurrentVersion\\Run` or `RunOnce` paths are eligible. Four observations cover set-value activity, deleted keys, exact Run/RunOnce key modifications, and aggregate activity by many explicit processes. Unsupported hives or near-match paths are diagnostics rather than matches; malformed JSON, missing fields, timezone-less timestamps, and wrong types are non-fatal. Grouping requires explicit host/user identity, duplicate relationships are suppressed, and reversed input produces stable IDs/evidence ordering. Registry telemetry remains isolated from authentication, DNS, file, network, process, and persistence detections. Values and paths are inert data: no Windows Registry access, subprocess execution, filesystem access, or enrichment occurs. Normalized registry fields round-trip through the optional SQLite repository boundary.

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

## Authentication, authorization, and audit boundary

`GET /health` is intentionally public and reports only minimal service status;
all analysis, account, audit, and session information remains protected.

Phase 16 adds standard-library authentication primitives under `sentinelforge.auth`.
Passwords use salted `hashlib.scrypt` hashes with encoded parameters and constant-time
verification. Users are stored in SQLite with roles `admin`, `analyst`, or `viewer`.
Sessions are server-side, cryptographically random, expiring, and represented to
browsers by HttpOnly, SameSite=Lax cookies. A separate non-HttpOnly CSRF cookie is
checked against a server-side session hash for state-changing requests; local Host
and Origin values are also validated.

Protected analysis resources require authentication. Analysts may run analysis;
viewers are read-only; admins may manage users and read audit records. Audit records
are append-only application records and never contain passwords, password hashes,
session secrets, or CSRF tokens. Login failures use a bounded in-memory local rate
limiter that resets on process restart. The first administrator is created explicitly
with `python -m sentinelforge user create-admin --database PATH`, using hidden
interactive password input. There is no default credential, external identity
provider, SSO, or public deployment support. This remains a local development and
analyst service, not an internet-facing identity system.

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
