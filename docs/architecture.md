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

## Phase 24 Windows system-event telemetry boundary

The `windows_system_event` source accepts newline-delimited JSON and is additive to, rather than a replacement for, the Windows Security XML parser covering authentication events 4624, 4625, and 4672. Required fields are timestamp, hostname, event ID, provider, and action. Optional username, process, executable, service, state, command, and message fields use explicit normalized values; service names are stripped without case folding or alias invention. Four standalone observations cover supported service states, stopped services, stopped-to-running service relationships within an inclusive 300-second window, and configuration-related events with an explicit command. Alerts are unmapped to ATT&CK and do not infer execution, persistence, compromise, maliciousness, or attribution. Records remain inert evidence; no Windows Event Log API, PowerShell, WMI, subprocess, or live host access is used. Windows system events are isolated from all existing cross-source correlations and round-trip through the optional SQLite payload repository.

## Phase 26 Investigation Package boundary

Phase 26 adds the Investigation Package — a deterministic boundary between detection and any future analyst/LLM consumer. The package is a self-contained, immutable, machine-readable structure capturing one incident's alerts, evidence, provenance, diagnostics, and chronology. It is produced by `build_package(alerts, diagnostics, incident)` or the CLI command `sentinelforge package <input> --source <source> --json`.

### Package schema

| Field | Type | Description |
|-------|------|-------------|
| `package_version` | string | Schema version (currently `"1"`) |
| `package_id` | string | 16-hex-char SHA-256 of stable content only |
| `generated_at` | string | UTC ISO-8601 timestamp (not in identity hash) |
| `incident` | dict or null | Embedded incident metadata when available |
| `alerts` | list of alert objects | Sorted by `(timestamp, alert_id)` |
| `evidence` | list of evidence objects | Deduplicated, sorted by `(timestamp, evidence_id)` |
| `diagnostics` | list of diagnostic objects | Parser rejections and ingestion failures |
| `chronology` | list of chronology entries | Deterministic timestamp-ordered sequence |
| `coverage` | coverage summary | Explicit counts and metadata |

### Canonical evidence identity

Every evidence item in a package has a stable `evidence_id`:

- If the source event already carries a non-empty `event_id`, it is preserved unchanged.
- Otherwise, a 16-hex-char SHA-256 digest of the canonicalized event content (timestamp, event type, source, hostname, username, message, raw) is generated. This digest is independent of array position, runtime IDs, input ordering, and generation metadata.

### Provenance model

Each evidence item records its telemetry `source` (e.g., `"linux-auth"`, `"network_connection"`). Each alert item records two provenance fields:

| Field | Description |
|-------|-------------|
| `detection_source` | The legacy alert `source` field (the rule family). |
| `contributing_sources` | *All* distinct telemetry sources present in the alert's evidence, sorted deterministically. This fixes the Phase 25 issue where cross-source alerts carried only a single source label. |

### Diagnostics / coverage semantics

Parser rejections are preserved as `PackageDiagnostic` objects with `telemetry_was_accepted: false`. The coverage summary reports explicit counts — no single "quality score" is computed. Contact coverage categories are:

- `no telemetry observed` — implicit (no evidence item in package)
- `telemetry received but rejected` — explicit diagnostic item
- `telemetry accepted with no alert` — implicit (evidence item exists without matching alert reference)

### Chronology ordering

The chronology is sorted by (1) timestamp ascending, (2) kind (`"evidence"` before `"alert"` for identical timestamps), (3) identifier as tie-breaker. This ordering is independent of input sequence.

### Canonical serialization

All list fields are sorted deterministically. `generated_at` is included in `to_dict()` but excluded from the `package_id` hash input. Repeated `to_dict()` calls on the same package produce identical output.

### Package identity

The `package_id` is a 16-hex-char SHA-256 digest of the serialized `package_version`, `incident`, `alerts`, `evidence`, `diagnostics`, and `chronology` — an ephemeral field. Changing any alert or evidence content changes the ID. Reordering equivalent input does not change the ID.

### Legacy null-ID handling

The Phase 25 LLM experiment exposed that alerts from certain sources (e.g., `linux-auth`) contain `null` evidence IDs. The Investigation Package resolves every `null` to a deterministic hash-based `evidence_id` at the package layer. The original alert objects are not modified.

### No security claims

The package is a deterministic representation of available evidence. It does not establish compromise, malware, attacker attribution, or intent. This is stated explicitly in the serialized output and in the documentation.

## Phase 27 and beyond

Phase 27 adds an optional LLM analyst layer that consumes only the canonical
Investigation Package (Phase 26) and produces a structured, validated
`AnalystAssessment`. The detection engine, correlations, and package remain
authoritative — the LLM is advisory.

```text
Telemetry
    ↓
DetectionEngine
    ↓
InvestigationPackage     ← deterministic, authoritative
    ↓
AnalystProvider          ← optional, opt-in
    ↓
LLM Analyst Output
    ↓
Output Validation        ← deterministic: schema, references, claims
    ↓
Validated AnalystAssessment
```

### Architecture

- **`sentinelforge/analyst.py`**: Provider abstraction (`AnalystProvider`),
  schema dataclasses (`AnalystAssessment`, `AnalystFact`, etc.), prompt builder
  (`build_analyst_prompt`), and `ValidationResult`.
- **`sentinelforge/analyst/_validator.py`**: Deterministic output validation:
  package ID matching, required section checks, alert/evidence ID citation
  validation, type checking, confidence level validation, unsupported-claim
  detection (warnings by default, errors in `--strict` mode).
- **`sentinelforge/analyst/mock.py`**: Deterministic mock provider for tests,
  returning configurable canned scenarios (valid, invalid IDs, unsupported
  claims, malformed structure, etc.).
- **`sentinelforge/analyst/deepseek.py`**: Real DeepSeek Chat Completions
  provider using only `urllib` (no external dependencies). Configuration is
  via constructor args or environment variables (`DEEPSEEK_API_KEY`,
  `DEEPSEEK_ENDPOINT`, `DEEPSEEK_MODEL`).

### Provider interface

`AnalystProvider` is abstract with a single method:

```python
def analyze(self, package_dict: Dict[str, Any], **kwargs: Any) -> str:
    """Return raw model response (expected JSON)."""
```

Factory: `AnalystProvider.create("mock"|"deepseek", **config)`.

### Key design rules

1. **No network by default** — existing commands work without an LLM. The
   `--provider none` flag builds the package and prints the prompt preview
   without making any request.
2. **Only the canonical package is sent** — no raw filesystem paths, secrets,
   environment variables, or API keys are in the prompt.
3. **Telemetry is DATA, not instructions** — the prompt explicitly warns the
   model not to obey instructions found inside command_line, message, raw
   evidence, DNS names, file contents, or registry values.
4. **Output validation is deterministic** — mismatched package IDs, missing
   sections, invented alert/evidence IDs, wrong types, and unsupported
   confidence levels are errors. Strong claims (compromise, malware, attacker
   attribution, persistence success, execution confirmed) are warnings by
   default, errors in `--strict` mode.
5. **No alert/package mutation** — the package is read-only. The LLM does not
   create, modify, or suppress alerts, change severity, or perform any action.
6. **No persistence** — Phase 27 does not store analyst results in the SQLite
   database. Results are ephemeral CLI output.
7. **No web console integration** — Phase 27 is CLI/library only.

### Limitations

- The validator checks that referenced alert/evidence IDs exist in the
  package, but does not verify that the cited evidence actually supports the
  model's textual claim. Semantic correctness is not guaranteed.
- Timeline arithmetic (e.g., "7 minutes 30 seconds") is text-level and not
  validated against the package chronology.
- Missing-telemetry-implying-clean-host is not detectable by the validator.
- The DeepSeek provider requires external credentials and network access.
  No live API call is made in the automated test suite.
- Model output is inherently probabilistic — the same package may produce
  different outputs across calls. The provider defaults to temperature=0.0
  for maximum determinism but identical output is not guaranteed.

### CLI usage

```text
# Offline/validation mode — preview the prompt, no network call
python -m sentinelforge analyze-with-llm fixtures/auth.log --source linux_auth --provider none

# Mock provider for testing validation
python -m sentinelforge analyze-with-llm fixtures/auth.log --source linux_auth --provider mock

# Full validated output as JSON
python -m sentinelforge analyze-with-llm fixtures/auth.log --source linux_auth --provider mock --json

# Strict mode — unsupported claim warnings become errors
python -m sentinelforge analyze-with-llm fixtures/auth.log --source linux_auth --provider mock --strict

# DeepSeek (requires DEEPSEEK_API_KEY in environment or --provider deepseek)
python -m sentinelforge analyze-with-llm fixtures/auth.log --source linux_auth --provider deepseek
```

### Testing

The test suite (`tests/test_phase27.py`) covers:

- Provider interface and factory
- Mock provider (8 scenarios)
- Schema construction and serialization
- Validator evidence citation (valid, invalid, missing, mismatched)
- Security claim guardrails (9 patterns, strict mode)
- Prompt builder (package content, DATA instruction, no secrets)
- Integration with real package + mock provider
- CLI offline mode, mock mode, invalid provider, help
- DeepSeek configuration (no live API call)
- Adversarial corpus (10 known LLM failure patterns)
- Regression (Phase 1–26 behavior unchanged)

All tests use only in-memory data and repository fixtures — no network calls
are required.

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

## Server-side queryability boundary

Phase 30 extends the existing authenticated list resources without changing their
array response shapes. `GET /alerts` accepts exact `severity`, `rule_id`, `source`,
`run_id`, ISO-8601 `since`/`until`, and bounded `limit` filters. `GET /incidents`
accepts exact `severity`, `status`, `risk_level`, `run_id`, numeric
`min_risk_score`/`max_risk_score`, timestamp bounds, and `limit`. `GET
/investigations` accepts exact `status`, `incident_id`, timestamp bounds, and
`limit`. `GET /runs` accepts exact `source`, timestamp bounds, and `limit`.

Supported query names are allowlisted; unknown names, malformed enums/IDs,
non-timezone timestamps, invalid numeric scores, reversed ranges, and limits
outside 1–1000 return HTTP 400. Timestamp bounds are normalized to UTC and are
inclusive. Persisted analysis timestamps are canonicalized to UTC `Z` form at
repository write boundaries; pre-existing historical rows are not rewritten and
are outside the canonical-storage guarantee. Query values are parameterized; JSON filters use only fixed internal
paths. No query parameter selects a database path. Existing no-parameter calls,
severity calls, detail routes, and `GET /runs?limit=N` retain their array-shaped
responses and default row-order compatibility. Requests using query filters use
explicit deterministic descending timestamp/update ordering with stable ID
secondary keys, and apply SQL limits after filtering.

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

Investigation statuses are limited to `active` and `completed`. Authenticated case
workflow mutations are exposed through `POST /incidents/{id}/status`,
`POST /investigations/{id}/status`, and `POST /investigations/{id}/notes`.
The `MANAGE_CASES` permission is granted only to analysts and administrators;
viewers remain read-only. Browser mutations use the existing Origin and CSRF
validation path; a present Origin must be allowed, while requests without an
Origin are accepted by the current same-origin policy. Status bodies contain only `status`, note bodies contain
only `content`, and actor identity is always taken from the authenticated
server-side session. Incident transitions remain `open → investigating`,
`open → resolved`, `investigating → resolved`, and `resolved → closed`;
investigations support `active → completed`. Repeating the current status is a
200 idempotent no-op and does not update timestamps or create mutation audit
records. Notes are append-only, server-authored, bounded to 16 KiB UTF-8, and
cannot be edited or deleted.

Each real mutation updates the JSON payload and relational timestamp, then
inserts its audit row in the same SQLite transaction. Audit actions are
`incident_status_transition`, `investigation_status_transition`, and
`investigation_note_create`, with resources `incident`, `investigation`, and
`investigation_note`. Audit details contain only bounded transition metadata or
note author/content length; they never contain secrets, tokens, or raw evidence.
Conditional status and payload timestamp updates prevent stale concurrent requests
from overwriting a committed state; conflicting requests return 409. Case writes
reserve the SQLite write lock before reading mutable state. A temporary SQLite
lock is returned as a generic 503 response without exposing database details. A
failed audit insertion rolls back the case mutation. Existing GET response shapes, IDs, detection semantics,
risk, evidence, timeline, InvestigationPackage behavior, and query semantics
remain unchanged. No investigation persistence, case-management UI, automated
response, or compromise claim is implemented.

Malformed and unsupported lines become diagnostics and do not stop other lines from being parsed. No command found in a log or evidence is executed, and the parser does not access live system logs.
