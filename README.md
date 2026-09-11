# SentinelForge

SentinelForge is a small, deterministic security-monitoring and detection-engineering lab for Linux authentication events. It demonstrates collection from an offline fixture, normalization, evidence-preserving parsing, rule evaluation, and structured alerts.

It is **not** an enterprise SIEM, production SOC platform, or autonomous security system. Phase 1 deliberately has no dashboard, database, network sensor, cloud integration, AI, or automated response. Phase 20 adds focused DNS telemetry coverage, and Phase 21 adds file-activity telemetry coverage, while keeping parsing offline, deterministic, and evidence-preserving.

## Architecture

`Event → observable extraction → threat context → alert / incident / investigation → evidence / timeline`

Phase 2 adds a small ingestion boundary. The reader handles explicit local file
input, while the pipeline passes lines to the existing source-specific parser and
returns normalized events plus non-fatal diagnostics. Phase 3 derives incidents
from related alerts without replacing the alert model. Phase 4 creates an
investigation from one incident, preserving event-derived evidence and a
chronological timeline. It does not add new log formats or duplicate parser logic.

The normalized `SecurityEvent` includes a timezone-aware UTC timestamp, source, event type, optional username/source IP/hostname/process, message, and the untouched raw line. Missing source data remains `None`. Phase 7 extracts conservative observables from actual event fields and selected message patterns. Local threat context is explicit demonstration metadata in `rules/threat_context.json`, not a threat feed; unknown observables remain unknown and no runtime network enrichment exists.

## Supported events

The controlled fixture format is:

`YYYY-MM-DDTHH:MM:SSZ hostname process[pid]: message`

Only `sshd` and `sudo` are supported by the Linux parser. A controlled Windows Security Event XML parser is also available through explicit `--source windows_security` selection. It supports event IDs 4624, 4625, and 4672, mapping them to successful authentication, failed authentication, and privileged logon. This is fixture-based parsing only; it does not access live Windows Event Logs or support every Windows XML variant.

## Detections

- `SSH_BRUTE_FORCE`: five failures from one IP within 120 seconds (high).
- `REPEATED_AUTH_FAILURE`: three failures for one account within 120 seconds (medium).
- `SUCCESS_AFTER_FAILURES`: same-account success after a failure within 300 seconds (medium).
- `SUSPICIOUS_SUDO_ACTIVITY`: observed sudo command (low).
- `SOURCE_TARGETS_MULTIPLE_ACCOUNTS`: three distinct accounts targeted by one source IP within 120 seconds (medium).
- `ACCOUNT_TARGETED_BY_MULTIPLE_SOURCES`: one account targeted by three distinct source IPs within 120 seconds (medium).
- `WINDOWS_PRIVILEGED_LOGON`: Windows Event ID 4672 observed with an explicit user (low).

Phase 20 DNS telemetry is newline-delimited JSON selected explicitly with `--source dns_query` (the `dns` alias is also accepted). Its four bounded observations are `DNS_QUERY_TO_SUSPICIOUS_DOMAIN`, `REPEATED_DNS_QUERY`, `SOURCE_QUERIES_MANY_DOMAINS`, and `DOMAIN_QUERIED_BY_MANY_SOURCES`. DNS query names use exact local threat-context matches; missing identities remain missing, malformed records become diagnostics, and no DNS event is treated as network connection activity.

Phase 21 file activity telemetry is newline-delimited JSON selected with `--source file_activity` (the parser also accepts the `file` alias). Required fields are timestamp, hostname, path, action, and username; optional hash, old path, and non-negative size values are validated and preserved. The four conservative observations are `REPEATED_FILE_ACTIVITY`, `HOST_MODIFIES_MANY_DISTINCT_FILES`, `EXECUTABLE_FILE_CREATED`, and `FILE_ACTIVITY_ON_SENSITIVE_PATH`. File paths use exact local `file_path` context matching, action is required for executable creation, missing identities never create grouping matches, and file records are never executed or treated as process/network/DNS telemetry.

Phase 22 system-persistence telemetry is newline-delimited JSON selected explicitly with `--source system_persistence` (the `persistence` alias is accepted only where source aliases are supported). Required fields are `timestamp`, `hostname`, `username`, `persistence_type`, `action`, and `name`; persistence types are limited to `service`, `scheduled_task`, and `cron`. Optional command, service-manager, task-path, process/process-name, executable, privilege, and process-ID fields are normalized without invention and retained as evidence. Valid records are normalized as `system_persistence` events. Phase 22 alerts are intentionally unmapped to ATT&CK because they report explicit telemetry rather than inferred execution or compromise. Invalid JSON, missing required fields, timezone-less timestamps, unsupported persistence types, and invalid numeric IDs become non-fatal diagnostics. Persistence records are data only: commands are never executed, and local SQLite round trips preserve their normalized fields.

Phase 24 Windows system-event telemetry is newline-delimited JSON selected with `--source windows_system_event`. It extends Windows telemetry without replacing the existing Windows Security authentication parser for 4624, 4625, and 4672. Required fields are timestamp, hostname, event_id, provider, and action; optional service, process, command, and message fields are normalized and preserved. Four unmapped, standalone observations report explicit service state, stopped service state, stopped-to-running transitions within an inclusive 300-second window, and configuration-related events with an explicit command. No execution, persistence, compromise, or maliciousness is inferred; no live Event Log access is performed.

Phase 23 registry telemetry is newline-delimited JSON selected explicitly with `--source registry_change` (the `registry` alias is also accepted by source routing). Required fields identify the timestamp, host, user, hive, exact key path, registry action, and value; normalized events preserve hive, key path, action, value name/data/type, and exact raw JSON. Detection is limited to four registered observations: set values, deleted keys, exact Run/RunOnce key modifications, and aggregate activity by many explicit processes. Only exact `HKCU`/`HKLM` `Software\\Microsoft\\Windows\\CurrentVersion\\Run` and `RunOnce` paths qualify; near paths and other hives do not. Malformed records, unsupported hives/paths, missing identities, invalid timestamps, and wrong field types become non-fatal diagnostics. Registry values are inert evidence: no registry access, process execution, path access, or external enrichment occurs, and normalized fields round-trip through local SQLite persistence.

Phase 25 adds deterministic replay with `sentinelforge replay <input> --source <source> --json`. Replay reuses the existing detection engine, preserves alert IDs/evidence, emits deterministic evidence-derived explanations, and can compare results with an expected JSON file containing an `alerts` list of `rule_id`, `severity`, and `count` (optionally stable `alert_ids` and `evidence_ids`). Evaluation reports matched, missing, unexpected, rule-level counts, and corpus-only true-positive/false-positive/false-negative metrics with precision and recall. Zero denominators are reported as 0.0. Expected-result mismatches return a nonzero replay exit status. Explanations are deterministic and evidence-derived; these metrics describe only the supplied evaluation corpus, not real-world detection accuracy. Replay also reports observational event/alert counts and elapsed processing time, not a production throughput benchmark.

Phase 26 adds the Investigation Package (`sentinelforge package <input> --source <source> --json`), a deterministic boundary between detection and any future analyst/LLM layer. The package is a self-contained machine-readable structure containing alerts, evidence, provenance, diagnostics, and chronology. Legacy null evidence IDs are resolved to stable deterministic identifiers. Cross-source alerts expose all contributing telemetry sources rather than just the first one. The `package_id` is a hash of stable content only — `generated_at` does not affect identity. See [investigation package documentation](docs/architecture.md).

Phase 27 adds an optional LLM analyst layer (`sentinelforge analyze-with-llm <input> --source <source> --provider mock`). It consumes only the canonical Investigation Package and produces a structured, validated `AnalystAssessment`. The analyst is NOT the detection engine: it does not create, modify, or suppress alerts, change severity, determine compromise, or perform any autonomous action. Output goes through deterministic validation that checks package ID, alert/evidence ID references, required sections, type correctness, confidence-level validity, and unsupported security claims. The LLM is opt-in — existing commands remain unchanged. Use `--provider none` to preview the exact prompt that would be sent without making a network request. Providers include a deterministic `mock` provider for testing and a configurable `deepseek` provider; new providers implement the `AnalystProvider` interface. Model output is advisory — human review remains required for consequential decisions.

An alert is one detection result. Correlation findings identify supported
multi-event evidence patterns, and risk assessment provides deterministic
prioritization; neither is probability or proof of compromise. Explicit ATT&CK mappings are linked to detection
rule IDs and are only added where the evidence supports them. An incident is a
deterministic correlation of alerts that share explicit evidence context, such as
the same username or source IP. An investigation is the structured analytical
context for exactly one incident. It preserves actual event-derived evidence and a
chronological timeline; it does not establish compromise. Incidents begin `open`
and support the forward transitions `investigating`, `resolved`, and `closed`;
`open → resolved` is also allowed.

Risk scoring uses the highest alert severity as its base (`low=10`, `medium=30`, `high=50`, `critical=70`), adds 10 points per supported correlation finding up to 20, adds 5 points per distinct explicit ATT&CK technique up to 10, and caps the score at 100. Levels are `low` (0–29), `medium` (30–59), `high` (60–79), and `critical` (80–100). This is a transparent prioritization score, not probability.

Rule metadata is held in an explicit deterministic registry, while detection logic remains in readable Python functions. Rule IDs are stable and registry iteration is deterministic; metadata files are never executed. Thresholds are represented by `RuleConfig`; `rules/auth_rules.yaml` is a human-readable reference. See [detection documentation](docs/detections.md).

## Installation and usage

Python 3.9+ is required. There are no runtime dependencies.

```text
python -m sentinelforge parse fixtures/auth.log
python -m sentinelforge detect fixtures/auth.log
python -m sentinelforge incident fixtures/auth.log
python -m sentinelforge investigate fixtures/auth.log
python -m sentinelforge observables fixtures/auth.log
python -m sentinelforge analyze fixtures/auth.log
python -m sentinelforge analyze fixtures/auth.log --json
python -m sentinelforge analyze fixtures/auth.log --severity high
python -m sentinelforge analyze fixtures/windows-security.xml --source windows_security
python -m sentinelforge analyze fixtures/windows-security.xml --source windows_security --json
python -m sentinelforge analyze fixtures/network-phase17.ndjson --source network_connection --json
python -m sentinelforge analyze fixtures/process-phase18.ndjson --source process_execution --json
python -m sentinelforge analyze fixtures/dns-phase20.ndjson --source dns_query --json
python -m sentinelforge analyze fixtures/auth.log --database data/sentinelforge.db
python -m sentinelforge history --database data/sentinelforge.db
python -m sentinelforge serve --host 127.0.0.1 --port 8765 --database data/sentinelforge.db
# Then open http://127.0.0.1:8765/ in a browser
python -m sentinelforge analyze-with-llm fixtures/auth.log --source linux_auth --provider none
python -m sentinelforge analyze-with-llm fixtures/auth.log --source linux_auth --provider mock
python -m sentinelforge analyze-with-llm fixtures/auth.log --source linux_auth --provider mock --json
python -m sentinelforge analyze-with-llm fixtures/auth.log --source linux_auth --provider mock --strict
# DeepSeek requires a configured API key (DEEPSEEK_API_KEY env var):
python -m sentinelforge analyze-with-llm fixtures/auth.log --provider deepseek --model deepseek-chat
```

The CLI reads only the path explicitly supplied by the user and emits JSON. The `analyze` command provides a concise human-readable report by default or deterministic structured output with `--json`. It supports display-only `--severity` and `--incident` filters. Optional local SQLite persistence is enabled with `--database`; `history` lists stored analysis runs. SQLite is local-only, versioned, and does not add cross-run correlation. A local development HTTP API and SOC web console are available with `serve`; it binds to loopback by default, serves the console at `http://127.0.0.1:8765/`, and exposes the public `/health` endpoint plus authenticated persisted read endpoints and POST `/analyze`. Create the first administrator explicitly with `python -m sentinelforge user create-admin --database data/sentinelforge.db`; passwords are entered interactively and never stored in plaintext. The API uses expiring server-side sessions, HttpOnly SameSite cookies, CSRF/origin checks, roles (`admin`, `analyst`, `viewer`), and append-only audit records. Protected endpoints require login; viewers are read-only, analysts may run analysis, and admins may manage users and view audit records. Login failures are rate-limited in memory and reset on process restart. This remains a local analyst/development service, not a production internet-facing identity system; there is no external identity provider, SSO, or public deployment support. The browser consumes API data only and analyst notes are read-only. CLI and API share the same application/reporting orchestration. The CLI uses the local ingestion reader and parsers, never executes log content, and never opens live system logs. An installed package also provides the `sentinelforge` command.

## Testing

Run:

```text
python -m unittest discover -v
python -m compileall src
```

Tests use only in-memory strings and repository fixtures; pytest is not required.

## Security scope and limitations

This is defensive software for learning and portfolio demonstration. Alerts describe observed evidence and cautious interpretations; failed and successful authentication patterns do not prove compromise. Input formats are intentionally narrow, timestamp handling is fixture-specific, and the project does not ingest every Linux distribution's auth format. Network telemetry is line-oriented JSON, uses exact local threat-context matches only, and reports observed connection patterns without labeling them as malware or command-and-control. Process telemetry is also line-oriented JSON; process names and command lines are treated only as data, never executed. Cross-source correlation links explicit authentication, network, and process event relationships within inclusive 300-second windows, requiring available identity fields to match and never claiming compromise. Correlations are deterministic and evidence-backed. All telemetry analysis performs no network access, subprocess execution, AI/LLM processing, or external enrichment. The investigation package is a deterministic representation of available evidence; it does not establish compromise, malware, attacker attribution, or intent. Do not commit real logs, credentials, or secrets.
