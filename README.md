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

This is defensive software for learning and portfolio demonstration. Alerts describe observed evidence and cautious interpretations; failed and successful authentication patterns do not prove compromise. Input formats are intentionally narrow, timestamp handling is fixture-specific, and the project does not ingest every Linux distribution's auth format. Network telemetry is line-oriented JSON, uses exact local threat-context matches only, and reports observed connection patterns without labeling them as malware or command-and-control. Process telemetry is also line-oriented JSON; process names and command lines are treated only as data, never executed. Cross-source correlation links explicit authentication, network, and process event relationships within inclusive 300-second windows, requiring available identity fields to match and never claiming compromise. Correlations are deterministic and evidence-backed. All telemetry analysis performs no network access, subprocess execution, AI/LLM processing, or external enrichment. Do not commit real logs, credentials, or secrets.
