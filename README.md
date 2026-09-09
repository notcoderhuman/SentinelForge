# SentinelForge

SentinelForge is a small, deterministic security-monitoring and detection-engineering lab for Linux authentication events. It demonstrates collection from an offline fixture, normalization, evidence-preserving parsing, rule evaluation, and structured alerts.

It is **not** an enterprise SIEM, production SOC platform, or autonomous security system. Phase 1 deliberately has no dashboard, database, network sensor, cloud integration, AI, or automated response.

## Architecture

`Linux auth fixture → parser → normalized event → detection engine → alert`

The normalized `SecurityEvent` includes a timezone-aware UTC timestamp, source, event type, optional username/source IP/hostname/process, message, and the untouched raw line. Missing source data remains `None`.

## Supported events

The controlled fixture format is:

`YYYY-MM-DDTHH:MM:SSZ hostname process[pid]: message`

Only `sshd` and `sudo` are supported. The parser recognizes failed password, invalid user, accepted password, and sudo lines containing `user=` and `command=`. Other lines produce diagnostics rather than being silently reinterpreted.

## Detections

- `SSH_BRUTE_FORCE`: five failures from one IP within 120 seconds (high).
- `REPEATED_AUTH_FAILURE`: three failures for one account within 120 seconds (medium).
- `SUCCESS_AFTER_FAILURES`: same-account success after a failure within 300 seconds (medium).
- `SUSPICIOUS_SUDO_ACTIVITY`: observed sudo command (low).

Thresholds are represented by `RuleConfig`; `rules/auth_rules.yaml` is a human-readable reference. See [detection documentation](docs/detections.md).

## Installation and usage

Python 3.9+ is required. There are no runtime dependencies.

```text
python -m sentinelforge parse fixtures/auth.log
python -m sentinelforge detect fixtures/auth.log
```

The CLI reads only the path explicitly supplied by the user and emits JSON. It never executes log content or opens live system logs. An installed package also provides the `sentinelforge` command.

## Testing

Run:

```text
python -m unittest discover -v
python -m compileall src
```

Tests use only in-memory strings and repository fixtures; pytest is not required.

## Security scope and limitations

This is defensive software for learning and portfolio demonstration. Alerts describe observed evidence and cautious interpretations; failed and successful authentication patterns do not prove compromise. Input formats are intentionally narrow, timestamp handling is fixture-specific, and the project does not ingest every Linux distribution's auth format. Do not commit real logs, credentials, or secrets.
