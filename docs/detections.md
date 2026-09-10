# Detection rules

Rule metadata is defined explicitly in the Python rule registry, while detector
algorithms remain readable Python functions. Rule definitions do not execute code
and `rules/auth_rules.yaml` remains reference metadata only.


## SSH_BRUTE_FORCE

- **Purpose:** identify a possible burst of failed SSH authentication.
- **Evidence:** five or more `authentication_failure` events from one source IP and `sshd`.
- **Default window:** 120 seconds; severity `high`.
- **Limitations:** shared NAT, scanners, and test activity can produce this pattern. It does not identify an attacker or prove compromise.
- **ATT&CK:** Explicit mapping to T1110 (Brute Force), with Credential Access tactic. This is a contextual mapping, not detection logic or proof of adversary behavior.

## REPEATED_AUTH_FAILURE

- **Purpose:** highlight repeated failures for one known account.
- **Evidence:** three or more failures for one username within 120 seconds; severity `medium`.
- **Limitations:** account names may be missing or spoofed in source logs.

## SUCCESS_AFTER_FAILURES

- **Purpose:** relate a successful login to earlier failures for the same account.
- **Evidence:** a success after at least one same-account failure within 300 seconds; severity `medium`.
- **Limitations:** this does not establish compromise; legitimate users mistype passwords.

## SUSPICIOUS_SUDO_ACTIVITY

- **Purpose:** make privileged command execution observable.
- **Evidence:** a supported `sudo` line containing `user=` and `command=`; severity `low`.
- **Limitations:** the command is not automatically malicious. No command is executed by SentinelForge.
- **ATT&CK:** No mapping is assigned; observed sudo activity alone is insufficient for a defensible technique mapping.

## Phase 10 relationship detections

These new rules use only the parser's existing `authentication_failure`, `username`,
and `source_ip` fields. The supplied `fixtures/phase10-source-account.log` is synthetic
demonstration data.

### SOURCE_TARGETS_MULTIPLE_ACCOUNTS

- **Purpose:** identify one source IP targeting multiple accounts.
- **Severity:** `medium`.
- **Threshold:** at least three distinct usernames.
- **Time window:** 120 seconds, inclusive.
- **Evidence:** three `authentication_failure` events with a source IP and username, sharing the source IP and having distinct usernames.
- **ATT&CK:** No mapping assigned; this relationship alone does not support a defensible technique mapping.
- **False positives:** shared NAT, scanners, monitoring, and legitimate administrative activity can produce this pattern.
- **Limitations:** the rule does not prove password spraying, malicious intent, or compromise.

### ACCOUNT_TARGETED_BY_MULTIPLE_SOURCES

- **Purpose:** identify one account targeted from multiple source IPs.
- **Severity:** `medium`.
- **Threshold:** at least three distinct source IPs.
- **Time window:** 120 seconds, inclusive.
- **Evidence:** three `authentication_failure` events with a username and source IP, sharing the username and having distinct source IPs.
- **ATT&CK:** No mapping assigned; this relationship alone does not support a defensible technique mapping.
- **False positives:** distributed legitimate clients, NAT/proxy changes, testing, and account-recovery activity can produce this pattern.
- **Limitations:** the rule does not prove coordinated activity, password spraying, or compromise.

## Windows parser compatibility

Windows Security Event IDs 4624, 4625, and 4672 normalize to
`authentication_success`, `authentication_failure`, and `privileged_logon`. The
existing authentication failure/success detections can naturally consume those
normalized events. `privileged_logon` is not treated as sudo activity, so the
existing sudo rule and sudo correlation are not forced onto Windows events.
The focused Windows-specific `WINDOWS_PRIVILEGED_LOGON` rule reports explicit 4672 observations at low severity; it does not claim misuse and has no ATT&CK mapping. Existing generic authentication detections remain reusable for normalized 4624/4625 events.

The parser uses explicit local XML fixtures and does not collect from live
Windows Event Logs. Unsupported Windows variants and event IDs produce
 diagnostics rather than fabricated events.

### WINDOWS_PRIVILEGED_LOGON

- **Purpose:** make a Windows Event ID 4672 privileged-logon observation visible to analysts.
- **Severity:** `low`.
- **Threshold:** one event.
- **Time window:** 300 seconds in metadata; the rule is event-scoped and does not aggregate events.
- **Evidence:** one `windows-security` event with `event_id=4672`, `event_type=privileged_logon`, and an explicit username.
- **ATT&CK:** No mapping assigned; the raw event does not establish misuse or a defensible technique by itself.
- **False positives:** legitimate administrative logons and expected service or operational accounts can produce this event.
- **Limitations:** the rule does not prove privilege abuse, command execution, or compromise.

## ATT&CK mapping policy

Mappings are explicit, offline, deterministic, and linked to source rule IDs. Only
techniques supported by the current rule evidence are mapped. Unmapped rules remain
valid and are not forced into a technique. A mapping is contextual metadata and does
not prove adversary behavior or full ATT&CK coverage.

## Correlation and risk

Correlation findings are generated after detection and before incident derivation.
They identify only these bounded, same-account sequences:

- authentication failures followed by successful authentication within 300 seconds;
- successful authentication followed by sudo activity within 300 seconds.

Risk is a deterministic prioritization score, not probability or proof of compromise:

```text
base severity: low=10, medium=30, high=50, critical=70
correlations: +10 each, capped at +20
ATT&CK techniques: +5 each distinct technique, capped at +10
final score: capped at 100
```

Risk levels are `low` (0–29), `medium` (30–59), `high` (60–79), and `critical`
(80–100). Both correlation and risk preserve existing alert evidence and do not
infer unsupported claims.
