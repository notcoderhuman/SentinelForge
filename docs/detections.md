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
