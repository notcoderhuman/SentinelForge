# Phase 1 detections

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
