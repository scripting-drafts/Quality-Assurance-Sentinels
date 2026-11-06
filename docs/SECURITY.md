# Security provenance detection

The sentinel detects **unexpected code provenance** on this host. It is an
evidence system, not a sandbox or a proof of compromise.

## Run

```bash
./bin/qa security scan
./bin/qa security policy
./bin/qa security scan --no-files --no-audit
./bin/qa findings --only open
```

`cycle` runs the process and audit checks every minute and the file-ownership
check every `QA_SECURITY_FILE_SCAN_S` seconds (default 300).

## Rules

| Rule | Severity | Meaning |
| --- | --- | --- |
| `security.root_user_path` | critical | Effective UID 0 process has an executable or cwd under a user-writable path. |
| `security.root_cmdline_user_path` | critical | UID 0 process command line names a user-writable path. |
| `security.root_writable_exe` | critical | UID 0 executable is owned by non-root or group/other-writable. |
| `security.root_from_user_parent` | critical | UID 0 process descends from a non-root parent outside an allowed elevation chain. |
| `security.root_elevated_session` | warning | UID 0 process carries a non-root login uid. |
| `security.deleted_exe` | critical/warning | Executable is deleted or anonymous (`memfd`). |
| `security.unexpected_uid_user_path` | critical | UID outside the allowlist runs code from a user-writable path. |
| `security.user_code_tmp` | warning | UID outside the allowlist runs from temporary storage. |
| `security.nonroot_caps` | warning | Non-root process holds capabilities outside the policy allowlist. |
| `security.root_owned_user_state` | warning | UID 0 files/directories exist under user-writable QA state. |
| `security.audit_root_exec` | critical | Auditd saw UID 0 exec with a non-root login uid or user-path command. |
| `security.audit_unexpected_user_exec` | error | Auditd saw an unexpected UID exec from a user-writable path. |
| `security.audit_priv_change` | critical/warning | Auditd saw setuid/setgid/capset activity. |
| `security.audit_unavailable` | warning | Auditd/ausearch is missing, so strict short-lived event coverage is off. |

Container processes are excluded from the host provenance rules; their
boundary is the container runtime. The LXQt shared-browser stack has its own
explicit-authorization guard.

## Policy

`config/security-policy.json` controls allowed UIDs, user-writable prefixes,
elevation parents, setuid helpers, capability allowlists, and root-owned state
exceptions. Keep `allow_root_user_path` empty unless a specific root command
from a user path is deliberately approved.

## Strict event coverage

The one-minute `/proc` scan cannot see commands that start and exit between
samples. For strict detection, install auditd and the QA exec/privilege rules:

```bash
sudo apt install auditd
sudo ./root/audit/install-audit-rules.sh
sudo auditctl -l | grep qa_security
```

The rules log every `execve` and setuid/setgid/capset event under the keys
`qa_security_exec` and `qa_security_priv`. The sentinel reads them with
`ausearch`; the operator account must be able to read the audit log (normally
via the `adm` group). If auditd is absent, the scanner raises
`security.audit_unavailable` rather than claiming complete coverage.

## Limits

- Snapshot rules can miss short-lived processes; auditd closes that gap.
- UID 0 inside a container is treated as a container-root boundary, not a host
  privilege escalation.
- A user with root or Docker access can bypass this detector; it is not a
  kernel LSM.
- Findings are deduplicated and counted. Dismiss a confirmed false positive
  with `./bin/qa findings --set-status dismissed --id N`.
- The detector does not kill processes. The separate LXQt `lxqt-stack` guard
  prevents unauthorized starts of that stack.
