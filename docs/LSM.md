# Linux Security Modules monitor

The sentinel records the active LSM stack and alerts on state drift, insecure
configuration, and recent AppArmor/SELinux denials.

## Sources

- `/sys/kernel/security/lsm`
- `/sys/kernel/security/lockdown`
- `/sys/kernel/security/apparmor/profiles`
- `/sys/module/apparmor/parameters/enabled`
- `/sys/fs/selinux/enforce` and `policyvers`
- `/sys/fs/smackfs`, `/sys/kernel/security/tomoyo`
- `/proc/sys/kernel/yama/ptrace_scope`
- `/sys/kernel/security/ima/policy` or `integrity/ima/policy`
- `/proc/cmdline` `lsm=` list
- kernel journal (`apparmor="DENIED"`, SELinux `avc: denied`)

## Commands

```bash
./bin/qa lsm check
./bin/qa lsm scan
./bin/qa lsm show
./bin/qa lsm baseline   # accept the current state after an intentional change
./bin/qa findings --only open
```

`cycle` scans every `QA_LSM_INTERVAL_S` seconds (default 300).

## Root handoff

AppArmor profile state is root-only, even for the capability-scoped operator
service. Install the dedicated root reader:

```bash
sudo ./root/install-lsm-read.sh
systemctl status qa-lsm-read.timer qa-lsm-read.service
```

The installer places `/usr/local/sbin/qa-lsm-read-helper` and a timer that
refreshes `var/lsm-state-root.json` every five minutes
(root:<operator-group>, 0640). The helper reads only LSM state; the operator
collector reads the handoff, computes the digest, and writes findings. If the
handoff is missing or stale, the collector falls back to a direct read and
reports `lsm.state_unreadable` when securityfs denies access.

Remove it with `sudo ./root/install-lsm-read.sh --uninstall`.

## Rules

| Rule | Severity | Meaning |
|---|---|---|
| `lsm.none` | critical | no active LSM list and securityfs unavailable |
| `lsm.apparmor.disabled` | warning | AppArmor present but not enabled |
| `lsm.selinux.permissive` | warning | SELinux present but not enforcing |
| `lsm.yama.ptrace_scope` | warning | `ptrace_scope=0` |
| `lsm.lockdown.none` | warning | lockdown LSM active but mode none |
| `lsm.ima.policy_missing` | warning | integrity LSM active without IMA policy |
| `lsm.state_unreadable` | warning | securityfs state could not be read |
| `lsm.state_changed` | warning | digest differs from the last accepted baseline |
| `lsm.apparmor.denial` | warning | AppArmor denial(s) in the journal |
| `lsm.selinux.denial` | warning | SELinux AVC denial(s) in the journal |

Denials are aggregated per day; `QA_LSM_DENIAL_ALERT` defaults to 1. Use
`qa lsm baseline` after an intentional LSM policy change so the next scan does
not treat it as drift.

## Enforcement

`lsm.lockdown.none` is addressed explicitly, not silently waived:

```bash
sudo ./root/lsm-enforce-lockdown.sh integrity
```

No lockdown helper is installed by the hardware service; enforcement is an
explicit operator action.

The script writes `integrity` (or `confidentiality`) to
`/sys/kernel/security/lockdown` and verifies the selection. For persistence
across reboots, add `lockdown=integrity` to the GRUB command line and rebuild
the configuration:

```bash
sudo ./root/add-lockdown-cmdline.sh --mode integrity
grep -o 'lockdown=[^ ]*' /proc/cmdline   # after reboot
```

Review the impact first: lockdown can block unsigned module loading, kexec, and
some firmware/debug interfaces. Some kernels expose the IMA policy write-only
(mode 0200) even to root; that is a kernel interface property, not unreadable
state, so it is recorded as `ima.readable=false` instead of
`lsm.state_unreadable`.

## Limits

The monitor is read-only. It cannot enforce policy, load profiles, or replace
AppArmor/SELinux tooling. Some securityfs files may require root; unreadable
state is reported, not invented. The root LSM helper closes the AppArmor/IMA
visibility gap without giving the Python collector or database root. When `cycle` cannot read required LSM state,
it records `lsm.state_unreadable` and returns a non-zero cycle status.
Entropy in profile digests can cause benign `lsm.state_changed` warnings;
review before dismissing.
