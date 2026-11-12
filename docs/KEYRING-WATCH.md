# Keyring watcher

Live attribution for session-bus Secret Service calls (`org.freedesktop.secrets`,
`org.freedesktop.portal.Secret`). The watcher records **who made the call**, not
what was stored or retrieved.

## Recorded

- D-Bus envelope: timestamp, serial, sender, destination, path, interface, member.
- Caller: PID, PPID, comm, exe, cwd, redacted argv, uid/euid/suid/fsuid,
  gid/egid/sgid/fsgid, supplementary groups, username.
- Session: audit loginuid/sessionid, logind session, seat/type/class/display,
  TTY, cgroup/unit, namespaces (pid/mnt/net/user/...), security label.
- Fingerprints: executable SHA-256, ELF build-id, size, mtime, inode, device.
- Bus: owned well-known names, service owner identity, transport and network
  endpoints. Local session buses are Unix sockets, so IP fields are null; SSH
  and remote logind sessions supply client IPs when present.
- Environment: strict whitelist only (display/session/SSH/desktop file).

## Never recorded

- D-Bus message bodies or secret values.
- Full process environments.
- Password/token/secret-looking argv values (replaced with `<redacted>`).

The log is host-local, mode `0600`, under `var/` (gitignored). It is not part of
evidence bundles.

## Files

- `var/keyring-access.log` — JSONL, hash-chained.
- `var/keyring-access.state` — chain head across rotation.
- `bin/keyring-watch` — collector.
- `root/systemd/keyring-watch.service` — user unit template.

## Commands

```bash
systemctl --user status keyring-watch
journalctl --user -u keyring-watch -f
~/QA-Sentinels/bin/keyring-watch --status
~/QA-Sentinels/bin/keyring-watch --verify
jq -c 'select(.event=="secret_service_call")' ~/QA-Sentinels/var/keyring-access.log
```

Install or refresh the unit:

```bash
mkdir -p ~/.config/systemd/user
cp ~/QA-Sentinels/root/systemd/keyring-watch.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now keyring-watch
```

Stop: `systemctl --user disable --now keyring-watch`.

## Limits

- Session bus only; root's system bus and other users are out of scope.
- A client that disappears before its first credential lookup is recorded with
  the identifiers D-Bus still exposes; normal callers are captured at connection
  birth.
- Rotation keeps five 50 MiB segments. `--verify` checks the current segment and
  its link to `.1`; older segments are retained for manual inspection.
