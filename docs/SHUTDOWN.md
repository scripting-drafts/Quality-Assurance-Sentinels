# Boot and shutdown listener

Layer 1 runs every minute and can therefore miss failures written during boot
or in the final seconds before power-off. The shutdown listener covers both
phases. It is a `final.target` systemd oneshot, installed with layer 1:

```bash
sudo ./root/install-shutdown.sh --redaction strict
```

`qa-shutdown-capture.service` starts after normal services and mounts are
stopped, then runs `bin/qa shutdown --capture`. It records matching
warning-or-worse journal messages from the whole boot in
`var/shutdown/<boot-id>.json`, split into:

- **`boot`** — failures from boot start until the shutdown marker
- **`shutdown`** — failures from the shutdown marker to the end of the journal

Covered messages include:

- `Failed to start OpenBSD Secure Shell server.`
- `Failed unmounting /media/<user>/2.`
- unit stop failures and other late systemd shutdown failures

The next routine ingest replays both phases into the events table. The layer-1
rules `systemd.service_start`, `systemd.unmount`, `systemd.unit_stop` and
`systemd.shutdown` turn them into findings, so they appear in reports,
evidence bundles, and the normal ticket workflow.

The listener also works without the systemd unit: `bin/qa boots` reconstructs
both phases from the latest completed boot's journal and stores the summary in
the boot's scan record. A volatile journal that loses the previous boot is the
reason the capture file exists.

## Redaction paths

Captured issues are redacted before they are written. Choose a profile with
`QA_CAPTURE_REDACTION`:

| Value | Behavior |
| --- | --- |
| `strict` (default) | Redacts operator identity, hostnames, addresses, IDs and paths while preserving path shape (`/home/<user>`). |
| `collapsed` | Same as strict, then replaces URLs and paths with `<url>` and `<path>`. |
| `metadata` | Withholds message text; keeps rule, unit, severity, timestamps, counts and fingerprint. |

Files are mode `0600`; `var/shutdown/` is mode `0700`. Exported findings pass
through the normal evidence/ticket redaction again.

Set `QA_CAPTURE_BOOT=0` to record only the shutdown phase.

## Commands

```bash
bin/qa shutdown --capture   # capture the current boot
bin/qa shutdown --capture --quiet   # one-line summary (used by the unit)
bin/qa shutdown --capture --redaction metadata   # per-run profile override
bin/qa shutdown --scan      # scan a boot without writing a capture
bin/qa shutdown --list      # list stored captures (default)
bin/qa shutdown --replay    # replay stored captures into events now
```

`--scan` accepts `--boot`, defaulting to `-1` for the previous boot:

```bash
bin/qa shutdown --scan --boot -1
bin/qa shutdown --scan --boot 0
```

## Verification

```bash
systemctl is-enabled qa-shutdown-capture.service
systemctl status qa-shutdown-capture.service   # inactive until shutdown
journalctl -u qa-shutdown-capture.service -b -1
bin/qa shutdown --list
bin/qa status
```

A capture is written only when the project directory is still mounted at
`final.target`. Keep the checkout on the root filesystem, or adjust
`ReadWritePaths=` and the capture directory in the unit and `QA_SHUTDOWN_DIR`.

Uninstall with:

```bash
sudo ./root/install-shutdown.sh --uninstall
```
