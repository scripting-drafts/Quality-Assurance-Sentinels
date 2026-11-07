# SIEM connector

QA Sentinels can export redacted findings to the local `qa-siem` service.

## Setup

```bash
cp config/siem.example.json config/siem.json
# Ensure the QA operator can read /etc/qa-siem/token, or set QA_SIEM_TOKEN.
chmod 600 config/siem.json
```

The endpoint must be loopback HTTP or HTTPS. Plaintext HTTP to a remote host
is refused unless `allow_insecure_http` is explicitly set.

## Commands

```bash
# Preview the normalized envelopes.
./bin/qa export --since 24h --format jsonl | head

# Send the lookback window.
./bin/qa forward --config config/siem.json

# Retry-safe dry run.
./bin/qa forward --config config/siem.json --dry-run
```

`forward` re-sends a bounded window. The SIEM deduplicates by `event_id`, so
overlapping windows and retries are safe. The default lookback is 24 hours.

## Schedule

Install the forwarder timer:

```bash
sudo ./root/install-siem-forward.sh
systemctl status qa-siem-forward.timer qa-siem-forward.service
```

It runs every five minutes as the operator and appends results to the systemd
journal. Manual forwarding remains available:

```bash
./bin/qa forward --config config/siem.json
```

Do not put the token on the command line. Use `QA_SIEM_TOKEN` or a token file
with mode `0600`/`0640`. The SIEM installer can share the token with the QA
operator group:

```bash
sudo /path/to/qa-siem/scripts/install.sh --token-group gerard
```

Remove the timer with `sudo ./root/install-siem-forward.sh --uninstall`.

## Scope

The exporter sends findings, journal events, crashes, boot state, hardware
runs, LSM runs, and ticket drafts. It sends summaries and an `evidence_ref`;
evidence bundles remain on the QA host. `redact()` is applied to detail and
subject fields before transmission.

## Mapping

| Local source | `event_type` | Rule |
|---|---|---|
| findings | `finding` | exact finding rule |
| journal events | `event` | `journal.<severity>` |
| crashes | `crash` | `crash.core2` or `crash` |
| boots | `boot` | `boot.unclean` or `boot.clean` |
| hardware runs | `hardware` | `hardware.run` |
| LSM runs | `lsm` | `lsm.run` |
| ticket drafts | `ticket` | `ticket.draft` |

See the QA SIEM repository `docs/INTEGRATION.md` for the receiving side.
