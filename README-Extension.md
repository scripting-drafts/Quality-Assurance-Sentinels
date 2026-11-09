# QA Sentinels — extension guide

## Command reference

All commands use `./bin/qa <command>` from the repository root.

| Area | Commands | What they do |
| --- | --- | --- |
| Setup and operations | `install.sh`, `uninstall.sh`, `init`, `compat`, `preflight`, `status`, `install-cron`, `posture` | Install or remove one/both layers, initialize, check Ubuntu upgrade compatibility, inspect prerequisites, check scheduling and security posture |
| Routine collection | `cycle` (`tick`, `layer1`; `phase1` legacy), `sample`, `ingest`, `inventory`, `report` | Capture system state and run every due layer-1 duty |
| Failure investigation | `boots`, `shutdown`, `findings`, `triage`, `correlate`, `trace`, `holds` | Examine restarts, boot and shutdown-window errors, events, their relationships, and held/outdated packages |
| Hardware health | `hardware` | Collect RAS/EDAC/AER/APEI, SMART/NVMe, GPU, BMC, sensors, turbostat/PCM/uncore, vendor logs |
| Linux Security Modules | `lsm` | Monitor AppArmor, SELinux, Smack, TOMOYO, Yama, lockdown, IMA, BPF, drift and denials |
| Security provenance | `security` | Detect unexpected user/root code execution, root-owned state, and audit coverage gaps |
| Evidence | `evidence`, `verify` | Export and validate hash-manifested bundles |
| Ticket workflow | `tickets`, `raise`, `notify`, `crosscheck` | Draft, rank, notify, and recheck candidate vendor reports; open hardware/LSM/security findings are drafted too |
| SIEM export | `export`, `forward` | Emit redacted JSONL or forward findings/events to a QA SIEM endpoint |
| Deep diagnostics | `deploy-layer2` (`deploy-phase2` legacy), `deep` | Configure and run queued tracing |
| Monitoring display | `logs` | Read, rotate or follow timestamped activity |

Useful examples:

```bash
./bin/qa compat --strict
./bin/qa report --kind daily --hours 24
./bin/qa crosscheck --deep
./bin/qa notify --test
./bin/qa logs --all-layers -f
./bin/qa logs --install-autostart
./bin/qa logs --rotate
./bin/qa tickets --list
```

Run `./bin/qa --help` for the full command list and `./bin/qa <command> --help` for individual options.

## Where files go

| Path | Contents |
| --- | --- |
| `var/` | SQLite database, application state, and shutdown-window captures |
| `journal/` | Local monitoring records and generated reports |
| `evidence/` | Evidence bundles and verification metadata |
| `tickets/drafts/` | Candidate vendor report drafts |
| `tickets/raise/` | Drafts judged ready for human review/submission |
| `tickets/standby/` | Lower-confidence or deferred drafts |
| `tickets/rejected/` | Reports explained by a held, outdated local build |
| `triage/core2/` | Core-2 cases, deep-trace requests, and results |
| `config/` | Settings documentation and optional reporter identity |

These directories are created by initialization as needed. The project uses local files; **ticket drafts are not automatically published**.

## Configuration and data handling

Configuration is primarily through `QA_...` environment variables. See [config/modes.md](config/modes.md) for capture breadth, retention, tracing duration, thresholds, and disk safeguards.

Examples:

```bash
# Broader collection: more information and higher storage usage.
QA_FULL_CAPTURE=1 ./bin/qa cycle

# Change the monitored physical core or its logical CPU mapping if needed.
QA_CORE2_ID=2 QA_CORE2_CPUS=2,8 ./bin/qa cycle
```

The default retention configuration is bounded. A low-free-space guard can suspend ingestion instead of filling the disk. Unbounded collection (`QA_KEEP_FOREVER=1`, debug journal capture, unlimited evidence events) requires conscious capacity planning.

Optional reporter details may be put in `config/identity.env`, using `config/identity.env.example` as a guide. The example requires explicit `TICKET_CONSENT=1` before identity is included in output. **Review and redact all bundles, tickets, traces, host identifiers, and hardware serial numbers before sharing them externally**; do not assume every diagnostic artifact is anonymous.

## Limitations and interpretation

- The system gathers **diagnostic evidence**, not a proof of hardware failure or bit flips. Crash correlation and physical-core affinity alone do not establish cause.
- An `UNCLEAN` boot classification can reflect a crash, power interruption, forced shutdown, or missing shutdown records.
- Layer 2 depends on kernel interfaces, capabilities, installed tools, and system policy. Unavailable probes may be skipped or reported.
- Some hardware details and other users' coredumps require optional privileged collection.
- More frequent or unrestricted logging can create performance and storage overhead.
- Ticket generation and classification require a human to validate the suspected cause and decide what to disclose.

## Project layout

- [`bin/qa`](bin/qa) — primary command-line entry point.
- [`sentinels/`](sentinels/) — monitoring, detection, correlation, evidence, and ticket logic.
- [`src/`](src/) — C sampler and Makefile.
- [`root/`](root/) — optional elevated system collection, systemd integration, and deep tracing.
- [`config/`](config/) — configuration notes and optional identity template.
- [`docs/COMPATIBILITY.md`](docs/COMPATIBILITY.md) — Ubuntu 22.04-26.10 baseline and upgrade checklist.
- [`docs/SECURITY.md`](docs/SECURITY.md) — security provenance rules, auditd coverage, and limits.
- [`docs/HARDWARE.md`](docs/HARDWARE.md) — hardware-health sources, privileges, scheduling, and limits.
- [`docs/LSM.md`](docs/LSM.md) — Linux Security Modules state, drift, denials, and limits.
- [`tests/`](tests/) — project tests.

To run the included Python test suite, from the repository root:

```bash
python3 -m unittest discover -s tests
```
