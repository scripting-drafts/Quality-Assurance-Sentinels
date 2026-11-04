# QA Sentinels

**Local monitoring and evidence system**

QA Sentinels periodically samples the system, examines journal and crash records, and organizes findings into reports and verifiable evidence bundles. When an incident warrants closer inspection, it can queue a separate, more privileged tracing run. It also helps correlate repeated failures and prepare vendor bug-report drafts; it does not submit tickets automatically.

The project pays particular attention to physical CPU core 2. Core affinity is captured as diagnostic context.

## How it works

| Component | Purpose | Runs when |
| --- | --- | --- |
| **Phase 1: routine monitoring** | Capture CPU, memory, kernel, process and log evidence; detect possible incidents | Every minute via user cron, or manually |
| **Boot analysis** | Classify prior boots as `CLEAN`, `UNCLEAN`, or `UNKNOWN`; flag unexplained stops | During analysis/monitoring |
| **Correlation and ticket preparation** | Connect recurring signatures to preceding events and separate promising vendor reports from standby drafts | On demand or through the configured workflow |
| **Phase 2: deep tracing** | Collect additional `ftrace`, `perf`, and optional eBPF diagnostics for selected findings | When a deep-trace request is queued or manually invoked |

The core implementation uses a **C sampler**, **Python 3 standard library**, **SQLite WAL**, and **cron/systemd**. Captured data is stored later on /journal, /triage and /tickets.

## Requirements

- A **Linux** host with Python 3, a C compiler, `make`, and access to relevant kernel and system-journal interfaces.
- `git` to clone the repository and `cron` for the default periodic schedule.
- Optional: `systemd`, `perf`, `ftrace` and eBPF build dependencies for deeper diagnostics.
- Sufficient local disk space for samples, journal records, reports, and traces.

Some information may be unavailable without journal permissions or elevated capabilities. Use `preflight` to see what the current host supports.

## Quick start: Phase 1

Run these commands **from the directory containing the cloned repository**:

```bash
git clone https://github.com/scripting-drafts/qa-sentinels.git
cd qa-sentinels

# Compile the local sampler into bin/qa_sample.
make -C src install

# Initialize storage and perform the first collection.
./bin/qa init
./bin/qa preflight
./bin/qa tick

# Inspect the result.
./bin/qa status
./bin/qa findings
./bin/qa boots

# Optional: schedule one monitoring tick per minute.
./bin/qa install-cron
```

`tick` performs one monitoring pass; `phase1` is an alias. The cron installation also configures a daily run at 08:00. The data and reports remain on the local machine.

> **Installer note:** The repository also contains `install.sh`, but the version reviewed on 2026-11-03 resolves its project root to the parent directory of the repository. Until that path is corrected, use the explicit commands above instead of relying on `./install.sh`.

### Check monitoring activity

```bash
./bin/qa status                 # Overall status
./bin/qa logs --lines 50       # Recent sentinel activity
./bin/qa logs --follow         # Follow new log entries
./bin/qa preflight             # Check prerequisites and access
```

To remove the user cron entries installed by this project:

```bash
./bin/qa install-cron --remove
```

## Investigate a crash or unexpected shutdown

1. **Review boot history.** `./bin/qa boots --limit 20` classifies recorded boots. An unclean or silent stop is a lead to investigate, not a definitive root-cause diagnosis.
2. **Review findings.** `./bin/qa findings` lists detected events; `./bin/qa triage` shows the core-2 investigation queue.
3. **Correlate prior events.** `./bin/qa correlate --days 30` looks for component signatures preceding unexpected stops, including recurrence across boots.
4. **Follow a signature.** `./bin/qa trace '<message-or-fingerprint>'` brings together related information from different layers.
5. **Create and validate evidence.** `./bin/qa evidence --reason "unexpected shutdown" --hours 24` produces an evidence bundle. Use `./bin/qa verify PATH_TO_BUNDLE` to check a bundle's manifest and hashes.
6. **Review potential vendor reports.** `./bin/qa tickets --days 7` generates drafts. `./bin/qa raise --days 30` places viable drafts in `tickets/raise/`, crashes explained by a held, outdated package in `tickets/rejected/`, and other drafts in `tickets/standby/` for later examination.

The system can mark a silent stop as critical and score recurring signatures. **A score or draft does not establish causality**; review the logs, evidence, and proposed explanation before sending a report.

## Phase 2: optional deep tracing

Phase 2 is deliberately separate from the ordinary monitor. It can use privileged kernel tracing interfaces and is intended for incidents that need more detail than the one-minute collection provides.

```bash
# Check whether the phase-2 path unit is installed.
./bin/qa deploy-phase2 --check

# Install/verify automated handling of queued deep-trace requests.
./bin/qa deploy-phase2

# Inspect pending requests and previous runs.
./bin/qa deep --list

# Example: queue a 30-second run for a recorded finding.
./bin/qa deep --finding 1 --duration 30 --enqueue
```

Replace `1` with an actual finding ID. A configured systemd path unit watches `triage/core2/deep-requests/` and processes queued requests. The default configuration can automatically queue phase-2 work for critical findings (`QA_DEEP_AUTO=1`); execution still depends on a working phase-2 deployment.

For manual tracing, inspect permissions and the impact first:

```bash
./bin/qa deep --dry-run --duration 30
./bin/qa deep --case 1 --duration 30 --perf-record
```

Kernel tracing may require elevated privileges or specific Linux capabilities. Do not indiscriminately run the entire monitoring application as root. See [root/README.md](root/README.md) for the supported systemd setup, optional read-only root evidence collector, and capability details.

### Optional eBPF counters

The separate eBPF tracer counts scheduler switches, wakeups, and page faults per CPU and process command name:

```bash
./root/ebpf/bootstrap-ebpf.sh
./root/ebpf/build.sh
```

The eBPF build requires kernel BTF and appropriate tools and libraries. When unavailable, phase 2 can still gather supported `ftrace`/`perf` evidence and records the eBPF limitation. Rebuild the tracer after a kernel upgrade. Details: [root/ebpf/README.md](root/ebpf/README.md).
