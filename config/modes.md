# Capture modes (no artificial caps)

Defaults are deliberately bounded. These switches remove the caps; each is an
environment variable read by `bin/qa`.

- `QA_FULL_CAPTURE=1` — ingest the whole journal at `info` priority (not only
  warnings), including every process that logs.
- `QA_JOURNAL_PRIORITY=debug` — go further; expect a very large database.
- `QA_KEEP_FOREVER=1` — disable event/sample/process/inventory retention.
- `QA_MAX_TICKETS=0` — no limit on vendor drafts per run.
- `QA_EVIDENCE_EVENT_LIMIT=0` — put every event in an evidence bundle.
- `QA_INVENTORY_INTERVAL_S=10800` — base inventory period.
- `QA_INVENTORY_MIN_S=900`, `QA_INVENTORY_MAX_S=43200` — adaptive floor/ceiling.
- `QA_DEEP_AUTO=1` — queue phase-2 tracing for critical phase-1 findings.
- `QA_DEEP_DURATION_S=30`, `QA_DEEP_MAX_DURATION_S=120` — trace window.
- `QA_DEEP_REQUEST_COOLDOWN_S=1800` — minimum gap per finding.
- eBPF is used when `bin/qa_ebpf` is built and phase 2 has `CAP_BPF`; otherwise
  phase 2 records `eBPF: unavailable` and continues with ftrace/perf.
- `QA_PSI_MEMORY_FULL_ALERT=10`, `QA_MEM_AVAILABLE_ALERT_PCT=5`,
  `QA_TEMP_ALERT_C=90`, `QA_IO_PRESSURE_ALERT=50` — phase-1 thresholds.
- `QA_LIVE_MIN_S=1.6`, `QA_LIVE_MAX_S=2.0` — randomised live-view refresh bounds.
- `QA_MIN_FREE_MIB=1024` — last-resort disk guard; ingestion pauses below it so
  the QA job cannot fill the disk and become the outage.

Two things are not limits and stay fixed: physical-core-2 evidence is always
recorded, and exported bundles/tickets are always redacted of operator identity.
