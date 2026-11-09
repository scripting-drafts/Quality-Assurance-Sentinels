# Capture modes (no artificial caps)

Defaults are deliberately bounded. These switches remove the caps; each is an
environment variable read by `bin/qa`.

- `QA_FULL_CAPTURE=1` — ingest the whole journal at `info` priority (not only
  warnings), including every process that logs.
- `QA_JOURNAL_PRIORITY=debug` — go further; expect a very large database.
- `QA_KEEP_FOREVER=1` — disable event/sample/process/inventory retention.
- `QA_EVENT_RETENTION_DAYS=0` — event retention; `0` keeps events forever.
- `QA_SAMPLE_RETENTION_DAYS=0`, `QA_PROC_RETENTION_DAYS=0` — sample and
  process snapshot retention; `0` keeps them forever.
- `QA_INVENTORY_RETENTION_DAYS=0` — inventory retention; `0` keeps it forever.
- `QA_DRAFTS_RETENTION_DAYS=30` — keep regenerated draft documents this long.
- `QA_RAISE_LOOKBACK_DAYS=30` — evidence window used by the raise gate.
- `QA_CYCLE_RAISE_HOURS=1` — raise-gate cadence in hours;
  `QA_CYCLE_RAISE_S` overrides it in seconds.
- `QA_MAX_TICKETS=10` — draft cap per run; substantive issues are prioritised
  before the cap so one-off warnings cannot crowd out high-volume faults.
  Set `0` for no limit.
- `QA_EVIDENCE_EVENT_LIMIT=0` — put every event in an evidence bundle.
- `QA_SHUTDOWN_DIR=var/shutdown` — where the shutdown listener writes its
  capture records.
- `QA_SHUTDOWN_RETENTION_DAYS` — capture retention; defaults to the event
  retention period (`0` keeps captures forever).
- `QA_CAPTURE_REDACTION=strict` — capture redaction profile: `strict`
  (default, preserves path shape), `collapsed` (replaces paths/URLs), or
  `metadata` (withholds message text).
- `QA_CAPTURE_BOOT=1` — include boot-phase failures in the shutdown capture;
  set `0` for shutdown-phase only.
- `QA_INVENTORY_INTERVAL_S=10800` — base inventory period.
- `QA_INVENTORY_MIN_S=900`, `QA_INVENTORY_MAX_S=43200` — adaptive floor/ceiling.
- `QA_DEEP_AUTO=1` — queue layer-2 tracing for critical layer-1 findings.
- `QA_DEEP_DURATION_S=30`, `QA_DEEP_MAX_DURATION_S=120` — trace window.
- `QA_DEEP_REQUEST_COOLDOWN_S=1800` — minimum gap per finding.
- `QA_CYCLE_CORRELATE_S=300` — correlation refresh and notification drain cadence.
- The dashboard writes `config/settings.json`; explicit environment variables
  still take precedence over that file.
- `QA_CYCLE_CROSSCHECK_S=21600` — crosscheck cadence.
- `QA_CYCLE_DAILY_HOUR=8` — earliest local hour for the daily report.
- `QA_LOG_MAX_MB=20`, `QA_LOG_KEEP=10` — `var/cron.log` rotates by
  copytruncate at the size cap and keeps that many numbered copies (200 MiB
  total by default).
- `QA_NOTIFY_TTL_DAYS=14` — undelivered notifications expire so their key can
  be queued again later; delivered rows age out after 30 days.
- `QA_NOTIFY_BACKOFF_S=300`, `QA_NOTIFY_BACKOFF_MAX_S=21600` — retry backoff
  for failed deliveries; unattempted and least-attempted rows go first.
- eBPF is used when `bin/qa_ebpf` is built and layer 2 has `CAP_BPF`; otherwise
  layer 2 records `eBPF: unavailable` and continues with ftrace/perf.
- `QA_PSI_MEMORY_FULL_ALERT=10`, `QA_MEM_AVAILABLE_ALERT_PCT=5`,
  `QA_TEMP_ALERT_C=90`, `QA_IO_PRESSURE_ALERT=50` — layer-1 thresholds.
- `QA_MIN_FREE_MIB=1024` — last-resort disk guard; ingestion pauses below it so
  the QA job cannot fill the disk and become the outage.

Two things are not limits and stay fixed: physical-core-2 evidence is always
recorded, and exported bundles/tickets are always redacted of operator identity.
