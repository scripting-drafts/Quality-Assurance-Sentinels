# qa-sentinels

Local QA sentinels: phase 1 is 1-minute detection with immediate evidence; phase 2 is queued root-level ftrace/perf/eBPF investigation. Physical-core-2 affinity is recorded and reported; never omitted from evidence or tickets.
Layers: C sampler · Python stdlib (ingest, inventory, detection, boot boundary, correlation, reports, tickets) · SQLite WAL · cron/systemd.
Run `bin/qa init`, then `bin/qa tick`; schedule with `bin/qa install-cron`; phase 2 with `bin/qa deploy-phase2`.
Commands: `status`, `preflight`, `deploy-phase2`, `phase1`, `deep`, `findings`, `boots`, `correlate`, `raise`, `notify`, `trace`, `crosscheck`, `logs`, `sample`, `ingest`, `inventory`, `report`, `evidence`, `verify`, `tickets`, `triage`, `posture`.
`boots` classifies every previous boot CLEAN/UNCLEAN/UNKNOWN; `correlate` (own 5-minute job) scores signatures recurring before silent stops.
Ready patterns become drafts plus clickable pop-ups; `raise` stages viable ones as `tickets/raise/<ticket>/` with redacted evidence; non-viable staged ones move to `tickets/in-standby/`, never deleted.
`crosscheck --deep` re-verifies drafts, verdicts and readiness every 6 h and raises drift; `logs --follow` is the timestamped colour monitor, autostarted at login.
Data stays here: `journal/`, `evidence/`, `tickets/drafts/`, `triage/`, `var/`; identity stays optional in `config/identity.env`.
