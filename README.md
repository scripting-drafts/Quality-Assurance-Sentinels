# qa-sentinels

Local QA sentinels in two phases: phase 1 is 1-minute detection with immediate evidence; phase 2 is queued root-level ftrace/perf/eBPF investigation.
Physical-core-2 affinity is recorded and reported; it is never omitted from evidence or tickets.
Layers: C sampler (kernel interfaces) · Python stdlib (ingest, inventory, detection, reports, tickets) · SQLite WAL (store) · cron/systemd (schedule).
Run `bin/qa init`, then `bin/qa tick`; install the schedule with `bin/qa install-cron`.
For phase 2, run `bin/qa deploy-phase2` (idempotent per host).
Commands: `status`, `preflight`, `deploy-phase2`, `phase1`, `deep`, `findings`, `sample`, `ingest`, `inventory`, `report`, `evidence`, `verify`, `tickets`, `triage`, `posture`.
Data stays in this directory: `journal/`, `evidence/`, `tickets/drafts/`, `triage/`, `var/`.
Optional identity for drafts lives in `config/identity.env` (see the `.example`); default is withheld.
