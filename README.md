# qa-sentinels

Local QA sentinels: phase 1 is 1-minute detection with evidence; phase 2 is queued ftrace/perf/eBPF tracing. Physical-core-2 affinity is always recorded.
- **Layers** — C sampler · Python stdlib · SQLite WAL · cron/systemd
- **Setup** — `bin/qa init` → `bin/qa tick` → `bin/qa install-cron`; phase 2: `bin/qa deploy-phase2`
- **Commands** — `status` `preflight` `deploy-phase2` `phase1` `deep` `findings` `boots` `correlate` `raise` `notify` `trace` `crosscheck` `logs` `sample` `ingest` `inventory` `report` `evidence` `verify` `tickets` `triage` `posture`
- **Boots** — `boots` classifies each previous boot CLEAN/UNCLEAN/UNKNOWN; a silent stop becomes one critical finding
- **Tickets** — `correlate` scores signatures recurring before stops; `raise` stages viable ones in `tickets/raise/` and parks the rest in `tickets/in-standby/`
- **Notify & monitor** — clickable pop-ups open their Markdown; `crosscheck --deep` re-verifies drafts and verdicts every 6 h; `logs --follow` shows timestamped colour and autostarts at login
- **Data** — local only: `journal/` `evidence/` `tickets/` `triage/` `var/`; identity optional in `config/identity.env`
