# Quality Assurance Sentinels — root-only evidence (optional)

The sentinel itself runs unprivileged. It already reads the journal through the
`adm` group, user coredumps and all of `/proc` and `/sys`.

Root adds: full `dmidecode` (memory slots, board serials), `smartctl`, `lspci -vv`,
`cpupower`, MCE/EDAC counters, and coredumps owned by other users.

Three options:

1. `sudo root/install-system.sh --takeover` — layer-1 systemd timer plus a layer-2
   path unit (`qa-sentinel-deep.path`). Both run as your account. Layer 2 adds
   `CAP_SYS_ADMIN`, `CAP_PERFMON`, `CAP_BPF`, `CAP_SYS_PTRACE`, `CAP_DAC_READ_SEARCH`,
   `CAP_DAC_OVERRIDE` and `CAP_SYS_RAWIO` for tracefs/perf/hardware probes. No root shell.
   Layer-2-only per-host automation: `bin/qa deploy-layer2` (idempotent, keeps cron).
2. `sudo root/install-lsm-read.sh` — dedicated root LSM state reader. It reads
   AppArmor profiles and IMA state that securityfs denies to the operator, then
   writes `var/lsm-state-root.json` (root:<operator-group>, 0640) every five
   minutes. It reads LSM state only and never opens the QA database.
3. `sudo root/collect-root-evidence.sh` — one-shot read-only hardware/MCE dump.

Layer 1 never has tracing capabilities. Layer 2 starts only when a JSON request
appears in `triage/core2/deep-requests/`, then archives it after the run. Manual run:

    sudo ~/Quality-Assurance-Sentinels/bin/qa deep --case 1 --duration 30 --perf-record

Run `sudo root/collect-root-evidence.sh` when a bundle needs that depth. Output
goes to `var/root-evidence/<utc>/` with mode 0700 and is **not** auto-bundled.
Review it and copy only the relevant, redacted excerpts into a vendor ticket.
See `root/PSTORE.md` for the pstore panic export installed with layer 1.

## eBPF tracer

`root/ebpf/` builds a verifier-friendly tracer for `sched_switch`,
`sched_wakeup` and user/kernel page faults, with per-CPU and per-comm counters.

    root/ebpf/bootstrap-ebpf.sh   # root: apt; non-root: local toolchain in ./toolchain
    root/ebpf/build.sh            # produces bin/qa_ebpf + bin/qa_trace.bpf.o

Layer 2 runs it only when `CAP_BPF` is present (the deep service has it).
Without the build, layer 2 records `eBPF: not built` and still runs ftrace/perf.
Layer 1 never has BPF capability.

Lockdown is an operator policy choice; the LSM reader records the selected mode
and never changes it. Do not load unsigned modules or give the sentinel blanket
sudo. Keep `perf_event_paranoid` at the policy value recorded by posture.
