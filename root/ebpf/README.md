# eBPF tracer

`qa_trace.bpf.c` counts, per CPU and per comm:

- scheduler switches (`sched_switch`)
- wakeups (`sched_wakeup`)
- user and kernel page faults (`page_fault_user`, `page_fault_kernel`)

The loader prints JSON with `totals`, `per_cpu` and `top_comms`. Phase 2 adds
that JSON to its report and hash manifest.

## Build

    root/ebpf/bootstrap-ebpf.sh   # root: apt; non-root: ./toolchain, no system change
    root/ebpf/build.sh            # bin/qa_ebpf + bin/qa_trace.bpf.o

`build.sh` regenerates `vmlinux.h` from the running kernel's BTF, so rebuild
after a kernel upgrade. It needs `clang`, `bpftool`, `libbpf-dev`, `libelf`,
`zlib`.

## Run

Phase 2 calls it automatically. Manually:

    sudo bin/qa_ebpf --duration 30

Requires `CAP_BPF` + `CAP_PERFMON`; the systemd deep service grants both.
Without them the loader fails before attaching and phase 2 records
`eBPF: Operation not permitted`, then continues with ftrace/perf.

## Limits

- Counters, not stacks. Use perf and coredump stacks for call paths.
- Per-comm aggregation is global, not per-core; `ftrace` supplies the per-core
  comm breakdown.
- `vmlinux.h` generation ties the object to the running kernel; rebuild on
  kernel change.
