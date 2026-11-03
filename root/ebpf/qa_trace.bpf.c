/* qa_trace.bpf.c — minimal, verifier-friendly eBPF tracing for phase 2.
 *
 * Counts scheduler switches, wakeups and page faults per CPU and per comm.
 * Deliberately avoids context-field offsets so it stays portable across
 * kernels: only helper calls and map operations are used.
 *
 * Build: root/ebpf/build.sh
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct comm_key {
    char comm[16];
    __u32 kind; /* 0 switch, 1 wakeup, 2 page fault */
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} totals SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 512);
    __type(key, struct comm_key);
    __type(value, __u64);
} by_comm SEC(".maps");

static __always_inline void bump_total(__u32 idx)
{
    __u64 *value = bpf_map_lookup_elem(&totals, &idx);
    if (value)
        __sync_fetch_and_add(value, 1);
}

static __always_inline void bump_comm(__u32 kind)
{
    struct comm_key key = {};
    bpf_get_current_comm(&key.comm, sizeof(key.comm));
    key.kind = kind;

    __u64 *value = bpf_map_lookup_elem(&by_comm, &key);
    if (value) {
        __sync_fetch_and_add(value, 1);
    } else {
        __u64 one = 1;
        bpf_map_update_elem(&by_comm, &key, &one, BPF_ANY);
    }
}

SEC("tracepoint/sched/sched_switch")
int tp_sched_switch(void *ctx)
{
    bump_total(0);
    bump_comm(0);
    return 0;
}

SEC("tracepoint/sched/sched_wakeup")
int tp_sched_wakeup(void *ctx)
{
    bump_total(1);
    bump_comm(1);
    return 0;
}

SEC("tracepoint/exceptions/page_fault_user")
int tp_page_fault_user(void *ctx)
{
    bump_total(2);
    bump_comm(2);
    return 0;
}

SEC("tracepoint/exceptions/page_fault_kernel")
int tp_page_fault_kernel(void *ctx)
{
    bump_total(2);
    bump_comm(2);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
