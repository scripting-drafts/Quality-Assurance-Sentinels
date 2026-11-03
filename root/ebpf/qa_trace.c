/* qa_trace.c — load qa_trace.bpf.o, attach tracepoints, print JSON.
 *
 * Needs CAP_BPF + CAP_PERFMON (or root). The systemd phase-2 service supplies
 * them; phase 1 never runs this binary.
 */
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_COMMS 512

struct comm_key {
    char comm[16];
    unsigned int kind;
};

static volatile sig_atomic_t stop;

static void on_signal(int sig) { (void)sig; stop = 1; }

static int print_libbpf(enum libbpf_print_level level, const char *fmt, va_list args)
{
    (void)level;
    return vfprintf(stderr, fmt, args);
}

struct link_ent {
    const char *prog;
    const char *category;
    const char *name;
    struct bpf_link *link;
};

int main(int argc, char **argv)
{
    char default_obj[4096] = "qa_trace.bpf.o";
    const char *object = default_obj;
    int duration = 30;

    ssize_t n = readlink("/proc/self/exe", default_obj, sizeof(default_obj) - 1);
    if (n > 0) {
        default_obj[n] = '\0';
        char *slash = strrchr(default_obj, '/');
        if (slash) {
            strcpy(slash + 1, "qa_trace.bpf.o");
        } else {
            strcpy(default_obj, "qa_trace.bpf.o");
        }
    }

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--object") == 0 && i + 1 < argc)
            object = argv[++i];
        else if (strcmp(argv[i], "--duration") == 0 && i + 1 < argc)
            duration = atoi(argv[++i]);
        else if (strcmp(argv[i], "--help") == 0) {
            printf("usage: %s [--object FILE] [--duration SEC]\n", argv[0]);
            return 0;
        }
    }
    if (duration < 1)
        duration = 1;

    libbpf_set_print(print_libbpf);
    struct bpf_object *obj = bpf_object__open_file(object, NULL);
    long err = libbpf_get_error(obj);
    if (err) {
        fprintf(stderr, "open %s: %s\n", object, strerror(-err));
        return 2;
    }
    if (bpf_object__load(obj)) {
        fprintf(stderr, "load failed: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 3;
    }

    struct link_ent links[] = {
        {"tp_sched_switch", "sched", "sched_switch", NULL},
        {"tp_sched_wakeup", "sched", "sched_wakeup", NULL},
        {"tp_page_fault_user", "exceptions", "page_fault_user", NULL},
        {"tp_page_fault_kernel", "exceptions", "page_fault_kernel", NULL},
    };
    int attached = 0;
    for (size_t i = 0; i < sizeof(links) / sizeof(links[0]); i++) {
        struct bpf_program *prog = bpf_object__find_program_by_name(obj, links[i].prog);
        if (!prog) {
            fprintf(stderr, "missing program %s\n", links[i].prog);
            continue;
        }
        links[i].link = bpf_program__attach_tracepoint(prog, links[i].category, links[i].name);
        long e = libbpf_get_error(links[i].link);
        if (e) {
            fprintf(stderr, "attach %s/%s: %s\n", links[i].category, links[i].name,
                    strerror(-e));
            links[i].link = NULL;
            continue;
        }
        attached++;
    }
    if (!attached) {
        fprintf(stderr, "nothing attached (need CAP_BPF/CAP_PERFMON)\n");
        bpf_object__close(obj);
        return 4;
    }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    for (int i = 0; i < duration && !stop; i++)
        sleep(1);

    int ncpu = libbpf_num_possible_cpus();
    if (ncpu < 1)
        ncpu = 1;
    unsigned long long *per_cpu = calloc((size_t)ncpu, sizeof(*per_cpu));
    unsigned long long *cpu_totals = calloc((size_t)ncpu * 3, sizeof(*cpu_totals));
    unsigned long long totals[3] = {0, 0, 0};
    int map_fd = bpf_object__find_map_fd_by_name(obj, "totals");
    if (map_fd >= 0 && per_cpu && cpu_totals) {
        for (unsigned int idx = 0; idx < 3; idx++) {
            memset(per_cpu, 0, (size_t)ncpu * sizeof(*per_cpu));
            if (bpf_map_lookup_elem(map_fd, &idx, per_cpu) == 0) {
                for (int c = 0; c < ncpu; c++) {
                    totals[idx] += per_cpu[c];
                    cpu_totals[(size_t)idx * ncpu + c] = per_cpu[c];
                }
            }
        }
    }

    struct comm_key key, next;
    unsigned long long value;
    struct {
        char comm[16];
        unsigned int kind;
        unsigned long long count;
    } top[MAX_COMMS];
    int ntop = 0;
    int comm_fd = bpf_object__find_map_fd_by_name(obj, "by_comm");
    if (comm_fd >= 0) {
        memset(&key, 0, sizeof(key));
        while (bpf_map_get_next_key(comm_fd, &key, &next) == 0) {
            if (bpf_map_lookup_elem(comm_fd, &next, &value) == 0 && ntop < MAX_COMMS) {
                memcpy(top[ntop].comm, next.comm, sizeof(top[ntop].comm));
                top[ntop].comm[sizeof(top[ntop].comm) - 1] = '\0';
                top[ntop].kind = next.kind;
                top[ntop].count = value;
                ntop++;
            }
            key = next;
        }
    }
    for (int i = 0; i < ntop; i++)
        for (int j = i + 1; j < ntop; j++)
            if (top[j].count > top[i].count) {
                __typeof__(top[0]) tmp = top[i];
                top[i] = top[j];
                top[j] = tmp;
            }

    printf("{\"duration_s\":%d,\"cpus\":%d,\"attached\":%d,"
           "\"totals\":{\"switches\":%llu,\"wakeups\":%llu,\"page_faults\":%llu},"
           "\"per_cpu\":[",
           duration, ncpu, attached, totals[0], totals[1], totals[2]);
    for (int c = 0; c < ncpu; c++) {
        printf("%s{\"cpu\":%d,\"switches\":%llu,\"wakeups\":%llu,\"page_faults\":%llu}",
               c ? "," : "", c,
               cpu_totals ? cpu_totals[c] : 0,
               cpu_totals ? cpu_totals[ncpu + c] : 0,
               cpu_totals ? cpu_totals[2 * ncpu + c] : 0);
    }
    printf("],\"top_comms\":[");
    int shown = ntop < 15 ? ntop : 15;
    for (int i = 0; i < shown; i++) {
        printf("%s{\"comm\":\"%.16s\",\"kind\":%u,\"count\":%llu}",
               i ? "," : "", top[i].comm, top[i].kind, top[i].count);
    }
    printf("]}\n");

    free(per_cpu);
    free(cpu_totals);
    for (size_t i = 0; i < sizeof(links) / sizeof(links[0]); i++)
        if (links[i].link)
            bpf_link__destroy(links[i].link);
    bpf_object__close(obj);
    return 0;
}
