/* qa_sample.c — kernel/memory/CPU touch-base sampler for QA Sentinels.
 *
 * Reads only world-readable /proc and /sys interfaces, writes one JSON
 * object per invocation to stdout. Never exits non-zero because one
 * sensor is missing: the sentinel must keep reporting.
 *
 * Build: make -C src
 */
#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static void jesc(const char *s, FILE *f)
{
    if (!s) { fputs("null", f); return; }
    fputc('"', f);
    for (; *s; s++) {
        unsigned char c = (unsigned char)*s;
        switch (c) {
        case '"':  fputs("\\\"", f); break;
        case '\\': fputs("\\\\", f); break;
        case '\n': fputs("\\n", f); break;
        case '\r': fputs("\\r", f); break;
        case '\t': fputs("\\t", f); break;
        default:
            if (c < 0x20) fprintf(f, "\\u%04x", c);
            else fputc(c, f);
        }
    }
    fputc('"', f);
}

static char *read_file(const char *path)
{
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    size_t cap = 4096, len = 0;
    char *buf = malloc(cap);
    if (!buf) { fclose(f); return NULL; }
    size_t n;
    while ((n = fread(buf + len, 1, cap - len - 1, f)) > 0) {
        len += n;
        if (len + 1 >= cap) {
            cap *= 2;
            char *t = realloc(buf, cap);
            if (!t) { free(buf); fclose(f); return NULL; }
            buf = t;
        }
    }
    buf[len] = '\0';
    fclose(f);
    while (len && (buf[len - 1] == '\n' || buf[len - 1] == '\r'))
        buf[--len] = '\0';
    return buf;
}

static char *trim(char *s)
{
    while (*s && isspace((unsigned char)*s)) s++;
    char *e = s + strlen(s);
    while (e > s && isspace((unsigned char)e[-1])) *--e = '\0';
    return s;
}

/* ---------- /proc/stat ---------- */
static void emit_cpus(FILE *out)
{
    FILE *f = fopen("/proc/stat", "r");
    fputs("\"cpus\":[", out);
    if (!f) { fputs("]", out); return; }
    char line[512];
    int first = 1;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, "cpu", 3) != 0 || !isdigit((unsigned char)line[3]))
            continue;
        long long v[10] = {0};
        int n = sscanf(line, "cpu%d %lld %lld %lld %lld %lld %lld %lld %lld %lld %lld",
                       &(int){0}, &v[0], &v[1], &v[2], &v[3], &v[4],
                       &v[5], &v[6], &v[7], &v[8], &v[9]);
        if (n < 5) continue;
        int id = -1;
        sscanf(line, "cpu%d", &id);
        if (!first) fputc(',', out);
        first = 0;
        fprintf(out,
                "{\"cpu\":%d,\"user\":%lld,\"nice\":%lld,\"system\":%lld,"
                "\"idle\":%lld,\"iowait\":%lld,\"irq\":%lld,\"softirq\":%lld,"
                "\"steal\":%lld,\"guest\":%lld,\"guest_nice\":%lld}",
                id, v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7], v[8], v[9]);
    }
    fclose(f);
    fputs("]", out);
}

/* ---------- /proc/meminfo ---------- */
static const char *const mem_keys[] = {
    "MemTotal", "MemFree", "MemAvailable", "Buffers", "Cached", "SwapCached",
    "Active", "Inactive", "Dirty", "Writeback", "AnonPages", "Mapped",
    "Shmem", "Slab", "SReclaimable", "SUnreclaim", "PageTables",
    "Committed_AS", "CommitLimit", "HardwareCorrupted", "HugePages_Total",
    "HugePages_Free", "Hugepagesize", NULL
};

static void emit_mem(FILE *out)
{
    FILE *f = fopen("/proc/meminfo", "r");
    fputs("\"mem\":{", out);
    if (!f) { fputs("}", out); return; }
    char line[256];
    int first = 1;
    while (fgets(line, sizeof line, f)) {
        char *colon = strchr(line, ':');
        if (!colon) continue;
        *colon = '\0';
        char *name = trim(line);
        int wanted = 0;
        for (int k = 0; mem_keys[k]; k++)
            if (strcmp(name, mem_keys[k]) == 0) { wanted = 1; break; }
        if (!wanted) continue;
        if (!first) fputc(',', out);
        first = 0;
        jesc(name, out);
        fprintf(out, ":%lld", atoll(colon + 1));
    }
    fclose(f);
    fputs("}", out);
}

/* ---------- /proc/pressure ---------- */
static void emit_psi_one(FILE *out, const char *name)
{
    char path[64];
    snprintf(path, sizeof path, "/proc/pressure/%s", name);
    char *buf = read_file(path);
    fprintf(out, "\"%s\":", name);
    if (!buf) { fputs("null", out); return; }
    fputc('{', out);
    int first = 1;
    char *save = NULL;
    for (char *tok = strtok_r(buf, "\n", &save); tok; tok = strtok_r(NULL, "\n", &save)) {
        char kind[16];
        double a10 = -1, a60 = -1, a300 = -1;
        long long total = -1;
        if (sscanf(tok, "%15s avg10=%lf avg60=%lf avg300=%lf total=%lld",
                   kind, &a10, &a60, &a300, &total) < 5)
            continue;
        if (!first) fputc(',', out);
        first = 0;
        jesc(kind, out);
        fprintf(out, ":{\"avg10\":%.2f,\"avg60\":%.2f,\"avg300\":%.2f,\"total_us\":%lld}",
                a10, a60, a300, total);
    }
    fputc('}', out);
    free(buf);
}

/* ---------- thermal + hwmon ---------- */
static void emit_thermals(FILE *out)
{
    fputs("\"thermal\":[", out);
    int first = 1;
    for (int i = 0; i < 64; i++) {
        char p[128], *type, *temp;
        snprintf(p, sizeof p, "/sys/class/thermal/thermal_zone%d/type", i);
        type = read_file(p);
        if (!type) continue;
        snprintf(p, sizeof p, "/sys/class/thermal/thermal_zone%d/temp", i);
        temp = read_file(p);
        if (temp) {
            if (!first) fputc(',', out);
            first = 0;
            fprintf(out, "{\"zone\":%d,\"type\":", i);
            jesc(type, out);
            fprintf(out, ",\"millideg_c\":%lld}", atoll(temp));
        }
        free(type);
        free(temp);
    }
    fputs("],\"hwmon\":[", out);
    first = 1;
    for (int i = 0; i < 64; i++) {
        char p[128], *name;
        snprintf(p, sizeof p, "/sys/class/hwmon/hwmon%d/name", i);
        name = read_file(p);
        if (!name) continue;
        for (int t = 1; t <= 16; t++) {
            char tp[160], *val, *label;
            snprintf(tp, sizeof tp, "/sys/class/hwmon/hwmon%d/temp%d_input", i, t);
            val = read_file(tp);
            if (!val) continue;
            snprintf(tp, sizeof tp, "/sys/class/hwmon/hwmon%d/temp%d_label", i, t);
            label = read_file(tp);
            if (!first) fputc(',', out);
            first = 0;
            fprintf(out, "{\"chip\":");
            jesc(name, out);
            fputs(",\"label\":", out);
            jesc(label ? label : "temp", out);
            fprintf(out, ",\"millideg_c\":%lld}", atoll(val));
            free(val);
            free(label);
        }
        free(name);
    }
    fputs("]", out);
}

/* ---------- CPU frequency + online ---------- */
static void emit_freq(FILE *out)
{
    fputs("\"freq_mhz\":{", out);
    int first = 1;
    for (int i = 0; i < 4096; i++) {
        char p[128], *v = NULL;
        snprintf(p, sizeof p, "/sys/devices/system/cpu/cpu%d/cpufreq/scaling_cur_freq", i);
        v = read_file(p);
        if (!v) {
            snprintf(p, sizeof p, "/sys/devices/system/cpu/cpu%d/cpufreq/cpuinfo_cur_freq", i);
            v = read_file(p);
        }
        if (!v) {
            snprintf(p, sizeof p, "/sys/devices/system/cpu/cpu%d", i);
            if (access(p, F_OK) != 0) break;
            continue;
        }
        if (!first) fputc(',', out);
        first = 0;
        fprintf(out, "\"%d\":%.0f", i, atoll(v) / 1000.0);
        free(v);
    }
    fputs("}", out);
}

static void emit_core2(FILE *out)
{
    fputs("\"core2\":{\"physical_id\":2,\"logical\":[", out);
    int first = 1;
    for (int i = 0; i < 4096; i++) {
        char p[160], *id;
        snprintf(p, sizeof p, "/sys/devices/system/cpu/cpu%d/topology/core_id", i);
        id = read_file(p);
        if (!id) break;
        if (atoi(id) == 2) {
            if (!first) fputc(',', out);
            first = 0;
            fprintf(out, "%d", i);
        }
        free(id);
    }
    fputs("]}", out);
}

/* ---------- processes ---------- */
struct proc_row {
    int pid, ppid, threads, last_cpu, nr_threads;
    long long rss_kb, ticks;
    char state[8];
    char comm[64];
    char exe[PATH_MAX];
    char cpus[128];
};

static void emit_procs(FILE *out)
{
    DIR *d = opendir("/proc");
    fputs("\"procs\":[", out);
    if (!d) { fputs("]", out); return; }
    int first = 1;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (!isdigit((unsigned char)de->d_name[0])) continue;
        int pid = atoi(de->d_name);
        if (pid <= 0) continue;

        char p[128], *stat = NULL, *status = NULL;
        snprintf(p, sizeof p, "/proc/%d/stat", pid);
        stat = read_file(p);
        if (!stat) continue;
        char *lp = strrchr(stat, ')');
        char *rp = strchr(stat, '(');
        if (!lp || !rp || lp <= rp) { free(stat); continue; }

        struct proc_row r;
        memset(&r, 0, sizeof r);
        r.pid = pid;
        size_t cl = (size_t)(lp - rp - 1);
        if (cl >= sizeof r.comm) cl = sizeof r.comm - 1;
        memcpy(r.comm, rp + 1, cl);
        r.comm[cl] = '\0';

        char *t[40] = {0};
        int nt = 0;
        char *save = NULL;
        for (char *tok = strtok_r(lp + 2, " ", &save); tok && nt < 40;
             tok = strtok_r(NULL, " ", &save))
            t[nt++] = tok;
        if (nt < 37) { free(stat); continue; }

        snprintf(r.state, sizeof r.state, "%s", t[0]);
        r.ppid = atoi(t[1]);
        r.ticks = atoll(t[11]) + atoll(t[12]);
        r.nr_threads = atoi(t[17]);
        r.last_cpu = atoi(t[36]);

        snprintf(p, sizeof p, "/proc/%d/status", pid);
        status = read_file(p);
        if (status) {
            char *s = strstr(status, "\nVmRSS:");
            if (s) r.rss_kb = atoll(s + 8);
            s = strstr(status, "\nThreads:");
            if (s) r.threads = atoi(s + 10);
            if (!r.threads) r.threads = r.nr_threads;
            s = strstr(status, "\nCpus_allowed_list:");
            if (s) {
                s = trim(s + 19);
                char *e = strchr(s, '\n');
                if (e) *e = '\0';
                snprintf(r.cpus, sizeof r.cpus, "%s", s);
            }
        }
        snprintf(p, sizeof p, "/proc/%d/exe", pid);
        ssize_t n = readlink(p, r.exe, sizeof r.exe - 1);
        if (n > 0) r.exe[n] = '\0';
        free(status);

        if (!first) fputc(',', out);
        first = 0;
        fprintf(out, "{\"pid\":%d,\"ppid\":%d,\"comm\":", r.pid, r.ppid);
        jesc(r.comm, out);
        fprintf(out, ",\"state\":");
        jesc(r.state, out);
        fprintf(out, ",\"threads\":%d,\"rss_kb\":%lld,\"cpu_ticks\":%lld,"
                     "\"last_cpu\":%d,\"cpus_allowed\":",
                r.nr_threads ? r.nr_threads : r.threads, r.rss_kb, r.ticks, r.last_cpu);
        jesc(r.cpus, out);
        fputs(",\"exe\":", out);
        jesc(r.exe[0] ? r.exe : NULL, out);
        fputc('}', out);
        free(stat);
    }
    closedir(d);
    fputs("]", out);
}

int main(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    struct tm tm;
    gmtime_r(&ts.tv_sec, &tm);
    char iso[64];
    strftime(iso, sizeof iso, "%Y-%m-%dT%H:%M:%SZ", &tm);

    char *boot_id = read_file("/proc/sys/kernel/random/boot_id");
    char *online = read_file("/sys/devices/system/cpu/online");
    char *uptime = read_file("/proc/uptime");
    char *vmstat = read_file("/proc/vmstat");
    char *load = read_file("/proc/loadavg");
    char *version = read_file("/proc/version");

    printf("{\"schema\":1,\"ts\":");
    jesc(iso, stdout);
    fputs(",\"boot_id\":", stdout);
    jesc(boot_id, stdout);
    printf(",\"uptime_s\":%.0f", uptime ? atof(uptime) : 0.0);
    fputs(",\"loadavg\":[", stdout);
    if (load) {
        double a = 0, b = 0, c = 0;
        int runnable = 0, total = 0;
        if (sscanf(load, "%lf %lf %lf %d/%d", &a, &b, &c, &runnable, &total) >= 3)
            printf("%.2f,%.2f,%.2f", a, b, c);
    }
    printf("],\"online_cpus\":");
    jesc(online, stdout);
    fputs(",\"kernel\":", stdout);
    jesc(version, stdout);
    fputs(",\"oom_kill\":", stdout);
    if (vmstat) {
        char *s = strstr(vmstat, "oom_kill ");
        printf("%lld", s ? atoll(s + 9) : -1);
    } else fputs("-1", stdout);

    fputc(',', stdout);
    emit_cpus(stdout);
    fputc(',', stdout);
    emit_mem(stdout);
    fputs(",\"psi\":{", stdout);
    emit_psi_one(stdout, "cpu");
    fputc(',', stdout);
    emit_psi_one(stdout, "io");
    fputc(',', stdout);
    emit_psi_one(stdout, "memory");
    fputs("},", stdout);
    emit_freq(stdout);
    fputc(',', stdout);
    emit_thermals(stdout);
    fputc(',', stdout);
    emit_core2(stdout);
    fputc(',', stdout);
    emit_procs(stdout);
    fputs("}\n", stdout);

    free(boot_id); free(online); free(uptime); free(vmstat);
    free(load); free(version);
    return 0;
}
