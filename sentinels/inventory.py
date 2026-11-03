"""Layered inventory of everything the machine is made of.

Each run stores (layer, item, value) for:
  L0-platform  firmware/DMI/CPU topology/GPU/NVMe
  L1-kernel    release, cmdline, sysctls, modules, boot params
  L2-services  systemd units, failed units, listening sockets, timers
  L3-packages  every installed dpkg package and version
  L4-userland  long-lived processes (comm+exe), key runtime versions
  L5-session   desktop/session identity and versions

Diff against the previous run yields explicit additions/removals/changes.
"""
from __future__ import annotations

import glob
import json
import os
import re
import socket
from collections import Counter
from datetime import timedelta

from . import config, db
from .util import iso, parse_iso, read_text, run, sha256_text, utcnow


def _put(out: dict, layer: str, item: str, value) -> None:
    if value is None:
        return
    text = str(value).strip()
    if not text:
        return
    out[(layer, item)] = text[:4000]


def _dmi(out: dict) -> None:
    for field in (
        "sys_vendor", "product_name", "product_version", "board_vendor",
        "board_name", "bios_vendor", "bios_version", "bios_date",
    ):
        value = read_text(f"/sys/class/dmi/id/{field}")
        if value:
            _put(out, "L0-platform", f"dmi/{field}", value)


def _cpu(out: dict) -> None:
    model = ""
    for line in read_text("/proc/cpuinfo").splitlines():
        if line.lower().startswith("model name"):
            model = line.split(":", 1)[1].strip()
            break
    _put(out, "L0-platform", "cpu/model", model)
    _put(out, "L0-platform", "cpu/logical_count", os.cpu_count())
    _put(out, "L0-platform", "cpu/online", read_text("/sys/devices/system/cpu/online"))

    found = []
    for path in sorted(glob.glob("/sys/devices/system/cpu/cpu[0-9]*/topology/core_id")):
        cpu = re.search(r"cpu(\d+)/", path)
        if not cpu:
            continue
        core_id = read_text(path)
        if core_id == str(config.CORE2_PHYSICAL_ID):
            found.append(int(cpu.group(1)))
    _put(out, "L0-platform", "cpu/core2_logical", ",".join(map(str, found)))
    _put(
        out, "L0-platform", "cpu/core2_siblings",
        read_text("/sys/devices/system/cpu/cpu2/topology/thread_siblings_list"),
    )

    # turbo/boost knobs explain frequency variance in crash reports
    _put(out, "L0-platform", "cpu/boost", read_text("/sys/devices/system/cpu/cpufreq/boost"))
    _put(out, "L0-platform", "cpu/governor",
         read_text("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"))


def _memory(out: dict) -> None:
    info = {}
    for line in read_text("/proc/meminfo").splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            info[k.strip()] = v.strip()
    for key in ("MemTotal", "SwapTotal", "Hugepagesize"):
        if key in info:
            _put(out, "L0-platform", f"memory/{key}", info[key])
    _put(out, "L0-platform", "memory/modules",
         "; ".join(read_text(p) for p in sorted(glob.glob("/sys/devices/system/edac/mc/mc*/dimm*/dimm_label"))[:8]))


def _gpu_and_storage(out: dict) -> None:
    rc, lspci, _ = run(["lspci", "-nn"], timeout=15)
    if rc == 0:
        for line in lspci.splitlines():
            if re.search(r"VGA|3D|Display", line):
                _put(out, "L0-platform", "pci/gpu", line.strip())
    rc, modinfo, _ = run(["nvidia-smi", "--query-gpu=name,driver_version,vbios_version",
                          "--format=csv,noheader"], timeout=15)
    if rc == 0 and modinfo.strip():
        _put(out, "L0-platform", "gpu/nvidia", modinfo.strip().replace("\n", "; "))
    for dev in sorted(glob.glob("/sys/block/nvme*n1")):
        name = os.path.basename(dev)
        _put(out, "L0-platform", f"storage/{name}/model",
             read_text(f"/sys/block/{name}/device/model"))
        _put(out, "L0-platform", f"storage/{name}/firmware",
             read_text(f"/sys/block/{name}/device/firmware_rev"))


def _kernel(out: dict) -> None:
    _put(out, "L1-kernel", "uname", read_text("/proc/sys/kernel/osrelease"))
    _put(out, "L1-kernel", "version", read_text("/proc/version"))
    _put(out, "L1-kernel", "cmdline", read_text("/proc/cmdline"))
    for key in (
        "panic", "panic_on_oops", "panic_on_warn", "hung_task_timeout_secs",
        "hung_task_panic", "softlockup_panic", "watchdog_thresh",
        "perf_event_paranoid", "unprivileged_bpf_disabled", "kptr_restrict",
        "dmesg_restrict", "tainted", "random/boot_id",
    ):
        _put(out, "L1-kernel", f"sysctl/kernel/{key}", read_text(f"/proc/sys/kernel/{key}"))
    for key in ("swappiness", "overcommit_memory", "overcommit_ratio", "min_free_kbytes"):
        _put(out, "L1-kernel", f"sysctl/vm/{key}", read_text(f"/proc/sys/vm/{key}"))

    modules = []
    for line in read_text("/proc/modules").splitlines():
        parts = line.split()
        if len(parts) >= 3:
            modules.append(f"{parts[0]}={parts[2]}B")
    _put(out, "L1-kernel", "modules/count", len(modules))
    _put(out, "L1-kernel", "modules/list", ",".join(sorted(modules)))

    sb = read_text("/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")
    if sb:
        try:
            _put(out, "L1-kernel", "secure_boot", int.from_bytes(sb.encode("latin-1")[4:5], "little"))
        except Exception:
            pass
    _put(out, "L1-kernel", "taint", read_text("/proc/sys/kernel/tainted"))


def _services(out: dict) -> None:
    rc, running, _ = run(
        ["systemctl", "list-units", "--type=service", "--state=running",
         "--no-legend", "--plain", "--no-pager"], timeout=20
    )
    if rc == 0:
        for line in running.splitlines():
            unit = line.split()[0] if line.split() else ""
            if unit:
                _put(out, "L2-services", f"running/{unit}", "active")

    rc, failed, _ = run(
        ["systemctl", "list-units", "--state=failed", "--no-legend", "--plain",
         "--no-pager"], timeout=20
    )
    if rc == 0:
        for line in failed.splitlines():
            unit = line.split()[0] if line.split() else ""
            if unit:
                _put(out, "L2-services", f"failed/{unit}", line.strip())

    rc, enabled, _ = run(
        ["systemctl", "list-unit-files", "--type=service", "--state=enabled",
         "--no-legend", "--no-pager"], timeout=20
    )
    if rc == 0:
        for line in enabled.splitlines():
            parts = line.split()
            if parts:
                _put(out, "L2-services", f"enabled/{parts[0]}", parts[1] if len(parts) > 1 else "enabled")

    rc, timers, _ = run(
        ["systemctl", "list-timers", "--all", "--no-legend", "--no-pager"], timeout=20
    )
    if rc == 0:
        for line in timers.splitlines():
            parts = line.split()
            if parts and parts[-1].endswith(".timer"):
                _put(out, "L2-services", f"timer/{parts[-1]}", "present")

    rc, sockets, _ = run(["ss", "-lntupH"], timeout=20)
    if rc == 0:
        for line in sockets.splitlines():
            parts = line.split()
            if len(parts) < 5:
                continue
            proto, local = parts[0], parts[3]
            proc = ""
            m = re.search(r'users:\(\("([^"]+)"', line)
            if m:
                proc = m.group(1)
            _put(out, "L2-services", f"listen/{proto}/{local}", proc)


def _packages(out: dict) -> None:
    rc, pkgs, _ = run(
        ["dpkg-query", "-W", "-f=${db:Status-Abbrev}\t${binary:Package}\t${Version}\n"],
        timeout=90,
    )
    if rc != 0:
        return
    for line in pkgs.splitlines():
        parts = line.split("\t")
        if len(parts) != 3:
            continue
        status, name, version = parts
        if not status.startswith("ii"):
            continue
        _put(out, "L3-packages", name, version)

    rc, snaps, _ = run(["snap", "list"], timeout=30)
    if rc == 0:
        for line in snaps.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2:
                _put(out, "L3-packages", f"snap:{parts[0]}", parts[1])


def _userland(out: dict, conn) -> None:
    row = conn.execute("SELECT ts, payload FROM samples ORDER BY ts DESC LIMIT 1").fetchone()
    if not row:
        return
    data = json.loads(row["payload"])
    procs = data.get("procs", [])
    seen = set()
    for proc in procs:
        comm = proc.get("comm") or ""
        exe = proc.get("exe") or ""
        if not comm:
            continue
        key = f"{comm}|{exe}"
        if key in seen:
            continue
        seen.add(key)
        _put(out, "L4-userland", f"process/{comm}", exe)
    _put(out, "L4-userland", "process/count", len(procs))

    for cmd in (["python3", "--version"], ["node", "--version"], ["firefox-esr", "--version"]):
        rc, out_s, err = run(cmd, timeout=10)
        if rc == 0:
            _put(out, "L4-userland", f"version/{cmd[0]}", (out_s or err).strip())

    driver = read_text("/proc/driver/nvidia/version")
    if driver:
        _put(out, "L4-userland", "version/nvidia-kernel", driver.splitlines()[0])


def _session(out: dict) -> None:
    for key in ("XDG_SESSION_TYPE", "XDG_CURRENT_DESKTOP", "XDG_SESSION_DESKTOP",
                "DESKTOP_SESSION", "WAYLAND_DISPLAY", "DISPLAY"):
        _put(out, "L5-session", f"env/{key}", os.environ.get(key))
    _put(out, "L5-session", "host", socket.gethostname())
    rc, versions, _ = run(
        ["dpkg-query", "-W", "-f=${Package}\t${Version}\n",
         "gnome-shell", "mutter", "gdm3", "libgtk-3-0", "libgl1-mesa-dri"],
        timeout=20,
    )
    if rc == 0:
        for line in versions.splitlines():
            parts = line.split("\t")
            if len(parts) == 2 and parts[1]:
                _put(out, "L5-session", f"pkg/{parts[0]}", parts[1])


def collect(conn) -> dict[tuple[str, str], str]:
    out: dict[tuple[str, str], str] = {}
    for fn in (_dmi, _cpu, _memory, _gpu_and_storage, _kernel, _services, _packages, _session):
        try:
            fn(out)
        except Exception:  # noqa: BLE001 - inventory is best effort per layer
            continue
    try:
        _userland(out, conn)
    except Exception:  # noqa: BLE001
        pass
    return out


def _fast_state() -> str:
    """Cheap fingerprint of things that mean "the machine changed"."""
    parts: list[str] = []
    for path in (
        "/var/lib/dpkg/status",
        "/var/lib/snapd/snaps",
        "/etc/systemd/system",
        "/usr/lib/systemd/system",
    ):
        try:
            st = os.stat(path)
            parts.append(f"{path}:{st.st_mtime_ns}:{st.st_size}")
        except OSError:
            parts.append(f"{path}:missing")
    parts.append("boot=" + read_text("/proc/sys/kernel/random/boot_id"))
    parts.append("kernel=" + read_text("/proc/sys/kernel/osrelease"))
    parts.append("modules=" + sha256_text(read_text("/proc/modules")))
    parts.append("online=" + read_text("/sys/devices/system/cpu/online"))
    return sha256_text("|".join(parts))


def next_interval(diff_count: int, item_count: int, baseline: bool = False) -> int:
    """Adapt the renewal period to how fast the machine is actually changing.

    <0.05% churn: 2x base; <0.5%: base; >=0.5%: half; >=2%: quarter.
    Always clamped to the configured floor/ceiling.
    """
    base = config.INVENTORY_INTERVAL_S
    if baseline or item_count <= 0:
        factor = 1.0
    else:
        ratio = diff_count / item_count
        if ratio >= 0.02:
            factor = 0.25
        elif ratio >= 0.005:
            factor = 0.5
        elif ratio <= 0.0005:
            factor = 2.0
        else:
            factor = 1.0
    return int(max(config.INVENTORY_MIN_S, min(config.INVENTORY_MAX_S, base * factor)))


def is_due(conn) -> tuple[bool, str]:
    """Decide whether to renew now, and why: baseline|event|scheduled."""
    last = db.meta_get(conn, "last_inventory_ts")
    if not last:
        return True, "baseline"
    now = utcnow()
    fast = _fast_state()
    previous_fast = db.meta_get(conn, "inventory_fast_state")
    if previous_fast and fast != previous_fast:
        age = (now - parse_iso(last)).total_seconds()
        if age >= config.INVENTORY_EVENT_GAP_S:
            return True, "event"
    next_ts = db.meta_get(conn, "next_inventory_ts")
    if next_ts and now < parse_iso(next_ts):
        return False, ""
    return True, "scheduled"


def run_inventory(conn, reason: str = "scheduled") -> dict:
    ts = iso()
    items = collect(conn)
    counts = Counter(layer for layer, _ in items)
    digest = sha256_text("\n".join(f"{l}|{i}|{v}" for (l, i), v in sorted(items.items())))

    prev = conn.execute(
        "SELECT id, digest FROM inventory_runs ORDER BY id DESC LIMIT 1"
    ).fetchone()

    cur = conn.execute(
        "INSERT INTO inventory_runs(ts, counts, digest, note) VALUES(?,?,?,?)",
        (ts, json.dumps(counts, sort_keys=True), digest,
         f"{reason}{'' if prev else ' (baseline)'}"),
    )
    run_id = cur.lastrowid
    conn.executemany(
        "INSERT OR REPLACE INTO inventory(run_id, layer, item, value) VALUES(?,?,?,?)",
        [(run_id, layer, item, value) for (layer, item), value in sorted(items.items())],
    )

    diffs = []
    if prev:
        old = {
            (r["layer"], r["item"]): r["value"]
            for r in conn.execute(
                "SELECT layer, item, value FROM inventory WHERE run_id=?", (prev["id"],)
            )
        }
        for key in sorted(set(old) | set(items)):
            layer, item = key
            before = old.get(key)
            after = items.get(key)
            if before == after:
                continue
            change = "added" if before is None else "removed" if after is None else "changed"
            diffs.append((ts, run_id, layer, change, item, before, after))
        conn.executemany(
            "INSERT INTO inventory_diffs(ts,run_id,layer,change,item,old_value,new_value)"
            " VALUES(?,?,?,?,?,?,?)",
            diffs,
        )

    db.meta_set(conn, "last_inventory_ts", ts)
    db.meta_set(conn, "last_inventory_id", str(run_id))
    interval = next_interval(len(diffs), len(items), baseline=prev is None)
    next_ts = (utcnow() + timedelta(seconds=interval)).strftime("%Y-%m-%dT%H:%M:%SZ")
    db.meta_set(conn, "inventory_interval_s", str(interval))
    db.meta_set(conn, "next_inventory_ts", next_ts)
    db.meta_set(conn, "inventory_fast_state", _fast_state())
    return {
        "ts": ts,
        "run_id": run_id,
        "counts": dict(counts),
        "digest": digest,
        "diffs": diffs,
        "previous_run": prev["id"] if prev else None,
        "reason": reason,
        "interval_s": interval,
        "next_ts": next_ts,
    }
