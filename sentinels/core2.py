"""Physical-core topology used by ticket drafts.

The configured monitor targets physical core 2, but a ticket must state whether
that core actually exists on the current host.  A historical crash can carry a
core-2 affinity mask even when the current machine no longer exposes core 2.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import config, db
from .util import iso, read_text, redact, sha256_text


def topology(cpu_root: str | Path = "/sys/devices/system/cpu") -> dict:
    root = Path(cpu_root)
    logical: list[int] = []
    physical: set[tuple[str, str]] = set()
    readable = 0
    tried = 0
    for cpu in sorted(root.glob("cpu[0-9]*")):
        try:
            number = int(cpu.name[3:])
        except ValueError:
            continue
        tried += 1
        core_id = read_text(cpu / "topology" / "core_id").strip()
        package_id = read_text(cpu / "topology" / "physical_package_id").strip()
        if not core_id:
            continue
        readable += 1
        physical.add((package_id, core_id))
        if core_id == str(config.CORE2_PHYSICAL_ID):
            logical.append(number)

    if tried == 0 or readable == 0:
        return {
            "present": None,
            "physical_id": config.CORE2_PHYSICAL_ID,
            "logical": [],
            "configured": list(config.CORE2_CPUS),
            "physical_cores": None,
            "logical_cpus": tried or None,
            "source": "unknown",
        }

    return {
        "present": bool(logical),
        "physical_id": config.CORE2_PHYSICAL_ID,
        "logical": sorted(logical),
        "configured": list(config.CORE2_CPUS),
        "physical_cores": len(physical),
        "logical_cpus": tried,
        "source": "sysfs",
    }


def presence(topo: dict) -> str:
    """Short human-readable presence state for a heading or environment line."""
    if topo.get("present") is True:
        cpus = ", ".join(str(cpu) for cpu in topo.get("logical") or [])
        total = topo.get("physical_cores")
        logical = topo.get("logical_cpus")
        suffix = ""
        if total and logical:
            suffix = f"; {total} physical cores / {logical} logical CPUs"
        return f"present (logical CPUs {cpus or 'unknown'}{suffix})"
    if topo.get("present") is False:
        total = topo.get("physical_cores")
        logical = topo.get("logical_cpus")
        suffix = ""
        if total and logical:
            suffix = f"; {total} physical cores / {logical} logical CPUs"
        return f"absent (the host does not expose physical core {topo.get('physical_id', 2)}{suffix})"
    return "unknown (CPU topology is unavailable)"


def theme_tag(topo: dict) -> str:
    if topo.get("present") is True:
        return "physical core 2 present"
    if topo.get("present") is False:
        return "physical core 2 absent"
    return "physical core 2 unknown"


def available_cpus(topo: dict) -> list[int]:
    """Logical CPUs to use when a control run is needed."""
    if topo.get("present") is True and topo.get("logical"):
        return list(topo["logical"])
    return [0]


# --- isolation policy -------------------------------------------------------
#
# A degrading core is only safe while the policy that fenced it still holds.
# The fault-lab project (fault-injection-rig) sets one of two modes in
# /etc/faultlab/mode:
#   retired - CPUs 2 and 8 are offlined; nothing runs there.
#   lab     - CPUs are online but isolated and cgroup-fenced for test work.
# Any drift from that state is a security-relevant finding: a process may be
# executing on unreliable silicon without the operator noticing.

CORE2_BOOT_PARAMS = ("isolcpus", "nohz_full", "rcu_nocbs", "irqaffinity")


def parse_cpu_list(text: str) -> set[int]:
    """Parse a kernel CPU list such as ``0-1,3,8-9``. Invalid tokens are ignored."""
    cpus: set[int] = set()
    for part in (text or "").replace(" ", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            first, _, last = part.partition("-")
            try:
                cpus.update(range(int(first), int(last) + 1))
            except ValueError:
                continue
        else:
            try:
                cpus.add(int(part))
            except ValueError:
                continue
    return cpus


def boot_params(path: str | Path = "/proc/cmdline") -> dict[str, str]:
    params: dict[str, str] = {}
    for token in read_text(path).split():
        key, _, value = token.partition("=")
        params[key] = value or "1"
    return params


def _online(cpu_root: Path, cpus: set[int]) -> set[int]:
    online: set[int] = set()
    for cpu in cpus:
        state = read_text(cpu_root / f"cpu{cpu}" / "online")
        if state in ("", "1"):
            online.add(cpu)
    return online


def _cpuset(root: Path, name: str) -> str:
    return read_text(root / name / "cpuset.cpus")


def _irq_hits(irq_root: str | Path, core: set[int]) -> list[str]:
    hits: list[str] = []
    for path in sorted(Path(irq_root).glob("[0-9]*/smp_affinity_list")):
        if parse_cpu_list(read_text(path)) & core:
            hits.append(path.parent.name)
    return hits


def isolation(*, cpu_root: str | Path | None = None,
              cgroup_root: str | Path | None = None,
              cmdline_path: str | Path = "/proc/cmdline",
              mode_path: str | Path | None = None,
              irq_root: str | Path = "/proc/irq") -> dict:
    """Snapshot the core-2 isolation policy and the state it is meant to hold."""
    cpu_root = Path(cpu_root or config.CORE2_CPU_ROOT)
    cgroup_root = Path(cgroup_root or config.CORE2_CGROUP_ROOT)
    mode_path = Path(mode_path or config.CORE2_MODE_FILE)
    core = set(config.CORE2_CPUS)

    configured = read_text(mode_path).strip().lower()
    enforce = (config.CORE2_ENFORCE or "auto").lower()
    if enforce in ("lab", "retired", "off"):
        mode = enforce
    elif enforce == "auto":
        mode = configured if configured in ("lab", "retired") else ""
    else:
        mode = configured if configured in ("lab", "retired") else ""

    params = boot_params(cmdline_path)
    param_cpus = {
        name: parse_cpu_list(params.get(name, ""))
        for name in CORE2_BOOT_PARAMS
    }
    slices = {
        name: _cpuset(cgroup_root, name)
        for name in ("system.slice", "user.slice", "faultlab.slice")
    }
    return {
        "mode": mode,
        "configured_mode": configured,
        "core_cpus": sorted(core),
        "online": sorted(_online(cpu_root, core)),
        "params": params,
        "param_cpus": {name: sorted(cpus) for name, cpus in param_cpus.items()},
        "isolated": sorted(parse_cpu_list(
            read_text(cpu_root / "isolated"))),
        "nohz_full": sorted(parse_cpu_list(
            read_text(cpu_root / "nohz_full"))),
        "slices": slices,
        "irq_hits": _irq_hits(irq_root, core) if "irqaffinity" in params else [],
        "topology": topology(cpu_root),
    }


def _finding(rule: str, severity: str, subject: str, detail: str,
             fingerprint: str) -> dict:
    ts = iso()
    return {
        "fingerprint": fingerprint,
        "ts": ts,
        "last_ts": ts,
        "rule": rule,
        "severity": severity,
        "subject": subject,
        "detail": redact(detail),
        "case_id": None,
    }


def _ab_findings(conn, path: str | Path | None = None) -> list[dict]:
    """Consume new faultlab-ab verdicts from the append-only JSONL log."""
    path = Path(path or config.CORE2_AB_RESULTS)
    if not path.is_file():
        return []
    try:
        stat = path.stat()
    except OSError:
        return []
    size = stat.st_size
    try:
        cursor = int(db.meta_get(conn, "core2_ab_offset", "0") or "0")
    except (TypeError, ValueError):
        cursor = 0
    try:
        prior_mtime = int(db.meta_get(conn, "core2_ab_mtime", "0") or "0")
    except (TypeError, ValueError):
        prior_mtime = 0
    # A rewrite or truncation invalidates the byte cursor.
    if size < cursor or (size <= cursor and stat.st_mtime_ns != prior_mtime):
        cursor = 0
    if size == cursor:
        return []

    with path.open("rb") as fh:
        fh.seek(cursor)
        chunk = fh.read(1_048_576)
        end = fh.tell()
    if len(chunk) == 1_048_576:
        cut = chunk.rfind(b"\n")
        if cut >= 0:
            chunk = chunk[:cut + 1]
            end = cursor + len(chunk)
    db.meta_set(conn, "core2_ab_offset", str(end))
    db.meta_set(conn, "core2_ab_mtime", str(stat.st_mtime_ns))

    levels = {
        "DIVERGENCE": ("core2.ab.divergence", "critical"),
        "HW-SUSPECT": ("core2.ab.hw_suspect", "warning"),
        "CONTROL-UNSTABLE": ("core2.ab.control_unstable", "warning"),
    }
    out: list[dict] = []
    for raw in chunk.splitlines():
        try:
            record = json.loads(raw.decode("utf-8", "replace"))
        except ValueError:
            continue
        verdict = str(record.get("verdict", "")).upper()
        if verdict not in levels:
            continue
        rule, severity = levels[verdict]
        command = str(record.get("command", "")).strip()
        ts = str(record.get("ts", "")) or iso()
        detail = (
            f"verdict={verdict} exit={record.get('exit')} "
            f"runs={record.get('runs')} mode={record.get('mode')} "
            f"command={command[:200]}"
        )
        out.append(_finding(
            rule, severity, "faultlab-ab", detail,
            f"core2|ab|{verdict.lower()}|{ts}|{sha256_text(command)[:16]}",
        ))
    return out


def findings(conn, *, cpu_root: str | Path | None = None,
             cgroup_root: str | Path | None = None,
             cmdline_path: str | Path = "/proc/cmdline",
             mode_path: str | Path | None = None,
             irq_root: str | Path = "/proc/irq",
             ab_path: str | Path | None = None) -> list[dict]:
    """Layer-1 findings for core-2 isolation drift and fault-lab verdicts."""
    if not config.CORE2_ENABLE:
        return []
    try:
        state = isolation(cpu_root=cpu_root, cgroup_root=cgroup_root,
                          cmdline_path=cmdline_path, mode_path=mode_path,
                          irq_root=irq_root)
    except OSError:
        state = None

    out: list[dict] = []
    if state is not None:
        core = set(state["core_cpus"])
        online = set(state["online"])
        mode = state["mode"]
        topo = state["topology"]
        if topo.get("present") is False:
            out.append(_finding(
                "core2.topology.absent", "warning", "topology",
                f"physical core {config.CORE2_PHYSICAL_ID} is no longer exposed",
                "core2|topology|absent",
            ))
        elif topo.get("present") is True and set(topo.get("logical") or []) != core:
            out.append(_finding(
                "core2.topology.changed", "warning", "topology",
                f"physical core {config.CORE2_PHYSICAL_ID} maps to logical "
                f"{topo.get('logical')} (expected {sorted(core)})",
                "core2|topology|changed",
            ))

        if mode == "retired":
            live = sorted(online & core)
            if live:
                out.append(_finding(
                    "core2.retired.online", "critical", "cpu",
                    f"mode=retired but CPUs {live} are online; the faulty core "
                    "is accepting work",
                    "core2|retired|online|" + ",".join(str(c) for c in live),
                ))
        elif mode == "lab":
            if not online & core:
                out.append(_finding(
                    "core2.lab.offline", "warning", "cpu",
                    "mode=lab but CPUs " + ",".join(str(c) for c in sorted(core))
                    + " are offline",
                    "core2|lab|offline",
                ))
            missing = [
                name for name in ("isolcpus", "nohz_full", "rcu_nocbs")
                if not (set(state["param_cpus"].get(name, [])) & core)
            ]
            if not core <= set(state["isolated"]):
                missing.append("sysfs:isolated")
            if not core <= set(state["nohz_full"]):
                missing.append("sysfs:nohz_full")
            if missing:
                out.append(_finding(
                    "core2.isolation.missing", "warning", "boot",
                    "missing or incomplete isolation: " + ", ".join(missing),
                    "core2|isolation|missing|lab",
                ))
            for name in ("system.slice", "user.slice"):
                cpus = parse_cpu_list(state["slices"].get(name, ""))
                if not cpus or cpus & core:
                    out.append(_finding(
                        "core2.isolation.unfenced", "critical", name,
                        f"{name} cpuset '{state['slices'].get(name, '')}' still "
                        "allows the faulty core",
                        f"core2|isolation|unfenced|{name}",
                    ))
            lab_cpus = parse_cpu_list(state["slices"].get("faultlab.slice", ""))
            if not lab_cpus & core:
                out.append(_finding(
                    "core2.lab.slice_missing", "warning", "faultlab.slice",
                    "faultlab.slice is missing or does not contain CPUs "
                    + ",".join(str(c) for c in sorted(core)),
                    "core2|lab|slice|faultlab",
                ))
            if "irqaffinity" in state["params"] and state["irq_hits"]:
                out.append(_finding(
                    "core2.irq.affinity", "warning", "irq",
                    "IRQ affinity still includes the faulty core: "
                    + ", ".join(state["irq_hits"][:12]),
                    "core2|irq|affinity",
                ))

    out.extend(_ab_findings(conn, ab_path))
    return out
