"""Physical-core topology used by ticket drafts.

The configured monitor targets physical core 2, but a ticket must state whether
that core actually exists on the current host.  A historical crash can carry a
core-2 affinity mask even when the current machine no longer exposes core 2.
"""
from __future__ import annotations

from pathlib import Path

from . import config
from .util import read_text


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
