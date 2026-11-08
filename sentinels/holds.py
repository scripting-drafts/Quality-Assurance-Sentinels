"""Held packages: what is pinned, and which pinned modules are outdated.

A crash in a held package is a different diagnosis than a crash in a normally
updated one: the running build may be months behind its candidate, and the fix
may already exist. This module answers two questions cheaply:

  * is the crashed package (or its module family) on hold?
  * is the held version actually older than what the archive offers?

`apt-mark showhold` can be very large (a global hold is a misconfiguration, not
a pin), so hold membership is always intersected with installed packages and
filtered to the crash's own family before any policy lookup happens.
"""
from __future__ import annotations

import re
from functools import lru_cache

from . import packages
from .util import run

# module-bearing families worth matching when a crash names no package
MODULE_PREFIXES = (
    "nvidia-", "linux-image-", "linux-modules-", "linux-headers-",
    "linux-generic", "dkms", "xserver-xorg-video-",
)


@lru_cache(maxsize=1)
def held() -> tuple[str, ...]:
    rc, out, _ = run(["apt-mark", "showhold"], timeout=60)
    if rc != 0:
        return ()
    return tuple(sorted(line.strip() for line in out.splitlines() if line.strip()))


@lru_cache(maxsize=256)
def _policies(names: tuple[str, ...]) -> dict[str, dict]:
    if not names:
        return {}
    rc, out, _ = run(["apt-cache", "policy", *names], timeout=120)
    if rc != 0:
        return {}
    result: dict[str, dict] = {}
    current = None
    for line in out.splitlines():
        head = re.match(r"^(\S+):$", line)
        if head:
            current = head.group(1)
            result[current] = {"installed": None, "candidate": None}
            continue
        if current is None or not line.startswith("  "):
            continue
        if line.startswith("  Installed:"):
            result[current]["installed"] = line.split(":", 1)[1].strip()
        elif line.startswith("  Candidate:"):
            result[current]["candidate"] = line.split(":", 1)[1].strip()
    for row in result.values():
        for key in ("installed", "candidate"):
            if row[key] in ("(none)", "none", ""):
                row[key] = None
    return result


def policy(name: str) -> dict:
    return _policies((name,)).get(name, {})


def counts() -> dict:
    installed = dict(packages.installed())
    held_names = [name for name in held() if name in installed]
    return {
        "held_total": len(held()),
        "installed_total": len(installed),
        "held_installed": len(held_names),
        # a hold set larger than the installed system is a global pin, not a choice
        "mass_hold": len(held()) > max(50, len(installed) * 2),
    }


def _related(name: str, owner: str | None) -> bool:
    if owner:
        if name == owner:
            return True
        family = owner.split("-")[0]
        return bool(family) and name.startswith(family + "-")
    # Module families are only a fallback when the executable has no owner.
    # Otherwise every held nvidia-* package would be attributed to every crash.
    return name.startswith(MODULE_PREFIXES)


def relevant(exe: str | None = None) -> dict:
    """Held, installed packages related to a crashed executable."""
    installed = dict(packages.installed())
    owner = packages.owner(exe).get("package")
    names = tuple(
        name for name in held()
        if name in installed and _related(name, owner)
    )
    policies = _policies(names)
    rows = []
    for name in names:
        policy = policies.get(name, {})
        current = policy.get("installed") or installed.get(name)
        candidate = policy.get("candidate")
        rows.append({
            "package": name,
            "installed": current,
            "candidate": candidate,
            "outdated": bool(current and candidate and current != candidate),
        })
    summary = counts()
    summary.update({
        "owner": owner,
        "relevant": rows,
        "outdated": [row for row in rows if row["outdated"]],
    })
    return summary
