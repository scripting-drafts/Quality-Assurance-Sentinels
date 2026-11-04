"""Package provenance for crash escalation.

A crash report is far more useful when the vendor can see *which build* was
running, not just the OS and kernel. This resolves the package that owns the
crashed executable and, when escalation needs it, the full installed package
inventory as ``name=version`` pairs.

Read-only and dependency-free: two dpkg queries, cached per process.
"""
from __future__ import annotations

from functools import lru_cache

from .util import run


@lru_cache(maxsize=1)
def installed() -> tuple[tuple[str, str], ...]:
    """Every installed package as (name, version), sorted by name."""
    rc, out, _ = run(
        ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"], timeout=60
    )
    if rc != 0:
        return ()
    rows = []
    for line in out.splitlines():
        if "\t" not in line:
            continue
        name, version = line.split("\t", 1)
        name, version = name.strip(), version.strip()
        if name:
            rows.append((name, version))
    return tuple(sorted(rows))


def owner(exe: str | None) -> dict:
    """Resolve the package owning an executable path."""
    if not exe:
        return {}
    rc, out, _ = run(["dpkg", "-S", str(exe)], timeout=20)
    if rc != 0:
        return {}
    versions = dict(installed())
    for line in out.splitlines():
        if ": " not in line or line.lower().startswith("diversion"):
            continue
        names, path = line.split(": ", 1)
        for name in (n.strip() for n in names.split(",")):
            if name in versions:
                return {"package": name, "version": versions[name], "path": path.strip()}
        name = names.split(",")[0].strip()
        if name:
            return {"package": name, "version": "", "path": path.strip()}
    return {}


def context(exe: str | None = None) -> dict:
    """Owner plus the complete package inventory, ready for a deep request."""
    packages = installed()
    return {
        "owner": owner(exe),
        "count": len(packages),
        "packages": [f"{name}={version}" for name, version in packages],
    }
