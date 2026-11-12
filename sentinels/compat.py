"""Ubuntu upgrade compatibility checks for QA Sentinels.

The matrix is intentionally conservative: a host outside the supported
Ubuntu/Python/SQLite/systemd/kernel range is reported as unsupported instead of
being silently assumed to work.
"""
from __future__ import annotations

import os
import platform
import re
import sqlite3
from pathlib import Path

from .util import read_text, run

SUPPORTED_OS = (
    (22, 4), (24, 4), (24, 10), (25, 4), (25, 10), (26, 4), (26, 10),
)
MIN_PYTHON = (3, 10)
MIN_SQLITE = (3, 37)
MIN_SYSTEMD = (249,)
MIN_KERNEL = (5, 15)


def _version_tuple(value: str) -> tuple[int, ...] | None:
    parts = re.findall(r"\d+", value or "")
    if not parts:
        return None
    return tuple(int(part) for part in parts[:3])


def _os_release() -> dict[str, str]:
    data = {}
    for line in read_text("/etc/os-release").splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        data[key.strip()] = value.strip().strip('"')
    return data


def _systemd_version() -> str:
    rc, out, err = run(["systemctl", "--version"], timeout=10)
    match = re.search(r"systemd\s+(\d+(?:\.\d+)*)", out or err)
    return match.group(1) if match else "unknown"


def evaluate(os_id: str, os_version: str, python_version: str,
             sqlite_version: str, systemd_version: str,
             kernel_version: str) -> dict:
    os_tuple = _version_tuple(os_version)
    py_tuple = _version_tuple(python_version)
    sqlite_tuple = _version_tuple(sqlite_version)
    systemd_tuple = _version_tuple(systemd_version)
    kernel_tuple = _version_tuple(kernel_version)
    checks = [
        {
            "name": "Ubuntu release",
            "ok": os_id.lower() == "ubuntu" and os_tuple in SUPPORTED_OS,
            "detail": f"{os_id or 'unknown'} {os_version or 'unknown'}",
        },
        {
            "name": "Python >= 3.10",
            "ok": bool(py_tuple and py_tuple >= MIN_PYTHON),
            "detail": python_version or "unknown",
        },
        {
            "name": "SQLite >= 3.37",
            "ok": bool(sqlite_tuple and sqlite_tuple >= MIN_SQLITE),
            "detail": sqlite_version or "unknown",
        },
        {
            "name": "systemd >= 249",
            "ok": bool(systemd_tuple and systemd_tuple >= MIN_SYSTEMD),
            "detail": systemd_version or "unknown",
        },
        {
            "name": "kernel >= 5.15",
            "ok": bool(kernel_tuple and kernel_tuple >= MIN_KERNEL),
            "detail": kernel_version or "unknown",
        },
    ]
    supported = all(check["ok"] for check in checks)
    return {
        "supported": supported,
        "checks": checks,
        "summary": (
            "supported Ubuntu baseline"
            if supported else
            "outside the documented Ubuntu 22.04-26.10 baseline"
        ),
    }


def report() -> dict:
    release = _os_release()
    data = evaluate(
        release.get("ID", ""),
        release.get("VERSION_ID", ""),
        platform.python_version(),
        sqlite3.sqlite_version,
        _systemd_version(),
        os.uname().release,
    )
    data["os"] = {
        "id": release.get("ID", ""),
        "version_id": release.get("VERSION_ID", ""),
        "pretty": release.get("PRETTY_NAME", ""),
    }
    data["versions"] = {
        "python": platform.python_version(),
        "sqlite": sqlite3.sqlite_version,
        "kernel": os.uname().release,
    }
    data["documentation"] = "docs/COMPATIBILITY.md"
    if not data["supported"]:
        data["note"] = (
            "Review docs/COMPATIBILITY.md before upgrading; "
            "run the full test suite on the new release."
        )
    return data
