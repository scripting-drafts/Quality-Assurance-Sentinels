"""Live sentinel log monitor: timestamps, severity colours, terminal-friendly.

The sentinel's own execution log (`var/cron.log`) is the honest record of what it
did and when. This renders it live so a recurring failure is visible as it
happens instead of being reconstructed after the fact.

Colour is disabled automatically when stdout is not a TTY, so piping to a file or
through cron stays plain text.
"""
from __future__ import annotations

import os
import re
import shutil
import sys
import time
from collections import deque
from datetime import datetime
from pathlib import Path

from . import config

RESET = "\033[0m"
COLORS = {
    "critical": "\033[1;31m",
    "error": "\033[31m",
    "warning": "\033[33m",
    "ok": "\033[32m",
    "info": "\033[36m",
    "meta": "\033[35m",
    "stamp": "\033[90m",
    "dim": "\033[2m",
}

_CRITICAL = re.compile(r"(?i)\b(panic|oops|mce|machine check|hardware error|Xid|"
                       r"oom-kill|out of memory|segfault|unc?lean)\b")
_ERROR = re.compile(r"(?i)\b(error|failed|failure|traceback|exception|refused|denied)\b")
_WARNING = re.compile(r"(?i)\b(warn|retry|throttl|degraded|stale|drift|pending)\b")
_OK = re.compile(r"(?i)\b(ok|done|complete|sent|installed|recorded|verified|ready)\b")
_HAS_STAMP = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}|^\[\d{2}:\d{2}:\d{2}\]")


def supports_color(stream=None) -> bool:
    stream = stream or sys.stdout
    if os.environ.get("NO_COLOR"):
        return False
    return bool(getattr(stream, "isatty", lambda: False)())


def classify_line(line: str) -> str:
    if _CRITICAL.search(line):
        return "critical"
    if _ERROR.search(line):
        return "error"
    if _WARNING.search(line):
        return "warning"
    if _OK.search(line):
        return "ok"
    return "info"


def format_line(line: str, color: bool = True, stamp: str | None = None) -> str:
    line = line.rstrip("\n")
    if not line.strip():
        return ""
    if not _HAS_STAMP.search(line):
        stamp = stamp or datetime.now().strftime("%H:%M:%S")
        line = f"[{stamp}] {line}"
    if not color:
        return line
    kind = classify_line(line)
    code = COLORS.get(kind, COLORS["info"])
    if kind == "critical":
        return f"{COLORS['stamp']}[!]{RESET} {code}{line}{RESET}"
    return f"{code}{line}{RESET}"


def tail_lines(path, n: int) -> list[str]:
    try:
        with open(path, "r", errors="replace") as fh:
            return list(deque(fh, maxlen=max(1, n)))
    except OSError:
        return []


def rotate(path=None, max_bytes: int | None = None, keep: int | None = None) -> dict:
    """Copy-and-truncate the execution log when it reaches the size cap.

    cron opens ``var/cron.log`` with ``>>`` for each run and closes it when the
    run ends, so a copytruncate rotation is safe. It also keeps the live viewer
    working: ``follow()`` reopens the file when its size drops below the read
    offset. Rotation happens before a cycle writes its own output, which keeps
    the copy window to milliseconds.
    """
    target = Path(path or (config.VAR / "cron.log"))
    cap = config.LOG_MAX_MB * 1024 * 1024 if max_bytes is None else max_bytes
    copies = config.LOG_KEEP if keep is None else max(1, int(keep))
    try:
        size = target.stat().st_size
    except OSError:
        return {}
    if size < cap:
        return {}

    oldest = target.with_name(f"{target.name}.{copies}")
    if oldest.exists():
        oldest.unlink()
    for index in range(copies - 1, 0, -1):
        source = target.with_name(f"{target.name}.{index}")
        if source.exists():
            source.rename(target.with_name(f"{target.name}.{index + 1}"))

    backup = target.with_name(f"{target.name}.1")
    shutil.copyfile(target, backup)
    with target.open("w", encoding="utf-8"):
        pass
    return {"path": str(target), "backup": str(backup), "bytes": size, "keep": copies}


def header(conn) -> list[str]:
    """Small live status block printed before following starts."""
    from . import correlate

    def count(sql: str) -> int:
        try:
            return int(conn.execute(sql).fetchone()[0])
        except Exception:  # noqa: BLE001 - a header must never break the viewer
            return 0

    ready = 0
    try:
        ready = sum(1 for c in correlate.aggregate(conn) if c["ready"])
    except Exception:  # noqa: BLE001
        pass
    open_findings = count("SELECT COUNT(*) FROM findings WHERE status='open'")
    rows = [
        ("boots", f"{count('SELECT COUNT(*) FROM boots')} recorded, "
                  f"{count('SELECT COUNT(*) FROM boots WHERE ended_clean=0')} unclean"),
        ("findings", f"{open_findings} open"),
        ("drafts", f"{count('SELECT COUNT(*) FROM ticket_drafts')} pending"),
        ("correlations", f"{ready} ticket-ready"),
        ("notifications", f"{count('SELECT COUNT(*) FROM notifications WHERE delivered=0')} undelivered"),
        ("cross-check", _last_crosscheck(conn)),
    ]
    lines = [f"{config.PROJECT_NAME} live monitor", ""]
    for label, value in rows:
        lines.append(f"  {label:<14} {value}")
    lines += ["", f"  log            {config.VAR / 'cron.log'}", ""]
    return lines


def _last_crosscheck(conn) -> str:
    try:
        row = conn.execute(
            "SELECT ts, drift FROM crosschecks ORDER BY id DESC LIMIT 1"
        ).fetchone()
    except Exception:  # noqa: BLE001
        return "never"
    if not row:
        return "never"
    return f"{row['ts']} (drift {row['drift']})"


def follow(path, lines: int = 20, color: bool = True, poll: float = 0.5) -> None:
    path = str(path)
    for line in tail_lines(path, lines):
        print(format_line(line, color), flush=True)
    try:
        fh = open(path, "r", errors="replace")  # noqa: SIM115 - closed in finally
        fh.seek(0, os.SEEK_END)
    except OSError as exc:
        print(format_line(f"[monitor] cannot open {path}: {exc}", color), flush=True)
        return
    try:
        while True:
            chunk = fh.readline()
            if chunk:
                print(format_line(chunk, color), flush=True)
                continue
            time.sleep(poll)
            try:
                if os.path.getsize(path) < fh.tell():
                    fh.close()
                    fh = open(path, "r", errors="replace")
            except OSError:
                pass
    except KeyboardInterrupt:
        print("\n[monitor] stopped", flush=True)
    finally:
        try:
            fh.close()
        except Exception:  # noqa: BLE001
            pass


# ---------------------------------------------------------------- autostart
def install_autostart() -> dict:
    """Open the monitor in a terminal at login. User-level, no root needed."""
    autostart = os.path.expanduser("~/.config/autostart")
    os.makedirs(autostart, exist_ok=True)

    wrapper = config.BIN / "qa-logs-terminal"
    wrapper.write_text(
        "#!/usr/bin/env bash\n"
        f'cd "{config.ROOT}" || exit 1\n'
        "exec ./bin/qa logs --follow\n",
        encoding="utf-8",
    )
    wrapper.chmod(0o755)

    desk = os.path.join(autostart, "qa-sentinels-logs.desktop")
    with open(desk, "w", encoding="utf-8") as fh:
        fh.write(
            "[Desktop Entry]\n"
            "Type=Application\n"
            f"Name={config.PROJECT_NAME} live log\n"
            "Comment=Live coloured sentinel log with timestamps\n"
            f"Exec={wrapper}\n"
            "Terminal=true\n"
            "X-GNOME-Autostart-enabled=true\n"
            "Hidden=false\n"
        )
    return {"desktop": desk, "wrapper": str(wrapper)}
