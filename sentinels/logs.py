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
import sys
import time
from collections import deque
from datetime import datetime

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


def _count(conn, sql: str) -> int:
    try:
        return int(conn.execute(sql).fetchone()[0])
    except Exception:  # noqa: BLE001 - a viewer must never break on a missing table
        return 0


def _dir_count(path) -> int:
    try:
        return sum(1 for child in path.iterdir() if child.is_dir())
    except OSError:
        return 0


def state_rows(conn) -> list[tuple[str, str]]:
    """The numbers every view shares."""
    from . import correlate, holds

    ready = 0
    try:
        ready = sum(1 for c in correlate.aggregate(conn) if c["ready"])
    except Exception:  # noqa: BLE001
        pass
    hold = holds.counts()
    open_findings = _count(conn, "SELECT COUNT(*) FROM findings WHERE status='open'")
    return [
        ("boots", f"{_count(conn, 'SELECT COUNT(*) FROM boots')} recorded, "
                  f"{_count(conn, 'SELECT COUNT(*) FROM boots WHERE ended_clean=0')} unclean"),
        ("findings", f"{open_findings} open"),
        ("drafts", f"{_count(conn, 'SELECT COUNT(*) FROM ticket_drafts')} pending"),
        ("raise", f"{_dir_count(config.RAISE_DIR)} staged, "
                  f"{_dir_count(config.STANDBY_DIR)} in standby"),
        ("correlations", f"{ready} ticket-ready"),
        ("notifications", f"{_count(conn, 'SELECT COUNT(*) FROM notifications WHERE delivered=0')} undelivered"),
        ("holds", f"{hold['held_total']} held, {hold['held_installed']} installed"
                  f"{' (GLOBAL HOLD)' if hold['mass_hold'] else ''}"),
        ("cross-check", _last_crosscheck(conn)),
    ]


def header(conn) -> list[str]:
    """Small live status block printed before following starts."""
    lines = ["qa-sentinels live monitor", ""]
    lines += [f"  {label:<14} {value}" for label, value in state_rows(conn)]
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


def _live_sections(conn, path, lines: int) -> list[tuple[str, list[str]]]:
    """One entry per section, in display order. Queried fresh each cycle."""
    from . import correlate

    sections = [
        ("State", [f"  {label:<14} {value}" for label, value in state_rows(conn)]),
    ]

    findings = conn.execute(
        "SELECT severity, rule, subject, detail FROM findings WHERE status='open'"
        " ORDER BY ts DESC LIMIT 6"
    ).fetchall() if _count(conn, "SELECT COUNT(*) FROM findings") else []
    body = [
        f"  {row['severity']:<9} {row['rule']:<18} {str(row['subject'])[:16]:<16} "
        f"{(row['detail'] or '')[:90]}"
        for row in findings
    ]
    sections.append(("Open findings", body or ["  none"]))

    ready = 0
    try:
        ready = sum(1 for c in correlate.aggregate(conn) if c["ready"])
    except Exception:  # noqa: BLE001
        pass
    sections.append(("Ticket pipeline", [
        f"  drafts {_count(conn, 'SELECT COUNT(*) FROM ticket_drafts')}"
        f" · raise {_dir_count(config.RAISE_DIR)}"
        f" · standby {_dir_count(config.STANDBY_DIR)}"
        f" · ready correlations {ready}"
    ]))

    tail = [format_line(line, color=False) for line in tail_lines(path, lines)]
    sections.append(("Recent activity", tail or ["  (log empty)"]))
    return sections


def live(path, lines: int = 10, color: bool = True, interval: int = 5) -> None:
    """Iterate the sections, redrawing in place until interrupted."""
    from . import db

    path = str(path)
    try:
        while True:
            if color:
                sys.stdout.write("\033[2J\033[H")
            stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"{COLORS['meta'] if color else ''}qa-sentinels live · {stamp}"
                  f"{RESET if color else ''}")
            with db.session() as conn:
                for title, body in _live_sections(conn, path, lines):
                    pad = "─" * max(0, 46 - len(title))
                    heading = f"── {title} {pad}"
                    print(f"{COLORS['info'] if color else ''}{heading}{RESET if color else ''}")
                    for line in body:
                        print(line)
                    print()
            if not color:
                print("[live] non-interactive output: rendered once")
                return
            time.sleep(max(1, interval))
    except KeyboardInterrupt:
        print("\n[live] stopped", flush=True)


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
            "Name=QA sentinels live log\n"
            "Comment=Live coloured sentinel log with timestamps\n"
            f"Exec={wrapper}\n"
            "Terminal=true\n"
            "X-GNOME-Autostart-enabled=true\n"
            "Hidden=false\n"
        )
    return {"desktop": desk, "wrapper": str(wrapper)}
