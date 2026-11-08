"""Boot boundary sentinel: classify why the previous boot ended.

Layer 1 samples a running system, so it is blind to the moment a machine stops
writing. This layer runs at the next boot and answers one question per boot:
did a shutdown sequence complete, or did the machine simply stop?

CLEAN   a ``systemd-shutdown`` sequence was logged and completed
UNCLEAN nothing of the kind was logged before the journal ends
UNKNOWN the journal no longer holds that boot

An UNCLEAN boot is not proof of a crash. It is the boundary condition that makes
a crash, a power loss or a firmware reset the only remaining explanations, so it
is escalated as a critical finding and carries the boot's own evidence with it.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime, timezone

from . import config, shutdown
from .util import iso, parse_iso, read_text, redact, run

SHUTDOWN_RE = re.compile(r"systemd-shutdown\[\d+\]:")

# One Xorg RandR probe prints roughly 28 NVIDIA(GPU-0) lines. A status poll
# every 0.4 s can add ~460k lines per boot and push the real last message out
# of the tail. These lines are presentation noise, not failure signatures.
TAIL_NOISE_RE = re.compile(
    r"NVIDIA\(GPU-0\):|NVIDIA\(0\): Setting mode|"
    r"\(EE\) event\d+.*client bug: event processing lagging"
)

# EFI pstore keeps the panic text that journald never receives. systemd-pstore
# archives it under <epoch/10>; a root helper can export a readable summary.
PSTORE_PANIC_RE = re.compile(
    r"Kernel panic|Oops:|BUG: unable|general protection fault|"
    r"stack-protector|Watchdog detected|hard LOCKUP|soft lockup"
)
PSTORE_WINDOW_BEFORE_S = 300
PSTORE_WINDOW_AFTER_S = 600

# (key, label, pattern) — deliberately anchored: a bare "BUG:" also matches
# Xorg's "client bug:" noise and would poison every boot verdict.
SCANS = [
    ("oom", "OOM killer",
     r"(?i)out of memory|oom-kill|Killed process"),
    ("panic", "kernel panic/oops",
     r"Kernel panic|[Kk]ernel BUG at|BUG: unable|Oops:|general protection fault|"
     r"soft lockup|hard LOCKUP|hung_task"),
    ("mce", "machine check",
     r"Machine check|\[Hardware Error\]|MCE: \["),
    ("watchdog", "watchdog",
     r"watchdog: BUG|Watchdog detected"),
    ("thermal", "thermal",
     r"(?i)thermal.*(?:critical|trip)|Package temperature above|throttl"),
    ("io", "I/O or fs errors",
     r"I/O error|EXT4-fs error|blk_update_request|ata[0-9]+.*failed"),
    ("coredump", "segfault/core dump",
     r"segfault at|core dumped|dumped core"),
    ("gpu", "nvidia/drm faults",
     r"Xid|NVRM|nv_drm_master_set|drm.*ERROR"),
]


# ---------------------------------------------------------------- journal
def _list_boots(limit: int = 8) -> list[dict]:
    rc, out, _ = run(["journalctl", "--list-boots", "--no-pager"], timeout=30)
    if rc != 0:
        return []
    boots = []
    for line in out.splitlines():
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        try:
            index = int(parts[0])
        except ValueError:
            continue
        boots.append({"index": index, "boot_id": parts[1], "span": parts[2].strip()})
    # only completed boots; the running one has no verdict yet
    return [b for b in boots if b["index"] < 0][-limit:]


def _journal(boot_id: str, n: int | None = None, priority: str | None = None) -> str:
    cmd = ["journalctl", "-b", boot_id, "--no-pager", "-o", "short-iso"]
    if priority:
        cmd += ["-p", priority]
    if n:
        cmd += ["-n", str(n)]
    rc, out, _ = run(cmd, timeout=60)
    return out if rc == 0 else ""


def _last_epoch(boot_id: str) -> str | None:
    rc, out, _ = run(
        ["journalctl", "-b", boot_id, "-n", "1", "-o", "json", "--no-pager"], timeout=30
    )
    if rc != 0:
        return None
    for line in out.splitlines():
        try:
            entry = json.loads(line)
            usec = int(entry["__REALTIME_TIMESTAMP"])
        except (ValueError, KeyError, TypeError, json.JSONDecodeError):
            continue
        return iso(datetime.fromtimestamp(usec / 1_000_000, tz=timezone.utc))
    return None


def _meaningful(lines: list[str]) -> list[str]:
    """Drop known high-volume Xorg/NVIDIA noise from a tail."""
    return [ln for ln in lines if ln.strip() and not TAIL_NOISE_RE.search(ln)]


def _pstore_epoch(name: str) -> int | None:
    # systemd-pstore names the directory with epoch seconds / 10.
    try:
        return int(name) * 10
    except (TypeError, ValueError):
        return None


def _pstore_archives(last_ts: str | None) -> list[dict]:
    """Find archived EFI pstore records near a boot's final journal entry.

    The archive directory name is the crash timestamp, not the next boot time.
    Read a root-exported summary when available; otherwise record that the
    root-only archive exists so the finding is not falsely called ``empty``.
    """
    if not last_ts:
        return []
    try:
        anchor = int(parse_iso(last_ts).timestamp())
    except (TypeError, ValueError):
        return []

    try:
        names = sorted(os.listdir(config.PSTORE_ARCHIVE_DIR))
    except OSError:
        return []

    found = []
    for name in names:
        epoch = _pstore_epoch(name)
        if epoch is None:
            continue
        if not (anchor - PSTORE_WINDOW_BEFORE_S <= epoch <= anchor + PSTORE_WINDOW_AFTER_S):
            continue

        item = {"name": name, "epoch": epoch, "readable": False, "source": "", "panic": ""}
        text = ""
        candidates = (
            ("export", config.PSTORE_EXPORT_DIR / name / "summary.txt"),
            ("archive", config.PSTORE_ARCHIVE_DIR / name / "dmesg.txt"),
        )
        for source, path in candidates:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            item["readable"] = True
            item["source"] = source
            break

        if text:
            hits = [ln.strip() for ln in text.splitlines() if PSTORE_PANIC_RE.search(ln)]
            if hits:
                # The archive is a new evidence source; redact it like the
                # journal before it reaches the database or a detail view.
                item["panic"] = redact(hits[-1])[:500]
        found.append(item)
    return found


def _pstore_labels(archives: list[dict] | None) -> list[str]:
    labels = []
    for item in archives or []:
        label = f"archive:{item['name']}"
        if item.get("panic"):
            label += ":panic"
        elif not item.get("readable"):
            label += ":root-only"
        else:
            label += ":no-panic"
        labels.append(label)
    return labels


def _pstore_scan(archives: list[dict]) -> dict | None:
    if not archives:
        return None
    hits = [a["panic"] for a in archives if a.get("panic")]
    unreadable = [a for a in archives if not a.get("readable")]
    scan = {
        "label": "archived pstore panic",
        "count": len(hits),
        "sample": hits[:3] or [
            f"{a['name']}: root-only archive (no readable export)"
            for a in unreadable[:3]
        ],
    }
    if hits:
        scan["note"] = f"archived pstore panic ({archives[-1]['name']})"
    elif unreadable:
        scan["note"] = f"archived pstore root-only ({len(unreadable)})"
    return scan


def _scan_output(boot_id: str) -> str:
    """Warning-or-worse lines across the WHOLE boot, filtered by journalctl.

    A bounded tail is wrong here: a chatty display driver can fill the last
    20k lines and push the boot's actual failure out of the window. journalctl
    filters server-side, so the result stays small even for a long boot.
    """
    combined = "|".join(f"(?:{pattern})" for _key, _label, pattern in SCANS)
    rc, out, _ = run(
        ["journalctl", "-b", boot_id, "--no-pager", "-o", "short-iso",
         "-p", "warning", "--grep", combined],
        timeout=120,
    )
    if rc == 0:
        return out
    # journalctl older than v237 has no --grep; bounded fallback
    return _journal(boot_id, n=20000, priority="warning")


# ---------------------------------------------------------------- shared helpers
def boot_info() -> dict:
    """Current boot time and uptime, for reports."""
    stat = read_text("/proc/stat")
    match = re.search(r"^btime\s+(\d+)", stat, re.MULTILINE)
    epoch = int(match.group(1)) if match else None
    return {
        "boot_epoch": epoch,
        "boot_time": (
            datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat() if epoch else "unknown"
        ),
        "uptime": read_text("/proc/uptime").split()[0] if read_text("/proc/uptime") else "?",
    }


def journal_tail(boot_ref: str, limit: int = 40, tail_only: bool = False
                 ) -> tuple[int, list[str]]:
    """Warning-or-worse lines for one boot. Count plus the last `limit` lines."""
    cmd = ["journalctl", "-b", boot_ref, "--no-pager", "-p", "warning", "-o", "short-iso"]
    if tail_only:
        cmd += ["-n", str(limit)]
    rc, out, err = run(cmd, timeout=60)
    if rc != 0:
        return 0, [f"(journal unavailable: {err.strip()[:160]})"]
    lines = _meaningful(out.splitlines())
    return len(lines), lines[-limit:]


# ---------------------------------------------------------------- host state
def _crash_capture_state(archives: list[dict] | None = None) -> dict:
    pstore: list[str] = []
    try:
        pstore = sorted(os.listdir("/sys/fs/pstore"))
    except OSError:
        pass

    # Keep archived records in the same column: "archive:<dir>:panic" when a
    # readable summary exists, otherwise "archive:<dir>:root-only".
    pstore.extend(_pstore_labels(archives))
    crashkernel = ""
    try:
        with open("/proc/cmdline", encoding="utf-8") as fh:
            m = re.search(r"crashkernel=\S+", fh.read())
            crashkernel = m.group(0) if m else ""
    except OSError:
        pass
    kexec = None
    try:
        with open("/sys/kernel/kexec_crash_loaded", encoding="utf-8") as fh:
            kexec = int(fh.read().strip())
    except (OSError, ValueError):
        pass
    try:
        vmcores = len([f for f in os.listdir("/var/crash") if f != "."])
    except OSError:
        vmcores = 0
    return {
        "pstore": pstore,
        "kexec_loaded": kexec,
        "crashkernel": crashkernel,
        "vmcores": vmcores,
    }


# ---------------------------------------------------------------- one boot
def scan_boot(boot: dict, refresh: bool = False) -> dict:
    boot_id = boot["boot_id"]
    tail = _journal(boot_id, n=300)
    wide = _scan_output(boot_id)
    last_ts = _last_epoch(boot_id) or iso()
    archives = _pstore_archives(last_ts)

    clean = bool(SHUTDOWN_RE.search(tail))
    lines = _meaningful(tail.splitlines())
    scans = {}
    for key, label, pattern in SCANS:
        regex = re.compile(pattern)
        hits = [ln for ln in wide.splitlines() if regex.search(ln)]
        scans[key] = {"label": label, "count": len(hits), "sample": hits[:3]}

    # The shutdown listener is the only source for errors written after the
    # last routine cycle.  Reconstruct the window for the latest completed
    # boot; older boots keep a capture record when one exists instead of
    # paying for another journal scan.
    try:
        sd = shutdown.scan_boot(
            boot_id, boot_id=boot_id, refresh=refresh,
            journal=boot.get("index") == -1,
        )
    except Exception:  # noqa: BLE001 - a boot verdict must not depend on this
        sd = {"count": 0, "errors": [], "phases": {}, "window_start": ""}
    phase_summary = sd.get("phases") or {}
    for phase, key, label in (
        ("boot", "startup", "startup errors"),
        ("shutdown", "shutdown", "shutdown errors"),
    ):
        items = [
            e for e in sd.get("errors", [])
            if (e.get("phase") or "shutdown") == phase
        ]
        summary = phase_summary.get(phase) or {}
        scans[key] = {
            "label": label,
            "count": int(summary.get("count") or len(items)),
            "sample": [str(e.get("message") or "")[:300] for e in items[:3]],
        }
        if summary.get("start"):
            scans[key]["window_start"] = summary["start"]

    pstore_scan = _pstore_scan(archives)
    if pstore_scan:
        scans["pstore"] = pstore_scan

    record = {
        "boot_id": boot_id,
        "seq": boot["index"],
        "span": boot["span"],
        "last_ts": last_ts,
        "ended_clean": 1 if clean else 0,
        "markers": "\n".join(ln for ln in tail.splitlines() if SHUTDOWN_RE.search(ln))[:2000],
        "last_message": (lines[-1][:2000] if lines else ""),
        "scans": json.dumps(scans, sort_keys=True),
    }
    record.update(_crash_capture_state(archives))
    return record


def refresh_pstore(conn) -> int:
    """Re-evaluate exported pstore archives for every recorded boot.

    ``collect(refresh=True)`` can only re-scan boots whose journal still
    exists. This pass uses the stored ``last_ts`` instead, so an export run
    later can upgrade an old ``archive:root-only`` record too.
    """
    updated = 0
    rows = conn.execute(
        "SELECT boot_id, last_ts, scans, pstore FROM boots"
    ).fetchall()
    for row in rows:
        archives = _pstore_archives(row["last_ts"])
        if not archives:
            continue
        try:
            scans = json.loads(row["scans"] or "{}")
        except json.JSONDecodeError:
            scans = {}
        scan = _pstore_scan(archives)
        if scan:
            scans["pstore"] = scan
        try:
            entries = json.loads(row["pstore"] or "[]")
        except json.JSONDecodeError:
            entries = []
        live = [p for p in entries if not str(p).startswith("archive:")]
        labels = live + _pstore_labels(archives)
        new_scans = json.dumps(scans, sort_keys=True)
        new_pstore = json.dumps(labels)
        if new_scans == (row["scans"] or "") and new_pstore == (row["pstore"] or ""):
            continue
        conn.execute(
            "UPDATE boots SET scans=?, pstore=? WHERE boot_id=?",
            (new_scans, new_pstore, row["boot_id"]),
        )
        updated += 1
    return updated


def collect(conn, limit: int = 8, refresh: bool = False) -> dict:
    """Record boots that are not in the store yet. Idempotent per boot id.

    ``refresh`` re-scans boots already stored, which matters when the scanner
    itself improves: a verdict is only as good as the evidence it read.
    """
    seen = {
        r["boot_id"]: r["scans"]
        for r in conn.execute("SELECT boot_id, scans FROM boots")
    }
    new, updated = [], []
    for boot in _list_boots(limit):
        exists = boot["boot_id"] in seen
        if exists and not refresh:
            # Backfill the newest completed boot once so an existing install
            # gains the shutdown evidence without waiting for another reboot.
            if boot["index"] != -1:
                continue
            try:
                scans = json.loads(seen[boot["boot_id"]] or "{}")
                if "startup" in scans and "shutdown" in scans:
                    continue
            except json.JSONDecodeError:
                pass
        record = scan_boot(boot, refresh=refresh)
        values = (
            record["seq"], record["span"], record["last_ts"], record["ended_clean"],
            record["markers"], record["last_message"], record["scans"],
            json.dumps(record["pstore"]), record["kexec_loaded"],
            record["crashkernel"], record["vmcores"], iso(),
        )
        if exists:
            conn.execute(
                "UPDATE boots SET seq=?, span=?, last_ts=?, ended_clean=?, markers=?,"
                " last_message=?, scans=?, pstore=?, kexec_loaded=?, crashkernel=?,"
                " vmcores=?, captured_ts=? WHERE boot_id=?",
                values + (record["boot_id"],),
            )
            updated.append(record)
        else:
            conn.execute(
                "INSERT OR IGNORE INTO boots"
                "(seq, span, last_ts, ended_clean, markers, last_message, scans,"
                " pstore, kexec_loaded, crashkernel, vmcores, captured_ts, boot_id)"
                " VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                values + (record["boot_id"],),
            )
            new.append(record)
    pstore_updated = refresh_pstore(conn) if refresh else 0
    return {
        "scanned": len(_list_boots(limit)),
        "new": len(new),
        "updated": len(updated),
        "pstore_updated": pstore_updated,
        "unclean": [r["boot_id"] for r in new + updated if r["ended_clean"] == 0],
        "records": [
            {
                "boot_id": r["boot_id"],
                "ended_clean": r["ended_clean"],
                "last_ts": r["last_ts"],
                "last_message": r["last_message"],
            }
            for r in new
        ],
    }


# ---------------------------------------------------------------- readers
def rows(conn, limit: int = 20) -> list[dict]:
    return [
        dict(r)
        for r in conn.execute("SELECT * FROM boots ORDER BY last_ts DESC LIMIT ?", (limit,))
    ]


def latest(conn) -> dict | None:
    row = conn.execute("SELECT * FROM boots ORDER BY last_ts DESC LIMIT 1").fetchone()
    return dict(row) if row else None


def verdict(row: dict) -> str:
    if row.get("ended_clean") is None:
        return "UNKNOWN"
    return "CLEAN" if row["ended_clean"] == 1 else "UNCLEAN"


def scan_counts(row: dict) -> dict:
    try:
        return json.loads(row.get("scans") or "{}")
    except json.JSONDecodeError:
        return {}


def findings(conn, since: str) -> list[dict]:
    """Layer-1 findings for boot boundaries that did not close cleanly."""
    out = []
    for row in conn.execute(
        "SELECT * FROM boots WHERE ended_clean=0"
        " AND COALESCE(captured_ts, last_ts)>=? ORDER BY last_ts DESC",
        (since,),
    ):
        row = dict(row)
        counts = scan_counts(row)
        noted_parts = []
        for value in counts.values():
            if value.get("count"):
                noted_parts.append(f"{value['label']}={value['count']}")
            elif value.get("note"):
                noted_parts.append(value["note"])
        noted = ", ".join(noted_parts) or "no failure signatures"

        pstore_entries = []
        try:
            pstore_entries = json.loads(row.get("pstore") or "[]")
        except json.JSONDecodeError:
            pass
        archived = [p for p in pstore_entries if str(p).startswith("archive:")]
        live = [p for p in pstore_entries if not str(p).startswith("archive:")]
        if archived and any(str(p).endswith(":panic") for p in archived):
            pstore_state = "archive(panic)"
        elif any(str(p).endswith(":root-only") for p in archived):
            pstore_state = "archive(root-only)"
        elif archived:
            pstore_state = "archive"
        elif live:
            pstore_state = "yes"
        else:
            pstore_state = "empty"

        out.append(
            {
                "fingerprint": f"boot|unclean|{row['boot_id']}",
                "ts": row["last_ts"],
                "last_ts": row["last_ts"],
                "rule": "boot.unclean",
                "severity": "critical",
                "subject": "boot",
                "detail": (
                    f"boot {row['boot_id'][:8]} ended without systemd-shutdown "
                    f"({noted}); last message: {(row['last_message'] or 'none')[:300]}; "
                    f"pstore={pstore_state} "
                    f"kexec_crash_loaded={row.get('kexec_loaded')}"
                ),
                "case_id": None,
            }
        )
    return out
