"""Desktop pop-ups for tickets that are about to be raised.

A draft sitting unnoticed in `tickets/drafts/` is worth nothing. This module
turns "a ticket became ready" into a visible notification, once per cluster,
and makes the notification **open the markdown it refers to**.

Click handling needs the freedesktop notification action API, which
`notify-send` 0.7.9 does not expose. When PyGObject is available the pop-up is
delivered over D-Bus with a `default` action and a detached waiter opens the
file; otherwise it degrades to a plain, unclickable notification and says so.

Delivery is best-effort: no session bus or notifier leaves the row queued and
`qa notify` reports it honestly. Send attempts are bounded so a dead backend
cannot hang a cycle indefinitely.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from datetime import timedelta

from . import config
from .util import iso, parse_iso, sha256_text, utcnow, write_text_atomic

APP = config.PROJECT_NAME


# ---------------------------------------------------------------- environment
def _runtime_dir() -> str:
    return f"/run/user/{os.getuid()}"


def _session_bus() -> str | None:
    """Address of the user session bus, even when cron scrubbed the env."""
    bus = os.environ.get("DBUS_SESSION_BUS_ADDRESS")
    if bus:
        return bus
    path = os.path.join(_runtime_dir(), "bus")
    if os.path.exists(path):
        return f"unix:path={path}"
    return None


def _graphical_session() -> bool:
    """True only when a click could actually open a file."""
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def _env() -> dict:
    env = dict(os.environ)
    bus = _session_bus()
    if bus and not env.get("DBUS_SESSION_BUS_ADDRESS"):
        env["DBUS_SESSION_BUS_ADDRESS"] = bus
    if not env.get("XDG_RUNTIME_DIR") and os.path.isdir(_runtime_dir()):
        env["XDG_RUNTIME_DIR"] = _runtime_dir()
    # The detached click helper imports sentinels; keep the repository first
    # even if the caller already exported an unrelated PYTHONPATH.
    env["PYTHONPATH"] = os.pathsep.join(
        [str(config.ROOT)] + ([env["PYTHONPATH"]] if env.get("PYTHONPATH") else [])
    )
    return env


def available() -> tuple[bool, str]:
    """Can a notification reach the desktop?

    Delivery is a D-Bus operation; DISPLAY is only needed later, to open a
    file on click. Cron has the session bus path but usually no DISPLAY, so
    requiring a graphical variable here would queue every scheduled alert
    forever.
    """
    if shutil.which("notify-send") is None and not _gi_available():
        return False, "no notification backend (notify-send or PyGObject)"
    if not _session_bus():
        return False, "no session bus (DBUS_SESSION_BUS_ADDRESS unset)"
    return True, "ok"


def _gi_available() -> bool:
    try:
        import gi

        gi.require_version("Gio", "2.0")
        from gi.repository import Gio, GLib  # noqa: F401

        return True
    except Exception:  # noqa: BLE001 - optional acceleration, never a requirement
        return False


# ---------------------------------------------------------------- opening
def open_target(path: str) -> tuple[bool, str]:
    """Open the markdown. QA_NOTIFY_OPEN=file|folder|select picks the view."""
    path = str(path)
    mode = os.environ.get("QA_NOTIFY_OPEN", "file").lower()
    if not os.path.exists(path):
        return False, f"missing target: {path}"
    if mode == "select" and shutil.which("nautilus"):
        cmd = ["nautilus", "--select", path]
    elif mode == "folder":
        cmd = ["xdg-open", os.path.dirname(path) or "."]
    elif shutil.which("xdg-open"):
        cmd = ["xdg-open", path]
    else:
        return False, "no opener (xdg-open missing)"
    try:
        subprocess.Popen(  # noqa: S603 - fixed argv, no shell
            cmd, env=_env(), start_new_session=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except OSError as exc:
        return False, str(exc)[:200]
    return True, " ".join(cmd)


# ---------------------------------------------------------------- sending
def send(title: str, body: str, urgency: str = "normal",
         path: str | None = None) -> tuple[bool, str]:
    ok, why = available()
    if not ok:
        return False, why
    if path:
        if _gi_available() and _graphical_session():
            if _spawn_click_helper(path, title, body, urgency):
                return True, "sent (click opens the markdown)"
            return False, "could not spawn the click helper"
        # A click cannot open anything without a desktop session. Deliver the
        # content anyway rather than dropping an alert on a headless cycle.
        ok, why = _plain_send(title, body, urgency)
        if ok:
            if not _graphical_session():
                return True, f"{why} (click support unavailable: no graphical session)"
            return True, f"{why} (click support unavailable: PyGObject missing)"
        return ok, why
    return _plain_send(title, body, urgency)


def _gi_send(title: str, body: str, urgency: str) -> tuple[bool, str]:
    """Plain D-Bus delivery when notify-send is not installed."""
    bus_address = _session_bus()
    if bus_address and not os.environ.get("DBUS_SESSION_BUS_ADDRESS"):
        # Gio reads the address from the process environment, unlike
        # notify-send which gets the prepared env below.
        os.environ["DBUS_SESSION_BUS_ADDRESS"] = bus_address
    try:
        import gi

        gi.require_version("Gio", "2.0")
        gi.require_version("GLib", "2.0")
        from gi.repository import Gio, GLib

        bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
        proxy = Gio.DBusProxy.new_sync(
            bus, Gio.DBusProxyFlags.NONE, None,
            "org.freedesktop.Notifications", "/org/freedesktop/Notifications",
            "org.freedesktop.Notifications", None,
        )
        hints = {
            "urgency": GLib.Variant(
                "y", {"low": 0, "normal": 1, "critical": 2}.get(urgency, 1)
            ),
        }
        proxy.call_sync(
            "Notify",
            GLib.Variant("(susssasa{sv}i)", (
                APP, 0, "", title, body, [], hints, 0,
            )),
            Gio.DBusCallFlags.NONE, -1, None,
        )
    except Exception as exc:  # noqa: BLE001 - optional backend
        return False, str(exc)[:200]
    return True, "sent (D-Bus)"


def _plain_send(title: str, body: str, urgency: str) -> tuple[bool, str]:
    if shutil.which("notify-send") is None:
        if _gi_available():
            return _gi_send(title, body, urgency)
        return False, "notify-send not installed"
    try:
        proc = subprocess.run(
            ["notify-send", "-a", APP, "-u", urgency, "-t", "0", "--",
             title, body.lstrip("- ")],
            capture_output=True, text=True, timeout=10, env=_env(), check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return False, str(exc)[:200]
    if proc.returncode != 0:
        return False, (proc.stderr or proc.stdout or "notify-send failed").strip()[:200]
    return True, "sent"


def _spawn_click_helper(path: str, title: str, body: str, urgency: str) -> bool:
    env = _env()
    env.update({
        "QA_NOTIFY_PATH": str(path),
        "QA_NOTIFY_TITLE": title,
        "QA_NOTIFY_BODY": body,
        "QA_NOTIFY_URGENCY": urgency,
    })
    try:
        proc = subprocess.Popen(  # noqa: S603 - fixed argv
            [sys.executable, "-m", "sentinels.notify", "--wait-open"],
            cwd=str(config.ROOT), env=env, start_new_session=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except OSError:
        return False
    # A helper that dies during import or before its D-Bus Notify call must
    # not be recorded as delivered. A healthy waiter lives for hours, so the
    # short wait only catches startup failures.
    try:
        return proc.wait(timeout=0.5) == 0
    except subprocess.TimeoutExpired:
        return True


def _wait_open_main() -> int:
    """Detached helper: show a clickable pop-up, then open the file on click."""
    import gi

    gi.require_version("Gio", "2.0")
    gi.require_version("GLib", "2.0")
    from gi.repository import Gio, GLib

    path = os.environ.get("QA_NOTIFY_PATH", "")
    title = os.environ.get("QA_NOTIFY_TITLE", APP)
    body = os.environ.get("QA_NOTIFY_BODY", "")
    urgency = os.environ.get("QA_NOTIFY_URGENCY", "normal")
    expire_ms = int(os.environ.get("QA_NOTIFY_EXPIRE_MS", "0"))

    bus = Gio.bus_get_sync(Gio.BusType.SESSION, None)
    proxy = Gio.DBusProxy.new_sync(
        bus, Gio.DBusProxyFlags.NONE, None,
        "org.freedesktop.Notifications", "/org/freedesktop/Notifications",
        "org.freedesktop.Notifications", None,
    )
    hints = {
        "urgency": GLib.Variant("y", {"low": 0, "normal": 1, "critical": 2}.get(urgency, 1)),
    }
    reply = proxy.call_sync(
        "Notify",
        GLib.Variant("(susssasa{sv}i)", (
            APP, 0, "", title, body, ["default", "Open in editor"], hints, expire_ms,
        )),
        Gio.DBusCallFlags.NONE, -1, None,
    )
    notification_id = reply.unpack()[0]

    loop = GLib.MainLoop()
    state = {"opened": False}

    def on_signal(_proxy, _sender, signal, params):
        got_id, value = params.unpack()
        if got_id != notification_id:
            return
        if signal == "NotificationClosed":
            loop.quit()
            return
        if signal != "ActionInvoked":
            return
        if value in ("default", "open"):
            ok, detail = open_target(path)
            state["opened"] = ok
            print(f"opened={ok} {detail}", flush=True)
        loop.quit()

    proxy.connect("g-signal", on_signal)
    # notifications persist until acted on; the waiter does not live forever
    wait_s = int(os.environ.get("QA_NOTIFY_WAIT_S", str(6 * 3600)))
    if expire_ms:
        wait_s = min(wait_s, max(1, expire_ms // 1000 + 1))
    GLib.timeout_add_seconds(wait_s, loop.quit)
    loop.run()
    return 0 if state["opened"] else 1


# ---------------------------------------------------------------- queue
def enqueue(conn, kind: str, key: str, title: str, body: str,
            detail: str = "", path: str | None = None,
            supersede: bool = False) -> bool:
    """Queue once per key. Returns True when it is new.

    ``supersede`` drops undelivered rows of the same kind with another key
    first, so the pop-up that eventually arrives describes the current state
    instead of an older state from before a delivery outage.
    """
    if supersede:
        conn.execute(
            "DELETE FROM notifications WHERE delivered=0 AND kind=? AND key<>?",
            (kind, key),
        )
    cur = conn.execute(
        "INSERT OR IGNORE INTO notifications(ts, kind, key, title, body, detail, path)"
        " VALUES(?,?,?,?,?,?,?)",
        (iso(), kind, key, title, body[:1000], detail[:2000], path),
    )
    return cur.rowcount > 0


def clear_pending(conn, kind: str) -> int:
    """Drop queued alerts for a condition that no longer holds."""
    cur = conn.execute(
        "DELETE FROM notifications WHERE delivered=0 AND kind=?", (kind,)
    )
    return cur.rowcount


def _drafts_index(conn) -> str | None:
    """One markdown page listing every draft, so a digest click has a target."""
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM ticket_drafts ORDER BY vendor, ts"
    )]
    if not rows:
        return None
    config.DRAFT_DIR.mkdir(parents=True, exist_ok=True)
    path = config.DRAFT_DIR / "INDEX.md"
    lines = [
        "# Ticket drafts",
        "",
        f"Generated {iso()} by {config.PROJECT_NAME}. "
        "Drafts are never submitted automatically.",
        "",
        "| vendor | title | draft |",
        "|---|---|---|",
    ]
    for row in rows:
        name = os.path.basename(row["path"] or "")
        lines.append(
            f"| {row['vendor']} | {row['title'][:110]} | [{name}]({name}) |"
        )
    write_text_atomic(path, "\n".join(lines) + "\n")
    return str(path)


def _correlation_report(conn, cluster: dict) -> str | None:
    """A markdown page per ready cluster, so its pop-up has a target too."""
    from . import trace

    config.REPORT_DIR.mkdir(parents=True, exist_ok=True)
    path = config.REPORT_DIR / f"correlation-{cluster['key']}.md"
    shown = cluster.get("display") or cluster["signature"]
    traced = trace.render(conn, cluster["signature"])
    if shown != cluster["signature"]:
        traced = [line.replace(cluster["signature"], shown) for line in traced]
    header = [
        f"# Correlated fault pattern — {cluster['vendor']}",
        "",
        f"- Signature: `{shown}`",
        f"- Silent stops: **{cluster['boots']}** of {cluster['total_unclean']}",
        f"- Occurrences in death windows: **{cluster['occurrences']}** "
        f"({cluster['crashes']} crash(es))",
        f"- Consistency: **{cluster['score']}** vs threshold {cluster['threshold']}",
        "- Attribution is inferred from message content; the stop has no logged cause.",
        "",
        "---",
        "",
    ]
    write_text_atomic(path, "\n".join(header + traced))
    return str(path)


def collect(conn) -> dict:
    """Queue notifications for drafts and for correlations that became ready.

    Drafts are batched into a single digest: ten drafts are one piece of news
    ("ten tickets are ready"), not ten interruptions. Correlations stay
    individual because each is a distinct fault pattern.
    """
    from . import correlate

    new = 0
    drafts = [dict(r) for r in conn.execute("SELECT * FROM ticket_drafts ORDER BY ts")]
    if drafts:
        digest = sha256_text("|".join(sorted(d["issue_key"] for d in drafts)))[:16]
        key = f"drafts|{digest}"
        row = conn.execute(
            "SELECT path FROM notifications WHERE key=?", (key,)
        ).fetchone()
        path = (
            row["path"] if row and row["path"] and os.path.exists(row["path"])
            else _drafts_index(conn)
        )
        vendors = sorted({d["vendor"] for d in drafts})
        body = "\n".join(f"- {d['vendor']}: {d['title'][:110]}" for d in drafts[:8])
        if len(drafts) > 8:
            body += f"\n- … and {len(drafts) - 8} more"
        new += enqueue(
            conn, "draft", key,
            f"{len(drafts)} ticket draft(s) ready ({', '.join(vendors)})",
            body,
            detail=str(config.DRAFT_DIR),
            path=path,
            supersede=True,
        )
    else:
        clear_pending(conn, "draft")

    for cluster in correlate.aggregate(conn, days=30):
        if not cluster["ready"]:
            continue
        key = f"corr|{cluster['key']}"
        row = conn.execute(
            "SELECT * FROM notifications WHERE key=?", (key,)
        ).fetchone()
        shown = cluster.get("display") or cluster["signature"]
        if row and row["path"] and os.path.exists(row["path"]):
            try:
                with open(row["path"], encoding="utf-8", errors="replace") as fh:
                    report_text = fh.read()
            except OSError:
                report_text = ""
            if shown in report_text:
                continue
        title = f"Consistent fault pattern: {cluster['vendor']}"
        body = (
            f"{shown[:120]}\n"
            f"{cluster['boots']} silent stop(s), {cluster['occurrences']} occurrence(s), "
            f"consistency {cluster['score']}/{cluster['threshold']}"
        )
        path = _correlation_report(conn, cluster)
        if row:
            # A queued alert whose markdown was removed still needs its click
            # target. Do not create a second row for the same key.
            conn.execute(
                "UPDATE notifications SET title=?, body=?, detail=?, path=? WHERE key=?",
                (title, body[:1000], shown[:2000], path, key),
            )
        else:
            new += enqueue(
                conn, "correlation", key, title, body,
                detail=shown, path=path,
            )
    return {"queued": new, "pending": pending_count(conn)}


def pending(conn, limit: int = 20) -> list[dict]:
    return [
        dict(r) for r in conn.execute(
            "SELECT * FROM notifications WHERE delivered=0 ORDER BY id LIMIT ?", (limit,)
        )
    ]


def pending_count(conn) -> int:
    return conn.execute("SELECT COUNT(*) FROM notifications WHERE delivered=0").fetchone()[0]


def _backoff_seconds(attempts: int) -> int:
    step = max(1, min(int(attempts or 0), 8))
    return min(config.NOTIFY_BACKOFF_S * (2 ** (step - 1)),
               config.NOTIFY_BACKOFF_MAX_S)


def _due_pending(conn, limit: int) -> list[dict]:
    """Fair selection: unattempted and least-attempted rows first.

    A dead backend must not pin the queue to its oldest rows, and a failing row
    must not be retried every cycle; both would starve newer notifications.
    """
    rows = conn.execute(
        "SELECT * FROM notifications WHERE delivered=0"
        " ORDER BY attempts ASC, COALESCE(last_attempt,'') ASC, id ASC"
    ).fetchall()
    now = utcnow()
    selected: list[dict] = []
    for row in rows:
        last = row["last_attempt"]
        if last:
            try:
                if (now - parse_iso(last)).total_seconds() < _backoff_seconds(row["attempts"]):
                    continue
            except (TypeError, ValueError):
                pass
        selected.append(dict(row))
        if len(selected) >= limit:
            break
    return selected


def _purge(conn) -> None:
    """Delivered rows age out; undelivered rows expire so keys can requeue."""
    delivered = iso(utcnow() - timedelta(days=30))
    pending = iso(utcnow() - timedelta(days=config.NOTIFY_TTL_DAYS))
    conn.execute("DELETE FROM notifications WHERE delivered=1 AND ts < ?", (delivered,))
    conn.execute("DELETE FROM notifications WHERE delivered=0 AND ts < ?", (pending,))


def _claim(conn, row: dict, attempt_ts: str) -> bool:
    """Take one row before sending it.

    ``attempts`` and ``last_attempt`` act as an optimistic version: the update
    only matches the values read by ``_due_pending``. SQLite serialises writers,
    so a concurrent ``qa notify --drain`` cannot send the same row twice.
    """
    cur = conn.execute(
        "UPDATE notifications SET attempts=attempts+1, last_attempt=?,"
        " last_error=NULL WHERE id=? AND delivered=0 AND attempts=?"
        " AND COALESCE(last_attempt,'')=?",
        (attempt_ts, row["id"], row["attempts"], row["last_attempt"] or ""),
    )
    return cur.rowcount == 1


def drain(conn, limit: int = 5) -> dict:
    """Deliver due notifications. Failures stay queued with backoff, never lost."""
    sent, failed = 0, []
    attempt_ts = iso()
    for row in _due_pending(conn, limit):
        if not _claim(conn, row, attempt_ts):
            continue
        ok, why = send(
            row["title"], row["body"],
            urgency="critical" if row["kind"] == "correlation" else "normal",
            path=row.get("path"),
        )
        if ok:
            conn.execute(
                "UPDATE notifications SET delivered=1, last_error=NULL WHERE id=?",
                (row["id"],),
            )
            sent += 1
        else:
            conn.execute(
                "UPDATE notifications SET last_error=? WHERE id=?",
                (why[:300], row["id"]),
            )
            failed.append({"key": row["key"], "reason": why, "attempts": row["attempts"] + 1})
        # Delivery already happened; make the claim/result durable before the
        # next send. Otherwise a later rollback would retry and duplicate it.
        conn.commit()
    _purge(conn)
    return {"sent": sent, "failed": failed, "pending": pending_count(conn)}


def _cli(argv: list[str]) -> int:
    if argv[:1] == ["--wait-open"]:
        return _wait_open_main()
    return 2


if __name__ == "__main__":
    raise SystemExit(_cli(sys.argv[1:]))
