"""Desktop pop-ups for tickets that are about to be raised.

A draft sitting unnoticed in `tickets/drafts/` is worth nothing. This module
turns "a ticket became ready" into a visible notification, once per cluster,
and makes the notification **open the markdown it refers to**.

Click handling needs the freedesktop notification action API, which
`notify-send` 0.7.9 does not expose. When PyGObject is available the pop-up is
delivered over D-Bus with a `default` action and a detached waiter opens the
file; otherwise it degrades to a plain, unclickable notification and says so.

Delivery is best-effort and never blocks a job: no session bus, no notifier, no
problem — the row stays queued and `qa notify` reports it honestly.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys

from . import config
from .util import iso, sha256_text

APP = "qa-sentinels"


# ---------------------------------------------------------------- environment
def _env() -> dict:
    env = dict(os.environ)
    if not env.get("DBUS_SESSION_BUS_ADDRESS"):
        bus = f"/run/user/{os.getuid()}/bus"
        if os.path.exists(bus):
            env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path={bus}"
    if not env.get("PYTHONPATH"):
        env["PYTHONPATH"] = str(config.ROOT)
    return env


def available() -> tuple[bool, str]:
    if shutil.which("notify-send") is None:
        return False, "notify-send not installed"
    if not _env().get("DISPLAY") and not _env().get("WAYLAND_DISPLAY"):
        return False, "no graphical session (DISPLAY/WAYLAND_DISPLAY unset)"
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
        if _gi_available():
            if _spawn_click_helper(path, title, body, urgency):
                return True, "sent (click opens the markdown)"
            return False, "could not spawn the click helper"
        ok, why = _plain_send(title, body, urgency)
        if ok:
            return True, f"{why} (click support unavailable: PyGObject missing)"
        return ok, why
    return _plain_send(title, body, urgency)


def _plain_send(title: str, body: str, urgency: str) -> tuple[bool, str]:
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
        subprocess.Popen(  # noqa: S603 - fixed argv
            [sys.executable, "-m", "sentinels.notify", "--wait-open"],
            cwd=str(config.ROOT), env=env, start_new_session=True,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
    except OSError:
        return False
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
        if signal != "ActionInvoked":
            return
        got_id, action = params.unpack()
        if got_id != notification_id:
            return
        if action in ("default", "open"):
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
            detail: str = "", path: str | None = None) -> bool:
    """Queue once per key. Returns True when it is new."""
    cur = conn.execute(
        "INSERT OR IGNORE INTO notifications(ts, kind, key, title, body, detail, path)"
        " VALUES(?,?,?,?,?,?,?)",
        (iso(), kind, key, title, body[:1000], detail[:2000], path),
    )
    return cur.rowcount > 0


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
        f"Generated {iso()} by qa-sentinels. Drafts are never submitted automatically.",
        "",
        "| vendor | title | draft |",
        "|---|---|---|",
    ]
    for row in rows:
        name = os.path.basename(row["path"] or "")
        lines.append(
            f"| {row['vendor']} | {row['title'][:110]} | [{name}]({name}) |"
        )
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return str(path)


def _correlation_report(conn, cluster: dict) -> str | None:
    """A markdown page per ready cluster, so its pop-up has a target too."""
    from . import trace

    config.REPORT_DIR.mkdir(parents=True, exist_ok=True)
    path = config.REPORT_DIR / f"correlation-{cluster['key']}.md"
    header = [
        f"# Correlated fault pattern — {cluster['vendor']}",
        "",
        f"- Signature: `{cluster['signature']}`",
        f"- Silent stops: **{cluster['boots']}** of {cluster['total_unclean']}",
        f"- Occurrences in death windows: **{cluster['occurrences']}** "
        f"({cluster['crashes']} crash(es))",
        f"- Consistency: **{cluster['score']}** vs threshold {cluster['threshold']}",
        "- Attribution is inferred from message content; the stop has no logged cause.",
        "",
        "---",
        "",
    ]
    path.write_text(
        "\n".join(header + trace.render(conn, cluster["signature"])),
        encoding="utf-8",
    )
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
        vendors = sorted({d["vendor"] for d in drafts})
        body = "\n".join(f"- {d['vendor']}: {d['title'][:110]}" for d in drafts[:8])
        if len(drafts) > 8:
            body += f"\n- … and {len(drafts) - 8} more"
        new += enqueue(
            conn, "draft", f"drafts|{digest}",
            f"{len(drafts)} ticket draft(s) ready ({', '.join(vendors)})",
            body,
            detail=str(config.DRAFT_DIR),
            path=_drafts_index(conn),
        )

    for cluster in correlate.aggregate(conn, days=30):
        if not cluster["ready"]:
            continue
        new += enqueue(
            conn, "correlation", f"corr|{cluster['key']}",
            f"Consistent fault pattern: {cluster['vendor']}",
            f"{cluster['signature'][:120]}\n"
            f"{cluster['boots']} silent stop(s), {cluster['occurrences']} occurrence(s), "
            f"consistency {cluster['score']}/{cluster['threshold']}",
            detail=cluster["signature"],
            path=_correlation_report(conn, cluster),
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


def drain(conn, limit: int = 5) -> dict:
    """Deliver queued notifications. Failures stay queued, never silently lost."""
    sent, failed = 0, []
    for row in pending(conn, limit):
        ok, why = send(
            row["title"], row["body"],
            urgency="critical" if row["kind"] == "correlation" else "normal",
            path=row.get("path"),
        )
        if ok:
            conn.execute("UPDATE notifications SET delivered=1 WHERE id=?", (row["id"],))
            sent += 1
        else:
            failed.append({"key": row["key"], "reason": why})
    conn.execute(
        "DELETE FROM notifications WHERE delivered=1"
        " AND ts < datetime('now','-30 days')"
    )
    return {"sent": sent, "failed": failed, "pending": pending_count(conn)}


def _cli(argv: list[str]) -> int:
    if argv[:1] == ["--wait-open"]:
        return _wait_open_main()
    return 2


if __name__ == "__main__":
    raise SystemExit(_cli(sys.argv[1:]))
