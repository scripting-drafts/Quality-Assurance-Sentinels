"""Viability gate: decide which drafts deserve to be raised, and stage them.

A draft is a guess. A raiseable ticket is a claim someone will defend in a
vendor tracker, so it has to survive four questions before it is staged:

  1. reproducible — the current evidence still produces this issue key
  2. attributable — a specific owner, not "local"
  3. substantiated  — enough occurrences, or at least one real crash
  4. fresh          — the evidence is inside the age window

Only tickets passing all four get a directory. Everything else is listed with
the reason it failed, because a silent rejection is indistinguishable from a bug.

Layout (one directory per ticket, never a flat pile):

    raise/<vendor>-<slug>-<key8>/
        ticket.md            the redacted draft, ready to post
        HOWTO.md             what to do with it, and what not to omit
        evidence/rows.json   the exact observations behind it (redacted)
        evidence/trace.md    signature → events → stops → correlation → draft
        evidence/manifest.json  hashes, provenance, scores
"""
from __future__ import annotations

import json
import re
import shutil

from . import boot, classify, config, correlate, report, tickets, trace, util
from .util import iso, sha256_text, utcnow

# Failures of the environment, not of the component. A vendor cannot fix DNS,
# a read-only mount or a wrong file permission owned by the local operator.
ENVIRONMENTAL = re.compile(
    r"(?i)failed to fetch|https?://|temporary failure (?:in name resolution|resolving)|"
    r"network is unreachable|no route to host|connection (?:refused|timed out)|"
    r"could not resolve|name or service not known|"
    r"permission denied|operation not permitted|no space left|"
    r"read-only file system|dns"
)


# ---------------------------------------------------------------- assessment
def _slug(value: str, limit: int = 60) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (value or "").lower()).strip("-")[:limit] or "ticket"


def assess(conn, draft: dict, issue: dict | None, days: int = 30,
           min_count: int | None = None) -> dict:
    """Return the viability verdict and every reason behind it."""
    min_count = config.RAISE_MIN_COUNT if min_count is None else min_count
    checks: list[dict] = []

    def check(name: str, ok: bool, detail: str) -> None:
        checks.append({"check": name, "ok": ok, "detail": detail})

    check("reproducible", issue is not None,
          "issue key still produced by current evidence" if issue
          else "no current evidence reproduces this draft")
    vendor = (issue or {}).get("vendor") or draft.get("vendor") or "local"
    check("attributed", vendor not in ("local", ""),
          f"owner is {vendor}")
    count = int((issue or {}).get("count") or 0)
    rows = (issue or {}).get("rows") or []
    crashes = sum(1 for r in rows if r.get("sig"))
    check("substantiated", count >= min_count or crashes >= 1,
          f"{count} occurrence(s), {crashes} crash row(s); need >= {min_count} or 1 crash")

    last = (issue or {}).get("last") or draft.get("ts") or ""
    fresh = False
    age_days = None
    try:
        age_days = (utcnow() - util.parse_iso(last)).days
        fresh = age_days <= config.RAISE_MAX_AGE_DAYS
    except Exception:  # noqa: BLE001 - an unparseable date must not crash a gate
        pass
    check("fresh", fresh, f"last evidence {age_days} day(s) old; limit {config.RAISE_MAX_AGE_DAYS}")

    signature = (issue or {}).get("signature") or ""
    rows = (issue or {}).get("rows") or []
    benign = bool(signature) and not classify.ticketworthy(signature, "event", "critical", count)
    environmental = bool(ENVIRONMENTAL.search(signature)) or any(
        ENVIRONMENTAL.search(str(r.get("message") or "")) for r in rows
    )
    signal = (
        (issue or {}).get("kind") == "correlation"
        or any(str(r.get("sig") or "") for r in rows)
        or any(str(r.get("severity") or "") == "critical" for r in rows)
        or count >= 10  # a high-volume error cluster is still a component signal
    )
    actionable = not benign and not environmental and signal
    reason = (
        "benign per classifier" if benign else
        "environmental/network/permission failure" if environmental else
        "no critical, crash or correlation signal"
    )
    check("actionable", actionable, reason if not actionable else "component-level signal present")

    viable = all(c["ok"] for c in checks)
    score = sum(1 for c in checks if c["ok"])
    return {
        "viable": viable,
        "score": score,
        "max_score": len(checks),
        "vendor": vendor,
        "checks": checks,
        "reasons": [c["detail"] for c in checks if not c["ok"]],
    }


def _dir_name(draft: dict, issue: dict | None) -> str:
    vendor = (issue or {}).get("vendor") or draft.get("vendor") or "local"
    signature = (issue or {}).get("signature") or draft.get("title") or "ticket"
    return f"{vendor}-{_slug(signature)}-{draft['issue_key'][:8]}"


# ---------------------------------------------------------------- redaction
def _redact_rows(rows: list[dict]) -> list[dict]:
    clean = []
    for row in rows:
        item = {}
        for key, value in row.items():
            item[key] = util.redact(value) if isinstance(value, str) else value
        clean.append(item)
    return clean


# ---------------------------------------------------------------- staging
def _write(path, text: str) -> str:
    """Write only on change. Re-running triage must not churn evidence files."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        try:
            if path.read_text(encoding="utf-8", errors="replace") == text:
                return sha256_text(text)
        except OSError:
            pass
    path.write_text(text, encoding="utf-8")
    return sha256_text(text)


def stage(conn, draft: dict, issue: dict, verdict: dict, bundle: dict | None) -> dict:
    """Create the per-ticket directory with its own evidence."""
    directory = config.RAISE_DIR / _dir_name(draft, issue)
    # never rm/rewrite: a staged ticket is a record, not a cache entry
    (directory / "evidence").mkdir(parents=True, exist_ok=True)

    hashes: dict[str, str] = {}

    ticket_text = ""
    if draft.get("path"):
        try:
            with open(draft["path"], encoding="utf-8", errors="replace") as fh:
                ticket_text = util.redact(fh.read())
        except OSError:
            ticket_text = ""
    hashes["ticket.md"] = _write(directory / "ticket.md", ticket_text)

    rows = _redact_rows(issue.get("rows") or [])
    hashes["evidence/rows.json"] = _write(
        directory / "evidence" / "rows.json",
        json.dumps(rows, indent=2, sort_keys=True, default=str) + "\n",
    )

    trace_text = util.redact("\n".join(trace.render(conn, issue["signature"], limit=200)))
    hashes["evidence/trace.md"] = _write(directory / "evidence" / "trace.md", trace_text + "\n")

    stop_ids = sorted({
        row["boot_id"] for row in rows if row.get("boot_id")
    })
    if not stop_ids and issue.get("kind") == "correlation":
        stop_ids = [c["boot_id"] for c in correlate.rows_for_signature(conn, issue["signature"])]
    stop_lines = ["# Silent stops linked to this ticket", ""]
    for boot_id in stop_ids:
        rec = conn.execute("SELECT * FROM boots WHERE boot_id=?", (boot_id,)).fetchone()
        if rec:
            rows_b = dict(rec)
            stop_lines += [
                f"## `{boot_id[:8]}` — {boot.verdict(rows_b)}",
                "",
                f"- Last entry: {rows_b['last_ts']}",
                f"- Last message: `{(rows_b['last_message'] or '')[:300]}`",
                f"- Crash capture: pstore {rows_b['pstore']}, "
                f"kexec_crash_loaded {rows_b['kexec_loaded']}, vmcores {rows_b['vmcores']}",
                "",
            ]
    if stop_ids:
        hashes["evidence/stops.md"] = _write(
            directory / "evidence" / "stops.md",
            util.redact("\n".join(stop_lines)) + "\n",
        )

    manifest = {
        "issue_key": issue["key"],
        "vendor": issue["vendor"],
        "signature": util.redact(issue["signature"]),
        "kind": issue.get("kind"),
        "occurrences": issue.get("count"),
        "first": issue.get("first"),
        "last": issue.get("last"),
        "viability": verdict,
        "generated": _first_seen(directory),
        "last_checked": iso(),
        "bundle": {
            "path": util.redact((bundle or {}).get("path") or ""),
            "sha256": (bundle or {}).get("sha256"),
            "prev_sha256": (bundle or {}).get("prev_sha256"),
        },
        "evidence_files": hashes,
    }
    hashes["evidence/manifest.json"] = _write(
        directory / "evidence" / "manifest.json",
        json.dumps(manifest, indent=2, sort_keys=True, default=str) + "\n",
    )

    _write(directory / "HOWTO.md", _howto(issue, verdict))
    _record_history(directory, issue, verdict, hashes)

    return {
        "directory": str(directory),
        "issue_key": issue["key"],
        "vendor": issue["vendor"],
        "signature": issue["signature"][:120],
        "files": sorted(hashes),
        "manifest_sha256": hashes["evidence/manifest.json"],
        "verdict": verdict,
    }


def _first_seen(directory) -> str:
    """Keep the original staging time when a ticket is re-triaged."""
    manifest = directory / "evidence" / "manifest.json"
    if manifest.exists():
        try:
            return json.loads(manifest.read_text(encoding="utf-8")).get("generated") or iso()
        except (OSError, json.JSONDecodeError):
            pass
    return iso()


def _record_history(directory, issue: dict, verdict: dict, hashes: dict) -> None:
    """Append one line per *material* change; repeated identical runs stay quiet."""
    path = directory / "evidence" / "history.jsonl"
    state = sha256_text(json.dumps({
        "occurrences": issue.get("count"),
        "last": issue.get("last"),
        "checks": verdict["checks"],
        "files": hashes,
    }, sort_keys=True, default=str))[:16]
    previous = ""
    if path.exists():
        try:
            lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
            if lines:
                previous = json.loads(lines[-1]).get("state", "")
        except (OSError, json.JSONDecodeError):
            pass
    if state == previous:
        return
    util.append_jsonl(path, {
        "ts": iso(),
        "state": state,
        "viable": verdict["viable"],
        "score": verdict["score"],
        "occurrences": issue.get("count"),
        "last_evidence": issue.get("last"),
        "reasons": verdict["reasons"],
    })


def _stamp() -> str:
    return utcnow().strftime("%Y%m%dT%H%M%SZ")


def _merge_into(source, destination, label: str) -> None:
    """Never delete a staged directory; park the older copy inside the newer."""
    target = destination / "evidence" / f"prior-{label}-{_stamp()}"
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.move(str(source), str(target))


def _record_standby(directory, event: str, reason: str) -> None:
    path = directory / "evidence" / "standby.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    util.append_jsonl(path, {"ts": iso(), "event": event, "reason": reason})


def reconcile(conn, viable_names: set[str],
              assessments: dict[str, dict]) -> dict:
    """Move tickets between raise/ and in-standby/. Never delete.

    raise/     = viable now, ready for a human to post
    in-standby = was viable, is not now; kept only as an audit trail
    """
    config.RAISE_DIR.mkdir(parents=True, exist_ok=True)
    config.STANDBY_DIR.mkdir(parents=True, exist_ok=True)
    reactivated, stood_down = [], []

    # a ticket that became viable again comes back out of standby
    for path in sorted(config.STANDBY_DIR.iterdir()):
        if not path.is_dir() or path.name not in viable_names:
            continue
        destination = config.RAISE_DIR / path.name
        if destination.exists():
            _merge_into(path, destination, "standby")
        else:
            shutil.move(str(path), str(destination))
        _record_standby(destination, "reactivated", "viability checks passed again")
        reactivated.append(path.name)

    # a staged ticket that is no longer viable is parked, not removed
    for path in sorted(config.RAISE_DIR.iterdir()):
        if not path.is_dir() or path.name in viable_names:
            continue
        info = assessments.get(path.name) or {}
        reasons = info.get("verdict", {}).get("reasons") or [
            "no current draft reproduces this ticket"
        ]
        destination = config.STANDBY_DIR / path.name
        if destination.exists():
            _merge_into(path, destination, "raise")
        else:
            shutil.move(str(path), str(destination))
        _record_standby(destination, "standby", "; ".join(reasons)[:500])
        stood_down.append({"ticket": path.name, "reason": "; ".join(reasons)[:300]})

    _write_standby_index(conn)
    return {"reactivated": reactivated, "stood_down": stood_down}


def _write_standby_index(conn) -> None:
    entries = []
    for path in sorted(config.STANDBY_DIR.iterdir()):
        if not path.is_dir():
            continue
        record = path / "evidence" / "standby.jsonl"
        last = {}
        if record.exists():
            try:
                lines = [ln for ln in record.read_text(encoding="utf-8").splitlines() if ln.strip()]
                if lines:
                    last = json.loads(lines[-1])
            except (OSError, json.JSONDecodeError):
                last = {}
        manifest = path / "evidence" / "manifest.json"
        vendor, signature = "", ""
        if manifest.exists():
            try:
                data = json.loads(manifest.read_text(encoding="utf-8"))
                vendor, signature = data.get("vendor", ""), data.get("signature", "")
            except (OSError, json.JSONDecodeError):
                pass
        entries.append({
            "name": path.name, "vendor": vendor, "signature": signature,
            "since": last.get("ts", ""), "reason": last.get("reason", ""),
        })
    lines = ["# Tickets in standby", "",
             f"Generated {iso()} — kept for traceability; nothing here is deleted.", ""]
    if entries:
        lines += ["| ticket | vendor | reason | since |", "|---|---|---|---|"]
        for entry in entries:
            lines.append(
                f"| [{entry['name']}]({entry['name']}/ticket.md) | {entry['vendor']} | "
                f"{entry['reason'][:140]} | {entry['since']} |"
            )
    else:
        lines.append("No tickets in standby.")
    _write(config.STANDBY_DIR / "INDEX.md", "\n".join(lines) + "\n")


def _howto(issue: dict, verdict: dict) -> str:
    return f"""# How to raise this ticket

Vendor: **{issue['vendor']}** — {issue['kind']} cluster `{issue['key']}`

1. Read `ticket.md`. It is already redacted; do not add host or identity data.
2. Check `evidence/rows.json` and `evidence/trace.md` still describe what you saw.
3. Attach the evidence bundle named in `evidence/manifest.json` (verify its SHA-256).
4. Post through the vendor channel in `ticket.md`. Submission is manual by design.
5. Keep `evidence/manifest.json`: it is what makes this ticket auditable later.

Viability: {verdict['score']}/{verdict['max_score']} checks passed.
"""


# ---------------------------------------------------------------- run
def run(conn, days: int = 30, min_count: int | None = None,
        notify_ready: bool = True) -> dict:
    config.RAISE_DIR.mkdir(parents=True, exist_ok=True)
    issues = {i["key"]: i for i in tickets.collect_issues(conn, days)}
    drafts = [dict(r) for r in conn.execute("SELECT * FROM ticket_drafts ORDER BY vendor, ts")]
    bundle_row = conn.execute("SELECT * FROM bundles ORDER BY id DESC LIMIT 1").fetchone()
    bundle = dict(bundle_row) if bundle_row else None

    raised, rejected = [], []
    assessments: dict[str, dict] = {}
    viable_names: set[str] = set()
    for draft in drafts:
        issue = issues.get(draft["issue_key"])
        verdict = assess(conn, draft, issue, days=days, min_count=min_count)
        name = _dir_name(draft, issue)
        assessments[name] = {"draft": draft, "verdict": verdict}
        if verdict["viable"] and issue:
            viable_names.add(name)
        else:
            rejected.append({
                "key": draft["issue_key"],
                "vendor": draft["vendor"],
                "title": draft["title"],
                "reasons": verdict["reasons"],
            })

    # park what stopped being viable *before* staging, so a reactivated
    # directory is reused instead of duplicated
    moves = reconcile(conn, viable_names, assessments)

    for draft in drafts:
        issue = issues.get(draft["issue_key"])
        verdict = assessments[_dir_name(draft, issue)]["verdict"]
        if verdict["viable"] and issue:
            raised.append(stage(conn, draft, issue, verdict, bundle))

    config.RAISE_DIR.mkdir(parents=True, exist_ok=True)
    index = ["# Tickets staged for raising", "",
             f"Generated {iso()} — {len(raised)} viable, {len(rejected)} rejected.", ""]
    by_vendor: dict[str, list[dict]] = {}
    for item in raised:
        by_vendor.setdefault(item["vendor"], []).append(item)
    for vendor in sorted(by_vendor):
        index += [f"## {vendor}", ""]
        for item in by_vendor[vendor]:
            rel = item["directory"].split("/")[-1]
            index.append(
                f"- [`{rel}`]({rel}/ticket.md) — {item['signature']} "
                f"({item['verdict']['score']}/{item['verdict']['max_score']} checks)"
            )
        index.append("")
    if rejected:
        index += ["## Rejected (not raised)", ""]
        for item in rejected:
            index.append(
                f"- {item['vendor']}: {item['title'][:100]} — "
                f"{'; '.join(item['reasons']) or 'no issue'}"
            )
        index.append("")
    _write(config.RAISE_DIR / "INDEX.md", "\n".join(index))

    if raised:
        report.append_journal(
            conn,
            f"Raise gate: {len(raised)} viable, {len(rejected)} rejected",
            "\n".join(f"- {r['vendor']}: {r['signature']}" for r in raised[:10]) + "\n",
            "raise",
        )
        if notify_ready:
            from . import notify

            # identity, not hashes: manifests are regenerated every run and a
            # hash-based key would pop a notification every 5 minutes.
            digest = sha256_text("|".join(sorted(r["issue_key"] for r in raised)))[:16]
            notify.enqueue(
                conn, "raise", f"raise|{digest}",
                f"{len(raised)} ticket(s) staged in raise/",
                "\n".join(f"- {r['vendor']}: {r['signature']}" for r in raised[:6]),
                detail=str(config.RAISE_DIR),
                path=str(config.RAISE_DIR / "INDEX.md"),
            )

    return {
        "drafts": len(drafts),
        "viable": len(raised),
        "rejected": len(rejected),
        "staged": [r["directory"] for r in raised],
        "rejected_keys": [r["key"] for r in rejected],
        "stood_down": moves["stood_down"],
        "reactivated": moves["reactivated"],
    }
