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
        evidence/logs.json   the exact observations behind it (redacted)
        evidence/trace.md    signature → events → stops → correlation → draft
        evidence/manifest.json  hashes, provenance, scores
        evidence/*.jsonl     append-only audit records

Naming convention: ``logs.json`` is the active evidence snapshot; ``*.jsonl``
is append-only history. Legacy ``rows.json`` is migrated automatically.

A ticket is keyed by signature, not by vendor or cluster kind, so vendor
reclassification and event/correlation views update one directory.
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

# When two clusters share a signature, a correlation carries the silent-stop
# context; a crash has a stack; a plain event is the weakest form.
KIND_RANK = {"correlation": 0, "crash": 1, "event": 2}

# Ticket evidence naming convention:
#   logs.json   snapshot of the observations behind the ticket
#   *.jsonl     append-only audit records (history, standby, rejected, dedupe)
#   *.md        human-readable reports and instructions
EVIDENCE_LOGS = "logs.json"
EVIDENCE_LOGS_LEGACY = "rows.json"


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

    # A crash in a held, outdated package is not a vendor bug yet: the fix may
    # already exist in the candidate, and only a local unpin can prove it.
    hold = (issue or {}).get("held") or {}
    outdated = hold.get("outdated") or []
    if outdated:
        shown = "; ".join(
            f"{h.get('package')} {h.get('installed')} -> {h.get('candidate')}"
            for h in outdated[:3]
        )
        hold_detail = f"held-outdated package(s): {shown}"
    elif hold.get("mass_hold"):
        hold_detail = (
            f"system-wide hold: {hold.get('held_total')} packages pinned, "
            f"{hold.get('held_installed')} installed"
        )
    else:
        hold_detail = "no held, outdated package matches this crash"
    hold_explained = bool(outdated) or bool(hold.get("mass_hold"))
    check("build-current", not hold_explained, hold_detail)

    viable = all(c["ok"] for c in checks)
    score = sum(1 for c in checks if c["ok"])
    return {
        "viable": viable,
        "score": score,
        "max_score": len(checks),
        "vendor": vendor,
        "hold_explained": hold_explained,
        "checks": checks,
        "reasons": [c["detail"] for c in checks if not c["ok"]],
    }


def _ticket_identity(draft: dict, issue: dict | None) -> tuple[str, str]:
    """The human-facing identity of a ticket: owner and signature.

    Event and correlation clusters can describe the exact same signature. They
    are two views of one ticket, not two tickets, so the directory name must
    not depend on the cluster kind or issue key.
    """
    vendor = (issue or {}).get("vendor") or draft.get("vendor") or "local"
    signature = util.redact(
        (issue or {}).get("signature") or draft.get("title") or "ticket"
    )
    return vendor, signature


def _identity(signature: str) -> str:
    """Stable ticket identity: the signature, independent of vendor routing.

    Vendor classification changes over time (for example systemd -> netplan for
    the same unit message). The fault is still one ticket, so vendor must not
    split it into two directories.
    """
    return sha256_text(signature)[:8]


def _dir_name(draft: dict, issue: dict | None) -> str:
    vendor, signature = _ticket_identity(draft, issue)
    return f"{vendor}-{_slug(signature)}-{_identity(signature)}"


def _display(issue: dict | None, draft: dict | None = None) -> str:
    """Human-readable label; signatures stay masked for identity only."""
    return util.redact(
        (issue or {}).get("display")
        or (issue or {}).get("signature")
        or (draft or {}).get("title")
        or "ticket"
    )


def _read_manifest(directory) -> dict:
    path = directory / "evidence" / "manifest.json"
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


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
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.exists():
        try:
            if path.read_text(encoding="utf-8", errors="replace") == text:
                return sha256_text(text)
        except OSError:
            pass
    util.write_text_atomic(path, text)
    return sha256_text(text)


def _already_staged(directory, issue: dict, bucket: str = "raise") -> bool:
    """True when this exact issue is already fully staged.

    Re-staging an unchanged ticket every hour only churns mtimes. New
    occurrences or a different issue still refresh the existing directory.
    """
    if not directory.is_dir():
        return False
    manifest = _read_manifest(directory)
    if manifest.get("issue_key") != issue.get("key"):
        return False
    if manifest.get("display") != _display(issue):
        return False
    if manifest.get("bucket") != bucket:
        return False
    if manifest.get("occurrences") != issue.get("count"):
        return False
    if manifest.get("last") != issue.get("last"):
        return False
    required = ("ticket.md", "HOWTO.md", "evidence/manifest.json",
                f"evidence/{EVIDENCE_LOGS}", "evidence/trace.md")
    return all((directory / rel).exists() for rel in required)


def _staged_summary(directory, issue: dict, verdict: dict,
                    bucket: str = "raise") -> dict:
    manifest = _read_manifest(directory)
    return {
        "directory": str(directory),
        "issue_key": issue["key"],
        "vendor": issue["vendor"],
        "signature": _display(issue)[:120],
        "bucket": bucket,
        "files": sorted((manifest.get("evidence_files") or {}).keys()),
        "manifest_sha256": (manifest.get("evidence_files") or {}).get(
            "evidence/manifest.json", ""
        ),
        "verdict": verdict,
    }


def stage(conn, draft: dict, issue: dict, verdict: dict, bundle: dict | None,
          root=None, bucket: str = "raise", name: str | None = None) -> dict:
    """Create the per-ticket directory with its own evidence.

    The layout is identical in raise/, rejected/ and standby/, so a ticket
    can move between buckets without losing evidence or history.
    """
    directory = (root or config.RAISE_DIR) / (name or _dir_name(draft, issue))
    # never rm/rewrite: a staged ticket is a record, not a cache entry
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        directory.chmod(0o700)
    except OSError:
        pass
    (directory / "evidence").mkdir(parents=True, exist_ok=True, mode=0o700)

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
    hashes[f"evidence/{EVIDENCE_LOGS}"] = _write(
        directory / "evidence" / EVIDENCE_LOGS,
        json.dumps(rows, indent=2, sort_keys=True, default=str) + "\n",
    )

    shown = _display(issue)
    traced = trace.render(conn, issue["signature"], limit=200)
    if shown != issue["signature"]:
        traced = [line.replace(issue["signature"], shown) for line in traced]
    trace_text = util.redact("\n".join(traced))
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

    if bucket == "rejected":
        hashes["REJECTED.md"] = _write(
            directory / "REJECTED.md", _rejection_note(issue, verdict)
        )
        _record_rejected(directory, verdict)

    manifest = {
        "issue_key": issue["key"],
        "vendor": issue["vendor"],
        "signature": util.redact(issue["signature"]),
        "display": _display(issue),
        "kind": issue.get("kind"),
        "bucket": bucket,
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

    _write(directory / "HOWTO.md", _howto(issue, verdict, bucket))
    _record_history(directory, issue, verdict, hashes)

    return {
        "directory": str(directory),
        "issue_key": issue["key"],
        "vendor": issue["vendor"],
        "signature": _display(issue)[:120],
        "bucket": bucket,
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


def _prior_logs_name(evidence, suffix: str | None = None):
    """Return a unique ``prior-logs-*.json`` path."""
    base = f"prior-logs-{suffix or _stamp()}"
    path = evidence / f"{base}.json"
    counter = 1
    while path.exists():
        path = evidence / f"{base}-{counter}.json"
        counter += 1
    return path


def _normalize_evidence_names(directory) -> None:
    """Apply the ticket evidence naming convention to one staged directory.

    ``logs.json`` is the active snapshot. Legacy ``rows.json`` is promoted to
    that name; if both exist, the newer file wins and the older one is kept as
    ``prior-logs-*.json``. Earlier ``prior-rows-*`` archives are renamed too.
    """
    evidence = directory / "evidence"
    active = evidence / EVIDENCE_LOGS
    legacy = evidence / EVIDENCE_LOGS_LEGACY
    try:
        if legacy.exists() and active.exists():
            if legacy.stat().st_mtime >= active.stat().st_mtime:
                active.rename(_prior_logs_name(evidence))
                legacy.rename(active)
            else:
                legacy.rename(_prior_logs_name(evidence))
        elif legacy.exists():
            legacy.rename(active)
        for old in evidence.glob("prior-rows-*.json"):
            suffix = old.name[len("prior-rows-"):]
            if suffix.endswith(".json"):
                suffix = suffix[:-5]
            old.rename(_prior_logs_name(evidence, suffix))
    except OSError:
        return

    howto = directory / "HOWTO.md"
    if howto.exists():
        try:
            text = howto.read_text(encoding="utf-8", errors="replace")
            if "evidence/rows.json" in text:
                _write(howto, text.replace("evidence/rows.json",
                                            f"evidence/{EVIDENCE_LOGS}"))
        except OSError:
            pass

    manifest_path = evidence / "manifest.json"
    if not manifest_path.exists():
        return
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    files = data.get("evidence_files")
    if not isinstance(files, dict):
        return
    changed = False
    for key in list(files):
        if key.endswith(EVIDENCE_LOGS_LEGACY):
            del files[key]
            changed = True
    if active.exists():
        try:
            digest = sha256_text(active.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            digest = ""
        key = f"evidence/{EVIDENCE_LOGS}"
        if digest and files.get(key) != digest:
            files[key] = digest
            changed = True
    if changed:
        data["evidence_files"] = files
        _write(
            manifest_path,
            json.dumps(data, indent=2, sort_keys=True, default=str) + "\n",
        )


def _merge_into(source, destination, label: str) -> None:
    """Never delete a staged directory; park the older copy inside the newer."""
    target = destination / "evidence" / f"prior-{label}-{_stamp()}-{source.name}"
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    shutil.move(str(source), str(target))


def _record_event(directory, record: str, event: str, reason: str) -> None:
    path = directory / "evidence" / record
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    util.append_jsonl(path, {"ts": iso(), "event": event, "reason": reason})


def _record_rejected(directory, verdict: dict) -> None:
    """One rejection entry per rejection episode, not one per five-minute run."""
    path = directory / "evidence" / "rejected.jsonl"
    if path.exists():
        try:
            lines = [ln for ln in path.read_text(encoding="utf-8").splitlines() if ln.strip()]
            if lines and json.loads(lines[-1]).get("event") == "rejected":
                return
        except (OSError, json.JSONDecodeError):
            pass
    _record_event(directory, "rejected.jsonl", "rejected",
                  "; ".join(verdict.get("reasons") or [])[:500])


def _bucket_roots() -> dict:
    return {
        "raise": config.RAISE_DIR,
        "standby": config.STANDBY_DIR,
        "rejected": config.REJECT_DIR,
    }


def _legacy_bucket_roots() -> dict:
    """Older/manual archives that still contain real ticket directories."""
    base = config.RAISE_DIR.parent
    return {
        "legacy-raised": base / "raised",
        "legacy-fixed": base / "fixed",
        "legacy-solved": base / "solved",
    }


def _existing_by_identity() -> dict[str, list[dict]]:
    """Every staged directory, grouped by its signature identity."""
    grouped: dict[str, list[dict]] = {}
    roots = dict(_bucket_roots())
    roots.update(_legacy_bucket_roots())
    for bucket, root in roots.items():
        if not root.exists():
            continue
        for path in sorted(root.iterdir()):
            if not path.is_dir():
                continue
            _normalize_evidence_names(path)
            manifest = _read_manifest(path)
            vendor = str(manifest.get("vendor") or "")
            signature = str(manifest.get("signature") or "")
            if not vendor or not signature:
                continue
            grouped.setdefault(_identity(signature), []).append({
                "bucket": bucket,
                "legacy": bucket.startswith("legacy-"),
                "path": path,
                "manifest": manifest,
                "kind": str(manifest.get("kind") or ""),
                "generated": str(manifest.get("generated") or ""),
            })
    return grouped


def _dedupe_existing(grouped: dict[str, list[dict]]) -> tuple[dict[str, dict], list[dict]]:
    """Keep one directory per signature and park the older copies.

    Vendor reclassification, legacy buckets, and event/correlation views all
    describe the same fault when the signature matches. Nothing is deleted:
    losing directories move under the winner's evidence/ as prior copies.
    """
    winners: dict[str, dict] = {}
    merged: list[dict] = []
    for ident, items in grouped.items():
        active = [item for item in items if not item["legacy"]]
        if not active:
            # Keep legacy archives intact when no live bucket owns the ticket.
            continue
        winner = max(
            active,
            key=lambda item: (
                item["bucket"] == "raise",
                -KIND_RANK.get(item["kind"], 3),
                item["generated"],
            ),
        )
        for item in items:
            if item is winner:
                continue
            _merge_into(item["path"], winner["path"], item["bucket"])
            _record_event(
                winner["path"], "dedupe.jsonl", "merged",
                f"duplicate {item['bucket']}/{item['path'].name}",
            )
            merged.append({
                "ticket": item["path"].name,
                "kept": winner["path"].name,
                "bucket": item["bucket"],
            })
        winners[ident] = winner
    return winners, merged


def reconcile(conn, desired: dict[str, str],
              assessments: dict[str, dict]) -> dict:
    """Move ticket directories to the bucket their verdict asks for.

    raise/     viable now, ready for a human to post
    rejected/  explained by local package state (held/outdated build)
    standby/   was viable, is not now; kept only as an audit trail

    Nothing is deleted: if the destination already exists, the older copy is
    parked inside its evidence/ directory instead of overwriting it.
    """
    roots = _bucket_roots()
    for root in roots.values():
        root.mkdir(parents=True, exist_ok=True)

    present: dict[str, str] = {}
    for bucket, root in roots.items():
        for path in sorted(root.iterdir()):
            if path.is_dir() and path.name not in present:
                present[path.name] = bucket

    reactivated, stood_down, rejected_moves = [], [], []
    for name, source in sorted(present.items()):
        target = desired.get(name, "standby")
        if target == source:
            continue
        src = roots[source] / name
        destination = roots[target] / name
        if destination.exists():
            _merge_into(src, destination, source)
        else:
            shutil.move(str(src), str(destination))

        info = assessments.get(name) or {}
        reason = "; ".join(
            info.get("verdict", {}).get("reasons")
            or ["no current draft reproduces this ticket"]
        )[:500]
        if target == "raise":
            _record_event(destination, "standby.jsonl", "reactivated",
                          "viability checks passed again")
            if source == "rejected":
                _record_event(destination, "rejected.jsonl", "cleared", reason)
            reactivated.append(name)
        elif target == "rejected":
            _record_event(destination, "rejected.jsonl", "rejected", reason)
            rejected_moves.append(name)
        else:
            _record_event(destination, "standby.jsonl", "standby", reason)
            stood_down.append({"ticket": name, "reason": reason[:300]})

    return {"reactivated": reactivated, "stood_down": stood_down,
            "rejected": rejected_moves}


def _write_bucket_index(root, record: str, title: str, empty: str) -> None:
    entries = []
    for path in sorted(root.iterdir()):
        if not path.is_dir():
            continue
        last = {}
        log = path / "evidence" / record
        if log.exists():
            try:
                lines = [ln for ln in log.read_text(encoding="utf-8").splitlines() if ln.strip()]
                if lines:
                    last = json.loads(lines[-1])
            except (OSError, json.JSONDecodeError):
                last = {}
        manifest = path / "evidence" / "manifest.json"
        vendor, signature = "", ""
        if manifest.exists():
            try:
                data = json.loads(manifest.read_text(encoding="utf-8"))
                vendor = data.get("vendor", "")
                signature = data.get("display") or data.get("signature", "")
            except (OSError, json.JSONDecodeError):
                pass
        entries.append({
            "name": path.name, "vendor": vendor, "signature": signature,
            "since": last.get("ts", ""), "reason": last.get("reason", ""),
        })
    lines = [f"# {title}", "",
             f"Generated {iso()} — kept for traceability; nothing here is deleted.", ""]
    if entries:
        lines += ["| ticket | vendor | reason | since |", "|---|---|---|---|"]
        for entry in entries:
            lines.append(
                f"| [{entry['name']}]({entry['name']}/ticket.md) | {entry['vendor']} | "
                f"{entry['reason'][:140]} | {entry['since']} |"
            )
    else:
        lines.append(empty)
    _write(root / "INDEX.md", "\n".join(lines) + "\n")


def _howto(issue: dict, verdict: dict, bucket: str = "raise") -> str:
    if bucket == "rejected":
        return f"""# Why this report is in rejected/

Vendor: **{issue['vendor']}** — {issue['kind']} cluster `{issue['key']}`

The crash is explained by local package state, not by a defect the vendor can
act on. See `REJECTED.md` for the exact reason.

1. Release the hold and upgrade the named package(s).
2. Re-run `./bin/qa raise`; if the crash stops reproducing on the candidate,
   the directory stays here as an audit record.
3. If it still reproduces on the current candidate, the ticket moves back to
   `tickets/raise/` automatically.

Viability: {verdict['score']}/{verdict['max_score']} checks passed.
"""
    return f"""# How to raise this ticket

Vendor: **{issue['vendor']}** — {issue['kind']} cluster `{issue['key']}`

1. Read `ticket.md`. It is already redacted; do not add host or identity data.
2. Check `evidence/logs.json` and `evidence/trace.md` still describe what you saw.
3. Attach the evidence bundle named in `evidence/manifest.json` (verify its SHA-256).
4. Post through the vendor channel in `ticket.md`. Submission is manual by design.
5. Keep `evidence/manifest.json`: it is what makes this ticket auditable later.

Viability: {verdict['score']}/{verdict['max_score']} checks passed.
"""


def _rejection_note(issue: dict, verdict: dict) -> str:
    reasons = "\n".join(
        f"- {reason}" for reason in (verdict.get("reasons") or ["no reason recorded"])
    )
    return f"""# Rejected — the local build explains this crash

Vendor: **{issue['vendor']}** — {issue['kind']} cluster `{issue['key']}`

A vendor cannot fix a pinned, outdated build. The draft is kept as evidence of
what was running, not as a report to post.

## Why

{reasons}

## What clears it

Upgrade the named package(s) to the candidate (release the hold first), then
re-run `./bin/qa raise`. The ticket returns to `tickets/raise/` only if the
crash still reproduces on the current build.
"""


# ---------------------------------------------------------------- run
def run(conn, days: int = 30, min_count: int | None = None,
        notify_ready: bool = True) -> dict:
    config.RAISE_DIR.mkdir(parents=True, exist_ok=True)
    config.REJECT_DIR.mkdir(parents=True, exist_ok=True)
    issues = {i["key"]: i for i in tickets.collect_issues(conn, days)}
    drafts = [dict(r) for r in conn.execute("SELECT * FROM ticket_drafts ORDER BY vendor, ts")]
    bundle_row = conn.execute("SELECT * FROM bundles ORDER BY id DESC LIMIT 1").fetchone()
    bundle = dict(bundle_row) if bundle_row else None

    raised, rejected, rejected_staged = [], [], []
    assessments: dict[str, dict] = {}
    desired: dict[str, str] = {}
    deduplicated: list[dict] = []

    # One ticket per vendor+signature. A correlation and a plain event for the
    # same signature are two views of one fault; staging both creates the
    # duplicate directories the raise queue must not contain.
    groups: dict[str, dict] = {}
    for draft in drafts:
        issue = issues.get(draft["issue_key"])
        verdict = assess(conn, draft, issue, days=days, min_count=min_count)
        vendor, signature = _ticket_identity(draft, issue)
        ident = _identity(signature)
        candidate = {
            "draft": draft,
            "issue": issue,
            "verdict": verdict,
            "vendor": vendor,
            "signature": signature,
            "display": _display(issue, draft),
            "rank": (
                0 if verdict["viable"] else 1,
                KIND_RANK.get((issue or {}).get("kind") or "", 3),
                -int((issue or {}).get("count") or 0),
                draft["issue_key"],
            ),
        }
        current = groups.get(ident)
        if current is None:
            groups[ident] = candidate
            continue
        winner = candidate if candidate["rank"] < current["rank"] else current
        loser = current if winner is candidate else candidate
        winner["deduped"] = current.get("deduped", 0) + 1
        groups[ident] = winner
        deduplicated.append({
            "key": loser["draft"]["issue_key"],
            "kept": winner["draft"]["issue_key"],
            "vendor": winner["vendor"],
            "signature": winner["display"][:120],
            "kind": (loser["issue"] or {}).get("kind") or "",
        })

    # Collapse duplicates that are already on disk before deciding what to
    # stage. The surviving directory name is reused instead of minting a new
    # one from a different issue key.
    existing, merged_existing = _dedupe_existing(_existing_by_identity())

    for ident, group in groups.items():
        draft, issue, verdict = group["draft"], group["issue"], group["verdict"]
        chosen = existing.get(ident)
        name = chosen["path"].name if chosen else _dir_name(draft, issue)
        group["name"] = name
        if verdict["viable"] and issue:
            desired[name] = "raise"
        elif issue and verdict.get("hold_explained"):
            # the local build explains it: keep the report, but never raise it
            desired[name] = "rejected"
        else:
            desired[name] = "standby"
        assessments[name] = {"draft": draft, "verdict": verdict}
        if not (verdict["viable"] and issue):
            rejected.append({
                "key": draft["issue_key"],
                "vendor": draft["vendor"],
                "title": draft["title"],
                "reasons": verdict["reasons"],
            })

    # re-bucket what moved *before* staging, so a directory that changed bucket
    # is updated in place instead of duplicated
    moves = reconcile(conn, desired, assessments)

    written = 0
    for ident, group in sorted(groups.items()):
        issue = group["issue"]
        if not issue:
            continue
        draft, verdict, name = group["draft"], group["verdict"], group["name"]
        if verdict["viable"]:
            directory = config.RAISE_DIR / name
            if _already_staged(directory, issue):
                raised.append(_staged_summary(directory, issue, verdict))
            else:
                raised.append(stage(conn, draft, issue, verdict, bundle, name=name))
                written += 1
        elif verdict.get("hold_explained"):
            directory = config.REJECT_DIR / name
            if _already_staged(directory, issue, bucket="rejected"):
                rejected_staged.append(
                    _staged_summary(directory, issue, verdict, "rejected")
                )
            else:
                rejected_staged.append(stage(
                    conn, draft, issue, verdict, bundle,
                    root=config.REJECT_DIR, bucket="rejected", name=name,
                ))
                written += 1

    config.RAISE_DIR.mkdir(parents=True, exist_ok=True)
    index = ["# Tickets staged for raising", "",
             f"Generated {iso()} — {len(raised)} viable, {len(rejected)} rejected, "
             f"{len(deduplicated)} duplicate(s) skipped.", ""]
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
    if deduplicated:
        index += ["## Deduplicated", ""]
        for item in deduplicated:
            index.append(
                f"- {item['vendor']}: {item['signature']} — "
                f"kept `{item['kept']}`, skipped `{item['key']}`"
            )
        index.append("")
    if merged_existing:
        index += ["## Merged existing duplicates", ""]
        for item in merged_existing:
            index.append(
                f"- `{item['ticket']}` ({item['bucket']}) → `{item['kept']}`"
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
    _write_bucket_index(config.STANDBY_DIR, "standby.jsonl", "Tickets in standby",
                        "No tickets in standby.")
    _write_bucket_index(config.REJECT_DIR, "rejected.jsonl", "Rejected reports",
                        "No rejected reports.")

    if raised or rejected_staged:
        report.append_journal(
            conn,
            f"Raise gate: {len(raised)} viable, {len(rejected)} rejected, "
            f"{len(rejected_staged)} filed under rejected/",
            "\n".join(f"- {r['vendor']}: {r['signature']}" for r in raised[:10]) + "\n",
            "raise",
        )
    if notify_ready:
        from . import notify

        if raised:
            # identity, not hashes: manifests are regenerated every run and a
            # hash-based key would pop a notification every 5 minutes.
            digest = sha256_text("|".join(sorted(r["issue_key"] for r in raised)))[:16]
            notify.enqueue(
                conn, "raise", f"raise|{digest}",
                f"{len(raised)} ticket(s) staged in raise/",
                "\n".join(f"- {r['vendor']}: {r['signature']}" for r in raised[:6]),
                detail=str(config.RAISE_DIR),
                path=str(config.RAISE_DIR / "INDEX.md"),
                supersede=True,
            )
        else:
            # Nothing is staged now; an undelivered alert would be misleading.
            notify.clear_pending(conn, "raise")

    return {
        "drafts": len(drafts),
        "viable": len(raised),
        "rejected": len(rejected),
        "staged": [r["directory"] for r in raised],
        "written": written,
        "deduplicated": deduplicated,
        "merged_existing": merged_existing,
        "rejected_staged": [r["directory"] for r in rejected_staged],
        "rejected_keys": [r["key"] for r in rejected],
        "stood_down": moves["stood_down"],
        "reactivated": moves["reactivated"],
        "rejected_moves": moves["rejected"],
    }
