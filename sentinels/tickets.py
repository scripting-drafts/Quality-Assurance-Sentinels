"""Generate per-vendor ticket drafts. Never submits anything.

Submission is deliberately manual: a human reviews each draft, attaches the
hash-verified evidence bundle and posts it through the vendor's tracker.
"""
from __future__ import annotations

import os
import re
from datetime import timedelta

from . import classify, config, correlate, db
from .util import (
    human_bytes, identity_for_ticket, iso, read_text, redact, run, sha256_text, utcnow,
)


def _environment() -> list[str]:
    os_release = {}
    for line in read_text("/etc/os-release").splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            os_release[k] = v.strip('"')
    cpu = ""
    for line in read_text("/proc/cpuinfo").splitlines():
        if line.lower().startswith("model name"):
            cpu = line.split(":", 1)[1].strip()
            break
    mem_kb = 0
    for line in read_text("/proc/meminfo").splitlines():
        if line.startswith("MemTotal:"):
            mem_kb = int(re.sub(r"[^0-9]", "", line))
            break
    gpu = ""
    rc, out, _ = run(["lspci", "-nn"], timeout=15)
    if rc == 0:
        for line in out.splitlines():
            if re.search(r"VGA|3D|Display", line):
                gpu = re.sub(r"\s+", " ", line.strip())
                break
    lines = [
        f"- OS: {os_release.get('PRETTY_NAME', 'Linux')}",
        f"- Kernel: {read_text('/proc/sys/kernel/osrelease')}",
        f"- CPU: {cpu or 'unknown'} ({os.cpu_count()} logical CPUs)",
        f"- Physical core 2 logical siblings: {', '.join(map(str, config.CORE2_CPUS))}",
        f"- Memory: {human_bytes(mem_kb)}",
    ]
    if gpu:
        lines.append(f"- GPU: {gpu}")
    platform = " ".join(
        filter(None, [
            read_text("/sys/class/dmi/id/sys_vendor"),
            read_text("/sys/class/dmi/id/product_name"),
        ])
    )
    if platform:
        lines.append(f"- Platform: {platform}")
    return lines


_COMMAND_LINE = re.compile(r"^\s*Command Line:\s*(.+?)\s*$", re.M)


def _repro_block(issue: dict) -> list[str]:
    """Return reproduction steps only when the evidence names a trigger.

    Event clusters carry no reliable trigger, so they get no Reproduction
    section instead of generic vendor boilerplate.
    """
    for row in issue.get("rows") or []:
        match = _COMMAND_LINE.search(row.get("context") or "")
        if match:
            command = match.group(1).strip()
            return [
                f"1. Run `{command}`.",
                "2. Capture the resulting crash and `coredumpctl info` output.",
            ]
    return []


def collect_issues(conn, days: int = 7, include_local: bool = False) -> list[dict]:
    since = (utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    crashes = [dict(r) for r in conn.execute(
        "SELECT * FROM crashes WHERE ts>=? ORDER BY ts DESC", (since,)
    )]
    events = [dict(r) for r in conn.execute(
        "SELECT * FROM events WHERE ts>=? AND severity IN ('critical','error') ORDER BY ts DESC",
        (since,),
    )]

    issues: dict[str, dict] = {}

    def add(vendor: str, signature: str, kind: str, row: dict) -> None:
        key = sha256_text(f"{vendor}|{kind}|{signature}")[:20]
        n = int(row.get("count") or 1)
        first = row.get("ts")
        last = row.get("last_ts") or row.get("ts")
        issue = issues.setdefault(
            key,
            {
                "key": key,
                "vendor": vendor,
                "signature": signature,
                "kind": kind,
                "rows": [],
                "count": 0,
                "severity": row.get("severity") or ("critical" if kind == "crash" else "error"),
                "first": first,
                "last": last,
            },
        )
        issue["rows"].append(row)
        issue["count"] += n
        if first:
            issue["first"] = min(issue["first"], first) if issue["first"] else first
        if last:
            issue["last"] = max(issue["last"], last) if issue["last"] else last
        if row.get("severity") == "critical":
            issue["severity"] = "critical"

    for c in crashes:
        blob = " ".join(str(c.get(k) or "") for k in ("comm", "exe", "sig", "context"))
        vendor = classify.vendor_for(blob)
        if c.get("core2_involved") == 1 and vendor == "local":
            vendor = "hardware"
        sig = f"{c.get('comm') or c.get('exe')} {c.get('sig')}"
        add(vendor, sig, "crash", c)

    for e in events:
        vendor = classify.vendor_for(e.get("unit") or "", e.get("message") or "")
        sig = classify.signature(e.get("message") or "")
        add(vendor, sig, "event", e)

    # dedicated hardware ticket: core-2 correlation must reach the platform vendor
    core2_crashes = [c for c in crashes if c.get("core2_involved") == 1]
    if core2_crashes:
        key = sha256_text("hardware|core2-correlation")[:20]
        issues[key] = {
            "key": key,
            "vendor": "hardware",
            "signature": "crashes correlated with physical core 2 affinity",
            "kind": "correlation",
            "rows": core2_crashes,
            "count": len(core2_crashes),
            "severity": "critical",
            "first": min(c["ts"] for c in core2_crashes),
            "last": max(c["ts"] for c in core2_crashes),
        }

    result = [
        i
        for i in issues.values()
        if (include_local or i["vendor"] != "local")
        and classify.ticketworthy(i["signature"], i["kind"], i["severity"], i["count"])
    ]
    # silent stops correlated with a recurring component signature: the one path
    # where a ticket has no single log line to point at, only a convergence.
    result.extend(correlate.ticket_candidates(conn, days))
    result.sort(
        key=lambda i: (
            i["kind"] != "correlation",
            i["kind"] != "crash",
            i["severity"] != "critical",
            -i["count"],
        )
    )
    return result


def _core2_table(rows: list[dict]) -> list[str]:
    crashed = [r for r in rows if "sig" in r]
    if not crashed:
        return ["No crash rows in this cluster."]
    lines = [
        "| time (UTC) | process | signal | allowed CPUs | core 2 in mask |",
        "|---|---|---|---|---|",
    ]
    for c in crashed[:25]:
        verdict = {1: "yes", 0: "no", None: "unknown"}.get(c.get("core2_involved"), "unknown")
        lines.append(
            f"| {c.get('ts')} | `{c.get('comm') or c.get('exe')}` | {c.get('sig')} | "
            f"`{c.get('cpus_allowed') or 'unknown'}` | {verdict} |"
        )
    lines += [
        "",
        "Affinity comes from the last `/proc/<pid>/status` sample before the crash. "
        "Unknown affinity is labelled unknown, not discarded. This correlation is part "
        "of the QA record and is included in every ticket.",
    ]
    return lines


def _draft(issue: dict, bundle: dict | None, identity: dict, consent: bool) -> tuple[str, str]:
    meta = classify.VENDOR_META.get(issue["vendor"], classify.VENDOR_META["local"])
    title = f"[QA] {meta['component']}: {issue['signature'][:120]}"
    rows = issue["rows"]
    example = ""
    if rows:
        example = rows[0].get("message") or rows[0].get("context") or ""

    lines = [
        f"# {title}",
        "",
        f"- Vendor / channel: **{meta['name']}** — {meta['channel']}",
        f"- Cluster key: `{issue['key']}`",
        f"- Occurrences: **{issue['count']}** between `{issue['first']}` and `{issue['last']}`",
        "",
        "## Environment",
        "",
        *_environment(),
        "",
    ]
    if issue.get("kind") == "crash":
        # vendors need the exact build, not just "Ubuntu 22.04"
        from . import packages as pkgmod

        exe = next((r.get("exe") for r in rows if r.get("exe")), None)
        pkg = pkgmod.context(exe)
        owner = pkg.get("owner") or {}
        from . import holds as holdsmod

        hold = holdsmod.relevant(exe)
        lines += [
            "## Installed packages",
            "",
            f"- Owning package: `{owner.get('package', 'unknown')}` "
            f"{owner.get('version', '')}".rstrip(),
            f"- Package inventory at draft time: **{pkg['count']}** packages",
            "",
            "```",
            *(pkg["packages"] or ["(package list unavailable)"]),
            "```",
            "",
        ]
        if hold.get("relevant") or hold.get("mass_hold"):
            lines += ["## Held packages", ""]
            if hold.get("mass_hold"):
                lines.append(
                    f"- **Global hold**: {hold['held_total']} packages held, "
                    f"{hold['held_installed']} installed — upgrades are pinned system-wide"
                )
            for row in (hold.get("outdated") or [])[:10]:
                lines.append(
                    f"- Outdated and held: `{row['package']}` {row['installed']} "
                    f"(candidate {row['candidate']})"
                )
            if not hold.get("outdated") and hold.get("relevant"):
                lines.append("- Related packages are held but current.")
            lines.append("")
    lines += [
        "## What happens",
        "",
        f"A recurring {issue['kind']} cluster was observed",
        "",
        "```",
        redact(example)[:3000] or "(no message captured)",
        "```",
        "",
    ]
    if issue.get("notes"):
        lines += ["## Consistency", "", issue["notes"], ""]
    if any("sig" in row for row in rows):
        lines += [
            "## Physical core 2 correlation (required, do not omit)",
            "",
            *_core2_table(rows),
            "",
        ]
    repro = _repro_block(issue)
    if repro:
        lines += ["## Reproduction", "", *repro, ""]
    lines += [
        "## Evidence (internal)",
        "",
    ]
    if bundle:
        import os as _os

        raw_path = str(bundle.get("path") or "")
        try:
            shown = _os.path.relpath(raw_path, config.ROOT)
            if shown.startswith(".."):
                shown = _os.path.basename(raw_path)
        except ValueError:
            shown = _os.path.basename(raw_path)
        lines += [
            f"- Bundle: `{shown}`",
            f"- Bundle SHA-256: `{bundle.get('sha256')}`",
            f"- Previous bundle SHA-256: `{bundle.get('prev_sha256')}`",
            f"- Contents: {bundle.get('contents', '')}",
            f"- Verify with: `cd ~/qa-sentinels && bin/qa verify {shown}`",
        ]
    else:
        lines += [
            "- No bundle generated yet. Run `~/qa-sentinels/bin/qa evidence --reason ticket` and attach it.",
        ]
    lines += [
        "",
        "## Reporter",
        "",
    ]
    if consent and identity:
        lines += [f"- Name: {identity.get('FULL_NAME', '')}"]
        if identity.get("LINKEDIN"):
            lines.append(f"- LinkedIn: {identity['LINKEDIN']}")
        if identity.get("GITHUB"):
            lines.append(f"- GitHub: {identity['GITHUB']}")
    else:
        lines.append(
            "- Identity withheld. Set `TICKET_CONSENT=1` plus FULL_NAME/LINKEDIN/GITHUB "
            "in `config/identity.env` to attach it; nothing is invented or auto-filled."
        )
    return title, "\n".join(lines) + "\n"


# Deprecated shim: kept so out-of-tree callers do not break.
_collect_issues = collect_issues


def generate(conn, days: int = 7, include_local: bool = False, max_tickets: int | None = None) -> list[dict]:
    issues = collect_issues(conn, days, include_local)
    cap = config.MAX_TICKETS if max_tickets is None else max_tickets
    selected = issues if cap <= 0 else issues[:cap]
    bundle_row = conn.execute(
        "SELECT * FROM bundles ORDER BY id DESC LIMIT 1"
    ).fetchone()
    bundle = dict(bundle_row) if bundle_row else None
    identity, consent = identity_for_ticket()

    made = []
    keep: set[str] = set()
    conn.execute("DELETE FROM ticket_drafts")
    for issue in selected:
        title, body = _draft(issue, bundle, identity, consent)
        vendor = issue["vendor"]
        slug = re.sub(r"[^a-z0-9]+", "-", issue["signature"].lower()).strip("-")[:60]
        path = config.DRAFT_DIR / f"{vendor}-{slug}-{issue['key'][:8]}.md"
        path.write_text(body, encoding="utf-8")
        keep.add(str(path))
        conn.execute(
            "INSERT INTO ticket_drafts(ts, vendor, path, title, issue_key)"
            " VALUES(?,?,?,?,?) ON CONFLICT(issue_key) DO UPDATE SET"
            " ts=excluded.ts, path=excluded.path, title=excluded.title",
            (iso(), vendor, str(path), title, issue["key"]),
        )
        made.append({"vendor": vendor, "title": title, "path": str(path), "count": issue["count"]})
    for old in config.DRAFT_DIR.glob("*.md"):
        if old.name == "INDEX.md":  # generated digest target, not a draft
            continue
        if str(old) not in keep:
            old.unlink(missing_ok=True)
    db.meta_set(conn, "last_ticket_run", iso())
    _triage_new_tickets(conn, selected)
    return made


def _triage_new_tickets(conn, issues: list[dict]) -> None:
    """Run the viability gate as soon as the draft set changes.

    Drafts are generated on a schedule, but a ticket that appears should be
    triaged in the same pass that created it, not up to five minutes later.
    """
    keys = {i["key"] for i in issues}
    seen = set(filter(None, (db.meta_get(conn, "triaged_draft_keys") or "").split(",")))
    if not keys or keys == seen:
        return
    from . import raise_ticket  # lazy: raise_ticket imports this module

    try:
        result = raise_ticket.run(conn)
        db.meta_set(conn, "triaged_draft_keys", ",".join(sorted(keys)))
        db.record_run(conn, "tickets/raise", True,
                      f"viable={result['viable']} rejected={result['rejected']}")
    except Exception as exc:  # noqa: BLE001 - triage must never block drafts
        db.record_run(conn, "tickets/raise", False, str(exc)[:300])
