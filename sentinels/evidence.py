"""Tamper-evident evidence bundles with a hash chain."""
from __future__ import annotations

import json
import os
import tarfile
from datetime import datetime, timedelta, timezone

from . import config, db, detect, hardware, lsm, posture, report, triage
from .util import (
    read_text, run, sha256_file, sha256_text, iso, utcnow, write_json,
    write_text_atomic, redact,
)


def _rows(conn, sql: str, args=()) -> list[dict]:
    return [dict(r) for r in conn.execute(sql, args).fetchall()]


def _compact_samples(conn, since_iso: str) -> list[dict]:
    rows = conn.execute(
        "SELECT ts, payload FROM samples WHERE ts>=? ORDER BY ts", (since_iso,)
    ).fetchall()
    out = []
    for row in rows:
        p = json.loads(row["payload"])
        out.append(
            {
                "ts": p.get("ts"),
                "loadavg": p.get("loadavg"),
                "online_cpus": p.get("online_cpus"),
                "mem": {k: p.get("mem", {}).get(k) for k in
                        ("MemTotal", "MemAvailable", "SwapFree", "Dirty", "HardwareCorrupted")},
                "psi": p.get("psi"),
                "freq_mhz": p.get("freq_mhz"),
                "thermal": p.get("thermal"),
                "oom_kill": p.get("oom_kill"),
                "core2": p.get("core2"),
            }
        )
    return out


def make_bundle(conn, reason: str = "manual", hours: int = 24, make_tar: bool = True,
                event_limit: int | None = None) -> dict:
    limit = config.EVIDENCE_EVENT_LIMIT if event_limit is None else event_limit
    now = datetime.now(timezone.utc)
    since = (now - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    stamp = now.strftime("%Y%m%d-%H%M%S")
    slug = "".join(c if c.isalnum() or c in "-_" else "-" for c in reason)[:40]
    path = config.EVIDENCE_DIR / f"{stamp}-{slug}"
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        os.chmod(path, 0o700)
    except OSError:
        pass

    latest_report = conn.execute(
        "SELECT path FROM reports ORDER BY id DESC LIMIT 1"
    ).fetchone()
    report_text = read_text(latest_report["path"]) if latest_report else ""

    files: dict[str, str] = {}

    def put(name: str, content) -> None:
        target = path / name
        if isinstance(content, (dict, list)):
            write_json(target, content)
        else:
            write_text_atomic(target, str(content))
        files[name] = sha256_file(target)

    crashes = _rows(conn, "SELECT * FROM crashes WHERE ts>=? ORDER BY ts DESC", (since,))
    for c in crashes:
        c["context"] = redact(c.get("context") or "")
        c["exe"] = redact(c.get("exe") or "")
        c["corefile"] = redact(c.get("corefile") or "")
    events = _rows(
        conn,
        "SELECT * FROM events WHERE ts>=? ORDER BY ts DESC"
        + (f" LIMIT {int(limit)}" if limit and limit > 0 else ""),
        (since,),
    )
    for e in events:
        e["message"] = redact(e.get("message") or "")
        e["raw"] = None

    latest_sample = conn.execute(
        "SELECT payload FROM samples ORDER BY ts DESC LIMIT 1"
    ).fetchone()
    sample = json.loads(latest_sample["payload"]) if latest_sample else {}
    for proc in sample.get("procs", []):
        proc["exe"] = redact(proc.get("exe") or "")
        proc["comm"] = redact(proc.get("comm") or "")

    inv_run = conn.execute("SELECT * FROM inventory_runs ORDER BY id DESC LIMIT 1").fetchone()
    inventory = {}
    diffs = []
    if inv_run:
        inventory = {
            "run": dict(inv_run),
            "items": [
                dict(r) for r in conn.execute(
                    "SELECT layer, item, value FROM inventory WHERE run_id=? ORDER BY layer, item",
                    (inv_run["id"],),
                )
            ],
        }
        diffs = _rows(
            conn,
            "SELECT layer, change, item, old_value, new_value FROM inventory_diffs "
            "WHERE run_id=? ORDER BY layer, item",
            (inv_run["id"],),
        )
        for row in inventory["items"]:
            row["value"] = redact(row["value"] or "")
        for row in diffs:
            row["old_value"] = redact(row.get("old_value") or "")
            row["new_value"] = redact(row.get("new_value") or "")

    put("summary.md", redact(report_text) or "# Evidence bundle\n\nNo report available.\n")
    put("events.json", events)
    put("crashes.json", crashes)
    put("sample-latest.json", sample)
    put("samples-summary.json", _compact_samples(conn, since))
    put("inventory.json", inventory)
    put("inventory-diff.json", diffs)
    hardware_data = hardware.latest(conn, complete=True)
    if hardware_data:
        hardware_data["run"]["detail"] = redact(hardware_data["run"].get("detail") or "")
        for item in hardware_data.get("items", []):
            item["value"] = redact(str(item.get("value") or ""))
    put("hardware.json", hardware_data)
    lsm_data = lsm.latest(conn)
    if lsm_data:
        lsm_data["state"] = json.loads(json.dumps(lsm_data.get("state") or {}))
        for key, values in (lsm_data.get("denials") or {}).items():
            if isinstance(values, list):
                lsm_data["denials"][key] = [redact(str(value)) for value in values]
    put("lsm.json", lsm_data)
    put("core2-analysis.md", report._core2_section(conn, since))
    tri_cases = triage.cases(conn, limit=10000)
    for case_row in tri_cases:
        for key in ("process", "signature", "detail", "notes"):
            case_row[key] = redact(case_row.get(key) or "")
        raw_path = str(case_row.get("path") or "")
        if raw_path:
            rel = os.path.relpath(raw_path, str(config.ROOT))
            case_row["path"] = rel if not rel.startswith("..") else os.path.basename(raw_path)
    put("triage-cases.json", tri_cases)
    put("triage-index.md", read_text(config.TRIAGE_DIR / "index.md") or "# Core-2 triage queue\n")
    redacted_findings = detect.list_findings(conn, limit=1000)
    for finding in redacted_findings:
        finding["detail"] = redact(finding.get("detail") or "")
        finding["subject"] = redact(finding.get("subject") or "")
    put("findings.json", redacted_findings)
    deep_runs = [
        dict(r) for r in conn.execute("SELECT * FROM deep_runs ORDER BY id DESC LIMIT 200")
    ]
    for row in deep_runs:
        row["path"] = os.path.basename(str(row.get("path") or ""))
    put("deep-runs.json", deep_runs)
    put("deep-index.md", redact(read_text(config.DEEP_DIR / "index.md") or "# Deep investigation runs\n"))
    for case_row in tri_cases[:200]:
        case_path = config.ROOT / str(case_row.get("path") or "")
        if case_path.is_file():
            put(f"triage-case-{case_row['id']:04d}.md", redact(read_text(case_path)))
    put("posture.json", posture.collect())
    put("sentinel-status.json", {
        "last_sample": db.meta_get(conn, "last_sample_ts"),
        "last_ingest": db.meta_get(conn, "last_journal_ingest"),
        "last_inventory": db.meta_get(conn, "last_inventory_ts"),
        "bundle_reason": reason,
        "window_hours": hours,
        "generated": iso(now),
    })

    prev = conn.execute(
        "SELECT sha256 FROM bundles ORDER BY id DESC LIMIT 1"
    ).fetchone()
    prev_sha = prev["sha256"] if prev else "GENESIS"
    manifest = {
        "bundle": path.name,
        "created": iso(now),
        "reason": reason,
        "window_hours": hours,
        "prev_bundle_sha256": prev_sha,
        "files": files,
        "redaction": [
            "home directory replaced with /home/<user>",
            "hostname, email, MAC, UUID, IPv4 and serial numbers masked",
            "journal identities and raw journal records dropped",
            "physical core 2 correlation retained (never omitted)",
        ],
    }
    body = json.dumps(manifest, indent=2, sort_keys=True)
    bundle_sha = sha256_text(body + "\n")
    manifest["bundle_sha256"] = bundle_sha
    write_json(path / "manifest.json", manifest)

    chain = config.EVIDENCE_DIR / "chain.log"
    with open(chain, "a", encoding="utf-8") as fh:
        fh.write(f"{iso(now)} {bundle_sha} prev={prev_sha} bundle={path.name}\n")
    try:
        os.chmod(chain, 0o600)
    except OSError:
        pass

    tar_path = None
    if make_tar:
        tar_path = path.with_suffix(".tar.gz")
        with tarfile.open(tar_path, "w:gz") as tar:
            tar.add(path, arcname=path.name)
        try:
            os.chmod(tar_path, 0o600)
        except OSError:
            pass

    conn.execute(
        "INSERT INTO bundles(ts, path, sha256, prev_sha256, contents) VALUES(?,?,?,?,?)",
        (iso(now), str(path), bundle_sha, prev_sha, ",".join(sorted(files))),
    )
    return {
        "path": str(path),
        "sha256": bundle_sha,
        "prev_sha256": prev_sha,
        "files": sorted(files),
        "tar": str(tar_path) if tar_path else None,
    }


def verify_bundle(path: str) -> dict:
    from pathlib import Path

    candidate = Path(path)
    if not candidate.is_absolute():
        options = [
            Path.cwd() / candidate,
            config.EVIDENCE_DIR / candidate,
            config.EVIDENCE_DIR / candidate.name,
        ]
        candidate = next((p for p in options if (p / "manifest.json").exists()), options[0])
    base = candidate
    manifest_path = base / "manifest.json"
    if not manifest_path.exists():
        return {"ok": False, "error": f"manifest missing in {base}"}
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {"ok": False, "error": f"invalid manifest: {exc}", "path": str(base)}
    if not isinstance(manifest, dict):
        return {"ok": False, "error": "manifest must be an object", "path": str(base)}
    problems = []
    root = base.resolve()
    files = manifest.get("files", {})
    if not isinstance(files, dict):
        return {"ok": False, "error": "manifest files must be an object", "path": str(base)}
    for name, expected in files.items():
        if not isinstance(name, str) or not name or os.path.isabs(name):
            problems.append(f"unsafe path: {name}")
            continue
        target = base / name
        try:
            resolved = target.resolve()
            resolved.relative_to(root)
        except (OSError, ValueError):
            problems.append(f"unsafe path: {name}")
            continue
        if not target.is_file():
            problems.append(f"missing: {name}")
        else:
            try:
                actual = sha256_file(target)
            except OSError:
                problems.append(f"unreadable: {name}")
                continue
            if actual != expected:
                problems.append(f"hash mismatch: {name}")
    body = dict(manifest)
    files_sha = body.get("files_sha256")
    claimed = body.get("bundle_sha256")
    if files_sha:
        recomputed = sha256_text("\n".join(
            f"{name}:{digest}" for name, digest in sorted(body.get("files", {}).items())
        ))
        if recomputed != files_sha:
            problems.append("files digest mismatch")
    else:
        body.pop("bundle_sha256", None)
        recomputed = sha256_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
        if claimed and claimed != recomputed:
            problems.append("bundle hash mismatch")
    return {"ok": not problems, "problems": problems, "path": str(base), "sha256": claimed}
