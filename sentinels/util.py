"""Small stdlib-only helpers shared by every sentinel."""
from __future__ import annotations

import hashlib
import json
import os
import re
import socket
import subprocess
import time
from datetime import datetime, timezone

from . import config


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(dt: datetime | None = None) -> str:
    return (dt or utcnow()).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(value: str) -> datetime:
    value = value.strip().replace("Z", "+00:00")
    return datetime.fromisoformat(value).astimezone(timezone.utc)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8", "replace"))


def sha256_file(path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run(cmd: list[str], timeout: int = 20) -> tuple[int, str, str]:
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
            check=False,
        )
        return p.returncode, p.stdout, p.stderr
    except FileNotFoundError:
        return 127, "", f"{cmd[0]}: not found"
    except subprocess.TimeoutExpired:
        return 124, "", f"{cmd[0]}: timed out after {timeout}s"


def read_text(path, default: str = "") -> str:
    try:
        with open(path, "r", errors="replace") as fh:
            return fh.read().strip()
    except OSError:
        return default


_HOSTNAME = socket.gethostname()
_USER = os.environ.get("USER") or os.environ.get("LOGNAME") or "user"
_EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")
_MAC_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
_UUID_RE = re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b")
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_SERIAL_RE = re.compile(r"(?i)\b(serial(?:\s*(?:number|no\.?))?\s*[:=]\s*)\S+")


def redact(text: str) -> str:
    """Remove operator-identifying data before anything leaves the host.

    Vendor tickets must contain the hardware/software facts, never the operator.
    Paths keep their shape so stack traces remain useful.
    """
    if not text:
        return ""
    text = text.replace(str(config.HOME), "/home/<user>")
    text = text.replace(os.path.expanduser("~"), "/home/<user>")
    if _HOSTNAME and _HOSTNAME not in ("localhost",):
        text = text.replace(_HOSTNAME, "<host>")
    text = _EMAIL_RE.sub("<email>", text)
    text = _MAC_RE.sub("<mac>", text)
    text = _UUID_RE.sub("<uuid>", text)
    text = _IPV4_RE.sub("<ip>", text)
    text = _SERIAL_RE.sub(r"\1<serial>", text)
    if _USER and len(_USER) > 2:
        text = re.sub(rf"\b{re.escape(_USER)}\b", "<user>", text)
    return text


def load_identity() -> dict[str, str]:
    """Read optional ticket identity. Empty by default; never synthesised.

    The file is intentionally outside every export/bundle: an operator must
    opt in with TICKET_CONSENT=1 before a draft carries their name or links.
    """
    identity: dict[str, str] = {}
    if not config.IDENTITY_FILE.exists():
        return identity
    for line in config.IDENTITY_FILE.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        identity[key.strip()] = value.strip().strip('"').strip("'")
    return identity


def identity_for_ticket() -> tuple[dict[str, str], bool]:
    ident = load_identity()
    consent = ident.get("TICKET_CONSENT", "0").lower() in ("1", "yes", "true")
    fields = {
        k: ident.get(k, "")
        for k in ("FULL_NAME", "LINKEDIN", "GITHUB")
        if ident.get(k)
    }
    return fields, consent


def fmt_duration(seconds: float) -> str:
    seconds = int(max(0, seconds))
    d, rem = divmod(seconds, 86400)
    h, rem = divmod(rem, 3600)
    m, s = divmod(rem, 60)
    if d:
        return f"{d}d{h:02d}h"
    if h:
        return f"{h}h{m:02d}m"
    if m:
        return f"{m}m{s:02d}s"
    return f"{s}s"


def human_bytes(kib: float) -> str:
    value = float(kib) * 1024
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(value) < 1024 or unit == "TiB":
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TiB"


def write_json(path, payload) -> None:
    tmp = str(path) + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True, default=str)
        fh.write("\n")
    os.replace(tmp, path)


def append_jsonl(path, payload) -> None:
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, sort_keys=True, default=str) + "\n")
