"""Severity and vendor classification, kept in one testable place."""
from __future__ import annotations

import re

CRITICAL_PATTERNS = [
    r"\bpanic\b", r"\bkernel panic\b", r"\boops\b", r"\bBUG:", r"\bWARNING: CPU:",
    r"general protection fault", r"\bMCE\b", r"machine check", r"hardware error",
    r"\bEDAC\b", r"\bRAS\b", r"mce: ", r"\bXid\b",
    r"NVRM: .*(?:Xid|error|fatal|assert|GPU has fallen|video memory|out of memory)",
    r"watchdog: BUG",
    r"soft lockup", r"hard lockup", r"hung task", r"out of memory", r"oom-kill",
    r"segfault", r"segmentation fault", r"\bSIGSEGV\b", r"\bSIGABRT\b", r"\bSIGBUS\b",
    r"\bSIGILL\b", r"I/O error", r"EXT4-fs error", r"XFS .*corrupt",
    r"ata[0-9.]+: (?:hard resetting|failed command|exception)", r"nvme.*(?:reset|timeout)",
    r"GPU has fallen off the bus", r"failed to idle channel", r"page fault",
    r"unrecoverable", r"fatal", r"corrupt", r"\bABRT\b",
]

ERROR_PATTERNS = [
    r"\berror\b", r"\berr\b", r"\bfailed\b", r"\bfailure\b", r"\bfatal\b",
    r"\babort\b", r"\bcrash", r"\bdenied\b", r"\bexception\b", r"\btimeout\b",
    r"cannot allocate", r"no space left", r"broken pipe",
]

WARNING_PATTERNS = [
    r"\bwarn", r"\bdeprecat", r"\bretry", r"\bthrottl", r"\bdegraded\b",
    r"unable to", r"not responding", r"slow", r"stall",
]

NOISE_PATTERNS = [
    r"Californ(?:ia|ie) institute of Technology",  # NVIDIA EDID spam
    r"NVIDIA\(GPU-0\): .*maximum pixel clock",
    r"Failed to set mode.*EDID",
    r"dbus-daemon.*(?:Activating|Successfully activated)",
    r"^\(--\)",                                   # Xorg info level
    r"^\(II\)",
    r"NVIDIA\(GPU-0\): ?(?:DFP|.*maximum pixel clock|disconnected|connected|Internal|$)",
    r"ibus-daemon.*GChildWatchSource",
    r"Owner of volume monitor",
    r"tracker-miner-f.*volume monitor",
    r"xf86CloseConsole",
    r"systemd-logind: (?:not releasing fd|failed to release device)",
    r"UnloadModule",
    r"Deleting GPU-0",
    r"Server terminated successfully",
    r"\(EE\) event\d+ - .*client bug: event processing lagging",
    r"NVRM: loading NVIDIA",
]

# Real but non-actionable for a vendor ticket: keep in the local record,
# never turn into a draft.
BENIGN_FOR_TICKET = [
    r"not generating service for xdg[ -]autostart",
    r"prime-offload",
    r"Failed to bind sideband socket",
    r"permission denied.*xdriver",
    r"NVRM: loading NVIDIA",
    r"Failed to take device /dev/dri/card0",
    r"Could not create transient scope for PID",
]


def ticketworthy(signature: str, kind: str, severity: str, count: int) -> bool:
    if kind in ("crash", "correlation"):
        return True
    if any(re.search(p, signature, re.IGNORECASE) for p in BENIGN_FOR_TICKET):
        return False
    if severity == "critical":
        return True
    return severity == "error" and count >= 5


def _match(patterns, text: str) -> bool:
    return any(re.search(p, text, re.IGNORECASE) for p in patterns)


def classify(message: str, priority: int | None = None) -> str:
    """Return one of critical|error|warning|info|noise."""
    text = (message or "").strip()
    if not text:
        return "info"
    if _match(NOISE_PATTERNS, text):
        return "noise"
    if _match(CRITICAL_PATTERNS, text):
        return "critical"
    if _match(ERROR_PATTERNS, text):
        return "error"
    if _match(WARNING_PATTERNS, text):
        return "warning"
    if priority is not None:
        if priority <= 2:
            return "critical"
        if priority == 3:
            return "error"
        if priority == 4:
            return "warning"
    return "info"


def priority_to_severity(priority: int | None) -> str:
    if priority is None:
        return "info"
    return {0: "critical", 1: "critical", 2: "critical", 3: "error", 4: "warning"}.get(
        priority, "info"
    )


VENDOR_RULES = [
    ("mozilla", re.compile(
        r"firefox|mozilla|webrender|gecko|js::|gfx::|compositor|libxul|tab crash|content process",
        re.IGNORECASE)),
    ("nvidia", re.compile(r"nvidia|nvrm|\bXid\b|nouveau|gpu has fallen", re.IGNORECASE)),
    ("canonical-kernel", re.compile(
        r"kernel|oops|panic|BUG:|mce|machine check|edac|nvme|ata[0-9]|ext4|xfs|"
        r"i915|amdgpu|soft lockup|hung task|oom", re.IGNORECASE)),
    ("gnome", re.compile(r"gnome-shell|mutter|gdm|tracker|evolution", re.IGNORECASE)),
    ("systemd", re.compile(r"systemd|journald|udev|logind|dbus", re.IGNORECASE)),
]

VENDOR_META = {
    "mozilla": {
        "name": "Mozilla",
        "channel": "Bugzilla (https://bugzilla.mozilla.org)",
        "component": "Core :: Graphics: WebRender",
    },
    "nvidia": {
        "name": "NVIDIA",
        "channel": "NVIDIA Linux driver feedback / distributor bug tracker",
        "component": "Proprietary GPU driver",
    },
    "canonical-kernel": {
        "name": "Canonical / Ubuntu kernel",
        "channel": "Launchpad (https://bugs.launchpad.net/ubuntu)",
        "component": "linux (Ubuntu)",
    },
    "gnome": {
        "name": "GNOME",
        "channel": "GNOME GitLab (https://gitlab.gnome.org)",
        "component": "mutter / gnome-shell",
    },
    "systemd": {
        "name": "systemd",
        "channel": "systemd GitHub issues / distro tracker",
        "component": "systemd",
    },
    "local": {
        "name": "Local / unassigned",
        "channel": "local triage queue",
        "component": "unknown",
    },
    "hardware": {
        "name": "Hardware vendor",
        "channel": "vendor support portal (use the DMI product name)",
        "component": "CPU / platform",
    },
}


def vendor_for(*texts: str) -> str:
    """Pick the most specific owner for a cluster of evidence."""
    blob = "\n".join(t for t in texts if t)
    for name, pattern in VENDOR_RULES:
        if pattern.search(blob):
            return name
    return "local"


SIGNATURE_MASKS = [
    (re.compile(r"0x[0-9a-fA-F]+"), "0xADDR"),
    (re.compile(r"\b\d{2,}\b"), "N"),
    (re.compile(r"\b[0-9a-fA-F]{8,}\b"), "HEX"),
    (re.compile(r"\b(?:pid|PID)\s*=?\s*\d+"), "PID"),
]


def signature(text: str, limit: int = 160) -> str:
    """Stable-ish signature for grouping recurring events."""
    value = (text or "").strip().splitlines()[0] if text else ""
    for rx, repl in SIGNATURE_MASKS:
        value = rx.sub(repl, value)
    value = re.sub(r"\s+", " ", value)
    return value[:limit]
