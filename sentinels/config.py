"""Central paths and constants for QA Sentinels."""
import json
import os
import pathlib
import re

PROJECT_NAME = "QA Sentinels"
PROJECT_SHORT = "QA Sentinels"
PROJECT_DESCRIPTION = "Security Focused Evidence Collecting Probes"
# Compatibility slug: repository directory, cron marker, unit names and env var.
PROJECT_SLUG = "qa-sentinels"
PROJECT_DIR = "QA-Sentinels"

HOME = pathlib.Path(os.environ.get("HOME", pathlib.Path.home()))
ROOT = pathlib.Path(os.environ.get("QA_SENTINELS_HOME", HOME / PROJECT_DIR)).resolve()

SETTINGS_FILE = ROOT / "config" / "settings.json"


def apply_settings_file(path=None) -> None:
    """Load numeric QA_* overrides written by the dashboard.

    Values are only accepted when the key is missing from the environment and
    the value is a bare number, so the file can never inject shell content.
    """
    target = pathlib.Path(path) if path else SETTINGS_FILE
    try:
        data = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if not isinstance(data, dict):
        return
    for key, value in data.items():
        if not isinstance(key, str) or not key.startswith("QA_"):
            continue
        if key in os.environ:
            continue
        text = str(value).strip()
        if not re.fullmatch(r"-?\d+(?:\.\d+)?", text):
            continue
        os.environ[key] = text


apply_settings_file()


def _faultlab_values(path: pathlib.Path) -> dict[str, str]:
    """Read faultlab's KEY=VALUE file without executing it."""
    values: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return values
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if re.fullmatch(r"[A-Z_][A-Z0-9_]*", key):
            values[key] = value.strip().strip('"').strip("'")
    return values


def _cpu_tuple(value: str | None) -> tuple[int, ...]:
    cpus: set[int] = set()
    for part in (value or "").replace(" ", ",").split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            first, _, last = part.partition("-")
            try:
                cpus.update(range(int(first), int(last) + 1))
            except ValueError:
                continue
            continue
        try:
            cpus.add(int(part))
        except ValueError:
            continue
    return tuple(sorted(cpus))


def _optional_int(value: str | None) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


FAULTLAB_CONFIG = pathlib.Path(
    os.environ.get("QA_FAULTLAB_CONFIG", "/etc/faultlab/config")
)
_FAULTLAB = _faultlab_values(FAULTLAB_CONFIG)

BIN = ROOT / "bin"
VAR = ROOT / "var"
DB_PATH = VAR / "sentinels.db"

# systemd-pstore moves EFI pstore records here after the next boot. The
# archive is root-owned; root/pstore-export.sh writes panic-only summaries to
# PSTORE_EXPORT_DIR so the unprivileged sentinel can read them.
PSTORE_ARCHIVE_DIR = pathlib.Path(
    os.environ.get("QA_PSTORE_ARCHIVE_DIR", "/var/lib/systemd/pstore")
)
PSTORE_EXPORT_DIR = pathlib.Path(
    os.environ.get("QA_PSTORE_EXPORT_DIR", str(VAR / "pstore"))
)

JOURNAL_DIR = ROOT / "journal"
REPORT_DIR = JOURNAL_DIR / "reports"
SHUTDOWN_DIR = pathlib.Path(
    os.environ.get("QA_SHUTDOWN_DIR", str(VAR / "shutdown"))
)
CAPTURE_REDACTION = os.environ.get("QA_CAPTURE_REDACTION", "strict").strip().lower()
if CAPTURE_REDACTION not in ("strict", "collapsed", "metadata"):
    CAPTURE_REDACTION = "strict"
CAPTURE_BOOT = os.environ.get("QA_CAPTURE_BOOT", "1").lower() in (
    "1", "yes", "true", "on",
)
EVIDENCE_DIR = ROOT / "evidence"
TICKET_DIR = ROOT / "tickets"
DRAFT_DIR = TICKET_DIR / "drafts"
RAISE_DIR = TICKET_DIR / "raise"
STANDBY_DIR = TICKET_DIR / "standby"
REJECT_DIR = TICKET_DIR / "rejected"
TRIAGE_DIR = ROOT / "triage" / "faultcore"
DEEP_DIR = TRIAGE_DIR / "deep"
DEEP_REQUEST_DIR = TRIAGE_DIR / "deep-requests"
DEEP_ARCHIVE_DIR = TRIAGE_DIR / "deep-requests" / "archive"
CONFIG_DIR = ROOT / "config"
IDENTITY_FILE = CONFIG_DIR / "identity.env"

SAMPLE_BIN = BIN / "qa_sample"

INVENTORY_INTERVAL_S = int(os.environ.get("QA_INVENTORY_INTERVAL_S", str(3 * 3600)))
INVENTORY_MIN_S = int(os.environ.get("QA_INVENTORY_MIN_S", "900"))
INVENTORY_MAX_S = int(os.environ.get("QA_INVENTORY_MAX_S", str(12 * 3600)))
INVENTORY_EVENT_GAP_S = int(os.environ.get("QA_INVENTORY_EVENT_GAP_S", "300"))

# two-layer operation
DEEP_DURATION_S = int(os.environ.get("QA_DEEP_DURATION_S", "30"))
DEEP_MAX_DURATION_S = int(os.environ.get("QA_DEEP_MAX_DURATION_S", "120"))
DEEP_AUTO = os.environ.get("QA_DEEP_AUTO", "1").lower() in ("1", "yes", "true", "on")
DEEP_REQUEST_COOLDOWN_S = int(os.environ.get("QA_DEEP_REQUEST_COOLDOWN_S", "1800"))

# layer 1 cycle: one command every minute owns the whole routine loop, so cron
# and systemd schedules stay equivalent. Each task is due-based and persisted.
CYCLE_CORRELATE_S = int(os.environ.get("QA_CYCLE_CORRELATE_S", "300"))
CYCLE_RAISE_HOURS = float(os.environ.get("QA_CYCLE_RAISE_HOURS", "1") or "1")
if CYCLE_RAISE_HOURS <= 0:
    CYCLE_RAISE_HOURS = 1.0
CYCLE_RAISE_S = int(os.environ.get(
    "QA_CYCLE_RAISE_S", str(max(60, int(CYCLE_RAISE_HOURS * 3600)))
))
CYCLE_CROSSCHECK_S = int(os.environ.get("QA_CYCLE_CROSSCHECK_S", str(6 * 3600)))
CYCLE_DAILY_HOUR = int(os.environ.get("QA_CYCLE_DAILY_HOUR", "8"))
PSI_MEMORY_FULL_ALERT = float(os.environ.get("QA_PSI_MEMORY_FULL_ALERT", "10"))
MEM_AVAILABLE_ALERT_PCT = float(os.environ.get("QA_MEM_AVAILABLE_ALERT_PCT", "5"))
TEMP_ALERT_C = float(os.environ.get("QA_TEMP_ALERT_C", "90"))
IO_PRESSURE_ALERT = float(os.environ.get("QA_IO_PRESSURE_ALERT", "50"))
FAULT_CPU = _optional_int(
    os.environ.get("QA_FAULT_CPU") or _FAULTLAB.get("FAULT_CPU")
)
CONTROL_CPU = _optional_int(
    os.environ.get("QA_CONTROL_CPU") or _FAULTLAB.get("CONTROL_CPU")
)
FAULT_CORE_CPUS = _cpu_tuple(
    os.environ.get("QA_FAULT_CORE_CPUS")
    or os.environ.get("QA_FAULT_CPUS")
    or os.environ.get("QA_CORE2_CPUS")
    or _FAULTLAB.get("FAULT_CPUS")
)
CONTROL_CPUS = _cpu_tuple(
    os.environ.get("QA_CONTROL_CPUS") or _FAULTLAB.get("CONTROL_CPUS")
)
SAFE_CPUS = _cpu_tuple(
    os.environ.get("QA_SAFE_CPUS") or _FAULTLAB.get("SAFE_CPUS")
)
FAULT_CORE_PHYSICAL_ID = _optional_int(
    os.environ.get("QA_FAULT_CORE_PHYSICAL_ID")
    or os.environ.get("QA_FAULT_CORE_ID")
    or os.environ.get("QA_FAULT_PHYSICAL_ID")
    or os.environ.get("QA_CORE2_ID")
)
_FAULT_CORE_ENABLE = os.environ.get(
    "QA_FAULT_CORE_ENABLE", os.environ.get("QA_CORE2_ENABLE", "auto")
).strip().lower()
if _FAULT_CORE_ENABLE in ("auto", ""):
    FAULT_CORE_ENABLE = bool(FAULT_CORE_CPUS)
else:
    FAULT_CORE_ENABLE = _FAULT_CORE_ENABLE in ("1", "yes", "true", "on")
FAULT_CORE_ENFORCE = os.environ.get(
    "QA_FAULT_CORE_ENFORCE", os.environ.get("QA_CORE2_ENFORCE", "auto")
).strip().lower()
if FAULT_CORE_ENFORCE not in ("auto", "lab", "retired", "off"):
    FAULT_CORE_ENFORCE = "auto"
FAULT_CORE_MODE_FILE = pathlib.Path(os.environ.get(
    "QA_FAULT_CORE_MODE_FILE", os.environ.get("QA_CORE2_MODE_FILE", "/etc/faultlab/mode")
))
FAULT_CORE_CPU_ROOT = pathlib.Path(os.environ.get(
    "QA_FAULT_CORE_CPU_ROOT", os.environ.get("QA_CORE2_CPU_ROOT", "/sys/devices/system/cpu")
))
FAULT_CORE_CGROUP_ROOT = pathlib.Path(os.environ.get(
    "QA_FAULT_CORE_CGROUP_ROOT", os.environ.get("QA_CORE2_CGROUP_ROOT", "/sys/fs/cgroup")
))
FAULT_CORE_AB_RESULTS = pathlib.Path(os.environ.get(
    "QA_FAULT_CORE_AB_RESULTS", os.environ.get("QA_CORE2_AB_RESULTS", "/var/log/faultlab/ab.jsonl")
))

# security provenance: live process scan every cycle, file ownership less often.
SECURITY_FILE_SCAN_S = int(os.environ.get("QA_SECURITY_FILE_SCAN_S", "300"))
SECURITY_AUDIT = os.environ.get("QA_SECURITY_AUDIT", "1").lower() in ("1", "yes", "true", "on")
SECURITY_POLICY_PATH = CONFIG_DIR / "security-policy.json"

# hardware-health tier: slow sampling, external tools are best-effort and
# privilege failures are recorded rather than failing the routine cycle.
HARDWARE_ENABLE = os.environ.get("QA_HARDWARE_ENABLE", "1").lower() in ("1", "yes", "true", "on")
HARDWARE_INTERVAL_S = max(60, int(os.environ.get("QA_HARDWARE_INTERVAL_S", "900")))
HARDWARE_TIMEOUT_S = max(5, int(os.environ.get("QA_HARDWARE_TIMEOUT_S", "20")))
HARDWARE_RAW_LIMIT = max(4096, int(os.environ.get("QA_HARDWARE_RAW_LIMIT", "200000")))
HARDWARE_CE_ALERT = int(os.environ.get("QA_HARDWARE_CE_ALERT", "1"))
HARDWARE_AER_CE_ALERT = int(os.environ.get("QA_HARDWARE_AER_CE_ALERT", "1"))
HARDWARE_NVME_USED_ALERT = int(os.environ.get("QA_HARDWARE_NVME_USED_ALERT", "1"))
HARDWARE_NVME_SPARE_ALERT = int(os.environ.get("QA_HARDWARE_NVME_SPARE_ALERT", "100"))
HARDWARE_GPU_TEMP_ALERT_C = int(os.environ.get("QA_HARDWARE_GPU_TEMP_ALERT_C", "65"))
HARDWARE_SENSOR_TEMP_ALERT_C = int(os.environ.get("QA_HARDWARE_SENSOR_TEMP_ALERT_C", "70"))
HARDWARE_STORAGE_TEMP_ALERT_C = int(os.environ.get("QA_HARDWARE_STORAGE_TEMP_ALERT_C", "50"))
HARDWARE_SOURCES_PATH = CONFIG_DIR / "hardware-sources.json"
HARDWARE_VENDOR_LINES = max(10, int(os.environ.get("QA_HARDWARE_VENDOR_LINES", "200")))
HARDWARE_RETENTION_DAYS = max(1, int(os.environ.get("QA_HARDWARE_RETENTION_DAYS", "14")))
HARDWARE_REQUIRED_SOURCES = tuple(
    item.strip() for item in os.environ.get(
        "QA_HARDWARE_REQUIRED_SOURCES",
        "ras,storage,gpu,bmc,sensors,turbostat,pcm,uncore,vendor",
    ).split(",") if item.strip()
)

# Linux Security Modules: state/drift and denial monitoring.
LSM_ENABLE = os.environ.get("QA_LSM_ENABLE", "1").lower() in ("1", "yes", "true", "on")
LSM_INTERVAL_S = max(60, int(os.environ.get("QA_LSM_INTERVAL_S", "300")))
LSM_DENIAL_ALERT = max(1, int(os.environ.get("QA_LSM_DENIAL_ALERT", "1")))
LSM_TIMEOUT_S = max(5, int(os.environ.get("QA_LSM_TIMEOUT_S", "20")))
LSM_RETENTION_DAYS = max(1, int(os.environ.get("QA_LSM_RETENTION_DAYS", "30")))
LSM_ROOT_HANDOFF = VAR / "lsm-state-root.json"
LSM_ROOT_HANDOFF_MAX_AGE_S = max(
    300, int(os.environ.get("QA_LSM_ROOT_HANDOFF_MAX_AGE_S", "1800"))
)

# capture breadth. Defaults are production-sane; the "no artificial cap" mode is
# opt-in because full-priority ingest and forever retention can fill a disk.
FULL_CAPTURE = os.environ.get("QA_FULL_CAPTURE", "0").lower() in ("1", "yes", "true", "on")
KEEP_FOREVER = os.environ.get("QA_KEEP_FOREVER", "0").lower() in ("1", "yes", "true", "on")
JOURNAL_PRIORITY = os.environ.get("QA_JOURNAL_PRIORITY", "info" if FULL_CAPTURE else "warning")
MAX_TICKETS = int(os.environ.get("QA_MAX_TICKETS", "10"))       # 0 = no cap
EVIDENCE_EVENT_LIMIT = int(os.environ.get("QA_EVIDENCE_EVENT_LIMIT", "5000"))  # 0 = all
MIN_FREE_MIB = int(os.environ.get("QA_MIN_FREE_MIB", "1024"))

# silent-stop correlation: how the final window of an unclean boot is linked to
# the events that preceded it, and when the pattern is strong enough to draft a
# vendor ticket. "Consistency" means the same component signature recurs across
# separate silent stops, not merely that it is frequent inside one.
CORRELATE_WINDOW_S = int(os.environ.get("QA_CORRELATE_WINDOW_S", "1800"))
CORRELATE_MIN_BOOTS = int(os.environ.get("QA_CORRELATE_MIN_BOOTS", "2"))
CORRELATE_MIN_COUNT = int(os.environ.get("QA_CORRELATE_MIN_COUNT", "3"))
CORRELATE_SINGLE_BOOT_MIN = int(os.environ.get("QA_CORRELATE_SINGLE_BOOT_MIN", "5"))

# viability gate for /raise: what must be true before a draft becomes a ticket
# a human is expected to actually post.
RAISE_MIN_COUNT = int(os.environ.get("QA_RAISE_MIN_COUNT", "3"))
RAISE_MAX_AGE_DAYS = int(os.environ.get("QA_RAISE_MAX_AGE_DAYS", "30"))

if JOURNAL_PRIORITY not in ("emerg", "alert", "crit", "err", "warning", "notice", "info", "debug"):
    JOURNAL_PRIORITY = "warning"

# retention: 0 keeps a class forever, matching the dashboard defaults
EVENT_RETENTION_DAYS = max(0, int(os.environ.get("QA_EVENT_RETENTION_DAYS", "0")))
SHUTDOWN_RETENTION_DAYS = max(0, int(
    os.environ.get("QA_SHUTDOWN_RETENTION_DAYS", str(EVENT_RETENTION_DAYS))
))
SAMPLE_RETENTION_DAYS = max(0, int(os.environ.get("QA_SAMPLE_RETENTION_DAYS", "0")))
PROC_RETENTION_DAYS = max(0, int(os.environ.get("QA_PROC_RETENTION_DAYS", "0")))
INVENTORY_RETENTION_DAYS = max(
    0, int(os.environ.get("QA_INVENTORY_RETENTION_DAYS", "0"))
)
DRAFT_RETENTION_DAYS = max(
    0, int(os.environ.get("QA_DRAFTS_RETENTION_DAYS", "30"))
)
RAISE_LOOKBACK_DAYS = max(
    1, int(os.environ.get("QA_RAISE_LOOKBACK_DAYS", "30"))
)

# execution-log rotation: copytruncate at the cap and keep a bounded set, so
# var/cron.log cannot grow without limit or rotate into thousands of tiny files
LOG_MAX_MB = max(1, int(os.environ.get("QA_LOG_MAX_MB", "20")))
LOG_KEEP = max(1, int(os.environ.get("QA_LOG_KEEP", "10")))

# notifications: retry backoff and retention for rows that never deliver
NOTIFY_TTL_DAYS = max(1, int(os.environ.get("QA_NOTIFY_TTL_DAYS", "14")))
NOTIFY_BACKOFF_S = max(60, int(os.environ.get("QA_NOTIFY_BACKOFF_S", "300")))
NOTIFY_BACKOFF_MAX_S = max(60, int(os.environ.get("QA_NOTIFY_BACKOFF_MAX_S", str(6 * 3600))))


def _secure(path, mode: int) -> None:
    try:
        path.chmod(mode)
    except OSError:
        pass


def ensure_dirs() -> None:
    for d in (
        VAR, JOURNAL_DIR, REPORT_DIR, EVIDENCE_DIR, TICKET_DIR, DRAFT_DIR,
        TRIAGE_DIR.parent, TRIAGE_DIR, DEEP_DIR, DEEP_REQUEST_DIR, DEEP_ARCHIVE_DIR, CONFIG_DIR,
        RAISE_DIR, STANDBY_DIR, REJECT_DIR, PSTORE_EXPORT_DIR, SHUTDOWN_DIR,
    ):
        d.mkdir(parents=True, exist_ok=True)
        _secure(d, 0o700)
    # Existing state from older installs may still be group/world-readable.
    for name in (
        "cron.log", "qa.db", "sentinels.db", "sentinels.db-wal",
        "sentinels.db-shm", "cycle.lock", "posture.json",
        "posture-baseline.json", "sudo-probe.json",
    ):
        path = VAR / name
        if path.exists():
            _secure(path, 0o600)
    for path in PSTORE_EXPORT_DIR.glob("*/summary.txt"):
        _secure(path, 0o600)
    for path in SHUTDOWN_DIR.glob("*.json"):
        _secure(path, 0o600)
    chain = EVIDENCE_DIR / "chain.log"
    if chain.exists():
        _secure(chain, 0o600)
    if IDENTITY_FILE.exists():
        _secure(IDENTITY_FILE, 0o600)
    if SECURITY_POLICY_PATH.exists():
        _secure(SECURITY_POLICY_PATH, 0o600)
    if HARDWARE_SOURCES_PATH.exists():
        _secure(HARDWARE_SOURCES_PATH, 0o600)
