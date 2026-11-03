"""Central paths and constants for qa-sentinels."""
import os
import pathlib

HOME = pathlib.Path(os.environ.get("HOME", pathlib.Path.home()))
ROOT = pathlib.Path(os.environ.get("QA_SENTINELS_HOME", HOME / "qa-sentinels")).resolve()

BIN = ROOT / "bin"
VAR = ROOT / "var"
DB_PATH = VAR / "sentinels.db"
SAMPLE_JSONL = VAR / "samples.jsonl"
LOCK_PATH = VAR / "tick.lock"

JOURNAL_DIR = ROOT / "journal"
REPORT_DIR = JOURNAL_DIR / "reports"
EVIDENCE_DIR = ROOT / "evidence"
TICKET_DIR = ROOT / "tickets"
DRAFT_DIR = TICKET_DIR / "drafts"
RAISE_DIR = TICKET_DIR / "raise"
STANDBY_DIR = TICKET_DIR / "in-standby"
TRIAGE_DIR = ROOT / "triage" / "core2"
DEEP_DIR = TRIAGE_DIR / "deep"
DEEP_REQUEST_DIR = TRIAGE_DIR / "deep-requests"
DEEP_ARCHIVE_DIR = TRIAGE_DIR / "deep-requests" / "archive"
CONFIG_DIR = ROOT / "config"
IDENTITY_FILE = CONFIG_DIR / "identity.env"

SAMPLE_BIN = BIN / "qa_sample"

CORE2_PHYSICAL_ID = int(os.environ.get("QA_CORE2_ID", "2"))
INVENTORY_INTERVAL_S = int(os.environ.get("QA_INVENTORY_INTERVAL_S", str(3 * 3600)))
INVENTORY_MIN_S = int(os.environ.get("QA_INVENTORY_MIN_S", "900"))
INVENTORY_MAX_S = int(os.environ.get("QA_INVENTORY_MAX_S", str(12 * 3600)))
INVENTORY_EVENT_GAP_S = int(os.environ.get("QA_INVENTORY_EVENT_GAP_S", "300"))

# two-phase operation
DEEP_DURATION_S = int(os.environ.get("QA_DEEP_DURATION_S", "30"))
DEEP_MAX_DURATION_S = int(os.environ.get("QA_DEEP_MAX_DURATION_S", "120"))
DEEP_AUTO = os.environ.get("QA_DEEP_AUTO", "1").lower() in ("1", "yes", "true", "on")
DEEP_REQUEST_COOLDOWN_S = int(os.environ.get("QA_DEEP_REQUEST_COOLDOWN_S", "1800"))
PSI_MEMORY_FULL_ALERT = float(os.environ.get("QA_PSI_MEMORY_FULL_ALERT", "10"))
MEM_AVAILABLE_ALERT_PCT = float(os.environ.get("QA_MEM_AVAILABLE_ALERT_PCT", "5"))
TEMP_ALERT_C = float(os.environ.get("QA_TEMP_ALERT_C", "90"))
IO_PRESSURE_ALERT = float(os.environ.get("QA_IO_PRESSURE_ALERT", "50"))
CORE2_CPUS = tuple(int(x) for x in os.environ.get("QA_CORE2_CPUS", "2,8").split(",") if x)

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

# log lines from these units are sentinel self-noise, never vendor evidence
SELF_UNIT_PREFIXES = ("qa-sentinel",)

# retention
EVENT_RETENTION_DAYS = int(os.environ.get("QA_EVENT_RETENTION_DAYS", "30"))
SAMPLE_RETENTION_DAYS = int(os.environ.get("QA_SAMPLE_RETENTION_DAYS", "7"))
PROC_RETENTION_DAYS = int(os.environ.get("QA_PROC_RETENTION_DAYS", "3"))
INVENTORY_RETENTION_DAYS = int(os.environ.get("QA_INVENTORY_RETENTION_DAYS", "90"))


def ensure_dirs() -> None:
    for d in (
        VAR, JOURNAL_DIR, REPORT_DIR, EVIDENCE_DIR, TICKET_DIR, DRAFT_DIR,
        TRIAGE_DIR, DEEP_DIR, DEEP_REQUEST_DIR, DEEP_ARCHIVE_DIR, CONFIG_DIR,
        RAISE_DIR, STANDBY_DIR,
    ):
        d.mkdir(parents=True, exist_ok=True)
