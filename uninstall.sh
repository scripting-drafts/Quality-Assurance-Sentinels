#!/usr/bin/env bash
# Remove installed Quality Assurance Sentinels hooks and build outputs, keeping gathered data.
#
# Default: removes the systemd units, the user cron block, the live-log
# autostart entry and compiled binaries. Keeps var/, journal/, evidence/,
# tickets/, triage/ and config/identity.env, so a reinstall continues from the
# history already collected.
#
# Usage: ./uninstall.sh [options]
#   --dry-run      print what would be removed, change nothing
#   --yes          do not prompt (data is still kept unless --purge-data)
#   --keep-build   keep compiled binaries (sampler, eBPF tracer)
#   --purge-data   also delete gathered data (asks for confirmation)
#   -h, --help     this text
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_NAME="Quality Assurance Sentinels"
DRY_RUN=0
ASSUME_YES=0
KEEP_BUILD=0
PURGE_DATA=0
FAILED=0

usage() { sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; }
die() { echo "$*" >&2; exit 2; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dry-run)    DRY_RUN=1 ;;
    --yes|-y)     ASSUME_YES=1 ;;
    --keep-build) KEEP_BUILD=1 ;;
    --purge-data) PURGE_DATA=1 ;;
    -h|--help)    usage; exit 0 ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
  shift
done

cd "$ROOT"
[[ -f install.sh && -d sentinels ]] || die "not a $PROJECT_NAME checkout: $ROOT"

run() {
  printf '   $ %s\n' "$*"
  [[ $DRY_RUN -eq 1 ]] || "$@"
}

try() {
  printf '   $ %s\n' "$*"
  [[ $DRY_RUN -eq 1 ]] || "$@" || { echo "   ! failed, continuing"; FAILED=1; }
}

DATA_DIRS=(var journal evidence tickets triage)
UNIT_FILES=(
  /etc/systemd/system/qa-sentinel.service
  /etc/systemd/system/qa-sentinel.timer
  /etc/systemd/system/qa-sentinel-deep.service
  /etc/systemd/system/qa-sentinel-deep.path
  /etc/systemd/system/qa-pstore-export.service
  /etc/systemd/system/qa-hardware.service
  /etc/systemd/system/qa-hardware.timer
  /etc/systemd/system/qa-lsm-read.service
  /etc/systemd/system/qa-lsm-read.timer
  /etc/systemd/system/qa-siem-forward.service
  /etc/systemd/system/qa-siem-forward.timer
)
AUTOSTART="${XDG_CONFIG_HOME:-$HOME/.config}/autostart/qa-sentinels-logs.desktop"
BUILT=(
  bin/qa_sample bin/qa_ebpf bin/qa_trace.bpf.o bin/qa_ebpf.build.json
  root/ebpf/qa_ebpf root/ebpf/qa_trace.bpf.o root/ebpf/vmlinux.h
)
if [[ ${EUID} -eq 0 ]]; then
  PRIV=()
else
  PRIV=(sudo)
fi

echo "$PROJECT_NAME uninstaller"
echo "  root: $ROOT"
echo
echo "will remove"
found_units=()
for unit in "${UNIT_FILES[@]}"; do
  [[ -e "$unit" ]] && found_units+=("$unit")
done
if [[ ${#found_units[@]} -gt 0 ]]; then
  echo "  systemd units: ${found_units[*]##*/}"
else
  echo "  systemd units: none installed"
fi
if command -v crontab >/dev/null 2>&1 && crontab -l 2>/dev/null | grep -q '>>> qa-sentinels >>>'; then
  echo "  user cron block: $PROJECT_NAME"
else
  echo "  user cron block: none installed"
fi
if [[ -e "$AUTOSTART" || -e bin/qa-logs-terminal ]]; then
  echo "  live-log autostart entry"
fi
if [[ $KEEP_BUILD -eq 1 ]]; then
  echo "  build outputs: kept (--keep-build)"
else
  echo "  compiled binaries: sampler, eBPF tracer, build stamp"
fi

echo
echo "will keep"
if [[ $PURGE_DATA -eq 1 ]]; then
  echo "  config/identity.env (only data left after purge)"
else
  for dir in "${DATA_DIRS[@]}"; do
    [[ -d "$dir" ]] || continue
    size="$(du -sh "$dir" 2>/dev/null | cut -f1 || true)"
    echo "  $dir/ (${size:-unreadable})"
  done
  [[ -f config/identity.env ]] && echo "  config/identity.env"
fi
echo

if [[ $PURGE_DATA -eq 1 && $ASSUME_YES -eq 0 && $DRY_RUN -eq 0 ]]; then
  read -r -p "Type DELETE to purge gathered data: " answer || answer=""
  [[ "$answer" == "DELETE" ]] || die "aborted; no data was deleted"
fi
if [[ $ASSUME_YES -eq 0 && $DRY_RUN -eq 0 ]]; then
  read -r -p "Proceed? [y/N] " reply || reply=""
  [[ "$reply" =~ ^[Yy] ]] || { echo "aborted; nothing was removed"; exit 1; }
fi

# ---------------------------------------------------------------- services
if [[ ${#found_units[@]} -gt 0 ]]; then
  unit_names=()
  for unit in "${found_units[@]}"; do
    unit_names+=("$(basename "$unit")")
  done
  if command -v systemctl >/dev/null 2>&1; then
    try "${PRIV[@]}" systemctl disable --now "${unit_names[@]}"
    try "${PRIV[@]}" systemctl stop "${unit_names[@]}"
  fi
  try "${PRIV[@]}" rm -f "${found_units[@]}"
  if command -v systemctl >/dev/null 2>&1; then
    try "${PRIV[@]}" systemctl daemon-reload
  fi
fi
[[ -e /usr/local/sbin/qa-lsm-read-helper ]] && try "${PRIV[@]}" rm -f /usr/local/sbin/qa-lsm-read-helper
[[ -e var/lsm-state-root.json ]] && try "${PRIV[@]}" rm -f var/lsm-state-root.json

# ---------------------------------------------------------------- scheduling
if [[ -x bin/qa ]]; then
  try ./bin/qa install-cron --remove
else
  echo "   (bin/qa missing: remove the $PROJECT_NAME cron block manually)"
fi

# ---------------------------------------------------------------- autostart
[[ -e "$AUTOSTART" ]] && try rm -f "$AUTOSTART"
[[ -e bin/qa-logs-terminal ]] && try rm -f bin/qa-logs-terminal

# ---------------------------------------------------------------- build
if [[ $KEEP_BUILD -eq 0 ]]; then
  try make -C src clean
  for artifact in "${BUILT[@]}"; do
    [[ -e "$artifact" ]] && try rm -f "$artifact"
  done
fi

# ---------------------------------------------------------------- data
if [[ $PURGE_DATA -eq 1 ]]; then
  for dir in "${DATA_DIRS[@]}"; do
    [[ -e "$dir" ]] && try rm -rf "$dir"
  done
fi

echo
if [[ $DRY_RUN -eq 1 ]]; then
  echo "dry run complete: nothing was removed"
elif [[ $FAILED -eq 1 ]]; then
  echo "uninstall finished with warnings: some items may remain"
  exit 1
elif [[ $PURGE_DATA -eq 1 ]]; then
  echo "uninstalled; gathered data purged"
else
  echo "uninstalled; gathered data kept"
fi
echo "next: $ROOT/install.sh"
