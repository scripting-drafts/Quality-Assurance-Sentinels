#!/usr/bin/env bash
# Export panic lines from root-only EFI pstore archives.
#
# systemd-pstore moves /sys/fs/pstore to /var/lib/systemd/pstore/<epoch/10>
# during the next boot. Those files are root-only, so the unprivileged sentinel
# cannot read them. This script writes only the panic/oops lines to
# var/pstore/<dir>/summary.txt with the repository owner's uid/gid and mode 0644.
#
# install.sh installs qa-pstore-export.service, which runs this after
# systemd-pstore at boot. The same export can be run manually:
#   sudo root/pstore-export.sh --refresh
#
# --refresh re-scans recorded boots after the export, so a boot previously
# marked archive:root-only is upgraded to archive:panic.

set -euo pipefail
umask 077

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${QA_PSTORE_ARCHIVE_DIR:-/var/lib/systemd/pstore}"
DST="${QA_PSTORE_EXPORT_DIR:-$ROOT/var/pstore}"
REFRESH=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --refresh) REFRESH=1 ;;
        -h|--help)
            sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
            exit 0
            ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done

if [ "$(id -u)" -ne 0 ]; then
    echo "pstore-export: must run as root" >&2
    exit 1
fi

OWNER="$(stat -c '%u:%g' "$ROOT")"
OWNER_NAME="$(stat -c '%U' "$ROOT")"
PATTERN='Kernel panic|Oops:|BUG: unable|general protection fault|stack-protector|Watchdog detected|hard LOCKUP|soft lockup'

mkdir -p "$DST"
chown "$OWNER" "$DST"
chmod 0700 "$DST"

tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

for dir in "$SRC"/*; do
    [ -d "$dir" ] || continue
    name="$(basename "$dir")"
    : > "$tmp"

    # Prefer the decoded dmesg.txt; fall back to the raw EFI records.
    if [ -f "$dir/dmesg.txt" ]; then
        grep -aE "$PATTERN" "$dir/dmesg.txt" >> "$tmp" || true
    else
        for part in "$dir"/dmesg-*; do
            [ -f "$part" ] || continue
            grep -aE "$PATTERN" "$part" >> "$tmp" || true
        done
    fi

    [ -s "$tmp" ] || continue

    mkdir -p "$DST/$name"
    chown "$OWNER" "$DST/$name"
    chmod 0700 "$DST/$name"
    install -m 0600 -o "${OWNER%%:*}" -g "${OWNER#*:}" "$tmp" "$DST/$name/summary.txt"
done

if [ "$REFRESH" -eq 1 ] && [ -x "$ROOT/bin/qa" ]; then
    OWNER_HOME="$(getent passwd "$OWNER_NAME" | cut -d: -f6)"
    if command -v runuser >/dev/null 2>&1; then
        if ! runuser -u "$OWNER_NAME" -- env HOME="$OWNER_HOME" \
            "$ROOT/bin/qa" boots --refresh; then
            echo "pstore-export: export done, but boot refresh failed" >&2
        fi
    else
        echo "pstore-export: run as $OWNER_NAME: $ROOT/bin/qa boots --refresh" >&2
    fi
fi
