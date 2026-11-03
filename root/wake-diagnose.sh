#!/usr/bin/env bash
# wake-diagnose.sh — read-only diagnosis of an unexplained boot / wake event.
#
# Collects the evidence needed to attribute a boot to WoL, RTC, USB or the
# power button. Nothing is modified: no setpci writes, no ethtool -s, no
# power-state changes. Output is tee'd to an evidence directory.
#
# Usage:
#   ./wake-diagnose.sh [OUTPUT_DIR]
#   sudo ./wake-diagnose.sh            # full capture (recommended)
#
# Default OUTPUT_DIR: $ROOT/evidence/<ts>-wake
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${1:-$ROOT/evidence/$(date +%Y%m%d-%H%M%S)-wake}"
mkdir -p "$OUT" || { echo "cannot create $OUT" >&2; exit 1; }

SUDO=""
[ "$(id -u)" -ne 0 ] && SUDO="sudo -n"

sec() { echo; echo "===== $* ====="; }

{
sec "0. context"
date -Is
uname -r
uptime | sed 's/  */ /g'
$SUDO dmidecode -t 0 2>/dev/null | grep -E "Vendor|Version|Release Date|Wake-up Type"
$SUDO dmidecode -t 1 2>/dev/null | grep -iE "Manufacturer|Product|Version"

sec "0b. boot history"
journalctl --list-boots --no-pager 2>/dev/null
last -x reboot shutdown 2>/dev/null | head -20

sec "0c. firmware wake source (primary signal)"
$SUDO dmidecode -t 0 2>/dev/null | grep -i "Wake-up"
$SUDO dmidecode -t 4 2>/dev/null | grep -i "Wake-up"

sec "0d. ACPI sleep states + kernel wake lines"
journalctl -k -b 0 --no-pager 2>/dev/null | grep -iE "supports S0|ACPI: PM: Preparing|wakeup|PME#|PM: Image"

sec "0e. ACPI GPE wake map"
cat /proc/acpi/wakeup 2>/dev/null

sec "1. NIC WoL state"
command -v ethtool >/dev/null || echo "ethtool MISSING -> apt install ethtool"
for d in /sys/class/net/*; do
  n=$(basename "$d")
  [ "$n" = lo ] && continue
  [ -e "$d/device" ] || continue
  drv=$(readlink -f "$d/device/driver" 2>/dev/null | xargs -r basename)
  echo "--- $n ($drv) ---"
  echo "operstate=$(cat "$d/operstate" 2>/dev/null) carrier=$(cat "$d/carrier" 2>/dev/null)"
  echo "power/wakeup=$(cat "$d/device/power/wakeup" 2>/dev/null)"
  command -v ethtool >/dev/null && $SUDO ethtool "$n" 2>/dev/null \
    | grep -iE "Supports Wake-on|Wake-on|Link detected"
done

sec "1b. NetworkManager WoL override"
for c in $(nmcli -t -f NAME,TYPE connection show 2>/dev/null \
           | awk -F: '$2=="802-3-ethernet"{print $1}' | tr '\n' '\0' | xargs -0 -n1 echo); do
  echo "$c: $(nmcli -g 802-3-ethernet.wake-on-lan connection show "$c" 2>/dev/null)"
done

sec "2. PCI PMCSR (read-only; bit8=PME_En, bit15=PME_Status)"
for bdf in $(lspci -D 2>/dev/null | grep -iE "ethernet|network" | awk '{print $1}'); do
  echo "$bdf $(lspci -s "$bdf" 2>/dev/null | cut -d' ' -f2-)"
  $SUDO setpci -s "$bdf" CAP_PM+4.w 2>/dev/null | sed 's/^/  PMCSR=/'
done

sec "3. kernel wake counters"
for dev in /sys/bus/pci/devices/*/power; do
  d=$(basename "$(dirname "$dev")")
  [ -r "$dev/wakeup" ] || continue
  [ "$(cat "$dev/wakeup" 2>/dev/null)" = enabled ] || continue
  printf '%s enabled | count=%s aborts=%s last_ms=%s\n' "$d" \
    "$(cat "$dev/wakeup_count" 2>/dev/null)" \
    "$(cat "$dev/wakeup_abort_count" 2>/dev/null)" \
    "$(cat "$dev/wakeup_last_time_ms" 2>/dev/null)"
done

sec "3b. global wakeup_count"
cat /sys/power/wakeup_count 2>/dev/null

sec "4. RTC alarm"
cat /proc/driver/rtc 2>/dev/null
echo "wakealarm=$(cat /sys/class/rtc/rtc0/wakealarm 2>/dev/null)  (empty=unarmed)"

sec "4b. scheduled power/wake jobs"
systemctl list-timers --all --no-pager 2>/dev/null | head -30
atq 2>/dev/null || echo "atq: no at jobs (or at not installed)"
echo "--- user crontab ---"
crontab -l 2>/dev/null | grep -viE '^\s*#'
echo "--- root crontab ---"
$SUDO crontab -l 2>/dev/null | grep -viE '^\s*#'
echo "--- grep for wake/power scheduling ---"
grep -rniE "rtcwake|wakealarm|shutdown|reboot|poweroff|suspend|hibernate" \
  /etc/cron* /etc/systemd/system /etc/rc.local /usr/local/bin /usr/local/sbin 2>/dev/null \
  | grep -viE "wakeup|wake on" | head -20

sec "5. link/carrier history (previous boots)"
for b in 0 -1 -2 -3; do
  echo "--- boot $b ---"
  journalctl -b "$b" -k --no-pager 2>/dev/null \
    | grep -iE "Link is (Up|Down)|NIC Link is (Up|Down)|carrier"
done

sec "6. verdict hints"
echo "A. Wake-up Type above: 'Power Switch' => power button / front-panel line."
echo "B. WoL needs: cable carrier up in S5, Wake-on: g, PME_En set, ACPI GPE enabled."
echo "C. Any section showing 'NO-CARRIER'/'Link is Down' on all NICs excludes WoL."
echo "D. wakealarm non-empty and matching boot time => RTC wake_timers."
} 2>&1 | tee "$OUT/wake-diagnose.txt"

chmod 600 "$OUT/wake-diagnose.txt" 2>/dev/null
echo
echo "evidence written to: $OUT/wake-diagnose.txt"
