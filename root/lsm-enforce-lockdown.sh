#!/usr/bin/env bash
# Explicitly enable the kernel lockdown LSM. Run as root after reviewing impact.
set -Eeuo pipefail
[[ $(id -u) -eq 0 ]] || { echo "run with sudo: sudo $0 [integrity|confidentiality]" >&2; exit 1; }
mode="${1:-integrity}"
case "$mode" in
  none|integrity|confidentiality) ;;
  *) echo "mode must be none, integrity, or confidentiality" >&2; exit 2 ;;
esac
path=/sys/kernel/security/lockdown
[[ -w "$path" ]] || { echo "$path is not writable; lockdown may be fixed by firmware/kernel" >&2; exit 1; }
current="$(cat "$path")"
printf 'current: %s\n' "$current"
if [[ "$current" == *"[$mode]"* ]]; then
  echo "lockdown already selected: $mode"
  exit 0
fi
printf '%s\n' "$mode" > "$path"
after="$(cat "$path")"
printf 'after  : %s\n' "$after"
[[ "$after" == *"[$mode]"* ]] || { echo "lockdown mode was not selected" >&2; exit 1; }
echo "lockdown mode selected: $mode"
