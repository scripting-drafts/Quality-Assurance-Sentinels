#!/usr/bin/env bash
# Add lockdown=integrity to the persistent GRUB kernel command line.
# --dry-run may be run as the operator; applying requires root.
set -Eeuo pipefail
GRUB=/etc/default/grub
MODE=integrity
DRY_RUN=0

usage() {
  echo "Usage: sudo $0 [--mode integrity|confidentiality] [--dry-run]" >&2
}

while (($#)); do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    --mode)
      MODE="${2:-}"
      [[ -n "$MODE" ]] || { usage; exit 2; }
      shift
      ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
  shift
done
case "$MODE" in
  integrity|confidentiality) ;;
  *) echo "mode must be integrity or confidentiality" >&2; exit 2 ;;
esac
[[ -f "$GRUB" ]] || { echo "missing $GRUB" >&2; exit 1; }
if (( ! DRY_RUN )); then
  [[ $(id -u) -eq 0 ]] || { echo "run with sudo: sudo $0 --mode $MODE" >&2; exit 1; }
fi

python3 - "$GRUB" "$MODE" "$DRY_RUN" <<'PY'
from pathlib import Path
import re
import shlex
import sys

path = Path(sys.argv[1])
mode = sys.argv[2]
dry_run = sys.argv[3] == "1"
text = path.read_text(encoding="utf-8")
arg = f"lockdown={mode}"
lines = text.splitlines()
found = False
for index, line in enumerate(lines):
    match = re.match(r'^(GRUB_CMDLINE_LINUX_DEFAULT|GRUB_CMDLINE_LINUX)="(.*)"\s*$', line)
    if not match:
        continue
    key, value = match.groups()
    tokens = shlex.split(value)
    if any(token == arg or token.startswith("lockdown=") for token in tokens):
        if arg in tokens:
            print(f"{key} already contains {arg}")
        else:
            print(f"{key} already contains a lockdown= token; refusing to duplicate")
        found = True
        break
    tokens.append(arg)
    lines[index] = f'{key}="{ " ".join(tokens) }"'
    print(f"would update {key}: {lines[index]}")
    found = True
    break
if not found:
    lines.append(f'GRUB_CMDLINE_LINUX_DEFAULT="quiet splash {arg}"')
    print(f'would append: {lines[-1]}')
if dry_run:
    print("dry-run: no file changed")
else:
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"updated {path}")
PY

if (( DRY_RUN )); then
  echo "Apply with: sudo $0 --mode $MODE"
  echo "Then rebuild GRUB and reboot; verify with: grep -o 'lockdown=[^ ]*' /proc/cmdline"
  exit 0
fi

update-grub
echo "GRUB updated. Reboot, then verify: grep -o 'lockdown=[^ ]*' /proc/cmdline"
