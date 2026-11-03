#!/usr/bin/env bash
# Single installer for every phase.
#
# Phase 1: build the C sampler, initialise the store, run one tick, schedule it.
# Phase 2: install the deep-trace path unit and build the eBPF tracer.
#
# Usage: ./install.sh [options]
#   --systemd       schedule phase 1 with a systemd timer instead of cron
#   --keep-cron     with --systemd, leave the user cron block in place
#   --no-phase2     skip phase 2 (deep trace + eBPF)
#   --skip-ebpf     install phase 2 but do not build the eBPF tracer
#   --user NAME     operator account for the systemd units
#   --phase2        accepted for compatibility; phase 2 is now the default
#   -h, --help      this text
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SYSTEMD=0
TAKEOVER=0
KEEP_CRON=0
PHASE2=1
SKIP_EBPF=0
USER_ARGS=()

usage() { sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --systemd)  SYSTEMD=1 ;;
    --takeover) SYSTEMD=1; TAKEOVER=1 ;;
    --keep-cron) KEEP_CRON=1 ;;
    --no-phase2) PHASE2=0 ;;
    --skip-ebpf) SKIP_EBPF=1 ;;
    --phase2) : ;;                      # legacy: phase 2 is the default now
    --user)
      [[ -n "${2:-}" ]] || { echo "--user needs a name" >&2; exit 2; }
      USER_ARGS=(--user "$2"); shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1 (try --help)" >&2; exit 2 ;;
  esac
  shift
done

cd "$ROOT"
if [[ ! -x bin/qa ]]; then
  echo "not a qa-sentinels checkout: $ROOT" >&2
  exit 1
fi

# a systemd timer plus cron would run phase 1 twice
if [[ $SYSTEMD -eq 1 && $KEEP_CRON -eq 0 ]]; then
  TAKEOVER=1
fi

echo "== phase 1: build and initialise"
make -C src install
./bin/qa init
./bin/qa tick

if [[ $PHASE2 -eq 1 ]]; then
  echo "== phase 2: deep trace"
  args=("${USER_ARGS[@]}")
  [[ $SKIP_EBPF -eq 1 ]] && args+=(--skip-ebpf)
  ./bin/qa deploy-phase2 "${args[@]}"
else
  echo "== phase 2: skipped (--no-phase2)"
fi

if [[ $SYSTEMD -eq 1 ]]; then
  echo "== phase 1: systemd timer"
  install_args=()
  [[ $TAKEOVER -eq 1 ]] && install_args+=(--takeover)
  install_args+=("${USER_ARGS[@]}")
  if [[ ${EUID} -eq 0 ]]; then
    root/install-system.sh "${install_args[@]}"
  elif command -v sudo >/dev/null 2>&1; then
    sudo root/install-system.sh "${install_args[@]}"
  else
    echo "need sudo to install the system timer; rerun as root" >&2
    exit 1
  fi
else
  echo "== phase 1: cron"
  ./bin/qa install-cron
fi

echo
echo "installed; verify with: $ROOT/bin/qa status"
