#!/usr/bin/env bash
# One-shot install: build the C sampler, initialise the store, install cron.
# Usage: ./install.sh [--phase2]
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PHASE2=0
for arg in "$@"; do
  case "$arg" in
    --phase2) PHASE2=1 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done
cd "$ROOT"
make -C src install
./bin/qa init
./bin/qa tick
./bin/qa install-cron
if [[ $PHASE2 -eq 1 ]]; then
  ./bin/qa deploy-phase2
else
  echo "phase 2 (deep trace): $ROOT/bin/qa deploy-phase2"
fi
echo "installed; follow with: $ROOT/bin/qa status"
