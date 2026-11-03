#!/usr/bin/env bash
# Live, self-refreshing sentinel dashboard.
# Sections (state, findings, ticket pipeline, recent activity) are re-queried
# and redrawn every 1.7-2.0 s (randomised; QA_LIVE_MIN_S / QA_LIVE_MAX_S).
# Ctrl-C stops it.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$ROOT/bin/qa" logs --live "$@"
