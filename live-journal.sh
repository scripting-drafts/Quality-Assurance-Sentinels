#!/usr/bin/env bash
# Live, self-refreshing sentinel dashboard.
# Sections (state, findings, ticket pipeline, recent activity) are re-queried
# and redrawn every QA_LIVE_INTERVAL seconds; Ctrl-C stops it.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "$ROOT/bin/qa" logs --live --interval "${QA_LIVE_INTERVAL:-5}" "$@"
