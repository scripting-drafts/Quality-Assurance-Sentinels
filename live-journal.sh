#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
exec ./bin/qa logs --all-layers --follow
