#!/usr/bin/env bash
# Single installer for Quality Assurance Sentinels.
#
# Two layers can be added independently:
#   layer 1  collection: build the sampler, initialise the store,
#                      run one cycle, schedule it (cron or systemd timer) and
#                      install the root pstore export unit
#   layer 2  deep diagnostics: eBPF tracer and the systemd path unit
#                      that consumes queued deep-trace requests
#
# Run without arguments for an interactive install.
#
# Usage: ./install.sh [options]
#   --layer1 / --no-layer1  add / skip layer 1 (optional)
#   --layer2 / --no-layer2  add / skip layer 2
#   --systemd               schedule layer 1 with a systemd timer (needs sudo)
#   --keep-cron             with --systemd, leave the existing user cron block
#   --skip-ebpf             deploy layer 2 without building the eBPF tracer
#   --user NAME             operator account for the systemd and deep units
#   --yes                   install the defaults without prompting
#   --dry-run               print the plan and commands, change nothing
#   --check                 report schedulers and leftovers, change nothing
#   --phase2 / --no-phase2  legacy aliases for --layer2 / --no-layer2
#   -h, --help              this text
set -euo pipefail

# The installer lives in the checkout, so its own directory is the root. The
# old /.. suffix targeted the checkout's parent and broke every relative path.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_NAME="Quality Assurance Sentinels"

LAYER1=""
LAYER2=""
SCHEDULE=""
KEEP_CRON=0
SKIP_EBPF=0
ASSUME_YES=0
DRY_RUN=0
CHECK=0
USER_ARGS=()

usage() { sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; }

die() { echo "$*" >&2; exit 2; }

audit_install() {
  local issues=0 found=0
  local autostart="${XDG_CONFIG_HOME:-$HOME/.config}/autostart/qa-sentinels-logs.desktop"
  local cron_text="" has_cron=0

  echo "$PROJECT_NAME installation check"
  echo "  root: $ROOT"
  echo
  echo "schedulers"

  if command -v crontab >/dev/null 2>&1; then
    cron_text="$(crontab -l 2>/dev/null || true)"
  fi
  if [[ "$cron_text" == *">>> qa-sentinels >>>"* ]]; then
    has_cron=1
    if [[ "$cron_text" == *"bin/qa tick"* ]]; then
      echo "  cron    : block present, still calls 'qa tick'"
      echo "  [warn] stale cron block; run ./bin/qa install-cron"
      issues=$((issues + 1))
    else
      echo "  cron    : block present, calls 'qa cycle'"
    fi
  else
    echo "  cron    : no block"
  fi

  if [[ -e /etc/systemd/system/qa-sentinel.timer ]]; then
    echo "  systemd : qa-sentinel.timer installed"
    if [[ $has_cron -eq 1 ]]; then
      echo "  [warn] both schedulers are installed; keep one"
      issues=$((issues + 1))
    fi
  else
    echo "  systemd : no qa-sentinel.timer"
  fi

  if [[ -e /etc/systemd/system/qa-pstore-export.service ]]; then
    echo "  pstore  : qa-pstore-export.service installed"
  else
    echo "  pstore  : no export unit (manual: sudo root/pstore-export.sh --refresh)"
  fi

  echo
  echo "layer 2"
  ./bin/qa deploy-layer2 --check 2>&1 | sed 's/^/  /' || true

  echo
  echo "leftovers"
  note() { echo "  [$1] $2"; found=$((found + 1)); }

  if [[ -d tickets/in-standby ]]; then
    note warn "tickets/in-standby/ is the old bucket name; move it to tickets/standby/"
  fi
  if [[ -d tickets/raised ]]; then
    local legacy
    legacy="$(find tickets/raised -mindepth 1 -maxdepth 1 -type d 2>/dev/null | wc -l | tr -d ' ')"
    if [[ "$legacy" -gt 0 ]]; then
      note info "tickets/raised/ holds $legacy legacy ticket(s); the current layout does not use it"
    fi
  fi
  if [[ -e src/qa_sample ]]; then
    note info "src/qa_sample is a duplicate build copy of bin/qa_sample"
  fi
  local pycache
  pycache="$(find . -type d -name __pycache__ -not -path './.git/*' 2>/dev/null | wc -l | tr -d ' ')"
  if [[ "$pycache" -gt 0 ]]; then
    note info "$pycache __pycache__ directory/directories"
  fi
  if [[ -e bin/qa-logs-terminal && ! -e "$autostart" ]]; then
    note info "bin/qa-logs-terminal exists without its autostart entry"
  fi
  local lock
  for lock in var/tick.lock var/correlate.lock var/raise.lock var/crosscheck.lock; do
    if [[ -e "$lock" ]]; then
      note info "$lock is a pre-cycle lock file"
    fi
  done

  echo
  if [[ $issues -eq 0 && $found -eq 0 ]]; then
    echo "no leftovers"
    return 0
  fi
  echo "$((issues + found)) leftover item(s); nothing was changed"
  return 1
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --layer1)     LAYER1=1 ;;
    --no-layer1)  LAYER1=0 ;;
    --layer2|--phase2)    LAYER2=1 ;;
    --no-layer2|--no-phase2) LAYER2=0 ;;
    --systemd)    SCHEDULE=systemd ;;
    --keep-cron)  KEEP_CRON=1 ;;
    --skip-ebpf)  SKIP_EBPF=1 ;;
    --yes|-y)     ASSUME_YES=1 ;;
    --dry-run)    DRY_RUN=1 ;;
    --check|--reconcile) CHECK=1 ;;
    --user)
      [[ -n "${2:-}" ]] || die "--user needs a name"
      USER_ARGS=(--user "$2")
      shift
      ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option: $1 (try --help)" ;;
  esac
  shift
done

cd "$ROOT"
[[ -x bin/qa ]] || die "not a $PROJECT_NAME checkout: $ROOT"

if [[ $CHECK -eq 1 ]]; then
  if audit_install; then exit 0; else exit 1; fi
fi

if [[ $ASSUME_YES -eq 0 && ( -z "$LAYER1" || -z "$LAYER2" ) && ! -t 0 ]]; then
  die "no terminal to prompt on; pass --layer1/--no-layer1 and --layer2/--no-layer2, or --yes"
fi

# ---------------------------------------------------------------- questions
ask() {
  # ask <question> <default y|n>; true when the answer is yes
  local question="$1" default="$2" reply
  if [[ $ASSUME_YES -eq 1 ]]; then
    [[ "$default" == "y" ]]
    return
  fi
  local hint="y/N"
  [[ "$default" == "y" ]] && hint="Y/n"
  read -r -p "$question [$hint] " reply || reply=""
  reply="${reply:-$default}"
  [[ "$reply" =~ ^[Yy] ]]
}

echo "$PROJECT_NAME installer"
echo "  root: $ROOT"
echo

if [[ -z "$LAYER1" ]]; then
  if ask "Add layer 1 (collection and scheduling)?" y; then
    LAYER1=1
  else
    LAYER1=0
  fi
fi

if [[ $LAYER1 -eq 1 && -z "$SCHEDULE" ]]; then
  if ask "Schedule layer 1 with a systemd timer instead of user cron?" n; then
    SCHEDULE=systemd
  else
    SCHEDULE=cron
  fi
fi

if [[ -z "$LAYER2" ]]; then
  if ask "Add layer 2 (deep trace and eBPF)?" y; then
    LAYER2=1
  else
    LAYER2=0
  fi
fi

if [[ $LAYER1 -eq 0 && $LAYER2 -eq 0 ]]; then
  die "nothing selected: add layer 1, layer 2, or both"
fi
if [[ $LAYER1 -eq 0 && "$SCHEDULE" == "systemd" ]]; then
  die "--systemd only applies to layer 1, which is disabled"
fi

# ---------------------------------------------------------------- plan
if [[ $LAYER1 -eq 1 ]]; then
  if [[ "$SCHEDULE" == "systemd" ]]; then
    layer1_plan="build sampler, init store, first cycle, systemd timer, pstore export unit"
  else
    layer1_plan="build sampler, init store, first cycle, user cron, pstore export unit"
  fi
else
  layer1_plan="skipped"
fi
if [[ $LAYER2 -eq 1 ]]; then
  layer2_plan="deep-trace path unit"
  [[ $SKIP_EBPF -eq 1 ]] && layer2_plan+=", eBPF build skipped" || layer2_plan+=", eBPF tracer"
else
  layer2_plan="skipped"
fi

echo
echo "plan"
echo "  layer 1: $layer1_plan"
echo "  layer 2: $layer2_plan"
echo

if [[ $ASSUME_YES -eq 0 && $DRY_RUN -eq 0 ]]; then
  ask "Proceed?" y || { echo "aborted"; exit 1; }
fi

run() {
  printf '   $ %s\n' "$*"
  [[ $DRY_RUN -eq 1 ]] || "$@"
}

pstore_unit() {
  cat <<EOF
[Unit]
Description=Export $PROJECT_NAME pstore panic summaries
Documentation=file://$ROOT/root/PSTORE.md
After=systemd-pstore.service local-fs.target systemd-journald.service
Wants=systemd-pstore.service
ConditionPathIsDirectory=/var/lib/systemd/pstore

[Service]
Type=oneshot
ExecStart=$ROOT/root/pstore-export.sh --refresh
TimeoutStartSec=300
Nice=10

[Install]
WantedBy=multi-user.target
EOF
}

install_pstore_unit() {
  local unit=/etc/systemd/system/qa-pstore-export.service
  if ! command -v systemctl >/dev/null 2>&1; then
    echo "   ! systemctl missing; pstore export unit not installed" >&2
    return 0
  fi
  if [[ $DRY_RUN -eq 1 ]]; then
    echo "   $ write pstore unit: $unit"
    echo "   $ systemctl daemon-reload"
    echo "   $ systemctl enable --now qa-pstore-export.service"
    return 0
  fi
  if [[ ${EUID} -eq 0 ]]; then
    pstore_unit >"$unit"
    systemctl daemon-reload
    systemctl enable --now qa-pstore-export.service
    echo "   installed qa-pstore-export.service"
  elif command -v sudo >/dev/null 2>&1 && { sudo -n true 2>/dev/null || [[ -t 0 ]]; }; then
    pstore_unit | sudo tee "$unit" >/dev/null
    sudo systemctl daemon-reload
    sudo systemctl enable --now qa-pstore-export.service
    echo "   installed qa-pstore-export.service"
  else
    echo "   ! pstore export unit not installed (sudo required)" >&2
    echo "     rerun with sudo or install $unit manually" >&2
  fi
}

# ---------------------------------------------------------------- layer 1
if [[ $LAYER1 -eq 1 ]]; then
  echo "== layer 1: collection"
  run make -C src install
  run ./bin/qa init
  run ./bin/qa cycle
fi

# ---------------------------------------------------------------- layer 2
if [[ $LAYER2 -eq 1 ]]; then
  echo "== layer 2: deep trace"
  deep_args=("${USER_ARGS[@]}")
  [[ $SKIP_EBPF -eq 1 ]] && deep_args+=(--skip-ebpf)
  run ./bin/qa deploy-layer2 "${deep_args[@]}"
else
  echo "== layer 2: skipped"
fi

# ---------------------------------------------------------------- scheduling
if [[ $LAYER1 -eq 1 && "$SCHEDULE" == "systemd" ]]; then
  echo "== layer 1: systemd timer"
  install_args=("${USER_ARGS[@]}")
  [[ $KEEP_CRON -eq 0 ]] && install_args+=(--takeover)
  if [[ ${EUID} -eq 0 ]]; then
    run root/install-system.sh "${install_args[@]}"
  elif command -v sudo >/dev/null 2>&1 || [[ $DRY_RUN -eq 1 ]]; then
    run sudo root/install-system.sh "${install_args[@]}"
  else
    die "need sudo to install the system timer; rerun as root"
  fi
elif [[ $LAYER1 -eq 1 ]]; then
  echo "== layer 1: cron"
  if [[ -e /etc/systemd/system/qa-sentinel.timer ]] && command -v systemctl >/dev/null 2>&1; then
    echo "   leftover systemd timer found; disabling it so only cron schedules"
    if [[ ${EUID} -eq 0 ]]; then
      run systemctl disable --now qa-sentinel.timer
    elif command -v sudo >/dev/null 2>&1 || [[ $DRY_RUN -eq 1 ]]; then
      run sudo systemctl disable --now qa-sentinel.timer
    else
      echo "   ! cannot disable qa-sentinel.timer without sudo" >&2
      echo "     run: sudo systemctl disable --now qa-sentinel.timer" >&2
    fi
  fi
  run ./bin/qa install-cron
else
  echo "== layer 1 skipped: nothing schedules the one-minute cycle"
  echo "   run $ROOT/bin/qa cycle manually, or rerun ./install.sh --layer1"
fi

if [[ $LAYER1 -eq 1 ]]; then
  echo "== pstore: root export unit"
  install_pstore_unit
fi

echo
if [[ $DRY_RUN -eq 1 ]]; then
  echo "dry run complete: the commands above were not executed"
else
  echo "installed"
fi
echo "  layer 1: $([[ $LAYER1 -eq 1 ]] && echo yes || echo no)"
echo "  layer 2: $([[ $LAYER2 -eq 1 ]] && echo yes || echo no)"
echo "verify with: $ROOT/bin/qa status"
