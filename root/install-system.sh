#!/usr/bin/env bash
# Install the sentinel as a system-wide systemd timer.
#
# It does NOT run the collector as root. It grants the operator's own account a
# narrow capability set (read any file, ptrace read, raw I/O, perfmon) plus the
# journal groups, so coredumps and hardware probes work while the database stays
# owned by the operator.
#
# Usage: sudo ./root/install-system.sh [--takeover] [--layer2-only] [--user NAME]
#   --takeover    remove the user cron block so only the system timer runs.
#   --layer2-only install only the deep-trace path/service and keep cron.
#   --user NAME   operator account for the unit (default: SUDO_USER/PKEXEC_UID/owner).
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "run with: sudo $0 [--takeover] [--layer2-only] [--user NAME]" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROJECT_NAME="QA Sentinels"
USER_NAME="${QA_SENTINEL_USER:-}"
TAKEOVER=0
LAYER2_ONLY=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --takeover) TAKEOVER=1 ;;
    --layer2-only|--phase2-only) LAYER2_ONLY=1 ;;
    --user)
      USER_NAME="${2:-}"
      [[ -n "$USER_NAME" ]] || { echo "--user needs a name" >&2; exit 2; }
      shift
      ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

if [[ -z "$USER_NAME" ]]; then
  if [[ -n "${SUDO_USER:-}" ]]; then
    USER_NAME="$SUDO_USER"
  elif [[ -n "${PKEXEC_UID:-}" ]]; then
    USER_NAME="$(id -nu "$PKEXEC_UID")"
  else
    USER_NAME="$(stat -c '%U' "$ROOT")"
  fi
fi
if [[ "$USER_NAME" == "root" ]]; then
  echo "refusing to run the sentinel as root; pass --user <operator> or set QA_SENTINEL_USER" >&2
  exit 2
fi
if ! id -u "$USER_NAME" >/dev/null 2>&1; then
  echo "no such user: $USER_NAME" >&2
  exit 2
fi
if ! runuser -u "$USER_NAME" -- test -w "$ROOT"; then
  echo "$ROOT is not writable by $USER_NAME; fix ownership before installing" >&2
  exit 2
fi
GROUP_NAME="$(id -gn "$USER_NAME")"

if [[ ! -e "$ROOT/var/cron.log" ]]; then
  install -o "$USER_NAME" -g "$GROUP_NAME" -m 0600 /dev/null "$ROOT/var/cron.log"
fi

if [[ ! -x "$ROOT/bin/qa" || ! -x "$ROOT/bin/qa_sample" ]]; then
  echo "building sampler as $USER_NAME"
  runuser -u "$USER_NAME" -- make -C "$ROOT/src" install
fi
runuser -u "$USER_NAME" -- "$ROOT/bin/qa" init >/dev/null

SERVICE=/etc/systemd/system/qa-sentinel.service
TIMER=/etc/systemd/system/qa-sentinel.timer
DEEP_SERVICE=/etc/systemd/system/qa-sentinel-deep.service
DEEP_PATH=/etc/systemd/system/qa-sentinel-deep.path

if [[ $LAYER2_ONLY -eq 0 ]]; then
cat >"$SERVICE" <<EOF
[Unit]
Description=$PROJECT_NAME layer-1 routine cycle
Documentation=file://$ROOT/README.md
After=local-fs.target

[Service]
Type=oneshot
User=$USER_NAME
Group=$GROUP_NAME
SupplementaryGroups=adm systemd-journal
Environment=QA_SENTINELS_HOME=$ROOT
Environment=PYTHONUNBUFFERED=1
StandardOutput=append:$ROOT/var/cron.log
StandardError=append:$ROOT/var/cron.log
AmbientCapabilities=CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_SYS_PTRACE CAP_SYS_RAWIO CAP_PERFMON CAP_SYS_ADMIN
CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_SYS_PTRACE CAP_SYS_RAWIO CAP_PERFMON CAP_SYS_ADMIN
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$ROOT
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
RestrictSUIDSGID=yes
UMask=0077
Nice=10
IOSchedulingClass=idle
ExecStart=/usr/bin/flock -n $ROOT/var/cycle.lock $ROOT/bin/qa cycle
TimeoutStartSec=300
EOF

cat >"$TIMER" <<EOF
[Unit]
Description=Run $PROJECT_NAME every minute
Documentation=file://$ROOT/README.md

[Timer]
OnBootSec=60
OnUnitActiveSec=60
AccuracySec=5s
Persistent=true
Unit=qa-sentinel.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now qa-sentinel.timer
if [[ -x "$ROOT/root/install-shutdown.sh" ]]; then
  "$ROOT/root/install-shutdown.sh" --redaction "${QA_CAPTURE_REDACTION:-strict}" || \
    echo "warning: shutdown listener was not installed; run sudo $ROOT/root/install-shutdown.sh --redaction ${QA_CAPTURE_REDACTION:-strict}" >&2
fi
fi

cat >"$DEEP_SERVICE" <<EOF
[Unit]
Description=$PROJECT_NAME layer-2 deep trace (tracefs + perf)
Documentation=file://$ROOT/README.md
After=local-fs.target

[Service]
Type=oneshot
User=$USER_NAME
Group=$GROUP_NAME
SupplementaryGroups=adm systemd-journal
Environment=QA_SENTINELS_HOME=$ROOT
Environment=PYTHONUNBUFFERED=1
AmbientCapabilities=CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_SYS_PTRACE CAP_SYS_RAWIO CAP_PERFMON CAP_BPF CAP_SYS_ADMIN
CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_SYS_PTRACE CAP_SYS_RAWIO CAP_PERFMON CAP_BPF CAP_SYS_ADMIN
NoNewPrivileges=yes
ProtectSystem=full
ProtectHome=read-only
ReadWritePaths=$ROOT
PrivateTmp=yes
ProtectKernelTunables=no
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
UMask=0077
Nice=10
IOSchedulingClass=idle
ExecStart=$ROOT/bin/qa deep --consume
TimeoutStartSec=900
EOF

cat >"$DEEP_PATH" <<EOF
[Unit]
Description=Trigger $PROJECT_NAME layer-2 deep trace on queued requests
Documentation=file://$ROOT/README.md

[Path]
PathExistsGlob=$ROOT/triage/core2/deep-requests/*.json
Unit=qa-sentinel-deep.service

[Install]
WantedBy=paths.target
EOF

systemctl daemon-reload
systemctl enable --now qa-sentinel-deep.path

if [[ $TAKEOVER -eq 1 ]]; then
  runuser -u "$USER_NAME" -- "$ROOT/bin/qa" install-cron --remove
fi

if [[ ! -x "$ROOT/bin/qa_ebpf" ]]; then
  echo "eBPF tracer not built; run as $USER_NAME:"
  echo "  $ROOT/root/ebpf/bootstrap-ebpf.sh && $ROOT/root/ebpf/build.sh"
fi

if [[ $LAYER2_ONLY -eq 0 ]]; then
  echo "installed qa-sentinel.timer and qa-sentinel-deep.path"
else
  echo "installed qa-sentinel-deep.path (layer 2 only; existing cron kept)"
fi
echo "  user    : $USER_NAME (not root)"
echo "  caps    : layer 1 read-only; layer 2 adds sys-admin/perfmon for tracefs"
echo "  root    : $ROOT"
if [[ $LAYER2_ONLY -eq 0 ]]; then
  systemctl --no-pager --lines=0 status qa-sentinel.timer qa-sentinel-deep.path || true
  echo "verify with: systemctl list-timers qa-sentinel.timer; $ROOT/bin/qa status"
else
  systemctl --no-pager --lines=0 status qa-sentinel-deep.path || true
  echo "verify with: systemctl status qa-sentinel-deep.path; $ROOT/bin/qa deep --list"
fi
