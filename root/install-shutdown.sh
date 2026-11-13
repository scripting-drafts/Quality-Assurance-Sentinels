#!/usr/bin/env bash
# Install/remove the shutdown-window error listener.
#
# The unit is wanted by final.target, so it starts after normal services and
# mounts are gone, captures the shutdown errors, and exits.  It is also ordered
# Before=final.target: WantedBy only adds a dependency, and without the ordering
# PID 1 can hand off to systemd-shutdown and kill the unit before it execs.
# It never runs as root during normal operation.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE=/etc/systemd/system/qa-shutdown-capture.service
REDACTION="${QA_CAPTURE_REDACTION:-strict}"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --uninstall)
      [[ $(id -u) -eq 0 ]] || { echo "run with sudo: sudo $0 --uninstall" >&2; exit 1; }
      systemctl disable --now qa-shutdown-capture.service 2>/dev/null || true
      rm -f "$SERVICE"
      systemctl daemon-reload
      echo "Removed the shutdown error listener"
      exit 0
      ;;
    --redaction)
      REDACTION="${2:-}"
      [[ -n "$REDACTION" ]] || { echo "--redaction needs strict|collapsed|metadata" >&2; exit 2; }
      shift
      ;;
    -h|--help)
      echo "usage: sudo $0 [--redaction strict|collapsed|metadata] | --uninstall"
      exit 0
      ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

case "$REDACTION" in
  strict|collapsed|metadata) ;;
  *) echo "invalid redaction profile: $REDACTION" >&2; exit 2 ;;
esac

[[ $(id -u) -eq 0 ]] || { echo "run with sudo: sudo $0" >&2; exit 1; }
USER_NAME="${QA_SENTINEL_USER:-${SUDO_USER:-$(stat -c '%U' "$ROOT")}}"
[[ -n "$USER_NAME" && "$USER_NAME" != root ]] || {
  echo "Set QA_SENTINEL_USER or run via sudo from the operator account" >&2; exit 1;
}
id -u "$USER_NAME" >/dev/null 2>&1 || { echo "no such user: $USER_NAME" >&2; exit 1; }
GROUP_NAME="$(id -gn "$USER_NAME")"

cat >"$SERVICE" <<EOF
[Unit]
Description=QA Sentinels boot and shutdown error listener
Documentation=file://$ROOT/docs/SHUTDOWN.md
DefaultDependencies=no
Before=final.target
After=umount.target systemd-journald.service
ConditionPathExists=$ROOT/bin/qa

[Service]
Type=oneshot
User=$USER_NAME
Group=$GROUP_NAME
SupplementaryGroups=adm systemd-journal
Environment=QA_SENTINELS_HOME=$ROOT
Environment=PYTHONUNBUFFERED=1
Environment=QA_CAPTURE_REDACTION=$REDACTION
ExecStart=$ROOT/bin/qa shutdown --capture --quiet
TimeoutStartSec=30
Nice=10
IOSchedulingClass=idle
UMask=0077
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=$ROOT
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
RestrictSUIDSGID=yes

[Install]
WantedBy=final.target
EOF

systemctl daemon-reload
systemctl enable qa-shutdown-capture.service
printf 'Installed qa-shutdown-capture.service for %s.\n' "$USER_NAME"
printf 'It runs at shutdown; verify after reboot with: bin/qa shutdown --list\n'
