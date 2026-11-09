#!/usr/bin/env bash
# Install the root-owned LSM state reader and its handoff timer.
# The helper is the only root process; the collector remains the operator.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE=/etc/systemd/system/qa-lsm-read.service
TIMER=/etc/systemd/system/qa-lsm-read.timer
HELPER=/usr/local/sbin/qa-lsm-read-helper

if [[ "${1:-}" == "--uninstall" ]]; then
  [[ $(id -u) -eq 0 ]] || { echo "run with sudo: sudo $0 --uninstall" >&2; exit 1; }
  systemctl disable --now qa-lsm-read.timer 2>/dev/null || true
  rm -f "$SERVICE" "$TIMER" "$HELPER" "$ROOT/var/lsm-state-root.json"
  systemctl daemon-reload
  echo "Removed LSM state reader, timer and handoff"
  exit 0
fi

[[ $(id -u) -eq 0 ]] || { echo "run with sudo: sudo $0" >&2; exit 1; }
USER_NAME="${SUDO_USER:-${QA_SENTINEL_USER:-}}"
[[ -n "$USER_NAME" && "$USER_NAME" != root ]] || {
  echo "Set QA_SENTINEL_USER or run via sudo from the operator account" >&2; exit 1;
}
id -u "$USER_NAME" >/dev/null 2>&1 || { echo "no such user: $USER_NAME" >&2; exit 1; }

install -o root -g root -m 0755 "$ROOT/root/lsm-read-helper.py" "$HELPER"

cat >"$SERVICE" <<EOF
[Unit]
Description=QA Sentinels root LSM state reader
Documentation=file://$ROOT/docs/LSM.md
After=local-fs.target
ConditionPathExists=$ROOT/bin/qa

[Service]
Type=oneshot
User=root
ExecStart=$HELPER --root $ROOT --user $USER_NAME
ProtectSystem=strict
ProtectHome=no
ReadWritePaths=$ROOT/var
PrivateTmp=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_SYS_ADMIN CAP_CHOWN
Nice=10
IOSchedulingClass=idle
TimeoutStartSec=60
EOF

cat >"$TIMER" <<'EOF'
[Unit]
Description=Refresh the root LSM state handoff every 5 minutes

[Timer]
OnBootSec=90s
OnUnitActiveSec=5min
AccuracySec=30s
Persistent=true
Unit=qa-lsm-read.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now qa-lsm-read.timer
systemctl start qa-lsm-read.service
printf 'Installed qa-lsm-read.timer for %s.\n' "$USER_NAME"
printf 'Verify: systemctl status qa-lsm-read.timer qa-lsm-read.service\n'
printf '        %s/bin/qa lsm check\n' "$ROOT"
