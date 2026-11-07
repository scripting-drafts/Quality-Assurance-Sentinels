#!/usr/bin/env bash
# Install the QA Sentinels -> QA SIEM forwarder timer.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE=/etc/systemd/system/qa-siem-forward.service
TIMER=/etc/systemd/system/qa-siem-forward.timer

if [[ "${1:-}" == "--uninstall" ]]; then
  [[ $(id -u) -eq 0 ]] || { echo "run with sudo: sudo $0 --uninstall" >&2; exit 1; }
  systemctl disable --now qa-siem-forward.timer 2>/dev/null || true
  rm -f "$SERVICE" "$TIMER"
  systemctl daemon-reload
  echo "Removed qa-siem-forward timer"
  exit 0
fi

[[ $(id -u) -eq 0 ]] || { echo "run with sudo: sudo $0" >&2; exit 1; }
USER_NAME="${SUDO_USER:-${QA_SENTINEL_USER:-}}"
[[ -n "$USER_NAME" && "$USER_NAME" != root ]] || {
  echo "Set QA_SENTINEL_USER or run via sudo from the operator account" >&2; exit 1;
}
id -u "$USER_NAME" >/dev/null 2>&1 || { echo "no such user: $USER_NAME" >&2; exit 1; }
GROUP_NAME="$(id -gn "$USER_NAME")"

if [[ ! -e "$ROOT/config/siem.json" ]]; then
  echo "missing $ROOT/config/siem.json; copy config/siem.example.json and configure it" >&2
  exit 1
fi

cat >"$SERVICE" <<EOF
[Unit]
Description=QA Sentinels SIEM forwarder
Documentation=file://$ROOT/docs/SIEM.md
After=local-fs.target
ConditionPathExists=$ROOT/config/siem.json

[Service]
Type=oneshot
User=$USER_NAME
Group=$GROUP_NAME
SupplementaryGroups=adm systemd-journal
Environment=QA_SENTINELS_HOME=$ROOT
Environment=PYTHONUNBUFFERED=1
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
ExecStart=$ROOT/bin/qa forward --config $ROOT/config/siem.json
TimeoutStartSec=120
EOF

cat >"$TIMER" <<'EOF'
[Unit]
Description=Forward QA Sentinels events to QA SIEM every 5 minutes

[Timer]
OnBootSec=90s
OnUnitActiveSec=5min
AccuracySec=30s
Persistent=true
Unit=qa-siem-forward.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now qa-siem-forward.timer
systemctl start qa-siem-forward.service
printf 'Installed qa-siem-forward.timer for %s.\n' "$USER_NAME"
printf 'Verify: systemctl status qa-siem-forward.timer qa-siem-forward.service\n'
