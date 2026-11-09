#!/usr/bin/env bash
# Install the capability-scoped hardware-health timer.
# The unit runs as the operator, never as root.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE=/etc/systemd/system/qa-hardware.service
TIMER=/etc/systemd/system/qa-hardware.timer

if [[ "${1:-}" == "--uninstall" ]]; then
  [[ $(id -u) -eq 0 ]] || { echo "run with sudo: sudo $0 --uninstall" >&2; exit 1; }
  systemctl disable --now qa-hardware.timer 2>/dev/null || true
  rm -f "$SERVICE" "$TIMER"
  systemctl daemon-reload
  echo "Removed hardware service and timer"
  exit 0
fi

[[ $(id -u) -eq 0 ]] || { echo "run with sudo: sudo $0" >&2; exit 1; }
USER_NAME="${SUDO_USER:-${QA_SENTINEL_USER:-}}"
[[ -n "$USER_NAME" && "$USER_NAME" != root ]] || {
  echo "Set QA_SENTINEL_USER or run via sudo from the operator account" >&2; exit 1;
}
id -u "$USER_NAME" >/dev/null 2>&1 || { echo "no such user: $USER_NAME" >&2; exit 1; }
GROUP_NAME="$(id -gn "$USER_NAME")"

cat >"$SERVICE" <<EOF
[Unit]
Description=QA Sentinels hardware-health tier
Documentation=file://$ROOT/docs/HARDWARE.md
After=local-fs.target
ConditionPathExists=$ROOT/bin/qa

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
TimeoutStartSec=180
ExecStart=$ROOT/bin/qa hardware collect
EOF

cat >"$TIMER" <<'EOF'
[Unit]
Description=Run the hardware-health tier every 15 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=15min
AccuracySec=30s
Persistent=true
Unit=qa-hardware.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now qa-hardware.timer
printf 'Installed qa-hardware.timer for %s.\n' "$USER_NAME"
printf 'Verify: systemctl status qa-hardware.timer\n'
printf '        journalctl -u qa-hardware.service -n 50\n'
