#!/usr/bin/env bash
# Install the capability-scoped hardware-health timer.
# The unit runs as the operator, never as root.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVICE=/etc/systemd/system/qa-hardware.service
TIMER=/etc/systemd/system/qa-hardware.timer
STORAGE_SERVICE=/etc/systemd/system/qa-hardware-storage.service
STORAGE_TIMER=/etc/systemd/system/qa-hardware-storage.timer
HELPER=/usr/local/sbin/qa-hardware-storage-probe
LSM_HELPER=/usr/local/sbin/qa-lsm-enforce-lockdown

if [[ "${1:-}" == "--uninstall" ]]; then
  [[ $(id -u) -eq 0 ]] || { echo "run with sudo: sudo $0 --uninstall" >&2; exit 1; }
  systemctl disable --now qa-hardware.timer qa-hardware-storage.timer 2>/dev/null || true
  rm -f "$SERVICE" "$TIMER" "$STORAGE_SERVICE" "$STORAGE_TIMER" "$HELPER" "$LSM_HELPER"
  systemctl daemon-reload
  echo "Removed hardware services, storage probe and timers"
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
Description=Quality Assurance Sentinels hardware-health tier
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

install -o root -g root -m 0755 "$ROOT/root/hardware-storage-probe.py" "$HELPER"
install -o root -g root -m 0755 "$ROOT/root/lsm-enforce-lockdown.sh" "$LSM_HELPER"

cat >"$STORAGE_SERVICE" <<EOF
[Unit]
Description=Quality Assurance Sentinels root SMART/NVMe probe
Documentation=file://$ROOT/docs/HARDWARE.md
After=local-fs.target

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
CapabilityBoundingSet=CAP_DAC_OVERRIDE CAP_DAC_READ_SEARCH CAP_SYS_RAWIO CAP_SYS_ADMIN CAP_CHOWN CAP_SYS_NICE
Nice=10
IOSchedulingClass=idle
TimeoutStartSec=180
EOF

cat >"$STORAGE_TIMER" <<'EOF'
[Unit]
Description=Run the root SMART/NVMe handoff probe every 10 minutes

[Timer]
OnBootSec=90s
OnUnitActiveSec=10min
AccuracySec=30s
Persistent=true
Unit=qa-hardware-storage.service

[Install]
WantedBy=timers.target
EOF

systemctl daemon-reload
systemctl enable --now qa-hardware-storage.timer
systemctl enable --now qa-hardware.timer
printf 'Installed qa-hardware.timer and qa-hardware-storage.timer for %s.\n' "$USER_NAME"
printf 'Verify: systemctl status qa-hardware.timer qa-hardware-storage.timer\n'
printf '        journalctl -u qa-hardware.service -u qa-hardware-storage.service -n 50\n'
