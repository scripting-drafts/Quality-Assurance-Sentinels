#!/usr/bin/env bash
# Install the QA security audit rules.  Requires root and auditd.
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
RULES="$ROOT/root/audit/qa-security.rules"
TARGET="/etc/audit/rules.d/qa-security.rules"

if [[ "${1:-}" == "--uninstall" ]]; then
  [[ $(id -u) -eq 0 ]] || { echo "Run with sudo for --uninstall" >&2; exit 1; }
  rm -f "$TARGET"
  if command -v augenrules >/dev/null 2>&1; then augenrules --load; fi
  echo "Removed $TARGET"
  exit 0
fi

[[ $(id -u) -eq 0 ]] || { echo "Run with sudo: sudo $0" >&2; exit 1; }
[[ -f "$RULES" ]] || { echo "Missing $RULES" >&2; exit 1; }
command -v auditctl >/dev/null 2>&1 || {
  echo "auditd is not installed. Install it first: sudo apt install auditd" >&2
  exit 1
}
install -D -m 0640 "$RULES" "$TARGET"
if command -v augenrules >/dev/null 2>&1; then
  augenrules --load
else
  auditctl -R "$TARGET"
fi
if command -v systemctl >/dev/null 2>&1; then
  systemctl enable --now auditd >/dev/null 2>&1 || true
fi
echo "Installed $TARGET"
echo "Verify: sudo auditctl -l | grep qa_security"
echo "The sentinel reads events with ausearch -k qa_security_exec / qa_security_priv."
