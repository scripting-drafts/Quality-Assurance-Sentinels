#!/usr/bin/env bash
# Optional root-only evidence pass. Run manually with sudo. Read-only probes;
# it changes no sysctl, kernel lockdown, module or permission state.
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
  echo "run with: sudo $0" >&2
  exit 1
fi

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="${ROOT}/var/root-evidence/$(date -u +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"
chmod 700 "$OUT"

have() { command -v "$1" >/dev/null 2>&1; }

{
  echo "# dmidecode — firmware and memory topology"
  if have dmidecode; then
    dmidecode -t bios -t baseboard -t memory 2>/dev/null || true
  else
    echo "dmidecode not installed"
  fi
} >"$OUT/dmi.txt"

{
  echo "# NVMe SMART"
  for dev in /dev/nvme*n1; do
    [[ -e "$dev" ]] || continue
    if have smartctl; then
      smartctl -a "$dev" 2>&1 || true
    else
      echo "smartctl not installed"
    fi
  done
} >"$OUT/storage.txt"

{
  echo "# PCI topology and link state"
  if have lspci; then lspci -vv 2>&1 || true; else echo "lspci not installed"; fi
} >"$OUT/pci.txt"

{
  echo "# CPU frequency / governor"
  if have cpupower; then cpupower frequency-info 2>&1 || true; else echo "cpupower not installed"; fi
  echo
  echo "# Per-CPU MSR-visible limits (read-only where available)"
  for c in /sys/devices/system/cpu/cpu[0-9]*; do
    [[ -d "$c" ]] || continue
    echo "== $(basename "$c") =="
    cat "$c/topology/core_id" "$c/topology/thread_siblings_list" 2>/dev/null || true
    cat "$c/cpufreq/scaling_cur_freq" 2>/dev/null || true
  done
} >"$OUT/cpu.txt"

{
  echo "# Kernel ring buffer (current boot)"
  dmesg -T 2>&1 || true
} >"$OUT/dmesg.txt"

{
  echo "# MCE / EDAC counters"
  if have ras-mc-ctl; then ras-mc-ctl --errors 2>&1 || true; else echo "ras-mc-ctl not installed"; fi
  grep -H . /sys/devices/system/edac/mc/mc*/ce_count 2>/dev/null || true
  grep -H . /sys/devices/system/edac/mc/mc*/ue_count 2>/dev/null || true
} >"$OUT/mce-edac.txt"

( cd "$OUT" && sha256sum -- * >SHA256SUMS )
chmod 600 "$OUT"/*
echo "root evidence written to: $OUT"
echo "review before attaching; this directory is intentionally not auto-bundled."
