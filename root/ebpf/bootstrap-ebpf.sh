#!/usr/bin/env bash
# Install eBPF build dependencies.
#
# Root: apt installs the normal packages.
# Non-root: downloads the same Ubuntu packages and extracts them under
#           $ROOT/toolchain, so no system change and no sudo are required.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
PKGS=(clang-14 libclang-cpp14 libllvm14 libclang-common-14-dev libclang1-14 libbpf-dev)

if [[ ${EUID} -eq 0 ]]; then
  echo "installing system packages: clang llvm libbpf-dev libelf-dev zlib1g-dev bpftool"
  apt-get update -qq
  apt-get install -y clang llvm libbpf-dev libelf-dev zlib1g-dev bpftool
  echo "now run: $ROOT/root/ebpf/build.sh"
  exit 0
fi

if ! command -v apt-get >/dev/null 2>&1 || ! command -v dpkg-deb >/dev/null 2>&1; then
  echo "need apt-get and dpkg-deb for the user-local toolchain" >&2
  exit 1
fi

TC="$ROOT/toolchain"
mkdir -p "$TC/debs"
cd "$TC/debs"
echo "downloading build packages (no root): ${PKGS[*]}"
apt-get download "${PKGS[@]}"
for deb in *.deb; do
  dpkg-deb -x "$deb" "$TC"
done
rm -rf "$TC/debs"
echo "toolchain ready: $TC"
echo "now run: $ROOT/root/ebpf/build.sh"
