#!/usr/bin/env bash
#
# build-kernel.sh — Build an up-to-date Linux guest kernel for cloud-hypervisor
#
# Uses the ch_defconfig from cloud-hypervisor/linux as a base config, applied to
# an upstream stable kernel. This lets you stay current on security patches
# without waiting for cloud-hypervisor to cut a release.
#
# All inputs are expected locally — no network access required at build time.
# Pre-download these into .cloud-hypervisor/kernel-build/sources/:
#
#   linux-<version>.tar.xz   — from https://cdn.kernel.org/pub/linux/kernel/
#   ch_defconfig              — from cloud-hypervisor/linux arch/x86/configs/
#   hardening.config          — from cloud-hypervisor/linux arch/x86/configs/
#
# Usage:
#   bash build-kernel.sh 6.19.9           # build from local sources
#   JOBS=4 bash build-kernel.sh 6.19.9    # control parallelism
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CH_DIR="${SCRIPT_DIR}/.cloud-hypervisor"
KERNEL_DIR="${CH_DIR}/kernel"
BUILD_DIR="${CH_DIR}/kernel-build"
SOURCES_DIR="${BUILD_DIR}/sources"

JOBS="${JOBS:-$(nproc)}"

# --------------------------------------------------------------------------- #
# Resolve kernel version
# --------------------------------------------------------------------------- #
if [[ $# -lt 1 ]]; then
    echo "Usage: bash build-kernel.sh <kernel-version>"
    echo ""
    echo "Example: bash build-kernel.sh 6.19.9"
    echo ""
    echo "Place these files in ${SOURCES_DIR}/ before running:"
    echo "  linux-<version>.tar.xz   (kernel source tarball)"
    echo "  ch_defconfig             (cloud-hypervisor kernel config)"
    echo "  hardening.config         (cloud-hypervisor hardening options)"
    exit 1
fi

KERNEL_VERSION="$1"

echo "=== Cloud Hypervisor Kernel Builder ==="
echo "  Kernel version:  ${KERNEL_VERSION}"
echo "  Sources dir:     ${SOURCES_DIR}"
echo "  Build jobs:      ${JOBS}"
echo ""

# --------------------------------------------------------------------------- #
# Prerequisites check
# --------------------------------------------------------------------------- #
missing=()
for cmd in make gcc flex bison bc xz; do
    command -v "$cmd" &>/dev/null || missing+=("$cmd")
done
if ! pkg-config --exists libelf 2>/dev/null && [[ ! -f /usr/include/libelf.h ]]; then
    missing+=("libelf-dev")
fi
if ! pkg-config --exists openssl 2>/dev/null && [[ ! -f /usr/include/openssl/ssl.h ]]; then
    missing+=("libssl-dev")
fi

if [[ ${#missing[@]} -gt 0 ]]; then
    echo "ERROR: Missing build dependencies: ${missing[*]}"
    echo ""
    echo "On Debian/Ubuntu:"
    echo "  sudo apt-get install build-essential flex bison bc libelf-dev libssl-dev"
    echo ""
    echo "On Fedora/CentOS:"
    echo "  sudo dnf install gcc make flex bison bc elfutils-libelf-devel openssl-devel"
    exit 1
fi

# --------------------------------------------------------------------------- #
# Verify local sources exist
# --------------------------------------------------------------------------- #
TARBALL="${SOURCES_DIR}/linux-${KERNEL_VERSION}.tar.xz"
DEFCONFIG="${SOURCES_DIR}/ch_defconfig"
HARDENING_CFG="${SOURCES_DIR}/hardening.config"

err=0
for f in "${TARBALL}" "${DEFCONFIG}" "${HARDENING_CFG}"; do
    if [[ ! -f "$f" ]]; then
        echo "ERROR: Missing: $f" >&2
        err=1
    fi
done
if [[ $err -ne 0 ]]; then
    echo "" >&2
    echo "Download these files on a machine with internet access:" >&2
    echo "  Kernel:   https://cdn.kernel.org/pub/linux/kernel/v${KERNEL_VERSION%%.*}.x/linux-${KERNEL_VERSION}.tar.xz" >&2
    echo "  Config:   https://raw.githubusercontent.com/cloud-hypervisor/linux/ch-6.16.9/arch/x86/configs/ch_defconfig" >&2
    echo "  Harden:   https://raw.githubusercontent.com/cloud-hypervisor/linux/ch-6.16.9/arch/x86/configs/hardening.config" >&2
    echo "" >&2
    echo "Then place them in: ${SOURCES_DIR}/" >&2
    exit 1
fi

# --------------------------------------------------------------------------- #
# Extract kernel source
# --------------------------------------------------------------------------- #
SRC_DIR="${BUILD_DIR}/linux-${KERNEL_VERSION}"

if [[ -d "${SRC_DIR}" ]]; then
    echo "Kernel source already extracted at ${SRC_DIR}"
else
    echo "Extracting linux-${KERNEL_VERSION}.tar.xz ..."
    tar -xf "${TARBALL}" -C "${BUILD_DIR}"
fi

# --------------------------------------------------------------------------- #
# Apply cloud-hypervisor kernel config
# --------------------------------------------------------------------------- #
echo "Applying ch_defconfig..."
cp "${DEFCONFIG}" "${SRC_DIR}/.config"

echo "Merging hardening.config..."
while IFS= read -r line; do
    [[ "$line" =~ ^CONFIG_ ]] || continue
    key="${line%%=*}"
    sed -i "/^${key}[= ]/d" "${SRC_DIR}/.config"
    echo "$line" >> "${SRC_DIR}/.config"
done < "${HARDENING_CFG}"

# Resolve any new/missing symbols with defaults
echo "Running olddefconfig (resolving new config symbols)..."
make -C "${SRC_DIR}" olddefconfig > /dev/null 2>&1

# --------------------------------------------------------------------------- #
# Build
# --------------------------------------------------------------------------- #
echo ""
echo "Building bzImage with ${JOBS} jobs... (this takes a few minutes)"
make -C "${SRC_DIR}" -j"${JOBS}" bzImage 2>&1 | tail -5

# --------------------------------------------------------------------------- #
# Install
# --------------------------------------------------------------------------- #
BZIMAGE="${SRC_DIR}/arch/x86/boot/bzImage"
if [[ ! -f "${BZIMAGE}" ]]; then
    echo "ERROR: bzImage not found at ${BZIMAGE}" >&2
    exit 1
fi

mkdir -p "${KERNEL_DIR}"

# Back up old kernel if present
if [[ -f "${KERNEL_DIR}/bzImage" ]]; then
    BACKUP="${KERNEL_DIR}/bzImage.$(date +%Y%m%d%H%M%S).bak"
    mv "${KERNEL_DIR}/bzImage" "${BACKUP}"
    echo "Backed up previous kernel to ${BACKUP}"
fi

cp "${BZIMAGE}" "${KERNEL_DIR}/bzImage"

KERNEL_SIZE=$(du -h "${KERNEL_DIR}/bzImage" | cut -f1)
echo ""
echo "=== Done ==="
echo "  Installed: ${KERNEL_DIR}/bzImage (${KERNEL_SIZE})"
echo "  Version:   ${KERNEL_VERSION} (upstream stable + ch_defconfig)"
echo ""
echo "To clean up build artifacts:  rm -rf ${BUILD_DIR}"
