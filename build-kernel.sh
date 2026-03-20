#!/usr/bin/env bash
#
# build-kernel.sh — Build an up-to-date Linux guest kernel for cloud-hypervisor
#
# Uses the ch_defconfig from cloud-hypervisor/linux as a base config, applied to
# the latest upstream stable kernel from kernel.org. This lets you stay current
# on security patches without waiting for cloud-hypervisor to cut a release.
#
# Usage:
#   bash build-kernel.sh                  # auto-detect latest stable kernel
#   bash build-kernel.sh 6.19.9           # build a specific version
#   JOBS=4 bash build-kernel.sh           # control parallelism
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CH_DIR="${SCRIPT_DIR}/.cloud-hypervisor"
KERNEL_DIR="${CH_DIR}/kernel"
BUILD_DIR="${CH_DIR}/kernel-build"

# cloud-hypervisor/linux branch to pull defconfig from (update when they rebase)
CH_LINUX_BRANCH="ch-6.16.9"
CH_LINUX_RAW="https://raw.githubusercontent.com/cloud-hypervisor/linux/${CH_LINUX_BRANCH}"

JOBS="${JOBS:-$(nproc)}"

# --------------------------------------------------------------------------- #
# Resolve kernel version
# --------------------------------------------------------------------------- #
resolve_latest_stable() {
    # kernel.org exposes a JSON endpoint with all releases
    local latest
    latest=$(curl -fsSL https://www.kernel.org/releases.json \
        | grep -Po '"version"\s*:\s*"\K[0-9]+\.[0-9]+\.[0-9]+' \
        | head -1)
    if [[ -z "$latest" ]]; then
        echo "ERROR: Could not determine latest stable kernel version." >&2
        exit 1
    fi
    echo "$latest"
}

if [[ $# -ge 1 ]]; then
    KERNEL_VERSION="$1"
else
    echo "Querying kernel.org for latest stable version..."
    KERNEL_VERSION=$(resolve_latest_stable)
fi

MAJOR_VERSION="${KERNEL_VERSION%%.*}"
TARBALL_URL="https://cdn.kernel.org/pub/linux/kernel/v${MAJOR_VERSION}.x/linux-${KERNEL_VERSION}.tar.xz"

echo "=== Cloud Hypervisor Kernel Builder ==="
echo "  Kernel version:  ${KERNEL_VERSION}"
echo "  CH defconfig:    ${CH_LINUX_BRANCH}"
echo "  Build jobs:      ${JOBS}"
echo ""

# --------------------------------------------------------------------------- #
# Prerequisites check
# --------------------------------------------------------------------------- #
missing=()
for cmd in make gcc flex bison bc curl xz; do
    command -v "$cmd" &>/dev/null || missing+=("$cmd")
done
# Check for libelf headers (needed for CONFIG_OBJTOOL)
if ! pkg-config --exists libelf 2>/dev/null && [[ ! -f /usr/include/libelf.h ]]; then
    missing+=("libelf-dev")
fi
# Check for libssl headers (needed for CONFIG_MODULE_SIG / cert gen)
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
# Download & extract kernel source
# --------------------------------------------------------------------------- #
mkdir -p "${BUILD_DIR}"
SRC_DIR="${BUILD_DIR}/linux-${KERNEL_VERSION}"

if [[ -d "${SRC_DIR}" ]]; then
    echo "Kernel source already extracted at ${SRC_DIR}"
else
    TARBALL="${BUILD_DIR}/linux-${KERNEL_VERSION}.tar.xz"
    if [[ -f "${TARBALL}" ]]; then
        echo "Tarball already downloaded."
    else
        echo "Downloading linux-${KERNEL_VERSION}.tar.xz ..."
        curl -fSL -o "${TARBALL}" "${TARBALL_URL}"
    fi
    echo "Extracting..."
    tar -xf "${TARBALL}" -C "${BUILD_DIR}"
    rm -f "${TARBALL}"
fi

# --------------------------------------------------------------------------- #
# Fetch cloud-hypervisor kernel config
# --------------------------------------------------------------------------- #
echo "Fetching ch_defconfig from cloud-hypervisor/linux (branch: ${CH_LINUX_BRANCH})..."
curl -fsSL -o "${SRC_DIR}/.config" \
    "${CH_LINUX_RAW}/arch/x86/configs/ch_defconfig"

echo "Fetching hardening.config..."
HARDENING=$(curl -fsSL "${CH_LINUX_RAW}/arch/x86/configs/hardening.config")

# Merge hardening options into .config
while IFS= read -r line; do
    [[ "$line" =~ ^CONFIG_ ]] || continue
    key="${line%%=*}"
    # Remove any existing line for this key, then append the hardening value
    sed -i "/^${key}[= ]/d" "${SRC_DIR}/.config"
    echo "$line" >> "${SRC_DIR}/.config"
done <<< "$HARDENING"

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
