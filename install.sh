#!/usr/bin/env bash
# Universal installer for libfprint-00a2 (Synaptics 06cb:00a2 / rev 0190:0061 & 0190:006a)
# Supports Fedora/RHEL, Ubuntu/Debian, Arch Linux, and openSUSE.
# No proprietary blobs are bundled: Lenovo's official r0yfp10w.exe is downloaded
# and verified via SHA-256 locally on the user's machine at install time.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUILD_DIR="${SCRIPT_DIR}/build"
LOCAL_INSTALLER=""

usage() {
    cat <<EOF
Usage: $0 [--installer /path/to/r0yfp10w.exe]

Options:
  --installer PATH   Use a local copy of Lenovo's r0yfp10w.exe instead of downloading it.
  -h, --help         Show this help message.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --installer)
            LOCAL_INSTALLER="${2:-}"
            [[ -f "$LOCAL_INSTALLER" ]] || { echo "Error: file not found: $LOCAL_INSTALLER" >&2; exit 1; }
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1" >&2
            usage
            exit 1
            ;;
    esac
done

log() { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[WARN]\033[0m %s\n' "$*"; }
err() { printf '\033[1;31m[ERROR]\033[0m %s\n' "$*" >&2; exit 1; }

if [[ $EUID -eq 0 ]]; then
    SUDO=""
else
    command -v sudo >/dev/null 2>&1 || err "sudo is required when not running as root."
    SUDO="sudo"
fi

# Verify hardware presence (non-fatal warning if unplugged/container)
if command -v lsusb >/dev/null 2>&1; then
    if lsusb | grep -qi "06cb:00a2"; then
        log "Detected Synaptics 06cb:00a2 fingerprint sensor."
    else
        warn "USB device 06cb:00a2 not detected by lsusb. Continuing anyway..."
    fi
fi

# Detect Linux distribution family
[[ -f /etc/os-release ]] || err "Cannot detect distribution: /etc/os-release not found."
# shellcheck source=/dev/null
source /etc/os-release
DISTRO_ID="${ID:-unknown}"
DISTRO_LIKE="${ID_LIKE:-}"

DISTRO_FAMILY="unknown"
case "$DISTRO_ID" in
    fedora|rhel|centos|rocky|almalinux|nobara) DISTRO_FAMILY="fedora" ;;
    ubuntu|debian|linuxmint|pop|elementary|zorin) DISTRO_FAMILY="debian" ;;
    arch|manjaro|endeavouros|cachyos|garuda) DISTRO_FAMILY="arch" ;;
    opensuse*|suse|sles) DISTRO_FAMILY="opensuse" ;;
    *)
        if [[ "$DISTRO_LIKE" == *fedora* || "$DISTRO_LIKE" == *rhel* ]]; then
            DISTRO_FAMILY="fedora"
        elif [[ "$DISTRO_LIKE" == *debian* || "$DISTRO_LIKE" == *ubuntu* ]]; then
            DISTRO_FAMILY="debian"
        elif [[ "$DISTRO_LIKE" == *arch* ]]; then
            DISTRO_FAMILY="arch"
        elif [[ "$DISTRO_LIKE" == *suse* ]]; then
            DISTRO_FAMILY="opensuse"
        fi
        ;;
esac

log "Detected distro: ${PRETTY_NAME:-$DISTRO_ID} (family: ${DISTRO_FAMILY})"

LIBDIR="lib64"
case "$DISTRO_FAMILY" in
    fedora)
        LIBDIR="lib64"
        log "Installing build dependencies via dnf..."
        $SUDO dnf install -y \
            gcc gcc-c++ meson ninja-build innoextract python3 \
            glib2-devel libgusb-devel pixman-devel openssl-devel \
            libgudev-devel systemd-devel gobject-introspection-devel \
            fprintd fprintd-pam
        ;;
    debian)
        MULTIARCH="$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || echo "x86_64-linux-gnu")"
        LIBDIR="lib/${MULTIARCH}"
        log "Installing build dependencies via apt..."
        $SUDO apt-get update
        $SUDO apt-get install -y \
            build-essential meson ninja-build pkg-config innoextract python3 \
            libglib2.0-dev libgusb-dev libpixman-1-dev libssl-dev \
            libgudev-1.0-dev libudev-dev gobject-introspection libgirepository1.0-dev \
            fprintd libpam-fprintd
        ;;
    arch)
        LIBDIR="lib"
        log "Installing build dependencies via pacman..."
        $SUDO pacman -S --needed --noconfirm \
            base-devel meson ninja innoextract python \
            glib2 libgusb pixman openssl libgudev systemd \
            gobject-introspection fprintd
        ;;
    opensuse)
        LIBDIR="lib64"
        log "Installing build dependencies via zypper..."
        $SUDO zypper --non-interactive install \
            gcc gcc-c++ meson ninja innoextract python3 \
            glib2-devel libgusb-devel libpixman-1-0-devel libopenssl-devel \
            libgudev-1_0-devel systemd-devel gobject-introspection-devel \
            fprintd fprintd-pam
        ;;
    *)
        err "Unsupported distribution '${DISTRO_ID}'. Please install libfprint build dependencies manually and run meson/ninja."
        ;;
esac

log "Configuring and compiling libfprint-00a2 (prefix=/usr, libdir=${LIBDIR})..."
rm -rf "$BUILD_DIR"
meson setup "$BUILD_DIR" "$SCRIPT_DIR" \
    --prefix=/usr \
    --libdir="$LIBDIR" \
    --buildtype=release \
    -Ddoc=false \
    -Dgtk-examples=false \
    -Dinstalled-tests=false \
    -Dintrospection=true \
    -Dudev_rules=enabled \
    -Dudev_hwdb=enabled

ninja -C "$BUILD_DIR"

log "Installing libfprint-00a2..."
$SUDO ninja -C "$BUILD_DIR" install
$SUDO ldconfig

log "Extracting and verifying official Lenovo firmware blobs (SHA-256 checked)..."
if [[ -n "$LOCAL_INSTALLER" ]]; then
    $SUDO python3 "${SCRIPT_DIR}/scripts/validity-extract-vendor-data.py" --installer "$LOCAL_INSTALLER"
else
    $SUDO python3 "${SCRIPT_DIR}/scripts/validity-extract-vendor-data.py"
fi

log "Reloading udev rules and restarting fprintd..."
$SUDO udevadm control --reload-rules
$SUDO udevadm trigger
$SUDO systemctl restart fprintd

log "Configuring PAM and package version lock..."
case "$DISTRO_FAMILY" in
    fedora)
        if command -v authselect >/dev/null 2>&1; then
            $SUDO authselect enable-feature with-fingerprint || warn "Could not enable authselect feature automatically."
        fi
        $SUDO dnf versionlock add libfprint || warn "Could not add dnf versionlock (install python3-dnf-plugin-versionlock if needed)."
        ;;
    debian)
        warn "Please enable 'Fingerprint authentication' in the pam-auth-update dialog."
        $SUDO pam-auth-update || true
        $SUDO apt-mark hold libfprint-2-2 || warn "Could not hold libfprint-2-2."
        ;;
    arch)
        warn "On Arch Linux, add 'IgnorePkg = libfprint' to /etc/pacman.conf to prevent upgrades from overwriting this driver."
        warn "To enable PAM, add 'auth sufficient pam_fprintd.so' to the top of /etc/pam.d/sudo and /etc/pam.d/system-local-login."
        ;;
    opensuse)
        if command -v pam-config >/dev/null 2>&1; then
            $SUDO pam-config --add --fprintd || true
        fi
        $SUDO zypper addlock libfprint-2-2 || true
        ;;
esac

cat <<'EOF'

====================================================================
Installation complete!

Next steps:
  1. Verify sensor detection:
       fprintd-list "$USER"

  2. Enroll your fingerprint (first open takes ~15s for provisioning;
     15 touches are required):
       fprintd-enroll

  3. Test verification:
       fprintd-verify
       sudo -k && sudo true
====================================================================
EOF

