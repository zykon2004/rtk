#!/usr/bin/env sh
# rtk installer - https://github.com/zykon2004/rtk
# Builds rtk from the LOCAL checkout (no network fetch, no git clone).
# Requires: cargo (https://rustup.rs).
# Usage: ./install.sh
#
# Override install dir:
#   RTK_INSTALL_DIR=/usr/local/bin ./install.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BINARY_NAME="rtk"
INSTALL_DIR="${RTK_INSTALL_DIR:-$HOME/.local/bin}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() {
    printf "${GREEN}[INFO]${NC} %s\n" "$1"
}

warn() {
    printf "${YELLOW}[WARN]${NC} %s\n" "$1"
}

error() {
    printf "${RED}[ERROR]${NC} %s\n" "$1"
    exit 1
}

check_deps() {
    if ! command -v cargo >/dev/null 2>&1; then
        error "cargo is required but not installed. Install Rust via https://rustup.rs"
    fi
    if [ ! -f "$SCRIPT_DIR/Cargo.toml" ]; then
        error "Cargo.toml not found in $SCRIPT_DIR. Run install.sh from the repo root."
    fi
    if [ ! -f "$SCRIPT_DIR/Cargo.lock" ]; then
        error "Cargo.lock missing. Refusing to build without a pinned lockfile."
    fi
}

build_and_install() {
    info "Building release binary from $SCRIPT_DIR (this may take a few minutes)..."
    (cd "$SCRIPT_DIR" && cargo build --release --locked) \
        || error "Build failed"

    mkdir -p "$INSTALL_DIR"
    cp "$SCRIPT_DIR/target/release/$BINARY_NAME" "$INSTALL_DIR/"
    chmod +x "$INSTALL_DIR/$BINARY_NAME"

    info "Installed $BINARY_NAME to $INSTALL_DIR/$BINARY_NAME"
}

verify() {
    if command -v "$BINARY_NAME" >/dev/null 2>&1; then
        info "Verification: $($BINARY_NAME --version)"
    else
        warn "Binary installed but not in PATH. Add to your shell profile:"
        warn "  export PATH=\"$INSTALL_DIR:\$PATH\""
    fi
}

main() {
    info "Installing $BINARY_NAME from local checkout..."
    check_deps
    build_and_install
    verify

    echo ""
    info "Installation complete! Run '$BINARY_NAME --help' to get started."
}

main
