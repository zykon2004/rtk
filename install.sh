#!/usr/bin/env sh
# rtk installer - https://github.com/zykon2004/rtk
# Builds rtk from source. Requires: git, cargo (https://rustup.rs).
# Usage: curl -fsSL https://raw.githubusercontent.com/zykon2004/rtk/refs/heads/master/install.sh | sh
#
# Override repo or ref:
#   RTK_REPO_URL=https://github.com/other/rtk.git RTK_REF=mybranch ./install.sh

set -e

REPO_URL="${RTK_REPO_URL:-https://github.com/zykon2004/rtk.git}"
BINARY_NAME="rtk"
INSTALL_DIR="${RTK_INSTALL_DIR:-$HOME/.local/bin}"
REF="${RTK_REF:-master}"

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
    if ! command -v git >/dev/null 2>&1; then
        error "git is required but not installed."
    fi
    if ! command -v cargo >/dev/null 2>&1; then
        error "cargo is required but not installed. Install Rust via https://rustup.rs"
    fi
}

build_and_install() {
    TEMP_DIR=$(mktemp -d)
    trap 'rm -rf "$TEMP_DIR"' EXIT

    info "Cloning $REPO_URL ($REF)..."
    git clone --depth 1 --branch "$REF" "$REPO_URL" "$TEMP_DIR/rtk" \
        || error "Failed to clone repository"

    info "Building release binary (this may take a few minutes)..."
    (cd "$TEMP_DIR/rtk" && cargo build --release) \
        || error "Build failed"

    mkdir -p "$INSTALL_DIR"
    mv "$TEMP_DIR/rtk/target/release/$BINARY_NAME" "$INSTALL_DIR/"
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
    info "Installing $BINARY_NAME from source..."
    check_deps
    build_and_install
    verify

    echo ""
    info "Installation complete! Run '$BINARY_NAME --help' to get started."
}

main
