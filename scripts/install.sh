#!/usr/bin/env bash
set -e

# AuthKit One-Command Installer
# Usage: curl -fsSL https://raw.githubusercontent.com/sirtheprogrammer/authkit/main/scripts/install.sh | bash

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}=====================================================${NC}"
echo -e "${BOLD}      Installing AuthKit — Stateless Auth Kit        ${NC}"
echo -e "${BOLD}=====================================================${NC}"

OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
ARCH="$(uname -m)"

case "$ARCH" in
  x86_64|amd64)
    TARGET_ARCH="amd64"
    ;;
  aarch64|arm64)
    TARGET_ARCH="arm64"
    ;;
  *)
    echo -e "${RED}Unsupported architecture: $ARCH${NC}"
    exit 1
    ;;
esac

BIN_DIR="/usr/local/bin"
if [ ! -w "$BIN_DIR" ]; then
  BIN_DIR="$HOME/.local/bin"
  mkdir -p "$BIN_DIR"
fi

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "$TMP_DIR"' EXIT

echo -e "Target OS:   ${BLUE}${OS}${NC}"
echo -e "Target Arch: ${BLUE}${TARGET_ARCH}${NC}"
echo -e "Install Dir: ${BLUE}${BIN_DIR}${NC}"

# Check if Go is installed to build from source or install
if command -v go >/dev/null 2>&1; then
  echo -e "Building AuthKit binary from source..."
  git clone --depth 1 https://github.com/sirtheprogrammer/authkit.git "$TMP_DIR/authkit"
  cd "$TMP_DIR/authkit"
  go build -ldflags="-s -w" -o "$BIN_DIR/authkit" ./cmd/authkit
else
  echo -e "Downloading pre-compiled binary..."
  RELEASE_URL="https://github.com/sirtheprogrammer/authkit/releases/latest/download/authkit_${OS}_${TARGET_ARCH}.tar.gz"
  curl -fsSL "$RELEASE_URL" -o "$TMP_DIR/authkit.tar.gz"
  tar -xzf "$TMP_DIR/authkit.tar.gz" -C "$BIN_DIR" authkit
  chmod +x "$BIN_DIR/authkit"
fi

chmod +x "$BIN_DIR/authkit"

echo -e "\n${GREEN}[OK] AuthKit installed successfully at ${BIN_DIR}/authkit${NC}\n"
echo -e "To get started:"
echo -e "  1. Initialize configuration:  ${BOLD}authkit init${NC}"
echo -e "  2. Start AuthKit service:     ${BOLD}authkit serve${NC}"
echo -e "  3. Open documentation:        ${BOLD}http://localhost:8080/docs.html${NC}"
echo -e "  4. Open admin console:        ${BOLD}http://localhost:8080/admin.html${NC}"
echo
