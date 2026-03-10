#!/usr/bin/env bash
set -euo pipefail

REPO="JonathanInTheClouds/leakcheck"
BINARY="leakcheck"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
RESET='\033[0m'

info()    { echo -e "${CYAN}${BOLD}==>${RESET} $*"; }
success() { echo -e "${GREEN}${BOLD}✓${RESET} $*"; }
warn()    { echo -e "${YELLOW}${BOLD}!${RESET} $*"; }
error()   { echo -e "${RED}${BOLD}✗${RESET} $*" >&2; exit 1; }

detect_os() {
  case "$(uname -s)" in
    Linux*)  echo "linux" ;;
    Darwin*) echo "darwin" ;;
    *)       error "Unsupported OS: $(uname -s)" ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64)  echo "amd64" ;;
    arm64|aarch64) echo "arm64" ;;
    *)             error "Unsupported architecture: $(uname -m)" ;;
  esac
}

detect_install_dir() {
  if [[ -w "/usr/local/bin" ]]; then
    echo "/usr/local/bin"
  elif [[ -n "${HOME:-}" ]]; then
    mkdir -p "$HOME/.local/bin"
    echo "$HOME/.local/bin"
  else
    error "Could not find a writable install directory."
  fi
}

fetch_latest_version() {
  curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | grep '"tag_name"' \
    | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/'
}

main() {
  echo ""
  echo -e "${BOLD}  leakcheck installer${RESET}"
  echo -e "  Scan git history for leaked secrets"
  echo ""

  OS=$(detect_os)
  ARCH=$(detect_arch)
  INSTALL_DIR=$(detect_install_dir)

  info "Detected platform: ${OS}/${ARCH}"
  info "Fetching latest release..."
  VERSION=$(fetch_latest_version)
  info "Latest version: ${VERSION}"

  BINARY_NAME="${BINARY}-${OS}-${ARCH}"
  BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"

  TMP_DIR=$(mktemp -d)
  trap 'rm -rf "$TMP_DIR"' EXIT

  info "Downloading ${BINARY_NAME}..."
  curl -fsSL --progress-bar "${BASE_URL}/${BINARY_NAME}" -o "${TMP_DIR}/${BINARY_NAME}"

  chmod +x "${TMP_DIR}/${BINARY_NAME}"

  if [[ -w "$INSTALL_DIR" ]]; then
    mv "${TMP_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY}"
  else
    warn "Need sudo to install to ${INSTALL_DIR}"
    sudo mv "${TMP_DIR}/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY}"
  fi

  echo ""
  success "leakcheck ${VERSION} installed!"
  echo ""
  echo -e "  ${CYAN}${BOLD}leakcheck scan${RESET}           — scan full git history"
  echo -e "  ${CYAN}${BOLD}leakcheck scan --staged${RESET}   — scan staged files only"
  echo -e "  ${CYAN}${BOLD}leakcheck watch${RESET}           — install as pre-commit hook"
  echo ""
}

main "$@"
