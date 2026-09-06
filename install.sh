#!/usr/bin/env sh
#
# Install `udc` (universal-devops-converter).
#
# Detects the OS and architecture, resolves a release, downloads the matching
# archive, verifies its SHA-256 checksum and installs the binary.
#
#   curl -fsSL https://raw.githubusercontent.com/pismy/universal-devops-converter/main/install.sh | sh
#   curl -fsSL .../install.sh | sh -s -- --version v1.2.3 --install-dir ~/.local/bin
#
# POSIX sh on purpose: this has to run inside minimal CI images that ship no
# bash.

set -eu

REPO="pismy/universal-devops-converter"
BIN="udc"

usage() {
  cat <<USAGE
Install ${BIN} from the ${REPO} GitHub releases.

Usage: install.sh [options]

Options:
  --version <TAG>      Release to install (e.g. v1.2.3). Default: latest
  --install-dir <DIR>  Where to install the binary.
                       Default: /usr/local/bin when writable, else ~/.local/bin
  --no-verify          Skip checksum verification (not recommended)
  -h, --help           Show this help

Environment:
  UDC_VERSION, UDC_INSTALL_DIR   Same as the matching options.
  GITHUB_TOKEN                   Used for the release API call, to avoid the
                                 unauthenticated rate limit in CI.
USAGE
}

log() { printf '%s\n' "$*" >&2; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

VERIFY=1
VERSION="${UDC_VERSION:-latest}"
INSTALL_DIR="${UDC_INSTALL_DIR:-}"

while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
    --install-dir) INSTALL_DIR="${2:?--install-dir needs a value}"; shift 2 ;;
    --no-verify) VERIFY=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown option '$1' (see --help)" ;;
  esac
done

# --- platform ---------------------------------------------------------------

detect_os() {
  os="$(uname -s)"
  case "$os" in
    Linux) echo linux ;;
    Darwin) echo darwin ;;
    MINGW*|MSYS*|CYGWIN*) echo windows ;;
    *) die "unsupported operating system '$os'" ;;
  esac
}

detect_arch() {
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64) echo amd64 ;;
    arm64|aarch64) echo arm64 ;;
    *) die "unsupported architecture '$arch'" ;;
  esac
}

OS="$(detect_os)"
ARCH="$(detect_arch)"
ASSET="${BIN}-${OS}-${ARCH}"
if [ "$OS" = windows ]; then
  ARCHIVE="${ASSET}.zip"
  BIN_FILE="${BIN}.exe"
else
  ARCHIVE="${ASSET}.tar.gz"
  BIN_FILE="${BIN}"
fi

# --- download helpers -------------------------------------------------------

if command -v curl >/dev/null 2>&1; then
  fetch() {
    if [ -n "${GITHUB_TOKEN:-}" ]; then
      curl -fsSL -H "Authorization: Bearer ${GITHUB_TOKEN}" "$1" -o "$2"
    else
      curl -fsSL "$1" -o "$2"
    fi
  }
  fetch_stdout() {
    if [ -n "${GITHUB_TOKEN:-}" ]; then
      curl -fsSL -H "Authorization: Bearer ${GITHUB_TOKEN}" "$1"
    else
      curl -fsSL "$1"
    fi
  }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -qO "$2" "$1"; }
  fetch_stdout() { wget -qO- "$1"; }
else
  die "neither curl nor wget is available"
fi

# --- resolve the release ----------------------------------------------------

if [ "$VERSION" = latest ]; then
  log "Resolving the latest release of ${REPO}…"
  # `sed` over the release API rather than a JSON parser: `jq` is not something
  # a minimal CI image can be assumed to have.
  TAG="$(fetch_stdout "https://api.github.com/repos/${REPO}/releases/latest" \
    | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
    | head -n 1)"
  [ -n "$TAG" ] || die "could not resolve the latest release of ${REPO}"
else
  TAG="$VERSION"
fi
log "Installing ${BIN} ${TAG} (${OS}/${ARCH})"

BASE_URL="https://github.com/${REPO}/releases/download/${TAG}"

# --- install directory ------------------------------------------------------

if [ -z "$INSTALL_DIR" ]; then
  if [ -d /usr/local/bin ] && [ -w /usr/local/bin ]; then
    INSTALL_DIR=/usr/local/bin
  else
    INSTALL_DIR="${HOME}/.local/bin"
  fi
fi
mkdir -p "$INSTALL_DIR" || die "cannot create '$INSTALL_DIR'"
[ -w "$INSTALL_DIR" ] || die "'$INSTALL_DIR' is not writable (try --install-dir, or run with sudo)"

# --- download, verify, unpack ----------------------------------------------

TMP="$(mktemp -d)"
# shellcheck disable=SC2064 # expand $TMP now: it must be removed even if unset later
trap "rm -rf '$TMP'" EXIT INT TERM

log "Downloading ${BASE_URL}/${ARCHIVE}"
fetch "${BASE_URL}/${ARCHIVE}" "${TMP}/${ARCHIVE}" || die "download failed"

if [ "$VERIFY" -eq 1 ]; then
  if fetch "${BASE_URL}/${ARCHIVE}.sha256" "${TMP}/${ARCHIVE}.sha256" 2>/dev/null; then
    expected="$(cut -d' ' -f1 < "${TMP}/${ARCHIVE}.sha256")"
    if command -v sha256sum >/dev/null 2>&1; then
      actual="$(sha256sum "${TMP}/${ARCHIVE}" | cut -d' ' -f1)"
    elif command -v shasum >/dev/null 2>&1; then
      actual="$(shasum -a 256 "${TMP}/${ARCHIVE}" | cut -d' ' -f1)"
    else
      actual=""
      log "warning: no sha256sum/shasum available, skipping checksum verification"
    fi
    if [ -n "$actual" ]; then
      [ "$actual" = "$expected" ] || die "checksum mismatch (expected $expected, got $actual)"
      log "Checksum verified."
    fi
  else
    log "warning: no published checksum for ${ARCHIVE}, skipping verification"
  fi
fi

case "$ARCHIVE" in
  *.tar.gz) tar -xzf "${TMP}/${ARCHIVE}" -C "$TMP" ;;
  *.zip)
    command -v unzip >/dev/null 2>&1 || die "unzip is required to unpack ${ARCHIVE}"
    unzip -q "${TMP}/${ARCHIVE}" -d "$TMP"
    ;;
esac

[ -f "${TMP}/${BIN_FILE}" ] || die "${BIN_FILE} not found in ${ARCHIVE}"
install -m 0755 "${TMP}/${BIN_FILE}" "${INSTALL_DIR}/${BIN_FILE}" 2>/dev/null \
  || { cp "${TMP}/${BIN_FILE}" "${INSTALL_DIR}/${BIN_FILE}" && chmod 0755 "${INSTALL_DIR}/${BIN_FILE}"; }

log "Installed ${INSTALL_DIR}/${BIN_FILE}"

case ":${PATH}:" in
  *":${INSTALL_DIR}:"*) ;;
  *) log "note: ${INSTALL_DIR} is not on your PATH — add it to use '${BIN}' directly." ;;
esac

"${INSTALL_DIR}/${BIN_FILE}" --version || true
