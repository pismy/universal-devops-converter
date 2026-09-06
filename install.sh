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
  DOWNLOADER=curl
elif command -v wget >/dev/null 2>&1; then
  DOWNLOADER=wget
else
  die "neither curl nor wget is available"
fi

# Download $1 into $2 and print the HTTP status.
#
# The status is the point: a bare "it failed" cannot tell a missing release from
# a rate limit, and those two need opposite fixes. `wget` cannot report one, so
# it gets 200/000.
http_get() {
  case "$DOWNLOADER" in
    curl)
      if [ -n "${GITHUB_TOKEN:-}" ]; then
        curl -sL -H "Authorization: Bearer ${GITHUB_TOKEN}" \
          -o "$2" -w '%{http_code}' "$1" 2>/dev/null || printf '000'
      else
        curl -sL -o "$2" -w '%{http_code}' "$1" 2>/dev/null || printf '000'
      fi
      ;;
    wget)
      if wget -qO "$2" "$1" 2>/dev/null; then printf '200'; else printf '000'; fi
      ;;
  esac
}

# Scratch space. Created before anything is fetched, because resolving the
# release already needs somewhere to put a response body.
TMP="$(mktemp -d)"
# shellcheck disable=SC2064 # expand $TMP now: it must be removed even if unset later
trap "rm -rf '$TMP'" EXIT INT TERM

# --- resolve the release ----------------------------------------------------

# `https://github.com/<repo>/releases/latest` redirects to the tag page of the
# latest non-draft, non-prerelease release. Reading the tag out of that redirect
# costs no API call, which matters: the unauthenticated API allows 60 requests
# per hour per IP, and a busy CI runner burns through that shared budget.
latest_from_redirect() {
  [ "$DOWNLOADER" = curl ] || return 0
  resolved="$(curl -sIL -o /dev/null -w '%{url_effective}' \
    "https://github.com/${REPO}/releases/latest" 2>/dev/null || true)"
  case "$resolved" in
    */releases/tag/*) printf '%s' "${resolved##*/releases/tag/}" ;;
    *) : ;;  # no release yet: GitHub keeps you on the releases index
  esac
}

resolve_latest() {
  tag="$(latest_from_redirect)"
  if [ -n "$tag" ]; then
    printf '%s' "$tag"
    return 0
  fi

  # Fall back to the API, and report what it actually said.
  status="$(http_get "https://api.github.com/repos/${REPO}/releases/latest" "${TMP}/latest.json")"
  case "$status" in
    200)
      # `sed` rather than a JSON parser: `jq` is not something a minimal CI
      # image can be assumed to have.
      tag="$(sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' \
        "${TMP}/latest.json" | head -n 1)"
      [ -n "$tag" ] || die "the GitHub API returned no tag_name for ${REPO}"
      printf '%s' "$tag"
      ;;
    404)
      die "${REPO} has no published release yet.
       If a release is being built right now, it stays a draft until every
       platform binary is uploaded, and drafts are not 'latest'.
       Install a specific tag with: --version <tag>"
      ;;
    403 | 429)
      die "GitHub rejected the request while resolving 'latest' (HTTP ${status}).
       This is almost always the unauthenticated API rate limit.
       Set GITHUB_TOKEN, or skip the lookup with: --version <tag>"
      ;;
    000)
      die "could not reach GitHub to resolve the latest release of ${REPO}.
       Check network access, or install a specific tag with: --version <tag>"
      ;;
    *)
      die "could not resolve the latest release of ${REPO} (HTTP ${status}).
       Install a specific tag with: --version <tag>"
      ;;
  esac
}

if [ "$VERSION" = latest ]; then
  log "Resolving the latest release of ${REPO}…"
  TAG="$(resolve_latest)"
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

log "Downloading ${BASE_URL}/${ARCHIVE}"
status="$(http_get "${BASE_URL}/${ARCHIVE}" "${TMP}/${ARCHIVE}")"
case "$status" in
  200) ;;
  404)
    die "no ${ARCHIVE} in release ${TAG} of ${REPO}.
       Either that release predates this platform, or the tag does not exist.
       See https://github.com/${REPO}/releases"
    ;;
  *) die "downloading ${ARCHIVE} failed (HTTP ${status})" ;;
esac

if [ "$VERIFY" -eq 1 ]; then
  if [ "$(http_get "${BASE_URL}/${ARCHIVE}.sha256" "${TMP}/${ARCHIVE}.sha256")" = 200 ]; then
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
