#!/bin/zsh
set -eu

ROOT="${0:A:h:h}"
BASE_VM="${TART_BASE_SOURCE_VM:-tahoe-base}"
RUNTIME_VM="${TART_RUNTIME_VM:-canuinstall-runtime}"
IMAGE="${TART_IMAGE:-ghcr.io/cirruslabs/macos-tahoe-base:latest}"
RUN_PID=""

cleanup() {
  tart stop "$RUNTIME_VM" --timeout 10 >/dev/null 2>&1 || true
  if [[ -n "$RUN_PID" ]]; then
    wait "$RUN_PID" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT INT TERM

vm_exists() {
  tart list --source local --format json | python3 -c \
    'import json, sys; name=sys.argv[1]; raise SystemExit(0 if any(item.get("Name") == name for item in json.load(sys.stdin)) else 1)' \
    "$1"
}

if [[ "$(uname -m)" != "arm64" ]]; then
  print -u2 "Tart dynamic analysis requires an Apple Silicon Mac."
  exit 1
fi

if ! command -v brew >/dev/null 2>&1; then
  print -u2 "Homebrew is required: https://brew.sh/"
  exit 1
fi

if ! command -v tart >/dev/null 2>&1; then
  print "Installing Tart..."
  brew install tart
fi

if ! vm_exists "$BASE_VM"; then
  print "Downloading the macOS base VM. This is a large download..."
  tart clone "$IMAGE" "$BASE_VM"
fi

if vm_exists "$RUNTIME_VM"; then
  print "$RUNTIME_VM already exists; no changes were made."
  print "Delete or rename it manually if you need to rebuild the runtime."
  exit 0
fi

print "Fetching the osquery installer..."
brew fetch --force osquery
BREW_CACHE="$(brew --cache)"
OSQUERY_PKG="$(find "$BREW_CACHE/downloads" -type f -name '*osquery*.pkg' -print | tail -1)"
if [[ -z "$OSQUERY_PKG" ]]; then
  print -u2 "Could not find the downloaded osquery package."
  exit 1
fi

print "Creating $RUNTIME_VM from $BASE_VM..."
tart clone "$BASE_VM" "$RUNTIME_VM"

PKG_DIR="${OSQUERY_PKG:h}"
PKG_NAME="${OSQUERY_PKG:t}"
print "Starting the runtime VM with a read-only installer share..."
tart run \
  --no-graphics \
  --no-audio \
  --no-clipboard \
  --net-softnet \
  --dir="osquery:$PKG_DIR:ro" \
  "$RUNTIME_VM" &
RUN_PID=$!

print "Waiting for the Tart Guest Agent..."
ready=false
for _ in {1..60}; do
  if tart exec "$RUNTIME_VM" /usr/bin/true >/dev/null 2>&1; then
    ready=true
    break
  fi
  sleep 2
done
if ! $ready; then
  print -u2 "The Tart Guest Agent did not become ready."
  exit 1
fi

print "Installing osquery inside the runtime VM..."
tart exec "$RUNTIME_VM" /usr/bin/sudo -n /usr/sbin/installer \
  -pkg "/Volumes/My Shared Files/osquery/$PKG_NAME" \
  -target /
tart exec "$RUNTIME_VM" /usr/local/bin/osqueryi --version

cleanup
trap - EXIT INT TERM
print "$RUNTIME_VM is ready."
