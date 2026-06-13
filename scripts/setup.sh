#!/bin/zsh
set -eu

ROOT="${0:A:h:h}"
WITH_DYNAMIC=false
WITH_CLAMAV=false

for arg in "$@"; do
  case "$arg" in
    --with-dynamic) WITH_DYNAMIC=true ;;
    --with-clamav) WITH_CLAMAV=true ;;
    -h|--help)
      cat <<'EOF'
Usage: ./scripts/setup.sh [--with-dynamic] [--with-clamav]

  --with-dynamic  Install Tart and prepare the large macOS runtime VM.
  --with-clamav   Install ClamAV for optional local malware scanning.
EOF
      exit 0
      ;;
    *)
      print -u2 "Unknown option: $arg"
      exit 2
      ;;
  esac
done

if [[ "$(uname -s)" != "Darwin" ]]; then
  print -u2 "CanUInstall requires macOS."
  exit 1
fi

if ! command -v python3 >/dev/null 2>&1; then
  print -u2 "Python 3.11+ is required. Install it with: brew install python"
  exit 1
fi

python3 - <<'PY'
import sys
if sys.version_info < (3, 11):
    raise SystemExit("Python 3.11+ is required.")
print(f"Python {sys.version.split()[0]} is available.")
PY

cd "$ROOT"
if [[ ! -d .venv ]]; then
  print "Creating .venv..."
  python3 -m venv .venv
fi

print "Installing Python requirements..."
.venv/bin/python -m pip install -r requirements.txt

if $WITH_CLAMAV; then
  if ! command -v brew >/dev/null 2>&1; then
    print -u2 "Homebrew is required for --with-clamav: https://brew.sh/"
    exit 1
  fi
  brew install clamav
fi

if $WITH_DYNAMIC; then
  "$ROOT/scripts/prepare-tart-runtime.sh"
fi

cat <<'EOF'

Setup complete.

Start CanUInstall:
  ./scripts/run.sh

Then open:
  http://127.0.0.1:8765
EOF
