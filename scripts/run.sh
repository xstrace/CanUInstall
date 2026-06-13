#!/bin/zsh
set -eu

ROOT="${0:A:h:h}"
PYTHON="$ROOT/.venv/bin/python"

if [[ ! -x "$PYTHON" ]]; then
  print -u2 "CanUInstall is not initialized. Run: ./scripts/setup.sh"
  exit 1
fi

cd "$ROOT"
exec "$PYTHON" app.py "$@"
