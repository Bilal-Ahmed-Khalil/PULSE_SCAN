#!/usr/bin/env bash
# Launch Security Scanner Pro on Linux / macOS
set -e
cd "$(dirname "$0")"

PYTHON="${PYTHON:-python3}"

# Prefer venv if present
if [ -x ".venv/bin/python" ]; then
  PYTHON=".venv/bin/python"
fi

echo "Using: $PYTHON"
$PYTHON -m pip install -q -r requirements.txt

# Linux needs Tk; macOS usually has it with python.org installers
if ! $PYTHON -c "import tkinter" 2>/dev/null; then
  echo "ERROR: tkinter is not available."
  echo "  Debian/Ubuntu:  sudo apt install python3-tk"
  echo "  Fedora:         sudo dnf install python3-tkinter"
  echo "  macOS:          install Python from python.org (includes Tk)"
  exit 1
fi

exec $PYTHON scanner_gui.py "$@"
