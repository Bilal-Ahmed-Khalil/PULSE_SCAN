#!/usr/bin/env bash
# Build a standalone binary for Linux or macOS with PyInstaller
set -e
cd "$(dirname "$0")"
PYTHON="${PYTHON:-python3}"

$PYTHON -m pip install -q -r requirements.txt pyinstaller

# One-folder is more reliable on Unix than onefile for Tk apps
$PYTHON -m PyInstaller \
  --noconfirm --clean --windowed \
  --name PulseScan \
  --add-data "scanner.py:." \
  --add-data "tech_vuln_scanner.py:." \
  --add-data "owasp_scanner.py:." \
  --add-data "autostart_util.py:." \
  --add-data "updater.py:." \
  --add-data "app_icon.png:." \
  --add-data "app_icon.ico:." \
  scanner_gui.py

echo ""
echo "Build complete:"
echo "  dist/PulseScan/"
echo "Run:"
echo "  ./dist/PulseScan/PulseScan"
