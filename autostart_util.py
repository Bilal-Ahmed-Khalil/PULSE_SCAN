
"""Cross-platform login autostart helpers."""
from __future__ import annotations
import os
import sys
from pathlib import Path


def set_autostart(enable: bool) -> bool:
    try:
        if sys.platform == "win32":
            return _windows(enable)
        if sys.platform == "darwin":
            return _macos(enable)
        return _linux(enable)
    except Exception as e:
        print(f"Autostart failed: {e}")
        return False


def _windows(enable: bool) -> bool:
    appdata = os.environ.get("APPDATA", "")
    if not appdata:
        return False
    startup = Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
    startup.mkdir(parents=True, exist_ok=True)
    bat = startup / "PulseScan.bat"
    if not enable:
        for p in (bat, startup / "PulseScan.lnk"):
            try:
                p.unlink(missing_ok=True)
            except Exception:
                pass
        return True
    if getattr(sys, "frozen", False):
        target = str(Path(sys.executable).resolve())
        content = f'@echo off\r\nstart "" "{target}"\r\n'
    else:
        script = Path(__file__).resolve().parent / "scanner_gui.py"
        content = f'@echo off\r\nstart "" "{sys.executable}" "{script}"\r\n'
    bat.write_text(content, encoding="utf-8")
    return True


def _macos(enable: bool) -> bool:
    agents = Path.home() / "Library" / "LaunchAgents"
    agents.mkdir(parents=True, exist_ok=True)
    plist = agents / "com.pulsescan.gui.plist"
    if not enable:
        os.system(f'launchctl unload "{plist}" 2>/dev/null')
        try:
            plist.unlink(missing_ok=True)
        except Exception:
            pass
        return True
    if getattr(sys, "frozen", False):
        args = f"        <string>{Path(sys.executable).resolve()}</string>\n"
    else:
        script = Path(__file__).resolve().parent / "scanner_gui.py"
        args = (
            f"        <string>{sys.executable}</string>\n"
            f"        <string>{script}</string>\n"
        )
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.pulsescan.gui</string>
    <key>ProgramArguments</key>
    <array>
{args}    </array>
    <key>RunAtLoad</key>
    <true/>
</dict>
</plist>
"""
    plist.write_text(xml, encoding="utf-8")
    os.system(f'launchctl load "{plist}" 2>/dev/null')
    return True


def _linux(enable: bool) -> bool:
    autostart = Path.home() / ".config" / "autostart"
    autostart.mkdir(parents=True, exist_ok=True)
    desktop = autostart / "security-header-scanner.desktop"
    if not enable:
        try:
            desktop.unlink(missing_ok=True)
        except Exception:
            pass
        return True
    if getattr(sys, "frozen", False):
        exec_line = str(Path(sys.executable).resolve())
    else:
        script = Path(__file__).resolve().parent / "scanner_gui.py"
        exec_line = f"{sys.executable} {script}"
    content = f"""[Desktop Entry]
Type=Application
Name=PulseScan
Comment=Security Scanner Pro
Exec={exec_line}
Terminal=false
X-GNOME-Autostart-enabled=true
"""
    desktop.write_text(content, encoding="utf-8")
    try:
        desktop.chmod(0o755)
    except Exception:
        pass
    return True
