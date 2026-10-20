"""
Auto-update for PulseScan (source + frozen .exe).

Remote version.json (S3):
{
  "version": "1.0.1",
  "notes": "Release notes",
  "download_url": "https://BUCKET.s3.amazonaws.com/releases/SecurityHeaderScannerGUI.exe",
  "mandatory": false
}

download_url may be:
  - .exe  → replaces running frozen executable
  - .zip  → extracts; if zip contains .exe, replaces binary; else updates source files
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

import requests

APP_VERSION = "1.0.0"
USER_AGENT = f"PulseScan/{APP_VERSION}"


def parse_version(v: str) -> Tuple[int, ...]:
    parts = []
    for p in (v or "0").strip().lstrip("vV").split("."):
        try:
            parts.append(int(p))
        except ValueError:
            parts.append(0)
    while len(parts) < 3:
        parts.append(0)
    return tuple(parts[:4])


def is_newer(remote: str, local: str = APP_VERSION) -> bool:
    return parse_version(remote) > parse_version(local)


def is_frozen() -> bool:
    return bool(getattr(sys, "frozen", False))


def current_executable() -> Path:
    if is_frozen():
        return Path(sys.executable).resolve()
    return Path(__file__).resolve()


def fetch_manifest(update_url: str, timeout: int = 15) -> Dict[str, Any]:
    if not update_url or not update_url.startswith(("http://", "https://")):
        raise ValueError("update_url must be a full http(s) URL to version.json")
    r = requests.get(
        update_url.strip(),
        timeout=timeout,
        headers={"User-Agent": USER_AGENT, "Cache-Control": "no-cache"},
    )
    r.raise_for_status()
    data = r.json()
    if not isinstance(data, dict) or "version" not in data:
        raise ValueError("Invalid manifest: missing 'version'")
    return data


def check_for_update(update_url: str) -> Dict[str, Any]:
    out = {
        "available": False,
        "local": APP_VERSION,
        "remote": APP_VERSION,
        "notes": "",
        "download_url": "",
        "mandatory": False,
        "error": None,
        "manifest": None,
    }
    try:
        manifest = fetch_manifest(update_url)
        out["manifest"] = manifest
        remote = str(manifest.get("version", "")).strip()
        out["remote"] = remote
        out["notes"] = str(manifest.get("notes") or "")
        out["download_url"] = str(manifest.get("download_url") or "")
        out["mandatory"] = bool(manifest.get("mandatory", False))
        out["available"] = is_newer(remote, APP_VERSION) and bool(out["download_url"])
        if is_newer(remote, APP_VERSION) and not out["download_url"]:
            out["error"] = "Newer version published but download_url is missing"
    except Exception as e:
        out["error"] = str(e)
    return out


def download_update(download_url: str, dest_dir: Optional[Path] = None,
                    progress_cb=None) -> Path:
    dest_dir = Path(dest_dir or tempfile.gettempdir())
    dest_dir.mkdir(parents=True, exist_ok=True)
    name = download_url.rstrip("/").split("/")[-1] or "update.bin"
    if "?" in name:
        name = name.split("?")[0]
    path = dest_dir / name
    with requests.get(
        download_url, stream=True, timeout=180,
        headers={"User-Agent": USER_AGENT},
    ) as r:
        r.raise_for_status()
        total = int(r.headers.get("Content-Length") or 0)
        done = 0
        with open(path, "wb") as f:
            for chunk in r.iter_content(chunk_size=256 * 1024):
                if not chunk:
                    continue
                f.write(chunk)
                done += len(chunk)
                if progress_cb and total:
                    progress_cb(done / total)
    return path


def extract_zip_update(zip_path: Path, target_dir: Path) -> Path:
    out = target_dir / "update_extract"
    if out.exists():
        shutil.rmtree(out, ignore_errors=True)
    out.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, "r") as zf:
        zf.extractall(out)
    return out


def find_exe_in_tree(root: Path) -> Optional[Path]:
    # Prefer known name, then any .exe
    preferred = list(root.rglob("SecurityHeaderScannerGUI.exe"))
    if preferred:
        return preferred[0]
    exes = [p for p in root.rglob("*.exe") if p.is_file()]
    return exes[0] if exes else None


def apply_source_update(extract_root: Path, app_dir: Path) -> list:
    written = []
    nested = extract_root / "security_header_scanner"
    root = nested if nested.is_dir() else extract_root
    for src in root.rglob("*"):
        if not src.is_file():
            continue
        if src.suffix.lower() not in {".py", ".txt", ".md", ".json", ".bat", ".sh", ".iss"}:
            continue
        rel = src.relative_to(root)
        dest = app_dir / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
        written.append(str(rel))
    return written


def _write_windows_replacer(current_exe: Path, new_exe: Path) -> Path:
    """
    Batch script: wait for this process to exit, replace .exe, restart.
    Must run as a detached process so it outlives the app.
    """
    bat = current_exe.parent / "_apply_update.bat"
    # Use timeout / ping to wait; then move files; then start new exe
    content = f"""@echo off
setlocal
set "TARGET={current_exe}"
set "NEWFILE={new_exe}"
set "LOG={current_exe.parent / "_update_log.txt"}"
echo Updating... > "%LOG%"
rem Wait until the running exe unlocks (max ~60s)
set /a n=0
:waitloop
set /a n+=1
if %n% GTR 60 goto do_replace
ping -n 2 127.0.0.1 >nul
del "%TARGET%.old" >nul 2>&1
move /Y "%TARGET%" "%TARGET%.old" >nul 2>&1
if errorlevel 1 goto waitloop
:do_replace
move /Y "%TARGET%" "%TARGET%.old" >nul 2>&1
copy /Y "%NEWFILE%" "%TARGET%" >nul
if errorlevel 1 (
  echo COPY FAILED >> "%LOG%"
  if exist "%TARGET%.old" move /Y "%TARGET%.old" "%TARGET%" >nul
  exit /b 1
)
echo Updated OK >> "%LOG%"
start "" "%TARGET%"
del "%NEWFILE%" >nul 2>&1
del "%~f0" >nul 2>&1
endlocal
"""
    bat.write_text(content, encoding="utf-8")
    return bat


def _write_unix_replacer(current_bin: Path, new_bin: Path) -> Path:
    sh = current_bin.parent / "_apply_update.sh"
    content = f"""#!/usr/bin/env bash
TARGET="{current_bin}"
NEWFILE="{new_bin}"
LOG="{current_bin.parent / "_update_log.txt"}"
echo "Updating..." > "$LOG"
for i in $(seq 1 30); do
  if mv -f "$TARGET" "$TARGET.old" 2>/dev/null; then
    break
  fi
  sleep 1
done
cp -f "$NEWFILE" "$TARGET"
chmod +x "$TARGET"
echo "Updated OK" >> "$LOG"
nohup "$TARGET" >/dev/null 2>&1 &
rm -f "$NEWFILE"
rm -f "$0"
"""
    sh.write_text(content, encoding="utf-8")
    try:
        sh.chmod(0o755)
    except Exception:
        pass
    return sh


def schedule_exe_replace(new_file: Path) -> Path:
    """
    Schedule replacement of the running frozen binary and restart.
    Returns path to helper script. Caller should os._exit after launching it.
    """
    current = current_executable()
    new_file = Path(new_file).resolve()
    if sys.platform == "win32":
        script = _write_windows_replacer(current, new_file)
        # Detached process
        subprocess.Popen(
            ["cmd", "/c", str(script)],
            close_fds=True,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP | getattr(subprocess, "DETACHED_PROCESS", 0x00000008),
        )
    else:
        script = _write_unix_replacer(current, new_file)
        subprocess.Popen(
            ["/bin/bash", str(script)],
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    return script


def install_update_package(package_path: Path, app_dir: Path) -> Dict[str, Any]:
    """
    Install downloaded package.
    Returns {mode: 'exe'|'source', detail: ..., restart_required: bool, restart_scheduled: bool}
    """
    package_path = Path(package_path)
    result = {
        "mode": "source",
        "detail": "",
        "restart_required": True,
        "restart_scheduled": False,
        "written": [],
    }

    # Direct .exe download
    if package_path.suffix.lower() == ".exe":
        if not is_frozen():
            # Running from source – just keep the exe next to app
            dest = app_dir / package_path.name
            shutil.copy2(package_path, dest)
            result["mode"] = "exe"
            result["detail"] = f"Saved new executable to {dest}"
            result["restart_required"] = False
            return result
        # Frozen: stage as .new and schedule replace
        staged = current_executable().with_suffix(current_executable().suffix + ".new")
        shutil.copy2(package_path, staged)
        schedule_exe_replace(staged)
        result["mode"] = "exe"
        result["detail"] = "Executable replacement scheduled; app will restart"
        result["restart_scheduled"] = True
        return result

    # Zip package
    if package_path.suffix.lower() == ".zip":
        extract_root = extract_zip_update(package_path, app_dir / "updates")
        exe = find_exe_in_tree(extract_root)
        if exe and is_frozen():
            staged = current_executable().with_suffix(current_executable().suffix + ".new")
            shutil.copy2(exe, staged)
            schedule_exe_replace(staged)
            result["mode"] = "exe"
            result["detail"] = f"Found {exe.name} in zip; replacement scheduled"
            result["restart_scheduled"] = True
            return result
        written = apply_source_update(extract_root, app_dir)
        result["mode"] = "source"
        result["written"] = written
        result["detail"] = f"Updated {len(written)} source files"
        result["restart_required"] = True
        return result

    raise ValueError(f"Unsupported package type: {package_path.suffix}")
