@echo off
REM Build standalone Windows executable (runs as Administrator)
REM Uses "python -m PyInstaller" so it works with Microsoft Store Python

echo.
echo ============================================================
echo  Security Header Scanner - Building Windows .exe (Admin)
echo ============================================================
echo.

echo [1/3] Installing / upgrading dependencies...
python -m pip install -r requirements.txt
python -m pip install customtkinter pillow pystray
python -m pip install --upgrade pyinstaller

echo.
echo [2/3] Building PulseScan.exe ...
echo      (this may take 1-3 minutes)
echo      UAC Admin is ENABLED - the app will ask for admin rights
echo.

python -m PyInstaller --onefile --windowed --uac-admin --clean --noconfirm --name PulseScan --add-data "scanner.py;." --add-data "tech_vuln_scanner.py;." --add-data "owasp_scanner.py;." --add-data "autostart_util.py;." --add-data "updater.py;." --add-data "app_icon.png;." --add-data "app_icon.ico;." --icon=app_icon.ico scanner_gui.py

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo BUILD FAILED!
    echo Make sure you are running this from the folder that contains scanner_gui.py
    pause
    exit /b 1
)

echo.
echo [3/3] Build finished successfully!
echo.
echo ============================================================
echo  Your executable is ready:
echo.
echo      dist\PulseScan.exe
echo.
echo  IMPORTANT:
echo  - The .exe will request Administrator rights when started
echo  - Reports will be saved next to the .exe (Program Files\...\reports)
echo  - Rebuild the installer with Inno Setup after this
echo ============================================================
echo.
pause
