@echo off
REM Simple launcher – place next to SecurityHeaderScanner.exe and domains.txt
cd /d "%~dp0"
if not exist reports mkdir reports
SecurityHeaderScanner.exe -d domains.txt -o reports --json
echo.
echo Scan finished. Check the reports folder for the latest PDF.
