# PulseScan

Formerly Security Scanner Pro — headers, tech stack, vuln & OWASP scanning.

# Security Header Vulnerability Scanner – GUI Edition

Modern desktop app that scans your domains for critical HTTP security headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, Permissions-Policy, COOP/CORP/COEP).

## Features

- **GUI** with domain list management (Add / Remove / Import / Save)
- **Live results table** inside the app (color-coded grades)
- **PDF report** generation (professional multi-page report)
- **Automatic scanning twice a day** (configurable times, runs while the app is open)
- **Slack notifications** via Incoming Webhook (summary + PDF path)
- Score (0-100) + letter grade (A+ → F) per domain
- Standalone Windows `.exe` support

## Screenshots of main window

- Left panel → Domains list + Add / Remove / Import / Save buttons  
- Right panel → Results table (Domain | Grade | Score | Status | Key Issues)  
- Top toolbar → Scan Now | Settings | Open PDF | Reports Folder  
- Bottom → Activity log  

## Quick Start (Python)

```bash
pip install -r requirements.txt
python scanner_gui.py
```

1. Click **＋ Add** or **Import…** to load your domains  
2. Click **💾 Save** (also writes `domains.txt` + `config.json`)  
3. Click **▶ Scan Now**  
4. Results appear instantly in the table. PDF is saved automatically.  
5. Open **⚙ Settings** to configure Slack webhook and auto-scan times.

## Slack Setup (recommended)

1. Go to https://api.slack.com/apps → Create New App → From scratch  
2. **Incoming Webhooks** → Activate → Add New Webhook to Workspace  
3. Copy the Webhook URL  
4. Paste it in the app **Settings**  
5. Enable “Send Slack report after automatic / manual scans”

The app will post a clean summary with grades and the PDF path after every scan.

## Automatic Scan (2× per day)

1. Open **Settings**  
2. Check **Enable automatic scan**  
3. Set two times (e.g. `08:00` and `20:00`) – 24-hour format, local time  
4. Save  

The scheduler runs **inside the application**. Keep the app open (or minimized) for automatic scans to fire.  
For true “always-on” even when logged out, you can still use Windows Task Scheduler with the CLI version (`scanner.py`).

## Building Windows .exe

On a Windows machine with Python 3.10+:

```bat
pip install -r requirements.txt
pyinstaller --onefile --windowed --name SecurityHeaderScannerGUI scanner_gui.py
```

Or simply double-click `build_exe.bat` (updated for GUI).

After building, copy these files next to the `.exe`:
- `scanner.py` (required – contains the scanning engine)
- (optional) `domains.txt`

Or rebuild with both files included (advanced).

### Recommended PyInstaller command (includes both modules)

```bat
pyinstaller --onefile --windowed --name SecurityHeaderScannerGUI ^
  --add-data "scanner.py;." scanner_gui.py
```

## Files

| File | Purpose |
|------|---------|
| `scanner_gui.py` | Main GUI application |
| `scanner.py` | Core scanning + PDF engine (used by GUI) |
| `config.json` | Saved settings + domain list (created on first save) |
| `domains.txt` | Simple text list (kept in sync) |
| `reports/` | PDF reports appear here |
| `build_exe.bat` | One-click Windows build |
| `requirements.txt` | Python dependencies |

## CLI version still available

```bash
python scanner.py                  # uses domains.txt
python scanner.py --single site.com
python scanner.py --json
```

## Notes

- The automatic scheduler only works while the GUI is running.
- Slack uses Incoming Webhooks only (no bot token required for basic reports).
- Always test CSP changes carefully before enforcing them in production.
- SSL errors and unreachable domains are reported clearly in the results table.

## License

Free for internal / organizational use.


## Linux / macOS

### Run from source
```bash
chmod +x run_gui.sh
./run_gui.sh
```

Dependencies:
- **Linux:** `sudo apt install python3-tk` (Debian/Ubuntu) or `sudo dnf install python3-tkinter` (Fedora)
- **macOS:** Python from [python.org](https://www.python.org) (includes Tk). Homebrew Python may need `brew install python-tk`

### Build standalone app
```bash
chmod +x build_unix.sh
./build_unix.sh
# binary: dist/SecurityHeaderScannerGUI/SecurityHeaderScannerGUI
```

### Autostart at login
Enable in **Settings → Start at login**.
- Linux: `~/.config/autostart/security-header-scanner.desktop`
- macOS: `~/Library/LaunchAgents/com.securityheaderscanner.gui.plist`
- Windows: Startup folder `.bat`

Data (config, reports, history) is stored next to the app when writable, otherwise:
- Linux/macOS: `~/.local/share/SecurityHeaderScanner/`
- Windows: `%LOCALAPPDATA%\SecurityHeaderScanner\`


## Auto-update (S3)

App version: **1.0.0**

1. Upload a public (or pre-signed) `version.json` to your S3 bucket, for example:
   `https://YOUR_BUCKET.s3.amazonaws.com/security-scanner/version.json`

2. Example manifest (`version.json.example`):
```json
{
  "version": "1.0.1",
  "notes": "What changed in this release",
  "download_url": "https://YOUR_BUCKET.s3.amazonaws.com/security-scanner/releases/security_header_scanner-1.0.1.zip",
  "mandatory": false
}
```

3. Upload the release zip (project folder) to the `download_url` path.

4. In the app **Settings → Update URL**, paste the full URL to `version.json`.

5. Use **↻ Update** in the toolbar, or enable **Check for updates when app starts**.

When a newer version is found, the app downloads the zip, extracts updated files into the app directory, and asks you to restart.
