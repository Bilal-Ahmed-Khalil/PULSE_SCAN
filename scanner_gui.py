#!/usr/bin/env python3
"""
Security Header Scanner – GUI Edition (v2)
Features:
- Domain groups / categories (multiple import lists)
- Manual Add / Remove domains
- Quick Scan (single domain at runtime)
- Full scan + auto-scan 2x/day
- Scan history per domain
- Results table + detailed popup
- PDF reports saved next to the .exe
- Slack notifications
- Auto-start with Windows (Startup folder)
"""

import json
import os
import sys
import threading
import time
import traceback
import shutil
from datetime import datetime, timezone, timedelta

# Pakistan Standard Time (UTC+5, no DST)
PKT = timezone(timedelta(hours=5), name="PKT")

def now_pkt() -> datetime:
    return datetime.now(PKT)

from pathlib import Path
from typing import Dict, List, Any, Optional

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog, scrolledtext

import requests
import schedule

try:
    from autostart_util import set_autostart
except ImportError:
    def set_autostart(enable: bool) -> bool:
        return False

try:
    from updater import (
        APP_VERSION, check_for_update, download_update, install_update_package, is_frozen,
    )
except ImportError:
    APP_VERSION = "1.0.0"
    def check_for_update(url):
        return {"available": False, "local": APP_VERSION, "remote": APP_VERSION, "error": "updater missing"}
    def download_update(*a, **k):
        raise RuntimeError("updater missing")
    def install_update_package(*a, **k):
        raise RuntimeError("updater missing")
    def is_frozen():
        return bool(getattr(sys, "frozen", False))

# Modern GUI: CustomTkinter when available (pip install customtkinter)
try:
    import customtkinter as ctk
    USE_CTK = True
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
except ImportError:
    USE_CTK = False

# Dual themes – dark cyberpunk + pearl white (max text contrast)
THEMES = {
    "dark": {
        "bg": "#050811",
        "card": "#0B101D",
        "border": "#1E293B",
        "border2": "#334155",
        "text": "#F8FAFC",       # near-white primary
        "text2": "#CBD5E1",      # secondary
        "text3": "#94A3B8",      # muted labels
        "emerald": "#10B981",
        "cyan": "#00F0FF",
        "violet": "#A855F7",
        "magenta": "#E879F9",
        "crimson": "#FF0055",
        "amber": "#F59E0B",
        "blue": "#38BDF8",
        "log_bg": "#030712",
        "entry_bg": "#0B101D",
        "entry_fg": "#F8FAFC",
        "tree_bg": "#050811",
        "tree_fg": "#F8FAFC",
        "tree_head_bg": "#0B101D",
        "tree_head_fg": "#00F0FF",
        "list_bg": "#050811",
        "list_fg": "#F8FAFC",
        "select_bg": "#1E3A5F",
        "btn_bg": "#1E293B",
        "btn_fg": "#F8FAFC",
    },
    "light": {
        "bg": "#F8FAFC",         # pearl white
        "card": "#FFFFFF",
        "border": "#E2E8F0",
        "border2": "#CBD5E1",
        "text": "#0F172A",       # near-black primary
        "text2": "#334155",      # secondary
        "text3": "#64748B",      # muted
        "emerald": "#059669",
        "cyan": "#0891B2",
        "violet": "#7C3AED",
        "magenta": "#C026D3",
        "crimson": "#DC2626",
        "amber": "#D97706",
        "blue": "#2563EB",
        "log_bg": "#F1F5F9",
        "entry_bg": "#FFFFFF",
        "entry_fg": "#0F172A",
        "tree_bg": "#FFFFFF",
        "tree_fg": "#0F172A",
        "tree_head_bg": "#E2E8F0",
        "tree_head_fg": "#0F172A",
        "list_bg": "#FFFFFF",
        "list_fg": "#0F172A",
        "select_bg": "#DBEAFE",
        "btn_bg": "#E2E8F0",
        "btn_fg": "#0F172A",
    },
}
C = dict(THEMES["dark"])  # active palette (mutable)
CURRENT_THEME = "dark"


# Optional system-tray support (install with: pip install pystray pillow)
try:
    import pystray
    from PIL import Image, ImageDraw
    TRAY_AVAILABLE = True
except ImportError:
    TRAY_AVAILABLE = False

# ---------------------------------------------------------------------------
# Import scanning engine (works as .py and as frozen .exe)
# ---------------------------------------------------------------------------
if getattr(sys, "frozen", False):
    sys.path.insert(0, getattr(sys, "_MEIPASS", str(Path(sys.executable).parent)))
else:
    sys.path.insert(0, str(Path(__file__).parent))

try:
    from scanner import (
        scan_domain,
        generate_pdf,
        SECURITY_HEADERS,
        normalize_url,
        compute_security_rating,
    )
    from tech_vuln_scanner import run_tech_and_vuln_scan, run_tech_scan, run_vulnerability_scan, run_full_recon, detect_technologies
    from owasp_scanner import run_owasp_scan, OWASP_CATEGORIES
except ImportError:
    try:
        import tkinter.messagebox as mb
        mb.showerror("Missing file", "scanner.py must be available")
    except Exception:
        print("ERROR: scanner.py not found")
    sys.exit(1)


# ---------------------------------------------------------------------------
# Paths
# - Executable location (for reading resources)
# - Data location (always writable: LocalAppData, never Program Files)
# ---------------------------------------------------------------------------
def get_app_dir() -> Path:
    """Folder containing the .exe or the .py script."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).parent.resolve()
    return Path(__file__).parent.resolve()


def _is_writable(folder: Path) -> bool:
    """Return True if we can create files inside folder."""
    try:
        folder.mkdir(parents=True, exist_ok=True)
        test = folder / ".write_test"
        test.write_text("ok", encoding="utf-8")
        test.unlink()
        return True
    except Exception:
        return False


def get_data_dir() -> Path:
    """
    Writable folder for config, history, reports, groups.
    Priority:
      1. Folder next to the .exe (works when running as Administrator)
      2. %LOCALAPPDATA%\\SecurityHeaderScanner (always writable for the user)
    """
    app_dir = get_app_dir()
    if _is_writable(app_dir):
        return app_dir

    if sys.platform == "win32":
        base = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))
    else:
        base = Path.home() / ".local" / "share"
    data = base / "PulseScan"
    try:
        data.mkdir(parents=True, exist_ok=True)
    except Exception:
        data = app_dir
    return data


APP_DIR = get_app_dir()
DATA_DIR = get_data_dir()

CONFIG_FILE = DATA_DIR / "config.json"
HISTORY_FILE = DATA_DIR / "scan_history.json"
REPORTS_DIR = DATA_DIR / "reports"
GROUPS_DIR = DATA_DIR / "domain_groups"

for _d in (REPORTS_DIR, GROUPS_DIR):
    try:
        _d.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass


def set_app_icon(root):
    """Set window / taskbar icon from bundled app_icon.png."""
    try:
        from PIL import Image, ImageTk
    except ImportError:
        Image = ImageTk = None
    candidates = []
    if getattr(sys, "frozen", False):
        meipass = getattr(sys, "_MEIPASS", None)
        if meipass:
            candidates.append(Path(meipass) / "app_icon.png")
        candidates.append(Path(sys.executable).parent / "app_icon.png")
    candidates.append(APP_DIR / "app_icon.png")
    candidates.append(Path(__file__).resolve().parent / "app_icon.png")
    icon_path = next((c for c in candidates if c.is_file()), None)
    if not icon_path:
        return
    try:
        # PNG via iconphoto (Windows/Linux/macOS Tk 8.6+)
        img = tk.PhotoImage(file=str(icon_path))
        root.iconphoto(True, img)
        root._icon_ref = img  # prevent GC
    except Exception:
        pass
    # Windows .ico fallback
    try:
        ico = icon_path.with_suffix(".ico")
        if ico.is_file():
            root.iconbitmap(default=str(ico))
    except Exception:
        pass


DEFAULT_CONFIG = {
    "theme": "dark",
    "domains": [],
    "groups": {},                  # {"XPAL": ["a.com", "b.com"], "Production": [...]}
    "active_group": "All",
    "slack_webhook": "",
    "auto_scan_enabled": False,
    "scan_times": ["08:00", "20:00"],
    "output_dir": str(REPORTS_DIR),
    "send_slack_on_auto": True,
    "send_slack_on_manual": True,
    "start_with_windows": False,
    "update_url": "",
    "check_updates_on_startup": True,
    "auto_apply_updates": True,
}


def load_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            for k, v in DEFAULT_CONFIG.items():
                if k not in cfg:
                    cfg[k] = v
            return cfg
        except Exception:
            pass
    return DEFAULT_CONFIG.copy()


def save_config(cfg: dict):
    try:
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except Exception as e:
        print(f"Failed to save config: {e}")


def load_history() -> dict:
    """history structure: { "domain.com": [ {scan_result}, {scan_result}, ... ] }"""
    if HISTORY_FILE.exists():
        try:
            with open(HISTORY_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def save_history(history: dict):
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(history, f, indent=2, default=str)
    except Exception as e:
        print(f"Failed to save history: {e}")


# ---------------------------------------------------------------------------
# Windows Startup helper
# ---------------------------------------------------------------------------
def set_windows_startup(enable: bool) -> bool:
    return set_autostart(enable)



# ---------------------------------------------------------------------------
# Slack
# ---------------------------------------------------------------------------
def send_slack_report(webhook: str, results: List[Dict], pdf_path: Optional[str] = None) -> bool:
    if not webhook or not webhook.startswith("https://hooks.slack.com/"):
        return False
    lines = []
    for r in results:
        domain = r.get("domain", "?")
        if r.get("error"):
            lines.append(f"• `{domain}` → ERROR: {r['error']}")
        else:
            g = r.get("grade", "F")
            s = r.get("overall_score", 0)
            emoji = {"A+": "🟢", "A": "🟢", "B": "🟡", "C": "🟠", "D": "🔴", "F": "🔴"}.get(g, "⚪")
            lines.append(f"• {emoji} `{domain}` → *{g}* ({s}/100)")

    summary = (
        f"*Security Headers Scan Report*\n"
        f"Time: {now_pkt().strftime('%Y-%m-%d %H:%M PKT')}\n"
        f"Domains: {len(results)}\n\n" + "\n".join(lines)
    )
    if pdf_path:
        summary += f"\n\n📄 PDF: `{pdf_path}`"

    try:
        resp = requests.post(webhook, json={"text": summary}, timeout=15)
        return resp.status_code == 200
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Main Application
# ---------------------------------------------------------------------------

def style_dialog(win):
    """Apply cyberpunk theme to Toplevel dialogs."""
    try:
        win.configure(bg=C["bg"])
    except Exception:
        pass
    if USE_CTK:
        try:
            # CTkToplevel would be ideal; for tk.Toplevel force colors on children later
            pass
        except Exception:
            pass


class SecurityScannerApp(ctk.CTk if USE_CTK else tk.Tk):
    def __init__(self):
        global CURRENT_THEME, C
        super().__init__()
        self.title(f"PulseScan v{APP_VERSION} – Headers · Tech · Vuln · OWASP")
        set_app_icon(self)
        self.geometry("1180x740")
        self.minsize(960, 620)

        self.cfg = load_config()
        # Restore saved theme preference before painting UI
        pref = (self.cfg.get("theme") or "dark").lower()
        if pref not in THEMES:
            pref = "dark"
        CURRENT_THEME = pref
        C.clear()
        C.update(THEMES[CURRENT_THEME])
        if USE_CTK:
            try:
                ctk.set_appearance_mode("light" if CURRENT_THEME == "light" else "dark")
            except Exception:
                pass

        if USE_CTK:
            try:
                self.configure(fg_color=C["bg"])
            except Exception:
                pass
        else:
            try:
                self.configure(bg=C["bg"])
            except Exception:
                pass
        self.history = load_history()
        self.results: List[Dict] = []
        self.last_pdf: Optional[str] = None
        self.scanning = False
        self.stop_scheduler = threading.Event()
        self.scheduler_thread = None
        self.tray_icon = None
        self._really_quit = False

        self._build_ui()
        # Sync theme button label with restored preference
        try:
            if hasattr(self, "_theme_btn"):
                label = "☀ Light" if CURRENT_THEME == "dark" else "☾ Dark"
                if USE_CTK:
                    self._theme_btn.configure(text=label)
                else:
                    self._theme_btn.configure(text=label)
            self._apply_theme()
        except Exception:
            pass
        self._refresh_group_combo()
        self._load_domains_into_list()
        self._start_scheduler_if_enabled()
        self._start_tray()
        # Silent update check shortly after UI is ready
        if self.cfg.get("check_updates_on_startup") and (self.cfg.get("update_url") or "").strip():
            self.after(2500, lambda: self.check_updates_ui(silent=True))

        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure(".", font=("Segoe UI", 9))
        style.configure("SOC.Treeview",
                        rowheight=28, font=("Segoe UI", 9),
                        background=C["bg"], fieldbackground=C["bg"],
                        foreground=C["text"], borderwidth=0)
        style.configure("SOC.Treeview.Heading",
                        font=("Segoe UI", 9, "bold"),
                        background="#0B101D", foreground=C["cyan"],
                        relief="flat", borderwidth=0)
        style.map("SOC.Treeview",
                  background=[("selected", C["border2"])],
                  foreground=[("selected", C["text"])])
        style.map("SOC.Treeview.Heading",
                  background=[("active", C["border2"])])
        style.configure("TCombobox", fieldbackground=C["card"], background=C["card"],
                        foreground=C["text"], arrowcolor=C["text2"])
        style.configure("TScrollbar", background=C["border"], troughcolor=C["bg"],
                        arrowcolor=C["text2"])
        try:
            self.configure(bg=C["bg"])
        except Exception:
            pass

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------



    def toggle_theme(self):
        global CURRENT_THEME, C
        CURRENT_THEME = "light" if CURRENT_THEME == "dark" else "dark"
        C.clear()
        C.update(THEMES[CURRENT_THEME])
        if USE_CTK:
            try:
                ctk.set_appearance_mode("light" if CURRENT_THEME == "light" else "dark")
            except Exception:
                pass
        self._apply_theme()
        try:
            self.cfg["theme"] = CURRENT_THEME
            save_config(self.cfg)
        except Exception:
            pass
        self.log_msg(f"Theme: {'Pearl White' if CURRENT_THEME == 'light' else 'Cyberpunk Dark'} (saved)")

    def _apply_theme(self):
        """Recolor main window widgets for current C palette."""
        bg, card, text, text2, text3 = C["bg"], C["card"], C["text"], C["text2"], C["text3"]
        try:
            if USE_CTK:
                self.configure(fg_color=bg)
            else:
                self.configure(bg=bg)
        except Exception:
            pass
        # Stored themeable widgets
        for attr, conf in (
            ("_body_frame", {"bg": bg}),
            ("_left_panel", {"bg": card, "highlightbackground": C["border"]}),
            ("_right_panel", {"bg": card, "highlightbackground": C["border"]}),
            ("_log_outer", {"bg": C["log_bg"], "highlightbackground": C["border"]}),
            ("_log_hdr", {"bg": C["log_bg"]}),
            ("_act1", {"bg": card}),
            ("_act2", {"bg": card}),
            ("_list_frame", {"bg": card}),
            ("_grp_row", {"bg": card}),
            ("_hdr_right", {"bg": card}),
            ("_tree_wrap", {"bg": card}),
        ):
            w = getattr(self, attr, None)
            if w is not None:
                try:
                    w.configure(**conf)
                except Exception:
                    pass
        for attr, conf in (
            ("_lbl_group", {"bg": card, "fg": text3}),
            ("_lbl_domains", {"bg": card, "fg": text3}),
            ("_lbl_results", {"bg": card, "fg": text3}),
            ("_lbl_results_hint", {"bg": card, "fg": text3}),
            ("_lbl_log", {"bg": C["log_bg"], "fg": text3}),
        ):
            w = getattr(self, attr, None)
            if w is not None:
                try:
                    w.configure(**conf)
                except Exception:
                    pass
        if hasattr(self, "domain_list"):
            try:
                self.domain_list.configure(
                    bg=C["list_bg"], fg=C["list_fg"],
                    selectbackground=C["select_bg"], selectforeground=text,
                    highlightbackground=C["border"],
                )
            except Exception:
                pass
        if hasattr(self, "log"):
            try:
                self.log.configure(bg=C["log_bg"], fg=text2, insertbackground=text2)
                self.log.tag_configure("ts", foreground=text3)
                self.log.tag_configure("info", foreground=C["blue"])
                self.log.tag_configure("ok", foreground=C["emerald"])
                self.log.tag_configure("err", foreground=C["crimson"])
                self.log.tag_configure("warn", foreground=C["amber"])
            except Exception:
                pass
        # ttk tree style
        try:
            style = ttk.Style()
            style.configure("SOC.Treeview",
                            background=C["tree_bg"], fieldbackground=C["tree_bg"],
                            foreground=C["tree_fg"])
            style.configure("SOC.Treeview.Heading",
                            background=C["tree_head_bg"], foreground=C["tree_head_fg"])
            style.map("SOC.Treeview",
                      background=[("selected", C["select_bg"])],
                      foreground=[("selected", text)])
        except Exception:
            pass
        # Rating row tags – readable on both themes
        if hasattr(self, "tree"):
            if CURRENT_THEME == "light":
                self.tree.tag_configure("A+", background="#D1FAE5", foreground="#065F46")
                self.tree.tag_configure("A", background="#D1FAE5", foreground="#065F46")
                self.tree.tag_configure("B", background="#ECFDF5", foreground="#047857")
                self.tree.tag_configure("C", background="#FEF3C7", foreground="#92400E")
                self.tree.tag_configure("D", background="#FFEDD5", foreground="#9A3412")
                self.tree.tag_configure("F", background="#FEE2E2", foreground="#991B1B")
                self.tree.tag_configure("ERR", background="#FEE2E2", foreground="#991B1B")
            else:
                self.tree.tag_configure("A+", background="#022C22", foreground="#10B981")
                self.tree.tag_configure("A", background="#022C22", foreground="#10B981")
                self.tree.tag_configure("B", background="#052E16", foreground="#34D399")
                self.tree.tag_configure("C", background="#1C1917", foreground="#F59E0B")
                self.tree.tag_configure("D", background="#1C0A0A", foreground="#FB7185")
                self.tree.tag_configure("F", background="#1C0A0A", foreground="#FF0055")
                self.tree.tag_configure("ERR", background="#1C0A0A", foreground="#FF0055")
        # Theme toggle button label
        if hasattr(self, "_theme_btn"):
            try:
                label = "☀ Light" if CURRENT_THEME == "dark" else "☾ Dark"
                if USE_CTK:
                    self._theme_btn.configure(text=label)
                else:
                    self._theme_btn.configure(text=label)
            except Exception:
                pass
        # Nav / CTk buttons hard to recolor fully – restart note
        if hasattr(self, "auto_label"):
            self._update_auto_label()
        if hasattr(self, "progress_line"):
            try:
                if USE_CTK:
                    self.progress_line.configure(fg_color=C["border"])
                else:
                    self.progress_line.configure(bg=C["border"])
            except Exception:
                pass

    def _build_ui(self):
        """SOC-grade dark dashboard layout."""
        bg, card, border = C["bg"], C["card"], C["border"]
        text, text2, text3 = C["text"], C["text2"], C["text3"]

        # ========== TOP NAV ==========
        if USE_CTK:
            top = ctk.CTkFrame(self, corner_radius=0, fg_color=card, height=56,
                              border_width=0)
            top.pack(fill=tk.X)
            top.pack_propagate(False)
            nav = ctk.CTkFrame(top, fg_color="transparent")
            nav.pack(fill=tk.BOTH, expand=True, padx=12, pady=8)

            def pill(parent, label, cmd, primary=False):
                if primary:
                    return ctk.CTkButton(
                        parent, text=label, command=cmd, height=32, width=110,
                        corner_radius=8, font=ctk.CTkFont(size=13, weight="bold"),
                        fg_color=C["emerald"], hover_color="#059669", text_color="#FFFFFF",
                    )
                return ctk.CTkButton(
                    parent, text=label, command=cmd, height=32,
                    corner_radius=8, font=ctk.CTkFont(size=12),
                    fg_color=C["border"], hover_color=C["border2"],
                    text_color=text, border_width=1, border_color=C["border2"],
                )

            pill(nav, "▶  Scan All", lambda: self.start_scan(auto=False), primary=True).pack(side=tk.LEFT, padx=(0, 8))

            # Secondary actions as unified slate pills
            modules = [
                ("⚡ Quick", self.quick_scan_dialog, C["cyan"]),
                ("🧬 Tech", self.tech_only_dialog, C["violet"]),
                ("🛡 Vuln", self.vuln_only_dialog, "#D946EF"),
                ("⚙ Settings", self.open_settings, C["border2"]),
                ("📄 PDF", self.open_pdf, C["border2"]),
                ("📁 Reports", self.open_reports_folder, C["border2"]),
            ]
            for label, cmd, accent in modules:
                b = ctk.CTkButton(
                    nav, text=label, command=cmd, height=32, corner_radius=8,
                    font=ctk.CTkFont(size=12),
                    fg_color=C["card"], hover_color=C["border"],
                    text_color=C["text"], border_width=1, border_color=accent,
                )
                b.pack(side=tk.LEFT, padx=3)

            right_nav = ctk.CTkFrame(nav, fg_color="transparent")
            right_nav.pack(side=tk.RIGHT)
            self._theme_btn = ctk.CTkButton(
                right_nav, text="☀ Light", command=self.toggle_theme, height=28, width=90,
                corner_radius=8, font=ctk.CTkFont(size=12),
                fg_color=C["border"], hover_color=C["border2"], text_color=text,
                border_width=1, border_color=C["cyan"],
            )
            self._theme_btn.pack(side=tk.LEFT, padx=6)
            self._update_btn = ctk.CTkButton(
                right_nav, text="↻ Update", command=self.check_updates_ui, height=28, width=90,
                corner_radius=8, font=ctk.CTkFont(size=12),
                fg_color=C["border"], hover_color=C["border2"], text_color=text,
                border_width=1, border_color=C["emerald"],
            )
            self._update_btn.pack(side=tk.LEFT, padx=4)
            self.auto_label = ctk.CTkLabel(right_nav, text="Auto-scan: Off",
                                          text_color=text3, font=ctk.CTkFont(size=12))
            self.auto_label.pack(side=tk.LEFT, padx=10)
            self.status_var = tk.StringVar(value="Ready")
            self.status_label = ctk.CTkLabel(right_nav, textvariable=self.status_var,
                                            text_color=C["blue"], font=ctk.CTkFont(size=12, weight="bold"))
            self.status_label.pack(side=tk.LEFT, padx=4)

            # Thin progress accent line under nav
            self.progress_line = ctk.CTkFrame(self, height=3, corner_radius=0, fg_color=C["border"])
            self.progress_line.pack(fill=tk.X)
        else:
            top = tk.Frame(self, bg=card, height=52)
            top.pack(fill=tk.X)
            top.pack_propagate(False)
            tk.Button(top, text="▶ Scan All", command=lambda: self.start_scan(auto=False),
                      bg=C["emerald"], fg="white", relief=tk.FLAT, padx=12, pady=6,
                      font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT, padx=8, pady=8)
            for label, cmd in (
                ("Quick", self.quick_scan_dialog), ("Tech", self.tech_only_dialog),
                ("Vuln", self.vuln_only_dialog), ("Settings", self.open_settings),
                ("PDF", self.open_pdf), ("Reports", self.open_reports_folder),
            ):
                tk.Button(top, text=label, command=cmd, bg=C["border"], fg=text,
                          relief=tk.FLAT, padx=8, pady=4, font=("Segoe UI", 9)).pack(side=tk.LEFT, padx=2, pady=8)
            self._theme_btn = tk.Button(top, text="☀ Light", command=self.toggle_theme,
                                         bg=C["btn_bg"], fg=C["btn_fg"], relief=tk.FLAT, padx=8, pady=4,
                                         font=("Segoe UI", 9))
            self._theme_btn.pack(side=tk.RIGHT, padx=6, pady=8)
            self._update_btn = tk.Button(top, text="↻ Update", command=self.check_updates_ui,
                                         bg=C["btn_bg"], fg=C["btn_fg"], relief=tk.FLAT, padx=8, pady=4,
                                         font=("Segoe UI", 9))
            self._update_btn.pack(side=tk.RIGHT, padx=4, pady=8)
            self.auto_label = tk.Label(top, text="Auto-scan: Off", bg=card, fg=text3, font=("Segoe UI", 9))
            self.auto_label.pack(side=tk.LEFT, padx=12)
            self.status_var = tk.StringVar(value="Ready")
            tk.Label(top, textvariable=self.status_var, bg=card, fg=C["blue"],
                     font=("Segoe UI", 9, "bold")).pack(side=tk.RIGHT, padx=12)
            self.progress_line = tk.Frame(self, height=3, bg=C["border"])
            self.progress_line.pack(fill=tk.X)

        # ========== BODY ==========
        self._body_frame = tk.Frame(self, bg=bg)
        body = self._body_frame
        body.pack(fill=tk.BOTH, expand=True)

        paned = ttk.Panedwindow(body, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        # ----- Left panel -----
        self._left_panel = tk.Frame(paned, bg=card, highlightbackground=border, highlightthickness=1)
        left = self._left_panel
        paned.add(left, weight=1)

        self._lbl_group = tk.Label(left, text="GROUP", bg=card, fg=text3,
                                 font=("Segoe UI", 9, "bold"), anchor="w")
        self._lbl_group.pack(fill=tk.X, padx=12, pady=(12, 4))
        self._grp_row = tk.Frame(left, bg=card)
        grp_row = self._grp_row
        grp_row.pack(fill=tk.X, padx=12, pady=(0, 6))
        self.group_var = tk.StringVar(value=self.cfg.get("active_group", "All"))
        self.group_combo = ttk.Combobox(grp_row, textvariable=self.group_var, state="readonly", width=22)
        self.group_combo.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.group_combo.bind("<<ComboboxSelected>>", lambda e: self._on_group_changed())

        self._lbl_domains = tk.Label(left, text="DOMAINS", bg=card, fg=text3,
                                   font=("Segoe UI", 9, "bold"), anchor="w")
        self._lbl_domains.pack(fill=tk.X, padx=12, pady=(12, 4))
        self._list_frame = tk.Frame(left, bg=card)
        list_frame = self._list_frame
        list_frame.pack(fill=tk.BOTH, expand=True, padx=12, pady=4)
        self.domain_list = tk.Listbox(
            list_frame, selectmode=tk.EXTENDED, font=("Consolas", 10),
            activestyle="none", bg="#0B0F19", fg=text, selectbackground=C["blue"],
            selectforeground=text, borderwidth=0, highlightthickness=1,
            highlightbackground=border, highlightcolor=C["blue"],
        )
        sb = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.domain_list.yview)
        self.domain_list.configure(yscrollcommand=sb.set)
        self.domain_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

        # Clear labeled action buttons
        def clear_btn(parent, label, cmd):
            b = tk.Button(
                parent, text=label, command=cmd,
                bg=C["border"], fg=C["text"],
                activebackground=C["border2"], activeforeground=C["cyan"],
                relief=tk.FLAT, bd=0,
                highlightthickness=1, highlightbackground=C["border2"],
                font=("Segoe UI", 9), padx=8, pady=5, cursor="hand2",
            )
            b.pack(side=tk.LEFT, padx=3, pady=2)
            return b

        self._act1 = tk.Frame(left, bg=card)
        act1 = self._act1
        act1.pack(fill=tk.X, padx=10, pady=(8, 2))
        clear_btn(act1, "+ Add", self.add_domain)
        clear_btn(act1, "− Remove", self.remove_domain)
        clear_btn(act1, "Save", self.save_domains)

        self._act2 = tk.Frame(left, bg=card)
        act2 = self._act2
        act2.pack(fill=tk.X, padx=10, pady=(2, 10))
        clear_btn(act2, "+ Group", self.add_group)
        clear_btn(act2, "− Group", self.remove_group)
        clear_btn(act2, "Import", self.import_group)
        clear_btn(act2, "Load", self.load_group_file)

        # ----- Right: results -----
        self._right_panel = tk.Frame(paned, bg=card, highlightbackground=border, highlightthickness=1)
        right = self._right_panel
        paned.add(right, weight=3)

        self._hdr_right = tk.Frame(right, bg=card)
        hdr = self._hdr_right
        hdr.pack(fill=tk.X, padx=12, pady=(10, 4))
        self._lbl_results = tk.Label(hdr, text="SCAN RESULTS", bg=card, fg=text3,
                                     font=("Segoe UI", 9, "bold"))
        self._lbl_results.pack(side=tk.LEFT)
        self._lbl_results_hint = tk.Label(hdr, text="Double-click a domain for full details", bg=card, fg=text3,
                                          font=("Segoe UI", 8))
        self._lbl_results_hint.pack(side=tk.RIGHT)

        self._tree_wrap = tk.Frame(right, bg=card)
        tree_wrap = self._tree_wrap
        tree_wrap.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        cols = ("domain", "overall", "score", "headers", "vuln", "owasp", "status", "issues", "last_scan")
        self.tree = ttk.Treeview(tree_wrap, columns=cols, show="headings", height=16, style="SOC.Treeview")
        for c, title, w, anchor in (
            ("domain", "Domain", 140, "w"),
            ("overall", "Overall", 60, "center"),
            ("score", "Score", 50, "center"),
            ("headers", "Headers", 55, "center"),
            ("vuln", "Vuln", 50, "center"),
            ("owasp", "OWASP", 55, "center"),
            ("status", "Status", 65, "center"),
            ("issues", "Key Issues", 180, "w"),
            ("last_scan", "Last Scan", 100, "w"),
        ):
            self.tree.heading(c, text=title)
            self.tree.column(c, width=w, anchor=anchor)

        tree_sb = ttk.Scrollbar(tree_wrap, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=tree_sb.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        tree_sb.pack(side=tk.RIGHT, fill=tk.Y)

        # Severity / rating row colors (subtle on dark)
        self.tree.tag_configure("A+", background="#022C22", foreground="#10B981")
        self.tree.tag_configure("A", background="#022C22", foreground="#10B981")
        self.tree.tag_configure("B", background="#052E16", foreground="#34D399")
        self.tree.tag_configure("C", background="#1C1917", foreground="#F59E0B")
        self.tree.tag_configure("D", background="#1C0A0A", foreground="#FB7185")
        self.tree.tag_configure("F", background="#1C0A0A", foreground="#FF0055")
        self.tree.tag_configure("ERR", background="#1C0A0A", foreground="#FF0055")

        self.tree.bind("<Double-1>", self.on_result_double_click)
        self.tree.bind("<Return>", self.on_result_double_click)

        # Empty-state hint (shown until first results)
        self.empty_hint = tk.Label(
            right,
            text="No active scan running.\nSelect a domain group and click  Scan All  to begin.",
            bg=card, fg=text3, font=("Segoe UI", 11), justify=tk.CENTER,
        )
        # placed after first scan is hidden via _add_result_row / start_scan

        # ========== ACTIVITY LOG ==========
        self._log_outer = tk.Frame(self, bg=C["log_bg"], highlightbackground=border, highlightthickness=1)
        log_outer = self._log_outer
        log_outer.pack(fill=tk.X, padx=10, pady=(0, 10))
        self._log_hdr = tk.Frame(log_outer, bg=C["log_bg"])
        log_hdr = self._log_hdr
        log_hdr.pack(fill=tk.X, padx=10, pady=(6, 2))
        self._lbl_log = tk.Label(log_hdr, text="ACTIVITY LOG", bg=C["log_bg"], fg=text3,
                                 font=("Segoe UI", 9, "bold"))
        self._lbl_log.pack(side=tk.LEFT)
        self.log = scrolledtext.ScrolledText(
            log_outer, height=5, font=("Consolas", 10), state=tk.DISABLED,
            bg=C["log_bg"], fg=text2, insertbackground=text2,
            borderwidth=0, highlightthickness=0,
        )
        self.log.pack(fill=tk.X, padx=8, pady=(0, 8))
        self.log.tag_configure("ts", foreground=text3)
        self.log.tag_configure("info", foreground=C["blue"])
        self.log.tag_configure("ok", foreground=C["emerald"])
        self.log.tag_configure("err", foreground=C["crimson"])
        self.log.tag_configure("warn", foreground=C["amber"])

        self._update_auto_label()


    def _refresh_group_combo(self):
        groups = ["All"] + sorted(self.cfg.get("groups", {}).keys())
        self.group_combo["values"] = groups
        if self.group_var.get() not in groups:
            self.group_var.set("All")

    def _on_group_changed(self):
        self.cfg["active_group"] = self.group_var.get()
        save_config(self.cfg)
        self._load_domains_into_list()

    def _get_current_domains(self) -> List[str]:
        group = self.group_var.get()
        if group == "All":
            # union of all groups + loose domains
            domains = set(self.cfg.get("domains", []))
            for g_domains in self.cfg.get("groups", {}).values():
                domains.update(g_domains)
            return sorted(domains)
        return list(self.cfg.get("groups", {}).get(group, []))

    def _load_domains_into_list(self):
        self.domain_list.delete(0, tk.END)
        for d in self._get_current_domains():
            self.domain_list.insert(tk.END, d)

    def add_domain(self):
        domain = simpledialog.askstring("Add Domain", "Enter domain or URL:", parent=self)
        if not domain or not domain.strip():
            return
        domain = domain.strip()
        group = self.group_var.get()

        if group == "All":
            if domain not in self.cfg.get("domains", []):
                self.cfg.setdefault("domains", []).append(domain)
        else:
            self.cfg.setdefault("groups", {}).setdefault(group, [])
            if domain not in self.cfg["groups"][group]:
                self.cfg["groups"][group].append(domain)

        save_config(self.cfg)
        self._load_domains_into_list()
        self.log_msg(f"Added: {domain}  (group: {group})")

    def remove_domain(self):
        sel = list(self.domain_list.curselection())
        if not sel:
            return
        group = self.group_var.get()
        to_remove = [self.domain_list.get(i) for i in sel]

        if group == "All":
            self.cfg["domains"] = [d for d in self.cfg.get("domains", []) if d not in to_remove]
            for g in self.cfg.get("groups", {}):
                self.cfg["groups"][g] = [d for d in self.cfg["groups"][g] if d not in to_remove]
        else:
            self.cfg["groups"][group] = [d for d in self.cfg["groups"].get(group, []) if d not in to_remove]

        save_config(self.cfg)
        self._load_domains_into_list()
        self.log_msg(f"Removed {len(to_remove)} domain(s)")

    def save_domains(self):
        # Current list becomes the content of the active group
        domains = list(self.domain_list.get(0, tk.END))
        group = self.group_var.get()
        if group == "All":
            self.cfg["domains"] = domains
        else:
            self.cfg.setdefault("groups", {})[group] = domains
        save_config(self.cfg)
        self.log_msg(f"Saved {len(domains)} domain(s) in group '{group}'")
        messagebox.showinfo("Saved", f"{len(domains)} domain(s) saved to group '{group}'.")

    def add_group(self):
        """Create a new empty group."""
        name = simpledialog.askstring("Add Group", "Enter name for the new group (e.g. XPAL, Production):", parent=self)
        if not name or not name.strip():
            return
        name = name.strip()
        if name == "All":
            messagebox.showwarning("Invalid name", "'All' is reserved. Choose another name.")
            return
        if name in self.cfg.get("groups", {}):
            messagebox.showinfo("Exists", f"Group '{name}' already exists. Switching to it.")
            self.group_var.set(name)
            self._load_domains_into_list()
            return

        self.cfg.setdefault("groups", {})[name] = []
        save_config(self.cfg)
        self._refresh_group_combo()
        self.group_var.set(name)
        self._load_domains_into_list()
        self.log_msg(f"Created new group: {name}")
        messagebox.showinfo("Group created", f"Group '{name}' created.\nYou can now Add domains or Load a file into it.")

    def remove_group(self):
        """Delete the currently selected group."""
        group = self.group_var.get()
        if group == "All":
            messagebox.showwarning("Cannot remove", "You cannot remove the 'All' view.")
            return
        if group not in self.cfg.get("groups", {}):
            messagebox.showinfo("Not found", f"Group '{group}' does not exist.")
            return

        count = len(self.cfg["groups"].get(group, []))
        if not messagebox.askyesno("Remove Group", f"Delete group '{group}' and its {count} domain(s)?\n\nThis cannot be undone."):
            return

        del self.cfg["groups"][group]
        save_config(self.cfg)
        self._refresh_group_combo()
        self.group_var.set("All")
        self._load_domains_into_list()
        self.log_msg(f"Removed group: {group}")
        messagebox.showinfo("Removed", f"Group '{group}' has been deleted.")

    def import_group(self):
        """Import a list of domains and create / update a named group."""
        name = simpledialog.askstring("Import Group", "Name for this group (e.g. XPAL, Production):", parent=self)
        if not name or not name.strip():
            return
        name = name.strip()

        path = filedialog.askopenfilename(
            title=f"Select domain list for group '{name}'",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return

        try:
            with open(path, "r", encoding="utf-8") as f:
                domains = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
        except Exception as e:
            messagebox.showerror("Import failed", str(e))
            return

        self.cfg.setdefault("groups", {})[name] = domains
        save_config(self.cfg)

        # Also copy the file into domain_groups folder for reference
        try:
            dest = GROUPS_DIR / f"{name}.txt"
            shutil.copy2(path, dest)
        except Exception:
            pass

        self._refresh_group_combo()
        self.group_var.set(name)
        self._load_domains_into_list()
        self.log_msg(f"Imported group '{name}' with {len(domains)} domain(s)")
        messagebox.showinfo("Imported", f"Group '{name}' created with {len(domains)} domains.")

    def load_group_file(self):
        """Load any .txt and merge into current group or All."""
        path = filedialog.askopenfilename(
            title="Load domain list",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                new_domains = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
        except Exception as e:
            messagebox.showerror("Load failed", str(e))
            return

        group = self.group_var.get()
        if group == "All":
            existing = set(self.cfg.get("domains", []))
            for d in new_domains:
                if d not in existing:
                    self.cfg.setdefault("domains", []).append(d)
        else:
            existing = set(self.cfg.get("groups", {}).get(group, []))
            self.cfg.setdefault("groups", {}).setdefault(group, [])
            for d in new_domains:
                if d not in existing:
                    self.cfg["groups"][group].append(d)

        save_config(self.cfg)
        self._load_domains_into_list()
        self.log_msg(f"Loaded {len(new_domains)} domain(s) into '{group}'")


    # ------------------------------------------------------------------
    # Tech stack + basic vulnerability scan
    # ------------------------------------------------------------------


    # ------------------------------------------------------------------
    # Progress / loading popup
    # ------------------------------------------------------------------

    def _show_progress(self, title: str = "Scanning…", message: str = "Please wait…"):
        """Progress popup while scans run."""
        self._hide_progress()
        win = tk.Toplevel(self)
        win.title(title)
        win.geometry("440x180")
        win.resizable(False, False)
        win.transient(self)
        win.configure(bg=C["bg"])
        try:
            win.attributes("-topmost", True)
        except Exception:
            pass
        try:
            self.update_idletasks()
            x = self.winfo_rootx() + max(0, (self.winfo_width() // 2) - 220)
            y = self.winfo_rooty() + max(0, (self.winfo_height() // 2) - 90)
            win.geometry(f"440x180+{x}+{y}")
        except Exception:
            pass

        outer = tk.Frame(win, bg=C["bg"], padx=10, pady=10)
        outer.pack(fill=tk.BOTH, expand=True)
        frame = tk.Frame(outer, bg=C["card"], padx=16, pady=12,
                        highlightbackground=C["cyan"], highlightthickness=1)
        frame.pack(fill=tk.BOTH, expand=True)

        self._progress_title_lbl = tk.Label(
            frame, text=title, font=("Segoe UI", 12, "bold"),
            bg=C["card"], fg=C["cyan"],
        )
        self._progress_title_lbl.pack(anchor=tk.W)

        self._progress_msg = tk.StringVar(value=message)
        tk.Label(
            frame, textvariable=self._progress_msg, font=("Segoe UI", 9),
            bg=C["card"], fg=C["text2"], wraplength=380, justify=tk.LEFT,
        ).pack(anchor=tk.W, pady=(6, 10))

        bar_row = tk.Frame(frame, bg=C["card"])
        bar_row.pack(fill=tk.X)
        self._progress_pct = tk.StringVar(value="0%")
        self._progress_canvas = tk.Canvas(
            bar_row, height=12, bg=C["border"], highlightthickness=0, bd=0,
        )
        self._progress_canvas.pack(side=tk.LEFT, fill=tk.X, expand=True)
        tk.Label(
            bar_row, textvariable=self._progress_pct, font=("Segoe UI", 9, "bold"),
            bg=C["card"], fg=C["emerald"], width=5,
        ).pack(side=tk.RIGHT, padx=(8, 0))

        # Button row (empty until finish)
        self._progress_btn_row = tk.Frame(frame, bg=C["card"])
        self._progress_btn_row.pack(fill=tk.X, pady=(12, 0))

        self._progress_win = win
        self._progress_ok_btn = None
        self._progress_done = False
        win.protocol("WM_DELETE_WINDOW", lambda: None)
        self._update_progress_bar(0)
        try:
            win.update()
        except Exception:
            pass

    def _update_progress_bar(self, percent: float):
        percent = max(0.0, min(100.0, float(percent or 0)))
        try:
            self._progress_pct.set(f"{int(percent)}%")
            c = self._progress_canvas
            c.update_idletasks()
            w = max(int(c.winfo_width()), 280)
            fill = int(w * percent / 100.0)
            c.delete("all")
            c.create_rectangle(0, 0, w, 12, fill=C["border"], outline="")
            c.create_rectangle(0, 0, fill, 12, fill=C["emerald"], outline="")
        except Exception:
            pass

    def _update_progress(self, message: str = None, percent: float = None):
        try:
            if getattr(self, "_progress_done", False):
                return
            if message is not None and hasattr(self, "_progress_msg"):
                self._progress_msg.set(message)
            if percent is not None:
                self._update_progress_bar(percent)
                # When bar hits 100%, immediately offer OK (don't wait only for finish)
                if float(percent) >= 99.5 and not getattr(self, "_progress_ok_btn", None):
                    self._finish_progress(message or "Scan complete. Click OK.")
                    return
            if getattr(self, "_progress_win", None):
                self._progress_win.update_idletasks()
        except Exception:
            pass

    def _hide_progress(self):
        win = getattr(self, "_progress_win", None)
        self._progress_win = None
        self._progress_ok_btn = None
        self._progress_done = False
        if win is not None:
            try:
                win.destroy()
            except Exception:
                pass

    def _finish_progress(self, message: str = "Scan complete."):
        """Mark complete, show OK, auto-close shortly after."""
        try:
            win = getattr(self, "_progress_win", None)
            if win is None:
                return
            self._progress_done = True
            try:
                self._progress_msg.set(message)
            except Exception:
                pass
            self._update_progress_bar(100)

            # Allow window close
            try:
                win.protocol("WM_DELETE_WINDOW", self._hide_progress)
            except Exception:
                pass

            # OK button
            if not self._progress_ok_btn:
                try:
                    for child in self._progress_btn_row.winfo_children():
                        child.destroy()
                except Exception:
                    pass
                try:
                    btn = tk.Button(
                        self._progress_btn_row,
                        text="OK",
                        command=self._hide_progress,
                        font=("Segoe UI", 10, "bold"),
                        bg=C["emerald"],
                        fg="#FFFFFF",
                        activebackground="#059669",
                        activeforeground="#FFFFFF",
                        relief=tk.FLAT,
                        padx=28,
                        pady=6,
                        cursor="hand2",
                    )
                    btn.pack()
                    self._progress_ok_btn = btn
                except Exception:
                    pass

            try:
                win.geometry("440x200")
                win.update()
            except Exception:
                pass

            # Hard auto-close after 2.5s so it never sticks
            try:
                win.after(2500, self._hide_progress)
            except Exception:
                self._hide_progress()
        except Exception:
            self._hide_progress()

    def tech_only_dialog(self):
        domain = None
        sel = self.tree.selection()
        if sel:
            domain = self.tree.item(sel[0], "values")[0]
        if not domain:
            domain = simpledialog.askstring("Tech Stack Scan", "Enter domain or URL:", parent=self)
        if not domain or not domain.strip():
            return
        domain = domain.strip()
        self.log_msg(f"Tech stack scan: {domain}")
        self.status_var.set(f"Tech scanning {domain}...")
        self._show_progress("Tech Stack Scan", f"Detecting technologies on {domain}…")

        def worker():
            try:
                self.after(0, lambda: self._update_progress(f"Fingerprinting {domain}…", 30))
                tech = run_tech_scan(domain)
                self.after(0, lambda: self._update_progress("Building report…", 90))
                report = {
                    "url": domain,
                    "technologies": tech.get("technologies", []),
                    "headers_sample": tech.get("headers_sample", {}),
                    "status_code": tech.get("status_code"),
                    "final_url": tech.get("final_url"),
                    "path_findings": [], "cookie_issues": [], "cors_issues": [],
                    "method_issues": [], "tls_issues": [], "cves": [],
                    "error": tech.get("error"),
                }
                self.after(0, lambda: self.show_tech_vuln_results(report, title_prefix="Tech Stack"))
                self.after(0, lambda: self.log_msg(f"Tech done: {domain} – {len(report['technologies'])} technologies"))
                self.after(0, lambda: self.status_var.set(f"Tech done: {domain}"))
            except Exception as e:
                self.after(0, lambda: self.log_msg(f"Tech error: {e}"))
            finally:
                self.after(0, lambda: self._finish_progress("Tech stack scan complete."))

        threading.Thread(target=worker, daemon=True).start()

    def vuln_only_dialog(self):
        domain = None
        sel = self.tree.selection()
        if sel:
            domain = self.tree.item(sel[0], "values")[0]
        if not domain:
            domain = simpledialog.askstring(
                "Vulnerability Scan",
                "Enter domain or URL:\n(Paths, CORS, TLS, cookies + NVD CVEs – may take a few minutes)",
                parent=self,
            )
        if not domain or not domain.strip():
            return
        domain = domain.strip()
        self.log_msg(f"Vuln scan: {domain}")
        self.status_var.set(f"Vuln scanning {domain}...")
        self._show_progress("Vulnerability Scan", f"Scanning {domain} (paths, TLS, OWASP, CVEs)…")

        def worker():
            try:
                self.after(0, lambda: self._update_progress("Running vulnerability checks…", 20))
                # Full recon with CVEs for single target
                full = run_full_recon(domain, include_cves=True)
                self.after(0, lambda: self._update_progress("Running OWASP Top 10 checks…", 70))
                tech, vuln = full.get("tech") or {}, full.get("vuln") or {}
                try:
                    owasp = run_owasp_scan(domain, technologies=tech.get("technologies"))
                except Exception:
                    owasp = {}
                report = {
                    "url": domain,
                    "technologies": tech.get("technologies", []),
                    "headers_sample": tech.get("headers_sample", {}),
                    "status_code": tech.get("status_code"),
                    "final_url": tech.get("final_url"),
                    "path_findings": vuln.get("path_findings", []),
                    "cookie_issues": vuln.get("cookie_issues", []),
                    "cors_issues": vuln.get("cors_issues", []),
                    "method_issues": vuln.get("method_issues", []),
                    "tls_issues": vuln.get("tls_issues", []),
                    "cves": vuln.get("cves", []),
                    "summary": vuln.get("summary", {}),
                    "owasp": owasp,
                    "error": full.get("error"),
                }
                self.after(0, lambda: self.show_tech_vuln_results(report, title_prefix="Vuln Scan (incl. OWASP T10)"))
                s = report.get("summary") or {}
                self.after(0, lambda: self.log_msg(
                    f"Vuln done: {domain} – crit={s.get('critical',0)} high={s.get('high',0)} "
                    f"med={s.get('medium',0)} cves={len(report.get('cves',[]))}"
                ))
                self.after(0, lambda: self.status_var.set(f"Vuln done: {domain}"))
            except Exception as e:
                self.after(0, lambda: self.log_msg(f"Vuln error: {e}"))
            finally:
                self.after(0, lambda: self._finish_progress("Vulnerability scan complete."))

        threading.Thread(target=worker, daemon=True).start()

    def tech_vuln_dialog(self):
        """Combined – kept for compatibility."""
        self.vuln_only_dialog()


    def _sev_tag(self, tree, severity: str):
        s = (severity or "").lower()
        if s in ("critical", "high"):
            return "sev_high"
        if s == "medium":
            return "sev_med"
        if s == "low":
            return "sev_low"
        if s == "pass":
            return "sev_pass"
        return "sev_info"

    def _style_sev_tree(self, tree):
        tree.tag_configure("sev_high", background="#FFCDD2")
        tree.tag_configure("sev_med", background="#FFE0B2")
        tree.tag_configure("sev_low", background="#FFF9C4")
        tree.tag_configure("sev_info", background="#E3F2FD")
        tree.tag_configure("sev_pass", background="#C8E6C9")

    def show_tech_vuln_results(self, report: dict, title_prefix: str = "Tech & Vuln"):
        url = report.get("url", "?")
        win = tk.Toplevel(self)
        win.title(f"{title_prefix} – {url}")
        win.geometry("860x640")
        win.minsize(700, 500)
        win.transient(self)
        style_dialog(win)

        # ===== Header banner =====
        hdr = tk.Frame(win, bg=C["card"], padx=14, pady=12)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text=title_prefix, font=("Segoe UI", 11), fg=C["cyan"], bg=C["card"]).pack(anchor=tk.W)
        tk.Label(hdr, text=url, font=("Segoe UI", 14, "bold"), fg=C["text"], bg=C["card"]).pack(anchor=tk.W)
        if report.get("error"):
            tk.Label(hdr, text=f"Error: {report['error']}", font=("Segoe UI", 9), fg=C["crimson"], bg=C["card"]).pack(anchor=tk.W)

        # ===== Summary strip =====
        s = report.get("summary") or {}
        owasp = report.get("owasp") or {}
        os_ = owasp.get("summary") or {}
        strip = tk.Frame(win, bg=C["border"], padx=12, pady=8)
        strip.pack(fill=tk.X)
        techs = report.get("technologies") or []
        summary_bits = [
            f"Technologies: {len(techs)}",
            f"Vuln C/H/M/L: {s.get('critical',0)}/{s.get('high',0)}/{s.get('medium',0)}/{s.get('low',0)}",
            f"Paths: {len(report.get('path_findings') or [])}",
            f"CVEs: {len(report.get('cves') or [])}",
        ]
        if owasp:
            summary_bits.append(f"OWASP risk: {owasp.get('risk_label', '–')} ({owasp.get('risk_score', '–')}/100)")
        tk.Label(strip, text="   ·   ".join(summary_bits), font=("Segoe UI", 9), bg=C["border"], fg=C["text"]).pack(anchor=tk.W)

        nb = ttk.Notebook(win)
        nb.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

        # --- Overview tab ---
        tab_ov = ttk.Frame(nb, padding=8)
        nb.add(tab_ov, text="Overview")
        ov = scrolledtext.ScrolledText(tab_ov, height=18, font=("Segoe UI", 10), wrap=tk.WORD, bg="#FAFAFA")
        lines = []
        lines.append(f"TARGET\n  {url}\n  Final: {report.get('final_url') or '–'}  |  HTTP {report.get('status_code') or '–'}\n")
        lines.append("TECHNOLOGY STACK")
        if techs:
            for titem in techs:
                ver = titem.get("version") or "version n/a"
                lines.append(f"  • {titem.get('name')}  [{ver}]  — {titem.get('category','')}")
        else:
            lines.append("  (none detected)")
        lines.append("\nVULNERABILITY SUMMARY")
        lines.append(f"  Critical: {s.get('critical',0)}   High: {s.get('high',0)}   Medium: {s.get('medium',0)}   Low: {s.get('low',0)}   Info: {s.get('info',0)}")
        high_paths = [p for p in (report.get("path_findings") or []) if p.get("severity") in ("critical", "high")]
        if high_paths:
            lines.append("\nCRITICAL / HIGH PATHS")
            for p in high_paths:
                lines.append(f"  • [{p.get('severity')}] {p.get('path')} — {p.get('description')}")
        if owasp:
            lines.append(f"\nOWASP TOP 10")
            lines.append(f"  Risk label: {owasp.get('risk_label')}   Score: {owasp.get('risk_score')}/100")
            for f in owasp.get("findings") or []:
                if f.get("severity") in ("critical", "high", "medium"):
                    lines.append(f"  • [{f.get('category')}] [{f.get('severity')}] {f.get('title')}")
        ov.insert(tk.END, "\n".join(lines))
        ov.configure(state=tk.DISABLED)
        ov.pack(fill=tk.BOTH, expand=True)

        # --- Technology ---
        tab_tech = ttk.Frame(nb, padding=6)
        nb.add(tab_tech, text="Technology")
        cols = ("name", "version", "category", "evidence")
        tree = ttk.Treeview(tab_tech, columns=cols, show="headings", height=14)
        for c, h, w in zip(cols, ["Technology", "Version", "Category", "Evidence"], [150, 90, 120, 320]):
            tree.heading(c, text=h)
            tree.column(c, width=w)
        for titem in techs:
            tree.insert("", tk.END, values=(
                titem.get("name", ""),
                titem.get("version") or "–",
                titem.get("category", ""),
                (titem.get("evidence") or "")[:100],
            ))
        tree.pack(fill=tk.BOTH, expand=True)
        if report.get("headers_sample"):
            ttk.Label(tab_tech, text="Headers: " + ", ".join(f"{k}={v}" for k, v in report["headers_sample"].items()),
                      font=("Segoe UI", 8), foreground="#555").pack(anchor=tk.W, pady=4)

        # --- Findings (paths + cookies + cors + methods + tls) ---
        tab_find = ttk.Frame(nb, padding=6)
        nb.add(tab_find, text="Vuln Findings")
        fcols = ("severity", "type", "item", "description")
        ftree = ttk.Treeview(tab_find, columns=fcols, show="headings", height=14)
        for c, h, w in zip(fcols, ["Severity", "Type", "Item", "Description"], [80, 90, 160, 360]):
            ftree.heading(c, text=h)
            ftree.column(c, width=w)
        self._style_sev_tree(ftree)
        def add_rows(items, typ, item_key):
            for it in items or []:
                sev = it.get("severity", "info")
                ftree.insert("", tk.END, values=(
                    sev.upper(), typ, it.get(item_key) or it.get("check") or it.get("cookie") or "",
                    it.get("description", "")[:140],
                ), tags=(self._sev_tag(ftree, sev),))
        add_rows(report.get("path_findings"), "Path", "path")
        add_rows(report.get("cookie_issues"), "Cookie", "cookie")
        add_rows(report.get("cors_issues"), "CORS", "check")
        add_rows(report.get("method_issues"), "Method", "check")
        add_rows(report.get("tls_issues"), "TLS", "check")
        ftree.pack(fill=tk.BOTH, expand=True)

        # --- CVEs ---
        tab_cve = ttk.Frame(nb, padding=6)
        nb.add(tab_cve, text="CVEs (NVD)")
        vcols = ("cve", "severity", "score", "product", "description")
        vtree = ttk.Treeview(tab_cve, columns=vcols, show="headings", height=12)
        for c, h, w in zip(vcols, ["CVE", "Severity", "Score", "Product", "Description"], [120, 80, 55, 110, 320]):
            vtree.heading(c, text=h)
            vtree.column(c, width=w)
        self._style_sev_tree(vtree)
        for v in report.get("cves") or []:
            sev = v.get("severity", "info")
            vtree.insert("", tk.END, values=(
                v.get("cve_id", ""), sev, v.get("score") if v.get("score") is not None else "–",
                f"{v.get('product','')} {v.get('version','')}".strip(),
                (v.get("description") or "")[:120],
            ), tags=(self._sev_tag(vtree, sev),))
        vtree.pack(fill=tk.BOTH, expand=True)
        ttk.Label(tab_cve, text="NIST NVD keyword search (free, rate-limited). Not a full exploit verification.",
                  font=("Segoe UI", 8), foreground="#666").pack(anchor=tk.W, pady=4)

        # --- OWASP detailed ---
        if owasp.get("findings") is not None:
            tab_ow = ttk.Frame(nb, padding=6)
            nb.add(tab_ow, text="OWASP Top 10")
            top = tk.Frame(tab_ow, bg="#E8F5E9" if owasp.get("risk_label") in ("Good", "Low") else "#FFEBEE", padx=10, pady=8)
            top.pack(fill=tk.X, pady=(0, 6))
            tk.Label(top, text=f"OWASP Risk: {owasp.get('risk_label', '–')}   Score: {owasp.get('risk_score', '–')}/100",
                     font=("Segoe UI", 12, "bold"),
                     bg=top["bg"], fg="#1B5E20" if owasp.get("risk_label") in ("Good", "Low") else "#B71C1C").pack(anchor=tk.W)
            tk.Label(top, text=f"high={os_.get('high',0)}  medium={os_.get('medium',0)}  low={os_.get('low',0)}  info={os_.get('info',0)}  pass={os_.get('pass',0)}",
                     font=("Segoe UI", 9), bg=top["bg"]).pack(anchor=tk.W)
            ocols = ("cat", "name", "severity", "title", "detail")
            otree = ttk.Treeview(tab_ow, columns=ocols, show="headings", height=12)
            for c, h, w in zip(ocols, ["ID", "Category", "Severity", "Finding", "Detail"], [45, 140, 75, 180, 280]):
                otree.heading(c, text=h)
                otree.column(c, width=w)
            self._style_sev_tree(otree)
            try:
                from owasp_scanner import OWASP_CATEGORIES as OC
            except Exception:
                OC = {}
            # issues first, then passes
            ordered = sorted(owasp.get("findings") or [], key=lambda f: 0 if f.get("severity") != "pass" else 1)
            for f in ordered:
                sev = f.get("severity", "info")
                otree.insert("", tk.END, values=(
                    f.get("category", ""),
                    OC.get(f.get("category", ""), f.get("category_name", "")),
                    sev.upper(),
                    f.get("title", ""),
                    (f.get("detail") or "")[:130],
                ), tags=(self._sev_tag(otree, sev),))
            otree.pack(fill=tk.BOTH, expand=True)
            ttk.Label(tab_ow, text="Mapped to OWASP Top 10:2021 · Automated signals only · Not a full penetration test",
                      font=("Segoe UI", 8), foreground="#666").pack(anchor=tk.W, pady=4)

        ttk.Button(win, text="Close", command=win.destroy).pack(pady=8)

    def show_owasp_results(self, report: dict):
        # Present OWASP-only results using the same attractive vuln window shape
        wrapped = {
            "url": report.get("url"),
            "technologies": [],
            "path_findings": [],
            "cookie_issues": [],
            "cors_issues": [],
            "method_issues": [],
            "tls_issues": [],
            "cves": [],
            "summary": report.get("summary") or {},
            "owasp": report,
            "error": report.get("error"),
        }
        self.show_tech_vuln_results(wrapped, title_prefix="OWASP Top 10 Assessment")


    def quick_scan_dialog(self):
        domain = simpledialog.askstring("Quick Scan", "Enter domain or URL to scan now:", parent=self)
        if not domain or not domain.strip():
            return
        domain = domain.strip()
        self.log_msg(f"Quick Scan started for: {domain}")
        self.status_var.set(f"Quick scanning {domain}...")
        self.scanning = True

        def worker():
            try:
                res = scan_domain(domain)
                self.results = [res]
                self._save_to_history(res)
                self.after(0, lambda: self.tree.delete(*self.tree.get_children()))
                self.after(0, lambda: self._add_result_row(res))
                self.after(0, lambda: self.log_msg(f"Quick Scan finished: {domain} → {res.get('grade', 'ERR')}"))
                self.after(0, lambda: self.status_var.set(f"Quick Scan done: {domain}"))
                # Optionally open details automatically
                self.after(100, lambda: self.show_domain_details(res))
            except Exception as e:
                self.after(0, lambda: self.log_msg(f"Quick Scan error: {e}"))
            finally:
                self.scanning = False
                self.after(0, lambda: self._finish_progress("Quick scan complete."))

        threading.Thread(target=worker, daemon=True).start()

    # ------------------------------------------------------------------
    # Full Scan
    # ------------------------------------------------------------------
    def start_scan(self, auto: bool = False):
        if self.scanning:
            messagebox.showwarning("Busy", "A scan is already running.")
            return
        domains = self._get_current_domains()
        if not domains:
            messagebox.showwarning("No domains", "Add or import domains first.")
            return

        self._show_progress("Scan All", f"Starting scan of {len(domains)} domain(s)…")
        self.scanning = True
        try:
            if hasattr(self, "progress_line"):
                if USE_CTK:
                    self.progress_line.configure(fg_color=C["emerald"])
                else:
                    self.progress_line.configure(bg=C["emerald"])
        except Exception:
            pass

        self.status_var.set("Scanning…")
        self.log_msg(f"{'Auto-' if auto else ''}Scan started ({len(domains)} domains) – group: {self.group_var.get()}")
        self.tree.delete(*self.tree.get_children())

        def worker():
            results = []
            try:
                total = len(domains)
                for i, domain in enumerate(domains, 1):
                    pct = (i - 1) / total * 100
                    self.after(0, lambda d=domain, i=i, p=pct: (
                        self.status_var.set(f"Scanning {i}/{total}: {d}"),
                        self._update_progress(f"Scanning {i}/{total}: {d}", p),
                    ))
                    res = scan_domain(domain)
                    # Attach tech + vuln (paths/cors/tls/cookies; skip NVD CVEs for speed on bulk)
                    try:
                        recon = run_full_recon(domain, include_cves=False)
                        res["tech"] = recon.get("tech") or {}
                        res["vuln"] = recon.get("vuln") or {}
                        try:
                            res["owasp"] = run_owasp_scan(domain, technologies=(res["tech"] or {}).get("technologies"))
                        except Exception as ox:
                            res["owasp"] = {"error": str(ox), "findings": [], "summary": {}}
                        compute_security_rating(res)
                    except Exception as ex:
                        res["tech"] = {"error": str(ex), "technologies": []}
                        res["vuln"] = {"error": str(ex), "summary": {}}
                        res["owasp"] = {"error": str(ex), "findings": [], "summary": {}}
                        compute_security_rating(res)
                    results.append(res)
                    self._save_to_history(res)
                    done_pct = i / total * 100
                    self.after(0, lambda r=res, p=done_pct, d=domain: (
                        self._add_result_row(r),
                        self._update_progress(f"Completed {d}", p),
                    ))

                # Always write reports to a writable location (never Program Files)
                configured = Path(self.cfg.get("output_dir", REPORTS_DIR))
                out_dir = configured
                try:
                    out_dir.mkdir(parents=True, exist_ok=True)
                    # Test write permission
                    test_file = out_dir / ".write_test"
                    test_file.write_text("ok")
                    test_file.unlink()
                except Exception:
                    out_dir = REPORTS_DIR  # fallback to LocalAppData
                    out_dir.mkdir(parents=True, exist_ok=True)
                    self.after(0, lambda: self.log_msg(
                        f"Note: configured folder not writable – using {out_dir}"
                    ))

                # Ensure every result has a combined security rating before PDF
                for _r in results:
                    try:
                        compute_security_rating(_r)
                    except Exception:
                        _r.setdefault("security_rating", _r.get("grade", "F"))
                        _r.setdefault("security_score", _r.get("overall_score", 0))
                        _r.setdefault("rating_breakdown", {
                            "headers": _r.get("overall_score", 0),
                            "vuln": "–",
                            "owasp": "–",
                        })

                ts = now_pkt().strftime("%Y%m%d_%H%M%S")
                pdf_path = out_dir / f"security_headers_report_{ts}.pdf"
                generate_pdf(results, str(pdf_path), now_pkt())
                self.after(0, lambda: self.log_msg(
                    "PDF ratings: " + ", ".join(
                        f"{x.get('domain','?')}={x.get('security_rating','?')}({x.get('security_score','?')})"
                        for x in results[:8]
                    ) + ("…" if len(results) > 8 else "")
                ))
                try:
                    shutil.copy2(pdf_path, out_dir / "latest_report.pdf")
                except Exception:
                    pass

                self.results = results
                self.last_pdf = str(pdf_path)

                send_slack = (auto and self.cfg.get("send_slack_on_auto")) or (not auto and self.cfg.get("send_slack_on_manual"))
                if send_slack and self.cfg.get("slack_webhook"):
                    ok = send_slack_report(self.cfg["slack_webhook"], results, str(pdf_path))
                    self.after(0, lambda: self.log_msg("Slack report sent ✓" if ok else "Slack send failed ✗"))

                self.after(0, lambda: self.log_msg(f"Scan finished. PDF: {pdf_path}"))
                self.after(0, lambda: self.status_var.set(f"Done – {len(results)} domains"))
                self.after(0, lambda: self._finish_progress(
                    f"Scan complete — {len(results)} domain(s). Click OK."
                ))
            except Exception as e:
                self.after(0, lambda: self.log_msg(f"Scan error: {e}"))
                self.after(0, lambda: self._finish_progress("Scan finished with errors. Click OK."))
            finally:
                self.scanning = False
                def _reset_line():
                    try:
                        if hasattr(self, "progress_line"):
                            if USE_CTK:
                                self.progress_line.configure(fg_color=C["border"])
                            else:
                                self.progress_line.configure(bg=C["border"])
                    except Exception:
                        pass
                self.after(0, _reset_line)

        threading.Thread(target=worker, daemon=True).start()

    def _save_to_history(self, res: Dict):
        domain = res.get("domain")
        if not domain:
            return
        entry = {
            "timestamp": res.get("timestamp"),
            "grade": res.get("grade"),
            "score": res.get("overall_score"),
            "status_code": res.get("status_code"),
            "error": res.get("error"),
            "evaluations": res.get("evaluations"),
            "headers_found": res.get("headers_found"),
            "info_leaks": res.get("info_leaks"),
            "final_url": res.get("final_url"),
        }
        self.history.setdefault(domain, [])
        self.history[domain].insert(0, entry)          # newest first
        self.history[domain] = self.history[domain][:30]  # keep last 30 scans
        save_history(self.history)

    def _add_result_row(self, r: Dict):
        domain = r.get("domain", "?")
        last = r.get("timestamp", "")[:16].replace("T", " ") if r.get("timestamp") else ""
        if r.get("error"):
            self.tree.insert("", tk.END, values=(domain, "ERR", "–", "Error", r["error"][:70], last), tags=("ERR",))
            return

        rating = r.get("security_rating") or r.get("grade") or "F"
        score = r.get("security_score", r.get("overall_score", 0))
        hdr = r.get("overall_score", 0)
        br = r.get("rating_breakdown") or {}
        vuln_sc = br.get("vuln", "–")
        owasp_sc = br.get("owasp", "–")
        owasp = r.get("owasp") or {}
        if owasp.get("risk_label"):
            owasp_sc = f"{owasp.get('risk_label')}"
        issues = []
        for key, ev in r.get("evaluations", {}).items():
            if not ev.get("present") or ev.get("score", 100) < 60:
                name = SECURITY_HEADERS.get(key, {}).get("name", key)
                issues.append(name.split("(")[0].strip())
        if owasp.get("risk_label") in ("High", "Medium"):
            issues.insert(0, f"OWASP:{owasp.get('risk_label')}")
        vs = (r.get("vuln") or {}).get("summary") or {}
        if vs.get("critical") or vs.get("high"):
            issues.insert(0, f"Vuln H:{vs.get('high',0)} C:{vs.get('critical',0)}")
        issue_str = ", ".join(issues[:3]) if issues else "Looking good"
        if len(issues) > 3:
            issue_str += "…"
        status = "● OK" if float(score or 0) >= 70 else ("● Warn" if float(score or 0) >= 40 else "● Fail")
        self.tree.insert("", tk.END, values=(
            domain, rating, f"{score}", f"{hdr}", f"{vuln_sc}", f"{owasp_sc}",
            status, issue_str, last
        ), tags=(rating,))

    # ------------------------------------------------------------------
    # Details + History popup
    # ------------------------------------------------------------------
    def on_result_double_click(self, event=None):
        sel = self.tree.selection()
        if not sel:
            return
        domain = self.tree.item(sel[0], "values")[0]
        result = next((r for r in self.results if r.get("domain") == domain), None)
        if not result and domain in self.history:
            # reconstruct a minimal result from latest history
            latest = self.history[domain][0]
            result = {"domain": domain, **latest}
        if result:
            self.show_domain_details(result)

    def show_domain_details(self, r: Dict):
        domain = r.get("domain", "Unknown")
        win = tk.Toplevel(self)
        win.title(f"Details – {domain}")
        win.geometry("780x640")
        win.minsize(600, 500)
        win.transient(self)
        style_dialog(win)

        header = tk.Frame(win, bg=C["card"], padx=12, pady=10)
        header.pack(fill=tk.X)
        grade = r.get("security_rating") or r.get("grade", "N/A")
        score = r.get("security_score", r.get("overall_score", r.get("score", 0)))
        br = r.get("rating_breakdown") or {}
        tk.Label(header, text=domain, font=("Segoe UI", 14, "bold"), bg=C["card"], fg=C["cyan"]).pack(side=tk.LEFT)
        tk.Label(header, text=f"  Rating {grade}  ({score}/100)", font=("Segoe UI", 12, "bold"),
                 bg=C["card"], fg=C["emerald"]).pack(side=tk.LEFT, padx=8)
        if br:
            tk.Label(header, text=f"  H:{br.get('headers','–')} V:{br.get('vuln','–')} O:{br.get('owasp','–')}",
                     font=("Segoe UI", 9), bg=C["card"], fg=C["text2"]).pack(side=tk.LEFT, padx=4)

        meta = tk.Frame(win, bg=C["bg"], padx=12, pady=4)
        meta.pack(fill=tk.X)
        tk.Label(meta, text=f"Final URL: {r.get('final_url', '–')}", font=("Segoe UI", 9),
                 bg=C["bg"], fg=C["text2"]).pack(anchor=tk.W)
        tk.Label(meta, text=f"Status: {r.get('status_code', '–')}   |   Scanned: {r.get('timestamp', '–')}",
                 font=("Segoe UI", 9), bg=C["bg"], fg=C["text2"]).pack(anchor=tk.W)

        ttk.Separator(win).pack(fill=tk.X, pady=6, padx=10)

        # Notebook: Current scan | History
        nb = ttk.Notebook(win)
        nb.pack(fill=tk.BOTH, expand=True, padx=10, pady=4)

        # --- Tab 1: Current evaluation ---
        tab1 = ttk.Frame(nb, padding=6)
        nb.add(tab1, text="Current Scan")

        cols = ("header", "status", "score", "details")
        detail_tree = ttk.Treeview(tab1, columns=cols, show="headings", height=11)
        detail_tree.heading("header", text="Header")
        detail_tree.heading("status", text="Status")
        detail_tree.heading("score", text="Score")
        detail_tree.heading("details", text="Issues / Notes")
        detail_tree.column("header", width=200)
        detail_tree.column("status", width=70, anchor=tk.CENTER)
        detail_tree.column("score", width=50, anchor=tk.CENTER)
        detail_tree.column("details", width=300)

        for key, meta_h in SECURITY_HEADERS.items():
            ev = r.get("evaluations", {}).get(key, {})
            present = "Present" if ev.get("present") else "Missing"
            sc = ev.get("score", 0)
            issues = "; ".join(ev.get("issues", [])) or "OK"
            if len(issues) > 90:
                issues = issues[:87] + "..."
            tag = "ok" if present == "Present" and sc >= 70 else ("warn" if present == "Present" else "miss")
            detail_tree.insert("", tk.END, values=(meta_h["name"], present, sc, issues), tags=(tag,))

        detail_tree.tag_configure("ok", background="#C8E6C9")
        detail_tree.tag_configure("warn", background="#FFF9C4")
        detail_tree.tag_configure("miss", background="#FFCDD2")
        detail_tree.pack(fill=tk.BOTH, expand=True)

        # --- Tech stack tab ---
        tab_tech = ttk.Frame(nb, padding=6)
        nb.add(tab_tech, text="Technology")
        tech = r.get("tech") or {}
        techs = tech.get("technologies") or []
        tcols = ("name", "version", "category")
        ttree = ttk.Treeview(tab_tech, columns=tcols, show="headings", height=12)
        ttree.heading("name", text="Technology")
        ttree.heading("version", text="Version")
        ttree.heading("category", text="Category")
        ttree.column("name", width=160)
        ttree.column("version", width=100)
        ttree.column("category", width=140)
        for item in techs:
            ttree.insert("", tk.END, values=(item.get("name", ""), item.get("version") or "–", item.get("category", "")))
        ttree.pack(fill=tk.BOTH, expand=True)
        if not techs:
            ttk.Label(tab_tech, text="No tech data – run Scan All or Tech Stack on this domain.").pack(anchor=tk.W, pady=6)

        # --- Vuln tab ---
        tab_vuln = ttk.Frame(nb, padding=6)
        nb.add(tab_vuln, text="Vulnerabilities")
        vuln = r.get("vuln") or {}
        vs = vuln.get("summary") or {}
        ttk.Label(tab_vuln, text=f"critical={vs.get('critical',0)} high={vs.get('high',0)} medium={vs.get('medium',0)} low={vs.get('low',0)}",
                  font=("Segoe UI", 9, "bold")).pack(anchor=tk.W)
        vtxt = scrolledtext.ScrolledText(tab_vuln, height=12, font=("Consolas", 9), wrap=tk.WORD)
        for label, key in (("Paths", "path_findings"), ("Cookies", "cookie_issues"), ("CORS", "cors_issues"),
                           ("Methods", "method_issues"), ("TLS", "tls_issues")):
            items = vuln.get(key) or []
            vtxt.insert(tk.END, f"=== {label} ({len(items)}) ===\n")
            for it in items[:15]:
                vtxt.insert(tk.END, f"  [{it.get('severity','?')}] {it.get('path') or it.get('check') or it.get('cookie') or ''}: {it.get('description','')}\n")
            vtxt.insert(tk.END, "\n")
        cves = vuln.get("cves") or []
        if cves:
            vtxt.insert(tk.END, f"=== CVEs ({len(cves)}) ===\n")
            for c in cves[:12]:
                vtxt.insert(tk.END, f"  {c.get('cve_id')} [{c.get('severity')}] {c.get('product')} {c.get('version')}: {(c.get('description') or '')[:80]}\n")
        vtxt.configure(state=tk.DISABLED)
        vtxt.pack(fill=tk.BOTH, expand=True)

        # --- OWASP tab ---
        tab_ow = ttk.Frame(nb, padding=6)
        nb.add(tab_ow, text="OWASP T10")
        owasp = r.get("owasp") or {}
        ttk.Label(tab_ow, text=f"Risk: {owasp.get('risk_label', '–')} ({owasp.get('risk_score', '–')}/100)",
                  font=("Segoe UI", 10, "bold")).pack(anchor=tk.W, pady=2)
        otxt = scrolledtext.ScrolledText(tab_ow, height=12, font=("Segoe UI", 9), wrap=tk.WORD)
        for f in owasp.get("findings") or []:
            otxt.insert(tk.END, f"[{f.get('category')}] [{f.get('severity','').upper()}] {f.get('title')}\n  {f.get('detail')}\n\n")
        if not owasp.get("findings"):
            otxt.insert(tk.END, "No OWASP data – run Scan All or Vuln Scan.")
        otxt.configure(state=tk.DISABLED)
        otxt.pack(fill=tk.BOTH, expand=True)

        # --- History tab ---
        tab2 = ttk.Frame(nb, padding=6)
        nb.add(tab2, text="History")
        hist_cols = ("when", "grade", "score", "status")
        hist_tree = ttk.Treeview(tab2, columns=hist_cols, show="headings", height=12)
        hist_tree.heading("when", text="Timestamp")
        hist_tree.heading("grade", text="Grade")
        hist_tree.heading("score", text="Score")
        hist_tree.heading("status", text="HTTP")
        hist_tree.column("when", width=160)
        hist_tree.column("grade", width=60, anchor=tk.CENTER)
        hist_tree.column("score", width=60, anchor=tk.CENTER)
        hist_tree.column("status", width=60, anchor=tk.CENTER)
        hist_tree.pack(fill=tk.BOTH, expand=True)
        records = self.history.get(domain, [])
        if not records and r.get("timestamp"):
            records = [r]
        for rec in records:
            ts = (rec.get("timestamp") or "")[:19].replace("T", " ")
            hist_tree.insert("", tk.END, values=(
                ts, rec.get("grade", "–"), rec.get("score", rec.get("overall_score", "–")), rec.get("status_code", "–"),
            ))
        ttk.Label(tab2, text=f"Last {len(records)} scan(s)", font=("Segoe UI", 8), foreground="#666").pack(anchor=tk.W, pady=4)

        ttk.Button(win, text="Close", command=win.destroy).pack(pady=8)

    # ------------------------------------------------------------------
    # PDF / folders
    # ------------------------------------------------------------------
    def open_pdf(self):
        path = self.last_pdf
        if not path or not Path(path).exists():
            latest = Path(self.cfg.get("output_dir", REPORTS_DIR)) / "latest_report.pdf"
            path = str(latest) if latest.exists() else None
        if not path:
            messagebox.showinfo("No report", "No PDF available yet. Run a scan first.")
            return
        try:
            if sys.platform == "win32":
                os.startfile(path)
            elif sys.platform == "darwin":
                os.system(f'open "{path}"')
            else:
                os.system(f'xdg-open "{path}"')
        except Exception as e:
            messagebox.showerror("Open failed", str(e))

    def open_reports_folder(self):
        folder = Path(self.cfg.get("output_dir", REPORTS_DIR))
        folder.mkdir(exist_ok=True)
        try:
            if sys.platform == "win32":
                os.startfile(folder)
            elif sys.platform == "darwin":
                os.system(f'open "{folder}"')
            else:
                os.system(f'xdg-open "{folder}"')
        except Exception as e:
            messagebox.showerror("Open failed", str(e))

    # ------------------------------------------------------------------
    # Settings
    # ------------------------------------------------------------------


    # ------------------------------------------------------------------
    # Auto-update (S3 / HTTP version.json)
    # ------------------------------------------------------------------

    def check_updates_ui(self, silent: bool = False):
        """Check S3 version.json; auto-download EXE/zip when newer version exists."""
        url = (self.cfg.get("update_url") or "").strip()
        if not url:
            if not silent:
                messagebox.showinfo(
                    "Updates",
                    "No update URL configured.\n\n"
                    "Settings → Update URL = full URL to version.json on S3, e.g.\n"
                    "https://YOUR_BUCKET.s3.amazonaws.com/security-scanner/version.json",
                )
            return
        self.log_msg(f"Checking for updates (v{APP_VERSION})…")
        if not silent:
            self.status_var.set("Checking updates…")

        def worker():
            info = check_for_update(url)

            def done():
                self.status_var.set("Ready")
                if info.get("error") and not info.get("available"):
                    self.log_msg(f"Update check: {info['error']}")
                    if not silent:
                        messagebox.showerror("Update check failed", info["error"])
                    return
                if not info.get("available"):
                    self.log_msg(f"Up to date (v{APP_VERSION})")
                    if not silent:
                        messagebox.showinfo(
                            "Up to date",
                            f"Latest version is already installed.\n\nLocal: v{APP_VERSION}\nRemote: v{info.get('remote', '?')}",
                        )
                    return

                self.log_msg(f"Update available: v{info.get('remote')} ← v{APP_VERSION}")
                auto = bool(self.cfg.get("auto_apply_updates", True)) or bool(info.get("mandatory"))
                if silent and auto:
                    self._download_and_apply_update(info, auto=True)
                    return
                notes = info.get("notes") or ""
                msg = (
                    f"New version v{info.get('remote')} is available (you have v{APP_VERSION}).\n\n"
                    f"{notes}\n\n"
                    f"Download and install now?\n"
                    f"(The app will restart automatically when updating the .exe)"
                )
                if messagebox.askyesno("Update available", msg):
                    self._download_and_apply_update(info, auto=False)

            self.after(0, done)

        threading.Thread(target=worker, daemon=True).start()

    def _download_and_apply_update(self, info: dict, auto: bool = False):
        url = info.get("download_url") or ""
        if not url:
            messagebox.showerror("Update", "download_url missing in version.json")
            return
        ver = info.get("remote", "?")
        self._show_progress("Updating", f"Downloading v{ver}…")
        self._update_progress(f"Downloading v{ver}…", 5)

        def worker():
            try:
                dest = DATA_DIR / "updates"
                dest.mkdir(parents=True, exist_ok=True)

                def prog(frac):
                    pct = 5 + int(max(0, min(1, frac)) * 70)
                    self.after(0, lambda p=pct: self._update_progress(f"Downloading v{ver}… {p}%", p))

                path = download_update(url, dest, progress_cb=prog)
                self.after(0, lambda: self._update_progress("Installing update…", 85))
                result = install_update_package(path, APP_DIR)

                def ok():
                    detail = result.get("detail") or "OK"
                    self.log_msg(f"Update install: {detail}")
                    if result.get("restart_scheduled"):
                        self._finish_progress(f"v{ver} installed — restarting…")
                        self.log_msg("New EXE staged. Restarting…")
                        # Give UI a moment, then exit so replacer can overwrite
                        def leave():
                            try:
                                self._really_quit = True
                                if self.tray_icon:
                                    try:
                                        self.tray_icon.stop()
                                    except Exception:
                                        pass
                            except Exception:
                                pass
                            os._exit(0)
                        self.after(1200, leave)
                    else:
                        self._finish_progress(f"v{ver} installed — please restart")
                        if not auto:
                            messagebox.showinfo(
                                "Update installed",
                                f"Version v{ver} was installed.\n\n{detail}\n\nPlease restart the application.",
                            )
                self.after(0, ok)
            except Exception as e:
                def err():
                    self._finish_progress("Update failed")
                    self.log_msg(f"Update failed: {e}")
                    if not auto:
                        messagebox.showerror("Update failed", str(e))
                self.after(0, err)

        threading.Thread(target=worker, daemon=True).start()

    def open_settings(self):
        """Cyberpunk-themed settings dialog matching main UI."""
        win = tk.Toplevel(self)
        win.title("Settings — PulseScan")
        win.geometry("560x520")
        win.minsize(480, 460)
        win.transient(self)
        win.grab_set()
        win.configure(bg=C["bg"])

        # Header
        hdr = tk.Frame(win, bg=C["card"], padx=16, pady=12)
        hdr.pack(fill=tk.X)
        tk.Label(hdr, text="⚙  SETTINGS", font=("Segoe UI", 13, "bold"),
                 bg=C["card"], fg=C["cyan"]).pack(anchor=tk.W)
        tk.Label(hdr, text="Configure Slack, schedule, startup & reports",
                 font=("Segoe UI", 9), bg=C["card"], fg=C["text2"]).pack(anchor=tk.W)

        body = tk.Frame(win, bg=C["bg"], padx=16, pady=12)
        body.pack(fill=tk.BOTH, expand=True)

        def lbl(parent, text):
            tk.Label(parent, text=text, font=("Segoe UI", 9, "bold"),
                     bg=C["bg"], fg=C["text3"]).pack(anchor=tk.W, pady=(8, 2))

        def entry(parent, var, width=None):
            e = tk.Entry(parent, textvariable=var, font=("Segoe UI", 10),
                         bg=C["card"], fg=C["text"], insertbackground=C["cyan"],
                         relief=tk.FLAT, highlightthickness=1,
                         highlightbackground=C["border"], highlightcolor=C["cyan"])
            e.pack(fill=tk.X, ipady=6, pady=(0, 4))
            return e

        def chk(parent, text, var):
            f = tk.Frame(parent, bg=C["bg"])
            f.pack(anchor=tk.W, fill=tk.X, pady=3)
            tk.Checkbutton(
                f, text=text, variable=var, font=("Segoe UI", 9),
                bg=C["bg"], fg=C["text"], activebackground=C["bg"],
                activeforeground=C["text"], selectcolor=C["card"],
                highlightthickness=0, bd=0,
            ).pack(anchor=tk.W)

        def divider(parent):
            tk.Frame(parent, bg=C["border"], height=1).pack(fill=tk.X, pady=10)

        # Slack
        lbl(body, "SLACK INCOMING WEBHOOK URL")
        slack_var = tk.StringVar(value=self.cfg.get("slack_webhook", ""))
        entry(body, slack_var)

        divider(body)

        # Auto scan
        auto_var = tk.BooleanVar(value=self.cfg.get("auto_scan_enabled", False))
        chk(body, "Enable automatic scan (while app is running)", auto_var)

        times = tk.Frame(body, bg=C["bg"])
        times.pack(fill=tk.X, pady=4)
        t1_var = tk.StringVar(value=self.cfg.get("scan_times", ["08:00", "20:00"])[0])
        t2_var = tk.StringVar(value=(self.cfg.get("scan_times", ["08:00", "20:00"]) + ["20:00"])[1])
        tk.Label(times, text="Time 1 (PKT)", font=("Segoe UI", 9), bg=C["bg"], fg=C["text2"]).pack(side=tk.LEFT)
        e1 = tk.Entry(times, textvariable=t1_var, width=8, font=("Segoe UI", 10),
                      bg=C["card"], fg=C["text"], insertbackground=C["cyan"],
                      relief=tk.FLAT, highlightthickness=1,
                      highlightbackground=C["border"], highlightcolor=C["cyan"])
        e1.pack(side=tk.LEFT, padx=6, ipady=4)
        tk.Label(times, text="Time 2 (PKT)", font=("Segoe UI", 9), bg=C["bg"], fg=C["text2"]).pack(side=tk.LEFT, padx=(12, 0))
        e2 = tk.Entry(times, textvariable=t2_var, width=8, font=("Segoe UI", 10),
                      bg=C["card"], fg=C["text"], insertbackground=C["cyan"],
                      relief=tk.FLAT, highlightthickness=1,
                      highlightbackground=C["border"], highlightcolor=C["cyan"])
        e2.pack(side=tk.LEFT, padx=6, ipady=4)

        slack_auto_var = tk.BooleanVar(value=self.cfg.get("send_slack_on_auto", True))
        slack_manual_var = tk.BooleanVar(value=self.cfg.get("send_slack_on_manual", True))
        chk(body, "Send Slack after automatic scans", slack_auto_var)
        chk(body, "Send Slack after manual scans", slack_manual_var)

        divider(body)

        startup_var = tk.BooleanVar(value=self.cfg.get("start_with_windows", False))
        _plat = (
            "Start at login (Windows)" if sys.platform == "win32"
            else "Start at login (macOS LaunchAgent)" if sys.platform == "darwin"
            else "Start at login (Linux autostart)"
        )
        chk(body, _plat, startup_var)
        tk.Label(body, text="Registers the app to launch when you sign in",
                 font=("Segoe UI", 8), bg=C["bg"], fg=C["text3"]).pack(anchor=tk.W)

        divider(body)

        divider(body)
        lbl(body, "UPDATE URL (S3 version.json)")
        update_url_var = tk.StringVar(value=self.cfg.get("update_url", ""))
        entry(body, update_url_var)
        tk.Label(body, text=f"Current app version: v{APP_VERSION}",
                 font=("Segoe UI", 8), bg=C["bg"], fg=C["text3"]).pack(anchor=tk.W)
        check_upd_var = tk.BooleanVar(value=self.cfg.get("check_updates_on_startup", True))
        chk(body, "Check for updates when app starts", check_upd_var)
        auto_apply_var = tk.BooleanVar(value=self.cfg.get("auto_apply_updates", True))
        chk(body, "Automatically download and install updates (EXE restarts itself)", auto_apply_var)

        lbl(body, "REPORTS OUTPUT FOLDER")
        out_row = tk.Frame(body, bg=C["bg"])
        out_row.pack(fill=tk.X)
        out_var = tk.StringVar(value=self.cfg.get("output_dir", str(REPORTS_DIR)))
        tk.Entry(out_row, textvariable=out_var, font=("Segoe UI", 9),
                 bg=C["card"], fg=C["text"], insertbackground=C["cyan"],
                 relief=tk.FLAT, highlightthickness=1,
                 highlightbackground=C["border"], highlightcolor=C["cyan"]).pack(
            side=tk.LEFT, fill=tk.X, expand=True, ipady=6)

        def browse():
            d = filedialog.askdirectory(initialdir=out_var.get())
            if d:
                out_var.set(d)

        tk.Button(out_row, text="Browse…", command=browse, font=("Segoe UI", 9),
                  bg=C["border"], fg=C["text"], activebackground=C["border2"],
                  activeforeground=C["text"], relief=tk.FLAT, padx=12, pady=4,
                  highlightthickness=1, highlightbackground=C["cyan"]).pack(side=tk.LEFT, padx=(8, 0))

        def save_and_close():
            self.cfg["slack_webhook"] = slack_var.get().strip()
            self.cfg["auto_scan_enabled"] = auto_var.get()
            self.cfg["scan_times"] = [t1_var.get().strip(), t2_var.get().strip()]
            self.cfg["send_slack_on_auto"] = slack_auto_var.get()
            self.cfg["send_slack_on_manual"] = slack_manual_var.get()
            self.cfg["output_dir"] = out_var.get().strip() or str(REPORTS_DIR)
            self.cfg["start_with_windows"] = startup_var.get()
            self.cfg["update_url"] = update_url_var.get().strip()
            self.cfg["check_updates_on_startup"] = check_upd_var.get()
            self.cfg["auto_apply_updates"] = auto_apply_var.get()
            ok = set_autostart(startup_var.get())
            if startup_var.get() and ok:
                self.log_msg("Added to system autostart")
            elif not startup_var.get():
                self.log_msg("Removed from system autostart")
            elif startup_var.get() and not ok:
                self.log_msg("Autostart registration failed")
            save_config(self.cfg)
            self._update_auto_label()
            self._stop_scheduler()
            self._start_scheduler_if_enabled()
            self.log_msg("Settings saved")
            win.destroy()

        foot = tk.Frame(win, bg=C["card"], padx=16, pady=12)
        foot.pack(fill=tk.X)
        tk.Button(foot, text="Save Settings", command=save_and_close,
                  font=("Segoe UI", 10, "bold"), bg=C["emerald"], fg="#FFFFFF",
                  activebackground="#059669", activeforeground="#FFFFFF",
                  relief=tk.FLAT, padx=20, pady=8).pack()

    def _update_auto_label(self):
        if self.cfg.get("auto_scan_enabled"):
            times = ", ".join(self.cfg.get("scan_times", []))
            text = f"Auto-scan: ON  ({times})"
            color = C["emerald"]
        else:
            text = "Auto-scan: Off"
            color = C["text3"]
        try:
            if USE_CTK and hasattr(self.auto_label, "configure"):
                self.auto_label.configure(text=text, text_color=color)
            else:
                self.auto_label.config(text=text, fg=color, bg=C["card"])
        except Exception:
            try:
                self.auto_label.configure(text=text)
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Scheduler
    # ------------------------------------------------------------------
    def _start_scheduler_if_enabled(self):
        if not self.cfg.get("auto_scan_enabled"):
            return
        self.stop_scheduler.clear()
        schedule.clear()
        for t in self.cfg.get("scan_times", []):
            try:
                schedule.every().day.at(t).do(self._scheduled_scan)
            except Exception as e:
                self.log_msg(f"Invalid time '{t}': {e}")

        def runner():
            while not self.stop_scheduler.is_set():
                schedule.run_pending()
                time.sleep(20)

        self.scheduler_thread = threading.Thread(target=runner, daemon=True)
        self.scheduler_thread.start()
        self.log_msg(f"Scheduler started: {self.cfg.get('scan_times')}")

    def _stop_scheduler(self):
        self.stop_scheduler.set()
        schedule.clear()
        self.scheduler_thread = None

    def _scheduled_scan(self):
        self.after(0, lambda: self.start_scan(auto=True))

    # ------------------------------------------------------------------
    # System tray (runs in background after window is closed)
    # ------------------------------------------------------------------
    def _create_tray_image(self):
        """Simple green shield icon for the tray."""
        img = Image.new("RGB", (64, 64), color=(21, 101, 192))
        d = ImageDraw.Draw(img)
        d.ellipse([8, 8, 56, 56], fill=(76, 175, 80))
        d.rectangle([28, 18, 36, 46], fill="white")
        d.rectangle([20, 30, 44, 38], fill="white")
        return img

    def _start_tray(self):
        if not TRAY_AVAILABLE:
            self.log_msg("Tray not available (install: pip install pystray pillow). Close will still hide window.")
            return

        def on_show(icon, item):
            self.after(0, self._show_window)

        def on_scan(icon, item):
            self.after(0, lambda: self.start_scan(auto=False))

        def on_quit(icon, item):
            self.after(0, self._quit_app)

        menu = pystray.Menu(
            pystray.MenuItem("Show Window", on_show, default=True),
            pystray.MenuItem("Scan Now", on_scan),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Exit", on_quit),
        )
        self.tray_icon = pystray.Icon(
            "SecurityHeaderScanner",
            self._create_tray_image(),
            "Security Header Scanner",
            menu,
        )
        # Run tray in background thread
        threading.Thread(target=self.tray_icon.run, daemon=True).start()
        self.log_msg("Running in system tray – close window to hide, right-click tray icon to Exit")

    def _show_window(self):
        self.deiconify()
        self.lift()
        self.focus_force()

    def _hide_to_tray(self):
        self.withdraw()
        self.log_msg("Window hidden – app is still running in the background (system tray)")

    def _quit_app(self):
        """Fully exit the application."""
        self._really_quit = True
        self._stop_scheduler()
        save_config(self.cfg)
        save_history(self.history)
        if self.tray_icon:
            try:
                self.tray_icon.stop()
            except Exception:
                pass
        self.destroy()

    # ------------------------------------------------------------------
    # Logging & close
    # ------------------------------------------------------------------
    def log_msg(self, msg: str):
        ts = now_pkt().strftime("%H:%M:%S")
        try:
            self.log.configure(state=tk.NORMAL)
            self.log.insert(tk.END, f"[{ts}] ", "ts")
            tag = "info"
            low = msg.lower()
            if any(x in low for x in ("error", "fail", "denied", "✗")):
                tag = "err"
            elif any(x in low for x in ("✓", "done", "finished", "sent", "saved")):
                tag = "ok"
            elif any(x in low for x in ("warn", "note:", "rate limit")):
                tag = "warn"
            self.log.insert(tk.END, msg + "\n", tag)
            self.log.see(tk.END)
            self.log.configure(state=tk.DISABLED)
        except Exception:
            pass

    def on_closing(self):
        """X button / Alt+F4 → hide to tray instead of quitting."""
        if self._really_quit:
            self._quit_app()
            return
        if TRAY_AVAILABLE and self.tray_icon:
            self._hide_to_tray()
        else:
            # No tray – ask user
            if messagebox.askyesno("Close", "No system tray available.\n\nQuit the application completely?"):
                self._quit_app()
            # else keep running (window stays open)


def main():
    app = SecurityScannerApp()
    app.protocol("WM_DELETE_WINDOW", app.on_closing)
    try:
        app.log_msg("SOC dark theme ready" + (" (CustomTkinter)" if USE_CTK else " (Tk fallback – pip install customtkinter)"))
    except Exception:
        pass
    app.mainloop()


if __name__ == "__main__":
    main()
