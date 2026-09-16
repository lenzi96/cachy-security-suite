"""
Update manager and security center dialog for Cachy Security Suite.
Includes multi-component status checks (GUI, Core Engine, ClamAV, Threat rules),
batch updating queue, background silent checking, changelog viewer, and 1-click self-update.
"""
import datetime
import json
import os
import re
import shutil
import subprocess
import sys
import urllib.request
from dataclasses import dataclass
from typing import List, Optional, Tuple

# Ensure parent directory of aur_scanner_gui is in sys.path
_pkg_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _pkg_root not in sys.path:
    sys.path.insert(0, _pkg_root)

from PyQt6.QtCore import QDateTime, QProcess, QSettings, QSize, Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QIcon, QTextCharFormat, QTextCursor
from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QFrame,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QTabWidget,
    QTextBrowser,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

import aur_scanner_gui


@dataclass
class UpdateInfo:
    cli_installed: str = "Unbekannt"
    cli_remote: str = "Unbekannt"
    cli_has_update: bool = False

    gui_installed: str = aur_scanner_gui.__version__
    gui_remote: str = aur_scanner_gui.__version__
    gui_has_update: bool = False

    github_repo: Optional[str] = None
    github_release_url: Optional[str] = None
    github_tarball_url: Optional[str] = None
    github_asset_api_url: Optional[str] = None
    github_release_notes: Optional[str] = None
    github_auth_error: bool = False
    github_error_message: Optional[str] = None

    clamav_installed: bool = False
    clamav_version: str = "Nicht installiert"
    clamav_db_version: str = "-"
    clamav_db_date_str: str = "-"
    clamav_db_age_days: int = 0
    clamav_needs_update: bool = False
    clamav_service_active: bool = False
    clamav_service_enabled: bool = False

    rules_count: int = 118
    check_error: Optional[str] = None
    checked_at: Optional[datetime.datetime] = None

    def total_updates_pending(self) -> int:
        count = 0
        if self.cli_has_update:
            count += 1
        if self.gui_has_update:
            count += 1
        if self.clamav_needs_update:
            count += 1
        return count


DEFAULT_GITHUB_REPO = "lenzi96/cachy-security-suite"


def get_github_repo() -> Optional[str]:
    """Retrieves configured or git-detected GitHub repository (e.g. 'owner/repo')."""
    settings = QSettings("CachySecurity", "CachySecuritySuite")
    custom = settings.value("updater/github_repo", "").strip()
    if custom:
        return custom

    source_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    try:
        res = subprocess.run(
            ["git", "-C", source_dir, "remote", "get-url", "origin"],
            capture_output=True,
            text=True,
            check=False,
        )
        if res.returncode == 0:
            url = res.stdout.strip()
            m = re.search(r"github\.com[:/]([^/]+)/([^/\.]+)", url)
            if m:
                repo = f"{m.group(1)}/{m.group(2)}"
                return repo[:-4] if repo.endswith(".git") else repo
    except Exception:
        pass
    return DEFAULT_GITHUB_REPO


def set_github_repo(repo_str: str) -> None:
    """Saves configured GitHub repository and updates git remote origin if in git repo."""
    repo_clean = repo_str.strip()
    # Normalize if full url was provided
    m = re.search(r"github\.com[:/]([^/]+)/([^/\.]+)", repo_clean)
    if m:
        repo_clean = f"{m.group(1)}/{m.group(2)}"
        if repo_clean.endswith(".git"):
            repo_clean = repo_clean[:-4]

    settings = QSettings("CachySecurity", "CachySecuritySuite")
    settings.setValue("updater/github_repo", repo_clean)

    # If in git repo, configure remote origin
    source_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if os.path.isdir(os.path.join(source_dir, ".git")) and repo_clean:
        target_url = f"https://github.com/{repo_clean}.git"
        check_rem = subprocess.run(["git", "-C", source_dir, "remote"], capture_output=True, text=True, check=False)
        if "origin" in check_rem.stdout:
            subprocess.run(["git", "-C", source_dir, "remote", "set-url", "origin", target_url], check=False)
        else:
            subprocess.run(["git", "-C", source_dir, "remote", "add", "origin", target_url], check=False)


def get_github_token() -> Optional[str]:
    """Retrieves GitHub personal access token from QSettings, env, or ~/.git-credentials."""
    settings = QSettings("CachySecurity", "CachySecuritySuite")
    token = settings.value("updater/github_token", "").strip()
    if token:
        return token
    env_token = os.environ.get("GITHUB_TOKEN", "").strip() or os.environ.get("GH_TOKEN", "").strip()
    if env_token:
        return env_token
    git_cred_path = os.path.expanduser("~/.git-credentials")
    if os.path.exists(git_cred_path):
        try:
            with open(git_cred_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if "github.com" in line:
                        m = re.search(r":([^@:]+)@github\.com", line)
                        if m:
                            tok = m.group(1).strip()
                            if tok.startswith("github_pat_") or tok.startswith("ghp_"):
                                return tok
        except Exception:
            pass
    # Check config file in user config directory
    cfg_token_path = os.path.expanduser("~/.config/cachy-security-suite/token")
    if os.path.exists(cfg_token_path):
        try:
            with open(cfg_token_path, "r", encoding="utf-8") as f:
                t = f.read().strip()
                if t:
                    return t
        except Exception:
            pass
    return None


def set_github_token(token_str: str) -> None:
    """Saves configured GitHub personal access token in QSettings."""
    settings = QSettings("CachySecurity", "CachySecuritySuite")
    settings.setValue("updater/github_token", token_str.strip())


def compare_versions(v1: str, v2: str) -> int:
    """Uses vercmp if available, else standard fallback."""
    if shutil.which("vercmp"):
        try:
            res = subprocess.run(
                ["vercmp", v1, v2],
                capture_output=True,
                text=True,
                check=False,
            )
            return int(res.stdout.strip())
        except Exception:
            pass

    # Simple numeric fallback
    parts1 = [int(p) for p in re.findall(r"\d+", v1)]
    parts2 = [int(p) for p in re.findall(r"\d+", v2)]
    return (parts1 > parts2) - (parts1 < parts2)


class UpdateCheckerWorker(QThread):
    finished = pyqtSignal(UpdateInfo)

    def run(self):
        info = UpdateInfo()
        info.gui_installed = aur_scanner_gui.__version__
        info.checked_at = datetime.datetime.now()

        # ----------------------------------------------------------------------
        # 1. Check local aur-scanner CLI version
        # ----------------------------------------------------------------------
        try:
            res = subprocess.run(
                ["pacman", "-Q", "aur-scanner"],
                capture_output=True,
                text=True,
                check=False,
            )
            if res.returncode == 0:
                parts = res.stdout.strip().split()
                if len(parts) >= 2:
                    info.cli_installed = parts[1]
            else:
                res2 = subprocess.run(
                    ["aur-scan", "--version"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if res2.returncode == 0:
                    info.cli_installed = res2.stdout.strip().replace("aur-scan", "").strip()
        except Exception:
            info.cli_installed = "Nicht gefunden"

        # ----------------------------------------------------------------------
        # 2. Check remote AUR RPC version for CLI & GUI
        # ----------------------------------------------------------------------
        try:
            url = "https://aur.archlinux.org/rpc/v5/info?arg[]=aur-scanner&arg[]=cachy-security-suite&arg[]=aur-scanner-gui"
            req = urllib.request.Request(
                url,
                headers={"User-Agent": f"cachy-security-suite/{info.gui_installed}"},
            )
            with urllib.request.urlopen(req, timeout=7) as resp:
                data = json.loads(resp.read().decode())
                results = data.get("results", [])
                for item in results:
                    name = item.get("Name")
                    ver = item.get("Version")
                    if name == "aur-scanner" and ver:
                        info.cli_remote = ver
                    elif name in ("cachy-security-suite", "aur-scanner-gui") and ver:
                        info.gui_remote = ver
        except Exception as exc:
            info.check_error = f"Verbindung zu aur.archlinux.org nicht möglich: {exc}"
            info.cli_remote = info.cli_installed
            info.gui_remote = info.gui_installed

        # GitHub Releases API check if repo is configured or detected
        gh_repo = get_github_repo()
        gh_token = get_github_token()
        if gh_repo:
            info.github_repo = gh_repo
            try:
                gh_url = f"https://api.github.com/repos/{gh_repo}/releases/latest"
                headers = {
                    "User-Agent": f"cachy-security-suite/{info.gui_installed}",
                    "Accept": "application/vnd.github+json",
                }
                if gh_token:
                    headers["Authorization"] = f"Bearer {gh_token}"
                gh_req = urllib.request.Request(
                    gh_url,
                    headers=headers,
                )
                with urllib.request.urlopen(gh_req, timeout=8) as gh_resp:
                    if gh_resp.status == 200:
                        gh_data = json.loads(gh_resp.read().decode())
                        tag = gh_data.get("tag_name", "").lstrip("v").strip()
                        if tag:
                            info.gui_remote = tag
                            info.github_release_url = gh_data.get("html_url", "")
                            info.github_release_notes = gh_data.get("body", "")
                            for asset in gh_data.get("assets", []):
                                if asset.get("name", "").endswith((".tar.gz", ".zip")):
                                    info.github_tarball_url = asset.get("browser_download_url", "")
                                    info.github_asset_api_url = asset.get("url", "")
                                    break
            except urllib.error.HTTPError as err:
                if err.code in (401, 403, 404):
                    info.github_auth_error = True
                    if not gh_token:
                        info.github_error_message = "Repository ist privat. Bitte GitHub-Token hinterlegen oder Repo auf 'Public' stellen."
                    else:
                        info.github_error_message = f"GitHub-Fehler {err.code}: Token ungültig oder unzureichende Rechte."
                else:
                    info.github_error_message = f"GitHub HTTP-Fehler {err.code}"
            except Exception as err:
                info.github_error_message = f"Netzwerkfehler: {str(err)}"

        # Compare CLI versions
        if info.cli_installed and info.cli_remote and info.cli_installed != "Nicht gefunden":
            cmp_res = compare_versions(info.cli_installed, info.cli_remote)
            info.cli_has_update = cmp_res < 0

        # Compare GUI versions
        if info.gui_installed and info.gui_remote and info.gui_remote != "Unbekannt":
            cmp_gui = compare_versions(info.gui_installed, info.gui_remote)
            info.gui_has_update = cmp_gui < 0

        # ----------------------------------------------------------------------
        # 3. Check ClamAV Antivirus Status & Signature Age
        # ----------------------------------------------------------------------
        if shutil.which("clamscan"):
            info.clamav_installed = True
            try:
                # clamscan -V output example: ClamAV 1.5.4/28123/Mon Sep 14 08:24:19 2026
                res_clam = subprocess.run(
                    ["clamscan", "-V"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                if res_clam.returncode == 0:
                    out = res_clam.stdout.strip()
                    parts = out.split("/")
                    if len(parts) >= 1:
                        info.clamav_version = parts[0].strip()
                    if len(parts) >= 2:
                        info.clamav_db_version = parts[1].strip()
                    if len(parts) >= 3:
                        info.clamav_db_date_str = parts[2].strip()
            except Exception:
                info.clamav_version = "ClamAV (Installiert)"

            # Check daily.cvd file timestamp
            db_candidates = [
                "/var/lib/clamav/daily.cvd",
                "/var/lib/clamav/daily.cld",
                os.path.expanduser("~/.cache/clamav/daily.cvd"),
            ]
            found_db = False
            for db_path in db_candidates:
                if os.path.exists(db_path):
                    try:
                        mtime = os.path.getmtime(db_path)
                        dt = datetime.datetime.fromtimestamp(mtime)
                        age_days = (datetime.datetime.now() - dt).days
                        info.clamav_db_age_days = max(0, age_days)
                        info.clamav_db_date_str = dt.strftime("%d.%m.%Y %H:%M")
                        found_db = True
                        if age_days >= 3:
                            info.clamav_needs_update = True
                        break
                    except Exception:
                        pass

            if not found_db:
                info.clamav_needs_update = True
                info.clamav_db_date_str = "Keine Signaturdatenbank"

            # Check ClamAV systemd service
            try:
                srv_act = subprocess.run(
                    ["systemctl", "is-active", "clamav-freshclam.service"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                info.clamav_service_active = (srv_act.stdout.strip() == "active")

                srv_en = subprocess.run(
                    ["systemctl", "is-enabled", "clamav-freshclam.service"],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                info.clamav_service_enabled = (srv_en.stdout.strip() == "enabled")
            except Exception:
                pass
        else:
            info.clamav_installed = False
            info.clamav_version = "Nicht installiert"

        self.finished.emit(info)


@dataclass
class UpdateStep:
    name: str
    command: List[str]
    description: str
    is_gui_update: bool = False


class BatchUpdateWorker(QThread):
    step_started = pyqtSignal(int, int, str)  # current_idx, total_steps, title
    output_line = pyqtSignal(str)
    all_completed = pyqtSignal(bool, str, bool)  # success, message, gui_was_updated

    def __init__(self, steps: List[UpdateStep]):
        super().__init__()
        self.steps = steps
        self.process: Optional[subprocess.Popen] = None
        self._is_cancelled = False
        self.gui_was_updated = False

    def cancel(self):
        self._is_cancelled = True
        if self.process and self.process.poll() is None:
            try:
                self.process.terminate()
            except Exception:
                pass

    def run(self):
        total = len(self.steps)
        if total == 0:
            self.all_completed.emit(True, "Keine anstehenden Updates.", False)
            return

        all_success = True
        failed_steps = []

        for idx, step in enumerate(self.steps, start=1):
            if self._is_cancelled:
                self.output_line.emit("\n[!] Vorgang durch Benutzer abgebrochen.")
                self.all_completed.emit(False, "Aktualisierung abgebrochen.", self.gui_was_updated)
                return

            self.step_started.emit(idx, total, step.name)
            self.output_line.emit(f"\n=======================================================")
            self.output_line.emit(f"[{idx}/{total}] {step.name}")
            self.output_line.emit(f"Befehl: {' '.join(step.command)}")
            self.output_line.emit(f"=======================================================\n")

            env = os.environ.copy()
            _pkg_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            if "PYTHONPATH" in env and env["PYTHONPATH"]:
                env["PYTHONPATH"] = f"{_pkg_root}:{env['PYTHONPATH']}"
            else:
                env["PYTHONPATH"] = _pkg_root

            try:
                self.process = subprocess.Popen(
                    step.command,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                    universal_newlines=True,
                    env=env,
                )

                if self.process.stdout:
                    for line in iter(self.process.stdout.readline, ""):
                        if self._is_cancelled:
                            break
                        self.output_line.emit(line.rstrip())

                self.process.wait()
                ret = self.process.returncode if self.process else 1

                if ret != 0:
                    all_success = False
                    failed_steps.append(step.name)
                    self.output_line.emit(f"\n[✗] Schritt '{step.name}' mit Statuscode {ret} beendet.")
                else:
                    self.output_line.emit(f"\n[✓] Schritt '{step.name}' erfolgreich abgeschlossen.")
                    if step.is_gui_update:
                        self.gui_was_updated = True

            except Exception as exc:
                all_success = False
                failed_steps.append(step.name)
                self.output_line.emit(f"\n[✗] Fehler bei '{step.name}': {exc}")

        if all_success:
            summary = "Alle gewählten Updates wurden erfolgreich abgeschlossen."
        else:
            summary = f"Einige Schritte schlugen fehl: {', '.join(failed_steps)}"

        self.all_completed.emit(all_success, summary, self.gui_was_updated)


class UpdateDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Sicherheits- & Update-Center - Cachy Security Suite")
        self.resize(780, 620)
        self.setMinimumSize(700, 540)

        self.checker_worker: Optional[UpdateCheckerWorker] = None
        self.batch_worker: Optional[BatchUpdateWorker] = None
        self.latest_info: Optional[UpdateInfo] = None

        self.init_ui()
        self.start_check()

    def init_ui(self):
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(20, 18, 20, 16)
        root_layout.setSpacing(12)

        # ----------------------------------------------------------------------
        # Top Header
        # ----------------------------------------------------------------------
        header_layout = QHBoxLayout()
        header_text = QVBoxLayout()
        header_text.setSpacing(2)

        lbl_title = QLabel("Sicherheits- & Update-Center")
        lbl_title.setStyleSheet("font-size: 19px; font-weight: 800; color: palette(text);")
        lbl_desc = QLabel("Verwalte Core-Engine, Virensignaturen, Bedrohungsdatenbank und Software-Aktualisierungen.")
        lbl_desc.setStyleSheet("font-size: 11px; color: #94a3b8;")
        lbl_desc.setWordWrap(True)

        header_text.addWidget(lbl_title)
        header_text.addWidget(lbl_desc)
        header_layout.addLayout(header_text)
        header_layout.addStretch()

        self.btn_refresh = QPushButton("  Auf Updates prüfen")
        self.btn_refresh.setIcon(QIcon.fromTheme("view-refresh"))
        self.btn_refresh.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_refresh.setStyleSheet("""
            QPushButton {
                padding: 7px 14px;
                border-radius: 6px;
                border: 1px solid palette(mid);
                background: palette(window);
                font-size: 11px;
                font-weight: 500;
            }
            QPushButton:hover { background: palette(button); }
            QPushButton:disabled { opacity: 0.5; }
        """)
        self.btn_refresh.clicked.connect(self.start_check)
        header_layout.addWidget(self.btn_refresh)

        self.btn_update_all = QPushButton("  🚀 Alle aktualisieren")
        self.btn_update_all.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_update_all.setEnabled(False)
        self.btn_update_all.setStyleSheet("""
            QPushButton {
                padding: 7px 16px;
                border-radius: 6px;
                background-color: #2563eb;
                color: #ffffff;
                font-size: 12px;
                font-weight: 700;
                border: none;
            }
            QPushButton:hover { background-color: #1d4ed8; }
            QPushButton:disabled { background-color: #334155; color: #64748b; }
        """)
        self.btn_update_all.clicked.connect(self.run_update_all)
        header_layout.addWidget(self.btn_update_all)

        root_layout.addLayout(header_layout)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setFixedHeight(4)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: none;
                background: transparent;
            }
            QProgressBar::chunk {
                background-color: #3b82f6;
                border-radius: 2px;
            }
        """)
        root_layout.addWidget(self.progress_bar)

        # ----------------------------------------------------------------------
        # Tab Widget
        # ----------------------------------------------------------------------
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid palette(mid);
                border-radius: 8px;
                background-color: palette(window);
                top: -1px;
            }
            QTabBar::tab {
                background-color: palette(base);
                color: #94a3b8;
                padding: 8px 18px;
                border: 1px solid palette(mid);
                border-bottom: none;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 4px;
                font-weight: 600;
                font-size: 11px;
            }
            QTabBar::tab:selected {
                background-color: palette(window);
                color: palette(text);
                border-bottom: 2px solid #2563eb;
            }
            QTabBar::tab:hover:!selected {
                background-color: palette(button);
                color: palette(text);
            }
        """)

        # Tab 1: Komponenten-Status
        self.tab_components = QWidget()
        self.init_components_tab()
        self.tabs.addTab(self.tab_components, "Status && Komponenten")

        # Tab 2: Was ist neu? (Changelog)
        self.tab_changelog = QWidget()
        self.init_changelog_tab()
        self.tabs.addTab(self.tab_changelog, "Was ist neu? (Changelog)")

        # Tab 3: Terminal-Ausgabe
        self.tab_log = QWidget()
        self.init_log_tab()
        self.tabs.addTab(self.tab_log, "Terminal-Ausgabe")

        root_layout.addWidget(self.tabs, stretch=1)

        # ----------------------------------------------------------------------
        # Bottom Bar
        # ----------------------------------------------------------------------
        bottom_layout = QHBoxLayout()
        self.lbl_status_summary = QLabel("Bereit.")
        self.lbl_status_summary.setStyleSheet("font-size: 11px; color: #94a3b8;")
        bottom_layout.addWidget(self.lbl_status_summary)
        bottom_layout.addStretch()

        self.btn_cancel = QPushButton("Abbrechen")
        self.btn_cancel.setVisible(False)
        self.btn_cancel.setStyleSheet("""
            QPushButton {
                padding: 6px 14px;
                border-radius: 6px;
                background-color: #dc2626;
                color: #ffffff;
                font-size: 11px;
                font-weight: 600;
                border: none;
            }
            QPushButton:hover { background-color: #b91c1c; }
        """)
        self.btn_cancel.clicked.connect(self.cancel_active_process)
        bottom_layout.addWidget(self.btn_cancel)

        btn_close = QPushButton("Schließen")
        btn_close.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_close.clicked.connect(self.accept)
        btn_close.setStyleSheet("""
            QPushButton {
                padding: 7px 18px;
                border-radius: 6px;
                border: 1px solid palette(mid);
                background: palette(window);
                font-size: 11px;
                font-weight: 500;
            }
            QPushButton:hover { background: palette(button); }
        """)
        bottom_layout.addWidget(btn_close)

        root_layout.addLayout(bottom_layout)

    # --------------------------------------------------------------------------
    # Tab 1: Components View
    # --------------------------------------------------------------------------
    def init_components_tab(self):
        scroll = QScrollArea(self.tab_components)
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(12, 14, 12, 14)
        layout.setSpacing(12)

        # ----------------------------------------------------------------------
        # Card 1: Cachy Security Suite (GUI)
        # ----------------------------------------------------------------------
        card_gui = QFrame()
        card_gui.setObjectName("cardGui")
        card_gui.setStyleSheet("""
            QFrame#cardGui {
                background-color: palette(base);
                border: 1px solid palette(mid);
                border-radius: 10px;
            }
            QFrame#cardGui QLabel { background: transparent; border: none; }
        """)
        c1_layout = QHBoxLayout(card_gui)
        c1_layout.setContentsMargins(14, 12, 14, 12)
        c1_layout.setSpacing(12)

        icon_c1 = QLabel()
        logo_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "resources", "aur-scanner-64.png")
        if os.path.exists(logo_path):
            icon_c1.setPixmap(QIcon(logo_path).pixmap(36, 36))
        else:
            icon_c1.setText("🛡️")
            icon_c1.setStyleSheet("font-size: 24px;")
        c1_layout.addWidget(icon_c1)

        c1_text = QVBoxLayout()
        c1_text.setSpacing(2)
        lbl_c1_title = QLabel("Cachy Security Suite (Grafische Oberfläche)")
        lbl_c1_title.setStyleSheet("font-size: 13px; font-weight: 700;")
        self.lbl_c1_version = QLabel(f"Installiert: v{aur_scanner_gui.__version__}")
        self.lbl_c1_version.setStyleSheet("font-size: 11px; opacity: 0.8;")
        self.lbl_c1_github = QLabel("GitHub: Prüfe...")
        self.lbl_c1_github.setStyleSheet("font-size: 10px; color: #94a3b8;")
        c1_text.addWidget(lbl_c1_title)
        c1_text.addWidget(self.lbl_c1_version)
        c1_text.addWidget(self.lbl_c1_github)
        c1_layout.addLayout(c1_text, stretch=1)

        self.badge_c1 = QLabel("✓ Aktuell")
        self.badge_c1.setStyleSheet("background-color: rgba(16, 185, 129, 0.15); color: #059669; padding: 4px 10px; border-radius: 6px; font-weight: 600; font-size: 11px;")
        c1_layout.addWidget(self.badge_c1)

        c1_btn_layout = QVBoxLayout()
        c1_btn_layout.setSpacing(4)

        self.btn_update_gui = QPushButton("Neu installieren")
        self.btn_update_gui.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_update_gui.setStyleSheet("""
            QPushButton {
                padding: 6px 12px;
                border-radius: 6px;
                border: 1px solid palette(mid);
                background: palette(window);
                font-size: 11px;
                font-weight: 500;
            }
            QPushButton:hover { background: palette(button); }
        """)
        self.btn_update_gui.clicked.connect(self.reinstall_gui)
        c1_btn_layout.addWidget(self.btn_update_gui)

        self.btn_link_github = QPushButton("🔗 GitHub-Repo...")
        self.btn_link_github.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_link_github.setStyleSheet("""
            QPushButton {
                padding: 4px 8px;
                border-radius: 5px;
                border: 1px solid #334155;
                background: rgba(255, 255, 255, 0.05);
                color: #94a3b8;
                font-size: 10px;
                font-weight: 500;
            }
            QPushButton:hover { background: rgba(255, 255, 255, 0.1); color: #ffffff; }
        """)
        self.btn_link_github.clicked.connect(self.configure_github_repo)
        c1_btn_layout.addWidget(self.btn_link_github)

        c1_layout.addLayout(c1_btn_layout)
        layout.addWidget(card_gui)

        # ----------------------------------------------------------------------
        # Card 2: aur-scanner Core Engine (CLI)
        # ----------------------------------------------------------------------
        card_cli = QFrame()
        card_cli.setObjectName("cardCli")
        card_cli.setStyleSheet("""
            QFrame#cardCli {
                background-color: palette(base);
                border: 1px solid palette(mid);
                border-radius: 10px;
            }
            QFrame#cardCli QLabel { background: transparent; border: none; }
        """)
        c2_layout = QHBoxLayout(card_cli)
        c2_layout.setContentsMargins(14, 12, 14, 12)
        c2_layout.setSpacing(12)

        icon_c2 = QLabel()
        icon_cli_theme = QIcon.fromTheme("applications-system")
        if not icon_cli_theme.isNull():
            icon_c2.setPixmap(icon_cli_theme.pixmap(36, 36))
        else:
            icon_c2.setText("⚙️")
            icon_c2.setStyleSheet("font-size: 24px;")
        c2_layout.addWidget(icon_c2)

        c2_text = QVBoxLayout()
        c2_text.setSpacing(2)
        lbl_c2_title = QLabel("aur-scanner Core Engine (CLI)")
        lbl_c2_title.setStyleSheet("font-size: 13px; font-weight: 700;")
        self.lbl_c2_version = QLabel("Prüfe CLI...")
        self.lbl_c2_version.setStyleSheet("font-size: 11px; opacity: 0.8;")
        c2_text.addWidget(lbl_c2_title)
        c2_text.addWidget(self.lbl_c2_version)
        c2_layout.addLayout(c2_text, stretch=1)

        self.badge_c2 = QLabel("Prüfe...")
        self.badge_c2.setStyleSheet("background-color: rgba(59, 130, 246, 0.15); color: #2563eb; padding: 4px 10px; border-radius: 6px; font-weight: 600; font-size: 11px;")
        c2_layout.addWidget(self.badge_c2)

        self.btn_update_cli = QPushButton("Aktualisieren")
        self.btn_update_cli.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_update_cli.setEnabled(False)
        self.btn_update_cli.setStyleSheet("""
            QPushButton {
                background-color: #2563eb;
                color: #ffffff;
                font-weight: 600;
                font-size: 11px;
                padding: 6px 14px;
                border-radius: 6px;
                border: none;
            }
            QPushButton:hover { background-color: #1d4ed8; }
            QPushButton:disabled { background-color: palette(mid); color: palette(text); opacity: 0.5; }
        """)
        self.btn_update_cli.clicked.connect(self.update_cli)
        c2_layout.addWidget(self.btn_update_cli)
        layout.addWidget(card_cli)

        # ----------------------------------------------------------------------
        # Card 3: ClamAV Antivirus & Signatures
        # ----------------------------------------------------------------------
        card_clam = QFrame()
        card_clam.setObjectName("cardClam")
        card_clam.setStyleSheet("""
            QFrame#cardClam {
                background-color: palette(base);
                border: 1px solid palette(mid);
                border-radius: 10px;
            }
            QFrame#cardClam QLabel { background: transparent; border: none; }
        """)
        c3_layout = QHBoxLayout(card_clam)
        c3_layout.setContentsMargins(14, 12, 14, 12)
        c3_layout.setSpacing(12)

        icon_c3 = QLabel()
        icon_clam_theme = QIcon.fromTheme("security-high")
        if not icon_clam_theme.isNull():
            icon_c3.setPixmap(icon_clam_theme.pixmap(36, 36))
        else:
            icon_c3.setText("🦠")
            icon_c3.setStyleSheet("font-size: 24px;")
        c3_layout.addWidget(icon_c3)

        c3_text = QVBoxLayout()
        c3_text.setSpacing(2)
        lbl_c3_title = QLabel("ClamAV Virensignaturen & Schutz")
        lbl_c3_title.setStyleSheet("font-size: 13px; font-weight: 700;")
        self.lbl_c3_status = QLabel("Prüfe Signaturstatus...")
        self.lbl_c3_status.setStyleSheet("font-size: 11px; opacity: 0.8;")
        self.lbl_c3_service = QLabel("Hintergrunddienst: Prüfe...")
        self.lbl_c3_service.setStyleSheet("font-size: 10px; color: #94a3b8;")
        c3_text.addWidget(lbl_c3_title)
        c3_text.addWidget(self.lbl_c3_status)
        c3_text.addWidget(self.lbl_c3_service)
        c3_layout.addLayout(c3_text, stretch=1)

        self.badge_c3 = QLabel("Prüfe...")
        self.badge_c3.setStyleSheet("padding: 4px 10px; border-radius: 6px; font-weight: 600; font-size: 11px;")
        c3_layout.addWidget(self.badge_c3)

        c3_buttons = QVBoxLayout()
        c3_buttons.setSpacing(4)

        self.btn_update_clam = QPushButton("Signaturen laden")
        self.btn_update_clam.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_update_clam.setStyleSheet("""
            QPushButton {
                background-color: #059669;
                color: #ffffff;
                font-weight: 600;
                font-size: 11px;
                padding: 6px 12px;
                border-radius: 6px;
                border: none;
            }
            QPushButton:hover { background-color: #047857; }
            QPushButton:disabled { background-color: palette(mid); color: palette(text); opacity: 0.5; }
        """)
        self.btn_update_clam.clicked.connect(self.update_clamav)
        c3_buttons.addWidget(self.btn_update_clam)

        self.btn_enable_service = QPushButton("Dienst aktivieren")
        self.btn_enable_service.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_enable_service.setVisible(False)
        self.btn_enable_service.setStyleSheet("""
            QPushButton {
                padding: 4px 10px;
                border-radius: 5px;
                border: 1px solid #3b82f6;
                background: rgba(59, 130, 246, 0.1);
                color: #3b82f6;
                font-size: 10px;
                font-weight: 600;
            }
            QPushButton:hover { background: #3b82f6; color: #ffffff; }
        """)
        self.btn_enable_service.clicked.connect(self.enable_clamav_service)
        c3_buttons.addWidget(self.btn_enable_service)

        c3_layout.addLayout(c3_buttons)
        layout.addWidget(card_clam)

        # ----------------------------------------------------------------------
        # Card 4: Threat Feeds & Heuristics
        # ----------------------------------------------------------------------
        card_feed = QFrame()
        card_feed.setObjectName("cardFeed")
        card_feed.setStyleSheet("""
            QFrame#cardFeed {
                background-color: palette(base);
                border: 1px solid palette(mid);
                border-radius: 10px;
            }
            QFrame#cardFeed QLabel { background: transparent; border: none; }
        """)
        c4_layout = QHBoxLayout(card_feed)
        c4_layout.setContentsMargins(14, 12, 14, 12)
        c4_layout.setSpacing(12)

        icon_c4 = QLabel()
        icon_feed_theme = QIcon.fromTheme("dialog-information")
        if not icon_feed_theme.isNull():
            icon_c4.setPixmap(icon_feed_theme.pixmap(36, 36))
        else:
            icon_c4.setText("📡")
            icon_c4.setStyleSheet("font-size: 24px;")
        c4_layout.addWidget(icon_c4)

        c4_text = QVBoxLayout()
        c4_text.setSpacing(2)
        lbl_c4_title = QLabel("Sicherheitsregeln & IOC-Bedrohungsdatenbank")
        lbl_c4_title.setStyleSheet("font-size: 13px; font-weight: 700;")
        lbl_c4_desc = QLabel("118 Erkennungsregeln aktiv | AUR-Paket-Metadaten & Cache")
        lbl_c4_desc.setStyleSheet("font-size: 11px; opacity: 0.8;")
        c4_text.addWidget(lbl_c4_title)
        c4_text.addWidget(lbl_c4_desc)
        c4_layout.addLayout(c4_text, stretch=1)

        self.badge_c4 = QLabel("✓ Bereit")
        self.badge_c4.setStyleSheet("background-color: rgba(16, 185, 129, 0.15); color: #059669; padding: 4px 10px; border-radius: 6px; font-weight: 600; font-size: 11px;")
        c4_layout.addWidget(self.badge_c4)

        self.btn_refresh_rules = QPushButton("Cache leeren / Rescan")
        self.btn_refresh_rules.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_refresh_rules.setStyleSheet("""
            QPushButton {
                padding: 6px 12px;
                border-radius: 6px;
                border: 1px solid palette(mid);
                background: palette(window);
                font-size: 11px;
                font-weight: 500;
            }
            QPushButton:hover { background: palette(button); }
        """)
        self.btn_refresh_rules.clicked.connect(self.rescan_rules)
        c4_layout.addWidget(self.btn_refresh_rules)
        layout.addWidget(card_feed)

        layout.addStretch()

        scroll.setWidget(container)
        tab_layout = QVBoxLayout(self.tab_components)
        tab_layout.setContentsMargins(0, 0, 0, 0)
        tab_layout.addWidget(scroll)

    # --------------------------------------------------------------------------
    # Tab 2: Changelog View
    # --------------------------------------------------------------------------
    def init_changelog_tab(self):
        layout = QVBoxLayout(self.tab_changelog)
        layout.setContentsMargins(12, 12, 12, 12)

        self.txt_changelog = QTextBrowser()
        self.txt_changelog.setOpenExternalLinks(True)
        self.txt_changelog.setStyleSheet("""
            QTextBrowser {
                background-color: palette(base);
                color: palette(text);
                border: 1px solid palette(mid);
                border-radius: 8px;
                padding: 14px;
                font-size: 12px;
                line-height: 1.5;
            }
        """)

        # Load CHANGELOG.md
        changelog_content = self.load_changelog()
        self.txt_changelog.setMarkdown(changelog_content)

        layout.addWidget(self.txt_changelog)

    def load_changelog(self) -> str:
        content = ""
        if self.latest_info and self.latest_info.github_release_notes:
            content += f"# Neuestes GitHub-Release (v{self.latest_info.gui_remote})\n\n{self.latest_info.github_release_notes}\n\n---\n\n"

        candidates = [
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "CHANGELOG.md"),
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "resources", "CHANGELOG.md"),
            "/usr/share/cachy-security-suite/CHANGELOG.md",
        ]
        for p in candidates:
            if os.path.exists(p):
                try:
                    with open(p, "r", encoding="utf-8") as f:
                        content += f.read()
                        return content
                except Exception:
                    pass

        if content:
            return content

        return f"# Cachy Security Suite v{aur_scanner_gui.__version__}\n\nKein Changelog gefunden."

    # --------------------------------------------------------------------------
    # Tab 3: Terminal Output View
    # --------------------------------------------------------------------------
    def init_log_tab(self):
        layout = QVBoxLayout(self.tab_log)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        log_header = QHBoxLayout()
        lbl_out = QLabel("Live-Befehlsausgabe:")
        lbl_out.setStyleSheet("font-weight: 600; font-size: 11px; color: #94a3b8;")
        log_header.addWidget(lbl_out)
        log_header.addStretch()

        btn_clear = QPushButton("Log leeren")
        btn_clear.setStyleSheet("font-size: 10px; padding: 3px 8px;")
        btn_clear.clicked.connect(lambda: self.txt_log.clear())
        log_header.addWidget(btn_clear)
        layout.addLayout(log_header)

        self.txt_log = QTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setFont(QFont("JetBrains Mono, monospace", 9))
        self.txt_log.setStyleSheet("""
            QTextEdit {
                background-color: #0f172a;
                color: #e2e8f0;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 8px;
            }
        """)
        layout.addWidget(self.txt_log, stretch=1)

    # --------------------------------------------------------------------------
    # Worker Connection & Results
    # --------------------------------------------------------------------------
    def start_check(self):
        self.btn_refresh.setEnabled(False)
        self.btn_update_all.setEnabled(False)
        self.progress_bar.setVisible(True)

        self.badge_c1.setText("Prüfe...")
        self.badge_c1.setStyleSheet("background-color: rgba(59, 130, 246, 0.15); color: #2563eb; padding: 4px 10px; border-radius: 6px; font-weight: 600; font-size: 11px;")
        self.badge_c2.setText("Prüfe...")
        self.badge_c2.setStyleSheet("background-color: rgba(59, 130, 246, 0.15); color: #2563eb; padding: 4px 10px; border-radius: 6px; font-weight: 600; font-size: 11px;")
        self.badge_c3.setText("Prüfe...")
        self.badge_c3.setStyleSheet("background-color: rgba(59, 130, 246, 0.15); color: #2563eb; padding: 4px 10px; border-radius: 6px; font-weight: 600; font-size: 11px;")

        self.lbl_c2_version.setText("Frage AUR RPC API ab...")
        self.lbl_status_summary.setText("Überprüfe Versionen und Virensignaturen...")

        self.checker_worker = UpdateCheckerWorker()
        self.checker_worker.finished.connect(self.on_check_finished)
        self.checker_worker.start()

    def on_check_finished(self, info: UpdateInfo):
        self.btn_refresh.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.latest_info = info

        # 1. Update GUI Card
        if info.github_auth_error:
            self.lbl_c1_version.setText(f"Installiert: v{info.gui_installed}  │  Verfügbar: Nicht abrufbar (404/Privat)")
            self.lbl_c1_github.setText(f"GitHub: {info.github_error_message or 'Repository ist privat'}")
            self.lbl_c1_github.setStyleSheet("color: #f87171; font-size: 11px;")
            self.badge_c1.setText("⚠️ Token erforderlich")
            self.badge_c1.setStyleSheet("background-color: rgba(239, 68, 68, 0.2); color: #f87171; padding: 4px 10px; border-radius: 6px; font-weight: 600; font-size: 11px;")
            self.btn_link_github.setText("🔑 Token hinterlegen...")
            self.btn_update_gui.setEnabled(False)
        else:
            self.lbl_c1_version.setText(f"Installiert: v{info.gui_installed}  │  Verfügbar: v{info.gui_remote}")
            self.btn_link_github.setText("🔗 GitHub-Repo...")
            if info.github_repo:
                self.lbl_c1_github.setText(f"GitHub: {info.github_repo} (Releases aktiv)")
                self.lbl_c1_github.setStyleSheet("color: #94a3b8; font-size: 11px;")
            else:
                self.lbl_c1_github.setText("GitHub: Noch nicht verknüpft")
                self.lbl_c1_github.setStyleSheet("color: #94a3b8; font-size: 11px;")

            if info.gui_has_update:
                self.badge_c1.setText(f"⬆ Update verfügbar (v{info.gui_remote})")
                self.badge_c1.setStyleSheet("background-color: #ea580c; color: #ffffff; padding: 4px 10px; border-radius: 6px; font-weight: 600; font-size: 11px;")
                self.btn_update_gui.setText("Jetzt aktualisieren")
                self.btn_update_gui.setStyleSheet("""
                    QPushButton {
                        background-color: #ea580c;
                        color: #ffffff;
                        font-weight: 600;
                        font-size: 11px;
                        padding: 6px 14px;
                        border-radius: 6px;
                        border: none;
                    }
                    QPushButton:hover { background-color: #c2410c; }
                """)
                self.btn_update_gui.setEnabled(True)
            else:
                self.badge_c1.setText("✓ Aktuell")
                self.badge_c1.setStyleSheet("background-color: rgba(16, 185, 129, 0.15); color: #059669; padding: 4px 10px; border-radius: 6px; font-weight: 600; font-size: 11px;")
                self.btn_update_gui.setText("Neu installieren")
                self.btn_update_gui.setEnabled(True)

        # 2. Update CLI Card
        self.lbl_c2_version.setText(f"Installiert: {info.cli_installed}  │  Im AUR: {info.cli_remote}")
        if info.cli_has_update:
            self.badge_c2.setText("⬆ Update verfügbar")
            self.badge_c2.setStyleSheet("background-color: #ea580c; color: #ffffff; padding: 4px 10px; border-radius: 6px; font-weight: 600; font-size: 11px;")
            self.btn_update_cli.setEnabled(True)
        else:
            self.badge_c2.setText("✓ Aktuell")
            self.badge_c2.setStyleSheet("background-color: rgba(16, 185, 129, 0.15); color: #059669; padding: 4px 10px; border-radius: 6px; font-weight: 600; font-size: 11px;")
            self.btn_update_cli.setEnabled(False)

        # 3. Update ClamAV Card
        if not info.clamav_installed:
            self.lbl_c3_status.setText("ClamAV Antivirus-Paket ist nicht im System installiert.")
            self.lbl_c3_service.setText("Tipp: Installiere ClamAV mit 'sudo pacman -S clamav'")
            self.badge_c3.setText("Nicht installiert")
            self.badge_c3.setStyleSheet("background-color: rgba(148, 163, 184, 0.15); color: #94a3b8; padding: 4px 10px; border-radius: 6px; font-weight: 600; font-size: 11px;")
            self.btn_update_clam.setEnabled(False)
            self.btn_enable_service.setVisible(False)
        else:
            self.btn_update_clam.setEnabled(True)
            age_text = f"Vor {info.clamav_db_age_days} Tag(en)" if info.clamav_db_age_days > 0 else "Heute"
            self.lbl_c3_status.setText(f"Signaturen: {info.clamav_db_date_str} ({age_text})  │  Daily DB: {info.clamav_db_version}")

            if info.clamav_service_active:
                srv_msg = "✓ Hintergrunddienst aktiv (automatische Updates)"
                self.btn_enable_service.setText("Dienst löschen")
                self.btn_enable_service.setStyleSheet("""
                    QPushButton {
                        padding: 4px 10px;
                        border-radius: 5px;
                        border: 1px solid #dc2626;
                        background: rgba(220, 38, 38, 0.1);
                        color: #ef4444;
                        font-size: 10px;
                        font-weight: 600;
                    }
                    QPushButton:hover { background: #dc2626; color: #ffffff; }
                """)
                self.btn_enable_service.setVisible(True)
            elif info.clamav_service_enabled:
                srv_msg = "Dienst aktiviert (wartet auf Timer)"
                self.btn_enable_service.setText("Dienst löschen")
                self.btn_enable_service.setStyleSheet("""
                    QPushButton {
                        padding: 4px 10px;
                        border-radius: 5px;
                        border: 1px solid #dc2626;
                        background: rgba(220, 38, 38, 0.1);
                        color: #ef4444;
                        font-size: 10px;
                        font-weight: 600;
                    }
                    QPushButton:hover { background: #dc2626; color: #ffffff; }
                """)
                self.btn_enable_service.setVisible(True)
            else:
                srv_msg = "⚠ Hintergrunddienst inaktiv (keine autom. Aktualisierung)"
                self.btn_enable_service.setText("Dienst aktivieren")
                self.btn_enable_service.setStyleSheet("""
                    QPushButton {
                        padding: 4px 10px;
                        border-radius: 5px;
                        border: 1px solid #3b82f6;
                        background: rgba(59, 130, 246, 0.1);
                        color: #3b82f6;
                        font-size: 10px;
                        font-weight: 600;
                    }
                    QPushButton:hover { background: #3b82f6; color: #ffffff; }
                """)
                self.btn_enable_service.setVisible(True)
            self.lbl_c3_service.setText(srv_msg)

            if info.clamav_needs_update:
                self.badge_c3.setText("⚠ Veraltet (>3 Tage)")
                self.badge_c3.setStyleSheet("background-color: rgba(234, 88, 12, 0.15); color: #ea580c; padding: 4px 10px; border-radius: 6px; font-weight: 600; font-size: 11px;")
            else:
                self.badge_c3.setText("✓ Signaturen aktuell")
                self.badge_c3.setStyleSheet("background-color: rgba(16, 185, 129, 0.15); color: #059669; padding: 4px 10px; border-radius: 6px; font-weight: 600; font-size: 11px;")

        # Enable "Update All" button if any update is pending
        pending = info.total_updates_pending()
        if pending > 0:
            self.btn_update_all.setEnabled(True)
            self.btn_update_all.setText(f"  🚀 Alle aktualisieren ({pending})")
            self.lbl_status_summary.setText(f"{pending} Aktualisierung(en) verfügbar.")
        else:
            self.btn_update_all.setEnabled(False)
            self.btn_update_all.setText("  ✓ Alles auf neuestem Stand")
            self.lbl_status_summary.setText("Alle Komponenten und Schutzschilde sind auf dem neuesten Stand.")

        if info.check_error:
            self.txt_log.append(f"[Hinweis] {info.check_error}\n")

    # --------------------------------------------------------------------------
    # Single and Batch Actions
    # --------------------------------------------------------------------------
    def update_cli(self):
        helper = "yay" if shutil.which("yay") else ("paru" if shutil.which("paru") else None)
        if not helper:
            QMessageBox.information(
                self,
                "AUR-Helper fehlt",
                "Weder 'yay' noch 'paru' gefunden. Bitte führe das Update manuell aus:\n\nyay -S aur-scanner",
            )
            return

        steps = [
            UpdateStep("aur-scanner Core Engine", [helper, "-S", "--noconfirm", "aur-scanner"], "AUR-Paket aur-scanner aktualisieren")
        ]
        self.execute_batch_steps(steps)

    def update_clamav(self):
        cmd = ["freshclam"]
        if os.geteuid() != 0 and shutil.which("pkexec"):
            cmd = ["pkexec", "freshclam"]

        steps = [
            UpdateStep("ClamAV Virensignaturen (freshclam)", cmd, "Neueste Viren- und Malware-Definitionen herunterladen")
        ]
        self.execute_batch_steps(steps)

    def enable_clamav_service(self):
        is_active_or_enabled = False
        if hasattr(self, "latest_info") and self.latest_info:
            is_active_or_enabled = self.latest_info.clamav_service_active or self.latest_info.clamav_service_enabled
        else:
            try:
                res = subprocess.run(["systemctl", "is-active", "clamav-freshclam.service"], capture_output=True, text=True, check=False)
                is_active_or_enabled = (res.stdout.strip() == "active")
            except Exception:
                pass

        if is_active_or_enabled:
            cmd = ["pkexec", "systemctl", "disable", "--now", "clamav-freshclam.service"]
            steps = [
                UpdateStep("ClamAV Hintergrunddienst löschen / stoppen", cmd, "Systemd Service beenden und aus Autostart entfernen")
            ]
        else:
            cmd = ["pkexec", "systemctl", "enable", "--now", "clamav-freshclam.service"]
            steps = [
                UpdateStep("ClamAV Hintergrunddienst aktivieren", cmd, "Systemd Service & Timer starten")
            ]
        self.execute_batch_steps(steps)

    def rescan_rules(self):
        steps = [
            UpdateStep("Bedrohungs-Cache & Heuristik", ["aur-scan", "system", "--rescan", "--no-color"], "Lokalen AUR-Cache leeren und Regeln neu scannen")
        ]
        self.execute_batch_steps(steps)

    def configure_github_repo(self):
        curr = get_github_repo() or ""
        repo, ok = QInputDialog.getText(
            self,
            "GitHub-Repository verknüpfen",
            "Gib dein GitHub-Repository im Format 'Benutzername/Repository' ein:\n"
            "(z. B. lenzi96/cachy-security-suite oder die HTTPS-URL):",
            text=curr,
        )
        if ok and repo.strip():
            set_github_repo(repo.strip())
            curr_token = get_github_token() or ""
            masked_token = (curr_token[:8] + "..." + curr_token[-4:]) if len(curr_token) > 12 else curr_token
            tok, tok_ok = QInputDialog.getText(
                self,
                "GitHub Access Token (optional)",
                "Gib dein GitHub Personal Access Token (PAT) ein\n"
                "(Erforderlich für private Repositories, optional für öffentliche Repositories):\n"
                f"Aktuell hinterlegt: {masked_token if masked_token else 'Keins'}",
                text=curr_token,
            )
            if tok_ok and tok.strip():
                set_github_token(tok.strip())
            active_repo = get_github_repo()
            QMessageBox.information(
                self,
                "GitHub verknüpft",
                f"Das Update-Center ist jetzt mit GitHub verknüpft:\nhttps://github.com/{active_repo}\n\nUpdates werden künftig direkt von dort bezogen.",
            )
            self.start_check()

    def reinstall_gui(self):
        source_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        installer = os.path.join(source_dir, "install.sh")

        steps = []
        if os.path.exists(installer) and os.path.isdir(os.path.join(source_dir, ".git")):
            # In developer git repo: pull and reinstall
            try:
                res = subprocess.run(["git", "-C", source_dir, "remote"], capture_output=True, text=True, check=False)
                if "origin" in res.stdout:
                    steps.append(UpdateStep("GitHub Quellcode synchronisieren (git pull)", ["git", "-C", source_dir, "pull", "--rebase"], "Aktualisiere lokale Dateien vom GitHub-Repository"))
            except Exception:
                pass
            steps.append(UpdateStep("Cachy Security Suite Reinstallation", ["bash", installer, "--user"], "Installiere grafische Oberfläche neu", is_gui_update=True))
        else:
            # Standalone installation on any computer: download tarball and install
            ver = self.latest_info.gui_remote if self.latest_info else aur_scanner_gui.__version__
            asset_url = self.latest_info.github_asset_api_url if self.latest_info else ""
            tarball_url = self.latest_info.github_tarball_url if self.latest_info else ""
            updater_script = os.path.abspath(__file__)
            tok = get_github_token()
            cmd = [
                sys.executable,
                updater_script,
                "--download-and-install",
                "--version",
                ver,
                "--asset-url",
                asset_url or "",
                "--tarball-url",
                tarball_url or "",
            ]
            if tok:
                cmd.extend(["--token", tok])
            steps.append(UpdateStep(
                f"Cachy Security Suite v{ver} herunterladen & installieren",
                cmd,
                "Lädt das offizielle GitHub Release-Archiv herunter und installiert die neue Version",
                is_gui_update=True,
            ))

        self.execute_batch_steps(steps)

    def run_update_all(self):
        if not self.latest_info:
            return

        steps: List[UpdateStep] = []

        # 1. ClamAV
        if self.latest_info.clamav_installed and self.latest_info.clamav_needs_update:
            cmd = ["freshclam"]
            if os.geteuid() != 0 and shutil.which("pkexec"):
                cmd = ["pkexec", "freshclam"]
            steps.append(UpdateStep("ClamAV Virensignaturen", cmd, "Aktualisiere Virensignaturen"))

        # 2. CLI
        if self.latest_info.cli_has_update:
            helper = "yay" if shutil.which("yay") else ("paru" if shutil.which("paru") else None)
            if helper:
                steps.append(UpdateStep("aur-scanner Core Engine", [helper, "-S", "--noconfirm", "aur-scanner"], "Core Engine Update"))

        # 3. GUI
        if self.latest_info.gui_has_update:
            source_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            installer = os.path.join(source_dir, "install.sh")
            if os.path.exists(installer) and os.path.isdir(os.path.join(source_dir, ".git")):
                steps.append(UpdateStep("Cachy Security Suite GUI", ["bash", installer, "--user"], "GUI Suite Update", is_gui_update=True))
            else:
                updater_script = os.path.abspath(__file__)
                tok = get_github_token()
                cmd = [
                    sys.executable,
                    updater_script,
                    "--download-and-install",
                    "--version",
                    self.latest_info.gui_remote,
                    "--asset-url",
                    self.latest_info.github_asset_api_url or "",
                    "--tarball-url",
                    self.latest_info.github_tarball_url or "",
                ]
                if tok:
                    cmd.extend(["--token", tok])
                steps.append(UpdateStep(
                    f"Cachy Security Suite v{self.latest_info.gui_remote} herunterladen & installieren",
                    cmd,
                    "Lädt das offizielle GitHub Release-Archiv herunter und installiert die neue Version",
                    is_gui_update=True,
                ))

        # 4. Rules & cache
        steps.append(UpdateStep("Bedrohungsregeln & Cache", ["aur-scan", "system", "--rescan", "--no-color"], "AUR-Cache aktualisieren"))

        if not steps:
            QMessageBox.information(self, "Aktuell", "Es stehen keine ausstehenden Updates an.")
            return

        self.execute_batch_steps(steps)

    def execute_batch_steps(self, steps: List[UpdateStep]):
        self.btn_refresh.setEnabled(False)
        self.btn_update_all.setEnabled(False)
        self.btn_cancel.setVisible(True)
        self.progress_bar.setVisible(True)

        # Switch to terminal tab so user can see live progress
        self.tabs.setCurrentIndex(2)

        self.batch_worker = BatchUpdateWorker(steps)
        self.batch_worker.step_started.connect(self.on_step_started)
        self.batch_worker.output_line.connect(self.on_log_line)
        self.batch_worker.all_completed.connect(self.on_batch_completed)
        self.batch_worker.start()

    def cancel_active_process(self):
        if self.batch_worker:
            self.batch_worker.cancel()
            self.btn_cancel.setEnabled(False)

    def on_step_started(self, current: int, total: int, title: str):
        self.lbl_status_summary.setText(f"Führe aus ({current}/{total}): {title}...")

    def on_log_line(self, line: str):
        cursor = self.txt_log.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        cursor.insertText(line + "\n")
        self.txt_log.setTextCursor(cursor)
        self.txt_log.ensureCursorVisible()

    def on_batch_completed(self, success: bool, message: str, gui_was_updated: bool):
        self.progress_bar.setVisible(False)
        self.btn_cancel.setVisible(False)
        self.btn_cancel.setEnabled(True)
        self.btn_refresh.setEnabled(True)

        self.lbl_status_summary.setText(message)

        if success:
            self.txt_log.append(f"\n[✓] {message}\n")
            if gui_was_updated:
                reply = QMessageBox.question(
                    self,
                    "Update abgeschlossen - Neustart?",
                    "Die Cachy Security Suite wurde erfolgreich aktualisiert!\n\n"
                    "Möchten Sie die Anwendung jetzt neu starten, um die Änderungen zu übernehmen?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                    QMessageBox.StandardButton.Yes,
                )
                if reply == QMessageBox.StandardButton.Yes:
                    self.restart_application()
            else:
                QMessageBox.information(self, "Erfolg", message)
        else:
            self.txt_log.append(f"\n[✗] {message}\n")
            QMessageBox.warning(self, "Hinweis", f"{message}\n\nDetails finden Sie im Terminal-Ausgabe-Reiter.")

        self.start_check()

    def restart_application(self):
        """Cleanly restarts Cachy Security Suite."""
        launcher = shutil.which("cachy-security-suite") or shutil.which("aur-scanner-gui") or sys.executable
        if launcher == sys.executable:
            QProcess.startDetached(sys.executable, sys.argv)
        else:
            QProcess.startDetached(launcher, [])
        QApplication.quit()


def download_and_install_release(version: str = "", asset_url: str = "", tarball_url: str = "", token: str = "") -> int:
    """
    Downloads GitHub release tarball, extracts it to /tmp, and executes install.sh --user.
    Supports both public repositories and private repositories with token.
    """
    import tempfile

    repo = get_github_repo() or DEFAULT_GITHUB_REPO
    token = token.strip() if token else (get_github_token() or "")

    # Always fetch latest live asset url directly from GitHub API when token is present
    if token:
        try:
            tag_slug = f"tags/v{version}" if version and not version.startswith("v") else (f"tags/{version}" if version else "latest")
            api_rel = f"https://api.github.com/repos/{repo}/releases/{tag_slug}"
            req = urllib.request.Request(api_rel, headers={
                "User-Agent": "cachy-security-suite",
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json"
            })
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                version = data.get("tag_name", "").lstrip("v").strip() or version
                for asset in data.get("assets", []):
                    if asset.get("name", "").endswith((".tar.gz", ".zip")):
                        asset_url = asset.get("url", "")
                        tarball_url = asset.get("browser_download_url", "")
                        break
        except Exception as e:
            pass

    if not version:
        try:
            gh_url = f"https://api.github.com/repos/{repo}/releases/latest"
            headers = {"User-Agent": "cachy-security-suite", "Accept": "application/vnd.github+json"}
            if token:
                headers["Authorization"] = f"Bearer {token}"
            req = urllib.request.Request(gh_url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode())
                version = data.get("tag_name", "").lstrip("v").strip()
                for asset in data.get("assets", []):
                    if asset.get("name", "").endswith((".tar.gz", ".zip")):
                        tarball_url = asset.get("browser_download_url", "")
                        asset_url = asset.get("url", "")
                        break
        except Exception as e:
            print(f"[FEHLER] Konnte Release-Informationen von GitHub nicht abrufen: {e}")
            return 1

    print("=======================================================")
    print("  Cachy Security Suite - Automatischer Release-Updater  ")
    print("=======================================================")
    print(f"Ziel-Version : v{version}")
    print(f"Repository   : {repo}")
    print(f"Token aktiv  : {'Ja' if token else 'Nein (Öffentliches Repo)'}")
    print("-------------------------------------------------------")

    tmp_dir = tempfile.mkdtemp(prefix="cachy_suite_update_")
    tar_path = os.path.join(tmp_dir, f"cachy-security-suite-v{version}.tar.gz")
    unpack_dir = os.path.join(tmp_dir, "unpacked")

    try:
        download_url = asset_url if (token and asset_url) else tarball_url
        if not download_url:
            download_url = f"https://github.com/{repo}/releases/download/v{version}/cachy-security-suite-v{version}.tar.gz"

        print("[1/4] Lade Release-Paket herunter...")
        curl_bin = shutil.which("curl")
        download_ok = False

        if curl_bin:
            curl_cmd = [curl_bin, "-sSL", "-f"]
            if token:
                curl_cmd.extend(["-H", f"Authorization: Bearer {token}"])
            curl_cmd.extend(["-H", "Accept: application/octet-stream", download_url, "-o", tar_path])
            res = subprocess.run(curl_cmd, check=False)
            if res.returncode == 0 and os.path.exists(tar_path) and os.path.getsize(tar_path) > 1000:
                download_ok = True

        if not download_ok:
            class NoAuthRedirect(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, req, fp, code, msg, headers, newurl):
                    new_req = super().redirect_request(req, fp, code, msg, headers, newurl)
                    if new_req and "Authorization" in new_req.headers:
                        del new_req.headers["Authorization"]
                    return new_req

            opener = urllib.request.build_opener(NoAuthRedirect)
            headers = {"User-Agent": "Cachy-Security-Suite"}
            if token and "api.github.com" in download_url:
                headers["Authorization"] = f"Bearer {token}"
                headers["Accept"] = "application/octet-stream"
            req = urllib.request.Request(download_url, headers=headers)
            try:
                with opener.open(req, timeout=30) as resp, open(tar_path, "wb") as out_f:
                    shutil.copyfileobj(resp, out_f)
                if os.path.exists(tar_path) and os.path.getsize(tar_path) > 1000:
                    download_ok = True
            except Exception as e:
                print(f"[Hinweis] urllib Download: {e}")

        if not download_ok:
            print("[FEHLER] Herunterladen des Release-Archivs fehlgeschlagen.")
            print("Hinweis: Falls das Repository privat ist, stelle sicher, dass ein gültiges Token hinterlegt ist.")
            return 1

        size_mb = os.path.getsize(tar_path) / (1024 * 1024)
        print(f"✓ Download erfolgreich ({size_mb:.2f} MB)")

        print("[2/4] Entpacke Archiv...")
        os.makedirs(unpack_dir, exist_ok=True)
        res_tar = subprocess.run(["tar", "-xzf", tar_path, "-C", unpack_dir], check=False)
        if res_tar.returncode != 0:
            print("[FEHLER] Archiv konnte nicht entpackt werden.")
            return 1
        print("✓ Entpacken abgeschlossen.")

        # Find install.sh inside unpacked folder
        installer_path = None
        for root, dirs, files in os.walk(unpack_dir):
            if "install.sh" in files:
                installer_path = os.path.join(root, "install.sh")
                break

        if not installer_path:
            print("[FEHLER] install.sh im entpackten Release-Archiv nicht gefunden.")
            return 1

        print(f"[3/4] Führe Installation aus ({installer_path} --user)...")
        os.chmod(installer_path, 0o755)
        res_inst = subprocess.run(["bash", installer_path, "--user"], check=False)
        if res_inst.returncode != 0:
            print(f"[FEHLER] Installation schlug fehl mit Exit-Code {res_inst.returncode}")
            return res_inst.returncode

        print("[4/4] Bereinige temporäre Dateien...")
        print(f"✓ Cachy Security Suite wurde erfolgreich auf v{version} aktualisiert!")
        return 0

    finally:
        try:
            shutil.rmtree(tmp_dir)
        except Exception:
            pass


if __name__ == "__main__":
    if any(arg in sys.argv for arg in ("--download-and-install", "-h", "--help")):
        import argparse
        parser = argparse.ArgumentParser(description="Cachy Security Suite Standalone Release Installer")
        parser.add_argument("--download-and-install", action="store_true")
        parser.add_argument("--version", default="")
        parser.add_argument("--asset-url", default="")
        parser.add_argument("--tarball-url", default="")
        parser.add_argument("--token", default="")
        args, _ = parser.parse_known_args()
        if args.download_and_install:
            sys.exit(download_and_install_release(args.version, args.asset_url, args.tarball_url, args.token))

