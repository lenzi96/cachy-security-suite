"""
AUR Package Download Dialog for Cachy Security Suite.
Enables downloading PKGBUILDs, snapshots and git repositories directly from the AUR,
with immediate post-download security scanning and antivirus audit actions.
"""
import json
import os
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from typing import Optional

from PyQt6.QtCore import QSettings, Qt, QThread, QUrl, pyqtSignal
from PyQt6.QtGui import QDesktopServices, QFont, QIcon
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
)


class AurDownloadWorker(QThread):
    progress_msg = pyqtSignal(str)
    finished = pyqtSignal(bool, str, str)  # success, target_path, message

    def __init__(self, pkg_name: str, target_dir: str, method: str = "snapshot"):
        super().__init__()
        self.pkg_name = pkg_name.strip()
        self.target_dir = os.path.expanduser(target_dir.strip())
        self.method = method

    def run(self):
        try:
            # 1. Query AUR RPC to confirm package exists
            self.progress_msg.emit(f"Frage AUR RPC API für '{self.pkg_name}' ab...")
            url = f"https://aur.archlinux.org/rpc/v5/info?arg[]={urllib.parse.quote(self.pkg_name)}"
            req = urllib.request.Request(url, headers={"User-Agent": "Cachy-Security-Suite/1.0.0"})

            try:
                with urllib.request.urlopen(req, timeout=10) as resp:
                    data = json.loads(resp.read().decode())
                    results = data.get("results", [])
                    if not results:
                        self.finished.emit(False, "", f"Paket '{self.pkg_name}' wurde im AUR nicht gefunden.")
                        return
                    pkg_info = results[0]
                    self.progress_msg.emit(
                        f"✓ Paket gefunden: {pkg_info.get('Name')} v{pkg_info.get('Version')} "
                        f"({pkg_info.get('Description', 'Keine Beschreibung')})"
                    )
            except Exception as e:
                self.progress_msg.emit(f"Hinweis: AUR RPC Abfrage fehlgeschlagen ({e}), versuche direkten Download...")

            # 2. Ensure target directory exists
            os.makedirs(self.target_dir, exist_ok=True)
            dest_dir = os.path.join(self.target_dir, self.pkg_name)

            # 3. Perform Download
            if self.method == "git" and shutil.which("git"):
                git_url = f"https://aur.archlinux.org/{self.pkg_name}.git"
                if os.path.isdir(os.path.join(dest_dir, ".git")):
                    self.progress_msg.emit(f"Bestehendes Git-Repository gefunden in: {dest_dir}")
                    self.progress_msg.emit("Führe 'git pull' aus...")
                    proc = subprocess.run(
                        ["git", "-C", dest_dir, "pull"],
                        capture_output=True,
                        text=True,
                    )
                    if proc.returncode != 0:
                        self.progress_msg.emit(f"Warnung bei git pull: {proc.stderr.strip()}")
                else:
                    self.progress_msg.emit(f"Klone Git-Repository: {git_url} ...")
                    proc = subprocess.run(
                        ["git", "clone", git_url, dest_dir],
                        capture_output=True,
                        text=True,
                    )
                    if proc.returncode != 0:
                        self.progress_msg.emit(f"Git-Clone fehlgeschlagen ({proc.stderr.strip()}), wechsle zu Snapshot-Archiv...")
                        self._download_snapshot(dest_dir)
            else:
                self._download_snapshot(dest_dir)

            # 4. Verification
            pkgbuild_file = os.path.join(dest_dir, "PKGBUILD")
            if os.path.isfile(pkgbuild_file):
                self.progress_msg.emit(f"✓ PKGBUILD erfolgreich verifiziert: {pkgbuild_file}")
                self.finished.emit(True, pkgbuild_file, f"Paket '{self.pkg_name}' erfolgreich nach '{dest_dir}' heruntergeladen!")
            elif os.path.isdir(dest_dir):
                self.progress_msg.emit(f"✓ Ordner erfolgreich erstellt: {dest_dir}")
                self.finished.emit(True, dest_dir, f"Paket '{self.pkg_name}' erfolgreich nach '{dest_dir}' heruntergeladen!")
            else:
                self.finished.emit(False, "", "Download abgeschlossen, aber Zielverzeichnis wurde nicht gefunden.")

        except Exception as exc:
            self.progress_msg.emit(f"Fehler beim Download: {exc}")
            self.finished.emit(False, "", str(exc))

    def _download_snapshot(self, dest_dir: str):
        snapshot_url = f"https://aur.archlinux.org/cgit/aur.git/snapshot/{self.pkg_name}.tar.gz"
        self.progress_msg.emit(f"Lade Snapshot-Archiv herunter: {snapshot_url} ...")

        with tempfile.TemporaryDirectory() as tmpdir:
            archive_path = os.path.join(tmpdir, f"{self.pkg_name}.tar.gz")
            req = urllib.request.Request(snapshot_url, headers={"User-Agent": "Cachy-Security-Suite/1.0.0"})
            with urllib.request.urlopen(req, timeout=15) as response, open(archive_path, "wb") as out_file:
                shutil.copyfileobj(response, out_file)

            self.progress_msg.emit(f"Archivgröße: {os.path.getsize(archive_path)} Bytes. Entpacke Quellcode...")
            with tarfile.open(archive_path, "r:gz") as tar:
                tar.extractall(self.target_dir)


class AurDownloadDialog(QDialog):
    # Signals to communicate actions back to main window or views
    request_local_scan = pyqtSignal(str)
    request_antivirus_scan = pyqtSignal(str)

    def __init__(self, prefill_pkg: str = "", parent=None):
        super().__init__(parent)
        self.setWindowTitle("AUR-Paket herunterladen & analysieren")
        self.resize(680, 520)
        self.setMinimumSize(600, 460)

        self.settings = QSettings("CachySecurity", "Suite")
        self.downloaded_path = ""
        self.worker: Optional[AurDownloadWorker] = None

        self.init_ui(prefill_pkg)

    def init_ui(self, prefill_pkg: str):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(12)

        # 1. Header
        header_layout = QHBoxLayout()
        header_layout.setSpacing(12)

        icon_lbl = QLabel("📥")
        icon_lbl.setStyleSheet("font-size: 32px;")
        header_layout.addWidget(icon_lbl)

        title_layout = QVBoxLayout()
        title_layout.setSpacing(2)
        lbl_title = QLabel("AUR-Quellcode herunterladen")
        lbl_title.setStyleSheet("font-size: 17px; font-weight: 800; color: palette(text);")
        lbl_sub = QLabel("Lädt PKGBUILD, .SRCINFO und alle Begleitdateien direkt aus dem offiziellen AUR.")
        lbl_sub.setStyleSheet("font-size: 12px; color: palette(text); opacity: 0.75;")
        title_layout.addWidget(lbl_title)
        title_layout.addWidget(lbl_sub)
        header_layout.addLayout(title_layout, stretch=1)
        layout.addLayout(header_layout)

        # 2. Input Configuration Card
        card = QFrame()
        card.setObjectName("dlConfigCard")
        card.setStyleSheet("""
            QFrame#dlConfigCard {
                background-color: palette(base);
                border: 1px solid palette(mid);
                border-radius: 10px;
                padding: 10px;
            }
        """)
        c_layout = QVBoxLayout(card)
        c_layout.setSpacing(10)

        # Package name input
        pkg_row = QHBoxLayout()
        lbl_pkg = QLabel("Paketname:")
        lbl_pkg.setFixedWidth(110)
        lbl_pkg.setStyleSheet("font-weight: 600; font-size: 12px;")
        self.edit_pkg = QLineEdit(prefill_pkg)
        self.edit_pkg.setPlaceholderText("z. B. visual-studio-code-bin, discord, yay...")
        self.edit_pkg.setStyleSheet("""
            QLineEdit {
                border: 1px solid palette(mid);
                border-radius: 6px;
                padding: 6px 10px;
                background-color: palette(window);
                font-size: 12px;
            }
            QLineEdit:focus { border: 1px solid #3b82f6; }
        """)
        pkg_row.addWidget(lbl_pkg)
        pkg_row.addWidget(self.edit_pkg)
        c_layout.addLayout(pkg_row)

        # Target Directory input
        dir_row = QHBoxLayout()
        lbl_dir = QLabel("Zielordner:")
        lbl_dir.setFixedWidth(110)
        lbl_dir.setStyleSheet("font-weight: 600; font-size: 12px;")

        default_dir = self.settings.value("download_target_dir", os.path.expanduser("~/Downloads/aur-packages"))
        self.edit_dir = QLineEdit(default_dir)
        self.edit_dir.setStyleSheet("""
            QLineEdit {
                border: 1px solid palette(mid);
                border-radius: 6px;
                padding: 6px 10px;
                background-color: palette(window);
                font-size: 12px;
            }
            QLineEdit:focus { border: 1px solid #3b82f6; }
        """)

        btn_browse_dir = QPushButton("Durchsuchen...")
        btn_browse_dir.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_browse_dir.setStyleSheet("""
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
        btn_browse_dir.clicked.connect(self.browse_directory)

        dir_row.addWidget(lbl_dir)
        dir_row.addWidget(self.edit_dir, stretch=1)
        dir_row.addWidget(btn_browse_dir)
        c_layout.addLayout(dir_row)

        # Download Method input
        method_row = QHBoxLayout()
        lbl_method = QLabel("Methode:")
        lbl_method.setFixedWidth(110)
        lbl_method.setStyleSheet("font-weight: 600; font-size: 12px;")

        self.combo_method = QComboBox()
        self.combo_method.addItem("AUR Snapshot (.tar.gz - Schnell & Zuverlässig)", "snapshot")
        if shutil.which("git"):
            self.combo_method.addItem("Git Clone (Vollständige Commit-Historie)", "git")
        self.combo_method.setStyleSheet("""
            QComboBox {
                border: 1px solid palette(mid);
                border-radius: 6px;
                padding: 5px 10px;
                background-color: palette(window);
                font-size: 12px;
            }
        """)

        method_row.addWidget(lbl_method)
        method_row.addWidget(self.combo_method, stretch=1)
        c_layout.addLayout(method_row)

        layout.addWidget(card)

        # 3. Post-Download Actions Card
        opt_card = QFrame()
        opt_card.setObjectName("optCard")
        opt_card.setStyleSheet("""
            QFrame#optCard {
                background-color: palette(base);
                border: 1px solid palette(mid);
                border-radius: 10px;
                padding: 10px;
            }
        """)
        opt_layout = QVBoxLayout(opt_card)
        opt_layout.setSpacing(6)

        lbl_opt = QLabel("Aktionen nach erfolgreichem Download:")
        lbl_opt.setStyleSheet("font-weight: 600; font-size: 12px; margin-bottom: 2px;")
        opt_layout.addWidget(lbl_opt)

        self.chk_open_scanner = QCheckBox("Direkt im PKGBUILD-Sicherheits-Scan analysieren")
        self.chk_open_scanner.setChecked(True)
        self.chk_open_scanner.setStyleSheet("font-size: 12px;")
        opt_layout.addWidget(self.chk_open_scanner)

        self.chk_open_antivirus = QCheckBox("Im Virenscanner (ClamAV && Threat-Intel) prüfen")
        self.chk_open_antivirus.setChecked(False)
        self.chk_open_antivirus.setStyleSheet("font-size: 12px;")
        opt_layout.addWidget(self.chk_open_antivirus)

        self.chk_open_folder = QCheckBox("Im Dateimanager (Dolphin) öffnen")
        self.chk_open_folder.setChecked(True)
        self.chk_open_folder.setStyleSheet("font-size: 12px;")
        opt_layout.addWidget(self.chk_open_folder)

        layout.addWidget(opt_card)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setFixedHeight(4)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: none;
                background: transparent;
                border-radius: 2px;
            }
            QProgressBar::chunk {
                background-color: #3b82f6;
                border-radius: 2px;
            }
        """)
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # Log Window
        self.txt_log = QTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setFixedHeight(110)
        self.txt_log.setFont(QFont("JetBrains Mono, monospace", 9))
        self.txt_log.setStyleSheet("""
            QTextEdit {
                background-color: palette(window);
                color: palette(text);
                border: 1px solid palette(mid);
                border-radius: 6px;
                padding: 6px;
            }
        """)
        layout.addWidget(self.txt_log)

        # Action Buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(10)

        self.btn_action_scanner = QPushButton("🔍 Im PKGBUILD-Scan öffnen")
        self.btn_action_scanner.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_action_scanner.setVisible(False)
        self.btn_action_scanner.setStyleSheet("""
            QPushButton {
                background-color: #059669;
                color: white;
                font-weight: 600;
                font-size: 12px;
                padding: 6px 14px;
                border-radius: 6px;
                border: none;
            }
            QPushButton:hover { background-color: #047857; }
        """)
        self.btn_action_scanner.clicked.connect(self.action_open_local_scan)

        self.btn_action_folder = QPushButton("📁 Ordner öffnen")
        self.btn_action_folder.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_action_folder.setVisible(False)
        self.btn_action_folder.setStyleSheet("""
            QPushButton {
                padding: 6px 12px;
                border-radius: 6px;
                border: 1px solid palette(mid);
                background: palette(window);
                font-size: 12px;
            }
            QPushButton:hover { background: palette(button); }
        """)
        self.btn_action_folder.clicked.connect(self.action_open_folder)

        btn_layout.addWidget(self.btn_action_scanner)
        btn_layout.addWidget(self.btn_action_folder)
        btn_layout.addStretch()

        self.btn_download = QPushButton("  Download starten")
        self.btn_download.setIcon(QIcon.fromTheme("download"))
        self.btn_download.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_download.setStyleSheet("""
            QPushButton {
                background-color: #2563eb;
                color: white;
                font-weight: 600;
                font-size: 12px;
                padding: 7px 20px;
                border-radius: 6px;
                border: none;
            }
            QPushButton:hover { background-color: #1d4ed8; }
        """)
        self.btn_download.clicked.connect(self.start_download)

        self.btn_close = QPushButton("Schließen")
        self.btn_close.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_close.setStyleSheet("""
            QPushButton {
                padding: 7px 16px;
                border-radius: 6px;
                border: 1px solid palette(mid);
                background: palette(window);
                font-size: 12px;
            }
            QPushButton:hover { background: palette(button); }
        """)
        self.btn_close.clicked.connect(self.close)

        btn_layout.addWidget(self.btn_download)
        btn_layout.addWidget(self.btn_close)
        layout.addLayout(btn_layout)

    def browse_directory(self):
        curr = self.edit_dir.text().strip() or os.path.expanduser("~")
        chosen = QFileDialog.getExistingDirectory(self, "Zielordner für AUR-Pakete wählen", curr)
        if chosen:
            self.edit_dir.setText(chosen)
            self.settings.setValue("download_target_dir", chosen)

    def start_download(self):
        pkg_name = self.edit_pkg.text().strip()
        target_dir = self.edit_dir.text().strip()
        method = self.combo_method.currentData()

        if not pkg_name:
            QMessageBox.warning(self, "Fehlende Eingabe", "Bitte gib einen gültigen AUR-Paketnamen ein.")
            return

        if not target_dir:
            QMessageBox.warning(self, "Fehlende Eingabe", "Bitte wähle ein Zielverzeichnis aus.")
            return

        self.settings.setValue("download_target_dir", target_dir)

        self.btn_download.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.txt_log.clear()
        self.btn_action_scanner.setVisible(False)
        self.btn_action_folder.setVisible(False)

        self.txt_log.append(f"Starte Download von '{pkg_name}' nach '{target_dir}'...")

        self.worker = AurDownloadWorker(pkg_name, target_dir, method)
        self.worker.progress_msg.connect(self.on_log_line)
        self.worker.finished.connect(self.on_download_finished)
        self.worker.start()

    def on_log_line(self, line: str):
        self.txt_log.append(line)
        cursor = self.txt_log.textCursor()
        self.txt_log.setTextCursor(cursor)
        self.txt_log.ensureCursorVisible()

    def on_download_finished(self, success: bool, target_path: str, msg: str):
        self.btn_download.setEnabled(True)
        self.progress_bar.setVisible(False)

        if success:
            self.downloaded_path = target_path
            self.txt_log.append(f"\n✓ {msg}\n")

            self.btn_action_scanner.setVisible(True)
            self.btn_action_folder.setVisible(True)

            # Auto-actions
            pkg_dir = os.path.dirname(target_path) if os.path.isfile(target_path) else target_path

            if self.chk_open_folder.isChecked():
                QDesktopServices.openUrl(QUrl.fromLocalFile(pkg_dir))

            if self.chk_open_scanner.isChecked():
                self.request_local_scan.emit(target_path)
                self.accept()
                return

            if self.chk_open_antivirus.isChecked():
                self.request_antivirus_scan.emit(pkg_dir)
                self.accept()
                return

            QMessageBox.information(
                self,
                "Download abgeschlossen",
                f"Das Paket wurde erfolgreich heruntergeladen:\n{target_path}\n\n"
                "Du kannst es jetzt im PKGBUILD-Scan oder Virenscanner analysieren.",
            )
        else:
            self.txt_log.append(f"\n✗ {msg}\n")
            QMessageBox.critical(self, "Download fehlgeschlagen", f"Download von '{self.edit_pkg.text()}' fehlgeschlagen:\n{msg}")

    def action_open_local_scan(self):
        if self.downloaded_path:
            self.request_local_scan.emit(self.downloaded_path)
            self.accept()

    def action_open_folder(self):
        if self.downloaded_path:
            pkg_dir = os.path.dirname(self.downloaded_path) if os.path.isfile(self.downloaded_path) else self.downloaded_path
            QDesktopServices.openUrl(QUrl.fromLocalFile(pkg_dir))
