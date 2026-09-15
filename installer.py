#!/usr/bin/env python3
"""
Modern Graphical Installer (Setup Wizard) for AUR Security Scanner.
"""
import os
import shutil
import subprocess
import sys
import time

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QIcon, QPixmap
from PyQt6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QCheckBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QRadioButton,
    QStackedWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


class InstallWorker(QThread):
    step_changed = pyqtSignal(str, int)  # message, percent
    log_line = pyqtSignal(str)
    finished = pyqtSignal(bool, str)

    def __init__(self, is_user_mode: bool, create_desktop_icon: bool, create_menu_icon: bool):
        super().__init__()
        self.is_user_mode = is_user_mode
        self.create_desktop_icon = create_desktop_icon
        self.create_menu_icon = create_menu_icon

    def run(self):
        try:
            source_dir = os.path.dirname(os.path.abspath(__file__))
            prefix = os.path.expanduser("~/.local") if self.is_user_mode else "/usr"
            bin_dir = os.path.join(prefix, "bin")
            share_dir = os.path.join(prefix, "share", "aur-scanner-gui")
            app_dir = os.path.join(prefix, "share", "applications")
            icon_svg_dir = os.path.join(prefix, "share", "icons", "hicolor", "scalable", "apps")
            icon_png_dir = os.path.join(prefix, "share", "icons", "hicolor", "256x256", "apps")

            self.step_changed.emit("Erstelle Zielverzeichnisse...", 15)
            self.log_line.emit(f"Ziel-Präfix: {prefix}")
            for d in [bin_dir, share_dir, app_dir, icon_svg_dir, icon_png_dir]:
                os.makedirs(d, exist_ok=True)
                self.log_line.emit(f"Erstelle Ordner: {d}")
            time.sleep(0.3)

            # Copy application files
            self.step_changed.emit("Kopiere Anwendungsdateien...", 40)
            target_pkg_dir = os.path.join(share_dir, "aur_scanner_gui")
            if os.path.exists(target_pkg_dir):
                shutil.rmtree(target_pkg_dir)
            shutil.copytree(os.path.join(source_dir, "aur_scanner_gui"), target_pkg_dir)
            self.log_line.emit("Paket 'aur_scanner_gui' kopiert.")

            shutil.copy2(os.path.join(source_dir, "main.py"), os.path.join(share_dir, "main.py"))
            os.chmod(os.path.join(share_dir, "main.py"), 0o755)
            self.log_line.emit("Hauptskript 'main.py' kopiert und Berechtigungen gesetzt.")
            time.sleep(0.3)

            # Copy Icons
            self.step_changed.emit("Installiere Anwendungs-Icons...", 60)
            res_dir = os.path.join(source_dir, "resources")
            target_res = os.path.join(share_dir, "resources")
            os.makedirs(target_res, exist_ok=True)
            if os.path.exists(res_dir):
                for item in os.listdir(res_dir):
                    s_file = os.path.join(res_dir, item)
                    t_file = os.path.join(target_res, item)
                    if os.path.isfile(s_file):
                        shutil.copy2(s_file, t_file)

            svg_src = os.path.join(res_dir, "aur-scanner.svg")
            if os.path.exists(svg_src):
                shutil.copy2(svg_src, os.path.join(icon_svg_dir, "aur-scanner.svg"))
                self.log_line.emit("Vektor-Icon (SVG) installiert.")

            png_src = os.path.join(res_dir, "aur-scanner-256.png")
            if os.path.exists(png_src):
                shutil.copy2(png_src, os.path.join(icon_png_dir, "aur-scanner.png"))
                self.log_line.emit("High-Res Icon (256x256 PNG) installiert.")
            time.sleep(0.2)

            # Create Launcher Executables
            self.step_changed.emit("Erstelle Starter-Skripte...", 75)
            launcher_path = os.path.join(bin_dir, "cachy-security-suite")
            launcher_content = f"""#!/usr/bin/env bash
exec python3 "{os.path.join(share_dir, 'main.py')}" "$@"
"""
            with open(launcher_path, "w", encoding="utf-8") as f:
                f.write(launcher_content)
            os.chmod(launcher_path, 0o755)
            self.log_line.emit(f"Starter erstellt: {launcher_path}")

            # Legacy / compatibility symlink/script
            legacy_launcher = os.path.join(bin_dir, "aur-scanner-gui")
            try:
                if os.path.islink(legacy_launcher) or os.path.exists(legacy_launcher):
                    os.remove(legacy_launcher)
                os.symlink("cachy-security-suite", legacy_launcher)
            except Exception:
                with open(legacy_launcher, "w", encoding="utf-8") as f:
                    f.write(launcher_content)
                os.chmod(legacy_launcher, 0o755)
            time.sleep(0.2)

            # Create Desktop Entry
            if self.create_menu_icon:
                self.step_changed.emit("Richte Startmenü-Verknüpfung ein...", 85)
                desktop_path = os.path.join(app_dir, "cachy-security-suite.desktop")
                desktop_content = f"""[Desktop Entry]
Name=Cachy Security Suite
Comment=Security and audit suite for Arch Linux & CachyOS
GenericName=Security Suite
Exec={launcher_path}
Icon=aur-scanner
Terminal=false
Type=Application
Categories=System;Security;Utility;
Keywords=cachy;cachyos;security;scanner;aur;clamav;antivirus;arch;pkgbuild;pacman;
StartupNotify=true
StartupWMClass=cachy-security-suite
"""
                with open(desktop_path, "w", encoding="utf-8") as f:
                    f.write(desktop_content)
                self.log_line.emit(f"Desktop-Datei erstellt: {desktop_path}")

                # Compatibility desktop entry
                legacy_desktop = os.path.join(app_dir, "aur-scanner-gui.desktop")
                try:
                    with open(legacy_desktop, "w", encoding="utf-8") as f:
                        f.write(desktop_content)
                except Exception:
                    pass

            # Optional: Desktop shortcut on ~/Desktop
            if self.create_desktop_icon:
                user_desktop = os.path.expanduser("~/Desktop")
                if os.path.exists(user_desktop):
                    sh_desktop = os.path.join(user_desktop, "cachy-security-suite.desktop")
                    shutil.copy2(desktop_path, sh_desktop)
                    os.chmod(sh_desktop, 0o755)
                    self.log_line.emit(f"Desktop-Verknüpfung angelegt: {sh_desktop}")

            # Update desktop database & icon cache
            self.step_changed.emit("Aktualisiere System-Caches...", 95)
            if shutil.which("update-desktop-database"):
                subprocess.run(["update-desktop-database", app_dir], capture_output=True, check=False)
                self.log_line.emit("Desktop-Datenbank aktualisiert.")

            if shutil.which("gtk-update-icon-cache"):
                subprocess.run(["gtk-update-icon-cache", "-q", os.path.join(prefix, "share", "icons", "hicolor")], capture_output=True, check=False)
                self.log_line.emit("Icon-Cache aktualisiert.")

            self.step_changed.emit("Fertig!", 100)
            self.log_line.emit("Installation erfolgreich abgeschlossen.")
            time.sleep(0.4)
            self.finished.emit(True, launcher_path)

        except Exception as exc:
            self.log_line.emit(f"FEHLER: {exc}")
            self.finished.emit(False, str(exc))


class GraphicalInstaller(QDialog):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cachy Security Suite - Installationsassistent")
        self.resize(760, 520)
        self.setMinimumSize(700, 480)

        # Set Window Icon
        source_dir = os.path.dirname(os.path.abspath(__file__))
        icon_path = os.path.join(source_dir, "resources", "aur-scanner-256.png")
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))

        self.installed_launcher = ""
        self.init_ui()

    def init_ui(self):
        root_layout = QHBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # ----------------------------------------------------------------------
        # LEFT DARK-SLATE SIDEBAR BANNER
        # ----------------------------------------------------------------------
        sidebar = QFrame()
        sidebar.setFixedWidth(230)
        sidebar.setStyleSheet("""
            QFrame {
                background-color: #0f172a;
                border-right: 1px solid #1e293b;
            }
            QLabel {
                background: transparent;
                border: none;
            }
        """)
        side_layout = QVBoxLayout(sidebar)
        side_layout.setContentsMargins(20, 24, 20, 20)
        side_layout.setSpacing(12)

        # Logo
        source_dir = os.path.dirname(os.path.abspath(__file__))
        logo_path = os.path.join(source_dir, "resources", "aur-scanner-64.png")
        logo_lbl = QLabel()
        if os.path.exists(logo_path):
            logo_lbl.setPixmap(QPixmap(logo_path).scaled(56, 56, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
        side_layout.addWidget(logo_lbl)

        # Title
        title_lbl = QLabel("Cachy Security")
        title_lbl.setStyleSheet("font-size: 17px; font-weight: 800; color: #f8fafc;")
        sub_lbl = QLabel("INSTALLATIONS-ASSISTENT")
        sub_lbl.setStyleSheet("font-size: 10px; font-weight: 700; color: #38bdf8; letter-spacing: 0.8px;")

        side_layout.addWidget(title_lbl)
        side_layout.addWidget(sub_lbl)

        # Steps indicator
        div = QFrame()
        div.setFrameShape(QFrame.Shape.HLine)
        div.setStyleSheet("background-color: #1e293b; max-height: 1px; margin: 10px 0px 14px 0px; border: none;")
        side_layout.addWidget(div)

        self.step_labels = []
        steps = ["1. Systemprüfung", "2. Optionen", "3. Installation", "4. Fertigstellung"]
        for i, st in enumerate(steps):
            lbl = QLabel(st)
            lbl.setStyleSheet("font-size: 12px; color: #64748b; font-weight: 500;")
            self.step_labels.append(lbl)
            side_layout.addWidget(lbl)

        side_layout.addStretch()

        ver_lbl = QLabel("Version 1.0.0 (Arch Linux)")
        ver_lbl.setStyleSheet("font-size: 10px; color: #94a3b8;")
        side_layout.addWidget(ver_lbl)

        root_layout.addWidget(sidebar)

        # ----------------------------------------------------------------------
        # RIGHT WIZARD PAGES
        # ----------------------------------------------------------------------
        right_container = QWidget()
        right_container.setStyleSheet("background-color: palette(window);")
        right_layout = QVBoxLayout(right_container)
        right_layout.setContentsMargins(28, 24, 28, 20)
        right_layout.setSpacing(16)

        self.pages = QStackedWidget()

        # Page 0: Welcome & System Check
        self.page_welcome = self.create_page_welcome()
        self.pages.addWidget(self.page_welcome)

        # Page 1: Options
        self.page_options = self.create_page_options()
        self.pages.addWidget(self.page_options)

        # Page 2: Progress & Log
        self.page_progress = self.create_page_progress()
        self.pages.addWidget(self.page_progress)

        # Page 3: Finish
        self.page_finish = self.create_page_finish()
        self.pages.addWidget(self.page_finish)

        right_layout.addWidget(self.pages, stretch=1)

        # Bottom Button Bar
        btn_bar = QHBoxLayout()
        btn_bar.setSpacing(10)

        self.btn_cancel = QPushButton("Abbrechen")
        self.btn_cancel.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_cancel.clicked.connect(self.close)
        self.btn_cancel.setStyleSheet("""
            QPushButton {
                padding: 7px 16px;
                border-radius: 6px;
                border: 1px solid palette(mid);
                background: palette(window);
                font-size: 12px;
            }
        """)

        self.btn_back = QPushButton("Zurück")
        self.btn_back.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_back.clicked.connect(self.prev_step)
        self.btn_back.setEnabled(False)
        self.btn_back.setStyleSheet("""
            QPushButton {
                padding: 7px 16px;
                border-radius: 6px;
                border: 1px solid palette(mid);
                background: palette(window);
                font-size: 12px;
            }
        """)

        self.btn_next = QPushButton("Weiter  →")
        self.btn_next.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_next.clicked.connect(self.next_step)
        self.btn_next.setStyleSheet("""
            QPushButton {
                background-color: #2563eb;
                color: #ffffff;
                font-weight: 600;
                font-size: 12px;
                padding: 7px 22px;
                border-radius: 6px;
                border: none;
            }
            QPushButton:hover {
                background-color: #1d4ed8;
            }
        """)

        btn_bar.addWidget(self.btn_cancel)
        btn_bar.addStretch()
        btn_bar.addWidget(self.btn_back)
        btn_bar.addWidget(self.btn_next)
        right_layout.addLayout(btn_bar)

        root_layout.addWidget(right_container)

        self.update_step_indicator(0)

    # --------------------------------------------------------------------------
    # PAGE 1: Welcome & Dependency Checks
    # --------------------------------------------------------------------------
    def create_page_welcome(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        lbl_h = QLabel("Willkommen zur Installation")
        lbl_h.setStyleSheet("font-size: 20px; font-weight: 800; color: palette(text);")
        lbl_sub = QLabel(
            "Dieser Assistent installiert die Cachy Security Suite (grafische Sicherheits- und "
            "Audit-Zentrale für Arch Linux & CachyOS) auf deinem System."
        )
        lbl_sub.setStyleSheet("font-size: 12px; color: palette(text); opacity: 0.75;")
        lbl_sub.setWordWrap(True)

        layout.addWidget(lbl_h)
        layout.addWidget(lbl_sub)

        # System Requirements Card
        card = QFrame()
        card.setObjectName("checkCard")
        card.setStyleSheet("""
            QFrame#checkCard {
                background-color: palette(base);
                border: 1px solid palette(mid);
                border-radius: 10px;
                padding: 12px;
            }
            QFrame#checkCard QLabel {
                background: transparent;
                border: none;
            }
        """)
        c_layout = QVBoxLayout(card)
        c_layout.setSpacing(8)

        lbl_c_title = QLabel("Systemvoraussetzungen & Status:")
        lbl_c_title.setStyleSheet("font-weight: 700; font-size: 12px;")
        c_layout.addWidget(lbl_c_title)

        # Check Python
        py_ver = sys.version.split()[0]
        self.lbl_chk_py = QLabel(f"✓ Python 3 ({py_ver}) verfügbar")
        self.lbl_chk_py.setStyleSheet("color: #10b981; font-weight: 600; font-size: 11px;")
        c_layout.addWidget(self.lbl_chk_py)

        # Check PyQt6
        self.lbl_chk_qt = QLabel("✓ PyQt6 (GUI Toolkit) verfügbar")
        self.lbl_chk_qt.setStyleSheet("color: #10b981; font-weight: 600; font-size: 11px;")
        c_layout.addWidget(self.lbl_chk_qt)

        # Check aur-scan
        has_aur_scan = shutil.which("aur-scan") is not None
        if has_aur_scan:
            self.lbl_chk_cli = QLabel("✓ aur-scan (CLI Core) auf dem System gefunden")
            self.lbl_chk_cli.setStyleSheet("color: #10b981; font-weight: 600; font-size: 11px;")
        else:
            self.lbl_chk_cli = QLabel("⚠ aur-scan nicht im Pfad (kann später via 'yay -S aur-scanner' installiert werden)")
            self.lbl_chk_cli.setStyleSheet("color: #eab308; font-weight: 600; font-size: 11px;")
        c_layout.addWidget(self.lbl_chk_cli)

        layout.addWidget(card)
        layout.addStretch()
        return w

    # --------------------------------------------------------------------------
    # PAGE 2: Installation Options
    # --------------------------------------------------------------------------
    def create_page_options(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(14)

        lbl_h = QLabel("Installationsoptionen")
        lbl_h.setStyleSheet("font-size: 20px; font-weight: 800; color: palette(text);")
        lbl_sub = QLabel("Wähle den gewünschten Installationsort und Verknüpfungen:")
        lbl_sub.setStyleSheet("font-size: 12px; color: palette(text); opacity: 0.75;")

        layout.addWidget(lbl_h)
        layout.addWidget(lbl_sub)

        # Location Group Card
        card_loc = QFrame()
        card_loc.setObjectName("cardLoc")
        card_loc.setStyleSheet("""
            QFrame#cardLoc {
                background-color: palette(base);
                border: 1px solid palette(mid);
                border-radius: 10px;
                padding: 12px;
            }
            QFrame#cardLoc QLabel, QFrame#cardLoc QRadioButton {
                background: transparent;
                border: none;
            }
        """)
        loc_layout = QVBoxLayout(card_loc)
        loc_layout.setSpacing(10)

        lbl_loc_title = QLabel("Installationsumfang:")
        lbl_loc_title.setStyleSheet("font-weight: 700; font-size: 12px;")
        loc_layout.addWidget(lbl_loc_title)

        self.radio_user = QRadioButton("Nur für den aktuellen Benutzer installieren (~/.local/) [Empfohlen]")
        self.radio_user.setChecked(True)
        self.radio_user.setStyleSheet("font-size: 12px; font-weight: 500;")

        lbl_user_hint = QLabel("  Keine Root- oder Sudo-Rechte erforderlich. Liegt direkt in deinem Home-Verzeichnis.")
        lbl_user_hint.setStyleSheet("font-size: 11px; opacity: 0.65; margin-left: 20px;")

        self.radio_system = QRadioButton("Systemweit für alle Benutzer installieren (/usr/)")
        self.radio_system.setStyleSheet("font-size: 12px; font-weight: 500;")
        # If user is not root, disable system-wide or show hint
        if os.geteuid() != 0:
            self.radio_system.setEnabled(False)
            self.radio_system.setText("Systemweit für alle Benutzer (/usr/) [Erfordert Root / sudo ./setup]")

        loc_layout.addWidget(self.radio_user)
        loc_layout.addWidget(lbl_user_hint)
        loc_layout.addWidget(self.radio_system)
        layout.addWidget(card_loc)

        # Shortcuts Card
        card_sc = QFrame()
        card_sc.setObjectName("cardSc")
        card_sc.setStyleSheet("""
            QFrame#cardSc {
                background-color: palette(base);
                border: 1px solid palette(mid);
                border-radius: 10px;
                padding: 12px;
            }
            QFrame#cardSc QLabel, QFrame#cardSc QCheckBox {
                background: transparent;
                border: none;
            }
        """)
        sc_layout = QVBoxLayout(card_sc)
        sc_layout.setSpacing(8)

        lbl_sc_title = QLabel("Verknüpfungen:")
        lbl_sc_title.setStyleSheet("font-weight: 700; font-size: 12px;")
        sc_layout.addWidget(lbl_sc_title)

        self.chk_menu = QCheckBox("Eintrag im Anwendungsmenü (Kickoff, KRunner, Startmenü) anlegen")
        self.chk_menu.setChecked(True)
        self.chk_menu.setStyleSheet("font-size: 12px;")

        self.chk_desktop = QCheckBox("Zusätzliche Verknüpfung auf dem Schreibtisch anlegen")
        self.chk_desktop.setChecked(False)
        self.chk_desktop.setStyleSheet("font-size: 12px;")

        sc_layout.addWidget(self.chk_menu)
        sc_layout.addWidget(self.chk_desktop)
        layout.addWidget(card_sc)

        layout.addStretch()
        return w

    # --------------------------------------------------------------------------
    # PAGE 3: Installation Progress & Log
    # --------------------------------------------------------------------------
    def create_page_progress(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)

        lbl_h = QLabel("Installation wird durchgeführt")
        lbl_h.setStyleSheet("font-size: 20px; font-weight: 800; color: palette(text);")
        self.lbl_step_status = QLabel("Bereite Installation vor...")
        self.lbl_step_status.setStyleSheet("font-size: 12px; font-weight: 600; color: #2563eb;")

        layout.addWidget(lbl_h)
        layout.addWidget(self.lbl_step_status)

        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(14)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid palette(mid);
                border-radius: 7px;
                background: palette(base);
                text-align: center;
                font-size: 10px;
            }
            QProgressBar::chunk {
                background-color: #2563eb;
                border-radius: 6px;
            }
        """)
        layout.addWidget(self.progress_bar)

        # Log Card
        lbl_log = QLabel("Detail-Protokoll:")
        lbl_log.setStyleSheet("font-weight: 600; font-size: 11px; color: palette(text); opacity: 0.8;")
        layout.addWidget(lbl_log)

        self.txt_log = QTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setFont(QFont("JetBrains Mono, monospace", 9))
        self.txt_log.setStyleSheet("""
            QTextEdit {
                background-color: palette(base);
                color: palette(text);
                border: 1px solid palette(mid);
                border-radius: 8px;
                padding: 6px;
            }
        """)
        layout.addWidget(self.txt_log, stretch=1)
        return w

    # --------------------------------------------------------------------------
    # PAGE 4: Finished
    # --------------------------------------------------------------------------
    def create_page_finish(self) -> QWidget:
        w = QWidget()
        layout = QVBoxLayout(w)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(14)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        icon_fin = QLabel("✓")
        icon_fin.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_fin.setStyleSheet("""
            font-size: 48px;
            font-weight: 900;
            color: #10b981;
            background: rgba(16, 185, 129, 0.15);
            border-radius: 40px;
            min-width: 80px;
            max-width: 80px;
            min-height: 80px;
            max-height: 80px;
        """)

        lbl_h = QLabel("Installation erfolgreich!")
        lbl_h.setStyleSheet("font-size: 22px; font-weight: 800; color: palette(text);")
        lbl_h.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.lbl_fin_desc = QLabel(
            "Cachy Security Suite wurde erfolgreich auf deinem System eingerichtet.\n"
            "Du kannst die Anwendung jetzt über das Startmenü oder Terminal aufrufen."
        )
        self.lbl_fin_desc.setStyleSheet("font-size: 12px; color: palette(text); opacity: 0.75; line-height: 1.5;")
        self.lbl_fin_desc.setAlignment(Qt.AlignmentFlag.AlignCenter)

        self.chk_start_now = QCheckBox("Cachy Security Suite jetzt starten")
        self.chk_start_now.setChecked(True)
        self.chk_start_now.setStyleSheet("font-size: 13px; font-weight: 600; margin-top: 10px;")

        layout.addStretch()
        layout.addWidget(icon_fin, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(lbl_h)
        layout.addWidget(self.lbl_fin_desc)
        layout.addWidget(self.chk_start_now, alignment=Qt.AlignmentFlag.AlignCenter)
        layout.addStretch()
        return w

    # --------------------------------------------------------------------------
    # Navigation Handlers
    # --------------------------------------------------------------------------
    def update_step_indicator(self, cur_idx: int):
        for i, lbl in enumerate(self.step_labels):
            if i == cur_idx:
                lbl.setStyleSheet("font-size: 12px; color: #38bdf8; font-weight: 700;")
            elif i < cur_idx:
                lbl.setStyleSheet("font-size: 12px; color: #10b981; font-weight: 600;")
            else:
                lbl.setStyleSheet("font-size: 12px; color: #64748b; font-weight: 500;")

    def next_step(self):
        cur = self.pages.currentIndex()
        if cur == 0:
            # Go to options
            self.pages.setCurrentIndex(1)
            self.btn_back.setEnabled(True)
            self.btn_next.setText("Jetzt installieren  →")
            self.update_step_indicator(1)
        elif cur == 1:
            # Start installation
            self.pages.setCurrentIndex(2)
            self.btn_back.setEnabled(False)
            self.btn_next.setEnabled(False)
            self.btn_cancel.setEnabled(False)
            self.update_step_indicator(2)
            self.start_install()
        elif cur == 3:
            # Finished -> close or launch
            if self.chk_start_now.isChecked() and self.installed_launcher:
                subprocess.Popen([self.installed_launcher])
            self.accept()

    def prev_step(self):
        cur = self.pages.currentIndex()
        if cur == 1:
            self.pages.setCurrentIndex(0)
            self.btn_back.setEnabled(False)
            self.btn_next.setText("Weiter  →")
            self.update_step_indicator(0)

    def start_install(self):
        is_user = self.radio_user.isChecked()
        create_sc = self.chk_desktop.isChecked()
        create_menu = self.chk_menu.isChecked()

        self.worker = InstallWorker(is_user, create_sc, create_menu)
        self.worker.step_changed.connect(self.on_step_changed)
        self.worker.log_line.connect(self.on_log_line)
        self.worker.finished.connect(self.on_install_finished)
        self.worker.start()

    def on_step_changed(self, msg: str, percent: int):
        self.lbl_step_status.setText(msg)
        self.progress_bar.setValue(percent)

    def on_log_line(self, line: str):
        self.txt_log.append(line)

    def on_install_finished(self, success: bool, result_path_or_err: str):
        if success:
            self.installed_launcher = result_path_or_err
            self.pages.setCurrentIndex(3)
            self.btn_next.setEnabled(True)
            self.btn_next.setText("Fertigstellen")
            self.btn_cancel.setVisible(False)
            self.update_step_indicator(3)
        else:
            self.lbl_step_status.setText("Fehler bei der Installation!")
            self.lbl_step_status.setStyleSheet("color: #ef4444; font-weight: bold;")
            self.btn_cancel.setEnabled(True)
            self.btn_cancel.setText("Schließen")


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("cachy-security-installer")
    app.setApplicationDisplayName("Cachy Security Suite Installer")

    installer = GraphicalInstaller()
    installer.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
