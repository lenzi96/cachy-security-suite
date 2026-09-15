"""
Main Window for AUR Security Scanner GUI with modern dark-slate sidebar and clean layout.
"""
import os
from PyQt6.QtCore import Qt, QSize, QTimer, QSettings
from PyQt6.QtGui import QAction, QFont, QIcon, QPixmap
from PyQt6.QtWidgets import (
    QButtonGroup,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QStackedWidget,
    QStatusBar,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from aur_scanner_gui.scanner_service import AurScannerService
from aur_scanner_gui.views.antivirus_view import AntivirusView
from aur_scanner_gui.views.ioc_view import IOCView
from aur_scanner_gui.views.local_scan_view import LocalScanView
from aur_scanner_gui.views.pre_install_view import PreInstallView
from aur_scanner_gui.views.rules_view import RulesView
from aur_scanner_gui.views.system_scan_view import SystemScanView


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Cachy Security Suite")
        self.resize(1200, 780)
        self.setMinimumSize(1020, 660)

        # Set window icon
        icon_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "resources",
            "aur-scanner-256.png",
        )
        if not os.path.exists(icon_path):
            icon_path = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                "resources",
                "aur-scanner.svg",
            )
        if os.path.exists(icon_path):
            self.setWindowIcon(QIcon(icon_path))
        else:
            self.setWindowIcon(QIcon.fromTheme("security-high"))

        self.init_ui()
        self.create_menu()
        self._bg_updater = None
        QTimer.singleShot(1500, self.start_background_update_check)

    def init_ui(self):
        central_widget = QWidget()
        central_widget.setStyleSheet("background-color: palette(window);")
        self.setCentralWidget(central_widget)

        root_layout = QHBoxLayout(central_widget)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # ----------------------------------------------------------------------
        # SLEEK DARK-SLATE SIDEBAR
        # ----------------------------------------------------------------------
        self.sidebar = QFrame()
        self.sidebar.setObjectName("sidebar")
        self.sidebar.setFixedWidth(240)
        self.sidebar.setStyleSheet("""
            QFrame#sidebar {
                background-color: #0f172a;
                border-right: 1px solid #1e293b;
            }
            QFrame#sidebar QLabel {
                background: transparent;
                border: none;
            }
        """)

        sidebar_layout = QVBoxLayout(self.sidebar)
        sidebar_layout.setContentsMargins(16, 22, 16, 18)
        sidebar_layout.setSpacing(6)

        # App Brand / Logo Header
        brand_layout = QHBoxLayout()
        brand_layout.setSpacing(12)

        logo_lbl = QLabel()
        icon_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "resources",
            "aur-scanner-64.png",
        )
        if os.path.exists(icon_path):
            pix = QPixmap(icon_path).scaled(36, 36, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation)
            logo_lbl.setPixmap(pix)
        else:
            logo_lbl.setPixmap(QIcon.fromTheme("security-high").pixmap(36, 36))
        logo_lbl.setStyleSheet("""
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 rgba(56, 189, 248, 0.18), stop:1 rgba(37, 99, 235, 0.08));
            border: 1px solid rgba(56, 189, 248, 0.35);
            border-radius: 10px;
            padding: 3px;
        """)

        brand_text_layout = QVBoxLayout()
        brand_text_layout.setSpacing(2)

        title_lbl = QLabel("Cachy Security")
        title_lbl.setStyleSheet("font-size: 16px; font-weight: 800; color: #f8fafc; letter-spacing: 0.3px;")
        sub_lbl = QLabel("SUITE v1.1.5")
        sub_lbl.setStyleSheet("""
            font-size: 9px;
            color: #38bdf8;
            font-weight: 800;
            letter-spacing: 1px;
            background: rgba(56, 189, 248, 0.12);
            border: 1px solid rgba(56, 189, 248, 0.25);
            border-radius: 4px;
            padding: 1px 6px;
        """)

        brand_text_layout.addWidget(title_lbl)
        brand_text_layout.addWidget(sub_lbl)

        brand_layout.addWidget(logo_lbl)
        brand_layout.addLayout(brand_text_layout)
        sidebar_layout.addLayout(brand_layout)

        # Divider
        div = QFrame()
        div.setFrameShape(QFrame.Shape.HLine)
        div.setStyleSheet("background-color: #1e293b; max-height: 1px; margin: 12px 0px 14px 0px; border: none;")
        sidebar_layout.addWidget(div)

        # Section label
        nav_header = QLabel("NAVIGATION")
        nav_header.setStyleSheet("font-size: 10px; font-weight: 700; color: #64748b; letter-spacing: 1.2px; margin-bottom: 4px;")
        sidebar_layout.addWidget(nav_header)

        # Navigation Buttons Group
        self.nav_group = QButtonGroup(self)
        self.nav_group.setExclusive(True)

        self.nav_buttons = []
        nav_items = [
            ("System-Audit", "applications-system", 0),
            ("PKGBUILD Scan", "system-search", 1),
            ("Vorab-Prüfung", "security-high", 2),
            ("Virenscanner", "security-medium", 3),
            ("Regel-Katalog", "dialog-information", 4),
            ("IOC-Datenbank", "security-low", 5),
        ]

        for text, icon_name, idx in nav_items:
            icon = QIcon.fromTheme(icon_name)
            btn = QPushButton(f"  {text}")
            if not icon.isNull():
                btn.setIcon(icon)
                btn.setIconSize(QSize(18, 18))
            btn.setCheckable(True)
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setStyleSheet("""
                QPushButton {
                    text-align: left;
                    padding: 10px 14px;
                    border-radius: 8px;
                    font-size: 13px;
                    font-weight: 500;
                    border: 1px solid transparent;
                    background: transparent;
                    color: #94a3b8;
                }
                QPushButton:hover {
                    background-color: rgba(255, 255, 255, 0.05);
                    color: #f8fafc;
                    border-color: rgba(255, 255, 255, 0.08);
                }
                QPushButton:checked {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1d4ed8, stop:1 #2563eb);
                    color: #ffffff;
                    font-weight: 600;
                    border-left: 3px solid #38bdf8;
                    border-radius: 8px;
                }
            """)
            btn.clicked.connect(lambda checked, i=idx: self.switch_view(i))
            self.nav_group.addButton(btn, idx)
            sidebar_layout.addWidget(btn)
            self.nav_buttons.append(btn)

        sidebar_layout.addStretch()

        # Sidebar Footer Card
        footer_card = QFrame()
        footer_card.setObjectName("footerCard")
        footer_card.setStyleSheet("""
            QFrame#footerCard {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #172033, stop:1 #0f172a);
                border: 1px solid #293548;
                border-radius: 10px;
            }
            QFrame#footerCard QLabel {
                border: none !important;
                background: transparent !important;
            }
        """)
        footer_layout = QVBoxLayout(footer_card)
        footer_layout.setContentsMargins(12, 10, 12, 10)
        footer_layout.setSpacing(4)

        lbl_core = QLabel("● aur-scan 2.0.0")
        lbl_core.setStyleSheet("font-size: 11px; font-weight: 700; color: #10b981;")
        lbl_rule_count = QLabel("118 Erkennungsregeln aktiv")
        lbl_rule_count.setStyleSheet("font-size: 10px; color: #94a3b8;")

        self.btn_check_updates = QPushButton("Auf Updates prüfen...")
        self.btn_check_updates.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_check_updates.setStyleSheet("""
            QPushButton {
                background: rgba(255, 255, 255, 0.06);
                color: #e2e8f0;
                font-size: 10px;
                font-weight: 600;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 6px 8px;
                margin-top: 4px;
            }
            QPushButton:hover {
                background: #2563eb;
                color: #ffffff;
                border-color: #3b82f6;
            }
        """)
        self.btn_check_updates.clicked.connect(self.show_update_dialog)

        footer_layout.addWidget(lbl_core)
        footer_layout.addWidget(lbl_rule_count)
        footer_layout.addWidget(self.btn_check_updates)
        sidebar_layout.addWidget(footer_card)

        root_layout.addWidget(self.sidebar)

        # ----------------------------------------------------------------------
        # RIGHT STACKED VIEWS
        # ----------------------------------------------------------------------
        self.stack = QStackedWidget()
        self.stack.setStyleSheet("background-color: palette(window);")

        self.system_scan_view = SystemScanView()
        self.local_scan_view = LocalScanView()
        self.local_scan_view.request_rule_explain.connect(self.switch_to_rule)
        self.pre_install_view = PreInstallView()
        self.pre_install_view.request_local_scan.connect(self.open_in_local_scan)
        self.pre_install_view.request_antivirus_scan.connect(self.open_in_antivirus)
        self.antivirus_view = AntivirusView()
        self.rules_view = RulesView()
        self.ioc_view = IOCView()

        self.stack.addWidget(self.system_scan_view)    # 0 (Default auf Start)
        self.stack.addWidget(self.local_scan_view)     # 1
        self.stack.addWidget(self.pre_install_view)    # 2
        self.stack.addWidget(self.antivirus_view)      # 3
        self.stack.addWidget(self.rules_view)          # 4
        self.stack.addWidget(self.ioc_view)            # 5

        root_layout.addWidget(self.stack)

        # Initial active tab: System-Audit (Index 0)
        self.switch_view(0)

        # Statusbar
        self.status_bar = QStatusBar()
        self.status_bar.setStyleSheet("""
            QStatusBar {
                border-top: 1px solid palette(mid);
                background-color: palette(window);
                font-size: 11px;
                padding: 2px 10px;
                color: palette(text);
            }
        """)
        self.setStatusBar(self.status_bar)
        self.status_bar.showMessage("Bereit | Cachy Security Suite - Schutz & Integritätsüberwachung")

    def switch_view(self, index: int):
        self.stack.setCurrentIndex(index)
        if index < len(self.nav_buttons):
            self.nav_buttons[index].setChecked(True)

    def trigger_system_audit(self):
        self.switch_view(0)
        self.system_scan_view.start_system_scan()

    def switch_to_rule(self, code: str):
        self.switch_view(4)
        self.rules_view.select_rule_by_code(code)

    def open_in_local_scan(self, path: str):
        self.switch_view(1)
        self.local_scan_view.set_target(path)
        self.local_scan_view.start_scan()

    def open_in_antivirus(self, path: str):
        self.switch_view(3)
        self.antivirus_view.path_input.setText(path)
        self.antivirus_view.start_scan()

    def create_menu(self):
        menubar = self.menuBar()
        menubar.setStyleSheet("""
            QMenuBar {
                background-color: palette(window);
                border-bottom: 1px solid palette(mid);
                padding: 2px 6px;
                font-size: 12px;
            }
            QMenuBar::item {
                padding: 4px 10px;
                border-radius: 4px;
            }
            QMenuBar::item:selected {
                background-color: palette(button);
            }
        """)

        # File Menu
        file_menu = menubar.addMenu("&Datei")

        act_open_file = QAction(QIcon.fromTheme("document-open"), "PKGBUILD &öffnen...", self)
        act_open_file.setShortcut("Ctrl+O")
        act_open_file.triggered.connect(self.local_scan_view.browse_file)
        file_menu.addAction(act_open_file)

        act_open_dir = QAction(QIcon.fromTheme("folder-open"), "&Ordner öffnen...", self)
        act_open_dir.setShortcut("Ctrl+Shift+O")
        act_open_dir.triggered.connect(self.local_scan_view.browse_directory)
        file_menu.addAction(act_open_dir)

        file_menu.addSeparator()

        act_download = QAction(QIcon.fromTheme("download"), "AUR-Paket &herunterladen...", self)
        act_download.setShortcut("Ctrl+D")
        act_download.triggered.connect(lambda: self.pre_install_view.open_download_dialog())
        file_menu.addAction(act_download)

        file_menu.addSeparator()

        act_exit = QAction(QIcon.fromTheme("application-exit"), "&Beenden", self)
        act_exit.setShortcut("Ctrl+Q")
        act_exit.triggered.connect(self.close)
        file_menu.addAction(act_exit)

        # Tools Menu
        tools_menu = menubar.addMenu("&Werkzeuge")

        act_sys_scan = QAction(QIcon.fromTheme("security-high"), "System-&Audit starten", self)
        act_sys_scan.setShortcut("F5")
        act_sys_scan.triggered.connect(self.trigger_system_audit)
        tools_menu.addAction(act_sys_scan)

        act_dl_tool = QAction(QIcon.fromTheme("download"), "AUR-Paket &herunterladen...", self)
        act_dl_tool.triggered.connect(lambda: self.pre_install_view.open_download_dialog())
        tools_menu.addAction(act_dl_tool)

        act_update = QAction(QIcon.fromTheme("view-refresh"), "Nach &Updates suchen...", self)
        act_update.triggered.connect(self.show_update_dialog)
        tools_menu.addAction(act_update)

        # Help Menu
        help_menu = menubar.addMenu("&Hilfe")

        act_update_help = QAction(QIcon.fromTheme("view-refresh"), "Nach &Updates suchen...", self)
        act_update_help.triggered.connect(self.show_update_dialog)
        help_menu.addAction(act_update_help)

        help_menu.addSeparator()

        act_version = QAction(QIcon.fromTheme("dialog-information"), "&Scanner-Version & Details", self)
        act_version.triggered.connect(self.show_version_dialog)
        help_menu.addAction(act_version)

        act_about = QAction(QIcon.fromTheme("help-about"), "&Über Cachy Security Suite", self)
        act_about.triggered.connect(self.show_about_dialog)
        help_menu.addAction(act_about)

    def start_background_update_check(self, force: bool = False):
        """Silently checks for updates in the background without popups."""
        import time
        settings = QSettings("CachySecurity", "CachySecuritySuite")
        last_check = settings.value("updater/last_background_check", 0, type=int)
        now = int(time.time())
        # Check at most once every 24 hours in background, unless forced
        if not force and (now - last_check < 86400):
            return

        from aur_scanner_gui.updater import UpdateCheckerWorker
        self._bg_updater = UpdateCheckerWorker()
        self._bg_updater.finished.connect(self._on_bg_update_finished)
        self._bg_updater.start()

    def _on_bg_update_finished(self, info):
        import time
        settings = QSettings("CachySecurity", "CachySecuritySuite")
        settings.setValue("updater/last_background_check", int(time.time()))

        pending = info.total_updates_pending()
        if pending > 0:
            self.btn_check_updates.setText(f"● Updates verfügbar ({pending})")
            self.btn_check_updates.setStyleSheet("""
                QPushButton {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #ea580c, stop:1 #c2410c);
                    color: #ffffff;
                    font-size: 10px;
                    font-weight: 700;
                    border: 1px solid #f97316;
                    border-radius: 5px;
                    padding: 5px 8px;
                    margin-top: 4px;
                }
                QPushButton:hover {
                    background: #ea580c;
                    border-color: #fdba74;
                }
            """)
            tips = []
            if info.cli_has_update:
                tips.append(f"aur-scanner Engine (v{info.cli_remote})")
            if info.gui_has_update:
                tips.append(f"Cachy Security Suite (v{info.gui_remote})")
            if info.clamav_needs_update:
                tips.append("ClamAV Virensignaturen veraltet")
            self.btn_check_updates.setToolTip("Sicherheits- & Software-Updates verfügbar:\n• " + "\n• ".join(tips))

    def show_update_dialog(self):
        from aur_scanner_gui.updater import UpdateDialog
        dlg = UpdateDialog(self)
        dlg.exec()

        # Reset button styling after dialog is closed
        self.btn_check_updates.setText("Auf Updates prüfen...")
        self.btn_check_updates.setStyleSheet("""
            QPushButton {
                background: rgba(255, 255, 255, 0.08);
                color: #e2e8f0;
                font-size: 10px;
                font-weight: 500;
                border: 1px solid #334155;
                border-radius: 5px;
                padding: 5px 8px;
                margin-top: 4px;
            }
            QPushButton:hover {
                background: #2563eb;
                color: #ffffff;
                border-color: #3b82f6;
            }
        """)
        self.btn_check_updates.setToolTip("Sicherheits- & Update-Center öffnen")

    def show_version_dialog(self):
        dlg = QDialog(self)
        dlg.setWindowTitle("Version & Engine Info")
        dlg.resize(480, 260)
        layout = QVBoxLayout(dlg)

        txt = QTextEdit()
        txt.setReadOnly(True)
        txt.setFont(QFont("JetBrains Mono, monospace", 10))
        txt.setPlainText(AurScannerService.get_version_info())
        layout.addWidget(txt)

        btn_box = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok)
        btn_box.accepted.connect(dlg.accept)
        layout.addWidget(btn_box)

        dlg.exec()

    def show_about_dialog(self):
        QMessageBox.about(
            self,
            "Über Cachy Security Suite",
            """<h3>Cachy Security Suite</h3>
            <p>Umfassende grafische Sicherheits-Zentrale für <b>CachyOS & Arch Linux</b>.</p>
            <p>Integriert <b>aur-scanner</b> Sicherheitsanalysen, Vorab-Prüfungen vor der Installation,
            systemweites AUR-Audit, ClamAV-Virenscanner und Datei-Integritätsprüfungen (VirusTotal).</p>
            <hr>
            <p>Entwickelt für CachyOS, Arch Linux & KDE Plasma.</p>
            """,
        )
