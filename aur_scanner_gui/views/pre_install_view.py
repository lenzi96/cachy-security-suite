"""
View for checking AUR packages before installation with modern card styling.
"""
import re
from typing import Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QIcon, QTextCharFormat, QTextCursor
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from aur_scanner_gui.dialogs.download_dialog import AurDownloadDialog
from aur_scanner_gui.scanner_service import ProcessStreamWorker


class PreInstallView(QWidget):
    request_local_scan = pyqtSignal(str)
    request_antivirus_scan = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.worker: Optional[ProcessStreamWorker] = None
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        # 1. Header
        header_layout = QVBoxLayout()
        header_layout.setSpacing(3)
        lbl_title = QLabel("AUR-Pakete vor der Installation prüfen")
        lbl_title.setStyleSheet("font-size: 18px; font-weight: 700; color: palette(text);")
        lbl_desc = QLabel("Lädt das Paket live aus dem AUR herunter und analysiert den gesamten Abhängigkeitsbaum vor dem Build.")
        lbl_desc.setStyleSheet("font-size: 12px; color: palette(text); opacity: 0.7;")
        header_layout.addWidget(lbl_title)
        header_layout.addWidget(lbl_desc)
        layout.addLayout(header_layout)

        # 2. Input & Controls Card
        card_input = QFrame()
        card_input.setObjectName("cardInput")
        card_input.setStyleSheet("""
            QFrame#cardInput {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #172033, stop:1 #0e1626);
                border: 1px solid #293548;
                border-radius: 10px;
                padding: 6px;
            }
        """)
        input_layout = QVBoxLayout(card_input)
        input_layout.setContentsMargins(14, 10, 14, 10)
        input_layout.setSpacing(10)

        row1 = QHBoxLayout()
        row1.setSpacing(10)
        self.pkg_input = QLineEdit()
        self.pkg_input.setPlaceholderText("AUR-Paketname(n) eingeben (z. B. yay, visual-studio-code-bin, discord)...")
        self.pkg_input.setStyleSheet("""
            QLineEdit {
                border: 1px solid #334155;
                border-radius: 7px;
                padding: 8px 12px;
                font-size: 12px;
                color: #f8fafc;
                background-color: #090d16;
            }
            QLineEdit:focus { border: 1px solid #3b82f6; }
        """)
        self.pkg_input.returnPressed.connect(self.start_check)

        self.btn_check = QPushButton("  Prüfung starten")
        self.btn_check.setIcon(QIcon.fromTheme("security-high"))
        self.btn_check.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_check.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2563eb, stop:1 #3b82f6);
                color: white;
                font-weight: 700;
                font-size: 12px;
                padding: 8px 18px;
                border-radius: 7px;
                border: none;
            }
            QPushButton:hover { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1d4ed8, stop:1 #2563eb); }
            QPushButton:disabled { background: #334155; color: #64748b; }
        """)
        self.btn_check.clicked.connect(self.start_check)

        self.btn_download = QPushButton("  Herunterladen...")
        self.btn_download.setIcon(QIcon.fromTheme("download"))
        self.btn_download.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_download.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #059669, stop:1 #10b981);
                color: white;
                font-weight: 700;
                font-size: 12px;
                padding: 8px 16px;
                border-radius: 7px;
                border: none;
            }
            QPushButton:hover { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #047857, stop:1 #059669); }
        """)
        self.btn_download.clicked.connect(lambda: self.open_download_dialog())

        self.btn_stop = QPushButton("Abbrechen")
        self.btn_stop.setIcon(QIcon.fromTheme("process-stop"))
        self.btn_stop.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_stop.setEnabled(False)
        self.btn_stop.setStyleSheet("""
            QPushButton {
                padding: 8px 16px;
                border-radius: 7px;
                border: 1px solid #334155;
                background: rgba(255, 255, 255, 0.05);
                color: #94a3b8;
                font-size: 12px;
                font-weight: 600;
            }
            QPushButton:hover:enabled { background: #ef4444; color: white; border-color: #dc2626; }
            QPushButton:disabled { opacity: 0.4; }
        """)
        self.btn_stop.clicked.connect(self.stop_check)

        row1.addWidget(self.pkg_input, stretch=3)
        row1.addWidget(self.btn_check)
        row1.addWidget(self.btn_download)
        row1.addWidget(self.btn_stop)
        input_layout.addLayout(row1)

        # Options row
        row2 = QHBoxLayout()
        self.chk_scan_deps = QCheckBox("Abhängigkeitsbaum analysieren")
        self.chk_scan_deps.setChecked(True)
        self.chk_scan_deps.setStyleSheet("font-size: 12px;")

        self.chk_optional_deps = QCheckBox("Optionale Abhängigkeiten einbeziehen")
        self.chk_optional_deps.setChecked(False)
        self.chk_optional_deps.setStyleSheet("font-size: 12px;")

        self.severity_combo = QComboBox()
        self.severity_combo.addItem("Min. Schweregrad: Alle", None)
        self.severity_combo.addItem("Critical", "critical")
        self.severity_combo.addItem("High", "high")
        self.severity_combo.addItem("Medium", "medium")
        self.severity_combo.addItem("Low", "low")
        self.severity_combo.setStyleSheet("""
            QComboBox {
                border: 1px solid palette(mid);
                border-radius: 6px;
                padding: 5px 10px;
                font-size: 12px;
                background: palette(window);
            }
        """)

        row2.addWidget(self.chk_scan_deps)
        row2.addWidget(self.chk_optional_deps)
        row2.addStretch()
        row2.addWidget(self.severity_combo)
        input_layout.addLayout(row2)

        layout.addWidget(card_input)

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

        # Status banner container
        self.banner_frame = QFrame()
        self.banner_frame.setObjectName("bannerFrame")
        self.banner_frame.setStyleSheet("""
            QFrame#bannerFrame {
                border-radius: 10px;
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #172033, stop:1 #0e1626);
                border: 1px solid #293548;
            }
        """)
        b_layout = QHBoxLayout(self.banner_frame)
        b_layout.setContentsMargins(14, 10, 14, 10)
        b_layout.setSpacing(10)

        self.status_banner = QLabel("Gib einen AUR-Paketnamen ein, um die Vorab-Prüfung zu starten.")
        self.status_banner.setStyleSheet("font-weight: 600; font-size: 12px; background: transparent; border: none; color: #f1f5f9;")
        b_layout.addWidget(self.status_banner, stretch=1)

        self.btn_quick_download = QPushButton("📥 Paket herunterladen...")
        self.btn_quick_download.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_quick_download.setVisible(False)
        self.btn_quick_download.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #059669, stop:1 #10b981);
                color: white;
                font-weight: 700;
                font-size: 11px;
                padding: 6px 14px;
                border-radius: 6px;
                border: none;
            }
            QPushButton:hover { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #047857, stop:1 #059669); }
        """)
        self.btn_quick_download.clicked.connect(self.on_quick_download_clicked)
        b_layout.addWidget(self.btn_quick_download)

        layout.addWidget(self.banner_frame)

        # Output Card
        output_card = QFrame()
        output_card.setObjectName("outputCard")
        output_card.setStyleSheet("""
            QFrame#outputCard {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #172033, stop:1 #0e1626);
                border: 1px solid #293548;
                border-radius: 10px;
            }
        """)
        out_layout = QVBoxLayout(output_card)
        out_layout.setContentsMargins(12, 12, 12, 12)
        out_layout.setSpacing(6)

        lbl_log = QLabel("Scan-Ausgabe & Abhängigkeitsbaum:")
        lbl_log.setStyleSheet("font-weight: 700; font-size: 12px; color: #f1f5f9;")
        out_layout.addWidget(lbl_log)

        self.txt_log = QTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setFont(QFont("JetBrains Mono, monospace", 10))
        self.txt_log.setStyleSheet("""
            QTextEdit {
                background-color: #090d16;
                color: #cbd5e1;
                border: 1px solid #1e293b;
                border-radius: 7px;
                padding: 8px;
            }
        """)
        out_layout.addWidget(self.txt_log)
        layout.addWidget(output_card, stretch=1)

    def set_banner_status(self, text: str, bg_color: str, border_color: str, text_color: str = "#ffffff"):
        self.status_banner.setText(text)
        self.banner_frame.setStyleSheet(f"""
            QFrame#bannerFrame {{
                border-radius: 8px;
                background-color: {bg_color};
                border: 1px solid {border_color};
            }}
            QLabel {{
                color: {text_color};
                background: transparent;
                border: none;
            }}
        """)

    def start_check(self):
        pkg_name = self.pkg_input.text().strip()
        if not pkg_name:
            QMessageBox.warning(self, "Hinweis", "Bitte gib mindestens einen AUR-Paketnamen ein.")
            return

        cmd = ["aur-scan", "check", "--no-confirm", "--no-color"]

        if not self.chk_scan_deps.isChecked():
            cmd.append("--no-deps")

        if self.chk_optional_deps.isChecked():
            cmd.append("--include-optional")

        sev = self.severity_combo.currentData()
        if sev:
            cmd.extend(["-s", sev])

        packages = [p.strip() for p in re.split(r"[,\s]+", pkg_name) if p.strip()]
        cmd.extend(packages)

        self.btn_check.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.btn_quick_download.setVisible(False)
        self.txt_log.clear()

        self.set_banner_status(f"Lade und überprüfe AUR-Paket: {', '.join(packages)}...", "#1e3a8a", "#3b82f6")

        self.worker = ProcessStreamWorker(cmd)
        self.worker.output_line.connect(self.on_output_line)
        self.worker.completed.connect(self.on_check_completed)
        self.worker.error.connect(self.on_check_error)
        self.worker.start()

    def stop_check(self):
        if self.worker:
            self.worker.cancel()
            self.btn_check.setEnabled(True)
            self.btn_stop.setEnabled(False)
            self.progress_bar.setVisible(False)
            self.set_banner_status("Prüfung abgebrochen.", "palette(base)", "palette(mid)", "palette(text)")

    def on_output_line(self, line: str):
        cursor = self.txt_log.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)

        fmt = QTextCharFormat()
        line_lower = line.lower()
        if "critical" in line_lower or "high" in line_lower:
            fmt.setForeground(QColor("#ef4444"))
            fmt.setFontWeight(QFont.Weight.Bold)
        elif "ok" in line_lower or "no critical/high" in line_lower:
            fmt.setForeground(QColor("#10b981"))
            fmt.setFontWeight(QFont.Weight.Bold)
        elif line.startswith("[AUR]") or line.startswith("[repo]"):
            fmt.setForeground(QColor("#3b82f6"))
        elif line.startswith("==="):
            fmt.setForeground(QColor("#64748b"))
        else:
            fmt.setForeground(QColor(self.palette().text().color()))

        cursor.insertText(line + "\n", fmt)
        self.txt_log.setTextCursor(cursor)
        self.txt_log.ensureCursorVisible()

    def on_check_completed(self, returncode: int, full_output: str):
        self.btn_check.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.progress_bar.setVisible(False)

        lower_out = full_output.lower()
        if "no critical/high findings" in lower_out or returncode == 0 and "critical" not in lower_out and "high" not in lower_out:
            self.set_banner_status("✓ Keine kritischen oder hohen Sicherheitsbefunde im Abhängigkeitsbaum gefunden!", "#065f46", "#10b981")
        else:
            self.set_banner_status("⚠ Achtung: Sicherheitswarnungen oder Findings festgestellt! Bitte Ausgabe prüfen.", "#991b1b", "#ef4444")

        # Offer quick download for primary package
        raw = self.pkg_input.text().strip()
        parts = [p.strip() for p in re.split(r"[,\s]+", raw) if p.strip()]
        if parts:
            primary_pkg = parts[0]
            self.btn_quick_download.setText(f"📥 '{primary_pkg}' herunterladen...")
            self.btn_quick_download.setVisible(True)

    def on_check_error(self, err_msg: str):
        self.btn_check.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.progress_bar.setVisible(False)
        self.set_banner_status("Fehler bei der Ausführung.", "#991b1b", "#ef4444")
        QMessageBox.critical(self, "Fehler", err_msg)

    def open_download_dialog(self, pkg_name: str = ""):
        if not pkg_name:
            raw = self.pkg_input.text().strip()
            parts = [p.strip() for p in re.split(r"[,\s]+", raw) if p.strip()]
            if parts:
                pkg_name = parts[0]

        dlg = AurDownloadDialog(pkg_name, self)
        dlg.request_local_scan.connect(self.request_local_scan.emit)
        dlg.request_antivirus_scan.connect(self.request_antivirus_scan.emit)
        dlg.exec()

    def on_quick_download_clicked(self):
        raw = self.pkg_input.text().strip()
        parts = [p.strip() for p in re.split(r"[,\s]+", raw) if p.strip()]
        pkg_name = parts[0] if parts else ""
        self.open_download_dialog(pkg_name)
