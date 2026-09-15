"""
View for auditing all installed AUR packages on the system with clean modern UI.
"""
import re
from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont, QIcon, QTextCharFormat, QTextCursor
from PyQt6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from aur_scanner_gui.scanner_service import ProcessStreamWorker
from aur_scanner_gui.widgets.status_card import StatusCard


class SystemScanView(QWidget):
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
        lbl_title = QLabel("Systemweites AUR-Sicherheitsaudit")
        lbl_title.setStyleSheet("font-size: 18px; font-weight: 700; color: palette(text);")
        lbl_desc = QLabel("Überprüft alle auf diesem System installierten AUR-Pakete gegen die IOC-Bedrohungsdatenbank und analysiert ihre PKGBUILDs.")
        lbl_desc.setStyleSheet("font-size: 12px; color: palette(text); opacity: 0.7;")
        header_layout.addWidget(lbl_title)
        header_layout.addWidget(lbl_desc)
        layout.addLayout(header_layout)

        # 2. Control Card
        card_ctrl = QFrame()
        card_ctrl.setObjectName("cardCtrl")
        card_ctrl.setStyleSheet("""
            QFrame#cardCtrl {
                background-color: palette(base);
                border: 1px solid palette(mid);
                border-radius: 10px;
                padding: 6px;
            }
        """)
        c_layout = QHBoxLayout(card_ctrl)
        c_layout.setContentsMargins(12, 10, 12, 10)
        c_layout.setSpacing(10)

        self.btn_start = QPushButton("  System-Audit starten")
        self.btn_start.setIcon(QIcon.fromTheme("security-high"))
        self.btn_start.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_start.setStyleSheet("""
            QPushButton {
                background-color: #10b981;
                color: white;
                font-weight: 600;
                font-size: 12px;
                padding: 7px 18px;
                border-radius: 6px;
                border: none;
            }
            QPushButton:hover {
                background-color: #059669;
            }
        """)
        self.btn_start.clicked.connect(self.start_system_scan)

        self.btn_stop = QPushButton("Abbrechen")
        self.btn_stop.setIcon(QIcon.fromTheme("process-stop"))
        self.btn_stop.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_stop.setEnabled(False)
        self.btn_stop.setStyleSheet("""
            QPushButton {
                padding: 7px 14px;
                border-radius: 6px;
                border: 1px solid palette(mid);
                background: palette(window);
                font-size: 12px;
            }
            QPushButton:hover:enabled {
                background: #ef4444;
                color: white;
                border-color: #dc2626;
            }
        """)
        self.btn_stop.clicked.connect(self.stop_system_scan)

        self.chk_rescan = QCheckBox("PKGBUILDs aus dem AUR neu herunterladen (--rescan)")
        self.chk_rescan.setStyleSheet("font-size: 12px;")

        self.severity_combo = QComboBox()
        self.severity_combo.addItem("Min. Schweregrad: Alle", None)
        self.severity_combo.addItem("Critical", "critical")
        self.severity_combo.addItem("High", "high")
        self.severity_combo.addItem("Medium", "medium")
        self.severity_combo.setStyleSheet("""
            QComboBox {
                border: 1px solid palette(mid);
                border-radius: 6px;
                padding: 5px 10px;
                font-size: 12px;
                background: palette(window);
            }
        """)

        c_layout.addWidget(self.btn_start)
        c_layout.addWidget(self.btn_stop)
        c_layout.addWidget(self.chk_rescan)
        c_layout.addStretch()
        c_layout.addWidget(self.severity_combo)
        layout.addWidget(card_ctrl)

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
                background-color: #10b981;
                border-radius: 2px;
            }
        """)
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # 3. Status Cards
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(10)
        self.card_status = StatusCard("Systemstatus", 0, "#10b981")
        self.card_status.set_text("Bereit", "#10b981")

        self.card_total_pkgs = StatusCard("Installierte AUR-Pakete", 0, "#3b82f6")
        self.card_issues = StatusCard("Sicherheitsbefunde", 0, "#ef4444")

        cards_layout.addWidget(self.card_status)
        cards_layout.addWidget(self.card_total_pkgs)
        cards_layout.addWidget(self.card_issues)
        layout.addLayout(cards_layout)

        # 4. Splitter: Results Table + Details Log
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setHandleWidth(8)

        # Table Card
        table_card = QFrame()
        table_card.setObjectName("tableCard")
        table_card.setStyleSheet("""
            QFrame#tableCard {
                background-color: palette(base);
                border: 1px solid palette(mid);
                border-radius: 10px;
            }
        """)
        t_layout = QVBoxLayout(table_card)
        t_layout.setContentsMargins(8, 8, 8, 8)
        lbl_tbl = QLabel("Geprüfte Pakete:")
        lbl_tbl.setStyleSheet("font-weight: 600; font-size: 12px;")
        t_layout.addWidget(lbl_tbl)

        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Status", "Paketname", "Prüfergebnis"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.table.setShowGrid(False)
        self.table.setAlternatingRowColors(True)
        self.table.setStyleSheet("""
            QTableWidget {
                border: none;
                background-color: transparent;
                font-size: 12px;
            }
            QTableWidget::item {
                padding: 6px 8px;
                border-bottom: 1px solid palette(mid);
            }
            QHeaderView::section {
                background-color: palette(window);
                color: palette(text);
                padding: 6px 8px;
                font-weight: 600;
                font-size: 11px;
                border: none;
                border-bottom: 2px solid palette(mid);
            }
        """)
        self.table.verticalHeader().setDefaultSectionSize(36)
        self.table.verticalHeader().setVisible(False)
        t_layout.addWidget(self.table)
        splitter.addWidget(table_card)

        # Log Card
        log_card = QFrame()
        log_card.setObjectName("logCard")
        log_card.setStyleSheet("""
            QFrame#logCard {
                background-color: palette(base);
                border: 1px solid palette(mid);
                border-radius: 10px;
            }
        """)
        l_layout = QVBoxLayout(log_card)
        l_layout.setContentsMargins(10, 10, 10, 10)
        l_layout.setSpacing(6)
        lbl_log = QLabel("Detailliertes Scan-Protokoll:")
        lbl_log.setStyleSheet("font-weight: 600; font-size: 12px;")
        l_layout.addWidget(lbl_log)

        self.txt_log = QTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setFont(QFont("JetBrains Mono, monospace", 10))
        self.txt_log.setStyleSheet("""
            QTextEdit {
                background-color: palette(window);
                color: palette(text);
                border: 1px solid palette(mid);
                border-radius: 6px;
                padding: 8px;
            }
        """)
        l_layout.addWidget(self.txt_log)
        splitter.addWidget(log_card)

        splitter.setSizes([260, 200])
        layout.addWidget(splitter)

    def start_system_scan(self):
        cmd = ["aur-scan", "system", "--no-color"]
        if self.chk_rescan.isChecked():
            cmd.append("--rescan")

        sev = self.severity_combo.currentData()
        if sev:
            cmd.extend(["-s", sev])

        self.btn_start.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.table.setRowCount(0)
        self.txt_log.clear()

        self.card_status.set_text("Scan läuft...", "#3b82f6")

        self.worker = ProcessStreamWorker(cmd)
        self.worker.output_line.connect(self.on_output_line)
        self.worker.completed.connect(self.on_scan_completed)
        self.worker.error.connect(self.on_scan_error)
        self.worker.start()

    def stop_system_scan(self):
        if self.worker:
            self.worker.cancel()
            self.btn_start.setEnabled(True)
            self.btn_stop.setEnabled(False)
            self.progress_bar.setVisible(False)
            self.card_status.set_text("Abgebrochen", "#ef4444")

    def on_output_line(self, line: str):
        cursor = self.txt_log.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        fmt = QTextCharFormat()
        line_lower = line.lower()

        if "critical" in line_lower or "high" in line_lower:
            fmt.setForeground(QColor("#ef4444"))
            fmt.setFontWeight(QFont.Weight.Bold)
        elif "ok" in line_lower or "no security issues" in line_lower:
            fmt.setForeground(QColor("#10b981"))
        else:
            fmt.setForeground(QColor(self.palette().text().color()))

        cursor.insertText(line + "\n", fmt)
        self.txt_log.setTextCursor(cursor)
        self.txt_log.ensureCursorVisible()

        m_scan = re.match(r"^Scanning:\s+([^\s]+)\s+(.*)$", line)
        if m_scan:
            pkg = m_scan.group(1)
            status = m_scan.group(2)
            row = self.table.rowCount()
            self.table.insertRow(row)

            is_ok = "ok" in status.lower()
            item_status = QTableWidgetItem("✓ Sicher" if is_ok else "⚠ Befund")
            item_status.setForeground(QColor("#10b981" if is_ok else "#ef4444"))
            item_status.setFont(QFont("sans-serif", 10, QFont.Weight.Bold))

            item_name = QTableWidgetItem(pkg)
            item_name.setFont(QFont("JetBrains Mono, monospace", 10, QFont.Weight.Bold))
            item_res = QTableWidgetItem(status)

            self.table.setItem(row, 0, item_status)
            self.table.setItem(row, 1, item_name)
            self.table.setItem(row, 2, item_res)

        m_count = re.match(r"^Found\s+(\d+)\s+AUR packages", line)
        if m_count:
            self.card_total_pkgs.set_value(int(m_count.group(1)))

    def on_scan_completed(self, returncode: int, full_output: str):
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.progress_bar.setVisible(False)

        lower_out = full_output.lower()
        if "no security issues found" in lower_out or (returncode == 0 and "critical" not in lower_out and "high" not in lower_out):
            self.card_status.set_text("SAUBER", "#10b981")
            self.card_issues.set_value(0)
        else:
            self.card_status.set_text("GEFÄHRDET", "#ef4444")
            issue_count = lower_out.count("critical") + lower_out.count("high")
            self.card_issues.set_value(max(1, issue_count))

    def on_scan_error(self, err: str):
        self.btn_start.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.progress_bar.setVisible(False)
        QMessageBox.critical(self, "Fehler", err)
