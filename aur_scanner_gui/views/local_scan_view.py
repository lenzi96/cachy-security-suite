"""
View for scanning local PKGBUILD files or directories with clean modern layout and empty state.
"""
import os
from typing import Optional

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QIcon
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    QStackedWidget,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from aur_scanner_gui.models import Finding, ScanResult
from aur_scanner_gui.scanner_service import ScanWorker
from aur_scanner_gui.widgets.code_view import CodeView
from aur_scanner_gui.widgets.empty_state import EmptyStateWidget
from aur_scanner_gui.widgets.severity_badge import SeverityBadge
from aur_scanner_gui.widgets.status_card import StatusCard


class LocalScanView(QWidget):
    request_rule_explain = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.current_result: Optional[ScanResult] = None
        self.worker: Optional[ScanWorker] = None
        self.init_ui()

    def init_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 20, 24, 20)
        main_layout.setSpacing(12)

        # 1. Header with Title & Subtitle
        header_layout = QVBoxLayout()
        header_layout.setSpacing(2)
        lbl_title = QLabel("PKGBUILD Sicherheits-Scan")
        lbl_title.setStyleSheet("font-size: 20px; font-weight: 800; color: palette(text);")
        lbl_desc = QLabel("Statische Quellcode- und Metadaten-Analyse lokaler PKGBUILDs auf Backdoors, Malicious URLs und unsichere Hooks.")
        lbl_desc.setStyleSheet("font-size: 12px; color: palette(text); opacity: 0.7;")
        header_layout.addWidget(lbl_title)
        header_layout.addWidget(lbl_desc)
        main_layout.addLayout(header_layout)

        # 2. Target Selection Panel (Unified Modern Card)
        sel_card = QFrame()
        sel_card.setObjectName("selCard")
        sel_card.setStyleSheet("""
            QFrame#selCard {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #172033, stop:1 #0e1626);
                border: 1px solid #293548;
                border-radius: 10px;
                padding: 4px;
            }
        """)
        sel_layout = QHBoxLayout(sel_card)
        sel_layout.setContentsMargins(12, 10, 12, 10)
        sel_layout.setSpacing(10)

        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("Pfad zu PKGBUILD oder Quellordner auswählen...")
        self.path_input.setStyleSheet("""
            QLineEdit {
                border: 1px solid #334155;
                border-radius: 7px;
                padding: 7px 12px;
                font-size: 12px;
                color: #f8fafc;
                background-color: #090d16;
            }
            QLineEdit:focus {
                border: 1px solid #3b82f6;
            }
        """)
        self.path_input.returnPressed.connect(self.start_scan)

        btn_file = QPushButton("  Datei...")
        btn_file.setIcon(QIcon.fromTheme("document-open"))
        btn_file.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_file.setStyleSheet("""
            QPushButton {
                padding: 7px 14px;
                border-radius: 7px;
                border: 1px solid #334155;
                background: rgba(255, 255, 255, 0.05);
                color: #f1f5f9;
                font-size: 12px;
                font-weight: 500;
            }
            QPushButton:hover {
                background: rgba(255, 255, 255, 0.1);
                border-color: #475569;
            }
        """)
        btn_file.clicked.connect(self.browse_file)

        btn_dir = QPushButton("  Ordner...")
        btn_dir.setIcon(QIcon.fromTheme("folder-open"))
        btn_dir.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_dir.setStyleSheet("""
            QPushButton {
                padding: 7px 14px;
                border-radius: 7px;
                border: 1px solid #334155;
                background: rgba(255, 255, 255, 0.05);
                color: #f1f5f9;
                font-size: 12px;
                font-weight: 500;
            }
            QPushButton:hover {
                background: rgba(255, 255, 255, 0.1);
                border-color: #475569;
            }
        """)
        btn_dir.clicked.connect(self.browse_directory)

        self.severity_combo = QComboBox()
        self.severity_combo.addItem("Min. Schweregrad: Alle", None)
        self.severity_combo.addItem("Critical", "critical")
        self.severity_combo.addItem("High", "high")
        self.severity_combo.addItem("Medium", "medium")
        self.severity_combo.addItem("Low", "low")
        self.severity_combo.addItem("Info", "info")
        self.severity_combo.setStyleSheet("""
            QComboBox {
                border: 1px solid #334155;
                border-radius: 7px;
                padding: 7px 12px;
                font-size: 12px;
                color: #f1f5f9;
                background: #111827;
            }
            QComboBox:hover { border-color: #3b82f6; }
            QComboBox::drop-down { border: none; }
            QComboBox QAbstractItemView {
                background-color: #0f172a;
                color: #f1f5f9;
                selection-background-color: #2563eb;
                border: 1px solid #334155;
            }
        """)

        self.btn_scan = QPushButton("  Jetzt scannen")
        self.btn_scan.setIcon(QIcon.fromTheme("system-search"))
        self.btn_scan.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_scan.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2563eb, stop:1 #3b82f6);
                color: #ffffff;
                font-weight: 700;
                font-size: 12px;
                padding: 8px 20px;
                border-radius: 7px;
                border: none;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1d4ed8, stop:1 #2563eb);
            }
        """)
        self.btn_scan.clicked.connect(self.start_scan)

        sel_layout.addWidget(self.path_input, stretch=3)
        sel_layout.addWidget(btn_file)
        sel_layout.addWidget(btn_dir)
        sel_layout.addWidget(self.severity_combo)
        sel_layout.addWidget(self.btn_scan)

        main_layout.addWidget(sel_card)

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
        main_layout.addWidget(self.progress_bar)

        # 3. Status Cards
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(10)

        self.card_status = StatusCard("Gesamtstatus", 0, "#10b981")
        self.card_status.set_text("Bereit", "#10b981")

        self.card_crit = StatusCard("Kritisch", 0, "#ef4444")
        self.card_high = StatusCard("Hoch", 0, "#f97316")
        self.card_med = StatusCard("Mittel", 0, "#eab308")
        self.card_low = StatusCard("Niedrig", 0, "#3b82f6")
        self.card_duration = StatusCard("Scan-Dauer", 0, "#64748b")
        self.card_duration.set_text("0 ms", "#64748b")

        cards_layout.addWidget(self.card_status)
        cards_layout.addWidget(self.card_crit)
        cards_layout.addWidget(self.card_high)
        cards_layout.addWidget(self.card_med)
        cards_layout.addWidget(self.card_low)
        cards_layout.addWidget(self.card_duration)

        main_layout.addLayout(cards_layout)

        # 4. Central Content Stack (Empty State vs Findings Splitter)
        self.content_stack = QStackedWidget()

        # View 0: Empty State
        self.empty_state = EmptyStateWidget()
        self.empty_state.open_file_requested.connect(self.browse_file)
        self.empty_state.open_dir_requested.connect(self.browse_directory)
        self.content_stack.addWidget(self.empty_state)

        # View 1: Findings Splitter
        self.splitter = QSplitter(Qt.Orientation.Vertical)
        self.splitter.setHandleWidth(8)

        # Findings Table Card
        table_card = QFrame()
        table_card.setObjectName("tableCard")
        table_card.setStyleSheet("""
            QFrame#tableCard {
                background-color: palette(base);
                border: 1px solid palette(mid);
                border-radius: 10px;
            }
        """)
        table_layout = QVBoxLayout(table_card)
        table_layout.setContentsMargins(8, 8, 8, 8)

        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Schweregrad", "Code", "Kategorie", "Titel", "Fundort"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
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
        self.table.itemSelectionChanged.connect(self.on_finding_selected)

        table_layout.addWidget(self.table)
        self.splitter.addWidget(table_card)

        # Detail Inspector Card
        self.detail_card = QFrame()
        self.detail_card.setObjectName("detailCard")
        self.detail_card.setStyleSheet("""
            QFrame#detailCard {
                background-color: palette(base);
                border: 1px solid palette(mid);
                border-radius: 10px;
                padding: 8px;
            }
        """)
        detail_layout = QVBoxLayout(self.detail_card)
        detail_layout.setContentsMargins(14, 12, 14, 12)
        detail_layout.setSpacing(8)

        # Header with Title and "Explain" button
        header_detail = QHBoxLayout()
        self.lbl_detail_title = QLabel("Wähle einen Befund aus der Tabelle aus")
        self.lbl_detail_title.setStyleSheet("font-weight: 700; font-size: 14px; color: palette(text);")

        self.btn_explain = QPushButton("  Regel-Erklärung")
        self.btn_explain.setIcon(QIcon.fromTheme("dialog-information"))
        self.btn_explain.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_explain.setEnabled(False)
        self.btn_explain.setStyleSheet("""
            QPushButton {
                padding: 5px 14px;
                border-radius: 6px;
                border: 1px solid palette(mid);
                background: palette(window);
                font-size: 11px;
                font-weight: 500;
            }
            QPushButton:hover {
                background: #3b82f6;
                color: #ffffff;
                border-color: #2563eb;
            }
        """)
        self.btn_explain.clicked.connect(self.on_explain_clicked)

        header_detail.addWidget(self.lbl_detail_title)
        header_detail.addStretch()
        header_detail.addWidget(self.btn_explain)
        detail_layout.addLayout(header_detail)

        # Description browser
        self.txt_description = QTextBrowser()
        self.txt_description.setOpenExternalLinks(True)
        self.txt_description.setMaximumHeight(110)
        self.txt_description.setStyleSheet("""
            QTextBrowser {
                border: 1px solid palette(mid);
                border-radius: 6px;
                background-color: palette(window);
                padding: 6px 10px;
            }
        """)
        detail_layout.addWidget(self.txt_description)

        # Code snippet view
        lbl_code = QLabel("Betroffener Code-Ausschnitt:")
        lbl_code.setStyleSheet("font-weight: 600; font-size: 11px; color: palette(text); opacity: 0.8;")
        detail_layout.addWidget(lbl_code)

        self.code_view = CodeView()
        self.code_view.setMaximumHeight(130)
        detail_layout.addWidget(self.code_view)

        self.splitter.addWidget(self.detail_card)
        self.splitter.setSizes([280, 260])

        self.content_stack.addWidget(self.splitter)
        main_layout.addWidget(self.content_stack, stretch=1)

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "PKGBUILD auswählen",
            os.path.expanduser("~"),
            "PKGBUILD (PKGBUILD *.PKGBUILD);;Alle Dateien (*)",
        )
        if file_path:
            self.path_input.setText(file_path)
            self.start_scan()

    def browse_directory(self):
        dir_path = QFileDialog.getExistingDirectory(
            self,
            "Verzeichnis mit PKGBUILD auswählen",
            os.path.expanduser("~"),
        )
        if dir_path:
            self.path_input.setText(dir_path)
            self.start_scan()

    def set_target(self, path: str):
        self.path_input.setText(path)
        self.start_scan()

    def start_scan(self):
        target = self.path_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Hinweis", "Bitte gib einen Pfad zu einem PKGBUILD oder Ordner an.")
            return

        if not os.path.exists(target):
            QMessageBox.critical(self, "Fehler", f"Der Pfad existiert nicht:\n{target}")
            return

        self.btn_scan.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.table.setRowCount(0)
        self.txt_description.clear()
        self.code_view.set_snippet("")
        self.btn_explain.setEnabled(False)
        self.lbl_detail_title.setText("Scanne...")

        severity = self.severity_combo.currentData()
        self.worker = ScanWorker(target, severity)
        self.worker.finished.connect(self.on_scan_finished)
        self.worker.error.connect(self.on_scan_error)
        self.worker.start()

    def on_scan_finished(self, result: ScanResult):
        self.btn_scan.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.current_result = result

        # Switch from empty state to findings splitter
        self.content_stack.setCurrentIndex(1)

        # Update cards
        self.card_crit.set_value(result.critical_count)
        self.card_high.set_value(result.high_count)
        self.card_med.set_value(result.medium_count)
        self.card_low.set_value(result.low_count)
        self.card_duration.set_text(f"{result.scan_duration_ms} ms", "#64748b")

        if result.critical_count > 0:
            self.card_status.set_text("GEFAHR", "#ef4444")
        elif result.high_count > 0:
            self.card_status.set_text("WARNUNG", "#f97316")
        elif result.medium_count > 0 or result.low_count > 0:
            self.card_status.set_text("HINWEISE", "#eab308")
        else:
            self.card_status.set_text("SAUBER", "#10b981")

        # Populate table
        self.table.setRowCount(len(result.findings))
        for row, f in enumerate(result.findings):
            badge = SeverityBadge(f.severity)
            badge_container = QWidget()
            b_layout = QHBoxLayout(badge_container)
            b_layout.setContentsMargins(6, 2, 6, 2)
            b_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            b_layout.addWidget(badge)
            self.table.setCellWidget(row, 0, badge_container)

            item_id = QTableWidgetItem(f.id)
            item_id.setFont(QFont("JetBrains Mono, monospace", 10, QFont.Weight.Bold))
            item_id.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row, 1, item_id)

            item_cat = QTableWidgetItem(f.category)
            self.table.setItem(row, 2, item_cat)

            item_title = QTableWidgetItem(f.title)
            self.table.setItem(row, 3, item_title)

            loc_str = ""
            if f.location.line is not None:
                loc_str = f"Zeile {f.location.line}"
            elif f.location.file:
                loc_str = os.path.basename(f.location.file)
            item_loc = QTableWidgetItem(loc_str)
            item_loc.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table.setItem(row, 4, item_loc)

        if result.findings:
            self.table.selectRow(0)
            count = len(result.findings)
            word = "Befund" if count == 1 else "Befunde"
            self.lbl_detail_title.setText(f"{count} {word} in {result.package_name}")
        else:
            self.lbl_detail_title.setText(f"✓ Keine Sicherheitsbefunde in {result.package_name} festgestellt.")

    def on_scan_error(self, err_msg: str):
        self.btn_scan.setEnabled(True)
        self.progress_bar.setVisible(False)
        QMessageBox.critical(self, "Scan-Fehler", err_msg)
        self.lbl_detail_title.setText("Fehler beim Scan")

    def on_finding_selected(self):
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows or not self.current_result:
            return

        row = selected_rows[0].row()
        if 0 <= row < len(self.current_result.findings):
            f = self.current_result.findings[row]
            self.lbl_detail_title.setText(f"[{f.id}] {f.title}")
            self.btn_explain.setEnabled(True)

            cwe_html = f"<span style='background: #e2e8f0; color: #334155; padding: 2px 6px; border-radius: 4px; font-weight: bold;'>CWE: {f.cwe_id}</span>" if f.cwe_id else ""
            rec_html = f"""
                <div style='margin-top: 6px; padding: 8px 12px; background-color: rgba(16, 185, 129, 0.1); border-left: 3px solid #10b981; border-radius: 4px;'>
                    <b>Empfehlung:</b> {f.recommendation}
                </div>
            """ if f.recommendation else ""

            html = f"""
                <div style="font-family: sans-serif; font-size: 12px; line-height: 1.4;">
                    <div style="margin-bottom: 4px;">
                        <span style='background: #dbeafe; color: #1e40af; padding: 2px 6px; border-radius: 4px; font-weight: bold;'>Kategorie: {f.category}</span>
                        {cwe_html}
                    </div>
                    <p style="margin: 4px 0;">{f.description}</p>
                    {rec_html}
                </div>
            """
            self.txt_description.setHtml(html)
            self.code_view.set_snippet(f.location.snippet, f.location.line)

    def on_explain_clicked(self):
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows or not self.current_result:
            return
        row = selected_rows[0].row()
        f = self.current_result.findings[row]
        self.request_rule_explain.emit(f.id)
