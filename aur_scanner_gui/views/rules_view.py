"""
View for browsing and searching security detection rules and explanations with clean modern UI.
"""
from typing import Dict, List

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QIcon
from PyQt6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from aur_scanner_gui.models import RuleItem
from aur_scanner_gui.scanner_service import AurScannerService
from aur_scanner_gui.widgets.severity_badge import SeverityBadge


class RulesView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.rules: List[RuleItem] = []
        self.init_ui()
        self.load_rules()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        # 1. Header
        header_layout = QVBoxLayout()
        header_layout.setSpacing(3)
        lbl_title = QLabel("Regel-Katalog & Erkennungsmuster")
        lbl_title.setStyleSheet("font-size: 18px; font-weight: 700; color: palette(text);")
        lbl_desc = QLabel("Durchsuche alle 118 integrierten Sicherheitsregeln und lies ausführliche Erklärungen zu Risiken.")
        lbl_desc.setStyleSheet("font-size: 12px; color: palette(text); opacity: 0.7;")
        header_layout.addWidget(lbl_title)
        header_layout.addWidget(lbl_desc)
        layout.addLayout(header_layout)

        # 2. Filter Card
        filter_card = QFrame()
        filter_card.setObjectName("filterCard")
        filter_card.setStyleSheet("""
            QFrame#filterCard {
                background-color: palette(base);
                border: 1px solid palette(mid);
                border-radius: 10px;
                padding: 4px;
            }
        """)
        f_layout = QHBoxLayout(filter_card)
        f_layout.setContentsMargins(10, 8, 10, 8)
        f_layout.setSpacing(8)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Suche nach Regel-Code, Titel oder Kategorie...")
        self.search_input.setStyleSheet("""
            QLineEdit {
                border: 1px solid palette(mid);
                border-radius: 6px;
                padding: 6px 12px;
                font-size: 12px;
                background-color: palette(window);
            }
            QLineEdit:focus {
                border: 1px solid #3b82f6;
            }
        """)
        self.search_input.textChanged.connect(self.apply_filter)

        self.category_combo = QComboBox()
        self.category_combo.addItem("Alle Kategorien", None)
        self.category_combo.setStyleSheet("""
            QComboBox {
                border: 1px solid palette(mid);
                border-radius: 6px;
                padding: 5px 10px;
                font-size: 12px;
                background: palette(window);
            }
        """)
        self.category_combo.currentIndexChanged.connect(self.apply_filter)

        self.severity_combo = QComboBox()
        self.severity_combo.addItem("Alle Schweregrade", None)
        self.severity_combo.addItem("Critical", "critical")
        self.severity_combo.addItem("High", "high")
        self.severity_combo.addItem("Medium", "medium")
        self.severity_combo.addItem("Low", "low")
        self.severity_combo.addItem("Info", "info")
        self.severity_combo.setStyleSheet("""
            QComboBox {
                border: 1px solid palette(mid);
                border-radius: 6px;
                padding: 5px 10px;
                font-size: 12px;
                background: palette(window);
            }
        """)
        self.severity_combo.currentIndexChanged.connect(self.apply_filter)

        btn_reload = QPushButton("Neu laden")
        btn_reload.setIcon(QIcon.fromTheme("view-refresh"))
        btn_reload.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_reload.setStyleSheet("""
            QPushButton {
                padding: 6px 12px;
                border-radius: 6px;
                border: 1px solid palette(mid);
                background: palette(window);
                font-size: 12px;
            }
            QPushButton:hover {
                background: palette(button);
            }
        """)
        btn_reload.clicked.connect(self.load_rules)

        f_layout.addWidget(self.search_input, stretch=3)
        f_layout.addWidget(self.category_combo)
        f_layout.addWidget(self.severity_combo)
        f_layout.addWidget(btn_reload)
        layout.addWidget(filter_card)

        # 3. Splitter: Rules Table (Left) + Explanation Pane (Right)
        splitter = QSplitter(Qt.Orientation.Horizontal)
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
        t_layout.setSpacing(6)

        self.lbl_count = QLabel("Lade Regeln...")
        self.lbl_count.setStyleSheet("font-weight: 600; font-size: 11px; color: palette(text); opacity: 0.8;")
        t_layout.addWidget(self.lbl_count)

        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Schweregrad", "Code", "Kategorie", "Titel"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
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
        self.table.itemSelectionChanged.connect(self.on_rule_selected)

        t_layout.addWidget(self.table)
        splitter.addWidget(table_card)

        # Detail Explanation Card
        detail_card = QFrame()
        detail_card.setObjectName("detailCard")
        detail_card.setStyleSheet("""
            QFrame#detailCard {
                background-color: palette(base);
                border: 1px solid palette(mid);
                border-radius: 10px;
            }
        """)
        d_layout = QVBoxLayout(detail_card)
        d_layout.setContentsMargins(10, 10, 10, 10)
        d_layout.setSpacing(6)

        lbl_det = QLabel("Regel-Dokumentation & realer Kontext:")
        lbl_det.setStyleSheet("font-weight: 600; font-size: 12px;")
        d_layout.addWidget(lbl_det)

        self.txt_explain = QTextBrowser()
        self.txt_explain.setFont(QFont("JetBrains Mono, monospace", 10))
        self.txt_explain.setStyleSheet("""
            QTextBrowser {
                background-color: palette(window);
                color: palette(text);
                border: 1px solid palette(mid);
                border-radius: 6px;
                padding: 10px;
            }
        """)
        d_layout.addWidget(self.txt_explain)

        splitter.addWidget(detail_card)
        splitter.setSizes([540, 440])

        layout.addWidget(splitter, stretch=1)

    def load_rules(self):
        self.rules = AurScannerService.get_rules()
        cats = sorted(list({r.category for r in self.rules if r.category}))
        self.category_combo.clear()
        self.category_combo.addItem("Alle Kategorien", None)
        for cat in cats:
            self.category_combo.addItem(cat, cat)

        self.apply_filter()

    def apply_filter(self):
        query = self.search_input.text().strip().lower()
        selected_cat = self.category_combo.currentData()
        selected_sev = self.severity_combo.currentData()

        filtered: List[RuleItem] = []
        for r in self.rules:
            if selected_cat and r.category != selected_cat:
                continue
            if selected_sev and r.severity.lower() != selected_sev.lower():
                continue
            if query:
                if (
                    query not in r.id.lower()
                    and query not in r.title.lower()
                    and query not in r.category.lower()
                ):
                    continue
            filtered.append(r)

        self.lbl_count.setText(f"{len(filtered)} von {len(self.rules)} Regeln angezeigt")

        self.table.setRowCount(len(filtered))
        for row, r in enumerate(filtered):
            # Column 0: Severity badge
            badge = SeverityBadge(r.severity)
            badge_container = QWidget()
            b_layout = QHBoxLayout(badge_container)
            b_layout.setContentsMargins(6, 2, 6, 2)
            b_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
            b_layout.addWidget(badge)
            self.table.setCellWidget(row, 0, badge_container)

            # Column 1: Code ID
            item_id = QTableWidgetItem(r.id)
            item_id.setFont(QFont("JetBrains Mono, monospace", 10, QFont.Weight.Bold))
            item_id.setData(Qt.ItemDataRole.UserRole, r)
            self.table.setItem(row, 1, item_id)

            # Column 2: Category
            item_cat = QTableWidgetItem(r.category)
            self.table.setItem(row, 2, item_cat)

            # Column 3: Title
            item_title = QTableWidgetItem(r.title)
            self.table.setItem(row, 3, item_title)

        if filtered:
            self.table.selectRow(0)
        else:
            self.txt_explain.setPlainText("Keine passenden Regeln gefunden.")

    def on_rule_selected(self):
        selected_rows = self.table.selectionModel().selectedRows()
        if not selected_rows:
            return

        row = selected_rows[0].row()
        item = self.table.item(row, 1)
        if not item:
            return

        rule: RuleItem = item.data(Qt.ItemDataRole.UserRole)
        if rule:
            self.txt_explain.setPlainText("Lade Erklärung...")
            explanation = AurScannerService.explain_code(rule.id)
            self.txt_explain.setPlainText(explanation)

    def select_rule_by_code(self, code: str):
        self.search_input.setText(code)
        for row in range(self.table.rowCount()):
            item = self.table.item(row, 1)
            if item and item.text().upper() == code.upper():
                self.table.selectRow(row)
                break
