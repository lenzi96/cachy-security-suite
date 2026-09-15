"""
View for the Indicators of Compromise (IOC) database with modern clean styling.
"""
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont, QIcon
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QSplitter,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from aur_scanner_gui.scanner_service import AurScannerService


class IOCView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.init_ui()
        self.load_ioc_info()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        # 1. Header
        header_layout = QVBoxLayout()
        header_layout.setSpacing(3)
        lbl_title = QLabel("IOC-Datenbank & Bedrohungs-Intelligenz")
        lbl_title.setStyleSheet("font-size: 18px; font-weight: 700; color: palette(text);")
        lbl_desc = QLabel("Überprüfe Indikatoren (Paketnamen, URLs, Hashes) gegen bekannte Bedrohungskampagnen im AUR.")
        lbl_desc.setStyleSheet("font-size: 12px; color: palette(text); opacity: 0.7;")
        header_layout.addWidget(lbl_title)
        header_layout.addWidget(lbl_desc)
        layout.addLayout(header_layout)

        # 2. Query Card
        query_card = QFrame()
        query_card.setObjectName("queryCard")
        query_card.setStyleSheet("""
            QFrame#queryCard {
                background-color: palette(base);
                border: 1px solid palette(mid);
                border-radius: 10px;
                padding: 4px;
            }
        """)
        q_layout = QHBoxLayout(query_card)
        q_layout.setContentsMargins(10, 8, 10, 8)
        q_layout.setSpacing(8)

        self.query_input = QLineEdit()
        self.query_input.setPlaceholderText("Paketname, Domain oder Wert eingeben (z. B. atomic-arch, chaos-rat)...")
        self.query_input.setStyleSheet("""
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
        self.query_input.returnPressed.connect(self.check_indicator)

        btn_check = QPushButton("  Indikator prüfen")
        btn_check.setIcon(QIcon.fromTheme("edit-find"))
        btn_check.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_check.setStyleSheet("""
            QPushButton {
                background-color: #2563eb;
                color: white;
                font-weight: 600;
                font-size: 12px;
                padding: 7px 18px;
                border-radius: 6px;
                border: none;
            }
            QPushButton:hover {
                background-color: #1d4ed8;
            }
        """)
        btn_check.clicked.connect(self.check_indicator)

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
        btn_reload.clicked.connect(self.load_ioc_info)

        q_layout.addWidget(self.query_input, stretch=3)
        q_layout.addWidget(btn_check)
        q_layout.addWidget(btn_reload)
        layout.addWidget(query_card)

        # 3. Splitter: Query Result + IOC Database Summary
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setHandleWidth(8)

        # Result Card
        res_card = QFrame()
        res_card.setObjectName("resCard")
        res_card.setStyleSheet("""
            QFrame#resCard {
                background-color: palette(base);
                border: 1px solid palette(mid);
                border-radius: 10px;
            }
        """)
        r_layout = QVBoxLayout(res_card)
        r_layout.setContentsMargins(10, 10, 10, 10)
        r_layout.setSpacing(6)

        lbl_res = QLabel("Abfrageergebnis:")
        lbl_res.setStyleSheet("font-weight: 600; font-size: 12px;")
        r_layout.addWidget(lbl_res)

        self.txt_result = QTextBrowser()
        self.txt_result.setFont(QFont("JetBrains Mono, monospace", 10))
        self.txt_result.setPlaceholderText("Ergebnisse der Indikator-Prüfung erscheinen hier...")
        self.txt_result.setMaximumHeight(120)
        self.txt_result.setStyleSheet("""
            QTextBrowser {
                background-color: palette(window);
                color: palette(text);
                border: 1px solid palette(mid);
                border-radius: 6px;
                padding: 8px;
            }
        """)
        r_layout.addWidget(self.txt_result)
        splitter.addWidget(res_card)

        # Summary Card
        db_card = QFrame()
        db_card.setObjectName("dbCard")
        db_card.setStyleSheet("""
            QFrame#dbCard {
                background-color: palette(base);
                border: 1px solid palette(mid);
                border-radius: 10px;
            }
        """)
        d_layout = QVBoxLayout(db_card)
        d_layout.setContentsMargins(10, 10, 10, 10)
        d_layout.setSpacing(6)

        lbl_db = QLabel("Bekannte Kampagnen & IOC-Datenbank-Status:")
        lbl_db.setStyleSheet("font-weight: 600; font-size: 12px;")
        d_layout.addWidget(lbl_db)

        self.txt_summary = QTextBrowser()
        self.txt_summary.setFont(QFont("JetBrains Mono, monospace", 10))
        self.txt_summary.setStyleSheet("""
            QTextBrowser {
                background-color: palette(window);
                color: palette(text);
                border: 1px solid palette(mid);
                border-radius: 6px;
                padding: 10px;
            }
        """)
        d_layout.addWidget(self.txt_summary)
        splitter.addWidget(db_card)

        splitter.setSizes([120, 360])
        layout.addWidget(splitter, stretch=1)

    def load_ioc_info(self):
        self.txt_summary.setPlainText("Lade IOC-Datenbank...")
        summary = AurScannerService.get_ioc_summary()
        self.txt_summary.setPlainText(summary)

    def check_indicator(self):
        val = self.query_input.text().strip()
        if not val:
            return
        self.txt_result.setPlainText(f"Prüfe Indikator '{val}'...")
        res = AurScannerService.check_ioc_indicator(val)
        self.txt_result.setPlainText(res)
