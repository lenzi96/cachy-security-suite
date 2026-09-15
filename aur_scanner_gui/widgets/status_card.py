"""
Status metric card widget with modern clean design.
"""
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QFrame, QLabel, QVBoxLayout


class StatusCard(QFrame):
    def __init__(self, title: str, count: int = 0, color_accent: str = "#2563eb", bg_tint: str = "rgba(37, 99, 235, 0.08)", parent=None):
        super().__init__(parent)
        self.color_accent = color_accent
        self.setObjectName("statusCard")
        self.setFixedHeight(78)

        self._apply_style(color_accent)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 10, 16, 10)
        layout.setSpacing(2)
        layout.setAlignment(Qt.AlignmentFlag.AlignVCenter)

        self.lbl_title = QLabel(title.upper())
        self.lbl_title.setStyleSheet("""
            font-size: 10px;
            font-weight: 700;
            color: #94a3b8;
            letter-spacing: 0.8px;
        """)
        self.lbl_title.setAlignment(Qt.AlignmentFlag.AlignLeft)

        self.lbl_count = QLabel(str(count))
        self.lbl_count.setStyleSheet(f"""
            font-size: 22px;
            font-weight: 800;
            color: {color_accent};
            letter-spacing: 0.3px;
        """)
        self.lbl_count.setAlignment(Qt.AlignmentFlag.AlignLeft)

        layout.addWidget(self.lbl_title)
        layout.addWidget(self.lbl_count)

    def _apply_style(self, accent: str):
        self.setStyleSheet(f"""
            QFrame#statusCard {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #172033, stop:1 #0e1626);
                border: 1px solid #293548;
                border-left: 4px solid {accent};
                border-radius: 10px;
            }}
            QFrame#statusCard:hover {{
                border-color: #3b82f6;
                border-left-color: {accent};
            }}
            QFrame#statusCard QLabel {{
                border: none !important;
                background: transparent !important;
                padding: 0px !important;
                margin: 0px !important;
            }}
        """)

    def set_value(self, count: int):
        self.lbl_count.setText(str(count))

    def set_text(self, text: str, color: str = None):
        self.lbl_count.setText(text)
        accent = color if color else self.color_accent
        self.lbl_count.setStyleSheet(f"""
            font-size: 18px;
            font-weight: 800;
            color: {accent};
            letter-spacing: 0.3px;
        """)
        self._apply_style(accent)
