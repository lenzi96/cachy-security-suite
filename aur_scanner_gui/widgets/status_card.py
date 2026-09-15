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
        self.setFixedHeight(74)

        self.setStyleSheet(f"""
            QFrame#statusCard {{
                background-color: palette(base);
                border: 1px solid palette(mid);
                border-left: 5px solid {color_accent};
                border-radius: 8px;
            }}
            QFrame#statusCard QLabel {{
                border: none !important;
                background: transparent !important;
                padding: 0px !important;
                margin: 0px !important;
            }}
        """)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(2)
        layout.setAlignment(Qt.AlignmentFlag.AlignVCenter)

        self.lbl_count = QLabel(str(count))
        self.lbl_count.setStyleSheet(f"""
            font-size: 20px;
            font-weight: 700;
            color: {color_accent};
        """)
        self.lbl_count.setAlignment(Qt.AlignmentFlag.AlignLeft)

        self.lbl_title = QLabel(title)
        self.lbl_title.setStyleSheet("""
            font-size: 11px;
            font-weight: 500;
            color: palette(text);
            opacity: 0.75;
        """)
        self.lbl_title.setAlignment(Qt.AlignmentFlag.AlignLeft)

        layout.addWidget(self.lbl_count)
        layout.addWidget(self.lbl_title)

    def set_value(self, count: int):
        self.lbl_count.setText(str(count))

    def set_text(self, text: str, color: str = None):
        self.lbl_count.setText(text)
        if color:
            self.lbl_count.setStyleSheet(f"""
                font-size: 16px;
                font-weight: 700;
                color: {color};
            """)
            self.setStyleSheet(f"""
                QFrame#statusCard {{
                    background-color: palette(base);
                    border: 1px solid palette(mid);
                    border-left: 5px solid {color};
                    border-radius: 8px;
                }}
                QFrame#statusCard QLabel {{
                    border: none !important;
                    background: transparent !important;
                    padding: 0px !important;
                    margin: 0px !important;
                }}
            """)
