"""
Modern Empty State widget when no scan or results are present.
"""
from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont, QIcon
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QVBoxLayout,
    QWidget,
)


class EmptyStateWidget(QFrame):
    open_file_requested = pyqtSignal()
    open_dir_requested = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("emptyState")
        self.setStyleSheet("""
            QFrame#emptyState {
                background-color: palette(base);
                border: 2px dashed palette(mid);
                border-radius: 12px;
            }
            QFrame#emptyState QLabel {
                background: transparent !important;
                border: none !important;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.setSpacing(12)
        layout.setContentsMargins(40, 40, 40, 40)

        # Icon / Illustration
        icon_lbl = QLabel()
        icon_lbl.setPixmap(QIcon.fromTheme("security-high").pixmap(64, 64))
        icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(icon_lbl)

        # Title
        title_lbl = QLabel("Bereit für die Sicherheitsprüfung")
        title_lbl.setStyleSheet("font-size: 16px; font-weight: 700; color: palette(text);")
        title_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title_lbl)

        # Description
        desc_lbl = QLabel(
            "Wähle eine PKGBUILD-Datei oder einen Quellordner aus,\n"
            "um statische Sicherheitsanalysen, Backdoor-Prüfungen und IOC-Scans durchzuführen."
        )
        desc_lbl.setStyleSheet("font-size: 12px; color: palette(text); opacity: 0.7; line-height: 1.5;")
        desc_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(desc_lbl)

        # Action Buttons
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(10)
        btn_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)

        btn_open = QPushButton("  PKGBUILD öffnen...")
        btn_open.setIcon(QIcon.fromTheme("document-open"))
        btn_open.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_open.setStyleSheet("""
            QPushButton {
                background-color: #2563eb;
                color: #ffffff;
                font-weight: 600;
                font-size: 12px;
                padding: 8px 18px;
                border-radius: 6px;
                border: none;
            }
            QPushButton:hover {
                background-color: #1d4ed8;
            }
        """)
        btn_open.clicked.connect(self.open_file_requested.emit)

        btn_dir = QPushButton("  Ordner öffnen...")
        btn_dir.setIcon(QIcon.fromTheme("folder-open"))
        btn_dir.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_dir.setStyleSheet("""
            QPushButton {
                background-color: palette(window);
                color: palette(text);
                font-weight: 500;
                font-size: 12px;
                padding: 8px 16px;
                border-radius: 6px;
                border: 1px solid palette(mid);
            }
            QPushButton:hover {
                background-color: palette(button);
            }
        """)
        btn_dir.clicked.connect(self.open_dir_requested.emit)

        btn_layout.addWidget(btn_open)
        btn_layout.addWidget(btn_dir)
        layout.addLayout(btn_layout)
