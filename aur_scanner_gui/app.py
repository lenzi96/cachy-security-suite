"""
Application bootstrap and entry point with modern dark theme initialization.
"""
import os
import shutil
import sys

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont, QIcon, QPalette
from PyQt6.QtWidgets import QApplication, QMessageBox

from aur_scanner_gui.main_window import MainWindow


def setup_dark_theme(app: QApplication):
    """Sets up an ultra-sleek, modern dark palette and global widget styles."""
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor("#0b0f19"))
    palette.setColor(QPalette.ColorRole.WindowText, QColor("#f1f5f9"))
    palette.setColor(QPalette.ColorRole.Base, QColor("#111827"))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#0d131f"))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor("#1e293b"))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor("#f8fafc"))
    palette.setColor(QPalette.ColorRole.Text, QColor("#f8fafc"))
    palette.setColor(QPalette.ColorRole.Button, QColor("#172033"))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor("#f1f5f9"))
    palette.setColor(QPalette.ColorRole.BrightText, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.Highlight, QColor("#2563eb"))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffffff"))
    palette.setColor(QPalette.ColorRole.Mid, QColor("#293548"))
    palette.setColor(QPalette.ColorRole.Dark, QColor("#090d16"))
    palette.setColor(QPalette.ColorRole.Light, QColor("#1e293b"))
    app.setPalette(palette)

    app.setStyleSheet("""
        QWidget {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Noto Sans", Ubuntu, Cantarell, sans-serif;
        }
        QToolTip {
            background-color: #1e293b;
            color: #f8fafc;
            border: 1px solid #475569;
            border-radius: 6px;
            padding: 6px 10px;
            font-size: 11px;
        }
        QMenuBar {
            background-color: #090d16;
            color: #94a3b8;
            border-bottom: 1px solid #1e293b;
            padding: 2px 4px;
            font-size: 12px;
        }
        QMenuBar::item {
            background: transparent;
            padding: 4px 10px;
            border-radius: 4px;
        }
        QMenuBar::item:selected {
            background-color: #1e293b;
            color: #f8fafc;
        }
        QMenu {
            background-color: #0f172a;
            color: #f1f5f9;
            border: 1px solid #1e293b;
            border-radius: 8px;
            padding: 4px;
            font-size: 12px;
        }
        QMenu::item {
            padding: 6px 20px;
            border-radius: 4px;
        }
        QMenu::item:selected {
            background-color: #2563eb;
            color: #ffffff;
        }
        QMenu::separator {
            height: 1px;
            background: #1e293b;
            margin: 4px 8px;
        }
        QStatusBar {
            background-color: #080c14;
            color: #64748b;
            border-top: 1px solid #1e293b;
            font-size: 11px;
            padding: 2px 8px;
        }
        QScrollBar:vertical {
            background: transparent;
            width: 8px;
            margin: 2px;
            border-radius: 4px;
        }
        QScrollBar::handle:vertical {
            background: #334155;
            border-radius: 4px;
            min-height: 24px;
        }
        QScrollBar::handle:vertical:hover {
            background: #475569;
        }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
            height: 0px;
        }
        QScrollBar:horizontal {
            background: transparent;
            height: 8px;
            margin: 2px;
            border-radius: 4px;
        }
        QScrollBar::handle:horizontal {
            background: #334155;
            border-radius: 4px;
            min-width: 24px;
        }
        QScrollBar::handle:horizontal:hover {
            background: #475569;
        }
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
            width: 0px;
        }
        QSplitter::handle {
            background-color: #1e293b;
            height: 1px;
        }
        QHeaderView::section {
            background-color: #0f172a;
            color: #94a3b8;
            padding: 6px 10px;
            border: none;
            border-bottom: 1px solid #1e293b;
            font-size: 11px;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
    """)


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("cachy-security-suite")
    app.setApplicationDisplayName("Cachy Security Suite")
    app.setDesktopFileName("cachy-security-suite")

    # Apply unified modern dark theme
    setup_dark_theme(app)

    # Set application icon
    icon_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "resources", "aur-scanner-256.png")
    if not os.path.exists(icon_path):
        icon_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "resources", "aur-scanner.svg")
    if os.path.exists(icon_path):
        app.setWindowIcon(QIcon(icon_path))
    else:
        app_icon = QIcon.fromTheme("security-high")
        if not app_icon.isNull():
            app.setWindowIcon(app_icon)

    # Check for aur-scan CLI tool
    if not shutil.which("aur-scan"):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Icon.Warning)
        msg.setWindowTitle("aur-scan nicht gefunden")
        msg.setText(
            "Das Befehlszeilenwerkzeug 'aur-scan' wurde im System-Pfad nicht gefunden.\n\n"
            "Bitte stelle sicher, dass 'aur-scanner' installiert ist (z. B. via 'yay -S aur-scanner')."
        )
        msg.exec()

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
