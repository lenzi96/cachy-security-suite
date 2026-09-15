"""
Application bootstrap and entry point.
"""
import os
import shutil
import sys

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QApplication, QMessageBox

from aur_scanner_gui.main_window import MainWindow


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("cachy-security-suite")
    app.setApplicationDisplayName("Cachy Security Suite")
    app.setDesktopFileName("cachy-security-suite")

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
