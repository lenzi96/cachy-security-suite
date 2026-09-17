"""
Polkit & Sudoers Setup Dialog for Cachy Security Suite.
Configures passwordless authorization for UFW firewall management
and ClamAV freshclam service control for administrative users (wheel group).
"""
import os
import shutil
import subprocess
import tempfile
from typing import Optional

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QIcon, QPixmap
from PyQt6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QProgressBar,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
)


class PolkitWorker(QThread):
    output_received = pyqtSignal(str)
    finished = pyqtSignal(bool, str)

    def __init__(self, uninstall: bool = False):
        super().__init__()
        self.uninstall = uninstall

    def _find_script(self) -> Optional[str]:
        candidates = [
            os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "setup-polkit.sh"),
            os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "setup-polkit.sh"),
            "/usr/share/cachy-security-suite/setup-polkit.sh",
            os.path.expanduser("~/.local/share/cachy-security-suite/setup-polkit.sh"),
        ]
        for p in candidates:
            if os.path.isfile(p):
                return p
        return None

    def run(self):
        script_path = self._find_script()
        temp_dir = None

        try:
            if not script_path:
                # Create a standalone script in temporary directory if not found on disk
                temp_dir = tempfile.mkdtemp(prefix="cachy_polkit_")
                script_path = os.path.join(temp_dir, "setup-polkit.sh")
                res_dir = os.path.join(temp_dir, "resources")
                os.makedirs(res_dir, exist_ok=True)

                rules_content = """polkit.addRule(function(action, subject) {
    if (subject.isInGroup("wheel") || subject.isInGroup("sudo")) {
        if (action.id === "org.freedesktop.policykit.exec") {
            var prog = action.lookup("program");
            if (prog === "/usr/bin/ufw" ||
                prog === "/usr/bin/freshclam" ||
                prog === "/usr/bin/systemctl") {
                return polkit.Result.YES;
            }
        }
        if (action.id === "org.freedesktop.systemd1.manage-units" ||
            action.id === "org.freedesktop.systemd1.manage-unit-files") {
            var unit = action.lookup("unit");
            if (!unit ||
                unit === "clamav-freshclam.service" || unit === "clamav-freshclam" ||
                unit === "ufw.service" || unit === "ufw") {
                return polkit.Result.YES;
            }
        }
    }
});
"""
                sudoers_content = """%wheel ALL=(ALL) NOPASSWD: /usr/bin/ufw, /usr/bin/systemctl * clamav-freshclam.service, /usr/bin/systemctl * clamav-freshclam, /usr/bin/systemctl * ufw.service, /usr/bin/systemctl * ufw, /usr/bin/freshclam\n"""

                with open(os.path.join(res_dir, "49-cachy-security-suite.rules"), "w") as f:
                    f.write(rules_content)
                with open(os.path.join(res_dir, "cachy-security-suite.sudoers"), "w") as f:
                    f.write(sudoers_content)

                script_code = f"""#!/usr/bin/env bash
set -e
DIR="{temp_dir}"
POLKIT_RULES_DIR="/etc/polkit-1/rules.d"
POLKIT_TARGET="$POLKIT_RULES_DIR/49-cachy-security-suite.rules"
SUDOERS_DIR="/etc/sudoers.d"
SUDOERS_TARGET="$SUDOERS_DIR/99-cachy-security-suite"

if [ "$1" = "--uninstall" ]; then
    rm -f "$POLKIT_TARGET" "$SUDOERS_TARGET" "/etc/cachy-security-suite/polkit-configured" 2>/dev/null || true
    echo "✓ Regeln erfolgreich entfernt."
    exit 0
fi

if [ -d "$POLKIT_RULES_DIR" ]; then
    cp "$DIR/resources/49-cachy-security-suite.rules" "$POLKIT_TARGET"
    chmod 644 "$POLKIT_TARGET"
    chown root:root "$POLKIT_TARGET" 2>/dev/null || true
    echo "✓ Polkit-Regel installiert."
fi
if [ -d "$SUDOERS_DIR" ]; then
    cp "$DIR/resources/cachy-security-suite.sudoers" "$SUDOERS_TARGET"
    chmod 440 "$SUDOERS_TARGET"
    chown root:root "$SUDOERS_TARGET" 2>/dev/null || true
    echo "✓ Sudoers-Drop-in installiert."
fi
mkdir -p "/etc/cachy-security-suite" 2>/dev/null || true
touch "/etc/cachy-security-suite/polkit-configured" 2>/dev/null || true
chmod 644 "/etc/cachy-security-suite/polkit-configured" 2>/dev/null || true
echo "✓ Konfiguration abgeschlossen."
"""
                with open(script_path, "w") as f:
                    f.write(script_code)
                os.chmod(script_path, 0o755)

            cmd = []
            if os.geteuid() != 0:
                if shutil.which("pkexec"):
                    cmd.append("pkexec")
                elif shutil.which("sudo"):
                    cmd.append("sudo")
            cmd.extend(["bash", script_path])
            if self.uninstall:
                cmd.append("--uninstall")

            self.output_received.emit(f">> Starte Befehl: {' '.join(cmd)}\n")

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )

            full_output = []
            if proc.stdout:
                for line in iter(proc.stdout.readline, ""):
                    full_output.append(line)
                    self.output_received.emit(line)
                proc.stdout.close()

            proc.wait()
            out_str = "".join(full_output).strip()

            if proc.returncode == 0:
                action_text = "entfernt" if self.uninstall else "eingerichtet"
                self.finished.emit(True, f"Regeln erfolgreich {action_text}.")
            elif proc.returncode in (126, 127):
                self.finished.emit(False, "Authentifizierung wurde vom Benutzer abgebrochen.")
            else:
                self.finished.emit(False, f"Fehler bei der Ausführung (Code {proc.returncode}).")

        except Exception as e:
            self.output_received.emit(f"Ausnahmefehler: {str(e)}\n")
            self.finished.emit(False, str(e))
        finally:
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)


class PolkitSetupDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Passwortlose Aktionen konfigurieren (Polkit & Sudoers)")
        self.resize(580, 480)
        self.setStyleSheet("""
            QDialog {
                background-color: #0f172a;
                color: #e2e8f0;
            }
            QLabel {
                color: #e2e8f0;
            }
        """)

        self.worker: Optional[PolkitWorker] = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(14)

        header_frame = QFrame()
        header_frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1e293b, stop:1 #0f172a);
                border: 1px solid #334155;
                border-radius: 8px;
            }
            QLabel {
                background: transparent;
                border: none;
            }
        """)
        header_layout = QHBoxLayout(header_frame)
        header_layout.setContentsMargins(12, 10, 12, 10)
        header_layout.setSpacing(14)

        icon_lbl = QLabel()
        icon_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "resources",
            "aur-scanner-64.png",
        )
        if os.path.exists(icon_path):
            icon_lbl.setPixmap(QPixmap(icon_path).scaled(40, 40, Qt.AspectRatioMode.KeepAspectRatio, Qt.TransformationMode.SmoothTransformation))
        else:
            icon_lbl.setPixmap(QIcon.fromTheme("security-high").pixmap(40, 40))
        header_layout.addWidget(icon_lbl)

        title_layout = QVBoxLayout()
        title_layout.setSpacing(2)
        title_lbl = QLabel("Passwortlose Sicherheits-Aktionen")
        title_lbl.setStyleSheet("font-size: 15px; font-weight: 700; color: #f8fafc; border: none; background: transparent;")
        desc_lbl = QLabel("Regeln für Polkit & Sudoers zur komfortablen Systemverwaltung")
        desc_lbl.setStyleSheet("font-size: 11px; color: #94a3b8; border: none; background: transparent;")
        title_layout.addWidget(title_lbl)
        title_layout.addWidget(desc_lbl)

        header_layout.addLayout(title_layout)
        header_layout.addStretch()
        layout.addWidget(header_frame)

        # Info Box
        info_box = QFrame()
        info_box.setStyleSheet("""
            QFrame {
                background-color: #1e293b;
                border-radius: 8px;
                padding: 12px;
            }
        """)
        info_layout = QVBoxLayout(info_box)
        info_layout.setContentsMargins(10, 10, 10, 10)
        info_layout.setSpacing(8)

        info_text = QLabel(
            "<b>Wozu dient diese Einrichtung?</b><br>"
            "Standardmäßig erfordern Firewall-Änderungen (UFW) und Systemd-Dienste (ClamAV Freshclam) "
            "bei jeder Aktion eine Administrator-Authentifizierung.<br><br>"
            "Durch die Konfiguration werden dedizierte Regeln angelegt:<br>"
            "• <code>/etc/polkit-1/rules.d/49-cachy-security-suite.rules</code><br>"
            "• <code>/etc/sudoers.d/99-cachy-security-suite</code><br><br>"
            "<b>Freigegebene Aktionen für Mitglieder der Gruppe <i>wheel</i>:</b><br>"
            "✓ UFW Firewall aktivieren, deaktivieren & Regeln verwalten<br>"
            "✓ ClamAV Freshclam Hintergrunddienst starten, stoppen & schalten<br>"
            "✓ Freshclam Virensignaturen manuell herunterladen"
        )
        info_text.setTextFormat(Qt.TextFormat.RichText)
        info_text.setWordWrap(True)
        info_text.setStyleSheet("font-size: 11px; line-height: 1.4; color: #cbd5e1;")
        info_layout.addWidget(info_text)
        layout.addWidget(info_box)

        # Progress / Log view
        self.log_view = QTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(QFont("JetBrains Mono, monospace", 9))
        self.log_view.setStyleSheet("""
            QTextEdit {
                background-color: #020617;
                color: #38bdf8;
                border: 1px solid #1e293b;
                border-radius: 6px;
                padding: 6px;
            }
        """)
        self.log_view.setPlaceholderText("Ausgabe der Berechtigungseinrichtung erscheint hier...")
        self.log_view.setMaximumHeight(90)
        layout.addWidget(self.log_view)

        # Progress Bar (indeterminate when running)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setFixedHeight(4)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                background-color: #1e293b;
                border: none;
                border-radius: 2px;
            }
            QProgressBar::chunk {
                background-color: #38bdf8;
                border-radius: 2px;
            }
        """)
        self.progress_bar.hide()
        layout.addWidget(self.progress_bar)

        # Action Buttons Layout
        btn_layout = QHBoxLayout()
        btn_layout.setSpacing(10)

        self.btn_uninstall = QPushButton("Regeln entfernen")
        self.btn_uninstall.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_uninstall.setStyleSheet("""
            QPushButton {
                background-color: #334155;
                color: #f1f5f9;
                font-size: 11px;
                font-weight: 600;
                padding: 7px 14px;
                border-radius: 6px;
                border: 1px solid #475569;
            }
            QPushButton:hover {
                background-color: #dc2626;
                border-color: #ef4444;
            }
            QPushButton:disabled {
                background-color: #1e293b;
                color: #64748b;
                border-color: #334155;
            }
        """)
        self.btn_uninstall.clicked.connect(self._on_uninstall_clicked)
        btn_layout.addWidget(self.btn_uninstall)

        btn_layout.addStretch()

        self.btn_close = QPushButton("Schließen")
        self.btn_close.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_close.setStyleSheet("""
            QPushButton {
                background-color: #1e293b;
                color: #94a3b8;
                font-size: 11px;
                padding: 7px 14px;
                border-radius: 6px;
                border: 1px solid #334155;
            }
            QPushButton:hover {
                background-color: #334155;
                color: #ffffff;
            }
        """)
        self.btn_close.clicked.connect(self.close)
        btn_layout.addWidget(self.btn_close)

        self.btn_install = QPushButton("Jetzt einrichten")
        self.btn_install.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_install.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #16a34a, stop:1 #15803d);
                color: #ffffff;
                font-size: 11px;
                font-weight: 700;
                padding: 7px 16px;
                border-radius: 6px;
                border: 1px solid #22c55e;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #22c55e, stop:1 #16a34a);
            }
            QPushButton:disabled {
                background-color: #1e293b;
                color: #64748b;
                border-color: #334155;
            }
        """)
        self.btn_install.clicked.connect(self._on_install_clicked)
        btn_layout.addWidget(self.btn_install)

        layout.addLayout(btn_layout)

    def _set_busy(self, busy: bool):
        self.btn_install.setEnabled(not busy)
        self.btn_uninstall.setEnabled(not busy)
        self.btn_close.setEnabled(not busy)
        if busy:
            self.progress_bar.show()
        else:
            self.progress_bar.hide()

    def _on_install_clicked(self):
        reply = QMessageBox.question(
            self,
            "Polkit-Regeln einrichten",
            "Möchtest du die Regeln für passwortlose Firewall- und ClamAV-Aktionen jetzt einrichten?\n\n"
            "Hierfür ist einmalig dein Administrator-Passwort erforderlich.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.Yes,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        self._start_task(uninstall=False)

    def _on_uninstall_clicked(self):
        reply = QMessageBox.question(
            self,
            "Regeln entfernen",
            "Möchtest du die eingerichteten Polkit- und Sudoers-Berechtigungen entfernen?\n\n"
            "Anschließend erfordern administrative Aktionen wieder die reguläre Passworteingabe.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        self._start_task(uninstall=True)

    def _start_task(self, uninstall: bool):
        self._set_busy(True)
        self.log_view.clear()
        self.worker = PolkitWorker(uninstall=uninstall)
        self.worker.output_received.connect(self._on_output)
        self.worker.finished.connect(self._on_finished)
        self.worker.start()

    def _on_output(self, text: str):
        self.log_view.insertPlainText(text)
        self.log_view.ensureCursorVisible()

    def _on_finished(self, success: bool, message: str):
        self._set_busy(False)
        if success:
            QMessageBox.information(self, "Erfolg", message)
        else:
            QMessageBox.warning(self, "Hinweis", message)
