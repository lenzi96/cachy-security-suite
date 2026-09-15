"""
Antivirus and malware scanner view (ClamAV & Threat-Intel Hash Audit).
"""
import hashlib
import os
import shutil
import subprocess
import webbrowser
from typing import List, Optional

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QIcon, QTextCharFormat, QTextCursor
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
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from aur_scanner_gui.widgets.status_card import StatusCard


class ClamScanWorker(QThread):
    output_line = pyqtSignal(str)
    file_scanned = pyqtSignal(str, str, str)  # file, status, virus_name
    finished = pyqtSignal(int, int, str)      # infected_count, total_scanned, summary

    def __init__(self, target_path: str, infected_only: bool = True):
        super().__init__()
        self.target_path = target_path
        self.infected_only = infected_only
        self.process: Optional[subprocess.Popen] = None
        self._is_cancelled = False

    def cancel(self):
        self._is_cancelled = True
        if self.process and self.process.poll() is None:
            try:
                self.process.terminate()
            except Exception:
                pass

    def run(self):
        infected_count = 0
        total_scanned = 0
        summary_lines = []

        cmd = ["clamscan", "-r"]
        if self.infected_only:
            cmd.append("-i")
        cmd.append(self.target_path)

        try:
            self.process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
            )

            is_summary = False
            for line in iter(self.process.stdout.readline, ""):
                if self._is_cancelled:
                    break
                clean_line = line.rstrip()
                self.output_line.emit(clean_line)

                if "----------- SCAN SUMMARY -----------" in clean_line:
                    is_summary = True

                if is_summary:
                    summary_lines.append(clean_line)
                    if "Infected files:" in clean_line:
                        parts = clean_line.split(":")
                        if len(parts) > 1:
                            try:
                                infected_count = int(parts[1].strip())
                            except ValueError:
                                pass
                    elif "Scanned files:" in clean_line:
                        parts = clean_line.split(":")
                        if len(parts) > 1:
                            try:
                                total_scanned = int(parts[1].strip())
                            except ValueError:
                                pass
                else:
                    # Parse infected lines: "/path/to/file: Virus.Name FOUND"
                    if " FOUND" in clean_line:
                        parts = clean_line.split(":")
                        if len(parts) >= 2:
                            fpath = parts[0].strip()
                            vname = parts[1].replace("FOUND", "").strip()
                            self.file_scanned.emit(fpath, "INFECTED", vname)
                    elif " OK" in clean_line:
                        fpath = clean_line.replace(": OK", "").strip()
                        self.file_scanned.emit(fpath, "OK", "")

            self.process.wait()
            self.finished.emit(infected_count, total_scanned, "\n".join(summary_lines))
        except Exception as exc:
            self.output_line.emit(f"Fehler bei Ausführung: {exc}")
            self.finished.emit(-1, 0, str(exc))


def has_clam_db() -> bool:
    for path in ["/var/lib/clamav", os.path.expanduser("~/.cache/clamav")]:
        if os.path.isdir(path):
            try:
                for f in os.listdir(path):
                    if f.endswith((".cvd", ".cld")):
                        return True
            except Exception:
                pass
    return False


class FreshClamWorker(QThread):
    output_line = pyqtSignal(str)
    finished = pyqtSignal(bool, str)

    def run(self):
        try:
            cmd = ["freshclam"]
            # Under Arch Linux / CachyOS, updating /var/lib/clamav requires root privileges
            if os.geteuid() != 0 and shutil.which("pkexec"):
                cmd = ["pkexec", "freshclam"]

            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                universal_newlines=True,
            )
            lines = []
            for line in iter(proc.stdout.readline, ""):
                c = line.rstrip()
                lines.append(c)
                self.output_line.emit(c)
            proc.wait()
            self.finished.emit(proc.returncode == 0, "\n".join(lines))
        except Exception as exc:
            self.output_line.emit(f"Fehler: {exc}")
            self.finished.emit(False, str(exc))


class AntivirusView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scan_worker: Optional[ClamScanWorker] = None
        self.freshclam_worker: Optional[FreshClamWorker] = None
        self.current_sha256 = ""
        self.init_ui()

    def init_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(12)

        # 1. Header
        header_layout = QVBoxLayout()
        header_layout.setSpacing(3)
        lbl_title = QLabel("Integrierter Virenscanner & Malware-Schutz")
        lbl_title.setStyleSheet("font-size: 18px; font-weight: 700; color: palette(text);")
        lbl_desc = QLabel("Scanne Binärdateien, Quellcode-Archive und Downloads mit ClamAV und Threat-Intelligence (VirusTotal).")
        lbl_desc.setStyleSheet("font-size: 12px; color: palette(text); opacity: 0.7;")
        header_layout.addWidget(lbl_title)
        header_layout.addWidget(lbl_desc)
        layout.addLayout(header_layout)

        # 2. Engine Status Banner
        has_clam = shutil.which("clamscan") is not None
        self.engine_card = QFrame()
        self.engine_card.setObjectName("engineCard")
        border_color = "#10b981" if has_clam else "#ea580c"
        self.engine_card.setStyleSheet(f"""
            QFrame#engineCard {{
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #172033, stop:1 #0e1626);
                border: 1px solid #293548;
                border-left: 4px solid {border_color};
                border-radius: 10px;
                padding: 4px;
            }}
            QFrame#engineCard QLabel {{
                background: transparent;
                border: none;
            }}
        """)
        e_layout = QHBoxLayout(self.engine_card)
        e_layout.setContentsMargins(14, 10, 14, 10)
        e_layout.setSpacing(12)

        self.icon_engine = QLabel("🛡️")
        self.icon_engine.setStyleSheet("font-size: 20px;")
        e_layout.addWidget(self.icon_engine)

        self.lbl_engine_info = QLabel("")
        self.lbl_engine_info.setWordWrap(True)
        e_layout.addWidget(self.lbl_engine_info, stretch=1)

        self.btn_update_sigs = QPushButton("Signaturen aktualisieren (freshclam)")
        self.btn_update_sigs.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_update_sigs.setStyleSheet("""
            QPushButton {
                padding: 6px 14px;
                border-radius: 6px;
                border: 1px solid #334155;
                background: rgba(255, 255, 255, 0.05);
                color: #f1f5f9;
                font-size: 11px;
                font-weight: 600;
            }
            QPushButton:hover { background: #2563eb; color: #ffffff; border-color: #3b82f6; }
        """)
        self.btn_update_sigs.clicked.connect(self.run_freshclam)
        e_layout.addWidget(self.btn_update_sigs)

        self.refresh_engine_status()
        layout.addWidget(self.engine_card)

        # 3. Target Selection Card
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
        s_layout = QHBoxLayout(sel_card)
        s_layout.setContentsMargins(12, 10, 12, 10)
        s_layout.setSpacing(10)

        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("Datei oder Verzeichnis für Virenprüfung auswählen...")
        self.path_input.setStyleSheet("""
            QLineEdit {
                border: 1px solid #334155;
                border-radius: 7px;
                padding: 7px 12px;
                font-size: 12px;
                color: #f8fafc;
                background-color: #090d16;
            }
            QLineEdit:focus { border: 1px solid #3b82f6; }
        """)
        self.path_input.returnPressed.connect(self.start_scan)

        btn_file = QPushButton("Datei...")
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
            QPushButton:hover { background: rgba(255, 255, 255, 0.1); border-color: #475569; }
        """)
        btn_file.clicked.connect(self.browse_file)

        btn_dir = QPushButton("Ordner...")
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
            QPushButton:hover { background: rgba(255, 255, 255, 0.1); border-color: #475569; }
        """)
        btn_dir.clicked.connect(self.browse_directory)

        self.scan_mode_combo = QComboBox()
        self.scan_mode_combo.addItem("ClamAV Viren-Scan", "clamav")
        self.scan_mode_combo.addItem("SHA-256 & Hash-Audit", "hash")
        self.scan_mode_combo.setStyleSheet("""
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

        self.btn_scan = QPushButton("  Scan starten")
        self.btn_scan.setIcon(QIcon.fromTheme("security-high"))
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
            QPushButton:hover { background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1d4ed8, stop:1 #2563eb); }
            QPushButton:disabled { background: #334155; color: #64748b; }
        """)
        self.btn_scan.clicked.connect(self.start_scan)

        self.btn_stop = QPushButton("Abbrechen")
        self.btn_stop.setIcon(QIcon.fromTheme("process-stop"))
        self.btn_stop.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_stop.setEnabled(False)
        self.btn_stop.setStyleSheet("""
            QPushButton {
                padding: 8px 16px;
                border-radius: 7px;
                border: 1px solid #334155;
                background: rgba(255, 255, 255, 0.05);
                color: #94a3b8;
                font-size: 12px;
                font-weight: 600;
            }
            QPushButton:hover:enabled { background: #ef4444; color: #ffffff; border-color: #dc2626; }
            QPushButton:disabled { opacity: 0.4; }
        """)
        self.btn_stop.clicked.connect(self.stop_scan)

        s_layout.addWidget(self.path_input, stretch=3)
        s_layout.addWidget(btn_file)
        s_layout.addWidget(btn_dir)
        s_layout.addWidget(self.scan_mode_combo)
        s_layout.addWidget(self.btn_scan)
        s_layout.addWidget(self.btn_stop)

        layout.addWidget(sel_card)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 0)
        self.progress_bar.setFixedHeight(4)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar { border: none; background: transparent; }
            QProgressBar::chunk { background-color: #3b82f6; border-radius: 2px; }
        """)
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        # 4. Metric Cards
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(10)
        self.card_status = StatusCard("Status", 0, "#10b981")
        self.card_status.set_text("Bereit", "#10b981")

        self.card_infected = StatusCard("Infizierte Dateien", 0, "#ef4444")
        self.card_scanned = StatusCard("Geprüfte Dateien", 0, "#3b82f6")

        cards_layout.addWidget(self.card_status)
        cards_layout.addWidget(self.card_infected)
        cards_layout.addWidget(self.card_scanned)
        layout.addLayout(cards_layout)

        # 5. Splitter: Results Table (Top) + Details / Hash Inspector (Bottom)
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.setHandleWidth(8)

        # Results Table Card
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

        self.table = QTableWidget()
        self.table.setColumnCount(3)
        self.table.setHorizontalHeaderLabels(["Ergebnis", "Schadsoftware / Signatur", "Dateipfad"])
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
            QTableWidget::item { padding: 6px 8px; border-bottom: 1px solid palette(mid); }
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
        self.table.verticalHeader().setDefaultSectionSize(34)
        self.table.verticalHeader().setVisible(False)
        t_layout.addWidget(self.table)
        splitter.addWidget(table_card)

        # Bottom Detail / Log Card
        bottom_card = QFrame()
        bottom_card.setObjectName("bottomCard")
        bottom_card.setStyleSheet("""
            QFrame#bottomCard {
                background-color: palette(base);
                border: 1px solid palette(mid);
                border-radius: 10px;
            }
        """)
        b_layout = QVBoxLayout(bottom_card)
        b_layout.setContentsMargins(10, 10, 10, 10)
        b_layout.setSpacing(8)

        # Hash / VirusTotal Action Bar
        hash_bar = QHBoxLayout()
        self.lbl_hash_info = QLabel("SHA-256: -")
        self.lbl_hash_info.setFont(QFont("JetBrains Mono, monospace", 10))
        self.lbl_hash_info.setStyleSheet("color: palette(text);")

        self.btn_vt = QPushButton("Auf VirusTotal prüfen ↗")
        self.btn_vt.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_vt.setEnabled(False)
        self.btn_vt.setStyleSheet("""
            QPushButton {
                padding: 5px 12px;
                border-radius: 6px;
                border: 1px solid palette(mid);
                background: palette(window);
                font-size: 11px;
                font-weight: 500;
            }
            QPushButton:hover { background: #3b82f6; color: white; border-color: #2563eb; }
        """)
        self.btn_vt.clicked.connect(self.open_virustotal)

        hash_bar.addWidget(self.lbl_hash_info, stretch=1)
        hash_bar.addWidget(self.btn_vt)
        b_layout.addLayout(hash_bar)

        self.txt_log = QTextEdit()
        self.txt_log.setReadOnly(True)
        self.txt_log.setFont(QFont("JetBrains Mono, monospace", 9))
        self.txt_log.setStyleSheet("""
            QTextEdit {
                background-color: palette(window);
                color: palette(text);
                border: 1px solid palette(mid);
                border-radius: 6px;
                padding: 8px;
            }
        """)
        b_layout.addWidget(self.txt_log)
        splitter.addWidget(bottom_card)

        splitter.setSizes([260, 200])
        layout.addWidget(splitter, stretch=1)

    def refresh_engine_status(self):
        has_clam = shutil.which("clamscan") is not None
        has_fresh = shutil.which("freshclam") is not None
        db_ready = has_clam_db()

        self.btn_update_sigs.setEnabled(has_fresh)

        if has_clam and db_ready:
            self.icon_engine.setText("🛡️")
            self.lbl_engine_info.setText(
                "<b>ClamAV Antivirus-Engine aktiv:</b> Signaturen geladen (/var/lib/clamav). Vollständiger Viren-Scan einsatzbereit."
            )
            self.lbl_engine_info.setStyleSheet("font-size: 12px; color: #065f46;")
            self.engine_card.setStyleSheet("""
                QFrame#engineCard {
                    background-color: rgba(16, 185, 129, 0.1);
                    border: 1px solid #10b981;
                    border-radius: 8px;
                    padding: 4px;
                }
                QFrame#engineCard QLabel {
                    background: transparent;
                    border: none;
                }
            """)
        elif has_clam and not db_ready:
            self.icon_engine.setText("⚠️")
            self.lbl_engine_info.setText(
                "<b>ClamAV installiert, aber Virendatenbank noch nicht initialisiert:</b> "
                "Führe im Terminal <code>sudo freshclam</code> aus oder klicke rechts auf 'Signaturen aktualisieren'."
            )
            self.lbl_engine_info.setStyleSheet("font-size: 12px; color: #9a3412;")
            self.engine_card.setStyleSheet("""
                QFrame#engineCard {
                    background-color: rgba(245, 158, 11, 0.12);
                    border: 1px solid #f59e0b;
                    border-radius: 8px;
                    padding: 4px;
                }
                QFrame#engineCard QLabel {
                    background: transparent;
                    border: none;
                }
            """)
        else:
            self.icon_engine.setText("ℹ️")
            self.lbl_engine_info.setText(
                "<b>ClamAV nicht installiert:</b> Für erweiterte Viren-Scans installiere ClamAV mit "
                "<code>sudo pacman -S clamav</code>. Integrierter SHA-256 Threat-Audit ist aktiv."
            )
            self.lbl_engine_info.setStyleSheet("font-size: 12px; color: #9a3412;")
            self.engine_card.setStyleSheet("""
                QFrame#engineCard {
                    background-color: rgba(234, 88, 12, 0.1);
                    border: 1px solid #ea580c;
                    border-radius: 8px;
                    padding: 4px;
                }
                QFrame#engineCard QLabel {
                    background: transparent;
                    border: none;
                }
            """)

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Datei für Virenprüfung auswählen",
            os.path.expanduser("~"),
            "Alle Dateien (*)",
        )
        if file_path:
            self.path_input.setText(file_path)
            self.start_scan()

    def browse_directory(self):
        dir_path = QFileDialog.getExistingDirectory(
            self,
            "Verzeichnis für Virenprüfung auswählen",
            os.path.expanduser("~"),
        )
        if dir_path:
            self.path_input.setText(dir_path)
            self.start_scan()

    def start_scan(self):
        target = self.path_input.text().strip()
        if not target:
            QMessageBox.warning(self, "Hinweis", "Bitte wähle eine Datei oder einen Ordner aus.")
            return

        if not os.path.exists(target):
            QMessageBox.critical(self, "Fehler", f"Pfad nicht gefunden:\n{target}")
            return

        mode = self.scan_mode_combo.currentData()
        self.table.setRowCount(0)
        self.txt_log.clear()
        self.card_infected.set_value(0)
        self.card_scanned.set_value(0)

        # Calculate SHA256 if file
        if os.path.isfile(target):
            try:
                hasher = hashlib.sha256()
                with open(target, "rb") as f:
                    while chunk := f.read(65536):
                        hasher.update(chunk)
                self.current_sha256 = hasher.hexdigest()
                self.lbl_hash_info.setText(f"SHA-256: {self.current_sha256}")
                self.btn_vt.setEnabled(True)
            except Exception as e:
                self.lbl_hash_info.setText(f"SHA-256 Fehler: {e}")
                self.btn_vt.setEnabled(False)
        else:
            self.current_sha256 = ""
            self.lbl_hash_info.setText("SHA-256: (Verzeichnis)")
            self.btn_vt.setEnabled(False)

        if mode == "hash":
            self.perform_hash_audit(target)
            return

        # ClamAV Scan
        if not shutil.which("clamscan"):
            self.append_log(
                "[HINWEIS] 'clamscan' (ClamAV) ist auf diesem System nicht installiert.\n"
                "          Installationsbefehl: sudo pacman -S clamav\n"
                "          Führe stattdessen SHA-256 Integritätsprüfung & VirusTotal-Audit durch...\n"
            )
            self.card_status.set_text("ClamAV fehlt (Fallback: SHA-256)", "#f59e0b")
            self.perform_hash_audit(target)
            return

        if not has_clam_db():
            self.append_log(
                "[HINWEIS] ClamAV ist installiert, aber die Virendatenbank ist noch nicht initialisiert.\n"
                "          Bitte führe einmalig im Terminal aus: sudo freshclam\n"
                "          (Oder aktiviere: sudo systemctl enable --now clamav-freshclam.service)\n"
                "          Führe stattdessen SHA-256 Integritätsprüfung & VirusTotal-Audit durch...\n"
            )
            self.card_status.set_text("DB fehlt (Fallback: SHA-256)", "#f59e0b")
            self.perform_hash_audit(target)
            return

        self.btn_scan.setEnabled(False)
        self.btn_stop.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.card_status.set_text("Scan läuft...", "#3b82f6")

        self.scan_worker = ClamScanWorker(target, infected_only=False)
        self.scan_worker.output_line.connect(self.on_log_line)
        self.scan_worker.file_scanned.connect(self.on_file_scanned)
        self.scan_worker.finished.connect(self.on_scan_finished)
        self.scan_worker.start()

    def append_log(self, text: str):
        self.txt_log.append(text)
        cursor = self.txt_log.textCursor()
        self.txt_log.setTextCursor(cursor)
        self.txt_log.ensureCursorVisible()

    def perform_hash_audit(self, target: str):
        self.card_status.set_text("Hash berechnet", "#10b981")
        if os.path.isfile(target):
            self.card_scanned.set_value(1)
            row = self.table.rowCount()
            self.table.insertRow(row)

            item_res = QTableWidgetItem("✓ Berechnet")
            item_res.setForeground(QColor("#10b981"))
            item_sig = QTableWidgetItem(f"SHA256: {self.current_sha256[:16]}...")
            item_path = QTableWidgetItem(target)

            self.table.setItem(row, 0, item_res)
            self.table.setItem(row, 1, item_sig)
            self.table.setItem(row, 2, item_path)

            self.txt_log.append(f"Datei: {target}")
            self.txt_log.append(f"Größe: {os.path.getsize(target)} Bytes")
            self.txt_log.append(f"SHA-256: {self.current_sha256}")
            self.txt_log.append("\nKlicke oben rechts auf 'Auf VirusTotal prüfen ↗', um den Hash live abzugleichen.")

    def stop_scan(self):
        if self.scan_worker:
            self.scan_worker.cancel()
            self.btn_scan.setEnabled(True)
            self.btn_stop.setEnabled(False)
            self.progress_bar.setVisible(False)
            self.card_status.set_text("Abgebrochen", "#ea580c")

    def on_log_line(self, line: str):
        cursor = self.txt_log.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.End)
        fmt = QTextCharFormat()

        if "FOUND" in line or "Infected files: [1-9]" in line:
            fmt.setForeground(QColor("#ef4444"))
            fmt.setFontWeight(QFont.Weight.Bold)
        elif "OK" in line:
            fmt.setForeground(QColor("#10b981"))
        else:
            fmt.setForeground(QColor(self.palette().text().color()))

        cursor.insertText(line + "\n", fmt)
        self.txt_log.setTextCursor(cursor)
        self.txt_log.ensureCursorVisible()

    def on_file_scanned(self, fpath: str, status: str, vname: str):
        row = self.table.rowCount()
        self.table.insertRow(row)

        if status == "INFECTED":
            item_status = QTableWidgetItem("⚠ INFIZIERT")
            item_status.setForeground(QColor("#ef4444"))
            item_status.setFont(QFont("sans-serif", 10, QFont.Weight.Bold))
        else:
            item_status = QTableWidgetItem("✓ Sauber")
            item_status.setForeground(QColor("#10b981"))

        item_name = QTableWidgetItem(vname if vname else "-")
        item_path = QTableWidgetItem(fpath)

        self.table.setItem(row, 0, item_status)
        self.table.setItem(row, 1, item_name)
        self.table.setItem(row, 2, item_path)

    def on_scan_finished(self, infected_count: int, total_scanned: int, summary: str):
        self.btn_scan.setEnabled(True)
        self.btn_stop.setEnabled(False)
        self.progress_bar.setVisible(False)

        self.card_scanned.set_value(total_scanned)
        self.card_infected.set_value(max(0, infected_count))

        if infected_count > 0:
            self.card_status.set_text("BEDROHUNG", "#ef4444")
            QMessageBox.critical(
                self,
                "Virenfund!",
                f"Achtung! ClamAV hat {infected_count} infizierte Datei(en) festgestellt!",
            )
        elif infected_count == 0:
            self.card_status.set_text("SAUBER", "#10b981")
        else:
            self.card_status.set_text("FEHLER", "#ea580c")

    def run_freshclam(self):
        self.btn_update_sigs.setEnabled(False)
        self.progress_bar.setVisible(True)
        self.txt_log.append("\n=== Aktualisiere ClamAV Virensignaturen (freshclam) ===")

        self.freshclam_worker = FreshClamWorker()
        self.freshclam_worker.output_line.connect(self.on_log_line)
        self.freshclam_worker.finished.connect(self.on_freshclam_finished)
        self.freshclam_worker.start()

    def on_freshclam_finished(self, success: bool, output: str):
        self.btn_update_sigs.setEnabled(True)
        self.progress_bar.setVisible(False)
        self.refresh_engine_status()
        if success:
            self.txt_log.append("✓ Signatur-Update erfolgreich abgeschlossen!\n")
            QMessageBox.information(
                self,
                "Signaturen aktualisiert",
                "Die ClamAV Virensignaturen wurden erfolgreich heruntergeladen und aktualisiert.",
            )
        else:
            self.txt_log.append(
                "\n[!] Hinweis zum Berechtigungsproblem:\n"
                "    Das ClamAV-Signaturverzeichnis (/var/lib/clamav) gehört dem System-Benutzer 'clamav'.\n"
                "    Führe im Terminal folgenden Befehl aus:\n"
                "        sudo freshclam\n\n"
                "    Empfohlen (Dauerhaften Hintergrunddienst aktivieren):\n"
                "        sudo systemctl enable --now clamav-freshclam.service\n"
            )
            dlg = QMessageBox(self)
            dlg.setIcon(QMessageBox.Icon.Warning)
            dlg.setWindowTitle("Root-Rechte für ClamAV-Update erforderlich")
            dlg.setText(
                "<h3>ClamAV Signatur-Update</h3>"
                "<p>Das Signaturverzeichnis <code>/var/lib/clamav</code> und das Log <code>/var/log/clamav/</code> "
                "sind geschützte Systemverzeichnisse und erfordern Root-Rechte zur Aktualisierung.</p>"
                "<p><b>Einmaliges Update im Terminal:</b><br>"
                "<code>sudo freshclam</code></p>"
                "<p><b>Empfohlen (Automatischer systemd-Dienst):</b><br>"
                "<code>sudo systemctl enable --now clamav-freshclam.service</code><br>"
                "<small>Hält die Signaturen künftig vollautomatisch im Hintergrund aktuell.</small></p>"
            )
            btn_copy = dlg.addButton("Befehle kopieren", QMessageBox.ButtonRole.ActionRole)
            dlg.addButton(QMessageBox.StandardButton.Ok)
            dlg.exec()
            if dlg.clickedButton() == btn_copy:
                clipboard = QApplication.clipboard()
                clipboard.setText("sudo freshclam && sudo systemctl enable --now clamav-freshclam.service")
                self.txt_log.append("✓ Befehl in die Zwischenablage kopiert!\n")

    def open_virustotal(self):
        if self.current_sha256:
            url = f"https://www.virustotal.com/gui/file/{self.current_sha256}"
            webbrowser.open(url)
