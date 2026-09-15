"""
Firewall management view for Cachy Security Suite.
Provides real-time packet filter status, quick security profiles, rule management,
rule creation dialog with service templates, and live block logging.
"""

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QFont, QIcon
from PyQt6.QtWidgets import (
    QComboBox,
    QDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from aur_scanner_gui.firewall_service import FirewallRule, FirewallService, FirewallStatus
from aur_scanner_gui.widgets.status_card import StatusCard


class AddRuleDialog(QDialog):
    """Modern modal dialog to create or configure firewall rules."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Firewall-Regel hinzufügen")
        self.resize(520, 480)
        self.setStyleSheet("""
            QDialog {
                background-color: #0f172a;
                color: #f8fafc;
            }
            QLabel {
                color: #cbd5e1;
                font-size: 12px;
                font-weight: 500;
            }
            QLineEdit, QComboBox {
                background-color: #1e293b;
                border: 1px solid #334155;
                border-radius: 6px;
                padding: 8px 12px;
                color: #f8fafc;
                font-size: 13px;
            }
            QLineEdit:focus, QComboBox:focus {
                border-color: #38bdf8;
            }
            QComboBox::drop-down {
                border: none;
                padding-right: 8px;
            }
        """)

        layout = QVBoxLayout(self)
        layout.setSpacing(14)
        layout.setContentsMargins(24, 20, 24, 20)

        # Header
        title = QLabel("Neue Firewall-Regel definieren")
        title.setStyleSheet("font-size: 16px; font-weight: 700; color: #f8fafc;")
        layout.addWidget(title)

        desc = QLabel("Wähle eine Vorlage oder gib eigene Port- und Verbindungsparameter an.")
        desc.setStyleSheet("color: #94a3b8; font-size: 12px;")
        layout.addWidget(desc)

        # Template Selection
        layout.addWidget(QLabel("Dienst-Vorlage:"))
        self.combo_template = QComboBox()
        self.combo_template.addItem("Benutzerdefinierte Regel (Manuell)", {})
        self.templates = FirewallService.get_app_profiles()
        for t in self.templates:
            self.combo_template.addItem(f"{t['title']} (Port {t['port']})", t)
        self.combo_template.currentIndexChanged.connect(self.on_template_changed)
        layout.addWidget(self.combo_template)

        # Port / Port range
        layout.addWidget(QLabel("Port oder Portbereich (z. B. 22 oder 1714:1764):"))
        self.input_port = QLineEdit()
        self.input_port.setPlaceholderText("z. B. 80, 443, 8080:8090 oder leer für alle")
        layout.addWidget(self.input_port)

        # Proto & Direction in horizontal layout
        h_layout1 = QHBoxLayout()
        v_proto = QVBoxLayout()
        v_proto.addWidget(QLabel("Protokoll:"))
        self.combo_proto = QComboBox()
        self.combo_proto.addItems(["ANY (TCP & UDP)", "TCP", "UDP"])
        v_proto.addWidget(self.combo_proto)
        h_layout1.addLayout(v_proto)

        v_dir = QVBoxLayout()
        v_dir.addWidget(QLabel("Richtung:"))
        self.combo_direction = QComboBox()
        self.combo_direction.addItems(["Eingehend (In)", "Ausgehend (Out)"])
        v_dir.addWidget(self.combo_direction)
        h_layout1.addLayout(v_dir)
        layout.addLayout(h_layout1)

        # Action & Source IP in horizontal layout
        h_layout2 = QHBoxLayout()
        v_act = QVBoxLayout()
        v_act.addWidget(QLabel("Aktion:"))
        self.combo_action = QComboBox()
        self.combo_action.addItems(["ALLOW (Erlauben)", "DENY (Blockieren / Verwerfen)", "REJECT (Ablehnen)", "LIMIT (Drosseln / Brute-Force-Schutz)"])
        v_act.addWidget(self.combo_action)
        h_layout2.addLayout(v_act)

        v_src = QVBoxLayout()
        v_src.addWidget(QLabel("Quell-IP / Subnetz (optional):"))
        self.input_src = QLineEdit()
        self.input_src.setPlaceholderText("Alle IPs (0.0.0.0/0)")
        v_src.addWidget(self.input_src)
        h_layout2.addLayout(v_src)
        layout.addLayout(h_layout2)

        # Comment
        layout.addWidget(QLabel("Beschreibung / Kommentar:"))
        self.input_comment = QLineEdit()
        self.input_comment.setPlaceholderText("z. B. Web-Entwicklungsserver")
        layout.addWidget(self.input_comment)

        layout.addStretch()

        # Dialog Buttons
        btn_layout = QHBoxLayout()
        btn_layout.addStretch()

        self.btn_cancel = QPushButton("Abbrechen")
        self.btn_cancel.setStyleSheet("""
            QPushButton {
                background-color: #1e293b;
                color: #cbd5e1;
                border: 1px solid #334155;
                padding: 8px 18px;
                border-radius: 6px;
                font-weight: 500;
            }
            QPushButton:hover { background-color: #334155; color: #ffffff; }
        """)
        self.btn_cancel.clicked.connect(self.reject)
        btn_layout.addWidget(self.btn_cancel)

        self.btn_save = QPushButton("Regel anwenden (Polkit)")
        self.btn_save.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #059669, stop:1 #10b981);
                color: #ffffff;
                border: none;
                padding: 8px 20px;
                border-radius: 6px;
                font-weight: 600;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #047857, stop:1 #059669);
            }
        """)
        self.btn_save.clicked.connect(self.on_apply)
        btn_layout.addWidget(self.btn_save)

        layout.addLayout(btn_layout)

    def on_template_changed(self, idx: int):
        data = self.combo_template.currentData()
        if data and isinstance(data, dict) and "port" in data:
            self.input_port.setText(data["port"])
            proto = data.get("proto", "ANY")
            if proto == "TCP":
                self.combo_proto.setCurrentIndex(1)
            elif proto == "UDP":
                self.combo_proto.setCurrentIndex(2)
            else:
                self.combo_proto.setCurrentIndex(0)
            self.input_comment.setText(data.get("title", ""))

    def on_apply(self):
        port = self.input_port.text().strip()
        proto_text = self.combo_proto.currentText()
        proto = "any"
        if "TCP" in proto_text:
            proto = "tcp"
        elif "UDP" in proto_text:
            proto = "udp"

        direction_text = self.combo_direction.currentText()
        direction = "in" if "Eingehend" in direction_text else "out"

        action_text = self.combo_action.currentText()
        action = "allow"
        if "DENY" in action_text:
            action = "deny"
        elif "REJECT" in action_text:
            action = "reject"
        elif "LIMIT" in action_text:
            action = "limit"

        src_ip = self.input_src.text().strip() or "any"
        comment = self.input_comment.text().strip()

        ok, msg = FirewallService.add_rule(
            action=action,
            direction=direction,
            proto=proto,
            port=port,
            src_ip=src_ip,
            comment=comment,
        )

        if ok:
            QMessageBox.information(self, "Erfolg", f"Firewall-Regel erfolgreich hinzugefügt:\n{msg}")
            self.accept()
        else:
            QMessageBox.critical(self, "Fehler", f"Regel konnte nicht erstellt werden:\n{msg}")


class FirewallView(QWidget):
    """Main view for Firewall & Network Protection."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.cached_status: FirewallStatus = FirewallStatus()
        self.cached_rules: list = []

        self.setup_ui()
        self.refresh_all()

    def setup_ui(self):
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(24, 24, 24, 24)
        root_layout.setSpacing(16)

        # 1. Header
        header_layout = QVBoxLayout()
        header_layout.setSpacing(4)
        lbl_title = QLabel("Firewall- & Netzwerkschutz")
        lbl_title.setStyleSheet("font-size: 20px; font-weight: 700; color: #f8fafc;")
        header_layout.addWidget(lbl_title)

        lbl_sub = QLabel("Zentrale Steuerung des Paketfilters (UFW / Netfilter), Port-Regeln und Netzwerkprofile.")
        lbl_sub.setStyleSheet("font-size: 13px; color: #94a3b8;")
        header_layout.addWidget(lbl_sub)
        root_layout.addLayout(header_layout)

        # 2. Status Banner Frame
        self.banner_card = QFrame()
        self.banner_card.setObjectName("fwBanner")
        self.banner_layout = QHBoxLayout(self.banner_card)
        self.banner_layout.setContentsMargins(18, 14, 18, 14)
        self.banner_layout.setSpacing(16)

        # Left status text
        v_banner_left = QVBoxLayout()
        v_banner_left.setSpacing(4)
        self.lbl_banner_status = QLabel("Ermittle Firewall-Status...")
        self.lbl_banner_status.setStyleSheet("font-size: 15px; font-weight: 700; color: #f8fafc;")
        v_banner_left.addWidget(self.lbl_banner_status)

        self.lbl_banner_details = QLabel("Lade Richtlinien und Paketfilter-Konfiguration...")
        self.lbl_banner_details.setStyleSheet("font-size: 12px; color: #94a3b8;")
        v_banner_left.addWidget(self.lbl_banner_details)
        self.banner_layout.addLayout(v_banner_left, stretch=1)

        # Right Action Buttons
        self.btn_toggle_fw = QPushButton("Firewall aktivieren")
        self.btn_toggle_fw.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_toggle_fw.clicked.connect(self.on_toggle_firewall)
        self.banner_layout.addWidget(self.btn_toggle_fw)

        self.btn_refresh = QPushButton("🔄 Neu laden")
        self.btn_refresh.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_refresh.setStyleSheet("""
            QPushButton {
                background-color: #1e293b;
                color: #cbd5e1;
                border: 1px solid #334155;
                padding: 8px 16px;
                border-radius: 6px;
                font-size: 12px;
                font-weight: 500;
            }
            QPushButton:hover { background-color: #334155; color: #ffffff; }
        """)
        self.btn_refresh.clicked.connect(self.refresh_all)
        self.banner_layout.addWidget(self.btn_refresh)

        root_layout.addWidget(self.banner_card)

        # 3. Metric Tiles
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(12)

        self.card_status = StatusCard("PAKETFILTER STATUS", "Bereit", color_accent="#10b981")
        self.card_rules = StatusCard("AKTIVE REGELN", 0, color_accent="#38bdf8")
        self.card_incoming = StatusCard("EINGEHEND", "DROP", color_accent="#10b981")
        self.card_outgoing = StatusCard("AUSGEHEND", "ALLOW", color_accent="#10b981")
        self.card_blocked = StatusCard("BLÖCKE ERFASST", 0, color_accent="#f59e0b")

        cards_layout.addWidget(self.card_status)
        cards_layout.addWidget(self.card_rules)
        cards_layout.addWidget(self.card_incoming)
        cards_layout.addWidget(self.card_outgoing)
        cards_layout.addWidget(self.card_blocked)
        root_layout.addLayout(cards_layout)

        # 4. Security Profiles Quick Bar
        profile_frame = QFrame()
        profile_frame.setStyleSheet("""
            QFrame {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #111827, stop:1 #0f172a);
                border: 1px solid #1e293b;
                border-radius: 8px;
                padding: 4px;
            }
        """)
        p_layout = QHBoxLayout(profile_frame)
        p_layout.setContentsMargins(12, 6, 12, 6)
        p_layout.setSpacing(12)

        lbl_prof = QLabel("🛡️ SCHNELL-PROFILE:")
        lbl_prof.setStyleSheet("font-size: 11px; font-weight: 700; color: #64748b; letter-spacing: 1px;")
        p_layout.addWidget(lbl_prof)

        self.btn_prof_home = QPushButton("🏠 Heimnetzwerk (Standard)")
        self.btn_prof_home.setToolTip("Eingehend: Blockieren (DROP) │ Ausgehend: Erlauben (ACCEPT)")
        self.btn_prof_home.clicked.connect(lambda: self.on_apply_profile("home"))
        p_layout.addWidget(self.btn_prof_home)

        self.btn_prof_wifi = QPushButton("☕ Öffentliches WLAN (Strikt)")
        self.btn_prof_wifi.setToolTip("Eingehend: Blockieren │ Ausgehend: Erlauben │ Erweitertes Logging")
        self.btn_prof_wifi.clicked.connect(lambda: self.on_apply_profile("public_wifi"))
        p_layout.addWidget(self.btn_prof_wifi)

        self.btn_prof_lock = QPushButton("🔒 Sicherheits-Lockdown")
        self.btn_prof_lock.setToolTip("Alle eingehenden & ausgehenden Verbindungen sperren (Notfall-Modus)")
        self.btn_prof_lock.clicked.connect(lambda: self.on_apply_profile("lockdown"))
        p_layout.addWidget(self.btn_prof_lock)

        for btn in (self.btn_prof_home, self.btn_prof_wifi, self.btn_prof_lock):
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            btn.setStyleSheet("""
                QPushButton {
                    background-color: #1e293b;
                    color: #94a3b8;
                    border: 1px solid #334155;
                    border-radius: 6px;
                    padding: 6px 14px;
                    font-size: 12px;
                    font-weight: 500;
                }
                QPushButton:hover {
                    background-color: #2563eb;
                    color: #ffffff;
                    border-color: #3b82f6;
                }
            """)

        p_layout.addStretch()
        root_layout.addWidget(profile_frame)

        # 5. Tabbed Workspace: Rules & Live Logs
        self.tabs = QTabWidget()
        self.tabs.setStyleSheet("""
            QTabWidget::pane {
                border: 1px solid #1e293b;
                border-radius: 8px;
                background-color: #0d1322;
            }
            QTabBar::tab {
                background: #111827;
                color: #94a3b8;
                border: 1px solid #1e293b;
                border-bottom: none;
                padding: 8px 18px;
                font-weight: 600;
                font-size: 12px;
                border-top-left-radius: 6px;
                border-top-right-radius: 6px;
                margin-right: 4px;
            }
            QTabBar::tab:selected {
                background: #0d1322;
                color: #38bdf8;
                border-bottom: 2px solid #38bdf8;
            }
        """)

        # Tab 1: Rules Table
        tab_rules = QWidget()
        v_rules = QVBoxLayout(tab_rules)
        v_rules.setContentsMargins(14, 14, 14, 14)
        v_rules.setSpacing(10)

        # Rules Actions bar
        h_rules_act = QHBoxLayout()
        self.btn_add_rule = QPushButton("➕ Regel hinzufügen...")
        self.btn_add_rule.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_add_rule.setStyleSheet("""
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #1d4ed8, stop:1 #2563eb);
                color: #ffffff;
                border: none;
                padding: 7px 16px;
                border-radius: 6px;
                font-size: 12px;
                font-weight: 600;
            }
            QPushButton:hover { background-color: #1d4ed8; }
        """)
        self.btn_add_rule.clicked.connect(self.open_add_rule_dialog)
        h_rules_act.addWidget(self.btn_add_rule)

        self.btn_del_rule = QPushButton("🗑️ Regel löschen")
        self.btn_del_rule.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_del_rule.setStyleSheet("""
            QPushButton {
                background-color: #1e293b;
                color: #f87171;
                border: 1px solid rgba(239, 68, 68, 0.3);
                padding: 7px 14px;
                border-radius: 6px;
                font-size: 12px;
                font-weight: 500;
            }
            QPushButton:hover {
                background-color: #ef4444;
                color: #ffffff;
            }
        """)
        self.btn_del_rule.clicked.connect(self.on_delete_selected_rule)
        h_rules_act.addWidget(self.btn_del_rule)

        h_rules_act.addStretch()

        self.lbl_rule_count = QLabel("0 aktive Regeln konfiguriert")
        self.lbl_rule_count.setStyleSheet("color: #64748b; font-size: 12px;")
        h_rules_act.addWidget(self.lbl_rule_count)
        v_rules.addLayout(h_rules_act)

        # Rules Table Widget
        self.table_rules = QTableWidget()
        self.table_rules.setColumnCount(7)
        self.table_rules.setHorizontalHeaderLabels([
            "Aktion", "Richtung", "Port / Bereich", "Protokoll", "Quelle", "IP-Version", "Kommentar / Anwendung"
        ])
        self.table_rules.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table_rules.horizontalHeader().setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)
        self.table_rules.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table_rules.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table_rules.verticalHeader().setVisible(False)
        self.table_rules.setStyleSheet("""
            QTableWidget {
                background-color: #0b1120;
                border: 1px solid #1e293b;
                border-radius: 6px;
                color: #f8fafc;
                gridline-color: #1e293b;
            }
            QTableWidget::item {
                padding: 6px 10px;
            }
            QTableWidget::item:selected {
                background-color: rgba(56, 189, 248, 0.2);
                color: #ffffff;
            }
            QHeaderView::section {
                background-color: #111827;
                color: #94a3b8;
                font-size: 11px;
                font-weight: 700;
                padding: 6px 10px;
                border: none;
                border-right: 1px solid #1e293b;
                border-bottom: 1px solid #1e293b;
            }
        """)
        v_rules.addWidget(self.table_rules)
        self.tabs.addTab(tab_rules, "🛡️ Firewall-Regeln")

        # Tab 2: Live Block Logs
        tab_logs = QWidget()
        v_logs = QVBoxLayout(tab_logs)
        v_logs.setContentsMargins(14, 14, 14, 14)
        v_logs.setSpacing(10)

        h_logs_info = QHBoxLayout()
        lbl_log_title = QLabel("Echtzeit-Blockprotokoll (Die letzten vom Paketfilter abgewiesenen Pakete):")
        lbl_log_title.setStyleSheet("color: #94a3b8; font-size: 12px; font-weight: 500;")
        h_logs_info.addWidget(lbl_log_title)
        h_logs_info.addStretch()

        self.btn_refresh_logs = QPushButton("🔄 Logs aktualisieren")
        self.btn_refresh_logs.setCursor(Qt.CursorShape.PointingHandCursor)
        self.btn_refresh_logs.setStyleSheet("""
            QPushButton {
                background-color: #1e293b;
                color: #cbd5e1;
                border: 1px solid #334155;
                padding: 6px 12px;
                border-radius: 6px;
                font-size: 11px;
            }
            QPushButton:hover { background-color: #334155; color: #ffffff; }
        """)
        self.btn_refresh_logs.clicked.connect(self.refresh_logs_only)
        h_logs_info.addWidget(self.btn_refresh_logs)
        v_logs.addLayout(h_logs_info)

        self.table_logs = QTableWidget()
        self.table_logs.setColumnCount(6)
        self.table_logs.setHorizontalHeaderLabels([
            "Zeit", "Quell-IP", "Ziel-Port", "Protokoll", "Interface", "Rohdaten"
        ])
        self.table_logs.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.table_logs.horizontalHeader().setSectionResizeMode(5, QHeaderView.ResizeMode.Stretch)
        self.table_logs.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table_logs.verticalHeader().setVisible(False)
        self.table_logs.setStyleSheet("""
            QTableWidget {
                background-color: #0b1120;
                border: 1px solid #1e293b;
                border-radius: 6px;
                color: #f8fafc;
                gridline-color: #1e293b;
                font-family: monospace;
                font-size: 11px;
            }
            QTableWidget::item { padding: 4px 8px; }
            QHeaderView::section {
                background-color: #111827;
                color: #94a3b8;
                font-size: 11px;
                font-weight: 700;
                padding: 6px 10px;
                border: none;
                border-right: 1px solid #1e293b;
                border-bottom: 1px solid #1e293b;
            }
        """)
        v_logs.addWidget(self.table_logs)
        self.tabs.addTab(tab_logs, "📋 Blockprotokoll")

        root_layout.addWidget(self.tabs, stretch=1)

    def refresh_all(self):
        """Refreshes status, rules, and block logs."""
        self.cached_status = FirewallService.get_status()
        self.cached_rules = FirewallService.get_rules()

        # Update banner
        if not self.cached_status.installed:
            self.lbl_banner_status.setText("❌ UFW ist nicht installiert")
            self.lbl_banner_details.setText("Installiere UFW mit 'sudo pacman -S ufw', um den Paketfilter zu nutzen.")
            self.btn_toggle_fw.setEnabled(False)
            self.banner_card.setStyleSheet("""
                QFrame#fwBanner {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #2a1215, stop:1 #170d10);
                    border: 1px solid #7f1d1d;
                    border-radius: 10px;
                }
            """)
        elif self.cached_status.enabled:
            self.lbl_banner_status.setText("🟢 Paketfilter aktiv & geschützt")
            self.lbl_banner_details.setText(
                f"Backend: {self.cached_status.backend_name} │ Eingehend: {self.cached_status.default_incoming} │ Ausgehend: {self.cached_status.default_outgoing}"
            )
            self.btn_toggle_fw.setText("Firewall deaktivieren")
            self.btn_toggle_fw.setStyleSheet("""
                QPushButton {
                    background-color: #1e293b;
                    color: #f87171;
                    border: 1px solid rgba(239, 68, 68, 0.4);
                    padding: 8px 18px;
                    border-radius: 6px;
                    font-size: 12px;
                    font-weight: 600;
                }
                QPushButton:hover { background-color: #ef4444; color: #ffffff; }
            """)
            self.banner_card.setStyleSheet("""
                QFrame#fwBanner {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #064e3b, stop:1 #062c22);
                    border: 1px solid #059669;
                    border-radius: 10px;
                }
            """)
        else:
            self.lbl_banner_status.setText("🔴 Firewall deaktiviert (Ungeschützt)")
            self.lbl_banner_details.setText("Der Paketfilter ist ausgeschaltet. Eingehende Verbindungen werden nicht gefiltert.")
            self.btn_toggle_fw.setText("⚡ Firewall jetzt aktivieren")
            self.btn_toggle_fw.setStyleSheet("""
                QPushButton {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #059669, stop:1 #10b981);
                    color: #ffffff;
                    border: none;
                    padding: 8px 18px;
                    border-radius: 6px;
                    font-size: 12px;
                    font-weight: 600;
                }
                QPushButton:hover {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #047857, stop:1 #059669);
                }
            """)
            self.banner_card.setStyleSheet("""
                QFrame#fwBanner {
                    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #3b1116, stop:1 #1c0b0e);
                    border: 1px solid #ef4444;
                    border-radius: 10px;
                }
            """)

        # Update Metric Tiles
        if self.cached_status.enabled:
            self.card_status.set_text("Aktiv", "#10b981")
        else:
            self.card_status.set_text("Inaktiv", "#ef4444")

        self.card_rules.set_value(len(self.cached_rules))

        if "DROP" in self.cached_status.default_incoming:
            self.card_incoming.set_text("DROP", "#10b981")
        else:
            self.card_incoming.set_text("ALLOW", "#f59e0b")

        if "ACCEPT" in self.cached_status.default_outgoing:
            self.card_outgoing.set_text("ALLOW", "#10b981")
        else:
            self.card_outgoing.set_text("DROP", "#f59e0b")

        # Populate rules table
        self.populate_rules_table()

        # Populate logs
        self.refresh_logs_only()

    def populate_rules_table(self):
        self.table_rules.setRowCount(0)
        self.lbl_rule_count.setText(f"{len(self.cached_rules)} aktive Regeln konfiguriert")

        for row, r in enumerate(self.cached_rules):
            self.table_rules.insertRow(row)

            # Action item
            item_act = QTableWidgetItem(r.action)
            if r.action == "ALLOW":
                item_act.setForeground(QColor("#10b981"))
            elif r.action in ("DENY", "REJECT"):
                item_act.setForeground(QColor("#ef4444"))
            else:
                item_act.setForeground(QColor("#f59e0b"))
            item_act.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table_rules.setItem(row, 0, item_act)

            # Direction
            item_dir = QTableWidgetItem(r.direction)
            item_dir.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table_rules.setItem(row, 1, item_dir)

            # Port / Range
            item_port = QTableWidgetItem(r.display_port())
            item_port.setFont(QFont("monospace", 10))
            self.table_rules.setItem(row, 2, item_port)

            # Protocol
            item_proto = QTableWidgetItem(r.proto)
            item_proto.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table_rules.setItem(row, 3, item_proto)

            # Source
            item_src = QTableWidgetItem(r.display_source())
            self.table_rules.setItem(row, 4, item_src)

            # IP Version
            item_ver = QTableWidgetItem("IPv6" if r.is_v6 else "IPv4")
            item_ver.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            self.table_rules.setItem(row, 5, item_ver)

            # Comment / App
            item_comm = QTableWidgetItem(r.comment or "-")
            self.table_rules.setItem(row, 6, item_comm)

    def refresh_logs_only(self):
        blocks = FirewallService.get_blocked_packets(limit=60)
        self.card_blocked.set_value(len(blocks))
        self.table_logs.setRowCount(0)

        for row, b in enumerate(blocks):
            self.table_logs.insertRow(row)
            self.table_logs.setItem(row, 0, QTableWidgetItem(b.time_str))

            item_src = QTableWidgetItem(b.src_ip)
            item_src.setForeground(QColor("#38bdf8"))
            self.table_logs.setItem(row, 1, item_src)

            item_dpt = QTableWidgetItem(b.dpt)
            item_dpt.setForeground(QColor("#f43f5e"))
            self.table_logs.setItem(row, 2, item_dpt)

            self.table_logs.setItem(row, 3, QTableWidgetItem(b.proto))
            self.table_logs.setItem(row, 4, QTableWidgetItem(b.interface))
            self.table_logs.setItem(row, 5, QTableWidgetItem(b.raw))

    def on_toggle_firewall(self):
        new_state = not self.cached_status.enabled
        action_name = "aktivieren" if new_state else "deaktivieren"
        ok, msg = FirewallService.set_enabled(new_state)
        if ok:
            QMessageBox.information(self, "Firewall", f"Firewall erfolgreich {action_name}t:\n{msg}")
            self.refresh_all()
        else:
            QMessageBox.critical(self, "Fehler", f"Aktion schlug fehl:\n{msg}")

    def on_apply_profile(self, profile: str):
        profiles_info = {
            "home": ("Heimnetzwerk (Standard)", "Standard-Schutz: Eingehend BLOCKIEREN, Ausgehend ERLAUBEN."),
            "public_wifi": ("Öffentliches WLAN (Strikt)", "Erhöhter Schutz mit detailliertem Logging für fremde Netzwerke."),
            "lockdown": ("Sicherheits-Lockdown", "ACHTUNG: Blockiert ALLE Verbindungen eingehend und ausgehend!"),
        }
        title, desc = profiles_info.get(profile, ("Profil", ""))
        reply = QMessageBox.question(
            self,
            f"Profil anwenden: {title}",
            f"Möchtest du das Profil '{title}' jetzt aktivieren?\n\n{desc}",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            ok, msg = FirewallService.apply_profile(profile)
            if ok:
                QMessageBox.information(self, "Profil aktiviert", f"Das Profil '{title}' wurde erfolgreich angewendet:\n{msg}")
                self.refresh_all()
            else:
                QMessageBox.critical(self, "Fehler", f"Profil konnte nicht angewendet werden:\n{msg}")

    def open_add_rule_dialog(self):
        dlg = AddRuleDialog(self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            self.refresh_all()

    def on_delete_selected_rule(self):
        selected_rows = self.table_rules.selectionModel().selectedRows()
        if not selected_rows:
            QMessageBox.warning(self, "Auswahl erforderlich", "Bitte wähle zuerst eine Regel aus der Tabelle aus.")
            return

        row = selected_rows[0].row()
        if row >= len(self.cached_rules):
            return

        rule = self.cached_rules[row]
        prompt = (
            f"Möchtest du diese Firewall-Regel wirklich löschen?\n\n"
            f"Aktion: {rule.action}\n"
            f"Port: {rule.display_port()} ({rule.proto})\n"
            f"Richtung: {rule.direction}\n"
            f"Kommentar: {rule.comment or '-'}"
        )
        reply = QMessageBox.question(
            self,
            "Regel löschen",
            prompt,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        )
        if reply == QMessageBox.StandardButton.Yes:
            ok, msg = FirewallService.delete_rule(rule)
            if ok:
                QMessageBox.information(self, "Regel gelöscht", f"Firewall-Regel erfolgreich gelöscht:\n{msg}")
                self.refresh_all()
            else:
                QMessageBox.critical(self, "Fehler", f"Regel konnte nicht gelöscht werden:\n{msg}")
