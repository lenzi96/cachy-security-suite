"""
Severity badge widget for visualizing finding severity levels.
"""
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QLabel


class SeverityBadge(QLabel):
    SEVERITY_STYLES = {
        "critical": {
            "bg": "#ef4444",
            "text": "#ffffff",
            "border": "#dc2626",
            "name": "KRITISCH",
        },
        "high": {
            "bg": "#f97316",
            "text": "#ffffff",
            "border": "#ea580c",
            "name": "HOCH",
        },
        "medium": {
            "bg": "#eab308",
            "text": "#1e293b",
            "border": "#ca8a04",
            "name": "MITTEL",
        },
        "low": {
            "bg": "#3b82f6",
            "text": "#ffffff",
            "border": "#2563eb",
            "name": "NIEDRIG",
        },
        "info": {
            "bg": "#64748b",
            "text": "#ffffff",
            "border": "#475569",
            "name": "INFO",
        },
    }

    def __init__(self, severity: str = "info", parent=None):
        super().__init__(parent)
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.set_severity(severity)

    def set_severity(self, severity: str):
        sev_key = severity.lower()
        style_info = self.SEVERITY_STYLES.get(
            sev_key,
            {"bg": "#64748b", "text": "#ffffff", "border": "#475569", "name": severity.upper()},
        )

        self.setText(style_info["name"])
        self.setStyleSheet(f"""
            QLabel {{
                background-color: {style_info['bg']};
                color: {style_info['text']};
                border: 1px solid {style_info['border']};
                border-radius: 5px;
                font-weight: 700;
                font-size: 10px;
                letter-spacing: 0.5px;
                padding: 2px 8px;
            }}
        """)
        self.setFixedHeight(22)
