"""
Code snippet viewer widget with line numbers and monospace font.
"""
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QPlainTextEdit


class CodeView(QPlainTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setReadOnly(True)
        self.setFont(QFont("JetBrains Mono, Fira Code, Source Code Pro, monospace", 10))
        self.setStyleSheet("""
            QPlainTextEdit {
                background-color: palette(base);
                color: palette(text);
                border: 1px solid palette(mid);
                border-radius: 6px;
                padding: 8px;
                selection-background-color: #3b82f6;
                selection-color: #ffffff;
            }
        """)

    def set_snippet(self, snippet: str, line_number: int = None):
        if not snippet:
            self.setPlainText("(Kein Code-Snippet verfügbar)")
            return

        lines = snippet.strip().split("\n")
        formatted_lines = []
        for i, l in enumerate(lines):
            prefix = f"{line_number + i:4d} │ " if line_number is not None else "     │ "
            formatted_lines.append(f"{prefix}{l}")

        self.setPlainText("\n".join(formatted_lines))
