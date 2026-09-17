"""
Modern animated Toggle Switch (Schiebeschalter) widget for PyQt6.
"""
from PyQt6.QtCore import (
    QEasingCurve,
    QPropertyAnimation,
    QRectF,
    QSize,
    Qt,
    pyqtProperty,
)
from PyQt6.QtGui import QBrush, QColor, QPainter, QPen
from PyQt6.QtWidgets import QAbstractButton


class ToggleSwitch(QAbstractButton):
    """
    Sleek, modern sliding toggle switch (Schiebeschalter).
    Supports animated thumb transition, custom colors, and keyboard accessibility.
    """

    def __init__(
        self,
        parent=None,
        width: int = 44,
        height: int = 22,
        active_color: str = "#10b981",
        inactive_color: str = "#334155",
        thumb_color: str = "#ffffff",
    ):
        super().__init__(parent)
        self.setCheckable(True)
        self._width = width
        self._height = height
        self.setFixedSize(width, height)
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        self._thumb_position = 0.0  # 0.0 = off (left), 1.0 = on (right)
        self._active_color = QColor(active_color)
        self._inactive_color = QColor(inactive_color)
        self._hover_inactive = QColor("#475569")
        self._hover_active = QColor("#059669")
        self._thumb_color = QColor(thumb_color)

        self._anim = QPropertyAnimation(self, b"thumb_position", self)
        self._anim.setDuration(160)
        self._anim.setEasingCurve(QEasingCurve.Type.InOutCubic)

        self.toggled.connect(self._on_toggled)

    def sizeHint(self) -> QSize:
        return QSize(self._width, self._height)

    @pyqtProperty(float)
    def thumb_position(self) -> float:
        return self._thumb_position

    @thumb_position.setter
    def thumb_position(self, pos: float):
        self._thumb_position = pos
        self.update()

    def _on_toggled(self, checked: bool):
        if not self._anim.state() == QPropertyAnimation.State.Running:
            self._anim.stop()
            self._anim.setStartValue(self._thumb_position)
            self._anim.setEndValue(1.0 if checked else 0.0)
            self._anim.start()

    def setChecked(self, checked: bool, animated: bool = False):
        self._anim.stop()
        super().setChecked(checked)
        if not animated:
            self._thumb_position = 1.0 if checked else 0.0
            self.update()
        else:
            self._anim.setStartValue(self._thumb_position)
            self._anim.setEndValue(1.0 if checked else 0.0)
            self._anim.start()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = QRectF(0, 0, self._width, self._height)
        radius = self._height / 2.0

        # Background track color interpolation
        if not self.isEnabled():
            bg_color = QColor("#1e293b")
        elif self.isChecked():
            bg_color = self._hover_active if self.underMouse() else self._active_color
        else:
            bg_color = self._hover_inactive if self.underMouse() else self._inactive_color

        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(bg_color))
        painter.drawRoundedRect(rect, radius, radius)

        # Subtle track border
        border_col = QColor(255, 255, 255, 30) if self.isChecked() else QColor(255, 255, 255, 15)
        painter.setPen(QPen(border_col, 1.0))
        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.drawRoundedRect(rect.adjusted(0.5, 0.5, -0.5, -0.5), radius, radius)

        # Draw sliding thumb knob
        margin = 2.0
        thumb_diameter = self._height - (margin * 2.0)
        min_x = margin
        max_x = self._width - thumb_diameter - margin
        cur_x = min_x + (max_x - min_x) * self._thumb_position
        cur_y = margin

        thumb_rect = QRectF(cur_x, cur_y, thumb_diameter, thumb_diameter)
        thumb_c = self._thumb_color if self.isEnabled() else QColor("#94a3b8")
        painter.setPen(Qt.PenStyle.NoPen)
        painter.setBrush(QBrush(thumb_c))
        painter.drawEllipse(thumb_rect)
