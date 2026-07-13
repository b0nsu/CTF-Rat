# Source Generated with Decompyle++
# File: ui.pyc (Python 3.12)

from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
import json
import math
from PyQt6.QtCore import QPoint, QPointF, QRectF, Qt, pyqtSignal, QLineF, QMimeData, QSize
from PyQt6.QtGui import QAction, QColor, QDrag, QFont, QIcon, QMouseEvent, QPainter, QPainterPath, QPen, QBrush, QPixmap
from PyQt6.QtWidgets import QAbstractItemView, QApplication, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QFrame, QGraphicsItem, QGraphicsObject, QGraphicsPathItem, QGraphicsScene, QGraphicsSimpleTextItem, QGraphicsPixmapItem, QGraphicsView, QHBoxLayout, QLabel, QLineEdit, QMainWindow, QMessageBox, QPushButton, QInputDialog, QScrollArea, QSpinBox, QSplitter, QTextEdit, QToolBar, QToolButton, QVBoxLayout, QWidget, QStyle
from model import EdgeModel, NodeModel, ProjectModel, RESOURCE_TYPES
from validator_bridge import HiddenValidator
TYPE_COLORS = {
    'Namespace': ('#95b7ff', '#1a2742'),
    'Node': ('#64f0c1', '#102c2a'),
    'Deployment': ('#b2a2ff', '#231f46'),
    'Pod': ('#dfe9ff', '#20273b'),
    'Service': ('#ffb682', '#43291d'),
    'Ingress': ('#ff96ce', '#451d36'),
    'Secret': ('#f3d578', '#443717'),
    'ConfigMap': ('#78cfff', '#123649') }
# WARNING: Decompyle incomplete
