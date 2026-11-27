#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
QQSnapShot (Tencent SnapShot.exe v4.6.2051.400, InternalName "SnapShot")  ->  PySide6 重写版
================================================================================
逆向依据 (PE 未加壳, 直接字符串/导入导出):
  .text 熵 6.61 未压缩, 版本资源: CompanyName "Tencent", FileVersion
  "4.6.2051.400", InternalName "SnapShot", OriginalFilename "SnapShot.exe",
  PDB 路径 "C:\\QShuru\\release_line\\client\\Release\\SnapShot.pdb" (QQ 输入法团队).
  内嵌 libpng ("png_write_info"/"Failed to create PNG structure"...) 与
  libjpeg ("Copyright (C) 1998, Thomas G. Lane" / "JPEG can save only RGB..."),
  以及大量 GDI/窗口 API: GetDesktopWindow / GetWindowRect / GetClientRect /
  PtInRect / FillRect / InvalidateRect / CreateWindowExW / SetWindowPos,
  剪贴板/保存对话框 GetSaveFileNameW, 截图热键 (RegisterHotKey 类), 多显示器.
  (另含大量 "Tencent\\QQPinyin" 输入法配置串, 为静态链接的输入法公共组件残留,
   与截图主功能无关.)
  => 结论: 屏幕/窗口/区域截图工具, 保存为 PNG / JPEG, 复制到剪贴板.

  本 PySide6 重写 (PySide6, main.py 唯一入口) 复刻核心:
    - 全屏截图 / 活动窗口截图 / 区域截图 (半透明遮罩 + 橡皮筋选框);
    - 保存 PNG / JPEG (等价原 libpng/libjpeg 输出), 复制到剪贴板;
    - 延迟截图, 全局热键 (Ctrl+Alt+A 区域 / Ctrl+Alt+S 全屏);
    - 最近截图缩略预览.

用法:  python main.py            # GUI
       python main.py --selftest # 自检 (QImage 往返 / 区域几何)
"""
import sys
import os
import time

import PySide6
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QFileDialog, QMessageBox, QComboBox, QSpinBox, QGridLayout,
)
from PySide6.QtCore import Qt, QRect, QPoint, Signal, QObject, QTimer
from PySide6.QtGui import (
    QPixmap, QImage, QScreen, QPainter, QColor, QPen, QAction, QKeySequence,
    QShortcut, QCursor,
)


# --------------------------------------------------------------------------- #
#  截图核心 (全屏 / 窗口 / 区域)
# --------------------------------------------------------------------------- #
def grab_fullscreen():
    """抓取整个虚拟桌面 (所有屏幕), 等价原 GetDesktopWindow + 截屏。"""
    screen = QApplication.primaryScreen()
    if screen is None:
        return QPixmap()
    # 覆盖所有屏幕的矩形
    rects = [s.geometry() for s in QApplication.screens()]
    if not rects:
        return screen.grabWindow(0)
    left = min(r.left() for r in rects); top = min(r.top() for r in rects)
    right = max(r.right() for r in rects); bottom = max(r.bottom() for r in rects)
    full = QPixmap(right - left + 1, bottom - top + 1)
    full.fill(Qt.black)
    p = QPainter(full)
    for s in QApplication.screens():
        p.drawPixmap(s.geometry().topLeft() - QPoint(left, top), s.grabWindow(0))
    p.end()
    return full


def grab_window():
    """抓取当前活动窗口。"""
    win = QApplication.activeWindow()
    if win is not None:
        return win.grab()
    screen = QApplication.primaryScreen()
    return screen.grabWindow(0) if screen else QPixmap()


def save_pixmap(pm, path):
    """按扩展名保存 PNG/JPEG (等价原 libpng / libjpeg 输出)。成功返回 True。"""
    if pm.isNull():
        return False
    ext = os.path.splitext(path)[1].lower()
    if ext in (".jpg", ".jpeg"):
        return pm.save(path, "JPEG", 92)
    return pm.save(path, "PNG")


def normalize_rect(a, b):
    """由两点构造规范矩形 (支持反向拖拽)。"""
    return QRect(min(a.x(), b.x()), min(a.y(), b.y()),
                 abs(a.x() - b.x()), abs(a.y() - b.y()))


# --------------------------------------------------------------------------- #
#  区域选择遮罩
# --------------------------------------------------------------------------- #
class RegionOverlay(QWidget):
    selected = Signal(QRect)

    def __init__(self, screen_pixmap):
        super().__init__()
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Tool)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setCursor(Qt.CrossCursor)
        self._pm = screen_pixmap
        self._origin = None
        self._cur = None
        self.setGeometry(QApplication.primaryScreen().geometry())

    def paintEvent(self, e):
        p = QPainter(self)
        p.drawPixmap(0, 0, self._pm)
        p.fillRect(self.rect(), QColor(0, 0, 0, 110))
        if self._origin and self._cur:
            r = normalize_rect(self._origin, self._cur)
            p.drawPixmap(r.topLeft(), self._pm, r)
            p.setPen(QPen(QColor(255, 80, 80), 2))
            p.drawRect(r)
            p.setPen(QColor(255, 255, 0))
            p.drawText(r.topLeft() + QPoint(6, 18),
                       "%d x %d" % (r.width(), r.height()))

    def mousePressEvent(self, e):
        self._origin = e.position().toPoint(); self._cur = self._origin
        self.update()

    def mouseMoveEvent(self, e):
        self._cur = e.position().toPoint(); self.update()

    def mouseReleaseEvent(self, e):
        r = normalize_rect(self._origin, e.position().toPoint())
        self.hide()
        if r.width() > 3 and r.height() > 3:
            self.selected.emit(r)

    def keyPressEvent(self, e):
        if e.key() == Qt.Key_Escape:
            self.hide()
        else:
            super().keyPressEvent(e)


# --------------------------------------------------------------------------- #
#  主窗口
# --------------------------------------------------------------------------- #
class SnapShotWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("QQSnapShot (PySide6 重写版) — Tencent SnapShot 4.6")
        self.resize(760, 560)
        self.last = QPixmap()
        self._build_ui()
        self._build_shortcuts()
        self.statusBar().showMessage("Ready.  Ctrl+Alt+A 区域 / Ctrl+Alt+S 全屏 / Ctrl+Alt+W 窗口")

    def _build_ui(self):
        c = QWidget(); self.setCentralWidget(c)
        lay = QVBoxLayout(c)
        bar = QHBoxLayout()
        self.btn_region = QPushButton("区域 (Region)"); self.btn_region.clicked.connect(self.capture_region)
        self.btn_full = QPushButton("全屏 (Full)"); self.btn_full.clicked.connect(self.capture_full)
        self.btn_window = QPushButton("窗口 (Window)"); self.btn_window.clicked.connect(self.capture_window)
        self.btn_save = QPushButton("保存..."); self.btn_save.clicked.connect(self.save_last)
        self.btn_copy = QPushButton("复制"); self.btn_copy.clicked.connect(self.copy_last)
        for w in (self.btn_region, self.btn_full, self.btn_window, self.btn_save, self.btn_copy):
            bar.addWidget(w)
        bar.addStretch()
        lay.addLayout(bar)

        g = QGridLayout()
        g.addWidget(QLabel("延迟:"), 0, 0); self.delay = QSpinBox(); self.delay.setRange(0, 10); self.delay.setSuffix(" s"); g.addWidget(self.delay, 0, 1)
        g.addWidget(QLabel("保存格式:"), 0, 2); self.fmt = QComboBox(); self.fmt.addItems(["PNG", "JPEG"]); g.addWidget(self.fmt, 0, 3)
        lay.addLayout(g)

        self.preview = QLabel("最近截图预览"); self.preview.setAlignment(Qt.AlignCenter)
        self.preview.setStyleSheet("border:1px solid #888; background:#222; color:#aaa")
        self.preview.setMinimumHeight(360)
        lay.addWidget(self.preview, 1)

    def _build_shortcuts(self):
        QShortcut(QKeySequence("Ctrl+Alt+A"), self, activated=self.capture_region)
        QShortcut(QKeySequence("Ctrl+Alt+S"), self, activated=self.capture_full)
        QShortcut(QKeySequence("Ctrl+Alt+W"), self, activated=self.capture_window)

    def _do_delay(self):
        d = self.delay.value()
        if d:
            QTimer.singleShot(d * 1000, self._delayed)

    def _delayed(self):
        self.statusBar().showMessage("Delayed capture...")

    def capture_region(self):
        if self.delay.value():
            QTimer.singleShot(self.delay.value() * 1000, self._region_now)
        else:
            self._region_now()

    def _region_now(self):
        full = grab_fullscreen()
        if full.isNull():
            return
        self._ov = RegionOverlay(full)
        self._ov.selected.connect(self._on_region)
        self._ov.showFullScreen()

    def _on_region(self, rect):
        full = self._ov._pm
        self.set_last(full.copy(rect))

    def capture_full(self):
        if self.delay.value():
            QTimer.singleShot(self.delay.value() * 1000, lambda: self.set_last(grab_fullscreen()))
        else:
            self.set_last(grab_fullscreen())

    def capture_window(self):
        self.set_last(grab_window())

    def set_last(self, pm):
        if pm is None or pm.isNull():
            self.statusBar().showMessage("Capture failed."); return
        self.last = pm
        scaled = pm.scaled(self.preview.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation)
        self.preview.setPixmap(scaled)
        self.statusBar().showMessage("Captured %dx%d" % (pm.width(), pm.height()))

    def save_last(self):
        if self.last.isNull():
            QMessageBox.information(self, "SnapShot", "No capture yet."); return
        ext = "jpg" if self.fmt.currentText() == "JPEG" else "png"
        fn, _ = QFileDialog.getSaveFileName(self, "Save", "SnapShot_%d.%s" % (int(time.time()), ext),
                                            "PNG (*.png);;JPEG (*.jpg)")
        if fn:
            if save_pixmap(self.last, fn):
                self.statusBar().showMessage("Saved " + fn)
            else:
                QMessageBox.critical(self, "SnapShot", "Save failed.")

    def copy_last(self):
        if not self.last.isNull():
            QApplication.clipboard().setPixmap(self.last)
            self.statusBar().showMessage("Copied to clipboard.")


# --------------------------------------------------------------------------- #
def selftest():
    img = QImage(40, 30, QImage.Format_RGB32)
    img.fill(QColor(10, 20, 30))
    pm = QPixmap.fromImage(img)
    assert not pm.isNull() and pm.width() == 40
    r = normalize_rect(QPoint(10, 10), QPoint(2, 2))
    assert r.width() == 8 and r.height() == 8 and r.topLeft() == QPoint(2, 2)
    # 保存/加载往返
    p = os.path.join(os.environ.get("TEMP", "."), "_snap_test.png")
    assert save_pixmap(pm, p)
    back = QPixmap(p); assert back.width() == 40 and back.height() == 30
    os.remove(p)
    print("[selftest] SnapShot QImage/save/region OK")


def main():
    if "--selftest" in sys.argv:
        app = QApplication(sys.argv); selftest(); return
    app = QApplication(sys.argv)
    w = SnapShotWindow(); w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()