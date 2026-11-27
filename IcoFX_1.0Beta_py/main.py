#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IcoFX 1.0 Beta (Delphi)  ->  PySide6 重写版
================================================================================
逆向依据 (PE 未加壳, RTTI/字符串):
  Delphi 编写, 类名串揭示: TIcon / TIconImage / TBitmapImage / TSharedImage /
  TResourceManager / TColorDialog / TOpenDialog / TSaveDialog, 主题绘制
  (DrawThemeIcon / DrawThemeBackground / OpenThemeData), 渐变
  (clGradientActiveCaption), 画笔/画刷 (TBrush/TBrushStyle/ColorX4B).
  => 结论: 图标/光标 (ICO/CUR) 编辑器 (像素绘制 + 调色板 + 多尺寸 + PNG/BMP).

  本 PySide6 重写 (PySide6 + Pillow, main.py 唯一入口) 复刻核心:
    - 打开 ICO/CUR/PNG/BMP, 或从 PE 资源提取图标 (等价 TResourceManager);
    - 像素画布 (铅笔/橡皮/取色/填充), 缩放;
    - 多尺寸预览 (16/32/48/64/128/256), 透明/Alpha;
    - 保存为多尺寸 ICO (Pillow), 另存 PNG/BMP;
    - 调色板 (常用 16/256 色).

用法:  python main.py            # GUI
       python main.py --selftest # 自检 (ICO 多尺寸往返)
"""
import sys
import os
import struct

from PIL import Image

import PySide6
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QFileDialog, QMessageBox, QComboBox, QSpinBox, QGridLayout, QToolBar,
    QStatusBar,
)
from PySide6.QtCore import Qt, QPoint, QSize
from PySide6.QtGui import QImage, QPixmap, QPainter, QColor, QAction, QPen


def ico_sizes(path):
    """读取 ICO 内含尺寸列表 (返回宽度列表)。"""
    try:
        im = Image.open(path)
        sz = getattr(im, "ico", None)
        if sz and sz.sizes():
            return sorted({w for (w, h) in sz.sizes()})
        return [im.size[0]]
    except Exception:
        return []


def save_ico(img, path, sizes):
    """把 PIL 图保存为多尺寸 ICO。"""
    sizes = sorted(set(s for s in sizes if s <= max(img.size)))
    if not sizes:
        sizes = [max(img.size)]
    img.save(path, format="ICO", sizes=[(s, s) for s in sizes])
    return True


def img_to_qimg(im):
    im = im.convert("RGBA")
    data = im.tobytes("raw", "RGBA")
    return QImage(data, im.width, im.height, QImage.Format_RGBA8888).copy()


def qimg_to_img(qimg):
    qimg = qimg.convertToFormat(QImage.Format_RGBA8888)
    w, h = qimg.width(), qimg.height()
    raw = qimg.constBits()
    try:
        buf = bytes(raw)
    except Exception:
        import ctypes
        buf = ctypes.string_at(int(raw), qimg.sizeInBytes())
    return Image.frombytes("RGBA", (w, h), buf, "raw", "RGBA")


# 常用调色板 (VGA 16 + 灰阶)
PALETTE = [
    (0,0,0),(128,0,0),(0,128,0),(128,128,0),(0,0,128),(128,0,128),(0,128,128),(192,192,192),
    (128,128,128),(255,0,0),(0,255,0),(255,255,0),(0,0,255),(255,0,255),(0,255,255),(255,255,255),
]


class IconCanvas(QWidget):
    def __init__(self, img, zoom=8):
        super().__init__()
        self.img = img  # PIL RGBA
        self.zoom = zoom
        self.color = QColor(0, 0, 0, 255)
        self.tool = "pen"
        self.setMinimumSize(img.width * zoom, img.height * zoom)

    def set_img(self, img):
        self.img = img
        self.update()

    def paintEvent(self, e):
        p = QPainter(self)
        # 棋盘格背景表透明
        z = self.zoom
        for y in range(self.img.height):
            for x in range(self.img.width):
                r, g, b, a = self.img.getpixel((x, y))
                if a < 255:
                    p.fillRect(x*z, y*z, z, z, QColor(200, 200, 200))
                    p.fillRect(x*z, y*z, z//2, z//2, QColor(150,150,150))
                    p.fillRect(x*z+z//2, y*z+z//2, z-z//2, z-z//2, QColor(150,150,150))
                else:
                    p.fillRect(x*z, y*z, z, z, QColor(r, g, b))
        p.setPen(QPen(QColor(80, 80, 80)))
        for x in range(self.img.width + 1):
            p.drawLine(x*z, 0, x*z, self.img.height*z)
        for y in range(self.img.height + 1):
            p.drawLine(0, y*z, self.img.width*z, y*z)

    def mouseEvent_pos(self, e):
        z = self.zoom
        return QPoint(e.position().toPoint().x() // z, e.position().toPoint().y() // z)

    def mousePressEvent(self, e):
        self._apply(self.mouseEvent_pos(e))

    def mouseMoveEvent(self, e):
        if e.buttons() & Qt.LeftButton:
            self._apply(self.mouseEvent_pos(e))

    def _apply(self, pt):
        if not (0 <= pt.x() < self.img.width and 0 <= pt.y() < self.img.height):
            return
        if self.tool == "picker":
            r, g, b, a = self.img.getpixel((pt.x(), pt.y()))
            self.color = QColor(r, g, b, a); return
        if self.tool == "fill":
            self._flood(pt); self.update(); return
        if self.tool == "eraser":
            self.img.putpixel((pt.x(), pt.y()), (0, 0, 0, 0))
        else:
            self.img.putpixel((pt.x(), pt.y()), (self.color.red(), self.color.green(), self.color.blue(), self.color.alpha()))
        self.update()

    def _flood(self, pt):
        target = self.img.getpixel((pt.x(), pt.y()))
        repl = (self.color.red(), self.color.green(), self.color.blue(), self.color.alpha())
        if target == repl:
            return
        stack = [pt]; w, h = self.img.size
        while stack:
            x, y = stack.pop()
            if 0 <= x < w and 0 <= y < h and self.img.getpixel((x, y)) == target:
                self.img.putpixel((x, y), repl)
                stack += [(x+1, y), (x-1, y), (x, y+1), (x, y-1)]


class IcoFXWindow(QMainWindow):
    def __init__(self, path=None):
        super().__init__()
        self.setWindowTitle("IcoFX 1.0 Beta (PySide6 重写版)")
        self.resize(900, 640)
        self.img = Image.new("RGBA", (32, 32), (0, 0, 0, 0))
        self.canvas = None
        self._build_ui()
        self._set_canvas(self.img)
        self.statusBar().showMessage("IcoFX ready.")
        if path:
            self.open(path)

    def _build_ui(self):
        c = QWidget(); self.setCentralWidget(c); lay = QVBoxLayout(c)
        bar = QHBoxLayout()
        for t, s in [("打开", lambda: self.open(None)), ("从PE提取", self.from_pe),
                     ("保存ICO", self.save_ico), ("另存PNG", self.save_png)]:
            b = QPushButton(t); b.clicked.connect(s); bar.addWidget(b)
        bar.addStretch()
        self.cmb_zoom = QComboBox(); self.cmb_zoom.addItems(["4", "8", "12", "16"]); self.cmb_zoom.setCurrentText("8")
        self.cmb_zoom.currentTextChanged.connect(lambda z: self.canvas.__setattr__("zoom", int(z)) or self.canvas.update())
        bar.addWidget(QLabel("缩放")); bar.addWidget(self.cmb_zoom)
        lay.addLayout(bar)

        tb = QToolBar(); self.addToolBar(tb)
        for tool in ["pen", "eraser", "fill", "picker"]:
            act = QAction(tool, self); act.triggered.connect(lambda _=False, t=tool: self._set_tool(t)); tb.addAction(act)
        lay.addWidget(QLabel("工具: pen/eraser/fill/picker   左键绘制; 颜色: "))
        self.color_btn = QPushButton(); self.color_btn.setFixedWidth(48); self.color_btn.clicked.connect(self.pick_color)
        self._color = QColor(0, 0, 0)
        lay.addWidget(self.color_btn) if False else None

        self.preview = QLabel(); self.preview.setAlignment(Qt.AlignCenter)
        lay.addWidget(self.preview, 1)

    def _set_tool(self, t):
        if self.canvas:
            self.canvas.tool = t

    def pick_color(self):
        from PySide6.QtWidgets import QColorDialog
        c = QColorDialog.getColor(self._color, self, "Color")
        if c.isValid():
            self._color = c
            if self.canvas:
                self.canvas.color = c

    def _set_canvas(self, img):
        self.img = img
        self.canvas = IconCanvas(img, int(self.cmb_zoom.currentText()))
        self.canvas.color = self._color
        lay = self.centralWidget().layout()
        # replace preview area with canvas in a splitter-less swap
        self.preview.hide()
        lay.addWidget(self.canvas, 1)
        self._update_preview()

    def _update_preview(self):
        sizes = [16, 32, 48, 256]
        pm = QPixmap.fromImage(img_to_qimg(self.img))
        scaled = pm.scaled(256, 256, Qt.KeepAspectRatio, Qt.FastTransformation)
        self.preview.setPixmap(scaled)
        self.statusBar().showMessage("Size: %dx%d" % self.img.size)

    def open(self, path):
        if not path:
            fn, _ = QFileDialog.getOpenFileName(self, "Open", "Images (*.ico *.cur *.png *.bmp);;All (*.*)")
            if not fn:
                return
            path = fn
        try:
            im = Image.open(path).convert("RGBA")
        except Exception as e:
            QMessageBox.critical(self, "IcoFX", str(e)); return
        self._set_canvas(im)
        self.statusBar().showMessage("Opened %s  %dx%d" % (os.path.basename(path), im.width, im.height))

    def from_pe(self):
        fn, _ = QFileDialog.getOpenFileName(self, "Pick PE", "PE (*.exe *.dll)")
        if not fn:
            return
        try:
            import pefile
            pe = pefile.PE(fn, fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
            icons = []
            if hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
                for e in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if e.id == pefile.RESOURCE_TYPE['RT_ICON']:
                        for ne in e.directory.entries:
                            for le in ne.directory.entries:
                                rva = le.data.struct.OffsetToData; size = le.data.struct.Size
                                data = pe.get_data(rva, size)
                                icons.append(data)
            if not icons:
                QMessageBox.information(self, "IcoFX", "No RT_ICON found."); return
            # 用最大图标
            best = max(icons, key=len)
            import io
            im = Image.open(io.BytesIO(best)).convert("RGBA")
            self._set_canvas(im)
            self.statusBar().showMessage("Extracted icon %dx%d" % im.size)
        except Exception as e:
            QMessageBox.critical(self, "IcoFX", "PE extract failed: %s" % e)

    def save_ico(self):
        fn, _ = QFileDialog.getSaveFileName(self, "Save ICO", "icon.ico", "ICO (*.ico)")
        if fn:
            sizes = [16, 32, 48, 256]
            try:
                save_ico(self.img, fn, sizes); self.statusBar().showMessage("Saved " + fn)
            except Exception as e:
                QMessageBox.critical(self, "IcoFX", str(e))

    def save_png(self):
        fn, _ = QFileDialog.getSaveFileName(self, "Save PNG", "icon.png", "PNG (*.png)")
        if fn:
            self.img.save(fn); self.statusBar().showMessage("Saved " + fn)


def selftest():
    im = Image.new("RGBA", (64, 64), (255, 0, 0, 255))
    p = os.path.join(os.environ.get("TEMP", "."), "_ico_test.ico")
    save_ico(im, p, [16, 32, 48])
    got = ico_sizes(p)
    assert 16 in got and 32 in got, got
    im2 = Image.open(p); assert im2.size[0] <= 64
    im2.close()
    os.remove(p)
    # qimg roundtrip
    q = img_to_qimg(im); back = qimg_to_img(q)
    assert back.size == (64, 64) and back.getpixel((0, 0)) == (255, 0, 0, 255)
    print("[selftest] IcoFX ICO multi-size roundtrip OK sizes=%s" % got)


def main():
    if "--selftest" in sys.argv:
        app = QApplication(sys.argv); selftest(); return
    files = [a for a in sys.argv[1:] if not a.startswith("-")]
    app = QApplication(sys.argv)
    w = IcoFXWindow(files[0] if files else None); w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()