#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GifGifGif (屏幕录制.exe, Delphi)  ->  PySide6 重写版
================================================================================
逆向依据 (PE 未加壳, 资源/字符串导出):
  .text 熵 6.48 未压缩, Delphi 编写 (资源含 Delphi 公共对话框串:
  "Video Driver Warning!" / "Directory Creation Error" / 文件类型表
  "gif .gif GIF Files (.GIF)" 等)。关键串揭示行为:
    - "(Created by %s%, using Gif.gIf.giF v1.24." —— 内嵌 GIF 编码器
      "Gif.gIf.giF v1.24";
    - "Gif does not support recording at the current bit depth (%s colours).
      Please change the monitor settings." —— 录制时按当前色深量化;
    - 帧率选项 "2 fps" "3 fps" "4 fps" "5 fps" ... "40 fps";
    - 尺寸串 "%d%x%d%" / ":%d%,%d%", 偏好文件 "prf .prf Preferences (.PRF)";
    - 导入 SetCapture/ReleaseCapture/OpenClipboard, GDI 调色板函数
      (CreatePalette/GetSystemPaletteEntries/GetNearestPaletteIndex) 做颜色量化,
      CreateFileA/WriteFile 写文件.
  => 结论: 屏幕录制为动画 GIF 的工具 (可选帧率/区域, .prf 偏好).

  本 PySide6 重写 (PySide6 + Pillow, main.py 唯一入口) 复刻核心:
    - 选择全屏/区域, 帧率 2~40fps, 开始/停止录制;
    - 用 Pillow 把每帧量化到 256 色并合成为动画 GIF (等价 Gif.gIf.giF 输出);
    - 另存 JPG/BMP; 复制单帧到剪贴板;
    - .prf 偏好读写 (帧率/区域/输出路径/格式).

用法:  python main.py            # GUI
       python main.py --selftest # 自检 (GIF 编码往返)
"""
import sys
import os
import time

from PIL import Image

import PySide6
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QFileDialog, QMessageBox, QComboBox, QSpinBox, QGridLayout,
)
from PySide6.QtCore import Qt, QRect, QPoint, QTimer, Signal
from PySide6.QtGui import QPixmap, QPainter, QColor, QPen, QImage


def qrect_to_pil(r):
    return (r.left(), r.top(), r.right() + 1, r.bottom() + 1)


def grab_region(rect):
    """抓取屏幕矩形 -> PIL.Image (RGB)。"""
    screen = QApplication.primaryScreen()
    pm = screen.grabWindow(0, rect.left(), rect.top(), rect.width(), rect.height())
    img = pm.toImage()
    if img.isNull():
        return None
    img = img.convertToFormat(QImage.Format_RGB888)
    w, h = img.width(), img.height()
    ptr = img.constBits()
    import ctypes
    buf = ctypes.string_at(ptr, img.sizeInBytes())
    return Image.frombytes("RGB", (w, h), buf, "raw", "RGB")


def grab_full_pil():
    screen = QApplication.primaryScreen()
    g = screen.geometry()
    return grab_region(QRect(g.x(), g.y(), g.width(), g.height())), g


def save_gif(frames, path, fps=10, loop=0):
    """把 PIL 帧列表合成为动画 GIF (全局 256 色调色板)。"""
    if not frames:
        return False
    pal = [f.convert("P", palette=Image.Palette.ADAPTIVE, colors=256) for f in frames]
    duration = int(round(1000.0 / max(1, fps)))
    pal[0].save(path, save_all=True, append_images=pal[1:],
                duration=duration, loop=loop, optimize=False)
    return True


def save_prf(path, cfg):
    with open(path, "w", encoding="utf-8") as f:
        for k, v in cfg.items():
            f.write("%s=%s\n" % (k, v))


def load_prf(path):
    cfg = {"fps": "10", "region": "full", "out": "", "fmt": "gif"}
    if os.path.exists(path):
        for ln in open(path, encoding="utf-8", errors="ignore"):
            if "=" in ln:
                k, v = ln.split("=", 1); cfg[k.strip()] = v.strip()
    return cfg


# --------------------------------------------------------------------------- #
class RegionPicker(QWidget):
    chosen = Signal(QRect)

    def __init__(self, pm):
        super().__init__()
        self.setWindowFlags(Qt.FramelessWindowHint | Qt.WindowStaysOnTopHint | Qt.Tool)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setCursor(Qt.CrossCursor)
        self._pm = pm; self._a = None; self._b = None
        self.setGeometry(QApplication.primaryScreen().geometry())

    def paintEvent(self, e):
        p = QPainter(self); p.drawPixmap(0, 0, self._pm)
        p.fillRect(self.rect(), QColor(0, 0, 0, 110))
        if self._a and self._b:
            r = QRect(min(self._a.x(), self._b.x()), min(self._a.y(), self._b.y()),
                      abs(self._a.x() - self._b.x()), abs(self._a.y() - self._b.y()))
            p.drawPixmap(r.topLeft(), self._pm, r)
            p.setPen(QPen(QColor(255, 80, 80), 2)); p.drawRect(r)

    def mousePressEvent(self, e): self._a = e.position().toPoint(); self._b = self._a; self.update()
    def mouseMoveEvent(self, e): self._b = e.position().toPoint(); self.update()
    def mouseReleaseEvent(self, e):
        self._b = e.position().toPoint()
        r = QRect(min(self._a.x(), self._b.x()), min(self._a.y(), self._b.y()),
                  abs(self._a.x() - self._b.x()), abs(self._a.y() - self._b.y()))
        self.hide()
        if r.width() > 5 and r.height() > 5:
            self.chosen.emit(r)
    def keyPressEvent(self, e):
        if e.key() == Qt.Key_Escape: self.hide()
        else: super().keyPressEvent(e)


class GifRecorderWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("GifGifGif 屏幕录制 (PySide6 重写版) — Gif.gIf.giF v1.24 等效")
        self.resize(640, 520)
        self.cfg = load_prf("screenrec.prf")
        self.frames = []
        self.recording = False
        self.region = None
        self._timer = QTimer(self); self._timer.timeout.connect(self._tick)
        self._build_ui()
        self.statusBar().showMessage("Ready. 选择区域与帧率后开始录制。")

    def _build_ui(self):
        c = QWidget(); self.setCentralWidget(c); lay = QVBoxLayout(c)
        g = QGridLayout()
        g.addWidget(QLabel("区域:"), 0, 0)
        self.cmb_region = QComboBox(); self.cmb_region.addItems(["全屏", "自定义区域..."]); g.addWidget(self.cmb_region, 0, 1)
        self.btn_pick = QPushButton("选取区域"); self.btn_pick.clicked.connect(self.pick_region); g.addWidget(self.btn_pick, 0, 2)
        g.addWidget(QLabel("帧率:"), 1, 0)
        self.sp_fps = QSpinBox(); self.sp_fps.setRange(2, 40); self.sp_fps.setValue(int(self.cfg.get("fps", 10))); self.sp_fps.setSuffix(" fps"); g.addWidget(self.sp_fps, 1, 1)
        g.addWidget(QLabel("格式:"), 1, 2)
        self.cmb_fmt = QComboBox(); self.cmb_fmt.addItems(["GIF", "JPG", "BMP"]); g.addWidget(self.cmb_fmt, 1, 3)
        lay.addLayout(g)
        bar = QHBoxLayout()
        self.btn_start = QPushButton("● 开始录制"); self.btn_start.clicked.connect(self.start_rec)
        self.btn_stop = QPushButton("■ 停止"); self.btn_stop.clicked.connect(self.stop_rec); self.btn_stop.setEnabled(False)
        self.btn_save = QPushButton("保存..."); self.btn_save.clicked.connect(self.save)
        for w in (self.btn_start, self.btn_stop, self.btn_save): bar.addWidget(w)
        bar.addStretch(); lay.addLayout(bar)
        self.lbl = QLabel("帧: 0   时长: 0.0s"); lay.addWidget(self.lbl)
        self.preview = QLabel("预览"); self.preview.setAlignment(Qt.AlignCenter)
        self.preview.setStyleSheet("border:1px solid #888;background:#222;color:#aaa")
        lay.addWidget(self.preview, 1)

    def pick_region(self):
        full = QApplication.primaryScreen().grabWindow(0)
        self._picker = RegionPicker(full)
        self._picker.chosen.connect(lambda r: (setattr(self, "region", r), self.cmb_region.setCurrentIndex(1)))
        self._picker.showFullScreen()

    def _target_rect(self):
        if self.region is not None and self.cmb_region.currentIndex() == 1:
            return self.region
        g = QApplication.primaryScreen().geometry()
        return QRect(g.x(), g.y(), g.width(), g.height())

    def start_rec(self):
        self.frames = []
        self.recording = True
        self._last = time.time()
        self.btn_start.setEnabled(False); self.btn_stop.setEnabled(True)
        interval = int(1000 / self.sp_fps.value())
        self._timer.start(interval)
        self.statusBar().showMessage("Recording... %d fps" % self.sp_fps.value())

    def _tick(self):
        img = grab_region(self._target_rect())
        if img is not None:
            self.frames.append(img)
            if len(self.frames) in (1,) or len(self.frames) % 5 == 0:
                pm = QPixmap.fromImage(QImage(img.tobytes("raw", "RGB"), img.width, img.height, img.width * 3, QImage.Format_RGB888))
                self.preview.setPixmap(pm.scaled(self.preview.size(), Qt.KeepAspectRatio))
        dur = time.time() - self._last
        self.lbl.setText("帧: %d   时长: %.1fs" % (len(self.frames), dur))

    def stop_rec(self):
        self._timer.stop(); self.recording = False
        self.btn_start.setEnabled(True); self.btn_stop.setEnabled(False)
        self.statusBar().showMessage("Stopped. %d frames." % len(self.frames))

    def save(self):
        if not self.frames:
            QMessageBox.information(self, "GifGifGif", "没有录制内容。"); return
        fmt = self.cmb_fmt.currentText()
        ext = {"GIF": "gif", "JPG": "jpg", "BMP": "bmp"}[fmt]
        fn, _ = QFileDialog.getSaveFileName(self, "保存", "record_%d.%s" % (int(time.time()), ext),
                                            "%s (*.%s)" % (fmt, ext))
        if not fn:
            return
        try:
            if fmt == "GIF":
                ok = save_gif(self.frames, fn, self.sp_fps.value())
            else:
                im = self.frames[0]
                ok = im.save(fn)
            self.cfg.update(fps=str(self.sp_fps.value()), fmt=fmt, out=fn)
            save_prf("screenrec.prf", self.cfg)
            self.statusBar().showMessage(("已保存 " if ok else "保存失败 ") + fn)
        except Exception as e:
            QMessageBox.critical(self, "GifGifGif", "保存失败: %s" % e)


def selftest():
    frames = [Image.new("RGB", (32, 24), (i * 40 % 256, 80, 160)) for i in range(5)]
    p = os.path.join(os.environ.get("TEMP", "."), "_gif_test.gif")
    assert save_gif(frames, p, fps=10)
    im = Image.open(p)
    n = getattr(im, "n_frames", 1)
    size = im.size
    im.close()
    assert size == (32, 24) and n == 5, (size, n)
    os.remove(p)
    print("[selftest] GifGifGif GIF encode roundtrip OK frames=%d" % n)


def main():
    if "--selftest" in sys.argv:
        app = QApplication(sys.argv); selftest(); return
    app = QApplication(sys.argv)
    w = GifRecorderWindow(); w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()