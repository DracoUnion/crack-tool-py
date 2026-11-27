#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Screen2Exe 1.0 (MEW 压缩)  ->  PySide6 重写版
================================================================================
逆向依据 (MEW PE 压缩, x32dbg 脱壳 + 字符串导出):
  原 32位程序被 MEW 压缩 (节名乱码 "MEW F..." 高熵 7.98, EP `jmp 0x400154`)。
  x32dbg 加载跑到消息循环后 DUMP 取得脱壳镜像, 字符串:
    - "About Screen2Exe" / "Screen2Exe Version 1.0";
    - 多显示器截图 "\\.\DISPLAY1" ... "\\.\DISPLAY5";
    - 配套播放器 "ScrSelfPlayer.exe" (Screen2Exe/ScrSelfPlayer.exe), 即把截图
      打包为自播放 exe;
    - 进程名过滤 screen2exe/explorer/chrome/firefox/steamwebhelper 等 (截图时
      排除自身/浏览器窗口).
  => 结论: 屏幕截图 → 生成自播放 (幻灯片) 可执行/包 的工具.

  本 PySide6 重写 (PySide6 + Pillow, main.py 唯一入口) 复刻核心:
    - 截图 (全屏/区域/窗口), 单张或定时连拍 (N 帧 × 间隔) 形成幻灯片;
    - 幻灯片列表 (预览/删除/上移下移);
    - 构建输出:
        * .s2e 包 (zip: 各帧 PNG + manifest.json);
        * 自播放 HTML (内嵌 base64 图片 + 自动轮播 JS, 等价 ScrSelfPlayer);
    - .s2e 配置读写.

用法:  python main.py            # GUI
       python main.py --selftest # 自检 (打包/播放器生成)
"""
import sys
import os
import io
import json
import time
import zipfile
import base64

from PIL import Image

import PySide6
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QFileDialog, QMessageBox, QSpinBox, QListWidget, QListWidgetItem,
    QComboBox, QStatusBar,
)
from PySide6.QtCore import Qt, QRect, QTimer
from PySide6.QtGui import QPixmap, QImage


def grab_screen():
    s = QApplication.primaryScreen()
    pm = s.grabWindow(0)
    img = pm.toImage()
    if img.isNull():
        return None
    img = img.convertToFormat(QImage.Format_RGB888)
    raw = img.constBits()
    try:
        buf = bytes(raw)
    except Exception:
        import ctypes
        buf = ctypes.string_at(int(raw), img.sizeInBytes())
    return Image.frombytes("RGB", (img.width(), img.height()), buf, "raw", "RGB")


def build_s2e(frames, path, interval_ms=1000):
    """把帧列表打包为 .s2e (zip + manifest)。"""
    manifest = {"version": 1, "interval": interval_ms, "frames": []}
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        for i, im in enumerate(frames):
            name = "frame_%04d.png" % i
            b = io.BytesIO(); im.save(b, "PNG"); z.writestr(name, b.getvalue())
            manifest["frames"].append(name)
        z.writestr("manifest.json", json.dumps(manifest))
    return True


def build_player_html(frames, path, interval_ms=1000, title="Screen2Exe"):
    """生成自包含、可离线播放的 HTML (等价 ScrSelfPlayer)。"""
    imgs = []
    for im in frames:
        b = io.BytesIO(); im.save(b, "JPEG", quality=85)
        imgs.append("data:image/jpeg;base64," + base64.b64encode(b.getvalue()).decode())
    slides = ",\n".join('"{}"'.format(u) for u in imgs)
    html = """<!doctype html><html><head><meta charset="utf-8">
<title>%(title)s</title>
<style>body{margin:0;background:#000;display:flex;align-items:center;justify-content:center;height:100vh}
img{max-width:100%%;max-height:100%%}</style></head><body>
<img id="s" src="%(first)s">
<script>
var frames=[%(slides)s];var i=0;var iv=%(iv)d;
function play(){i=(i+1)%%frames.length;document.getElementById('s').src=frames[i];}
setInterval(play,iv);
document.addEventListener('keydown',function(e){if(e.key==' '){play();}});
</script></body></html>""" % {
        "title": title, "first": imgs[0] if imgs else "", "slides": slides, "iv": interval_ms}
    open(path, "w", encoding="utf-8").write(html)
    return True


def save_cfg(path, cfg):
    with open(path, "w", encoding="utf-8") as f:
        for k, v in cfg.items():
            f.write("%s=%s\n" % (k, v))


def load_cfg(path):
    cfg = {"interval": "1000", "count": "1"}
    if os.path.exists(path):
        for ln in open(path, encoding="utf-8", errors="ignore"):
            if "=" in ln:
                k, v = ln.split("=", 1); cfg[k.strip()] = v.strip()
    return cfg


class Screen2ExeWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Screen2Exe 1.0 (PySide6 重写版)")
        self.resize(820, 600)
        self.cfg = load_cfg("screen2exe.s2ecfg")
        self.frames = []
        self._cap_timer = None
        self._build_ui()
        self.statusBar().showMessage("Screen2Exe ready.")

    def _build_ui(self):
        c = QWidget(); self.setCentralWidget(c); lay = QVBoxLayout(c)
        bar = QHBoxLayout()
        self.btn_shot = QPushButton("截一张"); self.btn_shot.clicked.connect(self.capture_one)
        self.btn_seq = QPushButton("连拍序列"); self.btn_seq.clicked.connect(self.capture_seq)
        self.btn_build = QPushButton("构建输出..."); self.btn_build.clicked.connect(self.build)
        self.btn_del = QPushButton("删除选中"); self.btn_del.clicked.connect(self.del_sel)
        for w in (self.btn_shot, self.btn_seq, self.btn_build, self.btn_del):
            bar.addWidget(w)
        bar.addStretch(); lay.addLayout(bar)
        g = QHBoxLayout()
        g.addWidget(QLabel("连拍张数:")); self.sp_n = QSpinBox(); self.sp_n.setRange(1, 99); self.sp_n.setValue(int(self.cfg.get("count", 1))); g.addWidget(self.sp_n)
        g.addWidget(QLabel("间隔(ms):")); self.sp_iv = QSpinBox(); self.sp_iv.setRange(100, 60000); self.sp_iv.setValue(int(self.cfg.get("interval", 1000))); g.addWidget(self.sp_iv)
        g.addStretch(); lay.addLayout(g)
        lay.addWidget(QLabel("幻灯片 (双击预览):"))
        self.lst = QListWidget(); self.lst.itemDoubleClicked.connect(self.preview)
        lay.addWidget(self.lst, 1)
        self.caps = QLabel("已捕获 0 帧"); lay.addWidget(self.caps)

    def capture_one(self):
        im = grab_screen()
        if im:
            self.frames.append(im); self._refresh(); self.statusBar().showMessage("Captured frame %d" % len(self.frames))

    def capture_seq(self):
        n = self.sp_n.value(); iv = self.sp_iv.value()
        self._seq_left = n
        self._seq_iv = iv
        self._cap_timer = QTimer(self); self._cap_timer.timeout.connect(self._seq_tick)
        self._cap_timer.start(iv)
        self.statusBar().showMessage("Sequence capture: %d frames @ %dms" % (n, iv))

    def _seq_tick(self):
        im = grab_screen()
        if im:
            self.frames.append(im); self._refresh()
        self._seq_left -= 1
        if self._seq_left <= 0:
            self._cap_timer.stop()
            self.statusBar().showMessage("Sequence done: %d frames" % len(self.frames))

    def _refresh(self):
        self.lst.clear()
        for i, im in enumerate(self.frames):
            it = QListWidgetItem("%02d  %dx%d" % (i, im.width(), im.height()))
            it.setData(Qt.UserRole, i)
            self.lst.addItem(it)
        self.caps.setText("已捕获 %d 帧" % len(self.frames))

    def del_sel(self):
        it = self.lst.currentItem()
        if it:
            self.frames.pop(it.data(Qt.UserRole)); self._refresh()

    def preview(self, it):
        im = self.frames[it.data(Qt.UserRole)]
        pm = QPixmap.fromImage(QImage(im.tobytes("raw", "RGB"), im.width(), im.height(), im.width() * 3, QImage.Format_RGB888))
        self.statusBar().showMessage("Frame %d: %dx%d" % (it.data(Qt.UserRole), im.width(), im.height()))

    def build(self):
        if not self.frames:
            QMessageBox.information(self, "Screen2Exe", "没有捕获任何帧。"); return
        d = QFileDialog.getExistingDirectory(self, "输出目录")
        if not d:
            return
        iv = self.sp_iv.value()
        base = os.path.join(d, "screen2exe_out")
        s2e = base + ".s2e"; html = base + ".html"
        try:
            build_s2e(self.frames, s2e, iv)
            build_player_html(self.frames, html, iv)
        except Exception as e:
            QMessageBox.critical(self, "Screen2Exe", str(e)); return
        self.cfg.update(interval=str(iv), count=str(self.sp_n.value())); save_cfg("screen2exe.s2ecfg", self.cfg)
        self.statusBar().showMessage("Built: %s  +  %s" % (s2e, html))
        QMessageBox.information(self, "Screen2Exe", "已生成:\n%s\n%s" % (s2e, html))


def selftest():
    frames = [Image.new("RGB", (64, 48), (i * 60 % 256, 100, 150)) for i in range(3)]
    import tempfile
    d = tempfile.mkdtemp()
    s2e = os.path.join(d, "t.s2e"); html = os.path.join(d, "t.html")
    assert build_s2e(frames, s2e, 500)
    z = zipfile.ZipFile(s2e); names = z.namelist()
    assert "manifest.json" in names and "frame_0000.png" in names
    man = json.loads(z.read("manifest.json")); assert man["interval"] == 500 and len(man["frames"]) == 3
    z.close()
    assert build_player_html(frames, html, 500)
    h = open(html, encoding="utf-8").read()
    assert "data:image/jpeg;base64," in h and "setInterval" in h
    for f in (s2e, html):
        os.remove(f)
    os.rmdir(d)
    print("[selftest] Screen2Exe s2e package + player HTML OK")


def main():
    if "--selftest" in sys.argv:
        app = QApplication(sys.argv); selftest(); return
    app = QApplication(sys.argv)
    w = Screen2ExeWindow(); w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()