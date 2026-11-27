#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JPGCompact (Delphi)  ->  PySide6 重写版
================================================================================
逆向依据 (ASPack 脱壳 + 字符串导出):
  原 32位 Delphi 程序被 ASPack 压缩 (.aspack + .adata 节, CODE 熵 8.00)。
  x32dbg 加载后 EP `pushad` → TraceOver 走过 ASPack 解压桩 → 内存 DUMP 取得
  脱壳镜像, 字符串揭示:
    - "Cannot change the size of a JPEG image" / "JPEG error #%d" /
      "JPEG Image File" / "Bitmap image is not valid" —— JPEG 处理 (libjpeg 类);
    - "OPENFOLDER" / "CURRENTFOLDER" / "CLOSEDFOLDER" /
      "Unable to retrieve folder details for \"%s\"" —— 文件夹批处理;
    - "TOPTIONFORM" / msctls_progress32 —— 选项表单 + 进度条;
    - "Cannot open file \"%s\". %s" / "Too many open files".
  => 结论: 批量 JPEG 压缩工具 (选文件夹 → 遍历 JPG → 按比例/质量压缩 → 进度).

  本 PySide6 重写 (PySide6 + Pillow, main.py 唯一入口) 复刻核心:
    - 选择源文件夹, 列出其中所有 .jpg/.jpeg (递归可选);
    - 设定质量 (1~95) 与最大边长 (等比缩放), 目标文件夹/覆盖;
    - 批量压缩, 进度条 + 统计 (原大小/新大小/节省率);
    - .jcfg 配置读写.

用法:  python main.py            # GUI
       python main.py --selftest # 自检 (JPEG 重压往返)
"""
import sys
import os

from PIL import Image

import PySide6
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QFileDialog, QMessageBox, QSpinBox, QComboBox, QCheckBox, QProgressBar,
    QTableWidget, QTableWidgetItem, QAbstractItemView,
)
from PySide6.QtCore import Qt, QThread, Signal


def find_jpgs(folder, recursive=False):
    out = []
    if recursive:
        for root, _, files in os.walk(folder):
            for f in files:
                if f.lower().endswith((".jpg", ".jpeg")):
                    out.append(os.path.join(root, f))
    else:
        for f in os.listdir(folder):
            fp = os.path.join(folder, f)
            if os.path.isfile(fp) and f.lower().endswith((".jpg", ".jpeg")):
                out.append(fp)
    return sorted(out)


def compact_one(src, dst, quality=60, max_side=0):
    """压缩单个 JPEG, 返回 (orig_size, new_size)。"""
    im = Image.open(src)
    w, h = im.size
    if max_side and max(w, h) > max_side:
        r = max_side / float(max(w, h))
        im = im.resize((max(1, int(w * r)), max(1, int(h * r))), Image.LANCZOS)
    if im.mode != "RGB":
        im = im.convert("RGB")
    im.save(dst, "JPEG", quality=quality, optimize=True)
    return os.path.getsize(src), os.path.getsize(dst)


def save_cfg(path, cfg):
    with open(path, "w", encoding="utf-8") as f:
        for k, v in cfg.items():
            f.write("%s=%s\n" % (k, v))


def load_cfg(path):
    cfg = {"quality": "60", "maxside": "0", "recursive": "0"}
    if os.path.exists(path):
        for ln in open(path, encoding="utf-8", errors="ignore"):
            if "=" in ln:
                k, v = ln.split("=", 1); cfg[k.strip()] = v.strip()
    return cfg


class CompactWorker(QThread):
    progress = Signal(int, int, str)   # done, total, name
    finished_ok = Signal(int, int, int)  # orig, new, count

    def __init__(self, files, outdir, quality, max_side):
        super().__init__()
        self.files = files; self.outdir = outdir
        self.quality = quality; self.max_side = max_side

    def run(self):
        orig = new = 0
        for i, f in enumerate(self.files, 1):
            dst = os.path.join(self.outdir, os.path.basename(f))
            try:
                o, n = compact_one(f, dst, self.quality, self.max_side)
                orig += o; new += n
            except Exception:
                pass
            self.progress.emit(i, len(self.files), os.path.basename(f))
        self.finished_ok.emit(orig, new, len(self.files))


class JPGCompactWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("JPGCompact (PySide6 重写版)")
        self.resize(900, 620)
        self.cfg = load_cfg("jpgcompact.jcfg")
        self.files = []
        self.worker = None
        self._build_ui()
        self.statusBar().showMessage("JPGCompact ready.")

    def _build_ui(self):
        c = QWidget(); self.setCentralWidget(c); lay = QVBoxLayout(c)
        bar = QHBoxLayout()
        self.btn_src = QPushButton("源文件夹..."); self.btn_src.clicked.connect(self.pick_src)
        self.btn_out = QPushButton("目标文件夹..."); self.btn_out.clicked.connect(self.pick_out)
        self.btn_go = QPushButton("开始压缩"); self.btn_go.clicked.connect(self.start)
        for w in (self.btn_src, self.btn_out, self.btn_go):
            bar.addWidget(w)
        bar.addStretch(); lay.addLayout(bar)
        g = QHBoxLayout()
        g.addWidget(QLabel("质量:")); self.sp_q = QSpinBox(); self.sp_q.setRange(1, 95); self.sp_q.setValue(int(self.cfg.get("quality", 60))); g.addWidget(self.sp_q)
        g.addWidget(QLabel("最大边长:")); self.sp_m = QSpinBox(); self.sp_m.setRange(0, 10000); self.sp_m.setValue(int(self.cfg.get("maxside", 0))); g.addWidget(self.sp_m)
        self.chk_rec = QCheckBox("递归"); self.chk_rec.setChecked(self.cfg.get("recursive") == "1"); g.addWidget(self.chk_rec)
        g.addStretch(); lay.addLayout(g)
        self.bar = QProgressBar(); lay.addWidget(self.bar)
        self.tab = QTableWidget(0, 3); self.tab.setHorizontalHeaderLabels(["File", "Orig", "New"])
        self.tab.setEditTriggers(QAbstractItemView.NoEditTriggers); lay.addWidget(self.tab, 1)

    def pick_src(self):
        d = QFileDialog.getExistingDirectory(self, "Source Folder")
        if d:
            self.files = find_jpgs(d, self.chk_rec.isChecked())
            self.tab.setRowCount(0)
            for f in self.files:
                r = self.tab.rowCount(); self.tab.insertRow(r)
                self.tab.setItem(r, 0, QTableWidgetItem(os.path.basename(f)))
            self.statusBar().showMessage("Found %d JPG in %s" % (len(self.files), d))

    def pick_out(self):
        d = QFileDialog.getExistingDirectory(self, "Output Folder")
        if d:
            self.outdir = d

    def start(self):
        if not self.files:
            QMessageBox.information(self, "JPGCompact", "选择源文件夹。"); return
        outdir = getattr(self, "outdir", None) or os.path.dirname(self.files[0])
        self.outdir = outdir
        self.bar.setValue(0)
        self.worker = CompactWorker(self.files, outdir, self.sp_q.value(), self.sp_m.value())
        self.worker.progress.connect(self.on_prog)
        self.worker.finished_ok.connect(self.on_done)
        self.btn_go.setEnabled(False)
        self.worker.start()

    def on_prog(self, done, total, name):
        self.bar.setMaximum(total); self.bar.setValue(done)
        self.statusBar().showMessage("[%d/%d] %s" % (done, total, name))

    def on_done(self, orig, new, count):
        self.btn_go.setEnabled(True)
        saved = (1 - new / orig) * 100 if orig else 0
        self.statusBar().showMessage("Done %d files: %d -> %d bytes (saved %.1f%%)" % (count, orig, new, saved))
        self.cfg.update(quality=str(self.sp_q.value()), maxside=str(self.sp_m.value()),
                        recursive="1" if self.chk_rec.isChecked() else "0")
        save_cfg("jpgcompact.jcfg", self.cfg)


def selftest():
    import tempfile
    d = tempfile.mkdtemp()
    src = os.path.join(d, "a.jpg")
    Image.new("RGB", (400, 300), (120, 60, 200)).save(src, "JPEG", quality=95)
    o = os.path.getsize(src)
    dst = os.path.join(d, "a_c.jpg")
    o2, n2 = compact_one(src, dst, quality=40, max_side=200)
    assert n2 < o2, (o2, n2)
    im = Image.open(dst); assert max(im.size) <= 200; im.close()
    # cleanup
    for f in os.listdir(d):
        try: os.remove(os.path.join(d, f))
        except OSError: pass
    os.rmdir(d)
    print("[selftest] JPGCompact recompress OK %d -> %d" % (o2, n2))


def main():
    if "--selftest" in sys.argv:
        selftest(); return
    app = QApplication(sys.argv)
    w = JPGCompactWindow(); w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()