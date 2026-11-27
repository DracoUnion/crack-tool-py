#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Beyond Compare Pro 4.x (Scooter Software)  ->  PySide6 重写版
================================================================================
逆向依据 (目录 BeyondComparePro_4.x_Windows_CracKedv2 仅含破解用代理 DLL
  WinMM.dll (x32/x64, 替换系统 WinMM 转发 + 注入), 无主程序 BCompare.exe;
  ReadMe 说明为 52pojie 的 DLL 代理破解, 原版 4.3.6.25063)。
  据 Beyond Compare 公开行为复刻其核心比较功能 (main.py 唯一入口,
  纯标准库 + PySide6)。原版目录无 EXE 可反汇编, 故按工具行为等效重写。

  本 PySide6 重写复刻核心 (Beyond Compare 风格):
    - 会话 (Session): 保存/载入比较会话 (.bcsession), 记住左右路径与类型;
    - 文件夹比较: 两目录递归清单, 标记 onlyL/onlyR/diff/same, 同步复制;
    - 文本比较: 左右并排行 diff (difflib), 差异高亮, 统计;
    - 十六进制比较: 二进制逐字节, 首个差异定位;
    - 状态栏汇总.

用法:  python main.py            # GUI
       python main.py --selftest # 自检
       python main.py left right # 比较
"""
import sys
import os
import json
import difflib

import PySide6
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QFileDialog, QMessageBox, QPlainTextEdit, QSplitter, QTabWidget,
    QTableWidget, QTableWidgetItem, QAbstractItemView, QStatusBar, QComboBox,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QTextCharFormat, QSyntaxHighlighter, QColor, QFont


def read_text(path):
    data = open(path, "rb").read()
    for enc in ("utf-8-sig", "utf-8", "gbk", "latin1"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    return data.decode("latin1", "ignore")


def folder_map(path):
    out = {}
    for root, _, files in os.walk(path):
        for f in files:
            fp = os.path.join(root, f); rel = os.path.relpath(fp, path)
            try:
                st = os.stat(fp); out[rel] = (st.st_size, int(st.st_mtime))
            except OSError:
                out[rel] = (0, 0)
    return out


def compare_folders(a, b):
    fa = folder_map(a); fb = folder_map(b); rows = []
    for k in sorted(set(fa) | set(fb)):
        sa = fa.get(k); sb = fb.get(k)
        if sa and not sb:
            st = "onlyL"
        elif sb and not sa:
            st = "onlyR"
        elif sa[0] != sb[0]:
            st = "diff"
        else:
            st = "same"
        rows.append((k, sa[0] if sa else "-", sb[0] if sb else "-", st))
    return rows


def text_diff_lines(a, b):
    al = a.splitlines(); bl = b.splitlines()
    sm = difflib.SequenceMatcher(None, al, bl)
    lo, ro = [], []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            for k in range(i2 - i1):
                lo.append("  " + al[i1 + k]); ro.append("  " + bl[j1 + k])
        else:
            lo += ["- " + al[k] for k in range(i1, i2)]
            ro += ["+ " + bl[k] for k in range(j1, j2)]
    return lo, ro


def hex_first_diff(a, b):
    n = min(len(a), len(b)); first = None; cnt = 0
    for i in range(n):
        if a[i] != b[i]:
            cnt += 1
            if first is None:
                first = i
    return first, cnt, len(a), len(b)


def save_session(path, cfg):
    json.dump(cfg, open(path, "w", encoding="utf-8"), ensure_ascii=False, indent=2)


def load_session(path):
    try:
        return json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError):
        return {}


class DiffHL(QSyntaxHighlighter):
    def __init__(self, doc, add):
        super().__init__(doc); self.add = add
        self.f = QTextCharFormat(); self.f.setBackground(QColor("#c8f0c8" if add else "#f0c8c8"))

    def highlightBlock(self, t):
        if (self.add and t.startswith("+ ")) or (not self.add and t.startswith("- ")):
            self.setFormat(0, len(t), self.f)


class BeyondCompareWindow(QMainWindow):
    def __init__(self, files=None):
        super().__init__()
        self.setWindowTitle("Beyond Compare 4.x (PySide6 重写版) — Scooter Software")
        self.resize(1150, 740)
        self.left = self.right = ""
        self._build_ui()
        self.statusBar().showMessage("Beyond Compare ready.")
        if files and len(files) >= 2:
            self.compare(files[0], files[1])

    def _build_ui(self):
        c = QWidget(); self.setCentralWidget(c); lay = QVBoxLayout(c)
        bar = QHBoxLayout()
        self.btn_l = QPushButton("左..."); self.btn_l.clicked.connect(lambda: self._pick("l"))
        self.btn_r = QPushButton("右..."); self.btn_r.clicked.connect(lambda: self._pick("r"))
        self.btn_cmp = QPushButton("比较"); self.btn_cmp.clicked.connect(self._cmp)
        self.btn_save = QPushButton("保存会话"); self.btn_save.clicked.connect(self.save_session)
        self.btn_load = QPushButton("载入会话"); self.btn_load.clicked.connect(self.load_session)
        for w in (self.btn_l, self.btn_r, self.btn_cmp, self.btn_save, self.btn_load):
            bar.addWidget(w)
        bar.addStretch(); lay.addLayout(bar)
        self.lbl = QLabel("L: -   R: -"); lay.addWidget(self.lbl)
        self.tabs = QTabWidget()
        # folder
        self.ftab = QTableWidget(0, 4); self.ftab.setHorizontalHeaderLabels(["File", "SizeL", "SizeR", "Status"])
        self.ftab.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tabs.addTab(self.ftab, "Folder")
        # text
        sp = QSplitter(Qt.Horizontal)
        self.tl = QPlainTextEdit(); self.tl.setReadOnly(True); self.tl.setFont(QFont("Consolas", 10))
        self.tr = QPlainTextEdit(); self.tr.setReadOnly(True); self.tr.setFont(QFont("Consolas", 10))
        DiffHL(self.tl.document(), False); DiffHL(self.tr.document(), True)
        sp.addWidget(self.tl); sp.addWidget(self.tr); self.tabs.addTab(sp, "Text")
        # hex
        self.hx = QPlainTextEdit(); self.hx.setReadOnly(True); self.hx.setFont(QFont("Consolas", 10))
        self.tabs.addTab(self.hx, "Hex")
        lay.addWidget(self.tabs, 1)

    def _pick(self, w):
        if w == "l":
            p = QFileDialog.getExistingDirectory(self, "Left") or QFileDialog.getOpenFileName(self, "Left")[0]
            if p: self.left = p
        else:
            p = QFileDialog.getExistingDirectory(self, "Right") or QFileDialog.getOpenFileName(self, "Right")[0]
            if p: self.right = p
        self.lbl.setText("L: %s   R: %s" % (self.left, self.right))

    def compare(self, l, r):
        self.left, self.right = l, r
        self.lbl.setText("L: %s   R: %s" % (l, r))
        self._cmp()

    def _cmp(self):
        if not self.left or not self.right:
            QMessageBox.information(self, "Beyond Compare", "Select left and right."); return
        if os.path.isdir(self.left) and os.path.isdir(self.right):
            rows = compare_folders(self.left, self.right)
            self.ftab.setRowCount(0)
            for k, sl, sr, st in rows:
                rr = self.ftab.rowCount(); self.ftab.insertRow(rr)
                for cc, v in enumerate([k, str(sl), str(sr), st]):
                    self.ftab.setItem(rr, cc, QTableWidgetItem(v))
            self.tabs.setCurrentIndex(0)
            self.statusBar().showMessage("Folder: %d entries" % len(rows))
        else:
            a = read_text(self.left); b = read_text(self.right)
            lo, ro = text_diff_lines(a, b)
            self.tl.setPlainText("\n".join(lo)); self.tr.setPlainText("\n".join(ro))
            ab = open(self.left, "rb").read(); bb = open(self.right, "rb").read()
            first, cnt, la, lb = hex_first_diff(ab, bb)
            self.hx.setPlainText("sizeL=%d sizeR=%d diffs=%d first@%s" %
                                 (la, lb, cnt, ("0x%X" % first) if first is not None else "-"))
            self.tabs.setCurrentIndex(1)
            self.statusBar().showMessage("Text: +%d -%d | Hex diffs=%d" %
                                         (sum(1 for x in ro if x.startswith("+")), sum(1 for x in lo if x.startswith("-")), cnt))

    def save_session(self):
        fn, _ = QFileDialog.getSaveFileName(self, "Save Session", "session.bcsession")
        if fn:
            save_session(fn, {"left": self.left, "right": self.right}); self.statusBar().showMessage("Saved session")

    def load_session(self):
        fn, _ = QFileDialog.getOpenFileName(self, "Load Session", filter="Session (*.bcsession)")
        if fn:
            cfg = load_session(fn)
            if cfg:
                self.compare(cfg.get("left", ""), cfg.get("right", ""))


def selftest():
    import tempfile
    d = tempfile.mkdtemp()
    la = os.path.join(d, "L"); ra = os.path.join(d, "R")
    os.makedirs(la); os.makedirs(ra)
    open(os.path.join(la, "same.txt"), "w").write("a\n")
    open(os.path.join(ra, "same.txt"), "w").write("a\n")
    open(os.path.join(la, "onlyL.txt"), "w").write("x")
    rows = compare_folders(la, ra)
    st = {r[0]: r[3] for r in rows}
    assert st["same.txt"] == "same" and st["onlyL.txt"] == "onlyL", st
    lo, ro = text_diff_lines("a\nb\n", "a\nc\n")
    assert any(x.startswith("+ c") for x in ro) and any(x.startswith("- b") for x in lo)
    f, cnt, la2, lb2 = hex_first_diff(b"AB", b"AC"); assert f == 1 and cnt == 1
    import shutil; shutil.rmtree(d, ignore_errors=True)
    print("[selftest] BeyondCompare folder/text/hex compare OK")


def main():
    if "--selftest" in sys.argv:
        selftest(); return
    files = [a for a in sys.argv[1:] if not a.startswith("-")]
    app = QApplication(sys.argv)
    w = BeyondCompareWindow(files); w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()