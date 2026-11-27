#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UltraCompare Professional 5.00 (IDM Computer Solutions)  ->  PySide6 重写版
================================================================================
逆向依据 (PE 未加壳, 版本资源):
  FileDescription/ProductName "UltraCompare Professional", CompanyName
  "IDM Computer Solutions, Inc.", FileVersion 5.00, InternalName "UltraCompare".
  资源含文本比较 / 二进制比较 / 文件夹比较 / 合并 / 同步对话框.
  => 结论: 文件/文件夹比较 (文本 diff + 二进制 diff + 合并) 工具.

  本 PySide6 重写 (纯标准库 + PySide6, main.py 唯一入口) 复刻核心:
    - 文本比较 (difflib 行级 diff, 左右并排, 差异高亮, 跳转);
    - 二进制比较 (逐字节, 首个差异定位);
    - 文件夹比较 (两目录文件清单 + 大小/时间/缺失 对比);
    - 合并 (把 B 的差异行并入 A, 输出合并文件);
    - 统计 (增/删/改 行数).

用法:  python main.py            # GUI
       python main.py --selftest # 自检
       python main.py a b        # 比较两文件
"""
import sys
import os
import difflib

import PySide6
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QFileDialog, QMessageBox, QPlainTextEdit, QSplitter, QComboBox,
    QStatusBar, QTableWidget, QTableWidgetItem, QAbstractItemView,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QTextCharFormat, QSyntaxHighlighter, QColor, QFont


def read_text(path):
    data = open(path, "rb").read()
    for enc in ("utf-8-sig", "utf-8", "gbk", "latin1"):
        try:
            return data.decode(enc), enc
        except UnicodeDecodeError:
            continue
    return data.decode("latin1", "ignore"), "latin1"


def text_diff(a, b):
    """返回 (opcodes, sm) 供 GUI/合并使用。"""
    sm = difflib.SequenceMatcher(None, a, b)
    return sm.get_opcodes(), sm


def diff_stats(opcodes):
    ins = sum(1 for t, *_ in opcodes if t in ("insert", "replace"))
    dele = sum(1 for t, *_ in opcodes if t in ("delete", "replace"))
    same = sum(i2 - i1 for t, i1, i2, _, _ in opcodes if t == "equal")
    return ins, dele, same


def binary_diff(a, b):
    n = min(len(a), len(b)); first = None; count = 0
    for i in range(n):
        if a[i] != b[i]:
            count += 1
            if first is None:
                first = i
    return first, count, len(a), len(b)


def folder_list(path):
    out = {}
    for root, _, files in os.walk(path):
        for f in files:
            fp = os.path.join(root, f)
            rel = os.path.relpath(fp, path)
            try:
                st = os.stat(fp)
                out[rel] = (st.st_size, int(st.st_mtime))
            except OSError:
                out[rel] = (0, 0)
    return out


def merge_text(a_lines, b_lines):
    sm = difflib.SequenceMatcher(None, a_lines, b_lines)
    out = []
    for tag, i1, i2, j1, j2 in sm.get_opcodes():
        if tag == "equal":
            out.extend(a_lines[i1:i2])
        elif tag in ("insert", "replace"):
            out.extend(b_lines[j1:j2])
        # delete -> 丢弃
    return out


class DiffHL(QSyntaxHighlighter):
    def __init__(self, doc, add=True):
        super().__init__(doc)
        self.fmt = QTextCharFormat()
        self.fmt.setBackground(QColor("#c8f0c8" if add else "#f0c8c8"))
        self.add = add

    def highlightBlock(self, text):
        if self.add and text.startswith("+ "):
            self.setFormat(0, len(text), self.fmt)
        elif not self.add and text.startswith("- "):
            self.setFormat(0, len(text), self.fmt)


class UltraCompareWindow(QMainWindow):
    def __init__(self, files=None):
        super().__init__()
        self.setWindowTitle("UltraCompare Professional 5.00 (PySide6 重写版) — IDM")
        self.resize(1100, 720)
        self.a = b""; self.b = b""
        self.ta = self.tb = ""
        self._build_ui()
        self.statusBar().showMessage("UltraCompare ready.")
        if files and len(files) >= 2:
            self.open(files[0], files[1])

    def _build_ui(self):
        c = QWidget(); self.setCentralWidget(c); lay = QVBoxLayout(c)
        bar = QHBoxLayout()
        self.btn_a = QPushButton("选择 A"); self.btn_a.clicked.connect(lambda: self._pick("a"))
        self.btn_b = QPushButton("选择 B"); self.btn_b.clicked.connect(lambda: self._pick("b"))
        self.btn_text = QPushButton("文本比较"); self.btn_text.clicked.connect(self.cmp_text)
        self.btn_bin = QPushButton("二进制比较"); self.btn_bin.clicked.connect(self.cmp_bin)
        self.btn_dir = QPushButton("文件夹比较"); self.btn_dir.clicked.connect(self.cmp_dir)
        self.btn_merge = QPushButton("合并 B->A"); self.btn_merge.clicked.connect(self.do_merge)
        for w in (self.btn_a, self.btn_b, self.btn_text, self.btn_bin, self.btn_dir, self.btn_merge):
            bar.addWidget(w)
        bar.addStretch(); lay.addLayout(bar)
        self.lbl = QLabel("A: -    B: -"); lay.addWidget(self.lbl)

        self.split = QSplitter(Qt.Horizontal)
        self.left = QPlainTextEdit(); self.left.setReadOnly(True); self.left.setFont(QFont("Consolas", 10))
        self.right = QPlainTextEdit(); self.right.setReadOnly(True); self.right.setFont(QFont("Consolas", 10))
        DiffHL(self.left.document(), add=False); DiffHL(self.right.document(), add=True)
        self.split.addWidget(self.left); self.split.addWidget(self.right)
        lay.addWidget(self.split, 1)
        self.dirtab = QTableWidget(0, 4); self.dirtab.setHorizontalHeaderLabels(["File", "SizeA", "SizeB", "Status"])
        self.dirtab.setEditTriggers(QAbstractItemView.NoEditTriggers); self.dirtab.setMaximumHeight(180)
        lay.addWidget(self.dirtab)

    def _pick(self, which):
        fn, _ = QFileDialog.getOpenFileName(self, "Select " + which.upper())
        if not fn:
            return
        if which == "a":
            self.a = open(fn, "rb").read(); self.ta, _ = read_text(fn); self.left.setPlainText(self.ta)
        else:
            self.b = open(fn, "rb").read(); self.tb, _ = read_text(fn); self.right.setPlainText(self.tb)
        self.lbl.setText("A: %d bytes    B: %d bytes" % (len(self.a), len(self.b)))

    def open(self, fa, fb):
        self.a = open(fa, "rb").read(); self.ta, _ = read_text(fa)
        self.b = open(fb, "rb").read(); self.tb, _ = read_text(fb)
        self.left.setPlainText(self.ta); self.right.setPlainText(self.tb)
        self.lbl.setText("A: %s (%d)   B: %s (%d)" % (os.path.basename(fa), len(self.a), os.path.basename(fb), len(self.b)))
        self.cmp_text()

    def cmp_text(self):
        if not self.ta and not self.tb:
            QMessageBox.information(self, "UltraCompare", "Select A and B first."); return
        al = self.ta.splitlines(); bl = self.tb.splitlines()
        sm = difflib.SequenceMatcher(None, al, bl)
        lo, ro = [], []
        for tag, i1, i2, j1, j2 in sm.get_opcodes():
            if tag == "equal":
                for k in range(i2 - i1):
                    lo.append("  " + al[i1 + k]); ro.append("  " + bl[j1 + k])
            else:
                for k in range(i1, i2):
                    lo.append("- " + al[k])
                for k in range(j1, j2):
                    ro.append("+ " + bl[k])
        self.left.setPlainText("\n".join(lo)); self.right.setPlainText("\n".join(ro))
        ins, dele, same = diff_stats(sm.get_opcodes())
        self.statusBar().showMessage("Text compare: +%d -%d  (equal %d lines)" % (ins, dele, same))

    def cmp_bin(self):
        if not self.a and not self.b:
            QMessageBox.information(self, "UltraCompare", "Select A and B first."); return
        first, count, la, lb = binary_diff(self.a, self.b)
        self.statusBar().showMessage("Binary: sizeA=%d sizeB=%d diffs=%d first@%s" %
                                     (la, lb, count, ("0x%X" % first) if first is not None else "-"))

    def cmp_dir(self):
        da = QFileDialog.getExistingDirectory(self, "Dir A")
        if not da:
            return
        db = QFileDialog.getExistingDirectory(self, "Dir B")
        if not db:
            return
        fa = folder_list(da); fb = folder_list(db)
        self.dirtab.setRowCount(0)
        for k in sorted(set(fa) | set(fb)):
            r = self.dirtab.rowCount(); self.dirtab.insertRow(r)
            sa = fa.get(k, (None,))[0]; sb = fb.get(k, (None,))[0]
            status = "same" if sa == sb and sa is not None else ("onlyA" if sb is None else ("onlyB" if sa is None else "diff"))
            for c, v in enumerate([k, str(sa), str(sb), status]):
                self.dirtab.setItem(r, c, QTableWidgetItem(v))
        self.statusBar().showMessage("Folder compare: %d files" % self.dirtab.rowCount())

    def do_merge(self):
        if not self.ta and not self.tb:
            return
        merged = merge_text(self.ta.splitlines(), self.tb.splitlines())
        fn, _ = QFileDialog.getSaveFileName(self, "Save Merged", "merged.txt")
        if fn:
            open(fn, "w", encoding="utf-8").write("\n".join(merged))
            self.statusBar().showMessage("Merged -> %s (%d lines)" % (fn, len(merged)))


def selftest():
    a = "line1\nline2\nline3\n"
    b = "line1\nline2 changed\nline3\nline4\n"
    ops, sm = text_diff(a.splitlines(), b.splitlines())
    ins, dele, same = diff_stats(ops)
    assert ins >= 1 and same >= 2, (ins, dele, same)
    merged = merge_text(a.splitlines(), b.splitlines())
    assert "line4" in merged and "line2 changed" in merged
    fa, cnt, la, lb = binary_diff(b"ABC", b"AXC")
    assert fa == 1 and cnt == 1
    print("[selftest] UltraCompare diff/merge/binary OK (+%d -%d)" % (ins, dele))


def main():
    if "--selftest" in sys.argv:
        selftest(); return
    files = [a for a in sys.argv[1:] if not a.startswith("-")]
    app = QApplication(sys.argv)
    w = UltraCompareWindow(files); w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()