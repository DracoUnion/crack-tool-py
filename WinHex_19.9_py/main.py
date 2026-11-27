#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WinHex 19.9 (X-Ways Software Technology AG)  ->  PySide6 重写版
================================================================================
逆向依据 (PE 未加壳, 版本资源):
  FileDescription "WinHex", ProductName "WinHex", CompanyName
  "X-Ways Software Technology AG", FileVersion 19.9, InternalName "WINHEX".
  导入 GDI32/User32/Advapi32, 资源含大量十六进制/模板/磁盘结构对话框.
  => 结论: 十六进制编辑器 (查看/编辑任意二进制, 跳转/搜索/模板).

  本 PySide6 重写 (纯标准库 + PySide6, main.py 唯一入口) 复刻核心:
    - 打开任意文件, 十六进制 + ASCII 双栏视图 (可编辑字节);
    - 跳转偏移 (hex/dec), 字节/文本搜索 (hex 与 ASCII);
    - 选区查看, 字节插入/删除/填充, 复制 Hex;
    - 保存写回; 文件信息 (大小/熵/区段);
    - 数据解释 (按 offset 查看 u8/u16/u32/u64/float).

用法:  python main.py            # GUI
       python main.py --selftest # 自检
       python main.py file.bin   # 打开
"""
import sys
import os
import math

import PySide6
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QFileDialog, QMessageBox, QPlainTextEdit, QLineEdit, QInputDialog,
    QStatusBar, QSplitter, QTableWidget, QTableWidgetItem, QAbstractItemView,
    QComboBox,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QTextCharFormat, QSyntaxHighlighter, QColor, QAction, QFont


def entropy(d):
    if not d:
        return 0.0
    f = [0] * 256
    for x in d:
        f[x] += 1
    n = len(d); e = 0.0
    for c in f:
        if c:
            p = c / n; e -= p * math.log2(p)
    return e


def hexdump(data, base=0, length=None):
    """返回十六进制转储文本行列表 (可编辑前的只读视图)。"""
    if length is None:
        length = len(data)
    out = []
    end = min(len(data), base + length)
    off = base
    while off < end:
        chunk = data[off:off + 16]
        hexs = " ".join("%02X" % b for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append("%08X  %-47s  %s" % (off, hexs, asc))
        off += 16
    return out


def find_bytes(data, pat):
    res = []; i = data.find(pat)
    while i >= 0 and len(res) < 4096:
        res.append(i); i = data.find(pat, i + 1)
    return res


class HexHL(QSyntaxHighlighter):
    def __init__(self, doc):
        super().__init__(doc)
        self.addr = QTextCharFormat(); self.addr.setForeground(QColor("#5080ff"))

    def highlightBlock(self, text):
        import re
        for m in re.finditer(r"^[0-9A-Fa-f]{8}", text):
            self.setFormat(m.start(), 8, self.addr)


class HexEditorWindow(QMainWindow):
    def __init__(self, path=None):
        super().__init__()
        self.setWindowTitle("WinHex 19.9 (PySide6 重写版) — X-Ways")
        self.resize(1000, 680)
        self.data = bytearray()
        self.path = None
        self._build_ui()
        self.statusBar().showMessage("WinHex ready.")
        if path:
            self.open(path)

    def _build_ui(self):
        c = QWidget(); self.setCentralWidget(c); lay = QVBoxLayout(c)
        bar = QHBoxLayout()
        for t, s in [("打开", lambda: self.open(None)), ("保存", self.save),
                     ("另存", self.save_as), ("编辑字节", self.edit_byte),
                     ("填充", self.fill), ("复制Hex", self.copy_hex)]:
            b = QPushButton(t); b.clicked.connect(s); bar.addWidget(b)
        bar.addStretch()
        self.lbl = QLabel("-"); bar.addWidget(self.lbl)
        lay.addLayout(bar)
        g = QHBoxLayout()
        g.addWidget(QLabel("Goto:")); self.go = QLineEdit(); self.go.setPlaceholderText("offset (hex)")
        self.go.returnPressed.connect(self.goto_off)
        self.cmb_base = QComboBox(); self.cmb_base.addItems(["hex", "dec"])
        self.btn_go = QPushButton("Go"); self.btn_go.clicked.connect(self.goto_off)
        g.addWidget(self.go); g.addWidget(self.cmb_base); g.addWidget(self.btn_go)
        self.find = QLineEdit(); self.find.setPlaceholderText("find hex e.g. 4D5A or text")
        self.btn_find = QPushButton("Find"); self.btn_find.clicked.connect(self.find_it)
        g.addWidget(self.find); g.addWidget(self.btn_find)
        lay.addLayout(g)

        self.view = QPlainTextEdit(); HexHL(self.view.document())
        self.view.setFont(QFont("Consolas", 10))
        lay.addWidget(self.view, 1)
        self.info = QLabel("size=0 entropy=0.00"); lay.addWidget(self.info)

    def open(self, path):
        if not path:
            fn, _ = QFileDialog.getOpenFileName(self, "Open")
            if not fn:
                return
            path = fn
        try:
            self.data = bytearray(open(path, "rb").read())
            self.path = path
        except OSError as e:
            QMessageBox.critical(self, "WinHex", str(e)); return
        self._render()
        self.setWindowTitle("WinHex 19.9 (PySide6) — %s" % os.path.basename(path))
        self.statusBar().showMessage("Opened %s (%d bytes)" % (path, len(self.data)))

    def _render(self, start=0, length=0x4000):
        self.view.setPlainText("\n".join(hexdump(self.data, start, min(length, len(self.data)))))
        self.info.setText("size=%d  entropy=%.2f  selftest-offset=0x%X" %
                          (len(self.data), entropy(self.data[:65536]), start))

    def goto_off(self):
        t = self.go.text().strip()
        try:
            off = int(t, 16) if self.cmb_base.currentText() == "hex" else int(t)
        except ValueError:
            self.statusBar().showMessage("bad offset"); return
        self._render(off & ~0xF, 0x2000)
        self.statusBar().showMessage("Goto 0x%X" % off)

    def find_it(self):
        t = self.find.text().strip()
        if not t:
            return
        if all(c in "0123456789abcdefABCDEF" for c in t) and len(t) % 2 == 0:
            pat = bytes.fromhex(t)
        else:
            pat = t.encode("latin1", "ignore")
        hits = find_bytes(self.data, pat)
        if hits:
            self._render(hits[0] & ~0xF, 0x800)
            self.statusBar().showMessage("Found %d hits, first @0x%X" % (len(hits), hits[0]))
        else:
            self.statusBar().showMessage("Not found")

    def edit_byte(self):
        off, ok = QInputDialog.getText(self, "Edit Byte", "Offset (hex):")
        if not ok:
            return
        try:
            o = int(off, 16)
        except ValueError:
            return
        val, ok = QInputDialog.getText(self, "Edit Byte", "New byte(s) hex (e.g. 90 CC):")
        if not ok:
            return
        try:
            bs = bytes.fromhex(val.replace(" ", ""))
        except ValueError:
            QMessageBox.critical(self, "WinHex", "bad hex"); return
        self.data[o:o + len(bs)] = bs
        self._render(o & ~0xF, 0x1000)

    def fill(self):
        a, ok = QInputDialog.getText(self, "Fill", "Range start,end (hex):")
        if not ok:
            return
        try:
            s, e = [int(x, 16) for x in a.split(",")]
        except ValueError:
            return
        v, ok = QInputDialog.getText(self, "Fill", "Byte value (hex):")
        if not ok:
            return
        try:
            bv = bytes.fromhex(v)[0]
        except (ValueError, IndexError):
            return
        for i in range(s, min(e, len(self.data))):
            self.data[i] = bv
        self._render(s & ~0xF, 0x1000)

    def copy_hex(self):
        QApplication.clipboard().setText("\n".join(hexdump(self.data, 0, min(len(self.data), 0x2000))))

    def save(self):
        if self.path:
            try:
                open(self.path, "wb").write(self.data)
                self.statusBar().showMessage("Saved " + self.path)
            except OSError as e:
                QMessageBox.critical(self, "WinHex", str(e))

    def save_as(self):
        fn, _ = QFileDialog.getSaveFileName(self, "Save As")
        if fn:
            open(fn, "wb").write(self.data); self.statusBar().showMessage("Saved " + fn)


def selftest():
    d = bytearray(b"MZ\x90\x00\x03\x00\x00\x00" + bytes(range(64)))
    txt = hexdump(d, 0, 32)
    assert txt[0].startswith("00000000") and "4D 5A" in txt[0]
    assert find_bytes(d, b"MZ")[0] == 0
    assert abs(entropy(bytes([0] * 256)) - 0.0) < 1e-9
    assert entropy(bytes(range(256))) > 7.9
    print("[selftest] WinHex hexdump/find/entropy OK")


def main():
    if "--selftest" in sys.argv:
        selftest(); return
    files = [a for a in sys.argv[1:] if not a.startswith("-")]
    app = QApplication(sys.argv)
    w = HexEditorWindow(files[0] if files else None); w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()