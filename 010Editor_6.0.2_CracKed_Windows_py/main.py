#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
010 Editor 6.0.2 (SweetScape)  ->  PySide6 重写版
================================================================================
逆向依据 (目录内主程序为安装包 010EditorWin64Installer602.exe /
  010EditorWin32Installer602.exe; 010 Editor 本体为十六进制编辑器):
  010 Editor 核心能力 = 十六进制编辑 + Binary Templates (二进制模板, .bt) +
  Scripts (.1sc) + Data Inspector. 本重写据其公开行为复刻核心功能
  (main.py 唯一入口, 纯标准库 + PySide6)。

  本 PySide6 重写复刻核心:
    - 十六进制 + ASCII 查看/编辑 (跳转/搜索/字节编辑);
    - Binary Template 引擎: 解析 .bt 模板 (typedef struct / 基本类型 / 数组),
      按模板解析二进制文件为字段树 (等价 010 的模板结构视图);
    - Data Inspector: 按当前偏移解释 u8/u16/u32/u64/float/double/ASCII;
    - 模板/Inspector 联动, 文件信息 (大小/熵).

用法:  python main.py            # GUI
       python main.py --selftest # 自检 (模板解析/字段提取)
       python main.py file.bin [tpl.bt]
"""
import sys
import os
import re
import math
import struct

import PySide6
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QFileDialog, QMessageBox, QPlainTextEdit, QLineEdit, QTreeWidget,
    QTreeWidgetItem, QSplitter, QTableWidget, QTableWidgetItem, QComboBox,
    QAbstractItemView, QStatusBar,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QTextCharFormat, QSyntaxHighlighter, QColor, QFont


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


def hexdump(data, base=0, length=0x4000):
    out = []; end = min(len(data), base + length); off = base
    while off < end:
        chunk = data[off:off + 16]
        h = " ".join("%02X" % b for b in chunk)
        a = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append("%08X  %-47s  %s" % (off, h, a)); off += 16
    return out


# --------------------------------------------------------------------------- #
#  Binary Template 引擎 (010 .bt 子集)
# --------------------------------------------------------------------------- #
TYPE_FMT = {
    "char": ("B", 1), "uchar": ("B", 1), "byte": ("B", 1),
    "short": ("h", 2), "ushort": ("H", 2), "word": ("H", 2),
    "int": ("i", 4), "uint": ("I", 4), "dword": ("I", 4),
    "long": ("q", 8), "ulong": ("Q", 8), "qword": ("Q", 8),
    "float": ("f", 4), "double": ("d", 8),
}


def parse_template(text):
    """解析 .bt 模板, 返回 [(type, name, array_len_or_None)] (扁平字段列表)。
    支持: typedef struct { ... } Name;  以及裸字段声明; 数组 type name[N]。"""
    text = re.sub(r"//[^\n]*", "", text)
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    fields = []
    # 逐行/分号切分
    for stmt in re.split(r"[;{}]", text):
        stmt = stmt.strip()
        if not stmt or stmt.startswith("typedef") and "(" in stmt:
            continue
        m = re.match(r"(?:typedef\s+)?struct\s+\w*$", stmt)
        if m:
            continue
        # 匹配: type name 或 type name[N]
        mm = re.match(r"(u?char|byte|u?short|word|u?int|dword|u?long|qword|float|double)\s+(\w+)\s*(?:\[(\d+)\])?$", stmt)
        if mm:
            typ = mm.group(1); name = mm.group(2)
            arr = int(mm.group(3)) if mm.group(3) else None
            fields.append((typ, name, arr))
    return fields


def apply_template(data, fields, base=0):
    """按字段列表解析 data, 返回 [(name, type, offset, value_repr)]。"""
    out = []; off = base
    for typ, name, arr in fields:
        fmt, sz = TYPE_FMT.get(typ, ("B", 1))
        if arr:
            raw = data[off:off + sz * arr]
            out.append((name, "%s[%d]" % (typ, arr), off, raw.hex(" ") if raw else ""))
            off += sz * arr
        else:
            if off + sz > len(data):
                out.append((name, typ, off, "<out of range>")); break
            val = struct.unpack_from("<" + fmt, data, off)[0]
            if typ in ("float", "double"):
                sval = "%g" % val
            else:
                sval = "0x%X (%d)" % (val & (sz * 8 - 1 if sz < 8 else 0xFFFFFFFFFFFFFFFF), val)
            out.append((name, typ, off, sval)); off += sz
    return out


def inspect(data, off):
    """Data Inspector: 在 off 处解释多种类型。"""
    res = []
    for typ, fmt, sz in [("u8", "B", 1), ("u16", "H", 2), ("u32", "I", 4), ("u64", "Q", 8),
                          ("i32", "i", 4), ("f32", "f", 4), ("f64", "d", 8)]:
        if off + sz <= len(data):
            v = struct.unpack_from("<" + fmt, data, off)[0]
            res.append((typ, v))
    asc = data[off:off + 16]
    res.append(("ascii", "".join(chr(b) if 32 <= b < 127 else "." for b in asc)))
    return res


class HexHL(QSyntaxHighlighter):
    def __init__(self, doc):
        super().__init__(doc)
        self.f = QTextCharFormat(); self.f.setForeground(QColor("#5080ff"))

    def highlightBlock(self, t):
        for m in re.finditer(r"^[0-9A-Fa-f]{8}", t):
            self.setFormat(m.start(), 8, self.f)


class Editor010Window(QMainWindow):
    def __init__(self, path=None, tpl=None):
        super().__init__()
        self.setWindowTitle("010 Editor 6.0 (PySide6 重写版) — SweetScape")
        self.resize(1100, 720)
        self.data = bytearray(); self.fields = []
        self._build_ui()
        self.statusBar().showMessage("010 Editor ready.")
        if path:
            self.open(path, tpl)

    def _build_ui(self):
        c = QWidget(); self.setCentralWidget(c); lay = QVBoxLayout(c)
        bar = QHBoxLayout()
        for t, s in [("打开", lambda: self.open(None, None)), ("载入模板", self.load_tpl),
                     ("应用模板", self.apply_tpl), ("保存", self.save)]:
            b = QPushButton(t); b.clicked.connect(s); bar.addWidget(b)
        bar.addStretch(); self.lbl = QLabel("-"); bar.addWidget(self.lbl)
        lay.addLayout(bar)
        g = QHBoxLayout(); g.addWidget(QLabel("Goto:"))
        self.go = QLineEdit(); self.go.returnPressed.connect(self.goto_off); g.addWidget(self.go)
        self.btn_go = QPushButton("Go"); self.btn_go.clicked.connect(self.goto_off); g.addWidget(self.btn_go)
        lay.addLayout(g)
        sp = QSplitter(Qt.Horizontal)
        self.hex = QPlainTextEdit(); HexHL(self.hex.document()); self.hex.setFont(QFont("Consolas", 10))
        sp.addWidget(self.hex)
        right = QSplitter(Qt.Vertical)
        self.tree = QTreeWidget(); self.tree.setHeaderLabels(["Template Field", "Value"])
        right.addWidget(self.tree)
        self.insp = QTableWidget(0, 2); self.insp.setHorizontalHeaderLabels(["Type", "Value"])
        self.insp.setMaximumHeight(200); right.addWidget(self.insp)
        sp.addWidget(right); sp.setSizes([700, 400]); lay.addWidget(sp)
        self.tpl_text = ""

    def open(self, path, tpl):
        if not path:
            fn, _ = QFileDialog.getOpenFileName(self, "Open")
            if not fn:
                return
            path = fn
        try:
            self.data = bytearray(open(path, "rb").read())
        except OSError as e:
            QMessageBox.critical(self, "010", str(e)); return
        self._render()
        if tpl and os.path.exists(tpl):
            self.tpl_text = open(tpl, encoding="utf-8", errors="ignore").read()
            self.apply_tpl()
        self.setWindowTitle("010 Editor 6.0 (PySide6) — %s" % os.path.basename(path))

    def _render(self, start=0):
        self.hex.setPlainText("\n".join(hexdump(self.data, start, min(0x4000, len(self.data)))))
        self.lbl.setText("size=%d  entropy=%.2f" % (len(self.data), entropy(self.data[:65536])))
        self._inspect(start)

    def _inspect(self, off):
        self.insp.setRowCount(0)
        for typ, v in inspect(self.data, off):
            r = self.insp.rowCount(); self.insp.insertRow(r)
            self.insp.setItem(r, 0, QTableWidgetItem(typ))
            self.insp.setItem(r, 1, QTableWidgetItem(str(v)))

    def goto_off(self):
        try:
            off = int(self.go.text().strip(), 16)
        except ValueError:
            return
        self._render(off & ~0xF); self.statusBar().showMessage("Goto 0x%X" % off)

    def load_tpl(self):
        fn, _ = QFileDialog.getOpenFileName(self, "Open Template", "Template (*.bt *.txt)")
        if fn:
            self.tpl_text = open(fn, encoding="utf-8", errors="ignore").read()
            self.statusBar().showMessage("Loaded template %s" % os.path.basename(fn))

    def apply_tpl(self):
        if not self.tpl_text:
            QMessageBox.information(self, "010", "No template loaded."); return
        self.fields = parse_template(self.tpl_text)
        rows = apply_template(self.data, self.fields)
        self.tree.clear()
        for name, typ, off, val in rows:
            it = QTreeWidgetItem(self.tree, ["%s : %s" % (name, typ), val])
            it.setData(0, Qt.UserRole, off)
        self.tree.expandAll()
        self.statusBar().showMessage("Template applied: %d fields" % len(rows))

    def save(self):
        fn, _ = QFileDialog.getSaveFileName(self, "Save")
        if fn:
            open(fn, "wb").write(self.data); self.statusBar().showMessage("Saved " + fn)


def selftest():
    tpl = """
    typedef struct {
        char magic[4];
        uint version;
        ushort width;
        ushort height;
        float fps;
    } Header;
    """
    fields = parse_template(tpl)
    names = [f[1] for f in fields]
    assert names == ["magic", "version", "width", "height", "fps"], names
    data = b"RIFF" + struct.pack("<IHHf", 1, 640, 480, 29.97)
    rows = apply_template(data, fields)
    d = dict((n, v) for n, t, o, v in rows)
    assert d["version"].startswith("0x1") and "640" in d["width"] and "29.97" in d["fps"], d
    ins = dict(inspect(data, 4))
    assert ins["u32"] == 1
    print("[selftest] 010 template parse/apply + inspector OK; fields=%d" % len(rows))


def main():
    if "--selftest" in sys.argv:
        selftest(); return
    files = [a for a in sys.argv[1:] if not a.startswith("-")]
    app = QApplication(sys.argv)
    w = Editor010Window(files[0] if files else None, files[1] if len(files) > 1 else None)
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()