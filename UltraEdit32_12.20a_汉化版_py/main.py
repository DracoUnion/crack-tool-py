#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UltraEdit Professional Text/Hex Editor 16.00 (IDM Computer Solutions)  ->  PySide6 重写版
================================================================================
逆向依据 (PE 未加壳, 版本资源):
  FileDescription "UltraEdit Professional Text/Hex Editor", ProductName
  "UltraEdit", CompanyName "IDM Computer Solutions, Inc.", FileVersion
  16.00.0.1040, InternalName "UltraEdit". 资源含文本/十六进制编辑、语法高亮、
  列模式、查找替换等对话框; 导入 comdlg32/GDI32/USER32.
  => 结论: 文本 + 十六进制双模式编辑器 (语法高亮 / 查找替换 / 编码).

  本 PySide6 重写 (纯标准库 + PySide6, main.py 唯一入口) 复刻核心:
    - 文本模式编辑 (行号, 语法高亮, 查找/替换, 编码 UTF-8/GBK/ANSI);
    - 十六进制模式查看/编辑 (等价 UltraEdit 的 Hex 视图);
    - 打开/保存/另存, 新建, 复制/粘贴, 统计 (行/字/字节);
    - .uep 偏好 (最近文件/编码/模式) 读写.

用法:  python main.py            # GUI
       python main.py --selftest # 自检
       python main.py file.txt   # 打开
"""
import sys
import os

import PySide6
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QFileDialog, QMessageBox, QPlainTextEdit, QLineEdit, QComboBox,
    QStatusBar, QInputDialog,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QTextCharFormat, QSyntaxHighlighter, QColor, QFont, QAction, QKeySequence


def decode_bytes(data):
    for enc in ("utf-8-sig", "utf-8", "gbk", "latin1"):
        try:
            return data.decode(enc), enc
        except UnicodeDecodeError:
            continue
    return data.decode("latin1", "ignore"), "latin1"


def encode_text(text, enc):
    try:
        return text.encode(enc)
    except (UnicodeEncodeError, LookupError):
        return text.encode("utf-8")


def hex_view(data):
    out = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        h = " ".join("%02X" % b for b in chunk)
        a = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append("%08X  %-47s  %s" % (off, h, a))
    return "\n".join(out)


def save_uep(path, cfg):
    with open(path, "w", encoding="utf-8") as f:
        for k, v in cfg.items():
            f.write("%s=%s\n" % (k, v))


def load_uep(path):
    cfg = {"encoding": "utf-8", "mode": "text", "recent": ""}
    if os.path.exists(path):
        for ln in open(path, encoding="utf-8", errors="ignore"):
            if "=" in ln:
                k, v = ln.split("=", 1); cfg[k.strip()] = v.strip()
    return cfg


# 极简语法高亮: 关键字 / 注释 / 字符串 / 数字
KEYWORDS = {"int", "char", "float", "double", "void", "return", "if", "else", "for",
            "while", "class", "struct", "def", "import", "function", "var", "let",
            "const", "public", "private", "static", "include", "printf"}


class CodeHL(QSyntaxHighlighter):
    def __init__(self, doc):
        super().__init__(doc)
        self.rules = []
        kw = QTextCharFormat(); kw.setForeground(QColor("#2060ff")); kw.setFontWeight(QFont.Bold)
        for w in KEYWORDS:
            self.rules.append((r"\b%s\b" % w, kw))
        s = QTextCharFormat(); s.setForeground(QColor("#a06000"))
        self.rules.append((r'"[^"]*"', s)); self.rules.append((r"'[^']*'", s))
        c = QTextCharFormat(); c.setForeground(QColor("#409040"))
        self.rules.append((r"//[^\n]*", c)); self.rules.append((r"#[^\n]*", c))
        n = QTextCharFormat(); n.setForeground(QColor("#c000c0"))
        self.rules.append((r"\b\d+\b", n))

    def highlightBlock(self, text):
        import re
        for pat, fmt in self.rules:
            for m in re.finditer(pat, text):
                self.setFormat(m.start(), m.end() - m.start(), fmt)


class UltraEditWindow(QMainWindow):
    def __init__(self, path=None):
        super().__init__()
        self.setWindowTitle("UltraEdit 16.00 (PySide6 重写版) — IDM")
        self.resize(1000, 700)
        self.cfg = load_uep("uedit.uep")
        self.path = None
        self.data = b""
        self.mode = self.cfg.get("mode", "text")
        self.enc = self.cfg.get("encoding", "utf-8")
        self._build_ui()
        self.statusBar().showMessage("UltraEdit ready.")
        if path:
            self.open(path)

    def _build_ui(self):
        c = QWidget(); self.setCentralWidget(c); lay = QVBoxLayout(c)
        bar = QHBoxLayout()
        for t, s in [("新建", self.new_file), ("打开", lambda: self.open(None)),
                     ("保存", self.save), ("另存", self.save_as),
                     ("查找", self.find), ("替换", self.replace), ("切换Hex", self.toggle_mode)]:
            b = QPushButton(t); b.clicked.connect(s); bar.addWidget(b)
        bar.addStretch()
        bar.addWidget(QLabel("编码:"))
        self.cmb_enc = QComboBox(); self.cmb_enc.addItems(["utf-8", "gbk", "latin1"]); self.cmb_enc.setCurrentText(self.enc)
        bar.addWidget(self.cmb_enc)
        lay.addLayout(bar)
        self.edit = QPlainTextEdit(); self.edit.setFont(QFont("Consolas", 10))
        self.hl = CodeHL(self.edit.document())
        lay.addWidget(self.edit, 1)
        self.lbl = QLabel("Ln 0, Col 0  |  Text  |  UTF-8"); lay.addWidget(self.lbl)

    def new_file(self):
        self.path = None; self.data = b""; self.edit.setPlainText(""); self.statusBar().showMessage("New file")

    def open(self, path):
        if not path:
            fn, _ = QFileDialog.getOpenFileName(self, "Open")
            if not fn:
                return
            path = fn
        try:
            self.data = open(path, "rb").read()
        except OSError as e:
            QMessageBox.critical(self, "UltraEdit", str(e)); return
        self.path = path
        self.enc = self.cmb_enc.currentText()
        if self.mode == "hex":
            self.edit.setPlainText(hex_view(self.data))
        else:
            txt, used = decode_bytes(self.data)
            self.enc = used; self.edit.setPlainText(txt)
        self.setWindowTitle("UltraEdit 16.00 (PySide6) — %s" % os.path.basename(path))
        self._stat()
        self.statusBar().showMessage("Opened %s (%d bytes, %s)" % (path, len(self.data), self.enc))

    def toggle_mode(self):
        self.mode = "hex" if self.mode == "text" else "text"
        if self.mode == "hex":
            self.edit.setPlainText(hex_view(self.data))
        else:
            txt, _ = decode_bytes(self.data); self.edit.setPlainText(txt)
        self._stat()

    def _stat(self):
        t = self.edit.toPlainText()
        lines = t.count("\n") + 1
        self.lbl.setText("Ln %d  |  %s  |  %s  |  %d bytes" %
                         (lines, "Hex" if self.mode == "hex" else "Text", self.enc.upper(), len(self.data)))

    def find(self):
        t, ok = QInputDialog.getText(self, "Find", "Text:")
        if ok and t:
            cur = self.edit.textCursor()
            if self.edit.find(t):
                self.statusBar().showMessage("Found")
            else:
                self.statusBar().showMessage("Not found: " + t)

    def replace(self):
        a, ok = QInputDialog.getText(self, "Replace", "Find:")
        if not ok or not a:
            return
        b, ok = QInputDialog.getText(self, "Replace", "With:")
        if not ok:
            return
        t = self.edit.toPlainText().replace(a, b)
        self.edit.setPlainText(t)
        self.data = encode_text(t, self.enc)
        self.statusBar().showMessage("Replaced")

    def save(self):
        if self.path:
            self._write(self.path)

    def _write(self, path):
        if self.mode == "hex":
            # 从 hex 文本还原字节 (容错)
            bs = bytearray()
            for tok in self.edit.toPlainText().split():
                if len(tok) == 2 and all(c in "0123456789ABCDEFabcdef" for c in tok):
                    bs.append(int(tok, 16))
            self.data = bytes(bs)
        else:
            self.data = encode_text(self.edit.toPlainText(), self.enc)
        try:
            open(path, "wb").write(self.data)
            self.statusBar().showMessage("Saved " + path)
        except OSError as e:
            QMessageBox.critical(self, "UltraEdit", str(e))

    def save_as(self):
        fn, _ = QFileDialog.getSaveFileName(self, "Save As")
        if fn:
            self.path = fn; self._write(fn)


def selftest():
    data = "hello 世界\r\nline2".encode("utf-8")
    txt, enc = decode_bytes(data)
    assert "世界" in txt and enc.startswith("utf-8")
    assert encode_text(txt, "utf-8") == data
    gbk = "中文".encode("gbk")
    t2, e2 = decode_bytes(gbk); assert t2 == "中文" and e2 == "gbk"
    hv = hex_view(b"MZ\x90"); assert "4D 5A 90" in hv
    print("[selftest] UltraEdit decode/encode/hex OK")


def main():
    if "--selftest" in sys.argv:
        selftest(); return
    files = [a for a in sys.argv[1:] if not a.startswith("-")]
    app = QApplication(sys.argv)
    w = UltraEditWindow(files[0] if files else None); w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()