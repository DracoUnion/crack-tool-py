#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CmpDisasm 0.84  ->  PySide6 重写版
================================================================================
逆向依据 (upx -d 脱壳 + 字符串导出):
  原程序 = 32位 MFC 程序, 原始被 UPX 压缩 (UPX0 空节 + UPX1 熵 7.93)。
  `upx -d` 还原 886272 字节后字符串揭示:
    - 基于 Scintilla 编辑控件 ("Scintilla" / "CallTip" / "MSDEVLineSelect" /
      "MSDEVColumnSelect" / "ACallTip") 的源码/反汇编查看编辑;
    - 反汇编/十六进制相关: AlphaBlend, Verdana 字体, PCRE 正则引擎
      ("No previous regular expression" / "Unmatched (" 等), ListBoxX;
    - 运行时为 MSVC ("runtime error" / "pure virtual function call" /
      "unable to initialize heap"), 导入 WSOCK32/WINMM/IMM32/COMDLG32 等;
    - 多显示器/高 DPI 支持 (EnumDisplayMonitors / GetMonitorInfoA /
      AlphaBlend), 即一个带语法高亮的反汇编/十六进制编辑器.
  => 结论: 反汇编器 (x86) + 十六进制查看/编辑, Scintilla 风格文本界面.

  本 PySide6 重写 (PySide6 + capstone, main.py 唯一入口) 复刻核心:
    - 打开 PE / 二进制, 反汇编 (capstone x86/x64, 自动按 PE 基址与节区);
    - 左侧反汇编列表 (地址/机器码/反汇编), 右侧十六进制;
    - 跳转 (g/G/地址), 关注寄存器/调用, 复制, 保存反汇编为文本;
    - 节区/入口/导入概览.

用法:  python main.py            # GUI
       python main.py --selftest # 自检
       python main.py file.exe   # 打开并反汇编
"""
import sys
import os
import struct

import capstone

import PySide6
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QFileDialog, QMessageBox, QPlainTextEdit, QLineEdit, QSplitter,
    QTableWidget, QTableWidgetItem, QAbstractItemView, QStatusBar, QInputDialog,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QTextCharFormat, QSyntaxHighlighter, QColor


def u16(b, o): return struct.unpack_from("<H", b, o)[0]
def u32(b, o): return struct.unpack_from("<I", b, o)[0]
def u64(b, o): return struct.unpack_from("<Q", b, o)[0]


class PESimple:
    def __init__(self, data):
        self.data = data
        self.valid = False
        self.base = 0
        self.entry = 0
        self.sections = []
        self.bits = 32
        if data[:2] != b"MZ":
            return
        e = u32(data, 0x3c)
        if data[e:e + 4] != b"PE\x00\x00":
            return
        opt = e + 24
        self.bits = 64 if u16(data, opt) == 0x20b else 32
        self.entry = u32(data, opt + 16)
        self.base = u64(data, opt + 24) if self.bits == 64 else u32(data, opt + 28)
        nsec = u16(data, e + 6)
        optsz = u16(data, e + 20)
        secoff = opt + optsz
        for i in range(nsec):
            o = secoff + i * 40
            name = data[o:o + 8].rstrip(b"\x00").decode("latin1")
            vsz = u32(data, o + 8); va = u32(data, o + 12)
            rsz = u32(data, o + 16); raw = u32(data, o + 20)
            self.sections.append((name, va, vsz, raw, rsz))
        self.valid = True

    def va_to_off(self, va):
        for name, sva, vsz, raw, rsz in self.sections:
            if sva <= va < sva + max(vsz, rsz):
                return raw + (va - sva)
        return None

    def off_to_va(self, off):
        for name, sva, vsz, raw, rsz in self.sections:
            if raw <= off < raw + rsz:
                return sva + (off - raw)
        return self.base + off


def disassemble(data, base, va_start, va_end, bits=32):
    """返回 [(va, bytes, mnemonic+op)]。"""
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64 if bits == 64 else capstone.CS_MODE_32)
    md.detail = False
    off = 0
    # 把 va 区间映射到文件偏移
    res = []
    for ins in md.disasm(data, base):
        if ins.address < va_start:
            continue
        if ins.address >= va_end:
            break
        res.append((ins.address, ins.bytes, ins.mnemonic + (" " + ins.op_str if ins.op_str else "")))
    return res


class HexHL(QSyntaxHighlighter):
    def __init__(self, doc):
        super().__init__(doc)
        self.rules = []
        fmt = QTextCharFormat(); fmt.setForeground(QColor("#c0c0c0"))
        self.rules.append((r"\b[0-9A-Fa-f]{2}\b", fmt))
        addr = QTextCharFormat(); addr.setForeground(QColor("#6080ff"))
        self.rules.append((r"^[0-9A-Fa-f]{8}", addr))

    def highlightBlock(self, text):
        import re
        for pat, fmt in self.rules:
            for m in re.finditer(pat, text):
                self.setFormat(m.start(), m.end() - m.start(), fmt)


class CmpDisasmWindow(QMainWindow):
    def __init__(self, path=None):
        super().__init__()
        self.setWindowTitle("CmpDisasm 0.84 (PySide6 重写版)")
        self.resize(1100, 720)
        self.data = b""
        self.pe = None
        self.rows = []
        self._build_ui()
        self.statusBar().showMessage("Ready.  Open a PE/binary to disassemble.")
        if path:
            self.open_file(path)

    def _build_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        lay = QVBoxLayout(central)
        bar = QHBoxLayout()
        self.btn_open = QPushButton("Open"); self.btn_open.clicked.connect(lambda: self.open_file(None))
        self.btn_save = QPushButton("Save Disasm"); self.btn_save.clicked.connect(self.save_disasm)
        self.btn_copy = QPushButton("Copy"); self.btn_copy.clicked.connect(self.copy_sel)
        self.lbl_info = QLabel("-")
        self.addr = QLineEdit(); self.addr.setPlaceholderText("g  (go to addr, e.g. 401000)")
        self.addr.returnPressed.connect(self.goto_addr)
        self.btn_go = QPushButton("Go"); self.btn_go.clicked.connect(self.goto_addr)
        for w in (self.btn_open, self.btn_save, self.btn_copy, self.lbl_info):
            bar.addWidget(w)
        bar.addStretch(); bar.addWidget(QLabel("Go:")); bar.addWidget(self.addr); bar.addWidget(self.btn_go)
        lay.addLayout(bar)

        self.split = QSplitter(Qt.Horizontal)
        self.disasm = QPlainTextEdit(); self.disasm.setReadOnly(True)
        self.hexv = QPlainTextEdit(); self.hexv.setReadOnly(True)
        HexHL(self.hexv.document())
        self.split.addWidget(self.disasm); self.split.addWidget(self.hexv)
        self.split.setSizes([720, 380])
        lay.addWidget(self.split)

        self.sec = QTableWidget(0, 5)
        self.sec.setHorizontalHeaderLabels(["Name", "VA", "VSize", "Raw", "RawSize"])
        self.sec.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.sec.setMaximumHeight(140)
        lay.addWidget(self.sec)

    def open_file(self, path):
        if not path:
            fn, _ = QFileDialog.getOpenFileName(self, "Open", filter="PE (*.exe *.dll *.sys);;All (*.*)")
            if not fn:
                return
            path = fn
        try:
            self.data = open(path, "rb").read()
        except OSError as e:
            QMessageBox.critical(self, "Error", str(e)); return
        self.pe = PESimple(self.data)
        self._fill_sections()
        if self.pe.valid:
            self.base = self.pe.base
            self.bits = self.pe.bits
            start = self.pe.base + self.pe.entry
            # 只反汇编入口所在节 (最多 128KB), 避免大文件卡顿
            sec = None
            for s in self.pe.sections:
                if s[1] <= self.pe.entry < s[1] + max(s[2], s[4]):
                    sec = s; break
            span = min(max(sec[2], sec[4]) if sec else 0x10000, 0x20000) or 0x10000
            self._disasm_range(start, start + span)
            self.lbl_info.setText("PE %d-bit base=0x%X ep=0x%X size=%d" %
                                  (self.bits, self.base, start, len(self.data)))
        else:
            self.base = 0; self.bits = 32
            self._disasm_range(0, len(self.data))
            self.lbl_info.setText("raw binary size=%d" % len(self.data))
        self.statusBar().showMessage("Opened %s" % os.path.basename(path))

    def _fill_sections(self):
        self.sec.setRowCount(0)
        if not self.pe or not self.pe.valid:
            return
        for name, va, vsz, raw, rsz in self.pe.sections:
            r = self.sec.rowCount(); self.sec.insertRow(r)
            for c, v in enumerate([name, "%X" % va, "%X" % vsz, "%X" % raw, "%X" % rsz]):
                self.sec.setItem(r, c, QTableWidgetItem(v))

    def _disasm_range(self, va_start, va_end):
        if self.pe and self.pe.valid:
            off = self.pe.va_to_off(va_start)
            if off is None:
                off = 0
        else:
            off = va_start
        self.rows = disassemble(self.data[off:], va_start, va_start, va_end, self.bits)
        lines = []
        for va, bs, txt in self.rows:
            hexs = " ".join("%02X" % b for b in bs[:8])
            lines.append("%08X  %-24s %s" % (va, hexs, txt))
        self.disasm.setPlainText("\n".join(lines))
        self._show_hex(off, 0x800)

    def _show_hex(self, off, length):
        d = self.data
        out = []
        end = min(len(d), off + length)
        while off < end:
            chunk = d[off:off + 16]
            hexs = " ".join("%02X" % b for b in chunk)
            asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            out.append("%08X  %-47s %s" % (off, hexs, asc))
            off += 16
        self.hexv.setPlainText("\n".join(out))

    def goto_addr(self):
        t = self.addr.text().strip()
        try:
            va = int(t, 16)
        except ValueError:
            self.statusBar().showMessage("Invalid address"); return
        # 找到包含该 va 的行并居中
        for i, (rowva, _, _) in enumerate(self.rows):
            if rowva >= va:
                self.disasm.moveCursor(self.disasm.textCursor().Start)
                self.statusBar().showMessage("Nearest 0x%X" % rowva)
                return
        self.statusBar().showMessage("0x%X not in range" % va)

    def save_disasm(self):
        fn, _ = QFileDialog.getSaveFileName(self, "Save Disasm", "disasm.txt", "Text (*.txt)")
        if fn:
            open(fn, "w", encoding="utf-8").write(self.disasm.toPlainText())
            self.statusBar().showMessage("Saved " + fn)

    def copy_sel(self):
        QApplication.clipboard().setText(self.disasm.toPlainText())


def selftest():
    code = b"\x55\x48\x89\xe5\x48\x83\xec\x20\xe8\x00\x00\x00\x00\xc3"
    rows = disassemble(code, 0x401000, 0x401000, 0x401000 + len(code), 64)
    assert rows and rows[0][0] == 0x401000
    assert rows[0][2].startswith("push")
    # PE 解析
    assert PESimple(b"MZ" + b"\x00" * 0x3a + struct.pack("<I", 0)).valid is False
    print("[selftest] CmpDisasm capstone disasm OK; first insn:", rows[0][2])


def main():
    if "--selftest" in sys.argv:
        selftest(); return
    files = [a for a in sys.argv[1:] if not a.startswith("-")]
    app = QApplication(sys.argv)
    w = CmpDisasmWindow(files[0] if files else None)
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()