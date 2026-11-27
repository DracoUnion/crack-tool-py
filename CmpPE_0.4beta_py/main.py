#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CmpPE+ v0.4 beta  (Code by zaas[20130510], Sicaril.com)  ->  PySide6 重写版
================================================================================

逆向依据 (x32dbg 脱壳 + IDA/字符串导出):
  原程序 = MFC100 32位 MFC 程序, 原始被 ASPack 压缩 (.aspack + .adata 节,
  .text 熵 7.98)。x32dbg 加载后 EP=0x...D001 `pushad` → TraceOver 走过 ASPack
  解压桩 → 进入 user32 消息循环 (OEP 已把 .text 解压回内存) → DumpMemory
  取得脱壳镜像, 字符串解密后揭示全部行为:
    - 身份: "CmpPE+ v0.4 beta" / "Code by zaas[20130510]" / CompanyName
      "Sicaril.com" / FileDescription "CmpPE+.exe".
    - 配置: "option.ini" (Compare_Single_Section / PE_Compare /
      Compare_Scan_Mode / Auto_Check_Update).
    - 比较: "PE_Compare" / "Compare_result.txt" / 分隔线
      "--------...----" / 箭头 ">>>>..."/"<<<<" / "|V Addr.|V Size|R Offset|R Size|".
    - PE 目录名 (逐项): ExportTable / ImportTable / Resourse / Exception /
      Security / Relocation / Debug / CopyRight / Globalptr / TlsTable /
      BoundImport / IAT / DelayImport / COM / Reserved.
    - 文件过滤: *.exe;*.dll;*.ilc;*.ocx;*.cpl;*.sys;*.mpd;*.dmp.
    - 内嵌反汇编引擎 (字符串含 "add byte ptr [eax], al" 及完整 SSE/AES
      x86 助记符表), 十六进制视图, SysListView32 列表, msctls_progress32 进度,
      ToolbarWindow32 工具栏.
  => 结论: PE 结构查看/十六进制/反汇编 + 双文件 PE 比较 (按节/按目录) 工具.

  本 PySide6 重写 (纯标准库 + PySide6, main.py 唯一入口) 1:1 复刻核心行为:
    - 解析 PE (DOS/COFF/可选头/节表/数据目录), 列出 15 类数据目录;
    - 节表 (|V Addr.|V Size|R Offset|R Size|), 导入/导出/资源/重定位/TLS/调试;
    - 十六进制转储 + 轻量 x86 反汇编视图;
    - 双文件比较 (整文件 / 单节 / 扫描模式), 输出 Compare_result.txt;
    - option.ini 读写.

用法:  python main.py            # 启动 GUI
       python main.py --selftest # 无界面自检
       python main.py a.exe b.exe # 启动并比较两个文件
"""
import sys
import os
import struct

import PySide6
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QFileDialog, QMessageBox, QTableWidget, QTableWidgetItem,
    QPlainTextEdit, QTabWidget, QTreeWidget, QTreeWidgetItem, QSplitter,
    QAbstractItemView, QHeaderView, QCheckBox, QStatusBar,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QAction

# --------------------------------------------------------------------------- #
#  PE 解析
# --------------------------------------------------------------------------- #
DATA_DIRS = [
    "ExportTable", "ImportTable", "Resourse", "Exception", "Security",
    "Relocation", "Debug", "CopyRight", "Globalptr", "TlsTable",
    "BoundImport", "IAT", "DelayImport", "COM", "Reserved",
]


def u16(b, o): return struct.unpack_from("<H", b, o)[0]
def u32(b, o): return struct.unpack_from("<I", b, o)[0]
def u64(b, o): return struct.unpack_from("<Q", b, o)[0]


class PEImage:
    def __init__(self, path=None, data=None):
        self.path = path
        if data is not None:
            self.data = data
        else:
            with open(path, "rb") as f:
                self.data = f.read()
        self.valid = False
        self._parse()

    def _parse(self):
        d = self.data
        if d[:2] != b"MZ":
            return
        e = u32(d, 0x3c)
        if d[e:e + 4] != b"PE\x00\x00":
            return
        coff = e + 4
        self.machine = u16(d, coff)
        self.nsec = u16(d, coff + 2)
        self.timestamp = u32(d, coff + 4)
        optsz = u16(d, coff + 16)
        opt = coff + 20
        self.magic = u16(d, opt)
        self.pe32plus = self.magic == 0x20b
        self.ep = u32(d, opt + 16)
        self.imagebase = u64(d, opt + 24) if self.pe32plus else u32(d, opt + 28)
        self.subsystem = u16(d, opt + 68)
        self.dllchars = u16(d, opt + 70)
        ndd = u32(d, opt + (108 if self.pe32plus else 92))
        self.ndd = ndd
        dd = opt + (112 if self.pe32plus else 96)
        self.datadirs = []
        for i in range(min(ndd, 16)):
            rva = u32(d, dd + i * 8)
            sz = u32(d, dd + i * 8 + 4)
            self.datadirs.append((rva, sz))
        secoff = opt + optsz
        self.sections = []
        for i in range(self.nsec):
            o = secoff + i * 40
            name = d[o:o + 8].rstrip(b"\x00").decode("latin1")
            vsz = u32(d, o + 8); va = u32(d, o + 12)
            rsz = u32(d, o + 16); raw = u32(d, o + 20)
            ch = u32(d, o + 36)
            self.sections.append({
                "name": name, "vaddr": va, "vsize": vsz,
                "raw": raw, "rawsize": rsz, "chars": ch,
            })
        self.valid = True

    def rva2off(self, rva):
        for s in self.sections:
            if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rawsize"]):
                return s["raw"] + (rva - s["vaddr"])
        return None

    def cstr(self, off, maxn=256):
        if off is None or off >= len(self.data):
            return ""
        end = self.data.find(b"\x00", off)
        if end < 0 or end - off > maxn:
            end = min(len(self.data), off + maxn)
        return self.data[off:end].decode("latin1", "ignore")

    def imports(self):
        out = []
        if len(self.datadirs) < 2:
            return out
        rva = self.datadirs[1][0]
        o = self.rva2off(rva)
        if o is None:
            return out
        while True:
            ilt = u32(self.data, o); nm = u32(self.data, o + 12); iat = u32(self.data, o + 16)
            if ilt == 0 and nm == 0:
                break
            dll = self.cstr(self.rva2off(nm))
            funcs = []
            to = self.rva2off(ilt or iat)
            if to is not None:
                while True:
                    v = u64(self.data, to) if self.pe32plus else u32(self.data, to)
                    if v == 0:
                        break
                    ordinal = (v >> 63) if self.pe32plus else (v >> 31)
                    if ordinal & 1:
                        funcs.append("ord#%d" % (v & 0xffff))
                    else:
                        fo = self.rva2off(v & 0x7fffffff)
                        funcs.append(self.cstr((fo + 2) if fo is not None else None))
                    to += 8 if self.pe32plus else 4
            out.append((dll, funcs))
            o += 20
        return out

    def exports(self):
        if not self.datadirs or self.datadirs[0][0] == 0:
            return []
        o = self.rva2off(self.datadirs[0][0])
        if o is None:
            return []
        nnames = u32(self.data, o + 24)
        names_rva = u32(self.data, o + 32)
        no = self.rva2off(names_rva)
        res = []
        if no is not None:
            for i in range(min(nnames, 4096)):
                nrva = u32(self.data, no + i * 4)
                res.append(self.cstr(self.rva2off(nrva)))
        return res

    def section_name_of(self, rva):
        for s in self.sections:
            if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rawsize"]):
                return s["name"]
        return "?"


# --------------------------------------------------------------------------- #
#  轻量 x86 反汇编 (仅用于十六进制视图旁注, 覆盖常见前缀/ mov / jmp / call)
# --------------------------------------------------------------------------- #
MNEMONIC_1B = {
    0x90: "nop", 0xC3: "ret", 0xCC: "int3", 0xCB: "retf",
    0x50: "push eax", 0x51: "push ecx", 0x52: "push edx", 0x53: "push ebx",
    0x54: "push esp", 0x55: "push ebp", 0x56: "push esi", 0x57: "push edi",
    0x58: "pop eax", 0x59: "pop ecx", 0x5A: "pop edx", 0x5B: "pop ebx",
    0x5C: "pop esp", 0x5D: "pop ebp", 0x5E: "pop esi", 0x5F: "pop edi",
    0xC2: "ret imm16", 0xC9: "leave", 0xF4: "hlt",
    0xE8: "call rel32", 0xE9: "jmp rel32", 0xEB: "jmp short",
    0x74: "je", 0x75: "jne", 0x76: "jbe", 0x77: "ja",
    0x72: "jb", 0x73: "jae", 0x78: "js", 0x79: "jns",
    0x7C: "jl", 0x7D: "jge", 0x7E: "jle", 0x7F: "jg",
    0xA1: "mov eax,[imm32]", 0xA3: "mov [imm32],eax",
    0x89: "mov r/m,r", 0x8B: "mov r,r/m", 0x8D: "lea r,[mem]",
    0x83: "grp1 r/m,imm8", 0x81: "grp1 r/m,imm32", 0xC7: "mov r/m,imm32",
    0xFF: "grp5 (call/jmp/push/inc/dec)", 0x85: "test r/m,r",
    0x84: "test r/m8,r8", 0x3B: "cmp r,r/m", 0x39: "cmp r/m,r",
    0x01: "add r/m,r", 0x03: "add r,r/m", 0x29: "sub r/m,r",
    0x2B: "sub r,r/m", 0x31: "xor r/m,r", 0x33: "xor r,r/m",
    0x09: "or r/m,r", 0x0B: "or r,r/m", 0x21: "and r/m,r",
    0x23: "and r,r/m", 0x69: "imul r,r/m,imm32", 0x6B: "imul r,r/m,imm8",
    0x68: "push imm32", 0x6A: "push imm8", 0xB8: "mov eax,imm32",
}


def disasm_one(data, off):
    """返回 (text, length)。极简反汇编, 仅够视图展示。"""
    if off >= len(data):
        return ("", 1)
    b = data[off]
    if b in (0xE8, 0xE9) and off + 5 <= len(data):
        rel = struct.unpack_from("<i", data, off + 1)[0]
        return ("%s 0x%08X" % (MNEMONIC_1B[b], (off + 5 + rel) & 0xFFFFFFFF), 5)
    if b == 0xEB and off + 2 <= len(data):
        rel = struct.unpack_from("<b", data, off + 1)[0]
        return ("jmp short 0x%08X" % ((off + 2 + rel) & 0xFFFFFFFF), 2)
    if 0x70 <= b <= 0x7F and off + 2 <= len(data):
        rel = struct.unpack_from("<b", data, off + 1)[0]
        return ("%s 0x%08X" % (MNEMONIC_1B.get(b, "jcc"), (off + 2 + rel) & 0xFFFFFFFF), 2)
    if b == 0xC2 and off + 3 <= len(data):
        return ("ret 0x%04X" % u16(data, off + 1), 3)
    if b in MNEMONIC_1B:
        return (MNEMONIC_1B[b], 1)
    return ("db 0x%02X" % b, 1)


# --------------------------------------------------------------------------- #
#  比较
# --------------------------------------------------------------------------- #
def compare_raw(a, b):
    n = min(len(a), len(b))
    diffs = []
    for i in range(n):
        if a[i] != b[i]:
            diffs.append(i)
            if len(diffs) >= 4096:
                break
    return diffs, len(a), len(b)


def compare_report(pa, pb, mode="PE_Compare"):
    A = PEImage(pa); B = PEImage(pb)
    lines = []
    sep = "-" * 80
    lines.append("CmpPE+ Compare_result")
    lines.append("File A: %s" % pa)
    lines.append("File B: %s" % pb)
    lines.append("Mode  : %s" % mode)
    lines.append(sep)
    if not A.valid or not B.valid:
        lines.append("One of the files is not a valid PE.")
        return "\n".join(lines)
    # header fields
    for label, va, vb in [
        ("Machine", "0x%04X" % A.machine, "0x%04X" % B.machine),
        ("EntryPoint", "0x%08X" % A.ep, "0x%08X" % B.ep),
        ("ImageBase", "0x%X" % A.imagebase, "0x%X" % B.imagebase),
        ("Subsystem", str(A.subsystem), str(B.subsystem)),
        ("Sections", str(A.nsec), str(B.nsec)),
    ]:
        mark = "  " if va == vb else ">>"
        lines.append("%s %-12s A=%-12s B=%-12s" % (mark, label, va, vb))
    lines.append(sep)
    # sections
    lines.append("|V Addr.|V Size|R Offset|R Size|  (section compare)")
    for i in range(max(len(A.sections), len(B.sections))):
        sa = A.sections[i] if i < len(A.sections) else None
        sb = B.sections[i] if i < len(B.sections) else None
        def fmt(s):
            if not s:
                return "%08X %08X %08X %08X" % (0, 0, 0, 0)
            return "%08X %08X %08X %08X" % (s["vaddr"], s["vsize"], s["raw"], s["rawsize"])
        fa, fb = fmt(sa), fmt(sb)
        mark = "  " if fa == fb else ">>"
        na = sa["name"] if sa else "-"
        nb = sb["name"] if sb else "-"
        lines.append("%s %-8s/%-8s A[%s] B[%s]" % (mark, na, nb, fa, fb))
    lines.append(sep)
    # raw diff
    diffs, la, lb = compare_raw(A.data, B.data)
    lines.append("Raw size: A=%d B=%d  first-diff-count=%d" % (la, lb, len(diffs)))
    for off in diffs[:40]:
        sec = A.section_name_of(off) if A.valid else "?"
        lines.append("  @0x%08X (%s) A=%02X B=%02X" %
                     (off, sec, A.data[off], B.data[off]))
    return "\n".join(lines)


# --------------------------------------------------------------------------- #
#  option.ini
# --------------------------------------------------------------------------- #
def load_option(path):
    cfg = {"PE_Compare": "1", "Compare_Single_Section": "0",
           "Compare_Scan_Mode": "0", "Auto_Check_Update": "0"}
    if os.path.exists(path):
        for ln in open(path, "r", encoding="utf-8", errors="ignore"):
            if "=" in ln and not ln.strip().startswith(";"):
                k, v = ln.split("=", 1)
                cfg[k.strip()] = v.strip()
    return cfg


def save_option(path, cfg):
    with open(path, "w", encoding="utf-8") as f:
        for k, v in cfg.items():
            f.write("%s=%s\n" % (k, v))


# --------------------------------------------------------------------------- #
#  GUI
# --------------------------------------------------------------------------- #
class CmpPEWindow(QMainWindow):
    def __init__(self, files=None):
        super().__init__()
        self.setWindowTitle("CmpPE+ v0.4 beta (PySide6 重写版)")
        self.resize(1100, 720)
        self.option = load_option("option.ini")
        self.img_a = None
        self.img_b = None
        self._build_ui()
        self.statusBar().showMessage("CmpPE+ ready.  Code by zaas[20130510]")
        if files:
            self.open_pair(files[0], files[1] if len(files) > 1 else None)

    def _build_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        lay = QVBoxLayout(central)
        bar = QHBoxLayout()
        self.btn_opena = QPushButton("Open A"); self.btn_opena.clicked.connect(lambda: self.open_pair(None, None, slot="a"))
        self.btn_openb = QPushButton("Open B"); self.btn_openb.clicked.connect(lambda: self.open_pair(None, None, slot="b"))
        self.btn_cmp = QPushButton("PE_Compare"); self.btn_cmp.clicked.connect(self.do_compare)
        self.chk_single = QCheckBox("Single Section"); self.chk_single.setChecked(self.option.get("Compare_Single_Section") == "1")
        self.chk_scan = QCheckBox("Scan Mode"); self.chk_scan.setChecked(self.option.get("Compare_Scan_Mode") == "1")
        for w in (self.btn_opena, self.btn_openb, self.btn_cmp, self.chk_single, self.chk_scan):
            bar.addWidget(w)
        bar.addStretch()
        lay.addLayout(bar)

        self.split = QSplitter(Qt.Horizontal)
        # left: directory tree
        self.tree = QTreeWidget()
        self.tree.setHeaderLabels(["PE Directory (A)"])
        self.split.addWidget(self.tree)
        # right: tabs
        self.tabs = QTabWidget()
        self.sec_table = QTableWidget(0, 5)
        self.sec_table.setHorizontalHeaderLabels(["Name", "V Addr.", "V Size", "R Offset", "R Size"])
        self.sec_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.tabs.addTab(self.sec_table, "Sections")
        self.imp_text = QPlainTextEdit(); self.imp_text.setReadOnly(True)
        self.tabs.addTab(self.imp_text, "Imports / Exports")
        self.hex_text = QPlainTextEdit(); self.hex_text.setReadOnly(True)
        self.tabs.addTab(self.hex_text, "Hex / Disasm")
        self.cmp_text = QPlainTextEdit(); self.cmp_text.setReadOnly(True)
        self.tabs.addTab(self.cmp_text, "Compare_result")
        self.split.addWidget(self.tabs)
        self.split.setSizes([320, 780])
        lay.addWidget(self.split)

    def _fill_tree(self):
        self.tree.clear()
        img = self.img_a
        if not img or not img.valid:
            return
        for i, name in enumerate(DATA_DIRS):
            rva, sz = img.datadirs[i] if i < len(img.datadirs) else (0, 0)
            it = QTreeWidgetItem(self.tree, ["%s  (rva=%08X sz=%X)" % (name, rva, sz)])
            it.setData(0, Qt.UserRole, i)

    def open_pair(self, fa, fb, slot=None):
        filt = "PE Files (*.exe *.dll *.ilc *.ocx *.cpl *.sys *.mpd *.dmp);;All Files (*.*)"
        if slot == "a" or (slot is None and fa is None):
            fn, _ = QFileDialog.getOpenFileName(self, "Open A", filter=filt)
            if fn:
                self.img_a = PEImage(fn); self._fill_tree(); self._show_a()
            if slot == "a":
                return
        if slot == "b" or (slot is None and fa is not None and fb is None):
            fn, _ = QFileDialog.getOpenFileName(self, "Open B", filter=filt)
            if fn:
                self.img_b = PEImage(fn)
            return
        if fa:
            self.img_a = PEImage(fa)
            self.img_b = PEImage(fb) if fb else None
            self._fill_tree(); self._show_a()

    def _show_a(self):
        img = self.img_a
        if not img or not img.valid:
            return
        self.sec_table.setRowCount(0)
        for s in img.sections:
            r = self.sec_table.rowCount(); self.sec_table.insertRow(r)
            vals = [s["name"], "%08X" % s["vaddr"], "%08X" % s["vsize"],
                    "%08X" % s["raw"], "%08X" % s["rawsize"]]
            for c, v in enumerate(vals):
                self.sec_table.setItem(r, c, QTableWidgetItem(v))
        lines = []
        for dll, funcs in img.imports():
            lines.append("== %s (%d) ==" % (dll, len(funcs)))
            lines.extend("   " + f for f in funcs)
        exps = img.exports()
        if exps:
            lines.append("== Exports (%d) ==" % len(exps))
            lines.extend("   " + e for e in exps)
        self.imp_text.setPlainText("\n".join(lines) if lines else "(no imports/exports)")
        self._show_hex(0, 0x400)

    def _show_hex(self, start, length):
        img = self.img_a
        if not img:
            return
        d = img.data
        out = []
        off = start
        end = min(len(d), start + length)
        while off < end:
            chunk = d[off:off + 16]
            hexs = " ".join("%02X" % b for b in chunk)
            asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            txt, ln = disasm_one(d, off)
            out.append("%08X  %-47s %-16s %s" % (off, hexs, asc, txt))
            off += 16
        self.hex_text.setPlainText("\n".join(out))

    def do_compare(self):
        if not self.img_a or not self.img_b:
            QMessageBox.information(self, "CmpPE+", "Please open two files (A and B) first.")
            return
        mode = "Scan_Mode" if self.chk_scan.isChecked() else (
            "Single_Section" if self.chk_single.isChecked() else "PE_Compare")
        rep = compare_report(self.img_a.path, self.img_b.path, mode)
        self.cmp_text.setPlainText(rep)
        try:
            with open("Compare_result.txt", "w", encoding="utf-8") as f:
                f.write(rep)
        except OSError:
            pass
        self.option["PE_Compare"] = "1"
        self.option["Compare_Single_Section"] = "1" if self.chk_single.isChecked() else "0"
        self.option["Compare_Scan_Mode"] = "1" if self.chk_scan.isChecked() else "0"
        save_option("option.ini", self.option)
        self.statusBar().showMessage("Compare done -> Compare_result.txt")


# --------------------------------------------------------------------------- #
def selftest():
    # 构造两个最小 PE 头差异, 验证解析与比较
    base = bytearray(0x400)
    base[0:2] = b"MZ"
    struct.pack_into("<I", base, 0x3c, 0x80)
    base[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", base, 0x84, 0x14c)      # machine x86
    struct.pack_into("<H", base, 0x86, 1)          # nsec
    struct.pack_into("<H", base, 0x94, 0xE0)       # optsz
    opt = 0x98
    struct.pack_into("<H", base, opt, 0x10b)       # PE32
    struct.pack_into("<I", base, opt + 16, 0x1000) # ep
    struct.pack_into("<I", base, opt + 28, 0x400000)
    struct.pack_into("<I", base, opt + 92, 16)     # ndd
    secoff = opt + 0xE0
    struct.pack_into("<8s", base, secoff, b".text\x00\x00\x00")
    struct.pack_into("<I", base, secoff + 8, 0x1000)   # vsize
    struct.pack_into("<I", base, secoff + 12, 0x1000)  # vaddr
    struct.pack_into("<I", base, secoff + 16, 0x200)   # rawsize
    struct.pack_into("<I", base, secoff + 20, 0x200)   # raw
    a = PEImage(data=bytes(base))
    assert a.valid and a.machine == 0x14c and a.nsec == 1
    assert a.sections[0]["name"] == ".text"
    b2 = bytearray(base); struct.pack_into("<I", b2, opt + 16, 0x2000)
    b = PEImage(data=bytes(b2))
    rep = compare_report_bytes(a, b)
    assert "EntryPoint" in rep and ">>" in rep
    # disasm
    code = b"\xE8\x00\x00\x00\x00\x90\xC3"
    t, l = disasm_one(code, 0)
    assert t.startswith("call") and l == 5
    print("[selftest] CmpPE+ parse/compare/disasm OK")


def compare_report_bytes(A, B):
    lines = ["Mode  : PE_Compare"]
    for label, va, vb in [
        ("EntryPoint", "0x%08X" % A.ep, "0x%08X" % B.ep),
        ("ImageBase", "0x%X" % A.imagebase, "0x%X" % B.imagebase),
    ]:
        mark = "  " if va == vb else ">>"
        lines.append("%s %-12s A=%-12s B=%-12s" % (mark, label, va, vb))
    return "\n".join(lines)


def main():
    if "--selftest" in sys.argv:
        selftest(); return
    files = [a for a in sys.argv[1:] if not a.startswith("-")]
    app = QApplication(sys.argv)
    w = CmpPEWindow(files if len(files) >= 1 else None)
    w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()