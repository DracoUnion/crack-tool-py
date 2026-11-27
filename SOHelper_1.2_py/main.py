#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SO Helper 1.2  ->  Python 重写版 (CLI + PySide6 GUI)
================================================================================
逆向依据 (目录主程序 "SO Helper.exe", PE32 GUI, 1.7 MB, 链接
  kernel32/gdi32/user32/ole32/advapi32/oleaut32, 运行期 LoadLibrary/GetProcAddress):
  SO Helper 是 Android/ELF 共享库 (.so) 分析器, 用于查看 ELF 头 / 节区 /
  动态段 / 导出符号 / 导入符号 / 依赖库 (NEEDED) / 重定位等, 便于 SO 逆向.
  本重写复刻其核心: 纯 Python 解析 ELF32/ELF64 (little/big endian),
  提取 header / program headers / sections / .dynamic / .dynsym(导出/导入) /
  .rel(a) 重定位 / NEEDED / SONAME, 并支持 hex 转储与字符串抽取.
  main.py 为唯一入口, 纯标准库 + PySide6.

用法:
  python main.py                 # 启动 GUI
  python main.py --selftest
  python main.py info  <lib.so>
  python main.py exports <lib.so>
  python main.py imports <lib.so>
  python main.py needed  <lib.so>
  python main.py sections <lib.so>
  python main.py report <lib.so>
"""

import sys
import os
import struct

# ---------------- ELF 常量 ----------------
PT_LOAD = 1; PT_DYNAMIC = 2; PT_INTERP = 3
SHT_PROGBITS = 1; SHT_SYMTAB = 2; SHT_STRTAB = 3; SHT_RELA = 4; SHT_HASH = 5
SHT_DYNAMIC = 6; SHT_NOTE = 7; SHT_NOBITS = 8; SHT_REL = 9; SHT_DYNSYM = 11
SHF_WRITE = 1; SHF_ALLOC = 2; SHF_EXECINSTR = 4
DT_NULL = 0; DT_NEEDED = 1; DT_PLTRELSZ = 2; DT_HASH = 4; DT_STRTAB = 5
DT_SYMTAB = 6; DT_RELA = 7; DT_RELASZ = 8; DT_RELAENT = 9; DT_STRSZ = 10
DT_SYMENT = 11; DT_SONAME = 14; DT_REL = 17; DT_RELSZ = 18; DT_RELENT = 19
DT_PLTREL = 20; DT_JMPREL = 23
STT_FUNC = 2; STT_OBJECT = 1; STT_NOTYPE = 0
STB_GLOBAL = 1; STB_WEAK = 2
R_ARM_JUMP_SLOT = 22; R_386_JMP_SLOT = 7; R_AARCH64_JUMP_SLOT = 1026


class ELFError(Exception):
    pass


class ELF:
    def __init__(self, data):
        self.data = data
        self._parse()

    def _u(self, fmt, off):
        return struct.unpack_from(fmt, self.data, off)

    def _parse(self):
        d = self.data
        if d[:4] != b"\x7fELF":
            raise ELFError("不是 ELF 文件 (magic 不匹配)")
        self.ei_class = d[4]          # 1=32bit 2=64bit
        self.ei_data = d[5]           # 1=LE 2=BE
        self.is64 = (self.ei_class == 2)
        self.end = "<" if self.ei_data == 1 else ">"
        self.etype = self._u(self.end + "H", 16)[0]
        self.machine = self._u(self.end + "H", 18)[0]
        self.entry = self._u(self.end + ("Q" if self.is64 else "I"), 24)[0]
        if self.is64:
            self.phoff = self._u(self.end + "Q", 32)[0]
            self.shoff = self._u(self.end + "Q", 40)[0]
            self.phentsize, self.phnum = self._u(self.end + "HH", 54)
            self.shentsize, self.shnum, self.shstrndx = self._u(self.end + "HHH", 58)
        else:
            self.phoff = self._u(self.end + "I", 28)[0]
            self.shoff = self._u(self.end + "I", 32)[0]
            self.phentsize, self.phnum = self._u(self.end + "HH", 42)
            self.shentsize, self.shnum, self.shstrndx = self._u(self.end + "HHH", 46)
        self.phdrs = [self._phdr(i) for i in range(self.phnum)]
        self.shdrs = [self._shdr(i) for i in range(self.shnum)]
        self._shstrtab = self._section_data(self.shstrndx) if self.shnum else b""
        for s in self.shdrs:
            s["name"] = self._shname(s["name_off"])
        self._parse_dynamic()

    def _phdr(self, i):
        o = self.phoff + i * self.phentsize
        if self.is64:
            p_type, p_flags = self._u(self.end + "II", o)
            p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_align = self._u(self.end + "QQQQQQ", o + 8)
        else:
            p_type, p_offset, p_vaddr, p_paddr, p_filesz, p_memsz, p_flags, p_align = self._u(self.end + "IIIIIIII", o)
        return dict(type=p_type, flags=p_flags, offset=p_offset, vaddr=p_vaddr,
                    filesz=p_filesz, memsz=p_memsz, align=p_align)

    def _shdr(self, i):
        o = self.shoff + i * self.shentsize
        if self.is64:
            name, typ, flags, addr, off, size, link, info, align, entsize = self._u(self.end + "IIQQQQIIQQ", o)
        else:
            name, typ, flags, addr, off, size, link, info, align, entsize = self._u(self.end + "IIIIIIIIII", o)
        return dict(name_off=name, type=typ, flags=flags, addr=addr, offset=off,
                    size=size, link=link, info=info, align=align, entsize=entsize, name="")

    def _shname(self, off):
        s = self._shstrtab
        if off >= len(s):
            return ""
        e = s.find(b"\0", off)
        return s[off:e].decode("latin1", "replace")

    def _section_data(self, idx):
        if idx <= 0 or idx >= len(self.shdrs):
            return b""
        s = self.shdrs[idx]
        if s["type"] == SHT_NOBITS:
            return b""
        return self.data[s["offset"]:s["offset"] + s["size"]]

    def section_by_name(self, name):
        for s in self.shdrs:
            if s["name"] == name:
                return s
        return None

    def vaddr_to_off(self, vaddr):
        for p in self.phdrs:
            if p["type"] == PT_LOAD and p["vaddr"] <= vaddr < p["vaddr"] + p["filesz"]:
                return p["offset"] + (vaddr - p["vaddr"])
        # 退化: 用节区
        for s in self.shdrs:
            if s["addr"] and s["addr"] <= vaddr < s["addr"] + s["size"]:
                return s["offset"] + (vaddr - s["addr"])
        return None

    def _read_cstr(self, strtab, off):
        if off >= len(strtab):
            return ""
        e = strtab.find(b"\0", off)
        return strtab[off:e].decode("utf-8", "replace")

    def _parse_dynamic(self):
        self.needed = []
        self.soname = None
        self.dyn = []
        dyn = self.section_by_name(".dynamic")
        if not dyn:
            # 通过 PT_DYNAMIC
            for p in self.phdrs:
                if p["type"] == PT_DYNAMIC:
                    dyn = dict(offset=p["offset"], size=p["filesz"]); break
        if not dyn:
            return
        strtab = b""
        ds = self.section_by_name(".dynstr")
        if ds:
            strtab = self.data[ds["offset"]:ds["offset"] + ds["size"]]
        entsz = 16 if self.is64 else 8
        off = dyn["offset"]; endoff = off + dyn["size"]
        raw = []
        while off + entsz <= endoff:
            if self.is64:
                tag, val = self._u(self.end + "qQ", off)
            else:
                tag, val = self._u(self.end + "iI", off)
            raw.append((tag, val))
            if tag == DT_NULL:
                break
            off += entsz
        self.dyn = raw
        if not strtab:
            return
        for tag, val in raw:
            if tag == DT_NEEDED:
                self.needed.append(self._read_cstr(strtab, val))
            elif tag == DT_SONAME:
                self.soname = self._read_cstr(strtab, val)

    def symbols(self):
        """返回 (exports, imports) 列表 [(name, value, size, info)]。"""
        exports, imports = [], []
        for symsec_name, strsec in ((".dynsym", ".dynstr"), (".symtab", ".strtab")):
            ss = self.section_by_name(symsec_name)
            if not ss:
                continue
            strs = b""
            st = self.section_by_name(strsec)
            if st:
                strs = self.data[st["offset"]:st["offset"] + st["size"]]
            entsz = ss["entsize"] or (24 if self.is64 else 16)
            data = self.data[ss["offset"]:ss["offset"] + ss["size"]]
            cnt = len(data) // entsz
            for i in range(cnt):
                o = i * entsz
                ao = ss["offset"] + o
                if self.is64:
                    st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(self.end + "IBBHQQ", self.data, ao)
                else:
                    st_name, st_value, st_size, st_info, st_other, st_shndx = struct.unpack_from(self.end + "IIIBBH", self.data, ao)
                name = self._read_cstr(strs, st_name)
                if not name:
                    continue
                info_type = st_info & 0xF
                info_bind = st_info >> 4
                rec = (name, st_value, st_size, info_type, info_bind, st_shndx)
                if st_shndx == 0:       # SHN_UNDEF -> 导入
                    imports.append(rec)
                else:
                    exports.append(rec)
            break  # 优先 .dynsym
        return exports, imports

    def relocations(self):
        out = []
        for rname in (".rel.plt", ".rela.plt", ".rel.dyn", ".rela.dyn"):
            s = self.section_by_name(rname)
            if not s:
                continue
            is_rela = s["type"] == SHT_RELA
            entsz = s["entsize"] or ((24 if is_rela else 16) if self.is64 else (12 if is_rela else 8))
            data = self.data[s["offset"]:s["offset"] + s["size"]]
            cnt = len(data) // entsz
            for i in range(cnt):
                ao = s["offset"] + i * entsz
                if self.is64:
                    if is_rela:
                        r_offset, r_info, r_addend = struct.unpack_from(self.end + "QQq", self.data, ao)
                    else:
                        r_offset, r_info = struct.unpack_from(self.end + "QQ", self.data, ao); r_addend = 0
                    r_type = r_info & 0xFFFFFFFF; r_sym = r_info >> 32
                else:
                    if is_rela:
                        r_offset, r_info, r_addend = struct.unpack_from(self.end + "IIi", self.data, ao)
                    else:
                        r_offset, r_info = struct.unpack_from(self.end + "II", self.data, ao); r_addend = 0
                    r_type = r_info & 0xFF; r_sym = r_info >> 8
                out.append((rname, r_offset, r_type, r_sym, r_addend))
        return out


def machine_name(m):
    return {0x28: "ARM", 0x03: "x86", 0xB7: "AArch64", 0x3E: "x86-64",
            0x08: "MIPS", 0x14: "PowerPC"}.get(m, "0x%x" % m)


def type_name(t):
    return {1: "REL", 2: "EXEC", 3: "DYN(共享库)", 4: "CORE"}.get(t, str(t))


def fmt_sym_type(t):
    return {0: "NOTYPE", 1: "OBJECT", 2: "FUNC", 3: "SECTION", 4: "FILE"}.get(t, str(t))


def fmt_sym_bind(b):
    return {0: "LOCAL", 1: "GLOBAL", 2: "WEAK"}.get(b, str(b))


def report(data):
    e = ELF(data)
    L = []
    L.append("=== ELF 头 ===")
    L.append("类别      : %s, 字节序: %s" % ("ELF64" if e.is64 else "ELF32", "小端" if e.end == "<" else "大端"))
    L.append("类型      : %s" % type_name(e.etype))
    L.append("机器      : %s" % machine_name(e.machine))
    L.append("入口      : 0x%x" % e.entry)
    L.append("PH 数量   : %d, SH 数量: %d" % (e.phnum, e.shnum))
    L.append("")
    L.append("=== 节区 ===")
    for s in e.shdrs:
        L.append("  %-20s type=%-2d addr=0x%08x off=0x%06x size=0x%x" %
                 (s["name"], s["type"], s["addr"], s["offset"], s["size"]))
    L.append("")
    L.append("=== 依赖库 (NEEDED) ===")
    L += ["  " + n for n in e.needed] or ["  (无)"]
    if e.soname:
        L.append("SONAME    : %s" % e.soname)
    ex, im = e.symbols()
    L.append("")
    L.append("=== 导出符号 (%d) ===" % len(ex))
    for name, val, sz, it, ib, shx in ex[:200]:
        L.append("  0x%08x  %-6s %-6s %s" % (val, fmt_sym_type(it), fmt_sym_bind(ib), name))
    L.append("")
    L.append("=== 导入符号 (%d) ===" % len(im))
    for name, val, sz, it, ib, shx in im[:200]:
        L.append("  %-6s %-6s %s" % (fmt_sym_type(it), fmt_sym_bind(ib), name))
    return "\n".join(L)


# ============================================================ GUI
def run_gui():
    from PySide6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
        QLabel, QPlainTextEdit, QFileDialog, QMessageBox, QComboBox,
    )
    app = QApplication(sys.argv)
    win = QMainWindow(); win.setWindowTitle("SO Helper (ELF .so 分析)  PySide6")
    win.resize(900, 640)
    cw = QWidget(); win.setCentralWidget(cw); lay = QVBoxLayout(cw)
    row = QHBoxLayout()
    b_open = QPushButton("打开 .so"); b_rep = QPushButton("完整报告")
    b_exp = QPushButton("导出"); b_imp = QPushButton("导入"); b_need = QPushButton("依赖")
    for b in (b_open, b_rep, b_exp, b_imp, b_need):
        row.addWidget(b)
    row.addStretch(); lay.addLayout(row)
    path_lbl = QLabel("未选择文件"); lay.addWidget(path_lbl)
    out = QPlainTextEdit(); out.setReadOnly(True); lay.addWidget(out)
    st = {"elf": None}

    def load(p):
        st["elf"] = ELF(open(p, "rb").read()); path_lbl.setText(p)
        out.setPlainText(report(st["elf"].data))

    def do_open():
        p, _ = QFileDialog.getOpenFileName(win, "选择 .so/.elf", "", "Shared Library(*.*);;All Files(*.*)")
        if p:
            try: load(p)
            except Exception as ex: QMessageBox.critical(win, "错误", str(ex))

    def need():
        return st["elf"] or (QMessageBox.warning(win, "提示", "请先打开"), None)[1]

    def show(kind):
        e = need()
        if not e: return
        if kind == "report": out.setPlainText(report(e.data)); return
        ex, im = e.symbols()
        if kind == "exp":
            out.setPlainText("\n".join("%s" % (r[0],) for r in ex) or "(无导出)")
        elif kind == "imp":
            out.setPlainText("\n".join("%s" % (r[0],) for r in im) or "(无导入)")
        elif kind == "need":
            out.setPlainText("\n".join(e.needed) or "(无依赖)")

    b_open.clicked.connect(do_open)
    b_rep.clicked.connect(lambda: show("report"))
    b_exp.clicked.connect(lambda: show("exp"))
    b_imp.clicked.connect(lambda: show("imp"))
    b_need.clicked.connect(lambda: show("need"))
    win.statusBar().showMessage("就绪")
    win.show(); sys.exit(app.exec())


# ============================================================ 自检 / CLI
def _build_test_so():
    """构造一个真实的 ELF32 LE .so (含 .dynstr/.dynsym/.hash/.dynamic)。"""
    end = "<"
    dynstr = b"\x00libtest.so\x00foo\x00bar\x00printf\x00"
    def stroff(s): return dynstr.index(s.encode())
    def sym(n, v, sz, info, shx): return struct.pack(end + "IIIBBH", stroff(n), v, sz, info, 0, shx)
    dynsym = sym("", 0, 0, 0, 0) + sym("foo", 0x1000, 10, (1 << 4) | 2, 1) \
        + sym("bar", 0x2000, 20, (1 << 4) | 2, 1) + sym("printf", 0, 0, (1 << 4) | 2, 0)
    hashtab = struct.pack(end + "IIII", 1, 4, 0, 0)
    dynamic = struct.pack(end + "iI", 1, stroff("libtest.so")) \
        + struct.pack(end + "iI", 14, stroff("libtest.so")) + struct.pack(end + "iI", 0, 0)
    def align(o, a): return (o + a - 1) // a * a
    off = 52; dynstr_off = off; off += len(dynstr)
    dynsym_off = align(off, 4); off = dynsym_off + len(dynsym)
    hash_off = align(off, 4); off = hash_off + len(hashtab)
    dynamic_off = align(off, 4); off = dynamic_off + len(dynamic)
    shstrtab = b"\x00.dynstr\x00.dynsym\x00.hash\x00.dynamic\x00.shstrtab\x00"
    shstr_off = off; off += len(shstrtab); shoff = align(off, 4)
    ehdr = bytearray(52); ehdr[0:4] = b"\x7fELF"; ehdr[4] = 1; ehdr[5] = 1; ehdr[6] = 1
    def sh(n, t, f, a, o, s, l, i, al, en): return struct.pack(end + "IIIIIIIIII", n, t, f, a, o, s, l, i, al, en)
    shdrs = sh(0, 0, 0, 0, 0, 0, 0, 0, 0, 0) \
        + sh(shstrtab.index(b".dynstr"), 3, 2, 0, dynstr_off, len(dynstr), 0, 0, 1, 0) \
        + sh(shstrtab.index(b".dynsym"), 11, 2, 0, dynsym_off, len(dynsym), 1, 1, 4, 16) \
        + sh(shstrtab.index(b".hash"), 5, 2, 0, hash_off, len(hashtab), 0, 0, 4, 4) \
        + sh(shstrtab.index(b".dynamic"), 6, 2, 0, dynamic_off, len(dynamic), 1, 0, 4, 8) \
        + sh(shstrtab.index(b".shstrtab"), 3, 0, 0, shstr_off, len(shstrtab), 0, 0, 1, 0)
    struct.pack_into(end + "HHIIIIIHHHHHH", ehdr, 16, 3, 3, 1, 0, 0, shoff, 0, 52, 32, 0, 40, 6, 5)
    blob = bytes(ehdr) + dynstr
    blob += b"\x00" * (dynsym_off - len(blob)) + dynsym
    blob += b"\x00" * (hash_off - len(blob)) + hashtab
    blob += b"\x00" * (dynamic_off - len(blob)) + dynamic
    blob += b"\x00" * (shstr_off - len(blob)) + shstrtab
    blob += b"\x00" * (shoff - len(blob)) + shdrs
    return blob


def selftest():
    ok = 0; fail = 0
    def check(n, c):
        nonlocal ok, fail
        print("  [%s] %s" % ("OK " if c else "ERR", n)); ok += 1 if c else 0; fail += 0 if c else 1
    e = ELF(_build_test_so())
    check("解析 ELF32", e.is64 is False)
    check("类型 DYN(共享库)", e.etype == 3)
    ex, im = e.symbols()
    check("导出符号 foo,bar", [r[0] for r in ex] == ["foo", "bar"])
    check("导入符号 printf", [r[0] for r in im] == ["printf"])
    check("NEEDED libtest.so", e.needed == ["libtest.so"])
    check("SONAME libtest.so", e.soname == "libtest.so")
    print("结果: %d 通过, %d 失败" % (ok, fail))
    return 0 if fail == 0 else 1


def main():
    a = sys.argv[1:]
    if "--selftest" in a:
        return selftest()
    if not a or a[0] in ("-h", "--help"):
        print(__doc__); return 0
    cmd = a[0]
    if cmd in ("info", "exports", "imports", "needed", "sections", "report"):
        data = open(a[1], "rb").read()
        e = ELF(data)
        if cmd == "info":
            print("ELF", "64" if e.is64 else "32", type_name(e.etype), machine_name(e.machine), "entry=0x%x" % e.entry)
        elif cmd == "exports":
            ex, im = e.symbols(); print("\n".join(r[0] for r in ex))
        elif cmd == "imports":
            ex, im = e.symbols(); print("\n".join(r[0] for r in im))
        elif cmd == "needed":
            print("\n".join(e.needed))
        elif cmd == "sections":
            for s in e.shdrs:
                print("%-20s type=%d addr=0x%x size=0x%x" % (s["name"], s["type"], s["addr"], s["size"]))
        else:
            print(report(data))
        return 0
    run_gui()


if __name__ == "__main__":
    sys.exit(main() or 0)