#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DIE_WinXP_Portable_3.07\\die.exe  ->  Python CLI 重写版

来源目录: D:\\Program Files\\crack-tool-pe\\DIE_WinXP_Portable_3.07
主程序  : die.exe (约 11 MB, 32-bit PE, 未加壳)
          Detect It Easy (DIE) 是基于 DIE-engine 的壳/保护器/编译器检测工具,
          支持文件/设备/内存/目录扫描, 通过 PE 区段名与字节/字符串签名匹配
          输出壳名 (如 UPX / ASPack / Themida / Enigma / VMProtect / PECompact
          / MPRESS ...)，未匹配则显示 "Unknown" / "Uncompressed".

逆向依据 (IDA 9.4 批处理反汇编, 基址 0x401000):
  段: .text(0x401000)/.idata/.rdata/.data, 入口 0x43D46F0
  身份字符串: 'Detect It Easy' / 'https://github.com/horsicq/DIE-engine' /
              'Signatures' / 'File scan' / 'Device scan' / 'Memory scan' /
              'Directory scan' / 'Unknown' / 'Uncompressed'
  签名特征字符串: '.aspack' / '.enigma1' / '.enigma2' / '.MPRESS1' / '.MPRESS2' /
              '.themida' / '.UPX0' / '.UPX1' / '.UPX2' / 'ASPacker 2.12' /
              'UPX 0.8x-1.2' / 'PECompact 1.4x' / 'Themida 1.8.0.0' 等
  IDA 仅识别 3 个函数, 其余为 Qt 界面与签名数据.

本程序为纯 Python CLI, main.py 为唯一入口, 可直接用
`python main.py <目标文件> <命令>` 运行.

实现的能力 (与 DIE 壳检测核心对齐):
  1. PE 解析 (DOS/COFF/可选头/节区/数据目录)
  2. 壳签名扫描: 区段名匹配 + 字节/字符串特征匹配 (UPX/ASPack/Themida/
     Enigma/VMProtect/PECompact/MPRESS/Obsidium/WinLicense/CodeVirtualizer/
     ASPack/SecuROM/Armadillo/RLPack/CCG/Petrite 等)
  3. 输出检测到的壳名列表, 无匹配则显示 "Unknown"
  4. 字符串抽取 / 十六进制转储 / 字节搜索
  5. 生成扫描文本报告 (report 命令)

  注: 原程序还可扫描设备/内存/目录并维护签名库 (die.ini), 本 Python 版
      实现单文件 PE 壳签名扫描 (静态等效).

依赖: 纯 Python 标准库 (无第三方依赖).

示例:
  python main.py some.exe scan
  python main.py some.exe info
  python main.py some.exe sections
  python main.py some.exe strings
  python main.py some.exe report out.txt
"""

import os
import struct
import sys

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2

# 区段名 -> 壳名 (不区分大小写)
SECTION_SIGS = {
    "upx0": "UPX", "upx1": "UPX", "upx2": "UPX",
    ".aspack": "ASPack",
    ".themida": "Themida",
    ".enigma": "Enigma Protector",
    ".vmp0": "VMProtect", ".vmp1": "VMProtect", ".vmp2": "VMProtect",
    ".pclstb": "PECompact", ".pcrypt": "PECompact", ".pec2": "PECompact",
    ".pec2mo": "PECompact",
    ".mpress1": "MPRESS", ".mpress2": "MPRESS",
    ".tshade": "PEshield / TSEraser",
    ".petrite": "Petrite",
    ".neolite": "Neolite",
    ".perplex": "Perplex",
    ".securom": "SecuROM",
    ".armadillo": "Armadillo",
    ".rlpack": "RLPack",
    ".ccg": "CCG",
}

# 字节/字符串特征 -> 壳名
STRING_SIGS = [
    ("VMProtect", "VMProtect"),
    ("Enigma Protector", "Enigma Protector"),
    ("Themida", "Themida"),
    ("WinLicense", "WinLicense / Themida"),
    ("Obsidium", "Obsidium"),
    ("CodeVirtualizer", "CodeVirtualizer"),
    ("ASPack", "ASPack"),
    ("PECompact", "PECompact"),
    ("MPRESS", "MPRESS"),
    ("SecuROM", "SecuROM"),
    ("Armadillo", "Armadillo"),
    ("RLPack", "RLPack"),
    ("Petrite", "Petrite"),
    ("Neolite", "Neolite"),
    ("CCG", "CCG"),
    ("NSPack", "NSPack"),
    ("PE-PROTECT", "PE-PROTECT"),
    ("Yoda's Protector", "Yoda's Protector"),
    ("PELock", "PELock"),
]

USAGE = """\
DIE (Detect It Easy) 重写版 (Python CLI) —— PE 壳/保护器签名扫描器

用法:
  python main.py <目标文件> <命令> [参数]

命令:
  scan             壳/保护器签名扫描, 输出检测到的壳名 (无匹配则显示 Unknown)
  info             PE 文件概要
  sections         节区表 (壳常修改区段名)
  strings [minlen] 提取 ASCII 字符串
  hexdump <rva> [len] 十六进制转储
  search <hex|text> 按字节/文本搜索
  report [out.txt] 生成扫描文本报告
  help             显示本帮助

示例:
  python main.py some.exe scan
  python main.py some.exe info
  python main.py some.exe sections
  python main.py some.exe report out.txt
"""


# ===================== PE 解析 =====================
class Section:
    def __init__(self, name, vsize, va, rsize, rptr, chars):
        self.name = name
        self.vsize = vsize
        self.va = va
        self.rsize = rsize
        self.rptr = rptr
        self.chars = chars


class PeFile:
    def __init__(self, data):
        self.data = data
        if data[:2] != b"MZ":
            raise ValueError("不是有效的 PE 文件 (缺少 MZ 头)")
        self.e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        if data[self.e_lfanew:self.e_lfanew + 4] != b"PE\x00\x00":
            raise ValueError("不是有效的 PE 文件 (缺少 PE 签名)")
        coff = self.e_lfanew + 4
        self.machine = struct.unpack_from("<H", data, coff)[0]
        self.num_sections = struct.unpack_from("<H", data, coff + 2)[0]
        self.timestamp = struct.unpack_from("<I", data, coff + 4)[0]
        opt_size = struct.unpack_from("<H", data, coff + 16)[0]
        self.opt = coff + 20
        self.magic = struct.unpack_from("<H", data, self.opt)[0]
        self.is_pe32 = (self.magic == 0x10B)
        if self.is_pe32:
            self.entry = struct.unpack_from("<I", data, self.opt + 16)[0]
            self.imagebase = struct.unpack_from("<I", data, self.opt + 28)[0]
            self.sizeof_image = struct.unpack_from("<I", data, self.opt + 56)[0]
            self.sizeof_headers = struct.unpack_from("<I", data, self.opt + 60)[0]
            dd = self.opt + 96
        else:
            self.entry = struct.unpack_from("<I", data, self.opt + 16)[0]
            self.imagebase = struct.unpack_from("<Q", data, self.opt + 24)[0]
            self.sizeof_image = struct.unpack_from("<I", data, self.opt + 56)[0]
            self.sizeof_headers = struct.unpack_from("<I", data, self.opt + 60)[0]
            dd = self.opt + 112
        self.dirs = []
        for i in range(16):
            va, sz = struct.unpack_from("<II", data, dd + i * 8)
            self.dirs.append((va, sz))
        sec = self.opt + opt_size
        self.sections = []
        for i in range(self.num_sections):
            o = sec + i * 40
            name = data[o:o + 8].rstrip(b"\x00").decode("latin1", "replace")
            vsize, va, rsize, rptr = struct.unpack_from("<IIII", data, o + 8)
            chars = struct.unpack_from("<I", data, o + 36)[0]
            self.sections.append(Section(name, vsize, va, rsize, rptr, chars))

    def rva_to_off(self, rva):
        if rva is None:
            return None
        for s in self.sections:
            if s.va <= rva < s.va + max(s.vsize, s.rsize):
                return s.rptr + (rva - s.va)
        if rva < self.sizeof_headers:
            return rva
        return None

    def read(self, rva, n):
        o = self.rva_to_off(rva)
        if o is None or o < 0 or o + n > len(self.data):
            return b""
        return self.data[o:o + n]

    def read_cstr(self, rva, limit=512):
        o = self.rva_to_off(rva)
        if o is None:
            return ""
        end = o
        while end < len(self.data) and end - o < limit and self.data[end] != 0:
            end += 1
        return self.data[o:end].decode("latin1", "replace")

    def u32(self, rva):
        b = self.read(rva, 4)
        return int.from_bytes(b, "little") if len(b) == 4 else 0


# ===================== 壳签名扫描 =====================
def scan_packers(pe):
    """返回检测到的壳名列表 (去重)."""
    found = []
    # 1) 区段名匹配
    for s in pe.sections:
        low = s.name.lower().strip(".")
        for key, pname in SECTION_SIGS.items():
            if key.strip(".") == low:
                if pname not in found:
                    found.append(pname)
    # 2) 字符串特征匹配 (对全文件)
    for sig, pname in STRING_SIGS:
        if pe.data.find(sig.encode("latin1", "replace")) >= 0:
            if pname not in found:
                found.append(pname)
    return found


# ===================== 辅助 =====================
def _extract_strings(blob, minlen):
    res = []
    cur = bytearray()
    for c in blob:
        if 32 <= c < 127:
            cur.append(c)
        else:
            if len(cur) >= minlen:
                res.append(cur.decode("latin1"))
            cur = bytearray()
    if len(cur) >= minlen:
        res.append(cur.decode("latin1"))
    return res


def _to_int(s):
    s = s.strip()
    return int(s, 16) if s.lower().startswith("0x") else int(s, 10)


# ===================== 命令 =====================
def cmd_scan(pe, target):
    print("== 壳/保护器签名扫描 (DIE 风格) ==")
    print("文件            : %s" % os.path.basename(target))
    print("格式            : %s  (Machine=0x%X)" %
          ("PE32+" if not pe.is_pe32 else "PE32", pe.machine))
    found = scan_packers(pe)
    if found:
        print("检测到        : %s" % ", ".join(found))
    else:
        print("检测到        : Unknown")
    print("节区数          : %d" % pe.num_sections)
    for s in pe.sections:
        print("  区段 %-12s VA=0x%08X VS=0x%06X 名称=%s" %
              (s.name, s.va, s.vsize, s.name))
    return EXIT_SUCCESS


def cmd_info(pe, target):
    print("== PE 头概要 ==")
    print("文件            : %s" % os.path.basename(target))
    print("大小            : %d 字节" % len(pe.data))
    print("格式            : %s  (Machine=0x%X)" %
          ("PE32+" if not pe.is_pe32 else "PE32", pe.machine))
    print("基址 ImageBase  : 0x%X" % pe.imagebase)
    print("入口点 Entry    : RVA 0x%X  (VA 0x%X)" % (pe.entry, pe.imagebase + pe.entry))
    print("镜像大小        : 0x%X" % pe.sizeof_image)
    print("节区数量        : %d" % pe.num_sections)
    return EXIT_SUCCESS


def cmd_sections(pe, target):
    print("%-14s %-10s %-10s %-10s %-10s %s" %
          ("名称", "VirtualAddr", "VirtSize", "RawPtr", "RawSize", "属性"))
    for s in pe.sections:
        attr = "".join(("R" if s.chars & 0x40000000 else "-",
                        "X" if s.chars & 0x20000000 else "-",
                        "W" if s.chars & 0x80000000 else "-"))
        print("%-14s 0x%08X 0x%08X 0x%08X 0x%08X %s" %
              (s.name, s.va, s.vsize, s.rptr, s.rsize, attr))
    return EXIT_SUCCESS


def cmd_strings(pe, target, minlen):
    print("== 字符串抽取 ==")
    for s in _extract_strings(pe.data, minlen):
        print(s)
    return EXIT_SUCCESS


def cmd_hexdump(pe, target, rva, length):
    off = pe.rva_to_off(rva)
    if off is None:
        print("错误: RVA 0x%X 不在任何节区" % rva, file=sys.stderr)
        return EXIT_FAILURE
    data = pe.data[off:off + length]
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        print("%08X  %-47s  %s" % (rva + i,
              " ".join("%02X" % c for c in chunk),
              "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)))
    return EXIT_SUCCESS


def cmd_search(pe, target, needle):
    if needle.lower().startswith("0x"):
        pat = bytes.fromhex(needle[2:].replace(" ", ""))
    elif all(ch in "0123456789abcdefABCDEF " for ch in needle) and len(needle.replace(" ", "")) % 2 == 0 and len(needle.replace(" ", "")) >= 2:
        pat = bytes.fromhex(needle.replace(" ", ""))
    else:
        pat = needle.encode("latin1", "replace")
    idx = 0
    found = 0
    while True:
        i = pe.data.find(pat, idx)
        if i < 0:
            break
        rva = pe.rva_to_off(i)
        print("命中: 文件偏移 0x%X  RVA 0x%X" % (i, rva if rva else 0))
        found += 1
        idx = i + 1
    if not found:
        print("未找到: %r" % needle)
    return EXIT_SUCCESS


def cmd_report(pe, target, out):
    lines = []
    lines.append("DIE 重写版 (Python CLI) — 壳签名扫描报告")
    lines.append("=" * 60)
    lines.append("文件: %s" % os.path.basename(target))
    lines.append("  格式: %s  Machine=0x%X" % ("PE32+" if not pe.is_pe32 else "PE32", pe.machine))
    lines.append("  ImageBase=0x%X  Entry=0x%X  SizeOfImage=0x%X" %
                 (pe.imagebase, pe.entry, pe.sizeof_image))
    lines.append("  节区数=%d" % pe.num_sections)
    found = scan_packers(pe)
    lines.append("")
    lines.append("-- 检测结果 --")
    if found:
        lines.append("  检测到: %s" % ", ".join(found))
    else:
        lines.append("  检测到: Unknown")
    lines.append("")
    lines.append("-- 节区 --")
    for s in pe.sections:
        lines.append("  %-12s VA=0x%08X VS=0x%08X RawPtr=0x%08X RawSize=0x%08X" %
                     (s.name, s.va, s.vsize, s.rptr, s.rsize))
    text = "\n".join(lines)
    if out:
        with open(out, "w", encoding="utf-8", errors="replace") as f:
            f.write(text + "\n")
        print("报告已写出: %s" % out)
    else:
        print(text)
    return EXIT_SUCCESS


# ===================== 入口 =====================
def main():
    try:
        sys.stdout.reconfigure(errors="replace")
        sys.stderr.reconfigure(errors="replace")
    except Exception:
        pass
    argv = sys.argv[1:]
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(USAGE)
        return EXIT_USAGE
    target = argv[0]
    if not os.path.isfile(target):
        print("错误: 找不到文件: %s" % target, file=sys.stderr)
        return EXIT_FAILURE
    with open(target, "rb") as f:
        data = f.read()
    try:
        pe = PeFile(data)
    except ValueError as e:
        print("错误: %s" % e, file=sys.stderr)
        return EXIT_FAILURE

    if len(argv) == 1:
        cmd = "scan"
        args = []
    else:
        cmd = argv[1].lower()
        args = argv[2:]

    if cmd == "scan":
        return cmd_scan(pe, target)
    if cmd == "info":
        return cmd_info(pe, target)
    if cmd == "sections":
        return cmd_sections(pe, target)
    if cmd == "strings":
        return cmd_strings(pe, target, int(args[0]) if args else 5)
    if cmd == "hexdump":
        return cmd_hexdump(pe, target, _to_int(args[0]) if args else pe.entry,
                           _to_int(args[1]) if len(args) > 1 else 256)
    if cmd == "search":
        if not args:
            print("用法: search <hex|text>", file=sys.stderr)
            return EXIT_USAGE
        return cmd_search(pe, target, args[0])
    if cmd == "report":
        out = args[0] if args else os.path.splitext(os.path.basename(target))[0] + "_die_report.txt"
        return cmd_report(pe, target, out)
    print("未知命令: %s" % cmd, file=sys.stderr)
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())