#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZynamicsBinDiff_7_Windows\\bindiff.exe  ->  Python CLI 重写版

来源目录: D:\\Program Files\\crack-tool-dasm\\ZynamicsBinDiff_7_Windows
主程序  : bindiff.exe (3.45 MB, PE32+, 64 位原生代码, 未加壳)
          目录内尚有 bindiff.jar (Java 部分) 及各种 IDA/Binary Ninja 插件 DLL,
          本重写以主程序 bindiff.exe 为对象.

逆向依据 (IDA 9.4 批处理反汇编, 64 位 PE, 基址 0x140000000):
  段: .text(0x140001000)/.idata/.rdata/.data/.pdata
  身份字符串:
    'BinDiff UI' / 'launch the BinDiff UI'                        (0x140276bb8)
    'Find similarities and differences in disassembled code.'    (0x140277140)
    'Usage: %1$s [OPTION] DIRECTORY ...'                          (0x140277140)
    'T:\\src\\git\\bindiff\\main_portable.cc'                      (0x140276888)
  功能定位: 二进制代码差异比对工具 (BinDiff), 支持
            目录内全部两两比对 / 指定 PRIMARY 与 SECONDARY 两文件比对 /
            导出 log(文本) 或 bin(BinDiff 数据库) 格式 / 启动 UI
  共导出 6582 个函数 / 16692 条字符串.

本程序为纯 Python CLI, main.py 为唯一入口, 可直接用
`python main.py <文件1> <文件2> <命令>` 运行.

实现的能力 (与 bindiff 核心比对对齐):
  1. PE 解析 (DOS/COFF/可选头 PE32+/节区/数据目录/导入表/导出表)
  2. 二进制文件逐字节比对 (diff): 找出不同偏移, 计算相似度, 输出不同区块
  3. 字符串抽取 (ASCII)
  4. capstone x64 反汇编 (带地址/字节/助记符/操作数)
  5. 节区/导入表/导出表/十六进制转储/字节搜索
  6. 生成 bindiff 风格文本比对报告 (log 格式)

  注: 原程序的函数级签名匹配与图同步需 C++ 引擎, 本 Python 版实现
      字节级二进制 diff 与静态反汇编部分.

依赖: capstone (x64 反汇编). 缺失时 disasm 不可用, 其余命令正常.

示例:
  python main.py A.exe B.exe diff
  python main.py A.exe B.exe strings
  python main.py A.exe info
  python main.py A.exe disasm 0x140001000 20
  python main.py A.exe B.exe listing report.txt
"""

import os
import struct
import sys

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    _HAS_CAP = True
except Exception:
    _HAS_CAP = False

USAGE = """\
Zynamics BinDiff 7 重写版 (Python CLI) —— 二进制文件比对/分析器

用法:
  python main.py <文件1> [文件2] <命令> [参数]

命令:
  info               单文件 PE 概要
  sections           节区表
  imports            导入表 (模块 -> 函数)
  exports            导出表 (函数/序号/地址)
  strings [minlen]   提取 ASCII 字符串 (单文件)
  hexdump <rva> [len] 十六进制转储 (单文件)
  disasm <rva> [count] 从地址反汇编 N 条指令 (单文件, x64)
  search <hex|text>  按字节/文本搜索 (单文件)
  diff               对文件1与文件2做逐字节比对, 输出不同区块与相似度
  listing [out.txt]  生成 bindiff 风格比对报告 (默认写文件)
  help               显示本帮助

示例:
  python main.py primary.bin secondary.bin diff
  python main.py primary.bin secondary.bin listing report.txt
  python main.py primary.bin info
  python main.py primary.bin disasm 0x140001000 30
"""


# ===================== PE 解析 (PE32+ 支持) =====================
class Section:
    def __init__(self, name, vsize, va, rsize, rptr, chars):
        self.name = name
        self.vsize = vsize
        self.va = va
        self.rsize = rsize
        self.rptr = rptr
        self.chars = chars

    @property
    def executable(self):
        return bool(self.chars & 0x20000000)

    def __repr__(self):
        return "<%s VA=0x%X VS=0x%X>" % (self.name, self.va, self.vsize)


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
        self.is_pe32p = (self.magic == 0x20B)
        if self.is_pe32p:
            self.entry = struct.unpack_from("<I", data, self.opt + 16)[0]
            self.imagebase = struct.unpack_from("<Q", data, self.opt + 24)[0]
            self.sizeof_image = struct.unpack_from("<I", data, self.opt + 56)[0]
            self.sizeof_headers = struct.unpack_from("<I", data, self.opt + 60)[0]
            self.subsystem = struct.unpack_from("<H", data, self.opt + 68)[0]
            dd = self.opt + 112
        else:
            self.entry = struct.unpack_from("<I", data, self.opt + 16)[0]
            self.imagebase = struct.unpack_from("<I", data, self.opt + 28)[0]
            self.sizeof_image = struct.unpack_from("<I", data, self.opt + 56)[0]
            self.sizeof_headers = struct.unpack_from("<I", data, self.opt + 60)[0]
            self.subsystem = struct.unpack_from("<H", data, self.opt + 68)[0]
            dd = self.opt + 96
        self.dirs = []
        n_dirs = 16 if self.is_pe32p else 16
        for i in range(n_dirs):
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

    def read_cstr(self, rva, limit=256):
        o = self.rva_to_off(rva)
        if o is None:
            return ""
        end = o
        while end < len(self.data) and end - o < limit and self.data[end] != 0:
            end += 1
        return self.data[o:end].decode("latin1", "replace")

    def imports(self):
        rva, size = self.dirs[1]
        result = []
        if not rva:
            return result
        o = self.rva_to_off(rva)
        if o is None:
            return result
        i = 0
        while True:
            ent = self.data[o + i * 20:o + i * 20 + 20]
            if len(ent) < 20:
                break
            oft, ts, fc, name_rva, ft = struct.unpack_from("<IIIII", ent, 0)
            if not (oft or name_rva or ft):
                break
            dll = self.read_cstr(name_rva)
            thunk_rva = oft if oft else ft
            funcs = []
            j = 0
            while True:
                b = self.read(thunk_rva + j * 4, 8)
                if not b or len(b) < 8:
                    break
                v = struct.unpack_from("<Q", b, 0)[0]
                if v == 0:
                    break
                if v & 0x8000000000000000:
                    fname = "Ordinal_%d" % (v & 0xFFFF)
                else:
                    fname = self.read_cstr(v + 2)
                funcs.append(fname)
                j += 1
            result.append((dll, funcs))
            i += 1
        return result

    def exports(self):
        rva, size = self.dirs[0]
        out = []
        if not rva:
            return out
        o = self.rva_to_off(rva)
        if o is None:
            return out
        (chars, ts, maj, mnr, name_rva, base, nfuncs, nnames,
         addr_funcs, addr_names, addr_ords) = struct.unpack_from("<IIHHIIIIIII", self.data, o)
        dll = self.read_cstr(name_rva)
        funcs = []
        for k in range(nfuncs):
            fo = self.rva_to_off(addr_funcs)
            f = struct.unpack_from("<I", self.data, fo + k * 4)[0] if fo is not None else 0
            funcs.append(f)
        names = {}
        for k in range(nnames):
            no = self.rva_to_off(addr_names)
            oo = self.rva_to_off(addr_ords)
            if no is None or oo is None:
                break
            nm_rva = struct.unpack_from("<I", self.data, no + k * 4)[0]
            idx = struct.unpack_from("<H", self.data, oo + k * 2)[0]
            names[idx] = self.read_cstr(nm_rva)
        for k in range(nfuncs):
            out.append((names.get(k, ""), base + k, funcs[k]))
        return out, dll


# ===================== 二进制比对 (diff) =====================
def diff_files(a, b):
    """逐字节比对, 返回 (相同字节数, 不同字节数, 不同区块列表, 长度差)."""
    la, lb = len(a), len(b)
    n = min(la, lb)
    same = 0
    diffs = []
    block_start = None
    for i in range(n):
        if a[i] == b[i]:
            same += 1
            if block_start is not None:
                diffs.append((block_start, i - 1, a[block_start:i], b[block_start:i]))
                block_start = None
        else:
            if block_start is None:
                block_start = i
    if block_start is not None:
        diffs.append((block_start, n - 1, a[block_start:n], b[block_start:n]))
    diff_count = n - same
    size_diff = abs(la - lb)
    return same, diff_count, diffs, size_diff


def fmt_block(start, end, ba, bb):
    lines = []
    lines.append("不同区块: 0x%X - 0x%X (%d 字节)" % (start, end, end - start + 1))
    lines.append("  文件1: %s" % ba[:64].hex(" "))
    lines.append("  文件2: %s" % bb[:64].hex(" "))
    return lines


# ===================== 反汇编器 (x64) =====================
def make_disassembler(bit64):
    md = Cs(CS_ARCH_X86, CS_MODE_64 if bit64 else CS_MODE_32)
    md.detail = True
    return md


def disasm_range(pe, start_rva, count):
    if not _HAS_CAP:
        raise RuntimeError("缺少 capstone 库, 无法反汇编 (pip install capstone)")
    md = make_disassembler(pe.is_pe32p)
    off = pe.rva_to_off(start_rva)
    if off is None:
        raise ValueError("地址 0x%X 不在任何节区内" % start_rva)
    code = pe.data[off:off + count * 16 + 16]
    lines = []
    n = 0
    for insn in md.disasm(code, pe.imagebase + start_rva):
        lines.append("%016X  %-24s %-8s %s" %
                     (insn.address, insn.bytes.hex(), insn.mnemonic, insn.op_str))
        n += 1
        if n >= count:
            break
    return lines


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
def cmd_info(pe, target):
    print("== 文件概要 ==")
    print("文件            : %s" % os.path.basename(target))
    print("大小            : %d 字节" % len(pe.data))
    print("格式            : PE32+  (Machine=0x%X)" % pe.machine)
    print("基址 ImageBase  : 0x%X" % pe.imagebase)
    print("入口点 Entry    : RVA 0x%X  (VA 0x%X)" % (pe.entry, pe.imagebase + pe.entry))
    print("镜像大小        : 0x%X" % pe.sizeof_image)
    print("节区数量        : %d" % pe.num_sections)
    print("子系统          : %d" % pe.subsystem)
    return EXIT_SUCCESS


def cmd_sections(pe, target):
    print("%-10s %-16s %-12s %-12s %-12s %s" %
          ("名称", "VirtualAddr", "VirtSize", "RawPtr", "RawSize", "属性"))
    for s in pe.sections:
        attr = "".join(("R" if s.chars & 0x40000000 else "-",
                        ("X" if s.executable else "-"),
                        ("W" if s.chars & 0x80000000 else "-")))
        print("%-10s 0x%016X 0x%08X 0x%08X 0x%08X %s" %
              (s.name, s.va, s.vsize, s.rptr, s.rsize, attr))
    return EXIT_SUCCESS


def cmd_imports(pe, target):
    imps = pe.imports()
    if not imps:
        print("No Imported Function References Were Found")
        return EXIT_SUCCESS
    for dll, funcs in imps:
        print("%s  (%d 个函数)" % (dll, len(funcs)))
        for f in funcs:
            print("    %s" % f)
    return EXIT_SUCCESS


def cmd_exports(pe, target):
    result = pe.exports()
    if not result:
        print("无导出表")
        return EXIT_SUCCESS
    exps, dll = result
    print("导出模块: %s" % dll)
    for name, ordinal, rva in exps:
        va = pe.imagebase + rva if rva else 0
        if name:
            print("  Exported fn(): %s - Ord:%04Xh  RVA=0x%X  VA=0x%X" % (name, ordinal, rva, va))
        else:
            print("  Exported fn(): <序号> - Ord:%04Xh  RVA=0x%X  VA=0x%X" % (ordinal, rva, va))
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
        print("%016X  %-47s  %s" % (rva + i,
              " ".join("%02X" % c for c in chunk),
              "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)))
    return EXIT_SUCCESS


def cmd_disasm(pe, target, rva, count):
    for ln in disasm_range(pe, rva, count):
        print(ln)
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
        # 文件偏移 -> rva
        if rva is None:
            rva = i
        print("命中: 文件偏移 0x%X  RVA 0x%X" % (i, rva))
        found += 1
        idx = i + 1
    if not found:
        print("未找到: %r" % needle)
    return EXIT_SUCCESS


def cmd_diff(a_path, b_path):
    with open(a_path, "rb") as f:
        a = f.read()
    with open(b_path, "rb") as f:
        b = f.read()
    same, diff_count, diffs, size_diff = diff_files(a, b)
    total = max(len(a), len(b))
    sim = (same / total * 100) if total else 100.0
    print("== 二进制比对 (bindiff 风格) ==")
    print("文件1 : %s (%d 字节)" % (os.path.basename(a_path), len(a)))
    print("文件2 : %s (%d 字节)" % (os.path.basename(b_path), len(b)))
    print("相同字节: %d" % same)
    print("不同字节: %d" % diff_count)
    print("长度差  : %d 字节" % size_diff)
    print("相似度  : %.2f%%" % sim)
    print("不同区块: %d 个" % len(diffs))
    for start, end, ba, bb in diffs[:50]:
        for ln in fmt_block(start, end, ba, bb):
            print(ln)
    if len(diffs) > 50:
        print("... (仅显示前 50 个不同区块)")
    return EXIT_SUCCESS


def cmd_listing(a_path, b_path, out):
    lines = []
    lines.append("Zynamics BinDiff 7 重写版 (Python CLI) 比对报告")
    lines.append("=" * 60)
    lines.append("文件1: %s" % os.path.basename(a_path))
    lines.append("文件2: %s" % os.path.basename(b_path))
    lines.append("")
    try:
        pe_a = PeFile(open(a_path, "rb").read())
        lines.append("[文件1] %s" % cmd_info_summary(pe_a, a_path))
    except Exception as e:
        lines.append("[文件1] 非 PE 或解析失败: %s" % e)
    try:
        pe_b = PeFile(open(b_path, "rb").read())
        lines.append("[文件2] %s" % cmd_info_summary(pe_b, b_path))
    except Exception as e:
        lines.append("[文件2] 非 PE 或解析失败: %s" % e)
    lines.append("")
    with open(a_path, "rb") as f:
        a = f.read()
    with open(b_path, "rb") as f:
        b = f.read()
    same, diff_count, diffs, size_diff = diff_files(a, b)
    total = max(len(a), len(b))
    sim = (same / total * 100) if total else 100.0
    lines.append("相同字节: %d" % same)
    lines.append("不同字节: %d" % diff_count)
    lines.append("长度差  : %d 字节" % size_diff)
    lines.append("相似度  : %.2f%%" % sim)
    lines.append("不同区块: %d 个" % len(diffs))
    for start, end, ba, bb in diffs:
        for ln in fmt_block(start, end, ba, bb):
            lines.append(ln)
    text = "\n".join(lines)
    if out:
        with open(out, "w", encoding="utf-8", errors="replace") as f:
            f.write(text + "\n")
        print("报告已写出: %s" % out)
    else:
        print(text)
    return EXIT_SUCCESS


def cmd_info_summary(pe, target):
    return "%s  PE32+  ImageBase=0x%X  Entry=0x%X  节区=%d" % (
        os.path.basename(target), pe.imagebase, pe.entry, pe.num_sections)


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

    # 第一个位置参数必须是文件
    if not os.path.isfile(argv[0]):
        print("错误: 找不到文件: %s" % argv[0], file=sys.stderr)
        return EXIT_FAILURE
    a_path = argv[0]

    # 第二个位置参数: 可能是文件2, 也可能是命令
    b_path = None
    cmd_start = 1
    if len(argv) >= 2 and os.path.isfile(argv[1]):
        b_path = argv[1]
        cmd_start = 2

    if cmd_start >= len(argv):
        cmd = "info"
        args = []
    else:
        cmd = argv[cmd_start].lower()
        args = argv[cmd_start + 1:]

    pe = None
    try:
        pe = PeFile(open(a_path, "rb").read())
    except ValueError:
        pass

    if cmd == "diff":
        if not b_path:
            print("diff 需要两个文件: python main.py <文件1> <文件2> diff", file=sys.stderr)
            return EXIT_USAGE
        return cmd_diff(a_path, b_path)
    if cmd == "listing":
        out = args[0] if args else os.path.splitext(os.path.basename(a_path))[0] + "_bindiff_report.txt"
        return cmd_listing(a_path, b_path, out)
    if pe is None:
        print("错误: 不是有效的 PE 文件: %s" % a_path, file=sys.stderr)
        return EXIT_FAILURE

    if cmd == "info":
        return cmd_info(pe, a_path)
    if cmd == "sections":
        return cmd_sections(pe, a_path)
    if cmd == "imports":
        return cmd_imports(pe, a_path)
    if cmd == "exports":
        return cmd_exports(pe, a_path)
    if cmd == "strings":
        return cmd_strings(pe, a_path, int(args[0]) if args else 5)
    if cmd == "hexdump":
        return cmd_hexdump(pe, a_path, _to_int(args[0]) if args else pe.entry,
                           _to_int(args[1]) if len(args) > 1 else 256)
    if cmd == "disasm":
        return cmd_disasm(pe, a_path, _to_int(args[0]) if args else pe.entry,
                          int(args[1]) if len(args) > 1 else 40)
    if cmd == "search":
        if not args:
            print("用法: search <hex|text>", file=sys.stderr)
            return EXIT_USAGE
        return cmd_search(pe, a_path, args[0])
    print("未知命令: %s" % cmd, file=sys.stderr)
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())