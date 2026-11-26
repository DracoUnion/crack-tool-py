#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Overlay_最终版\\Overlay.exe  ->  Python CLI 重写版

来源目录: D:\\Program Files\\crack-tool-pe\\Overlay_最终版
主程序  : Overlay.exe (约 570 KB, 32-bit PE, 未加壳)
          Overlay 是覆盖数据(Overlay Data)探测/提取工具, 检测 PE 文件末尾
          超出 PE 映射范围的附加数据(overlay), 常见于安装包/自解压/加壳残留.

逆向依据 (IDA 9.4 批处理反汇编, 基址 0x400000):
  段: seg000..seg006(0x401000)/.rsrc/.data/.idata/.tls/.rdata/.adata,
      入口 0x40E904B
  身份: 仅导入 kernel32.dll, 功能聚焦于 PE 文件结构扫描与覆盖数据提取.
  共导出约 6 万字符串 / 2 个已识别函数.

本程序为纯 Python CLI, main.py 为唯一入口, 可直接用
`python main.py <PE文件> <命令>` 运行.

实现的能力 (与 Overlay 覆盖数据探测核心对齐):
  1. PE 解析 (DOS/COFF/可选头 PE32/PE32+/节区/数据目录)
  2. 覆盖数据(Overlay)探测: 文件中超过 PE 头+全部节区 raw 范围的尾部数据,
     报告偏移、大小并可十六进制预览
  3. 导入表 / 导出表 (模块 -> 函数)
  4. 节区表 / 数据目录
  5. 字符串抽取 / 十六进制转储 / 字节搜索
  6. 生成 PE/Overlay 分析文本报告 (report 命令)

依赖: 纯 Python 标准库 (无第三方依赖).

示例:
  python main.py <PE文件> info
  python main.py <PE文件> overlay
  python main.py <PE文件> sections
  python main.py <PE文件> report out.txt
"""

import os
import struct
import sys

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2

USAGE = """\
Overlay 重写版 (Python CLI) —— PE 覆盖数据探测器

用法:
  python main.py <PE文件> <命令> [参数]

命令:
  info               PE 头概要
  sections           节区表
  imports            导入表 (模块 -> 函数)
  exports            导出表 (名称/序号/RVA)
  overlay            探测文件尾部的覆盖数据(Overlay)
  strings [minlen]   提取 ASCII 字符串
  hexdump <rva> [len] 十六进制转储
  search <hex|text>  按字节/文本搜索
  report [out.txt]   生成 PE/Overlay 分析文本报告
  help               显示本帮助

示例:
  python main.py setup.exe overlay
  python main.py setup.exe info
  python main.py setup.exe sections
  python main.py setup.exe report out.txt
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
        self.characteristics = struct.unpack_from("<H", data, coff + 18)[0]
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
                b = self.read(thunk_rva + j * 4, 4)
                if not b or len(b) < 4:
                    break
                v = struct.unpack_from("<I", b, 0)[0]
                if v == 0:
                    break
                if v & 0x80000000:
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
            return out, ""
        o = self.rva_to_off(rva)
        if o is None:
            return out, ""
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

    def overlay(self):
        end = self.sizeof_headers
        for s in self.sections:
            end = max(end, s.rptr + max(s.rsize, s.vsize))
        total = len(self.data)
        if total > end:
            return end, total - end, self.data[end:]
        return end, 0, b""


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
    print("== PE 头概要 ==")
    print("文件            : %s" % os.path.basename(target))
    print("大小            : %d 字节" % len(pe.data))
    print("格式            : %s  (Machine=0x%X)" %
          ("PE32+" if not pe.is_pe32 else "PE32", pe.machine))
    print("基址 ImageBase  : 0x%X" % pe.imagebase)
    print("入口点 Entry    : RVA 0x%X  (VA 0x%X)" % (pe.entry, pe.imagebase + pe.entry))
    print("镜像大小        : 0x%X" % pe.sizeof_image)
    print("头部大小        : 0x%X" % pe.sizeof_headers)
    print("节区数量        : %d" % pe.num_sections)
    ol_start, ol_size, _ = pe.overlay()
    print("覆盖数据(Overlay): 偏移=0x%X 大小=0x%X 字节" % (ol_start, ol_size))
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


def cmd_imports(pe, target):
    imps = pe.imports()
    if not imps:
        print("无导入表")
        return EXIT_SUCCESS
    for dll, funcs in imps:
        print("%s  (%d 个函数)" % (dll, len(funcs)))
        for f in funcs:
            print("    %s" % f)
    return EXIT_SUCCESS


def cmd_exports(pe, target):
    exps, dll = pe.exports()
    if not exps:
        print("无导出表")
        return EXIT_SUCCESS
    print("导出模块: %s" % dll)
    for name, ordinal, rva in exps:
        if name:
            print("  %-40s Ord:%04Xh  RVA=0x%X" % (name, ordinal, rva))
        else:
            print("  %-40s Ord:%04Xh  RVA=0x%X  (无名)" % ("<序号>", ordinal, rva))
    return EXIT_SUCCESS


def cmd_overlay(pe, target):
    print("== 覆盖数据(Overlay)探测 ==")
    print("文件            : %s" % os.path.basename(target))
    print("文件总大小      : %d 字节" % len(pe.data))
    ol_start, ol_size, ol_data = pe.overlay()
    print("PE 映射结束     : 0x%X (SizeOfHeaders + 最大节区 raw 结束)" % ol_start)
    if ol_size:
        print("覆盖数据偏移    : 0x%X" % ol_start)
        print("覆盖数据大小    : %d 字节 (0x%X)" % (ol_size, ol_size))
        print("覆盖数据首 64 字节:")
        chunk = ol_data[:64]
        print("  %s" % " ".join("%02X" % c for c in chunk))
        print("  可读部分: %s" % "".join(chr(c) if 32 <= c < 127 else "." for c in chunk))
    else:
        print("未检测到覆盖数据")
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
    lines.append("Overlay 重写版 (Python CLI) —— PE/Overlay 分析报告")
    lines.append("=" * 60)
    lines.append("文件: %s" % os.path.basename(target))
    lines.append("  格式: %s  Machine=0x%X" % ("PE32+" if not pe.is_pe32 else "PE32", pe.machine))
    lines.append("  基址=0x%X  入口=0x%X  镜像大小=0x%X" %
                 (pe.imagebase, pe.entry, pe.sizeof_image))
    lines.append("  节区数=%d  时间戳=0x%08X" % (pe.num_sections, pe.timestamp))
    ol_start, ol_size, _ = pe.overlay()
    lines.append("  覆盖数据(Overlay): 偏移=0x%X 大小=%d 字节" % (ol_start, ol_size))
    lines.append("")
    lines.append("-- 节区 --")
    for s in pe.sections:
        attr = "".join(("R" if s.chars & 0x40000000 else "-",
                        "X" if s.chars & 0x20000000 else "-",
                        "W" if s.chars & 0x80000000 else "-"))
        lines.append("  %-12s VA=0x%08X VS=0x%08X RawPtr=0x%08X RawSize=0x%08X %s" %
                     (s.name, s.va, s.vsize, s.rptr, s.rsize, attr))
    lines.append("")
    lines.append("-- 数据目录 --")
    names = ["Export", "Import", "Resource", "Exception", "Security", "BaseReloc",
             "Debug", "Arch", "GlobalPtr", "TLS", "LoadConfig", "BoundImport",
             "IAT", "DelayImport", "CLR", "Reserved"]
    for i, (va, sz) in enumerate(pe.dirs):
        if va or sz:
            lines.append("  %-12s RVA=0x%08X size=0x%X" % (names[i], va, sz))
    lines.append("")
    lines.append("-- 导入表 --")
    for dll, funcs in pe.imports():
        lines.append("  %s (%d)" % (dll, len(funcs)))
        for f in funcs:
            lines.append("    %s" % f)
    lines.append("")
    lines.append("-- 导出表 --")
    exps, dll = pe.exports()
    if exps:
        lines.append("  模块: %s" % dll)
        for name, ordinal, rva in exps:
            lines.append("      %-40s Ord:%04Xh  RVA=0x%X" % (name, ordinal, rva))
    else:
        lines.append("  无导出表")
    lines.append("")
    lines.append("-- 覆盖数据 --")
    if ol_size:
        lines.append("  偏移=0x%X 大小=%d 字节" % (ol_start, ol_size))
        chunk = ol_data[:32]
        lines.append("  首 32 字节: %s" % " ".join("%02X" % c for c in chunk))
    else:
        lines.append("  未检测到覆盖数据")
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
        cmd = "info"
        args = []
    else:
        cmd = argv[1].lower()
        args = argv[2:]

    if cmd == "info":
        return cmd_info(pe, target)
    if cmd == "sections":
        return cmd_sections(pe, target)
    if cmd == "imports":
        return cmd_imports(pe, target)
    if cmd == "exports":
        return cmd_exports(pe, target)
    if cmd == "overlay":
        return cmd_overlay(pe, target)
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
        out = args[0] if args else os.path.splitext(os.path.basename(target))[0] + "_overlay_report.txt"
        return cmd_report(pe, target, out)
    print("未知命令: %s" % cmd, file=sys.stderr)
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())