#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ImportsFixer_1.6\\Imports Fixer.exe  ->  Python CLI 重写版

来源目录: D:\\Program Files\\crack-tool-pe\\ImportsFixer_1.6
主程序  : Imports Fixer.exe (约 1 MB, 32-bit PE, 未加壳)
          导入表修复工具 (Import Fixer), 修复/重建 PE 程序的导入表 (IAT).

逆向依据 (IDA 9.4 批处理反汇编, 基址 0x400000):
  段: .text/.itext/.data/.bss/.idata/.tls/.rdata/.reloc/.rsrc, 入口 0x40CA838
  身份字符串: 'Rebuild' / 'PE Header' / 导入 kernel32.dll/user32.dll/ole32.dll/
              oleaut32.dll/imm32.dll/psapi.dll/urlmon.dll/dwmapi.dll/uxtheme.dll/
              shell32.dll/winmm.dll/COMCTL32.dll/MAPI32.DLL
  功能定位: 导入表修复工具, 修复 PE 程序的导入地址表 (IAT).
  共导出约 13 万字符串 / 2 个已识别函数.

本程序为纯 Python CLI, main.py 为唯一入口, 可直接用
`python main.py <PE文件> <命令>` 运行.

实现的能力 (与 Imports Fixer 核心对齐):
  1. PE 解析 (DOS/COFF/可选头/节区/数据目录)
  2. 导入表 (模块 -> 函数, 含 OriginalFirstThunk/OAT 与 FirstThunk/IAT 地址)
  3. IAT 槽位列表 (每个槽: RVA/VA, 当前绑定值)
  4. 导出表 (名称/序号/RVA)
  5. 基址重定位表 (IMAGE_BASE_RELOCATION 块)
  6. IAT 去绑定/重建 (把 IAT 每项置为 0, 保存为新文件)
  7. 字符串抽取 / 十六进制转储 / 字节搜索
  8. 生成 IAT/导入表文本报告 (report 命令)

  注: 真正的 IAT 函数地址填充需程序运行时内存状态, 本 Python 版实现
      静态 IAT 的查看与结构性重建框架.

依赖: 纯 Python 标准库 (无第三方依赖).

示例:
  python main.py 目标.exe info
  python main.py 目标.exe imports
  python main.py 目标.exe iat
  python main.py 目标.exe rebuild-imports rebuilt.exe
  python main.py 目标.exe report report.txt
"""

import os
import struct
import sys

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2

USAGE = """\
Imports Fixer 重写版 (Python CLI) —— IAT/导入表修复工具 (静态等效)

用法:
  python main.py <PE文件> <命令> [参数]

命令:
  info                    PE 头概要
  sections                节区表
  imports                 导入表 (模块 -> 函数, 含 OAT/IAT 地址)
  iat                     IAT 槽位列表 (每槽 RVA/VA/当前值)
  exports                 导出表 (名称/序号/RVA)
  reloc                   基址重定位表
  rebuild-imports <出文件>把 IAT 每项置 0 并保存 (模拟 IAT 重建/去绑定)
  strings [minlen]        提取 ASCII 字符串
  hexdump <rva> [len]     十六进制转储
  search <hex|text>       按字节/文本搜索
  report [out.txt]        生成 IAT/导入表文本报告
  help                    显示本帮助

示例:
  python main.py 目标.exe imports
  python main.py 目标.exe iat
  python main.py 目标.exe rebuild-imports rebuilt.exe
  python main.py 目标.exe report report.txt
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

    def u32(self, rva):
        b = self.read(rva, 4)
        return int.from_bytes(b, "little") if len(b) == 4 else 0

    def u16(self, rva):
        b = self.read(rva, 2)
        return int.from_bytes(b, "little") if len(b) == 2 else 0

    def read_cstr(self, rva, limit=512):
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
            oat_rva = oft if oft else 0
            iat_rva = ft if ft else 0
            funcs = []
            j = 0
            while True:
                b = self.read(oat_rva + j * 4, 4) if oat_rva else b""
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
            result.append((dll, funcs, oat_rva, iat_rva))
            i += 1
        return result

    def iat_entries(self):
        out = []
        for dll, funcs, oat_rva, iat_rva in self.imports():
            if not iat_rva:
                continue
            j = 0
            while True:
                v = self.u32(iat_rva + j * 4)
                if v == 0:
                    break
                fname = funcs[j] if j < len(funcs) else "?"
                out.append((iat_rva + j * 4, v, fname))
                j += 1
        return out

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

    def reloc(self):
        rva, size = self.dirs[5]
        out = []
        if not rva:
            return out
        pos = rva
        end = rva + size
        RELOC_TYPES = {
            0: "ABSOLUTE", 1: "HIGH", 2: "LOW", 3: "HIGHLOW", 4: "HIGHADJ",
            5: "MIPS_JMPADDR", 6: "SECTION", 7: "ARM_MOV32", 8: "ARM_THUMB_JMP24",
            10: "IA64_IMM64", 11: "DIR64", 12: "DIR32NB", 13: "SECTION64",
            14: "ARM_MOV32T", 15: "ARM_THUMB_MOV32T", 16: "ARM_THUMB_JMP11",
            17: "ARM_THUMB_JMP19", 18: "ARM_THUMB_JMP24X", 19: "ARM64_REL32",
            20: "ARM64_REL32_6", 21: "ARM64_REL32_20", 22: "ARM64_REL32_44",
            23: "ARM64_REL32_44X", 24: "ARM64_REL32_56", 25: "ARM64_REL32_62",
            26: "ARM64_REL32_LD_PAGE", 27: "ARM64_REL32_LD_PAGE_6",
            28: "ARM64_REL32_LD_PAGE_20", 29: "ARM64_REL32_LD_PAGE_44",
            30: "ARM64_REL32_LD_PAGE_44X", 31: "ARM64_REL32_LD_PAGE_56",
            32: "ARM64_REL32_LD_PAGE_62",
        }
        while pos < end:
            o = self.rva_to_off(pos)
            if o is None:
                break
            page_rva = struct.unpack_from("<I", self.data, o)[0]
            block_size = struct.unpack_from("<I", self.data, o + 4)[0]
            if block_size < 8:
                break
            out.append("BLOCK pageRVA=0x%X blockSize=0x%X" % (page_rva, block_size))
            n = (block_size - 8) // 2
            for k in range(n):
                v = self.u16(o + 8 + k * 2)
                t = (v >> 12) & 0xF
                off = v & 0xFFF
                out.append("  type=%s(0x%X) offset=0x%X finalRVA=0x%X" %
                           (RELOC_TYPES.get(t, "TYPE_%d" % t), t, off, page_rva + off))
            pos += block_size
        return out


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
    print("节区数量        : %d" % pe.num_sections)
    print("导入表 RVA      : 0x%X" % pe.dirs[1][0])
    print("导出表 RVA      : 0x%X" % pe.dirs[0][0])
    print("重定位表 RVA    : 0x%X" % pe.dirs[5][0])
    return EXIT_SUCCESS


def cmd_sections(pe, target):
    print("%-12s %-12s %-10s %-10s %-10s %s" %
          ("名称", "VirtualAddr", "VirtSize", "RawPtr", "RawSize", "属性"))
    for s in pe.sections:
        attr = "".join(("R" if s.chars & 0x40000000 else "-",
                        "X" if s.chars & 0x20000000 else "-",
                        "W" if s.chars & 0x80000000 else "-"))
        print("%-12s 0x%08X 0x%08X 0x%08X 0x%08X %s" %
              (s.name, s.va, s.vsize, s.rptr, s.rsize, attr))
    return EXIT_SUCCESS


def cmd_imports(pe, target):
    print("== 导入表 (DLL -> 函数, 含 OAT/IAT 地址) ==")
    imps = pe.imports()
    if not imps:
        print("无导入表")
        return EXIT_SUCCESS
    for dll, funcs, oat_rva, iat_rva in imps:
        print("%s  (%d 个函数)" % (dll, len(funcs)))
        print("    OAT(OriginalFirstThunk) RVA=0x%X  IAT(FirstThunk) RVA=0x%X" %
              (oat_rva, iat_rva))
        for f in funcs:
            print("      %s" % f)
    return EXIT_SUCCESS


def cmd_iat(pe, target):
    entries = pe.iat_entries()
    if not entries:
        print("无 IAT 槽位")
        return EXIT_SUCCESS
    print("%-10s %-10s %-10s %s" % ("IAT RVA", "IAT VA", "当前值", "函数"))
    for iat_rva, cur, name in entries:
        print("0x%08X  0x%08X  0x%08X  %s" %
              (iat_rva, pe.imagebase + iat_rva, cur, name))
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


def cmd_reloc(pe, target):
    out = pe.reloc()
    if not out:
        print("无重定位表")
        return EXIT_SUCCESS
    for ln in out:
        print(ln)
    return EXIT_SUCCESS


def cmd_rebuild_imports(pe, target, out):
    data = bytearray(pe.data)
    count = 0
    for iat_rva, cur, name in pe.iat_entries():
        o = pe.rva_to_off(iat_rva)
        if o is not None and o + 4 <= len(data):
            struct.pack_into("<I", data, o, 0)
            count += 1
    with open(out, "wb") as f:
        f.write(bytes(data))
    print("已重建 %d 个 IAT 槽位, 保存到: %s" % (count, out))
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
    lines.append("Imports Fixer 重写版 (Python CLI) —— IAT/导入表报告")
    lines.append("=" * 60)
    lines.append("文件: %s" % os.path.basename(target))
    lines.append("  格式: %s  ImageBase=0x%X  Entry=0x%X" %
                 ("PE32+" if not pe.is_pe32 else "PE32", pe.imagebase, pe.entry))
    lines.append("")
    lines.append("-- 导入表 --")
    for dll, funcs, oat_rva, iat_rva in pe.imports():
        lines.append("  %s  (%d)  OAT=0x%X IAT=0x%X" %
                     (dll, len(funcs), oat_rva, iat_rva))
        for f in funcs:
            lines.append("      %s" % f)
    lines.append("")
    lines.append("-- IAT 槽位 --")
    for iat_rva, cur, name in pe.iat_entries():
        lines.append("  IAT RVA=0x%08X VA=0x%08X 当前值=0x%08X  %s" %
                     (iat_rva, pe.imagebase + iat_rva, cur, name))
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
    lines.append("-- 重定位 --")
    lines.extend(pe.reloc())
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
    if cmd == "iat":
        return cmd_iat(pe, target)
    if cmd == "exports":
        return cmd_exports(pe, target)
    if cmd == "reloc":
        return cmd_reloc(pe, target)
    if cmd == "rebuild-imports":
        if not args:
            print("用法: rebuild-imports <输出文件>", file=sys.stderr)
            return EXIT_USAGE
        return cmd_rebuild_imports(pe, target, args[0])
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
        out = args[0] if args else os.path.splitext(os.path.basename(target))[0] + "_iat_report.txt"
        return cmd_report(pe, target, out)
    print("未知命令: %s" % cmd, file=sys.stderr)
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())