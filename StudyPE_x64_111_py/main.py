#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
StudyPE_x64_111\\StudyPE+ x64.exe  ->  Python CLI 重写版

来源目录: D:\\Program Files\\crack-tool-pe\\StudyPE_x64_111
主程序  : StudyPE+ x64.exe (约 8 MB, PE32+, 64 位, 未加壳, MFC 编写)
          PE Studio 是 PE 文件编辑器, 查看/编辑 PE 头、节区、导入表、
          导出表、资源、重定位、调试目录等.

逆向依据 (IDA 9.4 批处理反汇编, 基址 0x140000000):
  段: .text(0x140001000)/.idata/.rdata/.data/.pdata/.rsrc/.reloc, 入口 0x1402559DC
  身份: 导入 kernel32/user32/GDI32/comdlg32/advapi32/ole32/oleaut32/urlmon/
        dwmapi/uxtheme/shlwapi/msvcrt/mscoree 等
  功能定位: PE 文件编辑器, 查看/编辑 PE 结构与资源.
  共导出约 80 万字符串 / 11196 个已识别函数 (MFC 程序, 大部分逻辑在 VCL/MFC 库中).

本程序为纯 Python CLI, main.py 为唯一入口, 可直接用
`python main.py <PE文件> <命令>` 运行.

实现的能力 (与 PE Studio PE 编辑核心对齐):
  1. PE 解析 (DOS/COFF/可选头 PE32/PE32+/节区/数据目录/时间戳/校验和/子系统/
     节区对齐/文件对齐/OS/镜像/子系统版本)
  2. 导入表 (模块 -> 函数)
  3. 导出表 (名称/序号/RVA)
  4. 资源目录 / 基址重定位 / TLS / 调试目录
  5. 字符串抽取 / 十六进制转储 / 字节搜索
  6. 生成 PE 分析文本报告 (report 命令)

  注: 原程序可编辑 PE 并写回, 本 Python 版实现静态 PE 结构只读查看
      与报告导出 (静态等效).

依赖: 纯 Python 标准库 (无第三方依赖).

示例:
  python main.py StudyPE+ x64.exe info
  python main.py StudyPE+ x64.exe sections
  python main.py StudyPE+ x64.exe imports
  python main.py StudyPE+ x64.exe resources
  python main.py StudyPE+ x64.exe report out.txt
"""

import os
import struct
import sys

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2

USAGE = """\
StudyPE 重写版 (Python CLI) —— PE 文件编辑器/查看器

用法:
  python main.py <PE文件> <命令> [参数]

命令:
  info               PE 头概要
  sections           节区表
  imports            导入表 (模块 -> 函数)
  exports            导出表 (名称/序号/RVA)
  resources          资源目录树 (类型/名称/语言)
  reloc              基址重定位表
  tls                TLS 目录
  debug              调试目录
  strings [minlen]   提取 ASCII 字符串
  hexdump <rva> [len] 十六进制转储
  search <hex|text>  按字节/文本搜索
  report [out.txt]   生成 PE 分析文本报告
  help               显示本帮助

示例:
  python main.py "StudyPE+ x64.exe" info
  python main.py "StudyPE+ x64.exe" sections
  python main.py "StudyPE+ x64.exe" imports
  python main.py "StudyPE+ x64.exe" resources
  python main.py "StudyPE+ x64.exe" report out.txt
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
            self.checksum = struct.unpack_from("<I", data, self.opt + 64)[0]
            self.subsystem = struct.unpack_from("<H", data, self.opt + 68)[0]
            self.dll_characteristics = struct.unpack_from("<H", data, self.opt + 70)[0]
            self.stack_reserve = struct.unpack_from("<I", data, self.opt + 72)[0]
            self.stack_commit = struct.unpack_from("<I", data, self.opt + 76)[0]
            self.heap_reserve = struct.unpack_from("<I", data, self.opt + 80)[0]
            self.heap_commit = struct.unpack_from("<I", data, self.opt + 84)[0]
            self.loader_flags = struct.unpack_from("<I", data, self.opt + 88)[0]
            self.num_rva_and_sizes = struct.unpack_from("<I", data, self.opt + 92)[0]
            self.section_alignment = struct.unpack_from("<I", data, self.opt + 32)[0]
            self.file_alignment = struct.unpack_from("<I", data, self.opt + 36)[0]
            self.major_os = struct.unpack_from("<H", data, self.opt + 42)[0]
            self.minor_os = struct.unpack_from("<H", data, self.opt + 44)[0]
            self.major_image = struct.unpack_from("<H", data, self.opt + 48)[0]
            self.minor_image = struct.unpack_from("<H", data, self.opt + 50)[0]
            self.major_subsys = struct.unpack_from("<H", data, self.opt + 52)[0]
            self.minor_subsys = struct.unpack_from("<H", data, self.opt + 54)[0]
            dd = self.opt + 96
        else:
            self.entry = struct.unpack_from("<I", data, self.opt + 16)[0]
            self.imagebase = struct.unpack_from("<Q", data, self.opt + 24)[0]
            self.sizeof_image = struct.unpack_from("<I", data, self.opt + 56)[0]
            self.sizeof_headers = struct.unpack_from("<I", data, self.opt + 60)[0]
            self.checksum = struct.unpack_from("<I", data, self.opt + 64)[0]
            self.subsystem = struct.unpack_from("<H", data, self.opt + 68)[0]
            self.dll_characteristics = struct.unpack_from("<H", data, self.opt + 70)[0]
            self.stack_reserve = struct.unpack_from("<Q", data, self.opt + 72)[0]
            self.stack_commit = struct.unpack_from("<Q", data, self.opt + 80)[0]
            self.heap_reserve = struct.unpack_from("<Q", data, self.opt + 88)[0]
            self.heap_commit = struct.unpack_from("<Q", data, self.opt + 96)[0]
            self.loader_flags = struct.unpack_from("<I", data, self.opt + 104)[0]
            self.num_rva_and_sizes = struct.unpack_from("<I", data, self.opt + 108)[0]
            self.major_os = struct.unpack_from("<H", data, self.opt + 42)[0]
            self.minor_os = struct.unpack_from("<H", data, self.opt + 40)[0]
            self.major_image = struct.unpack_from("<H", data, self.opt + 46)[0]
            self.minor_image = struct.unpack_from("<H", data, self.opt + 44)[0]
            self.major_subsys = struct.unpack_from("<H", data, self.opt + 50)[0]
            self.minor_subsys = struct.unpack_from("<H", data, self.opt + 48)[0]
            self.section_alignment = struct.unpack_from("<I", data, self.opt + 32)[0]
            self.file_alignment = struct.unpack_from("<I", data, self.opt + 36)[0]
            dd = self.opt + 112
        self.dirs = []
        for i in range(min(self.num_rva_and_sizes, 16)):
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

    def _res_name(self, rva):
        if rva is None:
            return ""
        o = self.rva_to_off(rva)
        if o is None:
            return ""
        high = self.u16(rva)
        if high & 0x8000:
            return "#%d" % (high & 0x7FFF)
        length = self.u16(rva)
        if length == 0:
            return ""
        raw = self.data[o + 2:o + 2 + length * 2]
        try:
            s = raw.decode("utf-16-le", "replace")
        except Exception:
            s = ""
        printable = "".join(c for c in s if 32 <= ord(c) < 127)
        if printable:
            return printable
        return "<ustr len=%d>" % length

    def _walk_res(self, dir_rva, depth, out):
        if depth > 6:
            return
        if dir_rva in self._visited_res:
            return
        self._visited_res.add(dir_rva)
        o = self.rva_to_off(dir_rva)
        if o is None:
            return
        o2 = o + 8
        named = self.u16(o2 + 0); idents = self.u16(o2 + 2)
        total = named + idents
        base = o2 + 4
        shown = 0
        for k in range(total):
            if shown > 400:
                out.append("  " * depth + "  ... (更多条目已省略)")
                break
            ent_o = base + k * 8
            if ent_o + 8 > len(self.data):
                break
            name_rva = struct.unpack_from("<I", self.data, ent_o)[0]
            data_rva = struct.unpack_from("<I", self.data, ent_o + 4)[0]
            is_dir = bool(data_rva & 0x80000000)
            data_rva &= 0x7FFFFFFF
            name_rva &= 0x7FFFFFFF
            name = self._res_name(name_rva)
            indent = "  " * depth
            if is_dir:
                out.append("%sDIRECTORY %s (RVA 0x%X)" % (indent, name, dir_rva))
                self._walk_res(data_rva, depth + 1, out)
                shown += 1
            else:
                de = self.rva_to_off(data_rva)
                if de is None:
                    continue
                data_offset = struct.unpack_from("<I", self.data, de)[0]
                data_size = struct.unpack_from("<I", self.data, de + 4)[0]
                code_page = struct.unpack_from("<I", self.data, de + 8)[0]
                out.append("%s  DATA %s size=0x%X codepage=0x%X dataRVA=0x%X" %
                           (indent, name, data_size, code_page, data_offset))
                shown += 1

    def resources(self):
        rva, size = self.dirs[2]
        out = []
        if not rva:
            return out
        self._visited_res = set()
        self._walk_res(rva, 0, out)
        return out

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

    def tls(self):
        rva, size = self.dirs[9]
        out = []
        if not rva:
            return out
        o = self.rva_to_off(rva)
        if o is None:
            return out
        if self.is_pe32:
            (start, end, addr, calloc, zero, pad) = struct.unpack_from("<IIIIII", self.data, o)
        else:
            (start, end, addr, calloc, zero, pad) = struct.unpack_from("<QQQQII", self.data, o)
        out.append("StartAddressOfRawData=0x%X" % start)
        out.append("EndAddressOfRawData=0x%X" % end)
        out.append("AddressOfIndex=0x%X" % addr)
        out.append("AddressOfCallBacks=0x%X" % calloc)
        out.append("SizeOfZeroFill=0x%X" % zero)
        out.append("Padding=%d" % pad)
        return out

    def debug(self):
        rva, size = self.dirs[6]
        out = []
        if not rva:
            return out
        DEBUG_TYPES = {
            0: "UNKNOWN", 1: "COFF", 2: "CODEVIEW", 3: "FPO", 4: "MISC",
            5: "EXCEPTION", 6: "FIXUP", 7: "OMAP_TO_SRC", 8: "OMAP_FROM_SRC",
            9: "BORLAND", 11: "CLSID_HEADER", 12: "VC_FEATURE", 13: "POGO",
            14: "ILTCG", 15: "MPX", 16: "REPRO",
        }
        count = size // 28
        for k in range(count):
            o = self.rva_to_off(rva + k * 28)
            if o is None:
                break
            (characteristics, ts, maj, mnr, typ, data_rva, data_size) = \
                struct.unpack_from("<IIIIIII", self.data, o)
            out.append("DEBUG[%d] type=%s(0x%X) ts=0x%X ver=%d.%d dataRVA=0x%X dataSize=0x%X" %
                       (k, DEBUG_TYPES.get(typ, "TYPE_%d" % typ), typ, ts, maj, mnr,
                        data_rva, data_size))
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
    print("DOS e_lfanew    : 0x%X" % pe.e_lfanew)
    print("时间戳          : 0x%08X" % pe.timestamp)
    print("特征            : 0x%04X" % pe.characteristics)
    print("基址 ImageBase  : 0x%X" % pe.imagebase)
    print("入口点 Entry    : RVA 0x%X  (VA 0x%X)" % (pe.entry, pe.imagebase + pe.entry))
    print("镜像大小        : 0x%X" % pe.sizeof_image)
    print("头部大小        : 0x%X" % pe.sizeof_headers)
    print("节区对齐        : 0x%X" % pe.section_alignment)
    print("文件对齐        : 0x%X" % pe.file_alignment)
    print("校验和          : 0x%08X" % pe.checksum)
    print("子系统          : %d (主版=%d 次版=%d)" %
          (pe.subsystem, pe.major_subsys, pe.minor_subsys))
    print("OS 版本         : 主版=%d 次版=%d" % (pe.major_os, pe.minor_os))
    print("镜像版本        : 主版=%d 次版=%d" % (pe.major_image, pe.minor_image))
    print("DLL特征         : 0x%04X" % pe.dll_characteristics)
    print("栈保留/提交     : 0x%X / 0x%X" % (pe.stack_reserve, pe.stack_commit))
    print("堆保留/提交     : 0x%X / 0x%X" % (pe.heap_reserve, pe.heap_commit))
    print("RVA条目数       : %d" % pe.num_rva_and_sizes)
    names = ["Export", "Import", "Resource", "Exception", "Security", "BaseReloc",
             "Debug", "Arch", "GlobalPtr", "TLS", "LoadConfig", "BoundImport",
             "IAT", "DelayImport", "CLR", "Reserved"]
    for i, (va, sz) in enumerate(pe.dirs):
        if va or sz:
            print("  %-14s RVA=0x%-8X size=0x%X" % (names[i], va, sz))
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


def cmd_resources(pe, target):
    out = pe.resources()
    if not out:
        print("无资源目录")
        return EXIT_SUCCESS
    for ln in out:
        print(ln)
    return EXIT_SUCCESS


def cmd_reloc(pe, target):
    out = pe.reloc()
    if not out:
        print("无重定位表")
        return EXIT_SUCCESS
    for ln in out:
        print(ln)
    return EXIT_SUCCESS


def cmd_tls(pe, target):
    out = pe.tls()
    if not out:
        print("无 TLS 目录")
        return EXIT_SUCCESS
    for ln in out:
        print(ln)
    return EXIT_SUCCESS


def cmd_debug(pe, target):
    out = pe.debug()
    if not out:
        print("无调试目录")
        return EXIT_SUCCESS
    for ln in out:
        print(ln)
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
    lines.append("StudyPE 重写版 (Python CLI) —— PE 分析报告")
    lines.append("=" * 60)
    lines.append("文件: %s" % os.path.basename(target))
    lines.append("  格式: %s  Machine=0x%X" % ("PE32+" if not pe.is_pe32 else "PE32", pe.machine))
    lines.append("  基址=0x%X  入口=0x%X  镜像大小=0x%X" %
                 (pe.imagebase, pe.entry, pe.sizeof_image))
    lines.append("  节区数=%d  时间戳=0x%08X  校验和=0x%08X" %
                 (pe.num_sections, pe.timestamp, pe.checksum))
    lines.append("  节区对齐=0x%X  文件对齐=0x%X" %
                 (pe.section_alignment, pe.file_alignment))
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
    lines.append("-- 资源目录 --")
    lines.extend(pe.resources())
    lines.append("")
    lines.append("-- 重定位 --")
    lines.extend(pe.reloc())
    lines.append("")
    lines.append("-- TLS --")
    lines.extend(pe.tls())
    lines.append("")
    lines.append("-- 调试目录 --")
    lines.extend(pe.debug())
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
    if cmd == "resources":
        return cmd_resources(pe, target)
    if cmd == "reloc":
        return cmd_reloc(pe, target)
    if cmd == "tls":
        return cmd_tls(pe, target)
    if cmd == "debug":
        return cmd_debug(pe, target)
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
        out = args[0] if args else os.path.splitext(os.path.basename(target))[0] + "_pe_report.txt"
        return cmd_report(pe, target, out)
    print("未知命令: %s" % cmd, file=sys.stderr)
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())