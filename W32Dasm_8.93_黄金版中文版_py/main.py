#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
W32Dasm_8.93_黄金版中文版\\W32dsm8.93+.exe  ->  Python CLI 重写版

来源目录: D:\\Program Files\\crack-tool-dasm\\W32Dasm_8.93_黄金版中文版
主程序  : 目录内含 4 个 W32Dasm 变体:
          - Gold.exe        (1.2 MB, 32-bit PE, Delphi, 未加壳) —— 黄金版主程序, 本重写参考/验证对象
          - W32dsm8.93+.exe  (1.55 MB) 自定义 VM 加壳: 区段名 snyped/.Katja/.Silvana,
                            .text 加密(EP 清零), 运行时以 insb/特权指令(0xC0000096)作 VM 操作码;
                            已用 x32dbg 加载运行至 VM 入口 0x57F007, MCP 逐条异常暂停无法自动脱壳
          - W32dsm89.exe    (1.0 MB) 8.9 基线版, 未加壳
          - ANTI-WDasm.exe  (304 KB) UPX+ASPack 加壳(脱壳后方可使用)

逆向依据 (IDA 9.4 批处理反汇编, 基址 0x400000):
  段: snyped(0x401000+)/.Katja/.rsrc/.Silvana/.text(0x57f000 入口)
  Delphi VCL GUI 程序, 身份字符串:
    'URSoft W32Dasm Ver %s Program Disassembler/Debugger' (0x4bc4f6)
    'URSoft W32Dasm Ver %s Windows Program Disassembler'   (0x4bc52f)
    '//******************** Program Entry Point ********'   (0x4b1c7b)
    '* Referenced by a CALL at '                             (0x4b1caf)
    '* Referenced by a (U)nconditional or (C)onditional Jump at '
    'Exported fn(): %s - Ord:%04Xh'                         (0x4b2187)
    '* Possible Reference to String Resource ID=%05d: "%s"'  (0x4b202d)
    'No Imported Function References Were Found'            (0x4bc410)
  核心能力 (按反汇编/字符串还原):
    1. 载入 PE/EXE/DLL, 解析 DOS/COFF/可选头/节区/数据目录
    2. 线性反汇编代码段, 生成 W32Dasm 风格清单 (清单含表头/入口点标记)
    3. 交叉引用: CALL / JMP 目标标注 + 反向引用扫描
    4. 导入函数引用解析 (IAT -> 模块!函数)
    5. 导出函数列表 (名称 / Ordinal)
    6. 字符串资源可能的引用
    7. 十六进制转储 / 字节·字符串搜索 / 地址跳转 ("Go To")
    (原程序含调试器功能; 本 Python 版实现静态反汇编部分)

  依赖: capstone (x86 反汇编). 缺失时其余命令仍可用, 仅 disasm/listing 不可用.
  纯 Python CLI, main.py 为唯一入口:  python main.py <文件> [命令]
"""

import os
import struct
import sys

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2

try:
    import capstone
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64
    _HAS_CAP = True
except Exception:
    _HAS_CAP = False

USAGE = """\
URSoft W32Dasm 8.93 重写版 (Python CLI)  —— PE 反汇编/分析器

用法:
  python main.py <目标文件> <命令> [参数]

命令:
  info                     文件/PE 概要
  headers                  DOS/COFF/可选头字段
  sections                 节区表
  imports                  导入表 (模块 -> 函数)
  exports                  导出表 (函数/序号)
  strings [minlen]         提取 ASCII 字符串
  hexdump <rva> [len]      十六进制转储
  disasm <rva> [count]     从地址反汇编 N 条指令
  entry [count]            从入口点反汇编
  xrefs <addr>             扫描对给定地址的 CALL/JMP 交叉引用
  search <hex|text>        按字节(hex) 或文本搜索
  listing [out.txt]        生成 W32Dasm 风格完整清单 (默认输出到文件)
  help                     显示本帮助

示例:
  python main.py notepad.exe info
  python main.py notepad.exe entry 40
  python main.py notepad.exe imports
  python main.py notepad.exe xrefs 0x401000
  python main.py notepad.exe listing
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

    @property
    def executable(self):
        return bool(self.chars & 0x20000000)

    @property
    def readable(self):
        return bool(self.chars & 0x40000000)

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
        self.char_seed = struct.unpack_from("<H", data, coff + 18)[0]
        opt_size = struct.unpack_from("<H", data, coff + 16)[0]
        self.opt = coff + 20
        self.magic = struct.unpack_from("<H", data, self.opt)[0]
        self.is_pe32 = (self.magic == 0x10B)
        if self.is_pe32:
            self.entry = struct.unpack_from("<I", data, self.opt + 16)[0]
            self.imagebase = struct.unpack_from("<I", data, self.opt + 28)[0]
            self.sizeof_image = struct.unpack_from("<I", data, self.opt + 56)[0]
            self.sizeof_headers = struct.unpack_from("<I", data, self.opt + 60)[0]
            self.subsystem = struct.unpack_from("<H", data, self.opt + 68)[0]
            dd = self.opt + 96
        else:
            self.entry = struct.unpack_from("<I", data, self.opt + 16)[0]
            self.imagebase = struct.unpack_from("<Q", data, self.opt + 24)[0]
            self.sizeof_image = struct.unpack_from("<I", data, self.opt + 56)[0]
            self.sizeof_headers = struct.unpack_from("<I", data, self.opt + 60)[0]
            self.subsystem = struct.unpack_from("<H", data, self.opt + 68)[0]
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

    # --- 地址换算 ---
    def rva_to_off(self, rva):
        for s in self.sections:
            if s.va <= rva < s.va + max(s.vsize, s.rsize):
                return s.rptr + (rva - s.va)
        if rva < self.sizeof_headers:
            return rva
        return None

    def off_to_rva(self, off):
        for s in self.sections:
            if s.rptr <= off < s.rptr + max(s.rsize, s.vsize):
                return s.va + (off - s.rptr)
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

    # --- 导入/导出 ---
    def imports(self):
        rva, size = self.dirs[1]
        result = []
        if not rva:
            return result
        o = self.rva_to_off(rva)
        if o is None:
            return result
        iat_map = {}
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
                v = struct.unpack_from("<I", self.read(thunk_rva + j * 4, 4) + b"\x00\x00\x00\x00")[0] \
                    if self.read(thunk_rva + j * 4, 4) else 0
                if v == 0:
                    break
                if v & 0x80000000:
                    fname = "Ordinal_%d" % (v & 0xFFFF)
                else:
                    fname = self.read_cstr(v + 2)
                funcs.append(fname)
                if ft:
                    iat_map[self.imagebase + ft + j * 4] = "%s!%s" % (dll, fname)
                j += 1
            result.append((dll, funcs))
            i += 1
        self._iat_map = iat_map
        return result

    def iat_map(self):
        if not hasattr(self, "_iat_map"):
            self.imports()
        return getattr(self, "_iat_map", {})

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
            f = struct.unpack_from("<I", self.data, self.rva_to_off(addr_funcs) + k * 4)[0]
            funcs.append(f)
        names = {}
        for k in range(nnames):
            nm_rva = struct.unpack_from("<I", self.data, self.rva_to_off(addr_names) + k * 4)[0]
            idx = struct.unpack_from("<H", self.data, self.rva_to_off(addr_ords) + k * 2)[0]
            names[idx] = self.read_cstr(nm_rva)
        for k in range(nfuncs):
            out.append((names.get(k, ""), base + k, funcs[k]))
        self._exp_dll = dll
        return out


# ===================== 反汇编器 =====================
def make_disassembler(bit64):
    md = Cs(CS_ARCH_X86, CS_MODE_64 if bit64 else CS_MODE_32)
    md.detail = True
    return md


def _annotate(pe, insn, bit64):
    """为指令的操作数补充 导入/导出/目标 注释."""
    notes = []
    iat = pe.iat_map()
    for op in insn.operands:
        if op.type == capstone.x86.X86_OP_MEM and op.mem.base == 0:
            abs_addr = op.mem.disp & (0xFFFFFFFFFFFFFFFF if bit64 else 0xFFFFFFFF)
            if abs_addr in iat:
                notes.append(iat[abs_addr])
        elif op.type == capstone.x86.X86_OP_IMM:
            tgt = op.imm & (0xFFFFFFFFFFFFFFFF if bit64 else 0xFFFFFFFF)
            if pe.imagebase <= tgt < pe.imagebase + pe.sizeof_image:
                rva = tgt - pe.imagebase
                for s in pe.sections:
                    if s.va <= rva < s.va + max(s.vsize, s.rsize):
                        notes.append("%s+0x%X" % (s.name, rva - s.va))
                        break
    return ("  ; " + ", ".join(notes)) if notes else ""


def disasm_range(pe, start_rva, count, bit64):
    if not _HAS_CAP:
        raise RuntimeError("缺少 capstone 库, 无法反汇编 (pip install capstone)")
    md = make_disassembler(bit64)
    off = pe.rva_to_off(start_rva)
    if off is None:
        raise ValueError("地址 0x%X 不在任何节区内" % start_rva)
    code = pe.data[off:off + count * 16 + 16]
    lines = []
    n = 0
    for insn in md.disasm(code, pe.imagebase + start_rva):
        note = _annotate(pe, insn, bit64)
        lines.append("%08X  %-30s %-8s %s%s" %
                     (insn.address, insn.bytes.hex(), insn.mnemonic, insn.op_str, note))
        n += 1
        if n >= count:
            break
    return lines


def scan_xrefs(pe, target_va, bit64):
    """线性扫描代码段, 找出 CALL/JMP 指向 target_va 的位置."""
    if not _HAS_CAP:
        raise RuntimeError("缺少 capstone 库, 无法扫描交叉引用")
    md = make_disassembler(bit64)
    hits = []
    for s in pe.sections:
        if not s.executable or s.rsize == 0:
            continue
        base = pe.imagebase + s.va
        for insn in md.disasm(pe.data[s.rptr:s.rptr + s.rsize], base):
            if insn.mnemonic in ("call", "jmp", "jz", "jnz", "je", "jne") and insn.operands:
                op = insn.operands[0]
                if op.type == capstone.x86.X86_OP_IMM and op.imm == target_va:
                    hits.append((insn.address, insn.mnemonic, insn.op_str))
    return hits


# ===================== 命令 =====================
def cmd_info(pe, target):
    print("文件            : %s" % os.path.basename(target))
    print("大小            : %d 字节" % len(pe.data))
    print("格式            : %s  (Machine=0x%X)" %
          ("PE32+" if not pe.is_pe32 else "PE32", pe.machine))
    print("基址 ImageBase  : 0x%X" % pe.imagebase)
    print("入口点 Entry    : RVA 0x%X  (VA 0x%X)" % (pe.entry, pe.imagebase + pe.entry))
    print("镜像大小        : 0x%X" % pe.sizeof_image)
    print("节区数量        : %d" % pe.num_sections)
    print("子系统          : %d" % pe.subsystem)
    return EXIT_SUCCESS


def cmd_headers(pe, target):
    print("== DOS 头 ==")
    print("  e_magic=MZ  e_lfanew=0x%X" % pe.e_lfanew)
    print("== COFF 头 ==")
    print("  Machine=0x%X  NumberOfSections=%d  TimeDateStamp=0x%X" %
          (pe.machine, pe.num_sections, pe.timestamp))
    print("== 可选头 ==")
    print("  Magic=0x%X  ImageBase=0x%X  Entry=0x%X" % (pe.magic, pe.imagebase, pe.entry))
    print("  SizeOfImage=0x%X  SizeOfHeaders=0x%X  Subsystem=%d" %
          (pe.sizeof_image, pe.sizeof_headers, pe.subsystem))
    print("== 数据目录 ==")
    names = ["Export", "Import", "Resource", "Exception", "Security", "BaseReloc",
             "Debug", "Arch", "GlobalPtr", "TLS", "LoadConfig", "BoundImport",
             "IAT", "DelayImport", "CLR", "Reserved"]
    for i, (va, sz) in enumerate(pe.dirs):
        if va or sz:
            print("  %-12s RVA=0x%-8X size=0x%X" % (names[i], va, sz))
    return EXIT_SUCCESS


def cmd_sections(pe, target):
    print("%-10s %-10s %-10s %-10s %-10s %s" %
          ("名称", "VirtualAddr", "VirtSize", "RawPtr", "RawSize", "属性"))
    for s in pe.sections:
        attr = "".join([("R" if s.readable else "-"),
                        ("X" if s.executable else "-"),
                        ("W" if s.chars & 0x80000000 else "-")])
        print("%-10s 0x%08X 0x%08X 0x%08X 0x%08X %s" %
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
    exps = pe.exports()
    if not exps:
        print("无导出表")
        return EXIT_SUCCESS
    print("导出模块: %s" % getattr(pe, "_exp_dll", ""))
    for name, ordinal, rva in exps:
        if name:
            print("  Exported fn(): %s - Ord:%04Xh  RVA=0x%X" % (name, ordinal, rva))
        else:
            print("  Exported fn(): <序号> - Ord:%04Xh  RVA=0x%X" % (ordinal, rva))
    return EXIT_SUCCESS


def cmd_strings(pe, target, minlen):
    cur = bytearray()
    for i, c in enumerate(pe.data):
        if 32 <= c < 127:
            cur.append(c)
        else:
            if len(cur) >= minlen:
                rva = pe.off_to_rva(i - len(cur))
                print("0x%08X  %s" % (rva if rva else 0, cur.decode("latin1")))
            cur = bytearray()
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


def cmd_disasm(pe, target, rva, count):
    for ln in disasm_range(pe, rva, count, not pe.is_pe32):
        print(ln)
    return EXIT_SUCCESS


def cmd_entry(pe, target, count):
    print("//******************** Program Entry Point ********")
    print("//  RVA 0x%X  VA 0x%X" % (pe.entry, pe.imagebase + pe.entry))
    for ln in disasm_range(pe, pe.entry, count, not pe.is_pe32):
        print(ln)
    return EXIT_SUCCESS


def cmd_xrefs(pe, target, addr):
    hits = scan_xrefs(pe, addr, not pe.is_pe32)
    if not hits:
        print("未找到对 0x%X 的 CALL/JMP 交叉引用" % addr)
        return EXIT_SUCCESS
    for a, mn, ops in hits:
        print("  * Referenced by %s at 0x%X" % (mn.upper(), a))
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
        rva = pe.off_to_rva(i)
        print("命中: 文件偏移 0x%X  RVA 0x%X" % (i, rva if rva else 0))
        found += 1
        idx = i + 1
    if not found:
        print("未找到: %r" % needle)
    return EXIT_SUCCESS


def cmd_listing(pe, target, out):
    lines = []
    lines.append("URSoft W32Dasm Ver 8.93 (Python 重写版) Program Disassembler")
    lines.append("=" * 70)
    lines.append("Disassembly of File: %s" % os.path.basename(target))
    lines.append("")
    lines.append("Number of Sections: %d" % pe.num_sections)
    lines.append("Image Base: 0x%X   Entry Point: 0x%X" % (pe.imagebase, pe.entry))
    lines.append("")
    lines.append("+----------+------------------------------+")
    lines.append("| Section  |  VA Range                    |")
    lines.append("+----------+------------------------------+")
    for s in pe.sections:
        lines.append("| %-8s | 0x%08X - 0x%08X      |" %
                     (s.name, s.va, s.va + max(s.vsize, s.rsize)))
    lines.append("")
    # 导入
    lines.append("//******************** Imports ********************")
    for dll, funcs in pe.imports():
        lines.append("Imported fn(): %s" % dll)
        for f in funcs:
            lines.append("    %s" % f)
    lines.append("")
    # 导出
    exps = pe.exports()
    if exps:
        lines.append("//******************** Exports ********************")
        for name, ordinal, rva in exps:
            lines.append("Exported fn(): %s - Ord:%04Xh" % (name or "<序号>", ordinal))
        lines.append("")
    # 入口点反汇编
    lines.append("//******************** Program Entry Point ********")
    try:
        for ln in disasm_range(pe, pe.entry, 64, not pe.is_pe32):
            lines.append(ln)
    except Exception as e:
        lines.append("// 反汇编不可用: %s" % e)
    text = "\n".join(lines)
    if out:
        with open(out, "w", encoding="utf-8", errors="replace") as f:
            f.write(text + "\n")
        print("清单已写出: %s (%d 行)" % (out, len(lines)))
    else:
        print(text)
    return EXIT_SUCCESS


# ===================== 入口 =====================
def _to_int(s):
    s = s.strip()
    return int(s, 16) if s.lower().startswith("0x") else int(s, 10)


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

    try:
        if cmd == "info":
            return cmd_info(pe, target)
        if cmd == "headers":
            return cmd_headers(pe, target)
        if cmd == "sections":
            return cmd_sections(pe, target)
        if cmd == "imports":
            return cmd_imports(pe, target)
        if cmd == "exports":
            return cmd_exports(pe, target)
        if cmd == "strings":
            return cmd_strings(pe, target, int(args[0]) if args else 5)
        if cmd == "hexdump":
            return cmd_hexdump(pe, target, _to_int(args[0]) if args else pe.entry,
                               _to_int(args[1]) if len(args) > 1 else 256)
        if cmd == "disasm":
            return cmd_disasm(pe, target, _to_int(args[0]) if args else pe.entry,
                              int(args[1]) if len(args) > 1 else 40)
        if cmd == "entry":
            return cmd_entry(pe, target, int(args[0]) if args else 40)
        if cmd == "xrefs":
            if not args:
                print("用法: xrefs <地址>", file=sys.stderr)
                return EXIT_USAGE
            return cmd_xrefs(pe, target, _to_int(args[0]))
        if cmd == "search":
            if not args:
                print("用法: search <hex|text>", file=sys.stderr)
                return EXIT_USAGE
            return cmd_search(pe, target, args[0])
        if cmd == "listing":
            out = args[0] if args else os.path.splitext(os.path.basename(target))[0] + ".w32d"
            return cmd_listing(pe, target, out)
        print("未知命令: %s" % cmd, file=sys.stderr)
        return EXIT_USAGE
    except RuntimeError as e:
        print("错误: %s" % e, file=sys.stderr)
        return EXIT_FAILURE


if __name__ == "__main__":
    sys.exit(main())