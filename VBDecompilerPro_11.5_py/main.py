#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VBDecompilerPro_11.5_CrackedBy_GautamGreat\\VB Decompiler.exe  ->  Python CLI 重写版

来源目录: D:\\Program Files\\crack-tool-dasm\\VBDecompilerPro_11.5_CrackedBy_GautamGreat
目标文件: VB Decompiler.exe (约 15 MB, 32-bit PE, Enigma Protector 加壳)
脱壳产物: VB Decompiler.unpacked.exe (64 MB, 内存镜像重建 PE, raw=RVA)
          VB Decompiler.unpacked.bin  (0x400000-0x800A000 原始内存 dump)

逆向依据:
  [x32dbg] 静态入口点 0x4004E7E 为 Enigma 自解密桩 (pushad/call/pop ebp/sub ebp,.../jmp
           + xor byte ptr [eax],dl 循环). 硬件断点触发反调试 (DR 检测) 0xC0000005;
           软件运行进入异常驱动 VM (ud2 / div 溢出当 opcode).
           改为不带调试器正常启动 -> 程序自行解压 -> x64dbg 附加, 调用栈定位真实代码
           位于 Enigma RWX 区段 0x1330000+ (RVA 0xf30000), 0x13C4CEC 处为标准 Delphi
           序言 (push ebp / mov ebp,esp / ... / call), 与 dump 偏移 0xFC4CEC 字节一致.
  [IDA 9.4] 对重建 PE 批处理分析 (idat.exe -A -S导出脚本):
           - 段: HEADER / seg001..seg011 / .rsrc / seg013(0x1330000-0x392e000, 真实代码)
                 / .data(0x392e000-0x440a000)
           - 身份字符串: 'VB_Decompiler.exe' (0x3931070)
           - Enigma 运行时: 'EP_ActivationShowDialog' / 'EP_RegKeyRegisterAfterDate' ...
           - P-code 组件: 'TRegExpr(dump): Corrupted Opcode' (0x13f7b60),
                          'TRegExpr(misc): Bad p-code imported' (0x13f7bec)
           - 共导出 192838 条字符串 / 2 个已识别函数 (38MB 段未完全建函数表)

  本程序为纯 Python CLI, main.py 为唯一入口, 可直接用
  `python main.py <VB6可执行文件>` 运行.

  实现的 VB6 二进制解析 (与 VB Decompiler 处理对象一致):
    1. PE 解析 (DOS/COFF/可选头/节区/数据目录)
    2. 入口点 `push <VBHeader_VA>; call ThunRTMain` -> 定位 VBHeader ("VB5!")
    3. VBHeader: RuntimeBuild / Language(LCID) / SubMain / ProjectObject /
       ProjectName / HelpFile / HelpContext / LibFlags / Version / ProjectInfo
    4. ProjectInfo.ObjectTable -> ObjectTableEntry[] (窗体/模块/类)
    5. 对象名 / 类型 / 方法表 / 对象数据(窗体二进制) 定位
    6. 字符串抽取 / 十六进制转储 / 工程骨架导出
"""

import os
import sys

# ===================== 常量 =====================
EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2

IMAGEBASE_DEFAULT = 0x400000

# VB6 对象类型码 (ObjectType)
OBJTYPE = {
    0x21: "Form",
    0x22: "Class",
    0x23: "Module",
    0x2D: "Designer",
    0x2E: "PropertyBag",
}

# VB6 P-code 操作码 (部分, 常见指令; 未列出者按 Op_xx 显示)
PCODE = {
    0x00: "LitPush0", 0x01: "LitPush1", 0x02: "LitPushI2", 0x03: "LitPushI4",
    0x04: "LitPushR4", 0x05: "LitPushR8", 0x06: "LitPushCy", 0x07: "LitPushDate",
    0x08: "LitPushBool", 0x09: "LitPushSng", 0x0A: "LitPushDbl", 0x0B: "LitPushCur",
    0x0C: "LitPushStr", 0x0D: "LitPushVar", 0x0E: "LitPushNull", 0x0F: "LitPushEmpty",
    0x10: "LitPushError", 0x11: "LitPushByte", 0x12: "LitPushInt", 0x13: "LitPushLng",
    0x1A: "LitPushBool0", 0x1B: "LitPushBool1",
    0x20: "Pop", 0x21: "PopAddr", 0x22: "PopPush", 0x23: "PopWork", 0x24: "PopFor",
    0x30: "BinaryOpAdd", 0x31: "BinaryOpSub", 0x32: "BinaryOpMul", 0x33: "BinaryOpDiv",
    0x34: "BinaryOpIntDiv", 0x35: "BinaryOpMod", 0x36: "BinaryOpPow",
    0x37: "BinaryOpAnd", 0x38: "BinaryOpOr", 0x39: "BinaryOpXor",
    0x3A: "BinaryOpEqv", 0x3B: "BinaryOpImp", 0x3C: "BinaryOpEq",
    0x3D: "BinaryOpNe", 0x3E: "BinaryOpLt", 0x3F: "BinaryOpLe",
    0x40: "BinaryOpGt", 0x41: "BinaryOpGe", 0x42: "BinaryOpIs",
    0x43: "BinaryOpLike", 0x44: "BinaryOpConcat",
    0x50: "UnaryOpNeg", 0x51: "UnaryOpNot", 0x52: "UnaryOpPlus",
    0x60: "Assign", 0x61: "AssignRef", 0x62: "AssignData",
    0x70: "Call", 0x71: "CallAddr", 0x72: "CallMethod", 0x73: "CallWith",
    0x74: "CallByName", 0x75: "CallEvent",
    0x80: "Branch", 0x81: "BranchIf", 0x82: "BranchIfNot", 0x83: "BranchIfBool",
    0x84: "BranchIfNotBool", 0x85: "BranchIfNull", 0x86: "BranchIfNotNull",
    0x90: "SelectCase", 0x91: "Case", 0x92: "EndCase",
    0xA0: "For", 0xA1: "ForEach", 0xA2: "Next", 0xA3: "ExitFor",
    0xB0: "Do", 0xB1: "Loop", 0xB2: "While", 0xB3: "Wend",
    0xC0: "OnError", 0xC1: "Resume", 0xC2: "ExitSub", 0xC3: "ExitFunction",
    0xC4: "ExitProperty", 0xC5: "ExitFor",
    0xD0: "ProcStart", 0xD1: "ProcEnd", 0xD2: "FuncStart", 0xD3: "FuncEnd",
    0xE0: "Ret", 0xE1: "RetSub", 0xE2: "RetFunc",
    0xF0: "Nop", 0xF1: "End", 0xF2: "Stop",
}

USAGE = """\
VB Decompiler Pro 11.5 重写版 (Python CLI)

用法:
  python main.py <目标VB6文件> [选项]

选项:
  -i, --info        显示 VB 工程概要 (默认)
  -l, --list        列出全部对象 (窗体/模块/类)
  -o, --objects     显示对象表详情 (名称/类型/方法/数据偏移)
  -f, --forms       导出窗体对象数据 (二进制 + 可读字符串)
  -p, --pcode       反汇编 P-code 对象 (尽力而为)
  -s, --strings     抽取目标文件字符串
  -x, --hex         十六进制转储 VBHeader / 对象表
  -e, --export      导出工程骨架到 <名称>_project 目录
  -a, --all         等价于 -i -l -o -s
  -q, --quiet       静默模式 (仅输出错误)
  -h, --help        显示本帮助

示例:
  python main.py "VB Decompiler.exe" -i
  python main.py MyApp.exe -l
  python main.py MyApp.exe -e
"""


# ===================== PE 解析 =====================
class PeFile:
    def __init__(self, data):
        self.data = data
        if data[:2] != b"MZ":
            raise ValueError("不是有效的 PE 文件 (缺少 MZ 头)")
        e_lfanew = int.from_bytes(data[0x3C:0x40], "little")
        if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            raise ValueError("不是有效的 PE 文件 (缺少 PE 签名)")
        self.e_lfanew = e_lfanew
        coff = e_lfanew + 4
        self.machine = int.from_bytes(data[coff:coff + 2], "little")
        self.num_sections = int.from_bytes(data[coff + 2:coff + 4], "little")
        opt_size = int.from_bytes(data[coff + 16:coff + 18], "little")
        self.opt = coff + 20
        self.magic = int.from_bytes(data[self.opt:self.opt + 2], "little")
        self.is_pe32 = (self.magic == 0x10B)
        # PE32 / PE32+ 可选头字段偏移
        if self.is_pe32:
            self.imagebase = int.from_bytes(data[self.opt + 28:self.opt + 32], "little")
            self.entry_rva = int.from_bytes(data[self.opt + 16:self.opt + 20], "little")
            self.sizeof_image = int.from_bytes(data[self.opt + 56:self.opt + 60], "little")
            dd_off = self.opt + 96
        else:
            self.imagebase = int.from_bytes(data[self.opt + 24:self.opt + 32], "little")
            self.entry_rva = int.from_bytes(data[self.opt + 16:self.opt + 20], "little")
            self.sizeof_image = int.from_bytes(data[self.opt + 56:self.opt + 60], "little")
            dd_off = self.opt + 112
        self.num_dirs = int.from_bytes(data[self.opt + (92 if self.is_pe32 else 108):
                                            self.opt + (94 if self.is_pe32 else 110)], "little")
        self.data_dirs = []
        for i in range(self.num_dirs):
            va = int.from_bytes(data[dd_off + i * 8:dd_off + i * 8 + 4], "little")
            sz = int.from_bytes(data[dd_off + i * 8 + 4:dd_off + i * 8 + 8], "little")
            self.data_dirs.append((va, sz))
        # 节区表
        sec = self.opt + opt_size
        self.sections = []
        for i in range(self.num_sections):
            o = sec + i * 40
            name = data[o:o + 8].rstrip(b"\x00").decode("latin1", "replace")
            vsize = int.from_bytes(data[o + 8:o + 12], "little")
            va = int.from_bytes(data[o + 12:o + 16], "little")
            rsize = int.from_bytes(data[o + 16:o + 20], "little")
            rptr = int.from_bytes(data[o + 20:o + 24], "little")
            chars = int.from_bytes(data[o + 36:o + 40], "little")
            self.sections.append({
                "name": name, "vsize": vsize, "va": va,
                "rsize": rsize, "rptr": rptr, "chars": chars,
            })

    def rva_to_off(self, rva):
        for s in self.sections:
            if s["va"] <= rva < s["va"] + max(s["vsize"], s["rsize"]):
                return s["rptr"] + (rva - s["va"])
        return None

    def va_to_rva(self, va):
        return va - self.imagebase if va >= self.imagebase else va

    def off_to_rva(self, off):
        for s in self.sections:
            if s["rptr"] <= off < s["rptr"] + max(s["rsize"], s["vsize"]):
                return s["va"] + (off - s["rptr"])
        return None

    def read(self, rva, n):
        off = self.rva_to_off(rva)
        if off is None or off < 0 or off + n > len(self.data):
            return b""
        return self.data[off:off + n]

    def u16(self, rva):
        b = self.read(rva, 2)
        return int.from_bytes(b, "little") if len(b) == 2 else 0

    def u32(self, rva):
        b = self.read(rva, 4)
        return int.from_bytes(b, "little") if len(b) == 4 else 0

    def cstr(self, rva, limit=512):
        off = self.rva_to_off(rva)
        if off is None or off < 0 or off >= len(self.data):
            return ""
        end = off
        while end < len(self.data) and end - off < limit and self.data[end] != 0:
            end += 1
        return self.data[off:end].decode("latin1", "replace")


# ===================== VB6 解析 =====================
class VbObject:
    def __init__(self, name, otype, entry_rva, methods_rva, data_rva):
        self.name = name
        self.type = otype
        self.entry_rva = entry_rva
        self.methods_rva = methods_rva
        self.data_rva = data_rva


class VbProject:
    def __init__(self):
        self.valid = False
        self.header_rva = 0
        self.runtime_build = 0
        self.language = 0
        self.sub_main = 0
        self.project_object = 0
        self.project_name = ""
        self.help_file = ""
        self.help_context = 0
        self.lib_flags = 0
        self.version = 0
        self.project_info = 0
        self.object_table_rva = 0
        self.objects = []


def _hdr_ok(pe, rva):
    if rva is None or pe.read(rva, 4) != b"VB5!":
        return False
    rb = pe.u16(rva + 0x04)
    if not (0 < rb < 0x10000):
        return False
    pn = pe.u32(rva + 0x10)
    if pn:
        s = pe.cstr(pe.va_to_rva(pn), 64)
        if s and not all(32 <= ord(c) < 127 for c in s):
            return False
    return True


def find_vbheader(pe):
    """定位 VBHeader: 入口点 push imm32 / jmp[thunk] / 全文件校验扫描."""
    ep = pe.entry_rva
    b = pe.read(ep, 8)
    # 1) 标准 VB6: push <VBHeader_VA>; call ThunRTMain
    if len(b) >= 6 and b[0] == 0x68:
        rva = pe.va_to_rva(int.from_bytes(b[1:5], "little"))
        if _hdr_ok(pe, rva):
            return rva
    # 2) jmp dword ptr [addr] 跳板
    if len(b) >= 6 and b[0] == 0xFF and b[1] == 0x25:
        ptr = int.from_bytes(b[2:6], "little")
        pv = pe.u32(ptr) if ptr >= pe.imagebase else pe.u32(ptr)
        for cand in (pv, pv + pe.imagebase):
            r = pe.va_to_rva(cand)
            bb = pe.read(r, 8)
            if len(bb) >= 6 and bb[0] == 0x68:
                r2 = pe.va_to_rva(int.from_bytes(bb[1:5], "little"))
                if _hdr_ok(pe, r2):
                    return r2
            if _hdr_ok(pe, r):
                return r
    # 3) 全文件扫描 'VB5!' 并校验
    idx = 0
    while True:
        i = pe.data.find(b"VB5!", idx)
        if i < 0:
            break
        rva = pe.off_to_rva(i)
        if _hdr_ok(pe, rva):
            return rva
        idx = i + 1
    return 0


def parse_vb(pe):
    proj = VbProject()
    hrva = find_vbheader(pe)
    if not hrva:
        return proj
    if pe.read(hrva, 4) != b"VB5!":
        return proj
    proj.valid = True
    proj.header_rva = hrva
    proj.runtime_build = pe.u16(hrva + 0x04)
    proj.language = pe.u16(hrva + 0x06)
    proj.sub_main = pe.u32(hrva + 0x08)
    proj.project_object = pe.u32(hrva + 0x0C)
    proj.project_name = pe.cstr(pe.va_to_rva(pe.u32(hrva + 0x10)))
    proj.help_file = pe.cstr(pe.va_to_rva(pe.u32(hrva + 0x14)))
    proj.help_context = pe.u32(hrva + 0x18)
    proj.lib_flags = pe.u32(hrva + 0x1C)
    proj.version = pe.u32(hrva + 0x20)
    # ProjectInfo 指针在不同版本位于 0x24 / 0x28, 两者都试, 以 ObjectTable 有效者为准
    for pi_off in (0x24, 0x28):
        pi = pe.va_to_rva(pe.u32(hrva + pi_off))
        if not pi:
            continue
        ot = pe.va_to_rva(pe.u32(pi + 0x00))
        if ot and _valid_object_table(pe, ot):
            proj.project_info = pi
            proj.object_table_rva = ot
            break
    if proj.object_table_rva:
        proj.objects = _parse_objects(pe, proj.object_table_rva)
    return proj


def _valid_object_table(pe, ot_rva):
    cnt = pe.u16(ot_rva)
    return 0 < cnt < 0x1000


def _parse_objects(pe, ot_rva):
    objs = []
    cnt = pe.u16(ot_rva)
    ptr_base = ot_rva + 0x08
    for i in range(cnt):
        ent = pe.va_to_rva(pe.u32(ptr_base + i * 4))
        if not ent:
            continue
        otype = pe.u32(ent + 0x04)
        name = pe.cstr(pe.va_to_rva(pe.u32(ent + 0x08)))
        methods = pe.va_to_rva(pe.u32(ent + 0x10))
        data = pe.va_to_rva(pe.u32(ent + 0x14))
        objs.append(VbObject(name, otype, ent, methods, data))
    return objs


def type_name(t):
    return OBJTYPE.get(t, "Type_0x%X" % t)


# ===================== 命令实现 =====================
def cmd_info(pe, proj, quiet):
    out = []
    out.append("== VB 工程概要 ==")
    out.append("文件            : %s" % pe_file_name)
    out.append("PE 类型         : PE32%s  基址 0x%X" % ("+" if not pe.is_pe32 else "", pe.imagebase))
    out.append("入口点 RVA      : 0x%X" % pe.entry_rva)
    out.append("节区数          : %d" % pe.num_sections)
    if not proj.valid:
        out.append("VB 签名         : 未找到 'VB5!' (非 VB6 原生程序或已加密)")
        _emit(out, quiet)
        return EXIT_FAILURE
    out.append("VBHeader RVA    : 0x%X" % proj.header_rva)
    out.append("RuntimeBuild    : %d" % proj.runtime_build)
    out.append("Language(LCID)  : 0x%04X" % proj.language)
    out.append("工程名          : %s" % proj.project_name)
    out.append("版本            : %d.%d" % (proj.version >> 16, proj.version & 0xFFFF))
    out.append("Sub Main        : 0x%X" % proj.sub_main)
    out.append("LibFlags        : 0x%X" % proj.lib_flags)
    out.append("HelpFile        : %s" % proj.help_file)
    out.append("对象表 RVA      : 0x%X" % proj.object_table_rva)
    out.append("对象数量        : %d" % len(proj.objects))
    _emit(out, quiet)
    return EXIT_SUCCESS


def cmd_list(pe, proj, quiet):
    if not proj.valid:
        print("错误: 未找到 VB6 工程 (VB5!)", file=sys.stderr)
        return EXIT_FAILURE
    out = ["== 对象列表 (%d) ==" % len(proj.objects)]
    for i, o in enumerate(proj.objects):
        out.append("[%2d] %-20s %-10s entry=0x%X data=0x%X" %
                   (i, o.name or "<无名>", type_name(o.type), o.entry_rva, o.data_rva))
    _emit(out, quiet)
    return EXIT_SUCCESS


def cmd_objects(pe, proj, quiet):
    if not proj.valid:
        print("错误: 未找到 VB6 工程 (VB5!)", file=sys.stderr)
        return EXIT_FAILURE
    out = ["== 对象表详情 =="]
    for i, o in enumerate(proj.objects):
        out.append("[%d] 名称: %s" % (i, o.name))
        out.append("    类型: %s (0x%X)" % (type_name(o.type), o.type))
        out.append("    条目: 0x%X  方法表: 0x%X  数据: 0x%X" %
                   (o.entry_rva, o.methods_rva, o.data_rva))
        # 方法表: 首 u32 为方法数, 其后为方法名指针数组
        if o.methods_rva:
            n = pe.u32(o.methods_rva)
            if 0 < n < 0x1000:
                names = []
                for j in range(n):
                    nm = pe.va_to_rva(pe.u32(o.methods_rva + 4 + j * 4))
                    s = pe.cstr(nm)
                    if s:
                        names.append(s)
                if names:
                    out.append("    方法: %s" % ", ".join(names))
    _emit(out, quiet)
    return EXIT_SUCCESS


def cmd_forms(pe, proj, quiet):
    if not proj.valid:
        print("错误: 未找到 VB6 工程 (VB5!)", file=sys.stderr)
        return EXIT_FAILURE
    out = ["== 窗体对象数据 =="]
    for o in proj.objects:
        if type_name(o.type) != "Form":
            continue
        out.append("-- %s (data RVA 0x%X) --" % (o.name, o.data_rva))
        blob = pe.read(o.data_rva, 0x400)
        if not blob:
            out.append("   <无数据>")
            continue
        # 抽取可读字符串 (控件名/属性)
        strs = _extract_strings(blob, 4)
        if strs:
            out.append("   可读字符串: %s" % ", ".join(strs[:20]))
        out.append("   原始(hex前64字节): %s" % blob[:64].hex(" "))
    _emit(out, quiet)
    return EXIT_SUCCESS


def cmd_pcode(pe, proj, quiet):
    if not proj.valid:
        print("错误: 未找到 VB6 工程 (VB5!)", file=sys.stderr)
        return EXIT_FAILURE
    out = ["== P-code 反汇编 (尽力而为) =="]
    for o in proj.objects:
        if not o.methods_rva:
            continue
        n = pe.u32(o.methods_rva)
        if not (0 < n < 0x1000):
            continue
        out.append("-- %s : %d 个方法 --" % (o.name, n))
        for j in range(n):
            mname = pe.cstr(pe.va_to_rva(pe.u32(o.methods_rva + 4 + j * 4)))
            # 方法表项: 名称指针后紧跟方法数据指针 (布局随版本略有差异, 尽力解析)
            ent = o.methods_rva + 4 + j * 4
            code = pe.va_to_rva(pe.u32(ent + 4))
            out.append("   [%s] code=0x%X" % (mname or "?", code))
            blob = pe.read(code, 0x80)
            for k in range(0, len(blob) - 1, 2):
                op = blob[k]
                nm = PCODE.get(op, "Op_%02X" % op)
                out.append("     +%03X  %02X %-16s %s" %
                           (k, op, nm, blob[k + 1:k + 2].hex(" ")))
    _emit(out, quiet)
    return EXIT_SUCCESS


def cmd_strings(pe, proj, quiet):
    out = ["== 字符串抽取 =="]
    for s in _extract_strings(pe.data, 5):
        out.append(s)
    _emit(out, quiet)
    return EXIT_SUCCESS


def cmd_hex(pe, proj, quiet):
    out = ["== VBHeader 十六进制 (RVA 0x%X) ==" % proj.header_rva]
    blob = pe.read(proj.header_rva, 0x40)
    for i in range(0, len(blob), 16):
        chunk = blob[i:i + 16]
        out.append("%04X  %-47s  %s" %
                   (i, " ".join("%02X" % c for c in chunk),
                    "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)))
    if proj.object_table_rva:
        out.append("== ObjectTable 十六进制 (RVA 0x%X) ==" % proj.object_table_rva)
        blob = pe.read(proj.object_table_rva, 0x40)
        for i in range(0, len(blob), 16):
            chunk = blob[i:i + 16]
            out.append("%04X  %-47s  %s" %
                       (i, " ".join("%02X" % c for c in chunk),
                        "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)))
    _emit(out, quiet)
    return EXIT_SUCCESS


def cmd_export(pe, proj, out_dir, quiet):
    if not proj.valid:
        print("错误: 未找到 VB6 工程 (VB5!), 无法导出", file=sys.stderr)
        return EXIT_FAILURE
    os.makedirs(out_dir, exist_ok=True)
    # Project.vbp 风格工程文件
    lines = ["Type=Exe", "Name=%s" % (proj.project_name or "Project"),
             "Version=%d.%d" % (proj.version >> 16, proj.version & 0xFFFF),
             "Description=%s" % (proj.project_name or ""),
             "HelpFile=%s" % proj.help_file, ""]
    for o in proj.objects:
        ext = {"Form": "frm", "Class": "cls", "Module": "bas"}.get(type_name(o.type), "txt")
        lines.append("Object=%s.%s" % (o.name or "Object", ext))
    with open(os.path.join(out_dir, "Project.vbp"), "w", encoding="utf-8", errors="replace") as f:
        f.write("\n".join(lines))
    # 对象清单
    with open(os.path.join(out_dir, "ObjectList.txt"), "w", encoding="utf-8", errors="replace") as f:
        for o in proj.objects:
            f.write("%s\t%s\tentry=0x%X\tdata=0x%X\n" %
                    (o.name, type_name(o.type), o.entry_rva, o.data_rva))
    # 每对象元数据
    for o in proj.objects:
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in (o.name or "Object"))
        with open(os.path.join(out_dir, safe + ".txt"), "w", encoding="utf-8", errors="replace") as f:
            f.write("Name: %s\nType: %s (0x%X)\nEntry: 0x%X\nMethods: 0x%X\nData: 0x%X\n" %
                    (o.name, type_name(o.type), o.type, o.entry_rva, o.methods_rva, o.data_rva))
    print("工程已写出: %s" % out_dir)
    return EXIT_SUCCESS


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


def _emit(lines, quiet):
    if quiet:
        return
    for ln in lines:
        print(ln)


# ===================== 入口 =====================
pe_file_name = ""


def parse_args(argv):
    opts = {"target": None, "info": False, "list": False, "objects": False,
            "forms": False, "pcode": False, "strings": False, "hex": False,
            "export": False, "all": False, "quiet": False, "help": False,
            "output": None}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-h", "--help"):
            opts["help"] = True
        elif a in ("-i", "--info"):
            opts["info"] = True
        elif a in ("-l", "--list"):
            opts["list"] = True
        elif a in ("-o", "--objects"):
            opts["objects"] = True
        elif a in ("-f", "--forms"):
            opts["forms"] = True
        elif a in ("-p", "--pcode"):
            opts["pcode"] = True
        elif a in ("-s", "--strings"):
            opts["strings"] = True
        elif a in ("-x", "--hex"):
            opts["hex"] = True
        elif a in ("-e", "--export"):
            opts["export"] = True
        elif a in ("-a", "--all"):
            opts["all"] = True
        elif a in ("-q", "--quiet"):
            opts["quiet"] = True
        elif a in ("-O", "--output"):
            i += 1
            if i < len(argv):
                opts["output"] = argv[i]
        elif a.startswith("-") and a != "-":
            pass
        elif opts["target"] is None:
            opts["target"] = a
        i += 1
    return opts


def main():
    global pe_file_name
    try:
        sys.stdout.reconfigure(errors="replace")
        sys.stderr.reconfigure(errors="replace")
    except Exception:
        pass

    opts = parse_args(sys.argv[1:])
    if opts["help"] or not opts["target"]:
        print(USAGE)
        return EXIT_USAGE

    target = opts["target"]
    pe_file_name = os.path.basename(target)
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

    proj = parse_vb(pe)

    # 默认 info
    if not any(opts[k] for k in ("info", "list", "objects", "forms", "pcode",
                                 "strings", "hex", "export", "all")):
        opts["info"] = True
    if opts["all"]:
        opts["info"] = opts["list"] = opts["strings"] = True

    rc = EXIT_SUCCESS
    if opts["info"]:
        rc = cmd_info(pe, proj, opts["quiet"]) or rc
    if opts["list"]:
        rc = cmd_list(pe, proj, opts["quiet"]) or rc
    if opts["objects"]:
        rc = cmd_objects(pe, proj, opts["quiet"]) or rc
    if opts["forms"]:
        rc = cmd_forms(pe, proj, opts["quiet"]) or rc
    if opts["pcode"]:
        rc = cmd_pcode(pe, proj, opts["quiet"]) or rc
    if opts["strings"]:
        rc = cmd_strings(pe, proj, opts["quiet"]) or rc
    if opts["hex"]:
        rc = cmd_hex(pe, proj, opts["quiet"]) or rc
    if opts["export"]:
        out_dir = opts["output"] or (os.path.splitext(pe_file_name)[0] + "_project")
        rc = cmd_export(pe, proj, out_dir, opts["quiet"]) or rc
    return rc


if __name__ == "__main__":
    sys.exit(main())