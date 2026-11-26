#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ILByteDecoder 2.1 — Python CLI rewrite
======================================

原程序：ILByteDecoder_2.1/ILByteDecoder.exe
         (native MFC GUI, 输入 IL 字节 -> 反汇编为 IL 指令)

原程序把一段 IL 机器码（十六进制字节）解码成 IL 指令（助记符 + 操作数）。
该解码算法即 ECMA-335 Partition III 定义的 CIL 指令集，本程序用纯 Python
完整实现（单字节 + 0xFE 双字节前缀 + 操作数按类型解码），无第三方依赖。

用法：
    python main.py "02 1C 58 2A"          # 直接给十六进制字节
    python main.py -f code.bin            # 从二进制文件读取
    python main.py -f code.bin -o out.txt # 同时写入文件

输出示例：
    IL_0000: ldarg.0
    IL_0001: ldc.i4.1
    IL_0002: add
    IL_0003: ret
"""

import argparse
import struct
import sys

# ---------------------------------------------------------------------------
# 操作数类型
# ---------------------------------------------------------------------------
NONE = "none"
SBYTE = "sbyte"          # ShortInlineI  (1 字节有符号)
INT32 = "int32"          # InlineI
INT64 = "int64"          # InlineI8
FLOAT32 = "float32"      # ShortInlineR
FLOAT64 = "float64"      # InlineR
SHORTVAR = "shortvar"    # ShortInlineVar (1 字节无符号 变量/参数索引)
VAR = "var"              # InlineVar (2 字节无符号)
BRSHORT = "brshort"      # ShortInlineBrTarget (1 字节相对)
BRINT = "brint"          # InlineBrTarget (4 字节相对)
TOKEN = "token"          # InlineString/Method/Field/Type/Sig/Tok (4 字节)
SWITCH = "switch"        # InlineSwitch
U8 = "u8"                # 1 字节无符号 (unaligned./no. 的对齐/标志)

# ---------------------------------------------------------------------------
# 单字节操作码表: code -> (助记符, 操作数类型)
# 依据 ECMA-335 Partition III opcode 定义。
# ---------------------------------------------------------------------------
OP1 = {
    0x00: ("nop", NONE), 0x01: ("break", NONE),
    0x02: ("ldarg.0", NONE), 0x03: ("ldarg.1", NONE), 0x04: ("ldarg.2", NONE), 0x05: ("ldarg.3", NONE),
    0x06: ("ldloc.0", NONE), 0x07: ("ldloc.1", NONE), 0x08: ("ldloc.2", NONE), 0x09: ("ldloc.3", NONE),
    0x0A: ("stloc.0", NONE), 0x0B: ("stloc.1", NONE), 0x0C: ("stloc.2", NONE), 0x0D: ("stloc.3", NONE),
    0x0E: ("ldarg.s", SHORTVAR), 0x0F: ("ldarga.s", SHORTVAR),
    0x10: ("starg.s", SHORTVAR), 0x11: ("ldloc.s", SHORTVAR),
    0x12: ("ldloca.s", SHORTVAR), 0x13: ("stloc.s", SHORTVAR),
    0x14: ("ldnull", NONE), 0x15: ("ldc.i4.m1", NONE),
    0x16: ("ldc.i4.0", NONE), 0x17: ("ldc.i4.1", NONE), 0x18: ("ldc.i4.2", NONE),
    0x19: ("ldc.i4.3", NONE), 0x1A: ("ldc.i4.4", NONE), 0x1B: ("ldc.i4.5", NONE),
    0x1C: ("ldc.i4.6", NONE), 0x1D: ("ldc.i4.7", NONE), 0x1E: ("ldc.i4.8", NONE),
    0x1F: ("ldc.i4.s", SBYTE), 0x20: ("ldc.i4", INT32), 0x21: ("ldc.i8", INT64),
    0x22: ("ldc.r4", FLOAT32), 0x23: ("ldc.r8", FLOAT64),
    0x25: ("dup", NONE), 0x26: ("pop", NONE),
    0x27: ("jmp", TOKEN), 0x28: ("call", TOKEN), 0x29: ("calli", TOKEN),
    0x2A: ("ret", NONE),
    0x2B: ("br.s", BRSHORT), 0x2C: ("brfalse.s", BRSHORT), 0x2D: ("brtrue.s", BRSHORT),
    0x2E: ("beq.s", BRSHORT), 0x2F: ("bge.s", BRSHORT), 0x30: ("bgt.s", BRSHORT),
    0x31: ("ble.s", BRSHORT), 0x32: ("blt.s", BRSHORT),
    0x33: ("bne.un.s", BRSHORT), 0x34: ("bge.un.s", BRSHORT), 0x35: ("bgt.un.s", BRSHORT),
    0x36: ("ble.un.s", BRSHORT), 0x37: ("blt.un.s", BRSHORT),
    0x38: ("br", BRINT), 0x39: ("brfalse", BRINT), 0x3A: ("brtrue", BRINT),
    0x3B: ("beq", BRINT), 0x3C: ("bge", BRINT), 0x3D: ("bgt", BRINT),
    0x3E: ("ble", BRINT), 0x3F: ("blt", BRINT),
    0x40: ("bne.un", BRINT), 0x41: ("bge.un", BRINT), 0x42: ("bgt.un", BRINT),
    0x43: ("ble.un", BRINT), 0x44: ("blt.un", BRINT),
    0x45: ("switch", SWITCH),
    0x46: ("ldind.i1", NONE), 0x47: ("ldind.u1", NONE), 0x48: ("ldind.i2", NONE),
    0x49: ("ldind.u2", NONE), 0x4A: ("ldind.i4", NONE), 0x4B: ("ldind.u4", NONE),
    0x4C: ("ldind.i8", NONE), 0x4D: ("ldind.i", NONE), 0x4E: ("ldind.r4", NONE),
    0x4F: ("ldind.r8", NONE), 0x50: ("ldind.ref", NONE),
    0x51: ("stind.ref", NONE), 0x52: ("stind.i1", NONE), 0x53: ("stind.i2", NONE),
    0x54: ("stind.i4", NONE), 0x55: ("stind.i8", NONE), 0x56: ("stind.r4", NONE),
    0x57: ("stind.r8", NONE),
    0x58: ("add", NONE), 0x59: ("sub", NONE), 0x5A: ("mul", NONE),
    0x5B: ("div", NONE), 0x5C: ("div.un", NONE), 0x5D: ("rem", NONE),
    0x5E: ("rem.un", NONE), 0x5F: ("and", NONE), 0x60: ("or", NONE),
    0x61: ("xor", NONE), 0x62: ("shl", NONE), 0x63: ("shr", NONE),
    0x64: ("shr.un", NONE), 0x65: ("neg", NONE), 0x66: ("not", NONE),
    0x67: ("conv.i1", NONE), 0x68: ("conv.i2", NONE), 0x69: ("conv.i4", NONE),
    0x6A: ("conv.i8", NONE), 0x6B: ("conv.r4", NONE), 0x6C: ("conv.r8", NONE),
    0x6D: ("conv.u4", NONE), 0x6E: ("conv.u8", NONE),
    0x6F: ("callvirt", TOKEN), 0x70: ("cpobj", TOKEN), 0x71: ("ldobj", TOKEN),
    0x72: ("ldstr", TOKEN), 0x73: ("newobj", TOKEN), 0x74: ("castclass", TOKEN),
    0x75: ("isinst", TOKEN), 0x76: ("conv.r.un", NONE),
    0x79: ("unbox", TOKEN), 0x7A: ("throw", NONE),
    0x7B: ("ldfld", TOKEN), 0x7C: ("ldflda", TOKEN), 0x7D: ("stfld", TOKEN),
    0x7E: ("ldsfld", TOKEN), 0x7F: ("ldsflda", TOKEN), 0x80: ("stsfld", TOKEN),
    0x81: ("stobj", TOKEN),
    0x82: ("conv.ovf.i1.un", NONE), 0x83: ("conv.ovf.i2.un", NONE),
    0x84: ("conv.ovf.i4.un", NONE), 0x85: ("conv.ovf.i8.un", NONE),
    0x86: ("conv.ovf.u1.un", NONE), 0x87: ("conv.ovf.u2.un", NONE),
    0x88: ("conv.ovf.u4.un", NONE), 0x89: ("conv.ovf.u8.un", NONE),
    0x8A: ("conv.ovf.i.un", NONE), 0x8B: ("conv.ovf.u.un", NONE),
    0x8C: ("box", TOKEN), 0x8D: ("newarr", TOKEN), 0x8E: ("ldlen", NONE),
    0x8F: ("ldelema", TOKEN),
    0x90: ("ldelem.i1", NONE), 0x91: ("ldelem.u1", NONE), 0x92: ("ldelem.i2", NONE),
    0x93: ("ldelem.u2", NONE), 0x94: ("ldelem.i4", NONE), 0x95: ("ldelem.u4", NONE),
    0x96: ("ldelem.i8", NONE), 0x97: ("ldelem.i", NONE), 0x98: ("ldelem.r4", NONE),
    0x99: ("ldelem.r8", NONE), 0x9A: ("ldelem.ref", NONE),
    0x9B: ("stelem.i", NONE), 0x9C: ("stelem.i1", NONE), 0x9D: ("stelem.i2", NONE),
    0x9E: ("stelem.i4", NONE), 0x9F: ("stelem.i8", NONE), 0xA0: ("stelem.r4", NONE),
    0xA1: ("stelem.r8", NONE), 0xA2: ("stelem.ref", NONE),
    0xA3: ("ldelem", TOKEN), 0xA4: ("stelem", TOKEN), 0xA5: ("unbox.any", TOKEN),
    0xB3: ("conv.ovf.i1", NONE), 0xB4: ("conv.ovf.u1", NONE),
    0xB5: ("conv.ovf.i2", NONE), 0xB6: ("conv.ovf.u2", NONE),
    0xB7: ("conv.ovf.i4", NONE), 0xB8: ("conv.ovf.u4", NONE),
    0xB9: ("conv.ovf.i8", NONE), 0xBA: ("conv.ovf.u8", NONE),
    0xC2: ("refanyval", TOKEN), 0xC3: ("ckfinite", NONE),
    0xC6: ("mkrefany", TOKEN),
    0xD0: ("ldtoken", TOKEN),
    0xD1: ("conv.u2", NONE), 0xD2: ("conv.u1", NONE), 0xD3: ("conv.i", NONE),
    0xD4: ("conv.ovf.i", NONE), 0xD5: ("conv.ovf.u", NONE),
    0xD6: ("add.ovf", NONE), 0xD7: ("add.ovf.un", NONE),
    0xD8: ("mul.ovf", NONE), 0xD9: ("mul.ovf.un", NONE),
    0xDA: ("sub.ovf", NONE), 0xDB: ("sub.ovf.un", NONE),
    0xDC: ("endfinally", NONE), 0xDD: ("leave", BRINT), 0xDE: ("leave.s", BRSHORT),
    0xDF: ("stind.i", NONE), 0xE0: ("conv.u", NONE),
}

# ---------------------------------------------------------------------------
# 0xFE 双字节操作码表: 第二字节 -> (助记符, 操作数类型)
# ---------------------------------------------------------------------------
OP2 = {
    0x00: ("arglist", NONE),
    0x01: ("ceq", NONE), 0x02: ("cgt", NONE), 0x03: ("cgt.un", NONE),
    0x04: ("clt", NONE), 0x05: ("clt.un", NONE),
    0x06: ("ldftn", TOKEN), 0x07: ("ldvirtftn", TOKEN),
    0x09: ("ldarg", VAR), 0x0A: ("ldarga", VAR), 0x0B: ("starg", VAR),
    0x0C: ("ldloc", VAR), 0x0D: ("ldloca", VAR), 0x0E: ("stloc", VAR),
    0x0F: ("localloc", NONE),
    0x11: ("endfilter", NONE),
    0x12: ("unaligned.", U8), 0x13: ("volatile.", NONE), 0x14: ("tail.", NONE),
    0x15: ("initobj", TOKEN), 0x16: ("constrained.", TOKEN),
    0x17: ("cpblk", NONE), 0x18: ("initblk", NONE), 0x19: ("no.", U8),
    0x1A: ("rethrow", NONE),
    0x1C: ("sizeof", TOKEN), 0x1D: ("refanytype", NONE), 0x1E: ("readonly.", NONE),
}


class ByteReader:
    def __init__(self, data):
        self.d = data
        self.i = 0

    def eof(self):
        return self.i >= len(self.d)

    def u8(self):
        b = self.d[self.i]
        self.i += 1
        return b

    def s8(self):
        b = self.u8()
        return b - 0x100 if b & 0x80 else b

    def u16(self):
        v = self.d[self.i] | (self.d[self.i + 1] << 8)
        self.i += 2
        return v

    def u32(self):
        v = (self.d[self.i] | (self.d[self.i + 1] << 8) |
             (self.d[self.i + 2] << 16) | (self.d[self.i + 3] << 24))
        self.i += 4
        return v

    def i32(self):
        v = self.u32()
        return v - 0x100000000 if v & 0x80000000 else v

    def i64(self):
        v = self.u32() | (self.u32() << 32)
        return v - 0x10000000000000000 if v & 0x8000000000000000 else v

    def f32(self):
        return struct.unpack("<f", self.d[self.i:self.i + 4])[0]

    def f64(self):
        return struct.unpack("<d", self.d[self.i:self.i + 8])[0]


def fmt_token(tok):
    return "0x%08X" % (tok & 0xFFFFFFFF)


def decode(data):
    """把 IL 字节解码为 [(offset, mnemonic, operand_str)] 列表。"""
    r = ByteReader(data)
    out = []
    while not r.eof():
        start = r.i
        op = r.u8()
        if op == 0xFE:
            op2 = r.u8()
            mnem, otype = OP2.get(op2, ("unknown_fe_%02x" % op2, NONE))
        else:
            mnem, otype = OP1.get(op, ("unknown_%02x" % op, NONE))

        operand = ""
        if otype == NONE:
            operand = ""
        elif otype == SBYTE:
            operand = str(r.s8())
        elif otype == INT32:
            operand = str(r.i32())
        elif otype == INT64:
            operand = str(r.i64())
        elif otype == FLOAT32:
            operand = _ff(r.f32())
        elif otype == FLOAT64:
            operand = _ff(r.f64())
        elif otype == SHORTVAR:
            operand = str(r.u8())
        elif otype == VAR:
            operand = str(r.u16())
        elif otype == BRSHORT:
            operand = "IL_%04X" % ((start + 2 + r.s8()) & 0xFFFF)
        elif otype == BRINT:
            operand = "IL_%04X" % ((start + 5 + r.i32()) & 0xFFFF)
        elif otype == TOKEN:
            operand = fmt_token(r.u32())
        elif otype == U8:
            operand = str(r.u8())
        elif otype == SWITCH:
            n = r.u32()
            base = r.i + n * 4
            tgts = [base + r.i32() for _ in range(n)]
            operand = "(" + ", ".join("IL_%04X" % (t & 0xFFFF) for t in tgts) + ")"
        out.append((start, mnem, operand))
    return out


def _ff(v):
    # 浮点格式化：整数值去掉小数点
    if v == int(v) and abs(v) < 1e16:
        return str(int(v))
    return repr(v)


def parse_hex(s):
    s = s.strip()
    # 允许 "0x" 前缀、空格/逗号分隔
    s = s.replace(",", " ").replace("0x", " ").replace("0X", " ")
    parts = s.split()
    return bytes(int(p, 16) for p in parts)


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="ILByteDecoder 2.1 — Python CLI rewrite. "
                    "Decode CIL (MSIL) bytecode into IL instructions.")
    ap.add_argument("hex", nargs="?", help="IL 机器码（十六进制字节，空格分隔）")
    ap.add_argument("-f", "--file", help="从二进制文件读取 IL 字节")
    ap.add_argument("-o", "--output", help="输出写入文件（默认打印到 stdout）")
    args = ap.parse_args(argv)

    if args.file:
        with open(args.file, "rb") as f:
            data = f.read()
    elif args.hex:
        try:
            data = parse_hex(args.hex)
        except ValueError as e:
            print("Error: invalid hex input: %s" % e, file=sys.stderr)
            return 2
    else:
        ap.print_help(sys.stderr)
        return 2

    lines = []
    for off, mnem, operand in decode(data):
        if operand:
            lines.append("IL_%04X: %-14s %s" % (off, mnem, operand))
        else:
            lines.append("IL_%04X: %s" % (off, mnem))
    text = "\n".join(lines)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(text + "\n")
        print("wrote %s (%d instructions)" % (args.output, len(lines)), file=sys.stderr)
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())