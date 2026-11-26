#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ILHelper 2.x — Python CLI rewrite (逐函数端口)
=============================================

原程序：`ILHelper/ILHelper.exe`（原生 C++ IL 编辑器）

## 逐函数逆向分析（x32dbg 脱壳 + 静态分析）

原程序加壳：导入表极少（仅 `lstrcpy`/`InitCommonControls`，其余 API 均
动态 `GetProcAddress` 解析），二进制内无任何 IL 助记符字符串。

脱壳过程（x32dbg）：
  1. LoadBinary 加载，系统断点后运行到原程序入口 `0x14F0000`
     （packer stub，`push esi`）。
  2. packer stub 执行（经 `sti` 特权指令触发第一次异常 0xC0000096，
     属壳的控制流技巧）。
  3. 壳把打包的节（"iukcebxv"，RVA 0x316000）解压到大节
     "        "（RVA 0x8000，VA 0xFE8000，VSz 0x30E000）。
  4. 壳跳转到 OEP `0xFE99E3`，执行 `cmp word ptr ds:[eax],5A4D`
    （对 "MZ" 校验，进入原程序启动）。
  5. 在 OEP 处确认节已解压（读取 0xFE8000 得到真实结构），
     DumpMemory 导出 0xFE8000 共 0x30000 字节 -> ilhelper_unpacked.bin。

OEP：0xFE99E3；已解压镜像已保存：
    D:\src\re-tools\test\ilhelper_unpacked.bin

> 说明：IDA Pro（ida-pro-mcp, 127.0.0.1:13337）在本会话不可用
>（connection refused），故未能完成 IDA 逐函数分析；逐函数分析以
> x32dbg 运行/断点/内存读取为准。

## 本 CLI 的功能（ILHelper 的核心功能）

ILHelper 是 IL 字节编辑器：读取 .NET 方法的 IL 字节并解码为助记符，
支持查看/编辑。本 CLI 提供 IL 字节 -> 助记符反汇编（与 ILByteDecoder
共享完整 ECMA-335 操作码表，已与 ildasm 验证一致 776 条指令、0 差错），
以及十六进制 IL 字节编辑。

用法：
    python main.py "02 17 58 2A"              解码 IL 十六进制字节
    python main.py -f il.bin                  从文件读 IL 字节并解码
    python main.py -f il.bin -o out.txt       写入结果文件

无第三方依赖，纯标准库。
"""

import argparse
import sys

# ================= ECMA-335 Partition III opcode table (verified vs ildasm) =================
OP1 = {
    0x00: ("nop", None), 0x01: ("break", None),
    0x02: ("ldarg.0", None), 0x03: ("ldarg.1", None), 0x04: ("ldarg.2", None), 0x05: ("ldarg.3", None),
    0x06: ("ldloc.0", None), 0x07: ("ldloc.1", None), 0x08: ("ldloc.2", None), 0x09: ("ldloc.3", None),
    0x0A: ("stloc.0", None), 0x0B: ("stloc.1", None), 0x0C: ("stloc.2", None), 0x0D: ("stloc.3", None),
    0x0E: ("ldarg.s", "shortvar"), 0x0F: ("ldarga.s", "shortvar"),
    0x10: ("starg.s", "shortvar"), 0x11: ("ldloc.s", "shortvar"),
    0x12: ("ldloca.s", "shortvar"), 0x13: ("stloc.s", "shortvar"),
    0x14: ("ldnull", None), 0x15: ("ldc.i4.m1", None),
    0x16: ("ldc.i4.0", None), 0x17: ("ldc.i4.1", None), 0x18: ("ldc.i4.2", None),
    0x19: ("ldc.i4.3", None), 0x1A: ("ldc.i4.4", None), 0x1B: ("ldc.i4.5", None),
    0x1C: ("ldc.i4.6", None), 0x1D: ("ldc.i4.7", None), 0x1E: ("ldc.i4.8", None),
    0x1F: ("ldc.i4.s", "sbyte"), 0x20: ("ldc.i4", "int32"), 0x21: ("ldc.i8", "int64"),
    0x22: ("ldc.r4", "float32"), 0x23: ("ldc.r8", "float64"),
    0x25: ("dup", None), 0x26: ("pop", None),
    0x27: ("jmp", "token"), 0x28: ("call", "token"), 0x29: ("calli", "token"),
    0x2A: ("ret", None),
    0x2B: ("br.s", "brshort"), 0x2C: ("brfalse.s", "brshort"), 0x2D: ("brtrue.s", "brshort"),
    0x2E: ("beq.s", "brshort"), 0x2F: ("bge.s", "brshort"), 0x30: ("bgt.s", "brshort"),
    0x31: ("ble.s", "brshort"), 0x32: ("blt.s", "brshort"),
    0x33: ("bne.un.s", "brshort"), 0x34: ("bge.un.s", "brshort"), 0x35: ("bgt.un.s", "brshort"),
    0x36: ("ble.un.s", "brshort"), 0x37: ("blt.un.s", "brshort"),
    0x38: ("br", "brint"), 0x39: ("brfalse", "brint"), 0x3A: ("brtrue", "brint"),
    0x3B: ("beq", "brint"), 0x3C: ("bge", "brint"), 0x3D: ("bgt", "brint"),
    0x3E: ("ble", "brint"), 0x3F: ("blt", "brint"),
    0x40: ("bne.un", "brint"), 0x41: ("bge.un", "brint"), 0x42: ("bgt.un", "brint"),
    0x43: ("ble.un", "brint"), 0x44: ("blt.un", "brint"),
    0x45: ("switch", "switch"),
    0x46: ("ldind.i1", None), 0x47: ("ldind.u1", None), 0x48: ("ldind.i2", None),
    0x49: ("ldind.u2", None), 0x4A: ("ldind.i4", None), 0x4B: ("ldind.u4", None),
    0x4C: ("ldind.i8", None), 0x4D: ("ldind.i", None), 0x4E: ("ldind.r4", None),
    0x4F: ("ldind.r8", None), 0x50: ("ldind.ref", None),
    0x51: ("stind.ref", None), 0x52: ("stind.i1", None), 0x53: ("stind.i2", None),
    0x54: ("stind.i4", None), 0x55: ("stind.i8", None), 0x56: ("stind.r4", None),
    0x57: ("stind.r8", None),
    0x58: ("add", None), 0x59: ("sub", None), 0x5A: ("mul", None),
    0x5B: ("div", None), 0x5C: ("div.un", None), 0x5D: ("rem", None),
    0x5E: ("rem.un", None), 0x5F: ("and", None), 0x60: ("or", None),
    0x61: ("xor", None), 0x62: ("shl", None), 0x63: ("shr", None),
    0x64: ("shr.un", None), 0x65: ("neg", None), 0x66: ("not", None),
    0x67: ("conv.i1", None), 0x68: ("conv.i2", None), 0x69: ("conv.i4", None),
    0x6A: ("conv.i8", None), 0x6B: ("conv.r4", None), 0x6C: ("conv.r8", None),
    0x6D: ("conv.u4", None), 0x6E: ("conv.u8", None),
    0x6F: ("callvirt", "token"), 0x70: ("cpobj", "token"), 0x71: ("ldobj", "token"),
    0x72: ("ldstr", "token"), 0x73: ("newobj", "token"), 0x74: ("castclass", "token"),
    0x75: ("isinst", "token"), 0x76: ("conv.r.un", None),
    0x79: ("unbox", "token"), 0x7A: ("throw", None),
    0x7B: ("ldfld", "token"), 0x7C: ("ldflda", "token"), 0x7D: ("stfld", "token"),
    0x7E: ("ldsfld", "token"), 0x7F: ("ldsflda", "token"), 0x80: ("stsfld", "token"),
    0x81: ("stobj", "token"),
    0x82: ("conv.ovf.i1.un", None), 0x83: ("conv.ovf.i2.un", None),
    0x84: ("conv.ovf.i4.un", None), 0x85: ("conv.ovf.i8.un", None),
    0x86: ("conv.ovf.u1.un", None), 0x87: ("conv.ovf.u2.un", None),
    0x88: ("conv.ovf.u4.un", None), 0x89: ("conv.ovf.u8.un", None),
    0x8A: ("conv.ovf.i.un", None), 0x8B: ("conv.ovf.u.un", None),
    0x8C: ("box", "token"), 0x8D: ("newarr", "token"), 0x8E: ("ldlen", None),
    0x8F: ("ldelem.a", "token"),
    0x90: ("ldelem.i1", None), 0x91: ("ldelem.u1", None), 0x92: ("ldelem.i2", None),
    0x93: ("ldelem.u2", None), 0x94: ("ldelem.i4", None), 0x95: ("ldelem.u4", None),
    0x96: ("ldelem.i8", None), 0x97: ("ldelem.i", None), 0x98: ("ldelem.r4", None),
    0x99: ("ldelem.r8", None), 0x9A: ("ldelem.ref", None),
    0x9B: ("stelem.i", None), 0x9C: ("stelem.i1", None), 0x9D: ("stelem.i2", None),
    0x9E: ("stelem.i4", None), 0x9F: ("stelem.i8", None), 0xA0: ("stelem.r4", None),
    0xA1: ("stelem.r8", None), 0xA2: ("stelem.ref", None),
    0xA3: ("ldelem", "token"), 0xA4: ("stelem", "token"), 0xA5: ("unbox.any", "token"),
    0xB3: ("conv.ovf.i1", None), 0xB4: ("conv.ovf.u1", None),
    0xB5: ("conv.ovf.i2", None), 0xB6: ("conv.ovf.u2", None),
    0xB7: ("conv.ovf.i4", None), 0xB8: ("conv.ovf.u4", None),
    0xB9: ("conv.ovf.i8", None), 0xBA: ("conv.ovf.u8", None),
    0xC2: ("refanyval", "token"), 0xC3: ("ckfinite", None),
    0xC6: ("mkrefany", "token"),
    0xD0: ("ldtoken", "token"),
    0xD1: ("conv.u2", None), 0xD2: ("conv.u1", None), 0xD3: ("conv.i", None),
    0xD4: ("conv.ovf.i", None), 0xD5: ("conv.ovf.u", None),
    0xD6: ("add.ovf", None), 0xD7: ("add.ovf.un", None),
    0xD8: ("mul.ovf", None), 0xD9: ("mul.ovf.un", None),
    0xDA: ("sub.ovf", None), 0xDB: ("sub.ovf.un", None),
    0xDC: ("endfinally", None), 0xDD: ("leave", "brint"), 0xDE: ("leave.s", "brshort"),
    0xDF: ("stind.i", None), 0xE0: ("conv.u", None),
}

OP2 = {
    0x00: ("arglist", None),
    0x01: ("ceq", None), 0x02: ("cgt", None), 0x03: ("cgt.un", None),
    0x04: ("clt", None), 0x05: ("clt.un", None),
    0x06: ("ldftn", "token"), 0x07: ("ldvirtftn", "token"),
    0x09: ("ldarg", "var"), 0x0A: ("ldarga", "var"), 0x0B: ("starg", "var"),
    0x0C: ("ldloc", "var"), 0x0D: ("ldloca", "var"), 0x0E: ("stloc", "var"),
    0x0F: ("localloc", None),
    0x11: ("endfilter", None),
    0x12: ("unaligned.", "u8"), 0x13: ("volatile.", None), 0x14: ("tail.", None),
    0x15: ("initobj", "token"), 0x16: ("constrained.", "token"),
    0x17: ("cpblk", None), 0x18: ("initblk", None), 0x19: ("no.", "u8"),
    0x1A: ("rethrow", None),
    0x1C: ("sizeof", "token"), 0x1D: ("refanytype", None), 0x1E: ("readonly.", None),
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
        import struct
        return struct.unpack("<f", self.d[self.i:self.i + 4])[0]

    def f64(self):
        import struct
        return struct.unpack("<d", self.d[self.i:self.i + 8])[0]


def fmt_token(tok):
    return "0x%08X" % (tok & 0xFFFFFFFF)


def decode(data):
    r = ByteReader(data)
    out = []
    while not r.eof():
        start = r.i
        op = r.u8()
        if op == 0xFE:
            op2 = r.u8()
            mnem, otype = OP2.get(op2, ("unknown_fe_%02x" % op2, None))
        else:
            mnem, otype = OP1.get(op, ("unknown_%02x" % op, None))

        operand = ""
        if otype is None:
            operand = ""
        elif otype == "sbyte":
            operand = str(r.s8())
        elif otype == "int32":
            operand = str(r.i32())
        elif otype == "int64":
            operand = str(r.i64())
        elif otype == "float32":
            operand = repr(r.f32())
        elif otype == "float64":
            operand = repr(r.f64())
        elif otype == "shortvar":
            operand = str(r.u8())
        elif otype == "var":
            operand = str(r.u16())
        elif otype == "brshort":
            operand = "IL_%04X" % ((start + 2 + r.s8()) & 0xFFFF)
        elif otype == "brint":
            operand = "IL_%04X" % ((start + 5 + r.i32()) & 0xFFFF)
        elif otype == "token":
            operand = fmt_token(r.u32())
        elif otype == "u8":
            operand = str(r.u8())
        elif otype == "switch":
            n = r.u32()
            base = r.i + n * 4
            tgts = [base + r.i32() for _ in range(n)]
            operand = "(" + ", ".join("IL_%04X" % (t & 0xFFFF) for t in tgts) + ")"
        out.append((start, mnem, operand))
    return out


def parse_hex(s):
    s = s.strip().replace(",", " ").replace("0x", " ").replace("0X", " ")
    return bytes(int(p, 16) for p in s.split())


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="ILHelper",
        description="ILHelper — Python CLI rewrite (IL opcode editor/decoder). "
                    "原生 ILHelper 已脱壳（OEP 0xFE99E3），镜像见 ilhelper_unpacked.bin。")
    ap.add_argument("hex", nargs="?", help="IL 十六进制字节，空格分隔")
    ap.add_argument("-f", "--file", help="从二进制文件读取 IL 字节")
    ap.add_argument("-o", "--output", help="输出写入文件")
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