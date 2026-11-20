#!/usr/bin/env python3
"""
32bitCalculator v1.7 — Python CLI rewrite

原程序：32bitCalculator_1.7/32bitCalculator_1.7.exe (Win32 汇编, by cybult)
重写为纯 Python 命令行工具，无第三方依赖。

所有数值视为 32 位无符号整数，运算结果截断到 32 位 (0xFFFFFFFF)，
与原汇编程序的 32 位寄存器行为一致。
"""

import argparse
import binascii
import sys
import zlib

MASK32 = 0xFFFFFFFF


def u32(v):
    """将值截断为 32 位无符号整数。"""
    return v & MASK32


def parse_int(s):
    """解析整数字符串，支持 0x 十六进制前缀与十进制。"""
    s = s.strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s, 10)


def fmt_hex(v, digits=8):
    return "%0*lX" % (digits, u32(v))


# ---------------------------------------------------------------------------
# CRC-32 文件校验（对应原程序 "CRC-32 File Calculator"）
# ---------------------------------------------------------------------------
def cmd_crc32(args):
    crc = 0
    try:
        with open(args.file, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                crc = zlib.crc32(chunk, crc)
    except OSError as e:
        print("Error: %s" % e, file=sys.stderr)
        return 1
    print(fmt_hex(crc))
    return 0


# ---------------------------------------------------------------------------
# 字符串 <-> 十六进制（对应 String2Hex / Hex2String）
# ---------------------------------------------------------------------------
def cmd_str2hex(args):
    text = args.text
    if args.unescape:
        # 支持常见转义：\n \t \r \\ \xHH
        import codecs
        try:
            text = codecs.decode(text, "unicode_escape")
        except Exception:
            pass
    out = text.encode("utf-8").hex().upper()
    print(out)
    return 0


def cmd_hex2str(args):
    h = args.hex.replace(" ", "").replace("0x", "").replace("0X", "")
    try:
        data = bytes.fromhex(h)
    except ValueError as e:
        print("Error: invalid hex: %s" % e, file=sys.stderr)
        return 1
    try:
        print(data.decode("utf-8"))
    except UnicodeDecodeError:
        # 不是有效 UTF-8，则按 latin-1 输出原始字节
        print(data.decode("latin-1"))
    return 0


# ---------------------------------------------------------------------------
# 二进制 <-> 十六进制（对应 Hex2Bin / Bin2Hex）
# ---------------------------------------------------------------------------
def cmd_hex2bin(args):
    h = args.hex.replace(" ", "").replace("0x", "").replace("0X", "")
    try:
        data = bytes.fromhex(h)
    except ValueError as e:
        print("Error: invalid hex: %s" % e, file=sys.stderr)
        return 1
    bin_str = "".join(format(b, "08b") for b in data)
    # 按每 4 位一组显示，更易阅读
    grouped = " ".join(bin_str[i:i + 4] for i in range(0, len(bin_str), 4))
    print(grouped)
    return 0


def cmd_bin2hex(args):
    bin_str = args.bin.replace(" ", "").replace("_", "")
    if any(c not in "01" for c in bin_str):
        print("Error: input is not a binary string", file=sys.stderr)
        return 1
    # 补齐到 8 的倍数
    pad = (-len(bin_str)) % 8
    bin_str = "0" * pad + bin_str
    n = int(bin_str, 2)
    width = (len(bin_str) + 3) // 4
    print(fmt_hex(n, width))
    return 0


# ---------------------------------------------------------------------------
# 十进制 <-> 十六进制（32 位）
# ---------------------------------------------------------------------------
def cmd_dec2hex(args):
    n = parse_int(args.num)
    print(fmt_hex(n))
    return 0


def cmd_hex2dec(args):
    n = parse_int(args.num)
    print(u32(n))
    return 0


# ---------------------------------------------------------------------------
# 相对跳转偏移计算（对应原程序 "JMP Calc / Jump-Call Calculator"）
# ---------------------------------------------------------------------------
# 条件跳转 opcode 映射 (x86, 0F8x 两字节形式)
COND_OPCODES = {
    "jo": 0x80, "jno": 0x81,
    "jb": 0x82, "jc": 0x82, "jnae": 0x82,
    "jnb": 0x83, "jnc": 0x83, "jae": 0x83, "jnbe": 0x83,
    "jz": 0x84, "je": 0x84,
    "jnz": 0x85, "jne": 0x85,
    "jbe": 0x86, "jna": 0x86,
    "ja": 0x87, "jnbe": 0x87,
    "js": 0x88,
    "jns": 0x89,
    "jp": 0x8A, "jpe": 0x8A,
    "jnp": 0x8B, "jpo": 0x8B,
    "jl": 0x8C, "jnge": 0x8C,
    "jge": 0x8D, "jnl": 0x8D,
    "jle": 0x8E, "jng": 0x8E,
    "jg": 0x8F, "jnle": 0x8F,
}


def cmd_jmpcalc(args):
    frm = parse_int(args.fr)
    to = parse_int(args.to)
    # 相对偏移 = 目标 - (下一条指令地址)。这里按 "目标 - 当前" 的简易语义给出
    # 原程序给出的是从当前地址到目标地址的位移（有符号 32 位）。
    rel = u32(to - frm)  # 无符号 32 位展示
    rel_signed = (to - frm) & MASK32
    # 解释为有符号 32 位
    if rel_signed >= 0x80000000:
        rel_signed -= 0x100000000

    print("from : %s" % fmt_hex(frm))
    print("to   : %s" % fmt_hex(to))
    print("offset (hex): %s" % fmt_hex(rel))
    print("offset (dec): %d" % (to - frm))
    print("offset (signed 32-bit): %d" % rel_signed)
    print()
    print("条件跳转 opcode (E8/E9 为直接跳转，0F8x 为条件跳转):")
    print("  E8 rel32   -> call  near rel32")
    print("  E9 rel32   -> jmp   near rel32")
    for name, op in sorted(COND_OPCODES.items(), key=lambda x: x[1]):
        print("  0F%02X rel32 -> %s" % (op, name))
    return 0


# ---------------------------------------------------------------------------
# 32 位位运算（对应 and/or/xor/not/neg/rol/ror/shl/shr/imul/idiv/bswap）
# ---------------------------------------------------------------------------
def rol(v, n):
    n &= 31
    return u32((v << n) | (v >> (32 - n)))


def ror(v, n):
    n &= 31
    return u32((v >> n) | (v << (32 - n)) & MASK32)


def cmd_op(args):
    a = parse_int(args.a)
    op = args.op.lower()
    b = parse_int(args.b) if args.b is not None else None

    if op == "not":
        res = u32(~a)
        print("not  %s = %s" % (fmt_hex(a), fmt_hex(res)))
    elif op == "neg":
        res = u32(-a)
        print("neg  %s = %s  (dec: %d)" % (fmt_hex(a), fmt_hex(res), u32(-a)))
    elif op == "bswap":
        v = u32(a)
        res = u32(((v >> 24) & 0xFF) |
                  ((v >> 8) & 0xFF) << 8 |
                  ((v << 8) & 0xFFFF) >> 8 |
                  ((v << 24) & MASK32))
        # 更清晰的字节交换
        res = int.from_bytes(u32(a).to_bytes(4, "little"), "big") & MASK32
        print("bswap %s = %s" % (fmt_hex(a), fmt_hex(res)))
    elif op in ("rol", "ror"):
        if b is None:
            print("Error: %s 需要位移数 b", op, file=sys.stderr)
            return 1
        if op == "rol":
            res = rol(a, b)
        else:
            res = ror(a, b)
        print("%s  %s by %d = %s" % (op.upper(), fmt_hex(a), b, fmt_hex(res)))
    elif op == "shl":
        if b is None:
            print("Error: shl 需要位移数 b", file=sys.stderr)
            return 1
        res = u32(a << b)
        print("shl  %s << %d = %s  (carry: %d)" % (
            fmt_hex(a), b, fmt_hex(res), (a >> (32 - b)) & 1 if b else 0))
    elif op == "shr":
        if b is None:
            print("Error: shr 需要位移数 b", file=sys.stderr)
            return 1
        res = u32(a >> b)
        print("shr  %s >> %d = %s  (carry: %d)" % (
            fmt_hex(a), b, fmt_hex(res), (a >> (b - 1)) & 1 if b else 0))
    else:
        # and / or / xor / imul / idiv 需要两个操作数
        if b is None:
            print("Error: %s 需要两个操作数 a b", op, file=sys.stderr)
            return 1
        if op == "and":
            res = u32(a & b)
            print("and  %s & %s = %s" % (fmt_hex(a), fmt_hex(b), fmt_hex(res)))
        elif op == "or":
            res = u32(a | b)
            print("or   %s | %s = %s" % (fmt_hex(a), fmt_hex(b), fmt_hex(res)))
        elif op == "xor":
            res = u32(a ^ b)
            print("xor  %s ^ %s = %s" % (fmt_hex(a), fmt_hex(b), fmt_hex(res)))
        elif op == "imul":
            # 有符号 32 位乘法，取低 32 位
            sa = a if a < 0x80000000 else a - 0x100000000
            sb = b if b < 0x80000000 else b - 0x100000000
            res = u32(sa * sb)
            print("imul %s * %s = %s" % (fmt_hex(a), fmt_hex(b), fmt_hex(res)))
        elif op == "idiv":
            if b == 0:
                print("Error: Can't divide! (divisor is zero)", file=sys.stderr)
                return 1
            sa = a if a < 0x80000000 else a - 0x100000000
            sb = b if b < 0x80000000 else b - 0x100000000
            quot = int(sa / sb)  # 向零截断
            rem = sa - sb * quot
            print("idiv %s / %s = %d  (rem %d)" % (fmt_hex(a), fmt_hex(b), quot, rem))
    return 0


# ---------------------------------------------------------------------------
# 参数解析与主入口
# ---------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(
        prog="main.py",
        description="32bitCalculator v1.7 — Python CLI (纯 Python 重写，无第三方依赖)。",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("crc32", help="计算文件的 CRC-32 校验值")
    sp.add_argument("file", help="要计算 CRC-32 的文件路径")
    sp.set_defaults(func=cmd_crc32)

    sp = sub.add_parser("str2hex", help="字符串转十六进制")
    sp.add_argument("text", help="要转换的文本")
    sp.add_argument("-u", "--unescape", action="store_true",
                    help="先对文本进行转义序列解码 (\\n \\t \\xHH 等)")
    sp.set_defaults(func=cmd_str2hex)

    sp = sub.add_parser("hex2str", help="十六进制转字符串")
    sp.add_argument("hex", help="十六进制字符串")
    sp.set_defaults(func=cmd_hex2str)

    sp = sub.add_parser("hex2bin", help="十六进制转二进制")
    sp.add_argument("hex", help="十六进制字符串")
    sp.set_defaults(func=cmd_hex2bin)

    sp = sub.add_parser("bin2hex", help="二进制转十六进制")
    sp.add_argument("bin", help="二进制字符串 (如 01001000)")
    sp.set_defaults(func=cmd_bin2hex)

    sp = sub.add_parser("dec2hex", help="十进制转十六进制 (32 位无符号)")
    sp.add_argument("num", help="十进制整数")
    sp.set_defaults(func=cmd_dec2hex)

    sp = sub.add_parser("hex2dec", help="十六进制转十进制 (32 位无符号)")
    sp.add_argument("num", help="十六进制整数 (如 0x3039 或 3039)")
    sp.set_defaults(func=cmd_hex2dec)

    sp = sub.add_parser("jmpcalc", help="计算相对跳转偏移并列出条件跳转 opcode")
    sp.add_argument("fr", help="起始地址 (如 0x401000)")
    sp.add_argument("to", help="目标地址 (如 0x402000)")
    sp.set_defaults(func=cmd_jmpcalc)

    sp = sub.add_parser("op", help="32 位位运算")
    sp.add_argument("op", choices=["and", "or", "xor", "not", "neg", "rol", "ror",
                                    "shl", "shr", "imul", "idiv", "bswap"],
                    help="运算操作")
    sp.add_argument("a", help="操作数 a")
    sp.add_argument("b", nargs="?", default=None, help="操作数 b (部分操作需要)")
    sp.set_defaults(func=cmd_op)

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
