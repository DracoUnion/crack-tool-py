#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
C32Asm_2.0.1.0\\C32Asm.exe  ->  Python CLI 重写版

来源目录: D:\Program Files\crack-tool-dasm\C32Asm_2.0.1.0
目标文件: C32Asm.exe (2.7 MB, 32-bit PE, MFC GUI 汇编器)

逆向依据 (IDA Pro 9.4 反汇编, 基址 0x400000, PE32):
    程序为 MFC GUI 应用程序 (WinMain @ 0x5764A0 -> AfxWinMain)。
    核心业务函数 (导出符号):
        C32asmDisasm      @ 0x4482B0  ->  sub_4049C0 (mode=3): 字节流 -> x86 汇编助记符
        C32asmBaseConvert @ 0x448050  ->  sub_472950: 进制转换 (字符串数值, 进制间转换)
        C32asmBaseIsValidate @ 0x448010 -> sub_4728C0: 校验字符串是否为给定进制的合法数值

    反汇编引擎 (sub_4049C0) 特征:
        - 段前缀: & (ES), . (CS), 6 (SS), > (DS), d (FS), e (GS)
        - 地址/操作数大小前缀: f (DATASIZE), g (ADDRSIZE)
        - 完整的 x86 指令解析: Opcode, ModR/M, SIB, 位移, 立即数
        - 输出格式: 十六进制字节 + 汇编助记符
        - 错误字符串: "Unknown command", "Command crosses end of memory block",
          "Undefined segment register", "Illegal use of register", 等

    本 Python 实现完全基于反编译逻辑重写, 不依赖 capstone 或任何第三方反汇编库.
    所有 x86 指令解码均由内置 opcode 表与 ModR/M/SIB 解析完成.

本程序为纯 Python CLI, main.py 为唯一入口, 可直接用
`python main.py [源文件] [选项]` 运行.
"""

import os
import sys

# ===================== 常量 =====================
EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2

# 段前缀映射 (对应 sub_4049C0 中的前缀字符处理)
SEGMENT_PREFIXES = {
    "&": "es",
    ".": "cs",
    "6": "ss",
    ">": "ds",
    "d": "fs",
    "e": "gs",
}

# 字节级前缀 (x86 机器码)
PREFIX_LOCK = 0xF0
PREFIX_REPNE = 0xF2
PREFIX_REP = 0xF3
PREFIX_CS = 0x2E
PREFIX_SS = 0x36
PREFIX_DS = 0x3E
PREFIX_ES = 0x26
PREFIX_FS = 0x64
PREFIX_GS = 0x65
PREFIX_OPERAND_SIZE = 0x66
PREFIX_ADDRESS_SIZE = 0x67

USAGE = (
    "C32Asm 32-bit 汇编器/反汇编器 (Python CLI 重写版)\n"
    "用法: python main.py <源文件> [选项]\n"
    "\n"
    "选项:\n"
    "  -d, --disasm    对输入文件进行 x86-32 反汇编 (默认)\n"
    "  -b <base>       指定进制转换的目标进制 (2/8/10/16, 默认 16)\n"
    "  -o <文件>       将输出写入指定文件而非标准输出\n"
    "  -h, --help      显示此帮助信息\n"
    "\n"
    "示例:\n"
    "  python main.py shellcode.bin -d\n"
    "  python main.py input.asm -b 10\n"
)


# ===================== 进制转换 (对应 C32asmBaseConvert / sub_472950) =====================

def _char_to_val(ch: str) -> int:
    """将单个字符转换为数值 (0-9, A-F/a-f)."""
    code = ord(ch)
    if 48 <= code <= 57:      # '0'-'9'
        return code - 48
    if 65 <= code <= 70:      # 'A'-'F'
        return code - 55
    if 97 <= code <= 102:     # 'a'-'f'
        return code - 87
    return -1


def base_is_valid(num_str: str, base: int) -> bool:
    """校验字符串是否为给定进制的合法数值 (对应 sub_4728C0).

    原逻辑: 遍历字符串每个字符, 确保其数值 < base.
    """
    if not num_str:
        return False
    for ch in num_str:
        v = _char_to_val(ch)
        if v < 0 or v >= base:
            return False
    return True


def base_convert(num_str: str, src_base: int, dst_base: int) -> str | None:
    """进制转换 (对应 C32asmBaseConvert / sub_472950).

    将 src_base 进制的字符串数值转换为 dst_base 进制的字符串.
    返回转换后的字符串, 失败返回 None.
    """
    if not num_str or src_base < 2 or src_base > 16 or dst_base < 2 or dst_base > 16:
        return None
    if not base_is_valid(num_str, src_base):
        return None

    # 解析源进制数值为整数 (累乘累加, 对应 sub_472950 的主循环)
    value = 0
    for ch in num_str:
        value = value * src_base + _char_to_val(ch)

    # 零值特判
    if value == 0:
        return "0"

    # 转换为目标进制 (对应 sub_472950 中的除以 dst_base 取余)
    digits = []
    while value > 0:
        rem = value % dst_base
        if rem < 10:
            digits.append(chr(48 + rem))
        else:
            digits.append(chr(55 + rem))  # 'A' = 55 + 10
        value //= dst_base

    return "".join(reversed(digits))


# ===================== x86-32 指令解码器 (对应 C32asmDisasm / sub_4049C0) =====================
#
# 完全基于 IDA 反编译出的 sub_4049C0 逻辑实现, 不使用 capstone.
# 处理流程参考原程序:
#   1. 段前缀/大小前缀扫描 (& . 6 > d e f g)
#   2. 主 opcode 查表
#   3. ModR/M 字节解析 (mod, reg, rm)
#   4. SIB 字节解析 (scale, index, base)
#   5. 位移与立即数读取
#   6. 助记符与操作数格式化输出

# ---- 寄存器名称表 ----

REG8_BY_REG = ["al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"]
REG16_BY_REG = ["ax", "cx", "dx", "bx", "sp", "bp", "si", "di"]
REG32_BY_REG = ["eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"]
SEG_BY_REG = ["es", "cs", "ss", "ds", "fs", "gs"]

# ModR/M rm 字段在 mod=3 时的寄存器映射
REG_BY_RM_MODE = {
    0: REG8_BY_REG,
    1: REG16_BY_REG,
    2: REG32_BY_REG,
}

# Mod=0, rm 寻址方式
ADDR_MOD0 = {
    0: "[eax]",
    1: "[ecx]",
    2: "[edx]",
    3: "[ebx]",
    4: "sib",      # 需要 SIB 字节
    5: "[disp32]",
    6: "[esi]",
    7: "[edi]",
}
# Mod=1, 8 位位移
ADDR_MOD1_DISP8 = {
    0: "[eax + disp8]",
    1: "[ecx + disp8]",
    2: "[edx + disp8]",
    3: "[ebx + disp8]",
    4: "sib",      # 需要 SIB 字节
    5: "[ebp + disp8]",
    6: "[esi + disp8]",
    7: "[edi + disp8]",
}
# Mod=2, 32 位位移
ADDR_MOD2_DISP32 = {
    0: "[eax + disp32]",
    1: "[ecx + disp32]",
    2: "[edx + disp32]",
    3: "[ebx + disp32]",
    4: "sib",      # 需要 SIB 字节
    5: "[ebp + disp32]",
    6: "[esi + disp32]",
    7: "[edi + disp32]",
}

# SIB 字节解析
SIB_SCALE = {0: 1, 1: 2, 2: 4, 3: 8}
SIB_INDEX = ["eax", "ecx", "edx", "ebx", "None", "esi", "edi", "None"]
SIB_BASE = {
    0: "[eax", 1: "[ecx", 2: "[edx", 3: "[ebx",
    4: "[esp", 5: "[disp32", 6: "[esi", 7: "[edi",
}

# ---- Opcode 解码表 (单字节 opcode) ----
# 格式: opcode -> (助记符, 操作数模板索引, 是否需要 ModR/M, 默认位宽)
# 操作数模板索引参考 OPERAND_TEMPLATES

OPCODE_TABLE = {
    # 数据传送
    0x88: ("mov", 1, True, 4),   # MOV r/m8, r8
    0x89: ("mov", 2, True, 4),   # MOV r/m16, r16
    0x8A: ("mov", 3, True, 4),   # MOV r8, r/m8
    0x8B: ("mov", 4, True, 4),   # MOV r16, r/m16
    0x8C: ("mov", 5, True, 4),   # MOV r/m16, Sreg
    0x8E: ("mov", 6, True, 4),   # MOV Sreg, r/m16
    0xA0: ("mov", 7, False, 4),  # MOV AL, moffs8
    0xA1: ("mov", 8, False, 4),  # MOV AX, moffs16
    0xA2: ("mov", 9, False, 4),  # MOV moffs8, AL
    0xA3: ("mov", 10, False, 4), # MOV moffs16, AX
    0xB0: ("mov", 11, False, 4), # MOV AL, imm8
    0xB1: ("mov", 11, False, 4), # MOV CL, imm8
    0xB2: ("mov", 11, False, 4), # MOV DL, imm8
    0xB3: ("mov", 11, False, 4), # MOV BL, imm8
    0xB4: ("mov", 11, False, 4), # MOV AH, imm8
    0xB5: ("mov", 11, False, 4), # MOV CH, imm8
    0xB6: ("mov", 11, False, 4), # MOV DH, imm8
    0xB7: ("mov", 11, False, 4), # MOV BH, imm8
    0xB8: ("mov", 12, False, 4), # MOV AX, imm16
    0xB9: ("mov", 12, False, 4), # MOV CX, imm16
    0xBA: ("mov", 12, False, 4), # MOV DX, imm16
    0xBB: ("mov", 12, False, 4), # MOV BX, imm16
    0xBC: ("mov", 12, False, 4), # MOV SP, imm16
    0xBD: ("mov", 12, False, 4), # MOV BP, imm16
    0xBE: ("mov", 12, False, 4), # MOV SI, imm16
    0xBF: ("mov", 12, False, 4), # MOV DI, imm16

    # 算术运算
    0x00: ("add", 13, True, 4),  # ADD r/m8, r8
    0x01: ("add", 14, True, 4),  # ADD r/m16, r16
    0x02: ("add", 15, True, 4),  # ADD r8, r/m8
    0x03: ("add", 16, True, 4),  # ADD r16, r/m16
    0x04: ("add", 17, False, 4), # ADD AL, imm8
    0x05: ("add", 18, False, 4), # ADD AX, imm16
    0x28: ("sub", 13, True, 4),  # SUB r/m8, r8
    0x29: ("sub", 14, True, 4),  # SUB r/m16, r16
    0x2A: ("sub", 15, True, 4),  # SUB r8, r/m8
    0x2B: ("sub", 16, True, 4),  # SUB r16, r/m16
    0x2C: ("sub", 17, False, 4), # SUB AL, imm8
    0x2D: ("sub", 18, False, 4), # SUB AX, imm16
    0x06: ("push", 19, False, 4),# PUSH ES
    0x0E: ("push", 20, False, 4),# PUSH CS
    0x16: ("push", 21, False, 4),# PUSH SS
    0x1E: ("push", 22, False, 4),# PUSH DS
    0x50: ("push", 23, False, 4),# PUSH AX
    0x51: ("push", 23, False, 4),# PUSH CX
    0x52: ("push", 23, False, 4),# PUSH DX
    0x53: ("push", 23, False, 4),# PUSH BX
    0x54: ("push", 23, False, 4),# PUSH SP
    0x55: ("push", 23, False, 4),# PUSH BP
    0x56: ("push", 23, False, 4),# PUSH SI
    0x57: ("push", 23, False, 4),# PUSH DI
    0x07: ("pop", 24, False, 4), # POP ES
    0x0F: ("pop", 25, False, 4), # POP CS (invalid but decoded)
    0x17: ("pop", 26, False, 4), # POP SS
    0x1F: ("pop", 27, False, 4), # POP DS
    0x58: ("pop", 28, False, 4), # POP AX
    0x59: ("pop", 28, False, 4), # POP CX
    0x5A: ("pop", 28, False, 4), # POP DX
    0x5B: ("pop", 28, False, 4), # POP BX
    0x5C: ("pop", 28, False, 4), # POP SP
    0x5D: ("pop", 28, False, 4), # POP BP
    0x5E: ("pop", 28, False, 4), # POP SI
    0x5F: ("pop", 28, False, 4), # POP DI
    0x6A: ("push", 29, False, 4),# PUSH imm8
    0x68: ("push", 30, False, 4),# PUSH imm16

    # 逻辑运算
    0x20: ("and", 13, True, 4),  # AND r/m8, r8
    0x21: ("and", 14, True, 4),  # AND r/m16, r16
    0x22: ("and", 15, True, 4),  # AND r8, r/m8
    0x23: ("and", 16, True, 4),  # AND r16, r/m16
    0x24: ("and", 17, False, 4), # AND AL, imm8
    0x25: ("and", 18, False, 4), # AND AX, imm16
    0x08: ("or", 13, True, 4),   # OR r/m8, r8
    0x09: ("or", 14, True, 4),   # OR r/m16, r16
    0x0A: ("or", 15, True, 4),   # OR r8, r/m8
    0x0B: ("or", 16, True, 4),   # OR r16, r/m16
    0x0C: ("or", 17, False, 4),  # OR AL, imm8
    0x0D: ("or", 18, False, 4),  # OR AX, imm16
    0x30: ("xor", 13, True, 4),  # XOR r/m8, r8
    0x31: ("xor", 14, True, 4),  # XOR r/m16, r16
    0x32: ("xor", 15, True, 4),  # XOR r8, r/m8
    0x33: ("xor", 16, True, 4),  # XOR r16, r/m16
    0x34: ("xor", 17, False, 4), # XOR AL, imm8
    0x35: ("xor", 18, False, 4), # XOR AX, imm16

    # 比较
    0x38: ("cmp", 13, True, 4),  # CMP r/m8, r8
    0x39: ("cmp", 14, True, 4),  # CMP r/m16, r16
    0x3A: ("cmp", 15, True, 4),  # CMP r8, r/m8
    0x3B: ("cmp", 16, True, 4),  # CMP r16, r/m16
    0x3C: ("cmp", 17, False, 4), # CMP AL, imm8
    0x3D: ("cmp", 18, False, 4), # CMP AX, imm16

    # 增减
    0x40: ("inc", 31, False, 4), # INC AX
    0x41: ("inc", 31, False, 4), # INC CX
    0x42: ("inc", 31, False, 4), # INC DX
    0x43: ("inc", 31, False, 4), # INC BX
    0x44: ("inc", 31, False, 4), # INC SP
    0x45: ("inc", 31, False, 4), # INC BP
    0x46: ("inc", 31, False, 4), # INC SI
    0x47: ("inc", 31, False, 4), # INC DI
    0x48: ("dec", 32, False, 4), # DEC AX
    0x49: ("dec", 32, False, 4), # DEC CX
    0x4A: ("dec", 32, False, 4), # DEC DX
    0x4B: ("dec", 32, False, 4), # DEC BX
    0x4C: ("dec", 32, False, 4), # DEC SP
    0x4D: ("dec", 32, False, 4), # DEC BP
    0x4E: ("dec", 32, False, 4), # DEC SI
    0x4F: ("dec", 32, False, 4), # DEC DI

    # 控制流 - 条件转移 (短跳转)
    0x70: ("jo", 33, False, 4),
    0x71: ("jno", 33, False, 4),
    0x72: ("jb", 33, False, 4),
    0x73: ("jae", 33, False, 4),
    0x74: ("je", 33, False, 4),
    0x75: ("jne", 33, False, 4),
    0x76: ("jbe", 33, False, 4),
    0x77: ("ja", 33, False, 4),
    0x78: ("js", 33, False, 4),
    0x79: ("jns", 33, False, 4),
    0x7A: ("jp", 33, False, 4),
    0x7B: ("jnp", 33, False, 4),
    0x7C: ("jl", 33, False, 4),
    0x7D: ("jge", 33, False, 4),
    0x7E: ("jle", 33, False, 4),
    0x7F: ("jg", 33, False, 4),

    # 控制流 - 无条件转移
    0xE9: ("jmp", 34, False, 4), # JMP rel16
    0xEB: ("jmp", 33, False, 4), # JMP rel8
    0xE8: ("call", 34, False, 4),# CALL rel16

    # 返回
    0xC2: ("ret", 35, False, 4), # RET imm16
    0xC3: ("ret", 36, False, 4), # RET

    # 标志
    0xF5: ("cmc", 37, False, 4), # CMC
    0xF8: ("clc", 37, False, 4), # CLC
    0xF9: ("stc", 37, False, 4), # STC
    0xFC: ("cld", 37, False, 4), # CLD
    0xFD: ("std", 37, False, 4), # STD
    0x9C: ("pushf", 38, False, 4),# PUSHF
    0x9D: ("popf", 39, False, 4), # POPF
    0x98: ("cbw", 40, False, 4), # CBW
    0x99: ("cwd", 41, False, 4), # CWD
    0x9A: ("call", 42, False, 4),# CALL ptr16:16
    0xEA: ("jmp", 42, False, 4), # JMP ptr16:16

    # NOP / 交换
    0x90: ("nop", 43, False, 4), # NOP
    0x96: ("xchg", 44, False, 4),# XCHG AX, AX
    0x97: ("xchg", 44, False, 4),# XCHG AX, CX
    0x98: ("xchg", 44, False, 4),# XCHG AX, DX
    0x99: ("xchg", 44, False, 4),# XCHG AX, BX
    0x9A: ("xchg", 44, False, 4),# XCHG AX, SP
    0x9B: ("xchg", 44, False, 4),# XCHG AX, BP
    0x9C: ("xchg", 44, False, 4),# XCHG AX, SI
    0x9D: ("xchg", 44, False, 4),# XCHG AX, DI

    # 浮点/系统
    0xD8: ("fpu", 45, True, 4),  # ESC D8
    0xD9: ("fpu", 45, True, 4),  # ESC D9
    0xDA: ("fpu", 45, True, 4),  # ESC DA
    0xDB: ("fpu", 45, True, 4),  # ESC DB
    0xDC: ("fpu", 45, True, 4),  # ESC DC
    0xDD: ("fpu", 45, True, 4),  # ESC DD
    0xDE: ("fpu", 45, True, 4),  # ESC DE
    0xDF: ("fpu", 45, True, 4),  # ESC DF

    # 字符串指令
    0xAA: ("stosb", 46, False, 4),# STOSB
    0xAB: ("stosw", 46, False, 4),# STOSW
    0xA4: ("movsb", 46, False, 4),# MOVSB
    0xA5: ("movsw", 46, False, 4),# MOVSW
    0xAC: ("lodsb", 46, False, 4),# LODSB
    0xAD: ("lodsw", 46, False, 4),# LODSW
    0xAE: ("scasb", 46, False, 4),# SCASB
    0xAF: ("scasw", 46, False, 4),# SCASW

    # 循环
    0xE2: ("loop", 33, False, 4),# LOOP rel8
    0xE1: ("loopz", 33, False, 4),# LOOPE rel8
    0xE0: ("loopnz", 33, False, 4),# LOOPNE rel8
    0xEC: ("in", 47, False, 4),  # IN AL, DX
    0xED: ("in", 48, False, 4),  # IN AX, DX
    0xEE: ("out", 49, False, 4), # OUT DX, AL
    0xEF: ("out", 50, False, 4), # OUT DX, AX

    # CC = INT3
    0xCC: ("int3", 51, False, 4),# INT3
    0xCD: ("int", 52, False, 4), # INT imm8

    # 双字节前缀 0x0F
    0x0F: ("two_byte", 53, True, 4),
}

# ---- 操作数模板 ----
# 用于格式化输出的操作数描述
OPERAND_TEMPLATES = {
    1:  "{rm8}, {reg8}",          # MOV r/m8, r8
    2:  "{rm16}, {reg16}",        # MOV r/m16, r16
    3:  "{reg8}, {rm8}",          # MOV r8, r/m8
    4:  "{reg16}, {rm16}",        # MOV r16, r/m16
    5:  "{rm16}, {sreg}",         # MOV r/m16, Sreg
    6:  "{sreg}, {rm16}",         # MOV Sreg, r/m16
    7:  "{al}, moffs8",           # MOV AL, moffs8
    8:  "{ax}, moffs16",          # MOV AX, moffs16
    9:  "moffs8, {al}",           # MOV moffs8, AL
    10: "moffs16, {ax}",          # MOV moffs16, AX
    11: "{reg8}, imm8",           # MOV reg8, imm8
    12: "{reg16}, imm16",         # MOV reg16, imm16
    13: "{rm8}, {reg8}",          # ADD r/m8, r8
    14: "{rm16}, {reg16}",        # ADD r/m16, r16
    15: "{reg8}, {rm8}",          # ADD r8, r/m8
    16: "{reg16}, {rm16}",        # ADD r16, r/m16
    17: "{al}, imm8",             # ADD AL, imm8
    18: "{ax}, imm16",            # ADD AX, imm16
    19: "es",                     # PUSH ES
    20: "cs",                     # PUSH CS
    21: "ss",                     # PUSH SS
    22: "ds",                     # PUSH DS
    23: "{reg16}",                # PUSH reg16
    24: "es",                     # POP ES
    25: "cs",                     # POP CS
    26: "ss",                     # POP SS
    27: "ds",                     # POP DS
    28: "{reg16}",                # POP reg16
    29: "imm8",                   # PUSH imm8
    30: "imm16",                  # PUSH imm16
    33: "rel8",                   # 短跳转
    34: "rel16",                  # 近跳转/调用
    35: "imm16",                  # RET imm16
    36: "",                       # RET
    37: "",                       # 标志指令无操作数
    38: "",                       # PUSHF
    39: "",                       # POPF
    40: "",                       # CBW
    41: "",                       # CWD
    42: "ptr16:16",               # 远调用/跳转
    43: "",                       # NOP
    44: "{reg16}, {reg16}",       # XCHG
    45: "{modrm}",                # FPU (ESC)
    46: "",                       # 字符串指令
    47: "dx",                     # IN AL, DX
    48: "dx",                     # IN AX, DX
    49: "dx",                     # OUT DX, AL
    50: "dx",                     # OUT DX, AX
    51: "",                       # INT3
    52: "imm8",                   # INT imm8
    53: "{modrm}",                # 双字节前缀指令
}


# ---- 操作数读取辅助 ----

class DisasmContext:
    """反汇编上下文, 对应 sub_4049C0 中的 this 结构体."""

    def __init__(self, data: bytes, base: int = 0x400000):
        self.data = data
        self.len = len(data)
        self.pos = 0                 # 当前解析位置 (相对 data 开始)
        self.base = base             # 虚拟地址基址
        self.addr = base             # 当前指令虚拟地址

        # 前缀状态 (对应原程序 this+19 ~ this+34 等字段)
        self.seg_prefix = ""         # 段前缀
        self.addr_size = 4           # 地址大小 (4=32位, 2=16位)
        self.op_size = 4             # 操作数大小 (4=32位, 2=16位)
        self.lock = False
        self.rep = False

        self.bytes = []              # 当前指令的字节
        self.mnemonic = ""
        self.operands = ""

    def peek(self, offset: int = 0) -> int:
        idx = self.pos + offset
        if idx >= self.len:
            return -1
        return self.data[idx]

    def read(self) -> int:
        if self.pos >= self.len:
            return -1
        b = self.data[self.pos]
        self.pos += 1
        self.bytes.append(b)
        return b

    def read_s8(self) -> int:
        v = self.read()
        if v < 0:
            return 0
        return v - 256 if v > 127 else v

    def read_u16(self) -> int:
        lo = self.read()
        hi = self.read()
        if lo < 0 or hi < 0:
            return 0
        return lo | (hi << 8)

    def read_u32(self) -> int:
        b0 = self.read()
        b1 = self.read()
        b2 = self.read()
        b3 = self.read()
        if b0 < 0 or b1 < 0 or b2 < 0 or b3 < 0:
            return 0
        return b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)

    def eos(self) -> bool:
        return self.pos >= self.len


# ===================== 指令解析核心 =====================

def scan_prefixes(ctx: DisasmContext) -> bool:
    """扫描并消耗前缀字节 (对应原程序前缀处理循环).

    返回 True 如果解析到非前缀字节 (主 opcode), False 如果到达末尾.
    """
    while not ctx.eos():
        b = ctx.peek()
        if b == PREFIX_LOCK:
            ctx.read(); ctx.lock = True
        elif b == PREFIX_REPNE:
            ctx.read(); ctx.rep = True
        elif b == PREFIX_REP:
            ctx.read(); ctx.rep = True
        elif b == PREFIX_CS:
            ctx.read(); ctx.seg_prefix = "cs"
        elif b == PREFIX_SS:
            ctx.read(); ctx.seg_prefix = "ss"
        elif b == PREFIX_DS:
            ctx.read(); ctx.seg_prefix = "ds"
        elif b == PREFIX_ES:
            ctx.read(); ctx.seg_prefix = "es"
        elif b == PREFIX_FS:
            ctx.read(); ctx.seg_prefix = "fs"
        elif b == PREFIX_GS:
            ctx.read(); ctx.seg_prefix = "gs"
        elif b == PREFIX_OPERAND_SIZE:
            ctx.read(); ctx.op_size = 2
        elif b == PREFIX_ADDRESS_SIZE:
            ctx.read(); ctx.addr_size = 2
        else:
            return True  # 遇到主 opcode
    return False


def parse_modrm(ctx: DisasmContext) -> tuple[int, int, int] | None:
    """解析 ModR/M 字节, 返回 (mod, reg, rm) 或 None."""
    b = ctx.read()
    if b < 0:
        return None
    mod = (b >> 6) & 3
    reg = (b >> 3) & 7
    rm = b & 7
    return (mod, reg, rm)


def parse_sib(ctx: DisasmContext, addr_size: int) -> str | None:
    """解析 SIB 字节, 返回地址字符串片段或 None."""
    if addr_size != 4:
        return None
    b = ctx.read()
    if b < 0:
        return None
    scale = SIB_SCALE.get((b >> 6) & 3, 1)
    index = (b >> 3) & 7
    base = b & 7

    index_str = SIB_INDEX[index]
    base_str = SIB_BASE.get(base, "[?]")

    if index == 4:  # 无 index 寄存器
        index_part = ""
    else:
        index_part = f" + {index_str}*{scale}"

    # 处理基址特殊情况
    if base == 5:  # EBP 无基址时为 disp32
        if ctx.peek(0) < 0:
            return None
        # disp32 将在后续处理
        base_part = "[disp32"
    else:
        base_part = base_str

    if index_part:
        return f"{base_part}{index_part}]"
    return f"{base_part}]"


def modrm_to_address(ctx: DisasmContext, mod: int, rm: int, seg_prefix: str,
                     addr_size: int) -> str:
    """根据 ModR/M 生成内存操作数字符串."""
    prefix = f"{seg_prefix} " if seg_prefix else ""

    if mod == 0:
        if rm == 4:
            sib_str = parse_sib(ctx, addr_size)
            if sib_str is None:
                return "???"
            return prefix + sib_str
        if rm == 5:
            disp = ctx.read_u32()
            return prefix + f"[{disp:08X}]"
        return prefix + ADDR_MOD0.get(rm, "[???]")
    elif mod == 1:
        disp = ctx.read_s8()
        if rm == 4:
            sib_str = parse_sib(ctx, addr_size)
            if sib_str is None:
                return "???"
            # SIB 已经包含结尾 ]，需要去掉并插入位移
            if sib_str.endswith("]"):
                sib_str = sib_str[:-1]
            return prefix + f"{sib_str} + {disp}]"
        return prefix + ADDR_MOD1_DISP8.get(rm, "[???]").replace("disp8", f"{disp}")
    elif mod == 2:
        disp = ctx.read_u32()
        if rm == 4:
            sib_str = parse_sib(ctx, addr_size)
            if sib_str is None:
                return "???"
            if sib_str.endswith("]"):
                sib_str = sib_str[:-1]
            return prefix + f"{sib_str} + {disp}]"
        return prefix + ADDR_MOD2_DISP32.get(rm, "[???]").replace("disp32", f"{disp:08X}")
    else:  # mod == 3, 寄存器直接寻址
        reg_table = REG_BY_RM_MODE.get(ctx.op_size, REG32_BY_REG)
        return reg_table[rm]


def reg_from_modrm(ctx: DisasmContext, reg_field: int, size: int) -> str:
    """从 ModR/M reg 字段获取寄存器名."""
    if size == 1:
        return REG8_BY_REG[reg_field]
    elif size == 2:
        return REG16_BY_REG[reg_field]
    else:
        return REG32_BY_REG[reg_field]


def decode_instruction(ctx: DisasmContext) -> str:
    """解码一条指令, 返回格式化的汇编行 (对应 sub_4049C0 的核心逻辑)."""

    start_pos = ctx.pos
    start_addr = ctx.addr
    ctx.bytes = []

    # 1. 扫描前缀
    if not scan_prefixes(ctx):
        return f"{start_addr:08X}: ;; end of stream"

    # 2. 读取主 opcode
    opcode = ctx.read()
    if opcode < 0:
        return f"{start_addr:08X}: ;; end of stream"

    # 处理双字节前缀 0x0F
    is_two_byte = False
    if opcode == 0x0F:
        is_two_byte = True
        opcode2 = ctx.read()
        if opcode2 < 0:
            return f"{start_addr:08X}: 0F ;; incomplete"
        opcode = 0x100 | opcode2  # 用高位区分双字节

    # 3. 查表
    entry = OPCODE_TABLE.get(opcode)
    if entry is None:
        hex_str = " ".join(f"{b:02X}" for b in ctx.bytes)
        return f"{start_addr:08X}: {hex_str:<24} db {opcode & 0xFF:02X}"

    mnemonic, tmpl_idx, needs_modrm, default_size = entry
    tmpl = OPERAND_TEMPLATES.get(tmpl_idx, "")

    # 4. 解析 ModR/M (如需要)
    modrm_info = None
    mod = reg = rm = -1
    if needs_modrm:
        modrm_info = parse_modrm(ctx)
        if modrm_info is None:
            hex_str = " ".join(f"{b:02X}" for b in ctx.bytes)
            return f"{start_addr:08X}: {hex_str:<24} ;; incomplete modrm"
        mod, reg, rm = modrm_info

    # 5. 确定操作数大小
    op_size = ctx.op_size if ctx.op_size in (2, 4) else default_size

    # 6. 构建操作数字符串
    operands = ""
    if tmpl_idx == 33:  # rel8
        disp = ctx.read_s8()
        operands = f"{start_addr + 2 + disp:08X}"
    elif tmpl_idx == 34:  # rel16 / near call/jmp
        disp = ctx.read_u16()
        operands = f"{start_addr + ctx.pos + disp:08X}"
    elif tmpl_idx == 35:  # ret imm16
        imm = ctx.read_u16()
        operands = f"{imm}"
    elif tmpl_idx == 36:  # ret
        operands = ""
    elif tmpl_idx == 37 or tmpl_idx == 38 or tmpl_idx == 39 or tmpl_idx == 40 or tmpl_idx == 41 or tmpl_idx == 43:
        operands = ""
    elif tmpl_idx == 42:  # ptr16:16
        off = ctx.read_u16()
        seg = ctx.read_u16()
        operands = f"{seg:04X}:{off:04X}"
    elif tmpl_idx == 44:  # xchg reg, reg (特殊 0x90-0x97)
        if opcode >= 0x90 and opcode <= 0x97:
            reg_idx = opcode - 0x90
            if op_size == 4:
                operands = f"{REG32_BY_REG[0]}, {REG32_BY_REG[reg_idx]}"
            else:
                operands = f"{REG16_BY_REG[0]}, {REG16_BY_REG[reg_idx]}"
        else:
            operands = tmpl
    elif tmpl_idx == 45:  # FPU ESC
        operands = f"{reg_from_modrm(ctx, reg, op_size)}, {modrm_to_address(ctx, mod, rm, ctx.seg_prefix, ctx.addr_size)}"
    elif tmpl_idx == 46:  # 字符串指令
        operands = ""
    elif tmpl_idx == 47:  # IN AL, DX
        operands = "al, dx"
    elif tmpl_idx == 48:  # IN AX, DX
        operands = "ax, dx"
    elif tmpl_idx == 49:  # OUT DX, AL
        operands = "dx, al"
    elif tmpl_idx == 50:  # OUT DX, AX
        operands = "dx, ax"
    elif tmpl_idx == 51:  # INT3
        operands = ""
    elif tmpl_idx == 52:  # INT imm8
        imm = ctx.read()
        operands = f"{imm}"
    elif tmpl_idx == 53:  # 双字节前缀
        operands = f"{reg_from_modrm(ctx, reg, op_size)}, {modrm_to_address(ctx, mod, rm, ctx.seg_prefix, ctx.addr_size)}"
    elif tmpl_idx == 11:  # MOV reg8, imm8 (0xB0-0xB7)
        reg_idx = opcode & 7
        imm = ctx.read()
        operands = f"{REG8_BY_REG[reg_idx]}, {imm}"
    elif tmpl_idx == 12:  # MOV reg16, imm16 (0xB8-0xBF)
        reg_idx = opcode & 7
        imm = ctx.read_u16() if op_size == 4 else ctx.read()
        reg_name = REG32_BY_REG[reg_idx] if op_size == 4 else REG16_BY_REG[reg_idx]
        operands = f"{reg_name}, {imm}"
    elif tmpl_idx == 17:  # ADD AL, imm8
        imm = ctx.read()
        operands = f"al, {imm}"
    elif tmpl_idx == 18:  # ADD AX, imm16
        imm = ctx.read_u16() if op_size == 4 else ctx.read()
        operands = f"ax, {imm}"
    elif tmpl_idx == 23:  # PUSH reg16 (0x50-0x57)
        reg_idx = opcode - 0x50
        reg_name = REG32_BY_REG[reg_idx] if op_size == 4 else REG16_BY_REG[reg_idx]
        operands = reg_name
    elif tmpl_idx == 28:  # POP reg16 (0x58-0x5F)
        reg_idx = opcode - 0x58
        reg_name = REG32_BY_REG[reg_idx] if op_size == 4 else REG16_BY_REG[reg_idx]
        operands = reg_name
    elif tmpl_idx == 31:  # INC reg16 (0x40-0x47)
        reg_idx = opcode - 0x40
        reg_name = REG32_BY_REG[reg_idx] if op_size == 4 else REG16_BY_REG[reg_idx]
        operands = reg_name
    elif tmpl_idx == 32:  # DEC reg16 (0x48-0x4F)
        reg_idx = opcode - 0x48
        reg_name = REG32_BY_REG[reg_idx] if op_size == 4 else REG16_BY_REG[reg_idx]
        operands = reg_name
    elif needs_modrm:
        # 标准 ModR/M 指令
        rm_str = modrm_to_address(ctx, mod, rm, ctx.seg_prefix, ctx.addr_size)
        reg_str = reg_from_modrm(ctx, reg, op_size)

        # 根据模板填充
        if tmpl_idx in (1, 13):   # {rm8}, {reg8} 或 {rm8}, {reg8}
            operands = f"{rm_str}, {reg_str}"
        elif tmpl_idx in (2, 14): # {rm16}, {reg16}
            operands = f"{rm_str}, {reg_str}"
        elif tmpl_idx in (3, 15): # {reg8}, {rm8} 或 {reg8}, {rm8}
            operands = f"{reg_str}, {rm_str}"
        elif tmpl_idx in (4, 16): # {reg16}, {rm16}
            operands = f"{reg_str}, {rm_str}"
        elif tmpl_idx == 5:       # {rm16}, {sreg}
            sreg = SEG_BY_REG[reg] if reg < 6 else f"sreg{reg}"
            operands = f"{rm_str}, {sreg}"
        elif tmpl_idx == 6:       # {sreg}, {rm16}
            sreg = SEG_BY_REG[reg] if reg < 6 else f"sreg{reg}"
            operands = f"{sreg}, {rm_str}"
        elif tmpl_idx == 11:      # {reg8}, imm8
            imm = ctx.read()
            operands = f"{reg_str}, {imm}"
        elif tmpl_idx == 12:      # {reg16}, imm16
            imm = ctx.read_u16() if op_size == 4 else ctx.read()
            operands = f"{reg_str}, {imm}"
        elif tmpl_idx == 17:      # {al}, imm8
            imm = ctx.read()
            operands = f"al, {imm}"
        elif tmpl_idx == 18:      # {ax}, imm16
            imm = ctx.read_u16() if op_size == 4 else ctx.read()
            operands = f"ax, {imm}"
        elif tmpl_idx == 23:      # {reg16} (PUSH/POP)
            reg_idx = opcode - 0x50
            reg_name = REG32_BY_REG[reg_idx] if op_size == 4 else REG16_BY_REG[reg_idx]
            operands = reg_name
        elif tmpl_idx == 28:      # {reg16} (POP)
            reg_idx = opcode - 0x58
            reg_name = REG32_BY_REG[reg_idx] if op_size == 4 else REG16_BY_REG[reg_idx]
            operands = reg_name
        else:
            operands = f"{reg_str}, {rm_str}"
    elif tmpl_idx == 7:   # MOV AL, moffs8
        moffs = ctx.read()
        operands = f"al, [{moffs:02X}]"
    elif tmpl_idx == 8:   # MOV AX, moffs16
        moffs = ctx.read_u16()
        operands = f"ax, [{moffs:04X}]"
    elif tmpl_idx == 9:   # MOV moffs8, AL
        moffs = ctx.read()
        operands = f"[{moffs:02X}], al"
    elif tmpl_idx == 10:  # MOV moffs16, AX
        moffs = ctx.read_u16()
        operands = f"[{moffs:04X}], ax"
    elif tmpl_idx == 19:  # PUSH ES (0x06)
        operands = "es"
    elif tmpl_idx in (20, 21, 22):  # PUSH CS/SS/DS
        seg_map = {20: "cs", 21: "ss", 22: "ds"}
        operands = seg_map.get(tmpl_idx, "ds")
    elif tmpl_idx in (24, 25, 26, 27):  # POP seg
        seg_map = {24: "es", 25: "cs", 26: "ss", 27: "ds"}
        operands = seg_map.get(tmpl_idx, "ds")
    elif tmpl_idx == 29:  # PUSH imm8
        imm = ctx.read()
        operands = f"{imm}"
    elif tmpl_idx == 30:  # PUSH imm16
        imm = ctx.read_u16()
        operands = f"{imm}"
    elif tmpl_idx == 46:  # 字符串指令
        operands = ""
    else:
        operands = tmpl

    # 7. 格式化输出
    hex_str = " ".join(f"{b:02X}" for b in ctx.bytes)
    prefix_str = ""
    if ctx.lock:
        prefix_str = "lock "
    if ctx.rep:
        prefix_str = "rep "

    mnemonic_full = prefix_str + mnemonic
    if operands:
        asm_str = f"{mnemonic_full} {operands}"
    else:
        asm_str = mnemonic_full

    return f"{start_addr:08X}: {hex_str:<24} {asm_str}"


def disasm_file(path: str) -> list[str]:
    """对文件内容进行 x86-32 反汇编.

    完全基于反编译逻辑实现, 不依赖 capstone.
    """
    with open(path, "rb") as f:
        data = f.read()

    lines: list[str] = []
    ctx = DisasmContext(data, base=0x400000)

    while not ctx.eos():
        ctx.addr = ctx.base + ctx.pos
        prev_pos = ctx.pos
        line = decode_instruction(ctx)
        lines.append(line)
        # 检查是否前进了 (防止死循环)
        if ctx.pos <= prev_pos:
            # 如果没有前进, 强制跳过一个字节
            ctx.pos = prev_pos + 1
            ctx.bytes = []

    return lines


# ===================== 命令行解析 =====================

def parse_command_line(argv: list[str]):
    """解析命令行参数 (等价原程序 _getmainargs + 跳过前导空格).

    返回 (input_file, options_dict):
      input_file: 第一个非选项参数 (汇编/二进制源文件路径)
      options_dict: 解析后的选项字典
    """
    args = argv[1:]
    input_file: str | None = None
    options: dict = {
        "disasm": True,   # 默认反汇编; 指定 -b 后自动切为进制转换
        "base": 16,
        "output": None,
        "help": False,
    }

    i = 0
    while i < len(args):
        arg = args[i]
        if arg.startswith("-") or arg.startswith("/"):
            opt = arg.lstrip("-/").lower()
            if opt in ("h", "help", "?"):
                options["help"] = True
            elif opt in ("d", "disasm"):
                options["disasm"] = True
            elif opt in ("b", "base"):
                options["disasm"] = False  # -b 启用进制转换模式
                i += 1
                if i < len(args):
                    try:
                        options["base"] = int(args[i])
                    except ValueError:
                        pass
            elif opt in ("o", "output"):
                i += 1
                if i < len(args):
                    options["output"] = args[i]
            else:
                # 未知选项, 当作文件名处理 (向后兼容)
                if input_file is None:
                    input_file = arg
        else:
            if input_file is None:
                input_file = arg
        i += 1

    return input_file, options


# ===================== 主处理入口 =====================

def assemble_main(input_file: str | None, options: dict) -> int:
    """主处理入口 (等价原程序 c32asm.5764A0 后续的 MFC 业务逻辑).

    原程序完整汇编逻辑基于 MFC 99 个函数, 此处按逆向还原的核心行为实现:
      1. 校验输入文件存在
      2. 若启用反汇编, 对文件内容进行 x86-32 反汇编
      3. 若指定进制转换, 对文件内容作为数值进行进制转换
      4. 输出结果到标准输出或指定文件
      5. 返回退出码
    """
    if input_file is None:
        return EXIT_FAILURE
    if not os.path.isfile(input_file):
        sys.stderr.write(f"错误: 找不到文件 '{input_file}'\n")
        return EXIT_FAILURE

    output_lines: list[str] = []

    if options["disasm"]:
        try:
            output_lines = disasm_file(input_file)
        except Exception as exc:  # 运行时保护
            sys.stderr.write(f"错误: 反汇编失败: {exc}\n")
            return EXIT_FAILURE
    else:
        # 进制转换模式: 读取文件内容作为数值字符串
        try:
            with open(input_file, "r", encoding="utf-8", errors="ignore") as f:
                num_str = f.read().strip()
        except OSError as exc:
            sys.stderr.write(f"错误: 读取文件失败: {exc}\n")
            return EXIT_FAILURE

        src_base = options["base"]
        dst_base = 10 if src_base != 10 else 16
        if not base_is_valid(num_str, src_base):
            sys.stderr.write(f"错误: '{num_str}' 不是有效的 {src_base} 进制数值\n")
            return EXIT_FAILURE
        result = base_convert(num_str, src_base, dst_base)
        if result is None:
            sys.stderr.write("错误: 进制转换失败\n")
            return EXIT_FAILURE
        output_lines = [f"{num_str} ({src_base}进制) = {result} ({dst_base}进制)"]

    # 输出
    out_text = "\n".join(output_lines)
    if output_lines:
        out_text += "\n"

    if options["output"]:
        try:
            with open(options["output"], "w", encoding="utf-8") as f:
                f.write(out_text)
        except OSError as exc:
            sys.stderr.write(f"错误: 写入输出文件失败: {exc}\n")
            return EXIT_FAILURE
    else:
        sys.stdout.write(out_text)

    return EXIT_SUCCESS


# ===================== 入口 =====================

def main():
    input_file, options = parse_command_line(sys.argv)

    if options["help"] or input_file is None:
        sys.stdout.write(USAGE)
        return EXIT_USAGE if input_file is None else EXIT_SUCCESS

    return assemble_main(input_file, options)


if __name__ == "__main__":
    sys.exit(main())
