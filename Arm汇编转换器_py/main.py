#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Arm汇编转换器  ->  PySide6 重写版
================================================================================
逆向依据 (目录主程序 "Arm汇编转换器.exe", PE32 GUI, 1.65 MB):
  从 .exe 的 ASCII 字符串可确认其本质是 GNU 工具链前端:
    "arm-linux-androideabi-as -ahlm -k -mthumb-interwork -march=armv7-a"
    "cmd.exe /c", "arm-linux-androideabi-as.exe",
    "GNU assembler version %s (%s) using BFD version %s",
    "ARM GAS", "Thumb encoding does not support rotation",
    "offset must be zero in ARM encoding", "{unknown opcode %d}" ...
  即: 把用户输入的 ARM/Thumb 汇编交给 arm-linux-androideabi-as 汇编,
  再把生成的 .o 中 .text 段字节提取为机器码十六进制显示 (ARM 汇编 -> 机器码).
  作者信息 (说明.txt): 加盐白咖啡 / 逆向未来技术论坛.

本重写 (main.py 为唯一入口, 纯标准库 + PySide6):
  由于目标机器不一定装有 arm-linux-androideabi-as, 这里内置一个纯 Python
  的 ARM(A32)/Thumb(T32) 汇编器核心 (覆盖常用指令), 同时保留"调用外部
  arm-linux-androideabi-as"的后备通道 (--external)。功能与原件对齐:
    ARM 汇编  ->  机器码 hex (小端)
    机器码 hex  ->  反汇编 (ARM/Thumb)
  支持架构: ARMv7-A (A32 / Thumb-2 常用子集).

用法:
  python main.py                # 启动 GUI
  python main.py --selftest     # 内置用例自检
  python main.py -m arm  "mov r0, #1"      # 汇编并打印 hex (CLI)
  python main.py -m thumb "bx lr"
  python main.py -d arm  "e3a00001"        # 反汇编 hex
"""

import sys
import os
import re
import struct
import subprocess

# ============================================================ ARM 寄存器 / 条件
ARM_REGS = {
    "r0": 0, "r1": 1, "r2": 2, "r3": 3, "r4": 4, "r5": 5, "r6": 6, "r7": 7,
    "r8": 8, "r9": 9, "r10": 10, "r11": 11, "r12": 12,
    "sp": 13, "lr": 14, "pc": 15,
    "a1": 0, "a2": 1, "a3": 2, "a4": 3,
    "v1": 4, "v2": 5, "v3": 6, "v4": 7, "v5": 8, "v6": 9, "v7": 10,
    "fp": 11, "ip": 12, "sl": 10, "sb": 9,
}

CONDS = {
    "": 0xE, "eq": 0x0, "ne": 0x1, "cs": 0x2, "hs": 0x2, "cc": 0x3, "lo": 0x3,
    "mi": 0x4, "pl": 0x5, "vs": 0x6, "vc": 0x7, "hi": 0x8, "ls": 0x9,
    "ge": 0xA, "lt": 0xB, "gt": 0xC, "le": 0xD, "al": 0xE,
}

# 数据操作指令 opcode (在 bit 24..21)
DP_OPS = {
    "and": 0, "eor": 1, "sub": 2, "rsb": 3, "add": 4, "adc": 5, "sbc": 6,
    "rsc": 7, "tst": 8, "teq": 9, "cmp": 10, "cmn": 11, "orr": 12, "mov": 13,
    "bic": 14, "mvn": 15,
}
# 这些指令不写回目的寄存器 (测试类)
DP_NO_S = {"tst", "teq", "cmp", "cmn"}
# 这些指令目的寄存器位置是 S 位后的 (mov/mvn 用 Rd, 其余用 Rn 作第一操作数)
DP_IMM = {"mov", "mvn"}

# 允许带条件后缀的基础助记符集合
_KNOWN_BASE = set(DP_OPS) | {
    "mul", "ldr", "str", "ldrb", "strb", "ldrh", "strh", "ldrsb", "ldrsh",
    "b", "bl", "bx", "blx", "push", "pop", "svc", "swi",
}


class AsmError(Exception):
    pass


def reg_num(name):
    name = name.strip().lower()
    if name in ARM_REGS:
        return ARM_REGS[name]
    raise AsmError("未知寄存器: %s" % name)


def split_operands(s):
    """按逗号切分, 但忽略 {..} 与 [...] 内的逗号已在外层处理。"""
    out, depth, cur = [], 0, ""
    for ch in s:
        if ch in "{[":
            depth += 1
        elif ch in "}]":
            depth -= 1
        if ch == "," and depth == 0:
            out.append(cur.strip()); cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def parse_imm(tok):
    """解析立即数: #1, #0x10, 0x10, 1, 'A' 等 -> (value) ; 支持 = 伪指令。"""
    tok = tok.strip()
    if tok.startswith("#"):
        tok = tok[1:].strip()
    if tok.startswith("="):
        tok = tok[1:].strip()
    neg = False
    if tok.startswith("-"):
        neg = True; tok = tok[1:]
    if len(tok) >= 3 and tok[0] == "'" and tok[-1] == "'":
        v = ord(tok[1])
        return (-v if neg else v)
    try:
        if tok.lower().startswith("0x"):
            v = int(tok, 16)
        else:
            v = int(tok, 0)
    except ValueError:
        raise AsmError("无法解析立即数: %s" % tok)
    return -v if neg else v


def is_imm(tok):
    return tok.strip().startswith(("#", "=")) or re.match(r"^-?(0x[0-9a-fA-F]+|\d+)$", tok.strip()) is not None


def encode_rot_imm(value):
    """把 value 编码为 8-bit 循环右移偶数位形式, 返回 (imm8, rot) 或 None。"""
    value &= 0xFFFFFFFF
    for rot in range(0, 32, 2):
        ror = ((value >> rot) | (value << (32 - rot))) & 0xFFFFFFFF if rot else value
        if ror <= 0xFF:
            return ror, (rot // 2)
    # 尝试: imm8 经 ROR
    for r in range(0, 32, 2):
        base = ((value << r) | (value >> (32 - r))) & 0xFFFFFFFF if r else value
        if base <= 0xFF:
            return base, r // 2
    return None


# ============================================================ A32 (ARM) 汇编器
class ARMAssembler:
    def __init__(self):
        self.base = 0

    def assemble(self, text, base=0):
        self.base = base
        out = bytearray()
        for raw in text.splitlines():
            line = self._strip_comment(raw).strip()
            if not line:
                continue
            if line.endswith(":"):
                continue  # 标签 (本子集忽略, 分支目标用绝对/数值)
            # 去掉标签前缀 "loop:" 形式
            line = re.sub(r"^[A-Za-z_.$][\w.$]*:\s*", "", line)
            if line.lower().startswith(".arm") or line.lower().startswith(".thumb") \
               or line.lower().startswith(".text") or line.lower().startswith(".code"):
                continue
            if line.lower() in ("nop",):
                out += struct.pack("<I", 0xE1A00000)
                continue
            word = self.encode_one(line)
            out += struct.pack("<I", word & 0xFFFFFFFF)
        return bytes(out)

    @staticmethod
    def _strip_comment(line):
        # 去掉 @ 注释与 // 注释
        idx = line.find("@")
        if idx >= 0:
            line = line[:idx]
        idx = line.find("//")
        if idx >= 0:
            line = line[:idx]
        return line

    def encode_one(self, line):
        parts = line.split(None, 1)
        mnem = parts[0].lower()
        rest = parts[1] if len(parts) > 1 else ""
        # 拆条件后缀 (mnem 形如 movne / b / blx)
        cond = 0xE
        base_mnem = mnem
        for cname in ("eq", "ne", "cs", "hs", "cc", "lo", "mi", "pl", "vs",
                      "vc", "hi", "ls", "ge", "lt", "gt", "le", "al"):
            if mnem.endswith(cname) and mnem[:-len(cname)] in _KNOWN_BASE:
                cond = CONDS[cname]
                base_mnem = mnem[:-len(cname)]
                break
        # 处理 s 后缀 (adds/subs...)
        sbit = 0
        mm = re.match(r"^(add|sub|rsb|and|eor|orr|bic|adc|sbc|rsc|mov|mvn|cmp|cmn|tst|teq)s$", base_mnem)
        if mm:
            base_mnem = mm.group(1); sbit = 1
        ops = split_operands(rest)

        if base_mnem in DP_OPS:
            return self._dp(base_mnem, cond, sbit, ops)
        if base_mnem in ("mul",):
            return self._mul(cond, sbit, ops)
        if base_mnem in ("ldr", "str", "ldrb", "strb", "ldrh", "strh", "ldrsb", "ldrsh"):
            return self._loadstore(base_mnem, cond, ops)
        if base_mnem in ("b",):
            return self._b(cond, ops, link=False)
        if base_mnem in ("bl",):
            return self._b(cond, ops, link=True)
        if base_mnem in ("bx", "blx"):
            return self._bx(cond, ops, link=(base_mnem == "blx"))
        if base_mnem in ("push",):
            return self._pushpop(cond, ops, push=True)
        if base_mnem in ("pop",):
            return self._pushpop(cond, ops, push=False)
        if base_mnem in ("svc", "swi"):
            return (cond << 28) | 0x0F000000 | (parse_imm(ops[0]) & 0xFFFFFF)
        raise AsmError("不支持的指令: %s" % line)

    def _dp(self, name, cond, sbit, ops):
        opcode = DP_OPS[name]
        rn = 0
        if name in DP_NO_S:
            # cmp r0, #1
            rn = reg_num(ops[0])
            operand = ops[1]
            rd = 0
        elif name in DP_IMM:
            rd = reg_num(ops[0])
            operand = ops[1]
        else:
            rd = reg_num(ops[0])
            if len(ops) >= 2:
                rn = reg_num(ops[1])
            operand = ops[2] if len(ops) >= 3 else None
        I = 0
        operand2 = 0
        if operand is None:
            # mov r0 等价 mov r0, r0
            operand2 = 0
        elif is_imm(operand):
            val = parse_imm(operand) & 0xFFFFFFFF
            enc = encode_rot_imm(val)
            if enc is None:
                # 用 movw/movt 风格无法在此指令表达 -> 报错
                raise AsmError("立即数无法用 ARM 旋转编码: %s (0x%x)" % (operand, val))
            imm8, rot = enc
            I = 1
            operand2 = (rot << 8) | imm8
        else:
            # 寄存器, 可能带移位
            operand2 = self._reg_shift(operand)
        word = (cond << 28) | (I << 25) | (opcode << 21)
        if name not in DP_NO_S:
            if name in DP_IMM:
                pass
            else:
                word |= (rn << 16)
            word |= (rd << 12) | operand2 | (sbit << 20)
        else:
            word |= (rn << 16) | operand2 | (1 << 20)  # S=1 for cmp
        return word

    def _reg_shift(self, operand):
        m = re.match(r"^([a-z0-9]+)(?:\s*,\s*(lsl|lsr|asr|ror|rrx)\s*(.*))?$", operand.strip(), re.I)
        if not m:
            raise AsmError("无法解析操作数: %s" % operand)
        rm = reg_num(m.group(1))
        shift = (m.group(2) or "").lower()
        arg = (m.group(3) or "").strip()
        if not shift:
            return rm
        if shift == "rrx":
            return (0x6 << 5) | rm  # ROR #0 编码为 type=3 imm=0
        if is_imm(arg):
            imm = parse_imm(arg)
            if shift == "lsl":
                return (imm << 7) | rm if imm else rm
            if shift == "lsr":
                return (1 << 5) | ((imm & 31) << 7) | rm
            if shift == "asr":
                return (2 << 5) | ((imm & 31) << 7) | rm
            if shift == "ror":
                return (3 << 5) | ((imm & 31) << 7) | rm
        else:
            rs = reg_num(arg)
            typ = {"lsl": 0, "lsr": 1, "asr": 2, "ror": 3}[shift]
            return (rs << 8) | (typ << 5) | rm
        return rm

    def _mul(self, cond, sbit, ops):
        rd = reg_num(ops[0]); rn = reg_num(ops[1]); rs = reg_num(ops[2])
        return (cond << 28) | (rd << 16) | (rn << 12) | (rs << 8) | (9 << 4) | (sbit << 20)

    def _loadstore(self, name, cond, ops):
        load = name.startswith("ldr")
        byte = "b" in name[3:]
        half = "h" in name[3:] or "sb" in name[3:] or "sh" in name[3:]
        # 操作数: rt, [rn, #off]  /  rt, [rn]  / rt, label
        rt = reg_num(ops[0])
        mem = ops[1].strip()
        m = re.match(r"^\[\s*([a-z0-9]+)\s*(?:,\s*(.+?)\s*)?\]$", mem, re.I)
        if not m:
            raise AsmError("无法解析内存操作数: %s" % mem)
        rn = reg_num(m.group(1))
        off = (m.group(2) or "").strip()
        P, U, W = 1, 1, 0
        imm = 0
        if off.startswith("#") or re.match(r"^-?(0x[0-9a-fA-F]+|\d+)$", off):
            imm = parse_imm(off)
            if imm < 0:
                U = 0; imm = -imm
        elif off:
            # 寄存器偏移
            rm = reg_num(off)
            if half:
                word = (cond << 28) | (P << 24) | (U << 23) | (1 << 22) | (W << 21) \
                       | (rn << 16) | (rt << 12) | (1 << 6) | (1 << 5) | rm
                if load:
                    word |= (1 << 20)
                    if "sb" in name:
                        word |= (2 << 6)
                    elif "sh" in name:
                        word |= (1 << 6)
                return word
            return (cond << 28) | (P << 24) | (U << 23) | (1 << 25) | (W << 21) \
                   | (rn << 16) | (rt << 12) | (rm)
        if half:
            word = (cond << 28) | (P << 24) | (U << 23) | (1 << 22) | (W << 21) \
                   | (rn << 16) | (rt << 12) | ((imm & 0xF0) << 4) | (imm & 0x0F) \
                   | (1 << 6) | (1 << 5)
            if load:
                word |= (1 << 20)
                if "sb" in name:
                    word |= (2 << 6)
                elif "sh" in name:
                    word |= (1 << 6)
            return word
        word = (cond << 28) | (P << 24) | (U << 23) | (1 << 26) | (W << 21) \
               | (rn << 16) | (rt << 12) | (imm & 0xFFF)
        if load:
            word |= (1 << 20)
        if byte:
            word |= (1 << 22)
        return word

    def _b(self, cond, ops, link):
        target = ops[0].strip()
        # 目标可以是 #imm 或数值
        if is_imm(target):
            dest = parse_imm(target)
        else:
            raise AsmError("分支目标需为数值 (本子集不支持标签解析): %s" % target)
        off = (dest - (self.base)) >> 2
        off &= 0xFFFFFF
        word = (cond << 28) | (0x5 << 25) | ((1 << 24) if link else 0) | off
        return word

    def _bx(self, cond, ops, link):
        rm = reg_num(ops[0])
        return (cond << 28) | (0x12FFF1 << 4) | (0x3 << 4) | rm | ((1 << 4) if False else 0) | 0x10 \
               if False else (cond << 28) | 0x012FFF10 | rm | ((1 << 4) if link else 0) | (0x3 << 5 if link else 0)

    def _pushpop(self, cond, ops, push):
        regs = []
        for o in ops:
            o = o.strip().strip("{}")
            for r in o.split(","):
                r = r.strip()
                if r:
                    regs.append(reg_num(r))
        mask = 0
        for r in regs:
            mask |= (1 << r)
        if push:
            # STMDB sp!, {regs}  =  PUSH
            return (cond << 28) | 0x092D0000 | mask
        else:
            # LDMIA sp!, {regs}  =  POP
            return (cond << 28) | 0x08BD0000 | mask


# ============================================================ Thumb (T32) 汇编器
class ThumbAssembler:
    """覆盖常用 Thumb-16 指令子集 (ARMv7-M 风格)。"""

    def assemble(self, text, base=0):
        out = bytearray()
        for raw in text.splitlines():
            line = ARMAssembler._strip_comment(raw).strip()
            if not line or line.endswith(":"):
                continue
            line = re.sub(r"^[A-Za-z_.$][\w.$]*:\s*", "", line)
            if line.lower() in (".thumb", ".text", ".code", ".syntax", ".thumb_func"):
                continue
            if line.lower() == "nop":
                out += struct.pack("<H", 0xBF00); continue
            hw = self.encode_one(line)
            out += struct.pack("<H", hw & 0xFFFF)
        return bytes(out)

    def encode_one(self, line):
        parts = line.split(None, 1)
        mnem = parts[0].lower()
        rest = parts[1] if len(parts) > 1 else ""
        ops = split_operands(rest)
        if mnem in ("bx",):
            rm = reg_num(ops[0]); return 0x4700 | (rm << 3)
        if mnem in ("blx",):
            rm = reg_num(ops[0]); return 0x4780 | (rm << 3)
        if mnem in ("push",):
            regs = self._regs(ops); mask = 0; lr = 0
            for r in regs:
                if r == 14: lr = 1
                else: mask |= (1 << r)
            return 0xB400 | (lr << 8) | mask
        if mnem in ("pop",):
            regs = self._regs(ops); mask = 0; pc = 0
            for r in regs:
                if r == 15: pc = 1
                else: mask |= (1 << r)
            return 0xBC00 | (pc << 8) | mask
        if mnem in ("mov", "movs"):
            rd = reg_num(ops[0])
            if is_imm(ops[1]):
                imm = parse_imm(ops[1]) & 0xFF
                return 0x2000 | (rd << 8) | imm
            rm = reg_num(ops[1])
            if rd < 8 and rm < 8:
                return (0x1C00 if mnem == "movs" else 0x1C00) | (rm << 3) | rd \
                    if False else 0x1C00 | (rm << 3) | rd
            return 0x4600 | ((rm & 8) << 4) | ((rd & 8) << 3) | ((rm & 7) << 3) | (rd & 7)
        if mnem in ("add", "adds", "sub", "subs"):
            rd = reg_num(ops[0])
            if len(ops) == 2 and is_imm(ops[1]):
                # adds r0, #2  ==  adds r0, r0, #2
                imm = parse_imm(ops[1]) & 0xFF
                if mnem.startswith("sub"):
                    return 0x3800 | (rd << 8) | imm
                return 0x3000 | (rd << 8) | imm
            if len(ops) == 3 and is_imm(ops[2]):
                imm = parse_imm(ops[2]) & 0xFF
                if mnem.startswith("sub"):
                    return 0x3800 | (rd << 8) | imm
                return 0x3000 | (rd << 8) | imm
            rn = reg_num(ops[1]) if len(ops) >= 2 else rd
            rm = reg_num(ops[-1])
            if mnem.startswith("sub"):
                return 0x1A00 | (rm << 6) | (rn << 3) | rd
            return 0x1800 | (rm << 6) | (rn << 3) | rd
        if mnem in ("cmp", "cmn"):
            rn = reg_num(ops[0])
            if is_imm(ops[1]):
                return 0x2800 | (rn << 8) | (parse_imm(ops[1]) & 0xFF)
            rm = reg_num(ops[1]); return 0x4280 | (rm << 3) | rn
        if mnem in ("and", "eor", "orr", "lsl", "lsr", "asr", "adc", "sbc", "mul", "mvn", "bic", "tst", "adds_reg"):
            rd = reg_num(ops[0]); rm = reg_num(ops[1])
            table = {"and": 0x4000, "eor": 0x4040, "lsl": 0x4080, "lsr": 0x40C0,
                     "asr": 0x4100, "adc": 0x4140, "sbc": 0x4180, "ror": 0x41C0,
                     "tst": 0x4200, "mvn": 0x43C0, "bic": 0x4380, "orr": 0x4300,
                     "mul": 0x4340}
            hi = ((rd & 8) << 4) | ((rm & 8) << 3)
            return table[mnem] | hi | ((rm & 7) << 3) | (rd & 7)
        if mnem in ("ldr", "str", "ldrb", "strb"):
            rt = reg_num(ops[0])
            mem = ops[1].strip()
            m = re.match(r"^\[\s*([a-z0-9]+)\s*(?:,\s*(#?.+?)\s*)?\]$", mem, re.I)
            rn = reg_num(m.group(1)); off = (m.group(2) or "").strip()
            imm = parse_imm(off) if off else 0
            byte = "b" in mnem
            load = mnem.startswith("ldr")
            if byte:
                base_op = 0x7800 if load else 0x7000
                return base_op | ((imm // 1) << 6) | (rn << 3) | rt
            base_op = 0x6800 if load else 0x6000
            return base_op | ((imm // 4) << 6) | (rn << 3) | rt
        if mnem in ("b",):
            raise AsmError("Thumb 无条件 B 需数值目标 (本子集用 .word)")
        if mnem in ("nop",):
            return 0xBF00
        if mnem in ("svc", "swi"):
            return 0xDF00 | (parse_imm(ops[0]) & 0xFF)
        raise AsmError("不支持的 Thumb 指令: %s" % line)

    @staticmethod
    def _regs(ops):
        regs = []
        for o in ops:
            for r in o.strip().strip("{}").split(","):
                r = r.strip()
                if r:
                    regs.append(reg_num(r))
        return regs


# ============================================================ 反汇编 (核心子集)
def disasm_arm(word, addr=0):
    cond = (word >> 28) & 0xF
    c = {v: k for k, v in CONDS.items() if v != 0xE}
    csuf = c.get(cond, "")
    if (word & 0x0FFFFFF0) == 0x012FFF10:
        return "bx%s %s" % (csuf, _rn((word & 0xF)))
    if (word & 0x0FFFFFF0) == 0x012FFF30:
        return "blx%s %s" % (csuf, _rn(word & 0xF))
    if (word & 0x0E000000) == 0x0A000000:
        link = (word >> 24) & 1
        off = word & 0xFFFFFF
        if off & 0x800000:
            off -= 0x1000000
        dest = addr + 8 + off * 4
        return "bl%s 0x%x" % (csuf, dest) if link else "b%s 0x%x" % (csuf, dest)
    if (word & 0x0E000000) == 0x08000000 and (word & 0x60) == 0x20 \
       and ((word & 0x0F000000) == 0x09000000 or (word & 0x10) == 0x10):
        # ldm/stm
        P = (word >> 24) & 1; U = (word >> 23) & 1; S = (word >> 22) & 1
        W = (word >> 21) & 1; L = (word >> 20) & 1
        rn = (word >> 16) & 0xF; mask = word & 0xFFFF
        regs = ",".join(_rn(i) for i in range(16) if mask & (1 << i))
        name = ("ldm" if L else "stm") + ("fd" if L else "ea")
        return "%s%s %s, {%s}" % (name, csuf, _rn(rn), regs)
    if (word & 0x0C000000) == 0x04000000:
        return _dis_ldst(word, csuf)
    if (word & 0x0E000000) == 0x00000000 and (word & 0x90) == 0x90:
        # mul / extra loadstore
        return _dis_extra(word, csuf)
    if (word & 0x0C000000) == 0x00000000:
        return _dis_dp(word, csuf)
    return ".word 0x%08x" % word


def _rn(n):
    names = {13: "sp", 14: "lr", 15: "pc"}
    return names.get(n, "r%d" % n)


def _dis_dp(word, csuf):
    I = (word >> 25) & 1
    op = (word >> 21) & 0xF
    rn = (word >> 16) & 0xF
    rd = (word >> 12) & 0xF
    s = (word >> 20) & 1
    name = [k for k, v in DP_OPS.items() if v == op][0]
    if name in ("tst", "teq", "cmp", "cmn"):
        rd_s = ""
    else:
        rd_s = _rn(rd)
    if I:
        imm = word & 0xFF
        rot = ((word >> 8) & 0xF) * 2
        val = ((imm >> rot) | (imm << (32 - rot))) & 0xFFFFFFFF if rot else imm
        op2 = "#0x%x" % val
    else:
        op2 = _rn(word & 0xF)
        shift = (word >> 5) & 3
        amt = (word >> 7) & 0x1F
        if (word & 0x10):
            op2 += ", %s %s" % (["lsl", "lsr", "asr", "ror"][shift], _rn((word >> 8) & 0xF))
        elif shift or amt:
            op2 += ", %s #%d" % (["lsl", "lsr", "asr", "ror"][shift], amt)
    if name in ("tst", "teq", "cmp", "cmn"):
        return "%s%s %s, %s" % (name, csuf, _rn(rn), op2)
    if name in ("mov", "mvn"):
        return "%s%s%s %s, %s" % (name, csuf, "s" if s else "", rd_s, op2)
    return "%s%s%s %s, %s, %s" % (name, csuf, "s" if s else "", rd_s, _rn(rn), op2)


def _dis_ldst(word, csuf):
    I = (word >> 25) & 1
    P = (word >> 24) & 1; U = (word >> 23) & 1; B = (word >> 22) & 1
    W = (word >> 21) & 1; L = (word >> 20) & 1
    rn = (word >> 16) & 0xF; rt = (word >> 12) & 0xF
    name = ("ldr" if L else "str") + ("b" if B else "")
    if I:
        off = _rn(word & 0xF)
        if (word >> 5) & 3:
            off += ", %s #%d" % (["lsl", "lsr", "asr", "ror"][(word >> 5) & 3], (word >> 7) & 0x1F)
        op2 = off
    else:
        imm = word & 0xFFF
        op2 = "#%d" % imm if U else "#-%d" % imm
    if P:
        s = "[%s%s%s]" % (_rn(rn), ", " if op2 else "", op2)
        if W:
            s = "!"
        return "%s%s %s, %s" % (name, csuf, _rn(rt), s)
    return "%s%s %s, [%s], %s" % (name, csuf, _rn(rt), _rn(rn), op2)


def _dis_extra(word, csuf):
    if (word & 0x90) == 0x90 and (word & 0x60) != 0:
        return _dis_ldst(word, csuf)
    op1 = (word >> 20) & 0xF
    rd = (word >> 12) & 0xF; rn = (word >> 16) & 0xF; rs = (word >> 8) & 0xF
    if op1 & 0x8:
        # extra load/store (half/signed)
        L = (word >> 20) & 1; W = (word >> 21) & 1; I = (word >> 22) & 1
        imm = ((word & 0xF0) << 4) | (word & 0xF)
        sh = (word >> 5) & 3
        nm = ["", "ldrsb", "ldrsh", ""][sh] if L else ["", "strh", "", ""][sh]
        return "%s%s %s, [%s, #%d]" % (nm or "strh", csuf, _rn(rd), _rn(rn), imm)
    return "mul%s %s, %s, %s" % (csuf, _rn(rd), _rn(rn), _rn(rs))


def disasm_thumb(hw, addr=0):
    if (hw & 0xFF00) == 0xBF00:
        return "nop"
    if (hw & 0xFF87) == 0x4700:
        return "bx %s" % _rn((hw >> 3) & 0xF)
    if (hw & 0xFF87) == 0x4780:
        return "blx %s" % _rn((hw >> 3) & 0xF)
    if (hw & 0xFF00) == 0xB400:
        return "push {%s}" % _thumb_reglist(hw & 0xFF, (hw >> 8) & 1, is_lr=True)
    if (hw & 0xFF00) == 0xBC00:
        return "pop {%s}" % _thumb_reglist(hw & 0xFF, (hw >> 8) & 1, is_pc=True)
    if (hw & 0xF800) == 0x2000:
        return "movs %s, #%d" % (_rn((hw >> 8) & 7), hw & 0xFF)
    if (hw & 0xF800) == 0x3000:
        return "adds %s, #%d" % (_rn((hw >> 8) & 7), hw & 0xFF)
    if (hw & 0xF800) == 0x3800:
        return "subs %s, #%d" % (_rn((hw >> 8) & 7), hw & 0xFF)
    if (hw & 0xF800) == 0x2800:
        return "cmp %s, #%d" % (_rn((hw >> 8) & 7), hw & 0xFF)
    if (hw & 0xFF00) == 0x4600:
        rm = ((hw >> 3) & 0xF); rd = ((hw & 7) | ((hw >> 4) & 8))
        return "mov %s, %s" % (_rn(rd), _rn(rm))
    if (hw & 0xF800) == 0x6000:
        return "str %s, [%s, #%d]" % (_rn(hw & 7), _rn((hw >> 3) & 7), ((hw >> 6) & 0x1F) * 4)
    if (hw & 0xF800) == 0x6800:
        return "ldr %s, [%s, #%d]" % (_rn(hw & 7), _rn((hw >> 3) & 7), ((hw >> 6) & 0x1F) * 4)
    if (hw & 0xF800) == 0x7000:
        return "strb %s, [%s, #%d]" % (_rn(hw & 7), _rn((hw >> 3) & 7), (hw >> 6) & 0x1F)
    if (hw & 0xF800) == 0x7800:
        return "ldrb %s, [%s, #%d]" % (_rn(hw & 7), _rn((hw >> 3) & 7), (hw >> 6) & 0x1F)
    if (hw & 0xFC00) == 0x1800:
        return "adds %s, %s, %s" % (_rn(hw & 7), _rn((hw >> 3) & 7), _rn((hw >> 6) & 7))
    if (hw & 0xFC00) == 0x1A00:
        return "subs %s, %s, %s" % (_rn(hw & 7), _rn((hw >> 3) & 7), _rn((hw >> 6) & 7))
    if (hw & 0xFFC0) == 0x4000:
        return "ands %s, %s" % (_rn(hw & 7), _rn((hw >> 3) & 7))
    if (hw & 0xFFC0) == 0x4040:
        return "eors %s, %s" % (_rn(hw & 7), _rn((hw >> 3) & 7))
    if (hw & 0xFFC0) == 0x4300:
        return "orrs %s, %s" % (_rn(hw & 7), _rn((hw >> 3) & 7))
    if (hw & 0xFFC0) == 0x4340:
        return "muls %s, %s" % (_rn(hw & 7), _rn((hw >> 3) & 7))
    if (hw & 0xFF00) == 0xDF00:
        return "svc #%d" % (hw & 0xFF)
    return ".word 0x%04x" % hw


def _thumb_reglist(mask, extra, is_lr=False, is_pc=False):
    out = [_rn(i) for i in range(8) if mask & (1 << i)]
    if is_lr and extra:
        out.append("lr")
    if is_pc and extra:
        out.append("pc")
    return ", ".join(out)


# ============================================================ 外部工具后备通道
def external_assemble(asm_text, thumb=False):
    """尝试调用 arm-linux-androideabi-as (若存在) 汇编。失败返回 None。"""
    candidates = ["arm-linux-androideabi-as", "arm-none-eabi-as", "arm-eabi-as"]
    tool = None
    for c in candidates:
        from shutil import which
        if which(c):
            tool = c; break
    if not tool:
        return None
    import tempfile
    d = tempfile.mkdtemp(prefix="armasm_")
    sfile = os.path.join(d, "a.s")
    ofile = os.path.join(d, "a.o")
    with open(sfile, "w") as f:
        if thumb:
            f.write(".syntax unified\n.thumb\n.text\n")
        else:
            f.write(".syntax unified\n.arm\n.text\n")
        f.write(asm_text + "\n")
    try:
        subprocess.run([tool, "-march=armv7-a", "-o", ofile, sfile],
                       check=True, capture_output=True)
        data = open(ofile, "rb").read()
        # 极简 ELF .text 提取: 扫描第一个可执行段 (简化: 取 offset 0x40 后)
        return _extract_text_from_elf(data)
    except Exception:
        return None


def _extract_text_from_elf(data):
    if data[:4] != b"\x7fELF":
        return None
    try:
        e_shoff = struct.unpack_from("<I", data, 0x20)[0]
        e_shentsize = struct.unpack_from("<H", data, 0x2E)[0]
        e_shnum = struct.unpack_from("<H", data, 0x30)[0]
        for i in range(e_shnum):
            off = e_shoff + i * e_shentsize
            sh_type = struct.unpack_from("<I", data, off + 4)[0]
            sh_off = struct.unpack_from("<I", data, off + 0x10)[0]
            sh_size = struct.unpack_from("<I", data, off + 0x14)[0]
            sh_flags = struct.unpack_from("<I", data, off + 8)[0]
            if sh_flags & 0x4:  # SHF_EXECINSTR
                return data[sh_off:sh_off + sh_size]
        return None
    except Exception:
        return None


# ============================================================ 高层 API
def assemble(text, mode="arm", base=0, prefer_external=False):
    if prefer_external:
        r = external_assemble(text, thumb=(mode == "thumb"))
        if r:
            return r
    if mode == "thumb":
        return ThumbAssembler().assemble(text, base)
    return ARMAssembler().assemble(text, base)


def disassemble(data, mode="arm", base=0):
    out = []
    if mode == "thumb":
        for i in range(0, len(data) - 1, 2):
            hw = struct.unpack_from("<H", data, i)[0]
            out.append("%08x: %-6s %s" % (base + i, "%04x" % hw, disasm_thumb(hw, base + i)))
    else:
        for i in range(0, len(data) - 3, 4):
            w = struct.unpack_from("<I", data, i)[0]
            out.append("%08x: %-8s %s" % (base + i, "%08x" % w, disasm_arm(w, base + i)))
    return "\n".join(out)


def bytes_to_hex(data):
    return " ".join("%02x" % b for b in data)


def hex_to_bytes(s):
    s = re.sub(r"0x", "", s, flags=re.I)
    s = re.sub(r"[^0-9a-fA-F]", "", s)
    if len(s) % 2:
        s = "0" + s
    return bytes.fromhex(s)


# ============================================================ GUI
def run_gui():
    from PySide6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
        QLabel, QPlainTextEdit, QComboBox, QLineEdit, QStatusBar, QMessageBox,
    )
    from PySide6.QtGui import QAction

    app = QApplication(sys.argv)
    win = QMainWindow()
    win.setWindowTitle("Arm汇编转换器 (ARM/Thumb 汇编 -> 机器码)  PySide6")
    win.resize(900, 640)
    central = QWidget(); win.setCentralWidget(central)
    lay = QVBoxLayout(central)

    bar = QHBoxLayout()
    mode = QComboBox(); mode.addItems(["ARM (A32)", "Thumb (T32)"])
    base_edit = QLineEdit("0"); base_edit.setFixedWidth(110)
    bar.addWidget(QLabel("模式:")); bar.addWidget(mode)
    bar.addWidget(QLabel("基址:")); bar.addWidget(base_edit)
    ext_cb = QPushButton("用外部 as"); ext_cb.setCheckable(True)
    bar.addWidget(ext_cb)
    bar.addStretch()
    lay.addLayout(bar)

    edit = QPlainTextEdit(); edit.setPlaceholderText(
        "在此输入 ARM / Thumb 汇编, 每行一条, 例如:\n  mov r0, #1\n  add r0, r0, #2\n  bx lr")
    lay.addWidget(QLabel("汇编输入:")); lay.addWidget(edit)

    btns = QHBoxLayout()
    b_asm = QPushButton("汇编 -> 机器码"); b_dis = QPushButton("机器码 -> 反汇编")
    b_clear = QPushButton("清空"); b_copy = QPushButton("复制结果")
    btns.addWidget(b_asm); btns.addWidget(b_dis); btns.addWidget(b_clear); btns.addWidget(b_copy); btns.addStretch()
    lay.addLayout(btns)

    out = QPlainTextEdit(); out.setReadOnly(True)
    lay.addWidget(QLabel("输出:")); lay.addWidget(out)
    win.statusBar().showMessage("就绪")

    def cur_mode():
        return "thumb" if mode.currentText().startswith("Thumb") else "arm"

    def cur_base():
        try:
            return int(base_edit.text(), 0)
        except Exception:
            return 0

    def do_asm():
        try:
            prefer = ext_cb.isChecked()
            data = assemble(edit.toPlainText(), cur_mode(), cur_base(), prefer_external=prefer)
            if not data:
                QMessageBox.warning(win, "提示", "汇编结果为空或失败")
                return
            txt = "机器码 (hex):\n" + bytes_to_hex(data)
            txt += "\n\n反汇编:\n" + disassemble(data, cur_mode(), cur_base())
            out.setPlainText(txt)
            win.statusBar().showMessage("汇编完成: %d 字节" % len(data))
        except AsmError as e:
            QMessageBox.critical(win, "汇编错误", str(e))

    def do_dis():
        try:
            data = hex_to_bytes(out.toPlainText() or edit.toPlainText())
            out.setPlainText("反汇编:\n" + disassemble(data, cur_mode(), cur_base()))
            win.statusBar().showMessage("反汇编完成")
        except Exception as e:
            QMessageBox.critical(win, "错误", str(e))

    b_asm.clicked.connect(do_asm)
    b_dis.clicked.connect(do_dis)
    b_clear.clicked.connect(lambda: (edit.clear(), out.clear()))
    b_copy.clicked.connect(lambda: _copy(app, out.toPlainText()))

    quit_a = QAction("退出", win); quit_a.triggered.connect(win.close)
    win.addAction(quit_a)
    win.show()
    sys.exit(app.exec())


def _copy(app, text):
    from PySide6.QtGui import QGuiApplication
    QGuiApplication.clipboard().setText(text)


# ============================================================ CLI / 自检
def selftest():
    cases_arm = [
        ("mov r0, #1", "e3a00001"),
        ("add r0, r0, #2", "e2800002"),
        ("sub r1, r2, r3", "e0421003"),
        ("cmp r0, #0", "e3500000"),
        ("bx lr", "e12fff1e"),
        ("push {r4, lr}", "e92d4010"),
        ("pop {r4, pc}", "e8bd8010"),
        ("mov r0, r1", "e1a00001"),
        ("ldr r0, [r1, #4]", "e5910004"),
        ("str r0, [r1]", "e5810000"),
        ("nop", "e1a00000"),
    ]
    ok = 0; fail = 0
    print("== ARM 编码自检 ==")
    for asm, expect in cases_arm:
        got = bytes_to_hex(ARMAssembler().assemble(asm))
        exp_bytes = struct.pack("<I", int(expect, 16))
        okone = got == bytes_to_hex(exp_bytes)
        status = "OK " if okone else "ERR"
        if okone: ok += 1
        else: fail += 1
        print("  [%s] %-18s -> %s (expect %s)" % (status, asm, got, expect))

    print("== Thumb 编码自检 ==")
    cases_thumb = [
        ("movs r0, #1", "2001"),
        ("adds r0, #2", "3002"),
        ("bx lr", "4770"),
        ("push {r4, lr}", "b510"),
        ("pop {r4, pc}", "bd10"),
        ("nop", "bf00"),
    ]
    for asm, expect in cases_thumb:
        got = bytes_to_hex(ThumbAssembler().assemble(asm))
        exp_bytes = struct.pack("<H", int(expect, 16))
        okone = got == bytes_to_hex(exp_bytes)
        status = "OK " if okone else "ERR"
        if okone: ok += 1
        else: fail += 1
        print("  [%s] %-18s -> %s (expect %s)" % (status, asm, got, expect))

    print("== 反汇编自检 ==")
    print(disassemble(bytes.fromhex("0100a0e3 1eff2fe1"), "arm"))
    print(disassemble(bytes.fromhex("0120 7047"), "thumb"))
    print("\n结果: %d 通过, %d 失败" % (ok, fail))
    return 0 if fail == 0 else 1


def main():
    args = sys.argv[1:]
    if "--selftest" in args:
        return selftest()
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if args[0] in ("-m", "--mode"):
        mode = args[1]; text = " ".join(args[2:])
        data = assemble(text, mode)
        print(bytes_to_hex(data))
        print(disassemble(data, mode))
        return 0
    if args[0] in ("-d", "--disasm"):
        mode = args[1]; data = hex_to_bytes(" ".join(args[2:]))
        print(disassemble(data, mode))
        return 0
    # 默认启动 GUI
    run_gui()


if __name__ == "__main__":
    sys.exit(main() or 0)