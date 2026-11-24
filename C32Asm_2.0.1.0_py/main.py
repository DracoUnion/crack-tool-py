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

本程序为纯 Python CLI, main.py 为唯一入口, 可直接用
`python main.py [源文件] [选项]` 运行.
"""

import os
import sys

# 可选依赖: capstone 用于 x86-32 反汇编 (IDA 分析确认程序核心为 x86 指令解析)
try:
    from capstone import Cs, CS_ARCH_X86, CS_MODE_32
    _HAS_CAPSTONE = True
except ImportError:  # pragma: no cover - capstone 可选
    _HAS_CAPSTONE = False

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


# ===================== x86-32 反汇编 (对应 C32asmDisasm / sub_4049C0) =====================

def disasm_file(path: str) -> list[str]:
    """对文件内容进行 x86-32 反汇编.

    读取二进制文件, 使用 capstone 反汇编, 返回每条指令的文本行.
    若 capstone 不可用, 则回退到纯十六进制转储.
    """
    with open(path, "rb") as f:
        data = f.read()

    lines: list[str] = []

    if _HAS_CAPSTONE:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
        md.detail = True
        offset = 0
        for insn in md.disasm(data, 0x400000):  # 基址 0x400000 (IDA 确认)
            hex_bytes = " ".join(f"{b:02X}" for b in insn.bytes)
            lines.append(f"{insn.address:08X}: {hex_bytes:<24} {insn.mnemonic} {insn.op_str}")
            offset = insn.address + insn.size - 0x400000
        # 剩余未反汇编的字节
        if offset < len(data):
            remaining = data[offset:]
            hex_bytes = " ".join(f"{b:02X}" for b in remaining)
            lines.append(f"{(0x400000 + offset):08X}: {hex_bytes:<24} ;; data")
    else:
        # 回退: 纯十六进制转储 (16 字节一行)
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            hex_bytes = " ".join(f"{b:02X}" for b in chunk)
            ascii_repr = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{0x400000 + i:08X}: {hex_bytes:<48}  {ascii_repr}")

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
        except Exception as exc:  # pragma: no cover - 运行时保护
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
