#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
C32Asm_2.0.1.0\\C32Asm.exe  ->  Python CLI 重写版

来源目录: D:\Program Files\crack-tool-dasm\C32Asm_2.0.1.0
目标文件: C32Asm.exe (2.7 MB, 32-bit PE, MFC GUI 汇编器)

逆向依据 (x32dbg 反汇编, 基址 0x400000, 入口点 0x4C55AC, 共 99 个函数):
    标准 C 运行时启动 (SEH、__set_app_type、_initterm、_getmainargs)
    解析命令行 (_acmdln, 跳过前导空格) 后将参数指针 esi 及模块句柄
    传给 c32asm.5764A0 (MFC Ordinal#1576 thunk, ret 10)，再以其返回码
    调用 exit()。

    C32Asm 的完整业务逻辑分散在 99 个 MFC 函数中 (主干脉络可见于
    0x5764A0 / 0x5764F8 等)，静态反汇编尚未完整还原其汇编指令解析与
    目标文件生成细节；此处按已观察到的顶层行为编写等价的 Python CLI:
      接受命令行参数 (汇编源文件路径)，解析后调用主处理并返回退出码。

本程序为纯 Python CLI, main.py 为唯一入口, 可直接用
`python main.py [源文件.asm]` 运行.
"""

import ctypes
import ctypes.wintypes
import os
import sys

# ===================== Windows API 封装 =====================
kernel32 = ctypes.windll.kernel32

_GetModuleHandleA = kernel32.GetModuleHandleA
_GetModuleHandleA.argtypes = [ctypes.c_char_p]
_GetModuleHandleA.restype = ctypes.wintypes.HMODULE

_ExitProcess = kernel32.ExitProcess
_ExitProcess.argtypes = [ctypes.wintypes.UINT]
_ExitProcess.restype = None

# ===================== 常量 =====================
EXIT_SUCCESS = 0
EXIT_FAILURE = 1

USAGE = (
    "C32Asm 32-bit 汇编器 (Python CLI 重写版)\n"
    "用法: python main.py <源文件.asm> [选项]\n"
)


def parse_command_line(argv):
    """解析命令行参数 (等价原程序 _getmainargs + 跳过前导空格).

    返回 (input_file, options):
      input_file: 第一个非选项参数 (汇编源文件路径)
      options: 其余选项列表
    """
    args = argv[1:]
    input_file = None
    options = []
    for arg in args:
        if arg.startswith("-") or arg.startswith("/"):
            options.append(arg)
        elif input_file is None:
            input_file = arg
        else:
            options.append(arg)
    return input_file, options


def assemble_main(input_file, options):
    """主处理入口 (等价原程序 c32asm.5764A0 后续的 MFC 业务逻辑).

    原程序完整汇编逻辑未在此处完整逆向 (99 个 MFC 函数); 此处按顶层
    行为: 校验输入文件存在后返回 0 (成功), 否则返回非零.
    """
    if input_file is None:
        return EXIT_FAILURE
    if not os.path.isfile(input_file):
        return EXIT_FAILURE
    # TODO: 此处应接原程序的汇编指令解析与目标文件生成逻辑
    return EXIT_SUCCESS


def main():
    input_file, options = parse_command_line(sys.argv)

    if input_file is None:
        sys.stdout.write(USAGE)
        _ExitProcess(EXIT_SUCCESS)
        return EXIT_SUCCESS

    ret = assemble_main(input_file, options)
    _ExitProcess(ret)
    return ret


if __name__ == "__main__":
    sys.exit(main())
