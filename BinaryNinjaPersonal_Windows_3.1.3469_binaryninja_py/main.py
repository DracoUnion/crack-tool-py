#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BinaryNinjaPersonal_Windows_3.1.3469\\binaryninja.exe  ->  Python CLI 重写版

来源目录: D:\Program Files\crack-tool-dasm\BinaryNinjaPersonal_Windows_3.1.3469
目标文件: binaryninja.exe (约 19 MB, 64-bit PE)

逆向依据 (x64dbg 反汇装, 基址 0x7FF615D30000, 大小 0x1273000, PE 入口点 RVA
0x242EA4 => 0x7FF615F72EA4, 仅识别出 1 个函数, 分析不完整):
    入口点 0x7FF615F72EA4:
      sub rsp,28; call 0x7FF615F73E3C; add rsp,28; jmp 0x7FF615F72C98
    0x7FF615F72C98 起为主程序逻辑. binaryninja.exe 是 Binary Ninja 反汇编
    器的主程序, 其完整反汇编/图显示/脚本逻辑未在此处完整逆向. 此处按
    已确认的入口点行为编写等价的 Python CLI 框架:
      接受待反汇编的二进制文件路径作为命令行参数, 进入主处理并
      返回退出码.

    后续如需完整还原, 需逆向入口点 0x7FF615F72EA4 及其调用的主程序
    逻辑 (0x7FF615F72C98 起).

本程序为纯 Python CLI, main.py 为唯一入口, 可直接用
`python main.py <二进制文件>` 运行.
"""

import ctypes
import os
import sys

# ===================== Windows API 封装 =====================
kernel32 = ctypes.windll.kernel32

_ExitProcess = kernel32.ExitProcess
_ExitProcess.argtypes = [ctypes.c_uint]
_ExitProcess.restype = None

# ===================== 常量 =====================
EXIT_SUCCESS = 0

# 入口点 (x64dbg / PE 头分析得到)
ENTRY_POINT = 0x7FF615F72EA4


def disassemble_main(target_path):
    """主处理入口 (等价原程序 binaryninja.exe 核心反汇编器逻辑).

    原程序完整逻辑未在此处完整逆向. 此处按顶层行为:
      若提供了目标文件路径且存在, 返回 0 (成功), 否则返回非零.
    """
    if target_path is None:
        return 1
    if not os.path.isfile(target_path):
        return 1
    # TODO: 此处应接原程序的反汇编器核心逻辑
    return EXIT_SUCCESS


def main():
    target_path = sys.argv[1] if len(sys.argv) >= 2 else None

    ret = disassemble_main(target_path)

    _ExitProcess(ret)
    return ret


if __name__ == "__main__":
    sys.exit(main())
