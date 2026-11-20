#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
W32Dasm_8.93_黄金版中文版\\W32dsm89.exe  ->  Python CLI 重写版

来源目录: D:\Program Files\crack-tool-dasm\W32Dasm_8.93_黄金版中文版
目标文件: W32dsm89.exe (1 MB, 32-bit PE)

逆向依据 (x32dbg 反汇装, 基址 0x400000, 大小 0x100000, 入口点 0x40107C,
共 500 个函数):
    W32Dasm 8.93 黄金版中文版的主程序. 入口点 0x40107C, 但完整的反汇编
    引擎逻辑分布在 500 个函数中, 静态反汇装未完整还原其核心反汇编/
    显示逻辑. 此处按已确认的入口点编写等价的 Python CLI 框架:
      接受待反汇编的 PE 文件路径作为命令行参数, 进入主处理并返回退出码.

    后续如需完整还原, 需进一步逆向入口点 0x40107C 及其调用的 500 个
    函数的反汇编引擎核心逻辑.

本程序为纯 Python CLI, main.py 为唯一入口, 可直接用
`python main.py <待反汇编文件>` 运行.
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

# 入口点 (x32dbg 分析得到)
ENTRY_POINT = 0x40107C


def disassemble_main(target_path):
    """主处理入口 (等价原程序入口点 0x40107C 后续的反汇编引擎逻辑).

    原程序完整逻辑未在此处完整逆向 (500 个函数). 此处按顶层行为:
      校验目标文件存在后返回 0 (成功), 否则返回非零.
    """
    if target_path is None:
        return 1
    if not os.path.isfile(target_path):
        return 1
    # TODO: 此处应接原程序的 PE 反汇编引擎核心逻辑
    return EXIT_SUCCESS


def main():
    target_path = sys.argv[1] if len(sys.argv) >= 2 else None

    ret = disassemble_main(target_path)

    _ExitProcess(ret)
    return ret


if __name__ == "__main__":
    sys.exit(main())
