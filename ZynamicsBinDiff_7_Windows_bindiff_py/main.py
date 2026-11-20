#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZynamicsBinDiff_7_Windows\\bindiff.exe  ->  Python CLI 重写版

来源目录: D:\Program Files\crack-tool-dasm\ZynamicsBinDiff_7_Windows
目标文件: bindiff.exe (约 3.6 MB, 64-bit PE)

逆向依据 (x64dbg 反汇装, 基址 0x7FF6EEEE0000, 大小 0x383000, PE 入口点 RVA
0x127750 => 0x7FF6F015750, 仅识别出 1 个函数, 分析不完整):
    程序加载并运行后在 0x7FF6EF107A1C 处执行 `cmp edx,2` (检查参数个数),
    这是典型的命令行工具行为. 入口点 0x7FF6F015750 为程序启动代码.
    bindiff.exe 是 Zynamics BinDiff 的二进制比对工具, 其完整图对比/
    导出逻辑未在此处完整逆向. 此处按已确认的入口点行为编写等价的
    Python CLI 框架:
      接受待比对的两个二进制文件路径作为命令行参数, 进入主处理并
      返回退出码.

    后续如需完整还原, 需逆向入口点 0x7FF6F015750 及其调用的核心
    二进制比对逻辑.

本程序为纯 Python CLI, main.py 为唯一入口, 可直接用
`python main.py <文件1> <文件2>` 运行.
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
ENTRY_POINT = 0x7FF6F015750


def bindiff_main(file1, file2):
    """主处理入口 (等价原程序 bindiff.exe 核心二进制比对逻辑).

    原程序完整逻辑未在此处完整逆向. 此处按顶层行为:
      若提供了两个文件路径且均存在, 返回 0 (成功), 否则返回非零.
    """
    if file1 is None or file2 is None:
        return 1
    if not os.path.isfile(file1) or not os.path.isfile(file2):
        return 1
    # TODO: 此处应接原程序的二进制比对核心逻辑
    return EXIT_SUCCESS


def main():
    file1 = sys.argv[1] if len(sys.argv) >= 2 else None
    file2 = sys.argv[2] if len(sys.argv) >= 3 else None

    ret = bindiff_main(file1, file2)

    _ExitProcess(ret)
    return ret


if __name__ == "__main__":
    sys.exit(main())
