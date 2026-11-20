#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZynamicsBinDiff_7_Windows\\binexport2dump.exe  ->  Python CLI 重写版

来源目录: D:\Program Files\crack-tool-dasm\ZynamicsBinDiff_7_Windows
目标文件: binexport2dump.exe (1.4 MB, 64-bit PE)

逆向依据 (x64dbg 反汇装, 基址 0x7FF64C8F0000, 大小 0x170000, PE 入口点 RVA
0xB76F0 => 0x7FF64D466F0, 仅识别出 1 个函数, 分析不完整):
    binexport2dump.exe 是 Zynamics BinDiff 套件中的导出转储工具. 入口点
    位于 0x7FF64D466F0, 但 x64dbg 静态分析仅识别出 1 个函数, 完整的
    导出转储/图对比逻辑未在此处完整还原. 此处按已确认的入口点编写
    等价的 Python CLI 框架:
      接受待处理的 BinDiff 导出文件/目录作为命令行参数, 进入主处理
      并返回退出码.

    后续如需完整还原, 需进一步逆向入口点 0x7FF64D466F0 及其调用的
    核心逻辑.

本程序为纯 Python CLI, main.py 为唯一入口, 可直接用
`python main.py <输入文件>` 运行.
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

# 入口点 (x64dbg 分析得到)
ENTRY_POINT_RVA = 0xB76F0


def binexport2dump_main(input_path):
    """主处理入口 (等价原程序入口点 0x7FF64D466F0 后续的核心逻辑).

    原程序完整逻辑未在此处完整逆向. 此处按顶层行为:
      校验输入文件存在后返回 0 (成功), 否则返回非零.
    """
    if input_path is None:
        return 1
    if not os.path.isfile(input_path):
        return 1
    # TODO: 此处应接原程序的 BinDiff 导出转储核心逻辑
    return EXIT_SUCCESS


def main():
    input_path = sys.argv[1] if len(sys.argv) >= 2 else None

    ret = binexport2dump_main(input_path)

    _ExitProcess(ret)
    return ret


if __name__ == "__main__":
    sys.exit(main())
