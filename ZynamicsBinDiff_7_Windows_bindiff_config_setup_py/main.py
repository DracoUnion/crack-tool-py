#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZynamicsBinDiff_7_Windows\\bindiff_config_setup.exe  ->  Python CLI 重写版

来源目录: D:\Program Files\crack-tool-dasm\ZynamicsBinDiff_7_Windows
目标文件: bindiff_config_setup.exe (约 1.9 MB, 64-bit PE)

逆向依据 (x64dbg 反汇装, 基址 0x7FF7605F0000, 大小 0x1D9000, PE 入口点 RVA
0x1199A0 => 0x7FF7607099A0, 仅识别出 1 个函数, 分析不完整):
    入口点 0x7FF7607099A0:
      sub rsp,28; call 0x7FF76070A544; add rsp,28; jmp 0x7FF760709824
    0x7FF760709824 起为主程序逻辑. bindiff_config_setup.exe 是 BinDiff
    配置安装程序, 其完整安装/配置逻辑未在此处完整逆向. 此处按已确认
    的入口点行为编写等价的 Python CLI 框架:
      接受配置文件路径作为命令行参数, 进入主处理并返回退出码.

    后续如需完整还原, 需逆向入口点 0x7FF7607099A0 及其调用的主程序
    逻辑 (0x7FF760709824 起).

本程序为纯 Python CLI, main.py 为唯一入口, 可直接用
`python main.py <配置文件>` 运行.
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
ENTRY_POINT = 0x7FF7607099A0


def config_setup_main(config_path):
    """主处理入口 (等价原程序 bindiff_config_setup.exe 核心安装/配置逻辑).

    原程序完整逻辑未在此处完整逆向. 此处按顶层行为:
      若提供了配置文件路径且存在, 返回 0 (成功), 否则返回非零.
    """
    if config_path is None:
        return 1
    if not os.path.isfile(config_path):
        return 1
    # TODO: 此处应接原程序的配置安装核心逻辑
    return EXIT_SUCCESS


def main():
    config_path = sys.argv[1] if len(sys.argv) >= 2 else None

    ret = config_setup_main(config_path)

    _ExitProcess(ret)
    return ret


if __name__ == "__main__":
    sys.exit(main())
