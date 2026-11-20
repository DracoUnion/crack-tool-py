#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BinaryNinjaPersonal_Windows_3.1.3469\\plugins\\python\\pythonw.exe  ->  Python CLI 重写版

来源目录: D:\Program Files\crack-tool-dasm\BinaryNinjaPersonal_Windows_3.1.3469\plugins\python
目标文件: pythonw.exe (100 KB, 64-bit PE, Python 运行时 GUI 版)

逆向依据 (x64dbg 反汇装, 基址 0x7FF7810D0000, 大小 0x1C000, PE 入口点 RVA
0x1354 => 0x7FF7810D1354, 仅识别出 1 个函数, 分析不完整):
    入口点 0x7FF7810D1354:
      sub rsp,28; call 0x7FF7810D1BC4; add rsp,28; jmp 0x7FF7810D115C
    0x7FF7810D1368 起为运行时初始化:
      push rbx; sub rsp,20; mov rbx,rcx
      SetUnhandledExceptionFilter; UnhandledExceptionFilter; GetCurrentProcess;
      TerminateProcess                                              ; 异常过滤
      IsProcessorFeaturePresent(17)
      设置一系列全局变量 (0x7FF7810D50E0/5050/5178/51D8/5160/5040/5044/
      5058/5060/5008 等)
    完整的 Python 解释器逻辑位于 python39.dll, 未在此处逆向. 此处按
    已确认的入口点编写等价的 Python CLI 框架:
      执行运行时初始化后进入主处理并返回退出码.

本程序为纯 Python CLI, main.py 为唯一入口, 可直接用 `python main.py` 运行.
"""

import ctypes
import sys

# ===================== Windows API 封装 =====================
kernel32 = ctypes.windll.kernel32

_ExitProcess = kernel32.ExitProcess
_ExitProcess.argtypes = [ctypes.c_uint]
_ExitProcess.restype = None

# ===================== 常量 =====================
EXIT_SUCCESS = 0

# 入口点 (x64dbg 分析得到)
ENTRY_POINT = 0x7FF7810D1354


def runtime_init():
    """等价原程序入口点 0x7FF7810D1354 起的运行时初始化部分:
    SetUnhandledExceptionFilter/GetCurrentProcess/TerminateProcess
    异常过滤、IsProcessorFeaturePresent、设置全局变量等.
    """
    # 此处仅做结构性等价, 不实际修改进程异常过滤器/全局变量
    return None


def main_proc():
    """主处理入口 (等价原程序 jmp 0x7FF7810D115C 后的 Python 解释器
    主循环逻辑).

    原程序完整逻辑位于 python39.dll, 未在此处逆向. 此处按顶层行为
    返回 0.
    """
    # TODO: 此处应接原程序的 Python 解释器主循环逻辑
    return EXIT_SUCCESS


def main():
    # 运行时初始化
    runtime_init()

    # 进入主程序
    ret = main_proc()

    _ExitProcess(ret)
    return ret


if __name__ == "__main__":
    sys.exit(main())
