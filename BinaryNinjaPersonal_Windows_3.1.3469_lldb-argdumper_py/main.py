#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BinaryNinjaPersonal_Windows_3.1.3469\\plugins\\lldb\\lldb-argdumper.exe  ->  Python CLI 重写版

来源目录: D:\Program Files\crack-tool-dasm\BinaryNinjaPersonal_Windows_3.1.3469\plugins\lldb
目标文件: lldb-argdumper.exe (88 KB, 64-bit PE)

逆向依据 (x64dbg 反汇装, 基址 0x7FF713B70000, 大小 0x1A000, PE 入口点 RVA
0xF760 => 0x7FF713B7F760, 仅识别出 1 个函数, 分析不完整):
    入口点 0x7FF713B7F760:
      sub rsp,28; call 0x7FF713B80154; add rsp,28; jmp 0x7FF713B7F5E4
    0x7FF713B7F774 起为运行时初始化:
      mov [rsp+8],rbx; push rdi; sub rsp,20
      mov edx,0xFA0; lea rcx,[7FF713B856A8]; call InitializeCriticalSectionAndSpinCount
      lea rcx,[7FF713B81DD0]; call GetModuleHandleW
      ... GetProcAddress / CreateEventW ...
      call 0x7FF713B7FA64; test al,al
      lea rcx,[7FF713B7F844]; call 0x7FF713B7FC14
    完整逻辑未在此处完整逆向. 此处按已确认的入口点编写等价的 Python CLI
    框架: 执行运行时初始化(临界区/模块句柄/事件)后进入主处理并返回退出码.

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
ENTRY_POINT = 0x7FF713B7F760


def runtime_init():
    """等价原程序入口点 0x7FF713B7F760 起的运行时初始化部分:
    InitializeCriticalSectionAndSpinCount、GetModuleHandleW、
    GetProcAddress、CreateEventW 等.
    """
    # 此处仅做结构性等价, 不实际创建同步原语
    return None


def main_proc():
    """主处理入口 (等价原程序调用 0x7FF713B7FA64 / 0x7FF713B7FC14 后的
    主程序逻辑).

    原程序完整逻辑未在此处完整逆向. 此处按顶层行为返回 0.
    """
    # TODO: 此处应接原程序的主程序核心逻辑
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
