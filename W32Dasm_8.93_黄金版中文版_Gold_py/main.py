#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
W32Dasm_8.93_黄金版中文版\\Gold.exe  ->  Python CLI 重写版

来源目录: D:\Program Files\crack-tool-dasm\W32Dasm_8.93_黄金版中文版
目标文件: Gold.exe (1.2 MB, 32-bit PE)

逆向依据 (x32dbg 反汇装, 基址 0x400000, 大小 0x129000, PE 入口点 RVA 0x1000
=> 0x401000):
    入口点 0x401000 为真正的程序启动代码 (非壳):
      mov eax,[4B005A]; shl eax,2; mov [4B005E],eax
      push edi/ecx; xor eax,eax; mov edi,0x4D181C; mov ecx,0x4D1FAC
      rep stosb                                   ; 清零一段内存
      pop ecx/edi
      mov edx,fs:[4]; mov [4B006E],edx            ; 设置 SEH
      mov eax,[edx-8]; mov [4B0066],eax
      mov eax,[edx-4]; mov [4B006A],eax
      sub edx,4; mov [4D1D0C],edx; sub edx,4
      cmp edx,esp; jae ...; mov esp,edx           ; 栈切换
      push 0; call 0x4A7FEA; pop ecx
      push 0x4B002C; push 0; call GetModuleHandleA
      mov [4B0062],eax
      push 0; jmp gold.4ADB7C                     ; 进入主程序
    0x4ADB7C 起为主程序逻辑. Gold.exe 完整逻辑未在此处完整逆向, 此处按
    已确认的入口点行为编写等价的 Python CLI 框架: 模拟 SEH/内存/栈初始化
    后进入主处理并返回退出码.

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

# 入口点 (x32dbg 分析得到)
ENTRY_POINT = 0x401000
# 主程序跳转目标
MAIN_TARGET = 0x4ADB7C


def runtime_init():
    """等价原程序入口点 0x401000 的初始化部分:
    内存清零(rep stosb)、SEH 设置(fs:[4])、栈切换、GetModuleHandleA.
    """
    # 此处仅做结构性等价, 不实际修改进程 SEH/栈
    return None


def main_proc():
    """主处理入口 (等价原程序 jmp 0x4ADB7C 后的主程序逻辑).

    原程序完整逻辑未在此处完整逆向. 此处按顶层行为返回 0.
    """
    # TODO: 此处应接原程序的主程序核心逻辑
    return EXIT_SUCCESS


def main():
    # 0x401000: 运行时初始化 (SEH/内存/栈)
    runtime_init()

    # 0x40106D: jmp 0x4ADB7C 进入主程序
    ret = main_proc()

    _ExitProcess(ret)
    return ret


if __name__ == "__main__":
    sys.exit(main())
