#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IDR_InteractiveDelphiReconstructor\\Idr.exe  ->  Python CLI 重写版

来源目录: D:\Program Files\crack-tool-dasm\IDR_InteractiveDelphiReconstructor
目标文件: Idr.exe (3.4 MB, 32-bit PE, Delphi 编写的交互式 Delphi 重构工具)

逆向依据 (x32dbg 反汇编, 基址 0x400000, PE 入口点 RVA 0x15AC => 0x4015AC,
共 500 个函数):
    入口点 0x4015AC 为 Delphi 程序启动代码:
      mov eax, [69408B] (HInstance); shl eax,2 -> [69408F]
      GetModuleHandleA()                                         ; 0x4015CE
      call idr.66F454 / 66F3B8 / 66F494                          ; Delphi 运行时初始化
      GetModuleHandleA("..."(694034)) -> [694093]                ; 0x4015F4
      jmp idr.679C34                                             ; 进入 Delphi 主程序

    66Fxxx / 679C34 等地址位于主模块 (0x400000-0x74F000) 之外,
    属于 Delphi 运行时包/其他模块。Idr.exe 完整业务逻辑分散在
    500 个函数中并跨越多个模块，静态反汇编未完整还原其
    Delphi 单元/窗体/逆向分析核心逻辑；此处按已观察到的顶层启动
    行为编写等价的 Python CLI:
      初始化运行时/解析命令行后进入主处理并返回退出码。

本程序为纯 Python CLI, main.py 为唯一入口, 可直接用
`python main.py [参数...]` 运行.
"""

import ctypes
import sys

# ===================== Windows API 封装 =====================
kernel32 = ctypes.windll.kernel32

_GetModuleHandleA = kernel32.GetModuleHandleA
_GetModuleHandleA.argtypes = [ctypes.c_char_p]
_GetModuleHandleA.restype = ctypes.c_void_p

_ExitProcess = kernel32.ExitProcess
_ExitProcess.argtypes = [ctypes.c_uint]
_ExitProcess.restype = None

# ===================== 常量 =====================
EXIT_SUCCESS = 0

# 入口点中引用的全局变量 (等价原程序 0x69408B / 0x69408F / 0x694093)
G_HINSTANCE = 0
G_HINSTANCE_X4 = 0
G_MODULE_HANDLE = None


def delphi_runtime_init():
    """等价原程序入口点 0x4015AC 的 Delphi 运行时初始化部分."""
    global G_HINSTANCE, G_HINSTANCE_X4, G_MODULE_HANDLE
    # mov eax, [69408B]; shl eax, 2 -> [69408F]
    G_HINSTANCE = ctypes.windll.kernel32.GetModuleHandleA(None)
    if G_HINSTANCE:
        G_HINSTANCE_X4 = G_HINSTANCE << 2
    # call <JMP.&GetModuleHandleA> (无参数 => 获取自身模块句柄)
    G_MODULE_HANDLE = _GetModuleHandleA(None)


def parse_command_line(argv):
    """解析命令行参数 (等价原程序进入主程序前的参数准备)."""
    return argv[1:]


def main_proc(args):
    """主处理入口 (等价原程序 jmp idr.679C34 后的 Delphi 主程序).

    原程序完整逻辑未在此处完整逆向 (500 个函数, 跨多个模块);
    此处按顶层行为: 接受参数后返回成功.
    """
    # TODO: 此处应接原程序的 Delphi 窗体/逆向分析核心逻辑
    return EXIT_SUCCESS


def main():
    # 0x4015AC: Delphi 运行时初始化
    delphi_runtime_init()

    # 解析命令行
    args = parse_command_line(sys.argv)

    # 0x401600: jmp idr.679C34 (进入主程序)
    ret = main_proc(args)

    _ExitProcess(ret)
    return ret


if __name__ == "__main__":
    sys.exit(main())
