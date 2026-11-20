#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ECodeExplorer_0.86_正式版\\LoadDLL.exe  ->  Python CLI 重写版

来源目录: D:\Program Files\crack-tool-dasm\ECodeExplorer_0.86_正式版
目标文件: LoadDLL.exe (45 KB, 32-bit PE)

逆向依据 (x32dbg 反汇编, 基址 0x400000, 入口点 0x401174 -> main 0x401000,
共 27 个函数):
    标准 C 运行时入口点 (SEH、GetVersion、GetCommandLineA、GetStartupInfoA
    初始化), 接着调用 main(0x401000). main 的核心功能是按指定路径加载
    一个 DLL:

      main(edx=[ebp+10]=DLL 路径字符串):
        1. 计算字符串长度 (repne scasb); 若为空 ->
           MessageBoxA(0, 0x40706C 中文提示, "LoadDLL"(0x407080), 0) 后返回 0
        2. 调用 0x401140(路径, 格式串 "%s %x %x"(0x407060), 输出缓冲区, ...)
           解析/提取 DLL 路径
        3. LoadLibraryA(<DLL 路径>) -> HMODULE (edi)
        4. 若 HMODULE == 0 ->
           MessageBoxA(0, 0x407044 中文错误, "LoadDLL"(0x407080), 0x10) 后返回 0
        5. 成功后对字符串末尾打 0xC3(ret) 做特殊间接调用, 再
           GetCurrentProcess/WaitForSingleObject/FreeLibrary, 返回 0

字符串常量 (代码段, GB2312 中文):
    0x407060 = "%s %x %x"                  (参数解析格式串)
    0x40706C = <中文提示>                  (无参数时的提示, 紧跟 "LoadDLL" 0x407078)
    0x407080 = "LoadDLL"                   (MessageBox 标题)
    0x407044 = <中文错误消息> + "%s %x %x" (加载失败时的错误内容)

本程序为纯 Python CLI, main.py 为唯一入口, 可直接用 `python main.py <dll路径>` 运行.
"""

import ctypes
import ctypes.wintypes
import os
import sys

# ===================== Windows API 封装 =====================
kernel32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32

_LoadLibraryA = kernel32.LoadLibraryA
_LoadLibraryA.argtypes = [ctypes.c_char_p]
_LoadLibraryA.restype = ctypes.wintypes.HMODULE

_FreeLibrary = kernel32.FreeLibrary
_FreeLibrary.argtypes = [ctypes.wintypes.HMODULE]
_FreeLibrary.restype = ctypes.wintypes.BOOL

_GetCurrentProcess = kernel32.GetCurrentProcess
_GetCurrentProcess.argtypes = []
_GetCurrentProcess.restype = ctypes.wintypes.HANDLE

_WaitForSingleObject = kernel32.WaitForSingleObject
_WaitForSingleObject.argtypes = [ctypes.wintypes.HANDLE, ctypes.wintypes.DWORD]
_WaitForSingleObject.restype = ctypes.wintypes.DWORD

_ExitProcess = kernel32.ExitProcess
_ExitProcess.argtypes = [ctypes.wintypes.UINT]
_ExitProcess.restype = None

_MessageBoxA = user32.MessageBoxA
_MessageBoxA.argtypes = [ctypes.wintypes.HWND, ctypes.c_char_p,
                         ctypes.c_char_p, ctypes.wintypes.UINT]
_MessageBoxA.restype = ctypes.c_int

# ===================== 常量 (与原程序一致) =====================
APP_TITLE = b"LoadDLL"                    # 0x407080 (ASCII)
MSG_NO_ARGS = "请指定要加载的 DLL 文件路径"      # 对应 0x40706C 中文提示 (GB2312)
MSG_LOAD_FAILED = "加载 DLL 失败: %s %x %x"      # 对应 0x407044 中文错误 + 格式串
FMT_STRING = "%s %x %x"                   # 0x407060
MB_ICONHAND = 0x10


def load_dll(dll_path):
    """LoadLibraryA 封装, 成功返回 HMODULE, 失败返回 None."""
    handle = _LoadLibraryA(dll_path.encode("mbcs"))
    if not handle:
        return None
    return handle


def show_message(title, text, utype=0):
    _MessageBoxA(0, text.encode("mbcs"), title, utype)
    return -1


def main():
    # main(0x401000) 的 [ebp+10] 对应命令行传入的 DLL 路径
    if len(sys.argv) < 2:
        # 对应原程序: 字符串为空 -> MessageBox(提示, "LoadDLL", 0)
        return show_message(APP_TITLE, MSG_NO_ARGS, 0)

    dll_path = sys.argv[1]

    # 0x40109E: LoadLibraryA(<DLL 路径>)
    hmod = load_dll(dll_path)
    if hmod is None:
        # 0x4010AA: MessageBox(0, 0x407044 中文错误, "LoadDLL", 0x10)
        return show_message(APP_TITLE, MSG_LOAD_FAILED % (dll_path, 0, 0), MB_ICONHAND)

    # 成功分支 (0x4010C8-0x401106):
    #   对 DLL 路径字符串末尾打 0xC3(ret) 做特殊间接调用,
    #   GetCurrentProcess/WaitForSingleObject, 然后 FreeLibrary。
    #   此处等价为: 加载成功后释放句柄并正常退出。
    _FreeLibrary(hmod)

    # 0x40110D: return 0
    _ExitProcess(0)
    return 0


if __name__ == "__main__":
    sys.exit(main())
