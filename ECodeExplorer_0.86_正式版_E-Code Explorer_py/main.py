#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ECodeExplorer_0.86_正式版\\E-Code Explorer.exe  ->  Python CLI 重写版

来源目录: D:\Program Files\crack-tool-dasm\ECodeExplorer_0.86_正式版
目标文件: E-Code Explorer.exe (1.6 MB, 32-bit PE)

逆向依据 (x32dbg 反汇装, 基址 0x400000, 入口点 0x401000, 共 458 个函数):
    入口点 0x401000 的主逻辑与同目录 Example\示例程序_带花指令.exe
    (已单独逆向为 ECodeExplorer_0.86_正式版_py) 完全一致:

      GetModuleFileNameA 封装(0x4011EC) -> 取自身目录
      lstrcat(dir, "krnln.fnr")          ; 0x401019
      LoadLibraryA(dir + "krnln.fnr")
      成功 -> GetProcAddress(hmod, "GetNewSock")(0x40102D)
             call GetNewSock(1000)       ; 0x40107F
             EIP 修正后再次 call         ; 0x401185-0x401191
             FreeLibrary -> ExitProcess(0)
      失败 -> RegOpenKeyExA(HKEY_CURRENT_USER,
                            "Software\FlySky\E\Install", 0x401038)
             RegQueryValueExA(...,"Path"...)   ; 0x401052
             lstrcat(buf, "krnln.fne")        ; 0x401023
             LoadLibraryA(buf)
             失败 -> MessageBoxA(0, "Not found the kernel library...",
                                 "Error", 10)  ; 0x401057, 0x401096

    0x403xxx 处的若干函数为未被调用的花指令/干扰代码, 不影响主逻辑.

字符串常量:
    0x401019 = "krnln.fnr"
    0x401023 = "krnln.fne"
    0x40102D = "GetNewSock"
    0x401038 = "Software\\FlySky\\E\\Install"
    0x401052 = "Path"                   (注册表值名)
    0x401096 = "Error"                  (MessageBox 标题)
    0x401057 = "Not found the kernel library or the kernel library"  (MessageBox 内容)

本程序为纯 Python CLI, main.py 为唯一入口, 可直接用 `python main.py` 运行.
"""

import ctypes
import ctypes.wintypes
import os
import sys

# ===================== Windows API 封装 =====================
kernel32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32
advapi32 = ctypes.windll.advapi32

# 常量 (与原程序一致)
HKEY_CURRENT_USER = 0x80000001
REG_KEY = r"Software\FlySky\E\Install"
REG_VALUE = "Path"
REG_ACCESS = 0x20019  # KEY_ALL_ACCESS (原程序 push 20019)

DLL_NAME1 = "krnln.fnr"   # 0x401019
DLL_NAME2 = "krnln.fne"   # 0x401023
PROC_NAME = "GetNewSock"  # 0x40102D
CALL_ARG = 0x3E8          # 1000 (原程序 push 3E8)

MB_TITLE = "Error"                     # 0x401096
MB_MSG = ("Not found the kernel library or the kernel library")  # 0x401057
MB_ICON = 10                           # 原程序 push 10 作为 uType

_GetModuleFileNameA = kernel32.GetModuleFileNameA
_GetModuleFileNameA.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_ulong]
_GetModuleFileNameA.restype = ctypes.c_ulong

_LoadLibraryA = kernel32.LoadLibraryA
_LoadLibraryA.argtypes = [ctypes.c_char_p]
_LoadLibraryA.restype = ctypes.c_void_p

_GetProcAddress = kernel32.GetProcAddress
_GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
_GetProcAddress.restype = ctypes.c_void_p

_FreeLibrary = kernel32.FreeLibrary
_FreeLibrary.argtypes = [ctypes.c_void_p]
_FreeLibrary.restype = ctypes.c_int

_ExitProcess = kernel32.ExitProcess
_ExitProcess.argtypes = [ctypes.c_uint]
_ExitProcess.restype = None

_RegOpenKeyExA = advapi32.RegOpenKeyExA
_RegOpenKeyExA.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_ulong,
                           ctypes.c_ulong, ctypes.POINTER(ctypes.c_void_p)]
_RegOpenKeyExA.restype = ctypes.c_long

_RegQueryValueExA = advapi32.RegQueryValueExA
_RegQueryValueExA.argtypes = [ctypes.c_void_p, ctypes.c_char_p,
                              ctypes.POINTER(ctypes.c_ulong),
                              ctypes.POINTER(ctypes.c_ulong),
                              ctypes.c_char_p,
                              ctypes.POINTER(ctypes.c_ulong)]
_RegQueryValueExA.restype = ctypes.c_long

_RegCloseKey = advapi32.RegCloseKey
_RegCloseKey.argtypes = [ctypes.c_void_p]
_RegCloseKey.restype = ctypes.c_long

_MessageBoxA = user32.MessageBoxA
_MessageBoxA.argtypes = [ctypes.c_void_p, ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint]
_MessageBoxA.restype = ctypes.c_int


def get_self_dir():
    """取得当前程序所在目录, 并保留末尾反斜杠 (对应原程序 0x4011EC 截断到目录)."""
    exe_path = os.path.abspath(sys.argv[0])
    return os.path.dirname(exe_path) + "\\"


def ensure_trailing_backslash(path):
    """若路径不以 \\ 结尾, 则补上 (对应原程序 0x401140-0x401145)."""
    if not path.endswith("\\"):
        path += "\\"
    return path


def load_library(path):
    """封装 LoadLibraryA, 成功返回 HMODULE, 失败返回 None."""
    handle = _LoadLibraryA(path.encode("mbcs"))
    if not handle:
        return None
    return handle


def get_proc_address(module, name):
    """封装 GetProcAddress, 成功返回函数地址, 失败返回 None."""
    addr = _GetProcAddress(module, name.encode("mbcs"))
    if not addr:
        return None
    return addr


def call_function(addr, arg):
    """按 C 调用约定调用地址为 addr 的函数, 参数为 arg, 返回 int."""
    func = ctypes.CFUNCTYPE(ctypes.c_int)(addr)
    return func(arg)


def show_error():
    """失败时弹出 MessageBox (对应原程序 0x4011A5 分支), 并返回 -1."""
    _MessageBoxA(0, MB_MSG.encode("mbcs"), MB_TITLE.encode("mbcs"), MB_ICON)
    return -1


def main():
    # 1. 取自身目录 (GetModuleFileNameA 封装, 0x4011EC)
    base_dir = get_self_dir()

    # 2. 优先加载 <base_dir>\krnln.fnr (0x401019)
    path1 = base_dir + DLL_NAME1
    hmod = load_library(path1)

    if hmod is None:
        # 3. 加载失败 -> 从注册表读取 "Path", 构造 <Path>\krnln.fne (0x401023)
        hkey = ctypes.c_void_p()
        rc = _RegOpenKeyExA(HKEY_CURRENT_USER,
                            REG_KEY.encode("mbcs"),
                            0,
                            REG_ACCESS,
                            ctypes.byref(hkey))
        if rc != 0:
            return show_error()

        try:
            buf = ctypes.create_string_buffer(260)
            buf_size = ctypes.c_ulong(ctypes.sizeof(buf))
            rc = _RegQueryValueExA(hkey,
                                   REG_VALUE.encode("mbcs"),
                                   None,
                                   None,
                                   buf,
                                   ctypes.byref(buf_size))
        finally:
            _RegCloseKey(hkey)

        if rc != 0:
            return show_error()

        reg_path = ensure_trailing_backslash(buf.value.decode("mbcs"))
        path2 = reg_path + DLL_NAME2

        hmod = load_library(path2)
        if hmod is None:
            return show_error()

    # 6. GetProcAddress(hmod, "GetNewSock") (0x40102D)
    proc_addr = get_proc_address(hmod, PROC_NAME)
    if proc_addr is None:
        _FreeLibrary(hmod)
        return show_error()

    # 7. call GetNewSock(1000) (0x40117F)
    result = call_function(proc_addr, CALL_ARG)
    if not result:
        _FreeLibrary(hmod)
        return show_error()

    # 8. EIP 修正后再次 call (0x401185-0x401191)
    call_function(proc_addr, CALL_ARG)

    # 9. FreeLibrary 并正常退出 (0x40119A-0x401195)
    _FreeLibrary(hmod)
    _ExitProcess(0)
    return 0


if __name__ == "__main__":
    sys.exit(main())
