#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
E-Code Explorer.exe  ->  Python CLI 重写版

来源目录: D:\Program Files\crack-tool-dasm\ECodeExplorer_0.86_正式版
目标文件: E-Code Explorer.exe (32-bit PE, 易语言编译)
MD5: bd4dd82cd0c5708aba06b63eff9d4e33

逆向依据 (IDA Pro 反汇编, 基址 0x400000):
    入口点: 0x401000 (start -> sub_40100B)
    .text 只有 0x1000 字节, 其余逻辑在 .ecode (0x403000-0x58f000)
    里的易语言字节码, 由 krnln.fnr/fne 运行时解释执行, 本 CLI 只复现
    EXE 本身的启动/加载逻辑.

主逻辑 (汇编 -> 语义):
    sub_40100B (0x40100B):
      0x4010A3 子函数 sub_4011EC: GetModuleFileNameA 取自身路径,
                                     截断到目录(保留末尾 \) -> String1[260]
      0x4010B4: lstrcat(String1, "krnln.fnr")              ; 0x401019
      0x4010BA: LoadLibraryA(String1)
      若成功 -> 直接去取 GetNewSock
      若失败 -> 走注册表回退路径:
      0x4010E7: RegOpenKeyExA(HKEY_CURRENT_USER,
                              "Software\FlySky\E\Install", ; 0x401038
                              ..., KEY_READ)
      0x401119: RegQueryValueExA(hkey, "Path", ..., String1, &cbData) ; 0x401052
      0x401120: RegCloseKey(hkey)
      0x40113F-0x401145: 确保 String1 以 '\' 结尾(不足则补)
      0x401156: lstrcat(String1, "krnln.fne")              ; 0x401023
      0x40115C: LoadLibraryA(String1)
    LABEL_7 (0x401165):
      hLibModule = 加载到的句柄
      0x401171: GetProcAddress(hLibModule, "GetNewSock")   ; 0x40102D
      若 GetNewSock != NULL:
        0x40117F: v5 = GetNewSock(1000)  ; __stdcall int(int), 返回函数指针
        若 v5 != NULL:
          0x401191: v5(0x403000)         ; __cdecl void(int), .ecode 基址
          0x401195: ExitProcess(0)
      0x4011A0: FreeLibrary(hLibModule)  ; 仅在 GetNewSock/为空或 v5 为空时到达
    失败分支 (0x4011B3):
      MessageBoxA(0, "Not found the kernel library or the kernel library is invalid!",
                  "Error", 0x10)        ; 0x401057 / 0x401096, MB_ICONEXCLAMATION
      return -1

字符串常量:
    0x401019 = "krnln.fnr"
    0x401023 = "krnln.fne"
    0x40102D = "GetNewSock"
    0x401038 = "Software\\FlySky\\E\\Install"
    0x401052 = "Path"                 (注册表值名)
    0x401057 = "Not found the kernel library or the kernel library is invalid!"
    0x401096 = "Error"                (MessageBox 标题)
    0x403000 = .ecode 节基址 (传给 v5 的参数 4206592)

本程序为纯 Python CLI, main.py 为唯一入口, 可直接用 `python main.py` 运行.
缺少 krnln.fnr/fne 运行时时, 行为与原程序一致: 弹出错误 MessageBox 并退出码 -1.
"""

import ctypes
import ctypes.wintypes
import sys

# ===================== Windows API 封装 =====================
kernel32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32
advapi32 = ctypes.windll.advapi32

# 常量 (与原程序一致)
HKEY_CURRENT_USER = 0x80000001
REG_KEY = r"Software\FlySky\E\Install"
REG_VALUE = "Path"
REG_ACCESS = 0x20019  # KEY_READ (原程序 push KEY_READ)

DLL_NAME1 = "krnln.fnr"   # 0x401019
DLL_NAME2 = "krnln.fne"   # 0x401023
PROC_NAME = "GetNewSock"  # 0x40102D
GETNEWSOCK_ARG = 1000     # 0x3E8 (原程序 push 3E8)
ECODE_BASE = 0x403000     # 4206592, .ecode 节基址 (原程序 push 4206592)

MB_TITLE = "Error"                                             # 0x401096
MB_MSG = ("Not found the kernel library or the kernel library is invalid!")  # 0x401057
MB_ICON = 0x10                                                 # MB_ICONEXCLAMATION

# API 签名
_GetModuleFileNameA = kernel32.GetModuleFileNameA
_GetModuleFileNameA.argtypes = [ctypes.wintypes.HANDLE,
                                ctypes.c_char_p,
                                ctypes.wintypes.DWORD]
_GetModuleFileNameA.restype = ctypes.wintypes.DWORD

_LoadLibraryA = kernel32.LoadLibraryA
_LoadLibraryA.argtypes = [ctypes.c_char_p]
_LoadLibraryA.restype = ctypes.wintypes.HMODULE

_GetProcAddress = kernel32.GetProcAddress
_GetProcAddress.argtypes = [ctypes.wintypes.HMODULE, ctypes.c_char_p]
_GetProcAddress.restype = ctypes.c_void_p

_FreeLibrary = kernel32.FreeLibrary
_FreeLibrary.argtypes = [ctypes.wintypes.HMODULE]
_FreeLibrary.restype = ctypes.wintypes.BOOL

_ExitProcess = kernel32.ExitProcess
_ExitProcess.argtypes = [ctypes.wintypes.UINT]
_ExitProcess.restype = None

_RegOpenKeyExA = advapi32.RegOpenKeyExA
_RegOpenKeyExA.argtypes = [ctypes.wintypes.HKEY, ctypes.c_char_p,
                           ctypes.wintypes.DWORD, ctypes.wintypes.DWORD,
                           ctypes.POINTER(ctypes.wintypes.HKEY)]
_RegOpenKeyExA.restype = ctypes.wintypes.LONG

_RegQueryValueExA = advapi32.RegQueryValueExA
_RegQueryValueExA.argtypes = [ctypes.wintypes.HKEY, ctypes.c_char_p,
                              ctypes.POINTER(ctypes.wintypes.DWORD),
                              ctypes.POINTER(ctypes.wintypes.DWORD),
                              ctypes.c_char_p,
                              ctypes.POINTER(ctypes.wintypes.DWORD)]
_RegQueryValueExA.restype = ctypes.wintypes.LONG

_RegCloseKey = advapi32.RegCloseKey
_RegCloseKey.argtypes = [ctypes.wintypes.HKEY]
_RegCloseKey.restype = ctypes.wintypes.LONG

_MessageBoxA = user32.MessageBoxA
_MessageBoxA.argtypes = [ctypes.wintypes.HWND, ctypes.c_char_p,
                         ctypes.c_char_p, ctypes.wintypes.UINT]
_MessageBoxA.restype = ctypes.c_int


def get_self_dir():
    """取得当前程序所在目录, 并保留末尾反斜杠 (对应原程序 0x4011EC / sub_4011EC)."""
    buf = ctypes.create_string_buffer(260)
    n = _GetModuleFileNameA(None, buf, ctypes.sizeof(buf))
    if n == 0:
        # 兜底: 退回到 sys.argv[0]
        return os_dirname() + "\\"
    path = buf.value.decode("mbcs")
    # 截断到最后一个 '\'
    idx = path.rfind("\\")
    if idx != -1:
        return path[:idx + 1]
    return path + "\\"


def os_dirname():
    import os
    return os.path.dirname(os.path.abspath(__file__)) + "\\"


def ensure_trailing_backslash(path):
    """若路径不以 \\ 结尾, 则将最后一个字符改为 \\ (对应原程序 0x40113F-0x401145)."""
    if not path.endswith("\\"):
        path = path[:-1] + "\\" if path else "\\"
    return path


def load_library(path):
    """封装 LoadLibraryA, 成功返回 HMODULE, 失败返回 None."""
    handle = _LoadLibraryA(path.encode("mbcs"))
    if not handle:
        return None
    return handle


def get_proc_address(module, name):
    """封装 GetProcAddress, 成功返回函数地址(int), 失败返回 None."""
    addr = _GetProcAddress(module, name.encode("mbcs"))
    if not addr:
        return None
    return int(addr)


def call_stdcall_int_int(addr, arg):
    """按 __stdcall 调约定调用 int f(int), 返回 int."""
    func = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int)(addr)
    return func(arg)


def call_cdecl_void_int(addr, arg):
    """按 __cdecl 调约定调用 void f(int)."""
    func = ctypes.CFUNCTYPE(None, ctypes.c_int)(addr)
    func(arg)


def show_error():
    """失败时弹出 MessageBox (对应原程序 0x4011B3 分支), 并返回 -1."""
    _MessageBoxA(0, MB_MSG.encode("mbcs"), MB_TITLE.encode("mbcs"), MB_ICON)
    return -1


def main():
    # 1. 取自身目录 (GetModuleFileNameA 封装, sub_4011EC, 0x4010A3)
    base_dir = get_self_dir()

    # 2. 优先加载 <base_dir>\krnln.fnr (0x401019)
    path1 = base_dir + DLL_NAME1
    hmod = load_library(path1)

    if hmod is None:
        # 3. 加载失败 -> 从注册表读取 "Path", 构造 <Path>\krnln.fne (0x401023)
        hkey = ctypes.wintypes.HKEY()
        rc = _RegOpenKeyExA(HKEY_CURRENT_USER,
                            REG_KEY.encode("mbcs"),
                            0,
                            REG_ACCESS,
                            ctypes.byref(hkey))
        if rc != 0:
            return show_error()

        try:
            buf = ctypes.create_string_buffer(260)
            buf_size = ctypes.wintypes.DWORD(ctypes.sizeof(buf))
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

        # 4. 确保以 \\ 结尾, 再拼接 "krnln.fne" (0x40113F-0x401156)
        reg_path = ensure_trailing_backslash(buf.value.decode("mbcs"))
        path2 = reg_path + DLL_NAME2

        # 5. 加载 DLL
        hmod = load_library(path2)
        if hmod is None:
            return show_error()

    # LABEL_7 (0x401165): 取 GetNewSock
    proc_addr = get_proc_address(hmod, PROC_NAME)
    if proc_addr is not None:
        # 0x40117F: v5 = GetNewSock(1000) (__stdcall int(int)), 返回函数指针
        v5 = call_stdcall_int_int(proc_addr, GETNEWSOCK_ARG)
        if v5 != 0:
            # 0x401191: v5(0x403000) (__cdecl void(int)), .ecode 基址
            call_cdecl_void_int(v5, ECODE_BASE)
            # 0x401195: ExitProcess(0)
            _ExitProcess(0)
            return 0

    # GetNewSock 为空 或 v5 为空: 释放句柄后报错 (0x4011A0)
    _FreeLibrary(hmod)
    return show_error()


if __name__ == "__main__":
    sys.exit(main())
