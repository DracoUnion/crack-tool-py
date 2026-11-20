#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Yogda_1.0.564\\uninst.exe  ->  Python CLI 重写版

来源目录: D:\Program Files\crack-tool-dasm\Yogda_1.0.564
目标文件: uninst.exe (50 KB, 32-bit PE, NSIS 生成的卸载程序)

逆向依据 (x32dbg 反汇编, 基址 0x400000, 入口点 0x4030FA, 共 31 个函数):
    本程序是 NSIS 安装器生成的卸载程序, 其具体卸载目标(文件列表/注册表项)
    嵌在 NSIS 数据块中, 需解析 NSIS 二进制格式才能得知; 静态反汇编只能还原
    其可观察的顶层行为: 命令行参数解析、临时目录处理、卸载主流程入口、
    清理流程、NSIS 错误提示.

主逻辑 (汇编 -> 语义):
    0x4030FA 入口点:
      InitCommonControls()                         ; 0x403119
      SetErrorMode(0x8001)                         ; 0x40311F
      OleInitialize()                              ; 0x40312B
      call 0x405D2E -> 存 [42EB64]                 ; 0x403138
      SHGetFileInfoA(..., 0x428F98, 160)           ; 0x40314E (缓冲区全零)
      子函数 0x405A0C 处理字符串                   ; 0x403163
      GetCommandLineA() -> 0x434000 缓冲区         ; 0x403168
      命令行解析循环:
        首字符 '"' -> 标记引号模式
        遇到 '/' 参数:
          "S"   (0x53) -> esi |= 2   (静默标记)
          "NCRC" (dword 0x4352434E) -> esi |= 4
          "/D=" (dword 0x3D442F20 @ eax-2) -> 分支 0x40321D 处理安装目录
      GetTempPathA(400, 0x435400)                  ; 0x403239
      call 0x4030C6                                ; 0x40323F
        非零 -> 0x403268 删除 [435000] 文件
        零   -> GetWindowsDirectoryA + "\\Temp" -> 再次 call 0x4030C6
      0x403268: DeleteFileA([435000])              ; 删除卸载相关文件
      call 0x402C22                                ; 0x403274
      若 [42EB7C] != 0: 解析 /D= 目录, lstrcat 拼接路径
      call 0x403555                                ; 卸载主逻辑 -> 存 [esp+18]
      call 0x40347B                                ; 清理
      OleUninitialize()                            ; 0x4032EB
      若 [esp+10] != 0: MessageBox + ExitProcess(2)

NSIS 错误字符串 (代码段):
    0x409140 = "~nsu.tmp"
    0x40914C = "\\Temp"
    0x409154 = "NSIS Error"
    0x409160 = "Error writing temporary file. Make sure your temp folder is valid"

本程序为纯 Python CLI, main.py 为唯一入口, 可直接用 `python main.py` 运行.
"""

import ctypes
import ctypes.wintypes
import os
import sys

# ===================== Windows API 封装 =====================
kernel32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32
ole32 = ctypes.windll.ole32
shell32 = ctypes.windll.shell32
user32_dll = ctypes.windll.user32

_GetCommandLineA = kernel32.GetCommandLineA
_GetCommandLineA.argtypes = []
_GetCommandLineA.restype = ctypes.c_char_p

_GetModuleHandleA = kernel32.GetModuleHandleA
_GetModuleHandleA.argtypes = [ctypes.c_char_p]
_GetModuleHandleA.restype = ctypes.wintypes.HMODULE

_GetTempPathA = kernel32.GetTempPathA
_GetTempPathA.argtypes = [ctypes.wintypes.DWORD, ctypes.c_char_p]
_GetTempPathA.restype = ctypes.wintypes.DWORD

_GetWindowsDirectoryA = kernel32.GetWindowsDirectoryA
_GetWindowsDirectoryA.argtypes = [ctypes.c_char_p, ctypes.wintypes.UINT]
_GetWindowsDirectoryA.restype = ctypes.wintypes.UINT

_DeleteFileA = kernel32.DeleteFileA
_DeleteFileA.argtypes = [ctypes.c_char_p]
_DeleteFileA.restype = ctypes.wintypes.BOOL

_CreateDirectoryA = kernel32.CreateDirectoryA
_CreateDirectoryA.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
_CreateDirectoryA.restype = ctypes.wintypes.BOOL

_SetCurrentDirectoryA = kernel32.SetCurrentDirectoryA
_SetCurrentDirectoryA.argtypes = [ctypes.c_char_p]
_SetCurrentDirectoryA.restype = ctypes.wintypes.BOOL

_CopyFileA = kernel32.CopyFileA
_CopyFileA.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.wintypes.BOOL]
_CopyFileA.restype = ctypes.wintypes.BOOL

_ExitProcess = kernel32.ExitProcess
_ExitProcess.argtypes = [ctypes.wintypes.UINT]
_ExitProcess.restype = None

_OleInitialize = ole32.OleInitialize
_OleInitialize.argtypes = [ctypes.c_void_p]
_OleInitialize.restype = ctypes.c_long

_OleUninitialize = ole32.OleUninitialize
_OleUninitialize.argtypes = []
_OleUninitialize.restype = None

_SHGetFileInfoA = shell32.SHGetFileInfoA
_SHGetFileInfoA.argtypes = [ctypes.c_char_p, ctypes.wintypes.DWORD,
                            ctypes.c_void_p, ctypes.wintypes.UINT, ctypes.c_uint]
_SHGetFileInfoA.restype = ctypes.wintypes.DWORD

_MessageBoxA = user32_dll.MessageBoxA
_MessageBoxA.argtypes = [ctypes.wintypes.HWND, ctypes.c_char_p,
                         ctypes.c_char_p, ctypes.wintypes.UINT]
_MessageBoxA.restype = ctypes.c_int

# ===================== 常量 (与原程序一致) =====================
SET_ERROR_MODE = 0x8001

TMP_SUFFIX = b"~nsu.tmp"          # 0x409140
TEMP_SUFFIX = b"\\Temp"           # 0x40914C
NSIS_ERROR_TITLE = b"NSIS Error"  # 0x409154
NSIS_ERROR_MSG = (b"Error writing temporary file. Make sure your temp folder "
                  b"is valid")                              # 0x409160

# 命令行参数标记
FLAG_SILENT = 0x2   # /S
FLAG_NCRC = 0x4     # /NCRC

# 卸载主逻辑返回码含义(估算)
UNINST_SUCCESS = 0


def parse_command_line(cmdline: bytes):
    """解析 NSIS 卸载器命令行(对应 0x40316E-0x40322E).

    返回 (flags, install_dir):
      flags: bit0 未用, bit1 = 静默(/S), bit2 = /NCRC
      install_dir: /D= 指定的安装目录(若有)
    """
    flags = 0
    install_dir = None
    if not cmdline:
        return flags, install_dir

    # 将 bytes 按 ASCII 逐字节处理(原程序按 cl 字节比较)
    i = 0
    n = len(cmdline)
    in_quote = False
    while i < n:
        ch = cmdline[i]
        if ch == 0x22:  # '"'
            in_quote = not in_quote
            i += 1
            continue
        if ch == 0x20:  # ' '
            i += 1
            continue
        if ch == 0x2F:  # '/' 参数开始
            i += 1
            if i >= n:
                break
            # 单字符参数
            if cmdline[i] == 0x53:  # 'S' -> 静默
                flags |= FLAG_SILENT
                i += 1
                continue
            # 多字符参数 NCRC
            if i + 3 < n and cmdline[i:i + 4] == b"NCRC":
                flags |= FLAG_NCRC
                i += 4
                continue
            # /D= 安装目录
            if i + 2 < n and cmdline[i:i + 3] == b"/D=":
                i += 3
                start = i
                while i < n and cmdline[i] not in (0x20, 0x22):
                    i += 1
                install_dir = cmdline[start:i].decode("mbcs", errors="ignore")
                continue
            # 其他未知参数跳过
            while i < n and cmdline[i] not in (0x20, 0x22):
                i += 1
            continue
        i += 1
    return flags, install_dir


def get_temp_path():
    """GetTempPathA(400, buf) -> 临时目录字符串."""
    buf = ctypes.create_string_buffer(400)
    _GetTempPathA(400, buf)
    return buf.value.decode("mbcs", errors="ignore")


def get_windows_dir():
    """GetWindowsDirectoryA -> Windows 目录字符串."""
    buf = ctypes.create_string_buffer(260)
    _GetWindowsDirectoryA(buf, 260)
    return buf.value.decode("mbcs", errors="ignore")


def show_nsis_error():
    """弹出 NSIS 错误 MessageBox(对应原程序错误提示字符串)."""
    _MessageBoxA(0, NSIS_ERROR_MSG, NSIS_ERROR_TITLE, 0x10)  # MB_ICONHAND
    return -1


def uninstall_main(silent: bool, install_dir: str | None):
    """卸载主逻辑(对应原程序 call 0x403555 及前后的文件/目录操作).

    由于具体卸载目标(文件/注册表)嵌在 NSIS 数据块中, 静态反汇编无法
    完整还原; 此处实现等价的顶层卸载框架:
      - 若指定 install_dir, 切换到该目录
      - 删除临时文件 ~nsu.tmp
      - 调用清理子流程(0x40347B 等价)
    返回 0 表示成功, 非零表示失败.
    """
    # 0x40322E: ebp = 0x435400 (GetTempPathA 结果)
    temp_path = get_temp_path()
    if not temp_path:
        return 1

    # 0x40323F: call 0x4030C6 (检查/创建临时卸载文件)
    # 此处等价于确认 temp 目录可用
    tmp_file = os.path.join(temp_path, TMP_SUFFIX.decode("mbcs", errors="ignore"))

    # 0x403268: DeleteFileA([435000]) -> 删除卸载相关文件
    try:
        if os.path.exists(tmp_file):
            os.remove(tmp_file)
    except OSError:
        pass

    # 0x403311-0x403336: 若有 /D= 目录, lstrcat 拼接后 CreateDirectory + SetCurrentDirectory
    if install_dir:
        try:
            if not os.path.isdir(install_dir):
                os.makedirs(install_dir, exist_ok=True)
            os.chdir(install_dir)
        except OSError:
            return 1

    # 0x403555: 卸载主逻辑(此处因缺乏 NSIS 数据块, 等价为无具体文件操作)
    # 0x40347B: 清理
    return UNINST_SUCCESS


def main():
    # 0x403119: InitCommonControls (无等价, 略)
    # 0x40311F: SetErrorMode(0x8001)
    ctypes.windll.kernel32.SetErrorMode(SET_ERROR_MODE)

    # 0x40312B: OleInitialize()
    _OleInitialize(None)

    try:
        # 0x403168: GetCommandLineA()
        cmdline = _GetCommandLineA()
        flags, install_dir = parse_command_line(cmdline)

        silent = bool(flags & FLAG_SILENT)

        # 0x403239: GetTempPathA -> 0x40323F call 0x4030C6
        # 若写临时文件失败 -> NSIS Error
        temp_path = get_temp_path()
        tmp_file = os.path.join(temp_path, TMP_SUFFIX.decode("mbcs", errors="ignore"))
        try:
            # 等价于原程序写临时文件检查
            with open(tmp_file, "wb") as f:
                f.write(b"")
        except OSError:
            return show_nsis_error()

        # 执行卸载主流程
        ret = uninstall_main(silent, install_dir)
        if ret != UNINST_SUCCESS:
            return show_nsis_error()

        # 0x4032EB: OleUninitialize()
    finally:
        _OleUninitialize()

    # 0x4032F1-0x40330B: 根据结果决定退出码
    _ExitProcess(0)
    return 0


if __name__ == "__main__":
    sys.exit(main())
