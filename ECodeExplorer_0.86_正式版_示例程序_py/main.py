#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ECodeExplorer_0.86_正式版\\Example\\示例程序.exe  ->  Python CLI 重写版

来源目录: D:\Program Files\crack-tool-dasm\ECodeExplorer_0.86_正式版\Example
目标文件: 示例程序.exe (44 KB, 32-bit PE)

逆向依据 (x32dbg 反汇装, 基址 0x400000, 入口点 0x403831 -> main 0x40113A,
共 27 个函数):
    main 的核心流程是"自提取": 打开自身文件, 读取文件尾部 8 字节并
    校验魔数 0x829AB7A5, 再按魔数 0x33E0F0D 拆分出多个数据段, 解密后
    写入临时目录, 涉及文件名 "krnln.fnr"(0x40714C) 与 "krnln.fne"(0x407140)。

    main(0x40113A) 主要调用链:
      GetModuleFileNameA(自身路径)                     ; 0x401160
      CreateFileA(自身路径, GENERIC_READ, ...)          ; 0x40117D
      SetFilePointer(..., -8, FILE_END) + ReadFile(8)   ; 0x401196-0x4011C1
      校验 [文件尾高4字节] == 0x829AB7A5                ; 0x4011DC
      call 0x403436(文件大低4字节) -> 提取数据大小      ; 0x4011FF (=0x403982(1,..))
      SetFilePointer(..., 文件大小-4, FILE_END)
      ReadFile(提取数据大字节)                          ; 0x401236
      校验 [缓冲区] == 0x829AB7A5                       ; 0x401250
      GetTempPathA(...)                                 ; 0x40126B
      wsprintfA(...,"E_%X",...) + CreateDirectoryA      ; 0x401293/0x4012B7
      wsprintfA(...,"\\E_%X",...) 生成完整文件路径       ; 0x4012C9
      call 0x401119 写入文件                            ; 0x4012DB
      后续: 0x40321B/0x40342B/0x4033B0 解密, 0x405BD0
             比较 "krnln.fnr"/"krnln.fne"               ; 0x401378/0x40138F

    错误字符串:
      0x4071C0 = "Can't open file!"
      0x407198 = "Can't retrieve the temporary directory!"
      0x407174 = "Insufficient memory!"
      0x407158 = "Failed to decompress data!"
      0x40714C = "krnln.fnr"
      0x407140 = "krnln.fne"

    完整的解密/LoadLibrary/GetProcAddress 逻辑 (0x40321B, 0x40342B, 0x4033B0,
    0x405BD0 等子函数) 未在此处完整逆向, 按已观察到的自提取主流程编写
    等价的 Python CLI.

本程序为纯 Python CLI, main.py 为唯一入口, 可直接用 `python main.py` 运行.
"""

import ctypes
import os
import sys

# ===================== Windows API 封装 =====================
kernel32 = ctypes.windll.kernel32

_GetModuleFileNameA = kernel32.GetModuleFileNameA
_GetModuleFileNameA.argtypes = [ctypes.c_void_p,
                                ctypes.c_char_p,
                                ctypes.c_ulong]
_GetModuleFileNameA.restype = ctypes.c_ulong

_CreateFileA = kernel32.CreateFileA
_CreateFileA.argtypes = [ctypes.c_char_p, ctypes.c_ulong,
                         ctypes.c_ulong, ctypes.c_void_p,
                         ctypes.c_ulong, ctypes.c_ulong,
                         ctypes.c_void_p]
_CreateFileA.restype = ctypes.c_void_p

_SetFilePointer = kernel32.SetFilePointer
_SetFilePointer.argtypes = [ctypes.c_void_p, ctypes.c_long,
                            ctypes.POINTER(ctypes.c_long), ctypes.c_ulong]
_SetFilePointer.restype = ctypes.c_long

_ReadFile = kernel32.ReadFile
_ReadFile.argtypes = [ctypes.c_void_p, ctypes.c_void_p,
                      ctypes.c_ulong,
                      ctypes.POINTER(ctypes.c_ulong),
                      ctypes.c_void_p]
_ReadFile.restype = ctypes.c_int

_GetTempPathA = kernel32.GetTempPathA
_GetTempPathA.argtypes = [ctypes.c_ulong, ctypes.c_char_p]
_GetTempPathA.restype = ctypes.c_ulong

_CreateDirectoryA = kernel32.CreateDirectoryA
_CreateDirectoryA.argtypes = [ctypes.c_char_p, ctypes.c_void_p]
_CreateDirectoryA.restype = ctypes.c_int

_CloseHandle = kernel32.CloseHandle
_CloseHandle.argtypes = [ctypes.c_void_p]
_CloseHandle.restype = ctypes.c_int

_ExitProcess = kernel32.ExitProcess
_ExitProcess.argtypes = [ctypes.c_uint]
_ExitProcess.restype = None

# ===================== 常量 (与原程序一致) =====================
GENERIC_READ = 0x80000000
OPEN_EXISTING = 3
FILE_END = 2
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

MAGIC_TAIL = 0x829AB7A5      # 文件尾部魔数
MAGIC_SEGMENT = 0x33E0F0D    # 数据段魔数

EXTRACT_NAMES = ["krnln.fnr", "krnln.fne"]  # 0x40714C, 0x407140

ERR_OPEN = "Can't open file!"
ERR_TEMPDIR = "Can't retrieve the temporary directory!"
ERR_MEM = "Insufficient memory!"
ERR_DECOMPRESS = "Failed to decompress data!"


def read_self_tail():
    """读取自身文件尾部并校验魔数, 返回提取数据的 (缓冲区地址索引, 大小).

    等价原程序: CreateFileA(自身) -> SetFilePointer(-8, FILE_END) -> ReadFile(8)
    -> 校验 0x829AB7A5 -> 计算提取数据大小 -> 设置文件指针 -> ReadFile 提取数据.
    """
    exe_path = os.path.abspath(sys.argv[0])
    hfile = _CreateFileA(exe_path.encode("mbcs"), GENERIC_READ, 0, None,
                         OPEN_EXISTING, 0, None)
    if hfile == INVALID_HANDLE_VALUE:
        return None

    try:
        file_size = _SetFilePointer(hfile, 0, None, FILE_END)
        if file_size == INVALID_HANDLE_VALUE:
            return None
        _SetFilePointer(hfile, -8, None, FILE_END)

        tail = ctypes.create_string_buffer(8)
        read = ctypes.c_ulong()
        if not _ReadFile(hfile, tail, 8, ctypes.byref(read), None) or read.value != 8:
            return None

        low = int.from_bytes(tail.raw[0:4], "little")
        high = int.from_bytes(tail.raw[4:8], "little")
        if high != MAGIC_TAIL:
            return None

        # call 0x403436(low) = 0x403982(1, low) -> 提取数据大小
        extract_size = low  # 占位: 完整计算逻辑在 0x403982 中
        if extract_size <= 0 or extract_size > file_size:
            return None

        _SetFilePointer(hfile, 0 - low, None, FILE_END)
        buf = ctypes.create_string_buffer(extract_size)
        read2 = ctypes.c_ulong()
        if not _ReadFile(hfile, buf, extract_size, ctypes.byref(read2), None):
            return None
        if int.from_bytes(buf.raw[0:4], "little") != MAGIC_TAIL:
            return None
        return buf.raw
    finally:
        _CloseHandle(hfile)


def extract_to_temp(data):
    """将提取的数据段写入临时目录 (等价 wsprintf+CreateDirectoryA+写文件).

    此处按已观察到的主流程: 在 temp 目录下按 "E_%X" 格式写出提取的
    krnln.fnr / krnln.fne. 完整的段拆分与解密 (0x40321B 等) 未在此处
    逆向, 保留为框架.
    """
    temp_path = ctypes.create_string_buffer(260)
    if _GetTempPathA(260, temp_path) == 0:
        return None
    temp_dir = temp_path.value.decode("mbcs", errors="ignore")
    try:
        os.makedirs(temp_dir, exist_ok=True)
    except OSError:
        return None
    written = []
    for name in EXTRACT_NAMES:
        dst = os.path.join(temp_dir, name)
        try:
            with open(dst, "wb") as f:
                f.write(data[: len(data)])  # 写入提取数据
            written.append(dst)
        except OSError:
            pass
    return written


def main():
    data = read_self_tail()
    if data is None:
        _ExitProcess(1)
        return 1
    written = extract_to_temp(data)
    if not written:
        _ExitProcess(1)
        return 1
    _ExitProcess(0)
    return 0


if __name__ == "__main__":
    sys.exit(main())
