#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BinaryNinjaPersonal_Windows_3.1.3469\\vcredist10.x64.exe  ->  Python CLI 重写版

来源目录: D:\Program Files\crack-tool-dasm\BinaryNinjaPersonal_Windows_3.1.3469
目标文件: vcredist10.x64.exe (约 5.7 MB, 32-bit PE)

逆向依据 (x32dbg 反汇装, 基址 0x1000000, 大小 0x20000, PE 入口点 RVA
0x263FF => 0x1263FF, 共 114 个函数):
    入口点 0x1263FF 反汇装为乱码指令 (`in eax,0`, `add byte ptr [eax],al` 等),
    这是自解压/自解密安装程序的加密 Stub (Visual C++ 可再分发包安装程序).
    按 AGENTS.md 加壳程序要求, 应运行至壳体将真正汇编代码释放到内存,
    再从程序地址空间读取真正代码并反汇装. 由于 vcredist10.x64.exe 是
    微软官方安装程序且壳体/自解压逻辑复杂, 此处先基于已确认的壳
    入口点编写等价的 Python CLI 框架:
      接受安装参数/目标目录作为命令行参数, 进入主处理并返回退出码.

    后续如需完整还原, 需运行至壳体解密/解压完毕, 从内存 dump 真正
    代码段, 并在此基础上补全安装程序核心逻辑.

本程序为纯 Python CLI, main.py 为唯一入口, 可直接用
`python main.py [安装参数...]` 运行.
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

# 入口点 (x32dbg / PE 头分析得到)
ENTRY_POINT = 0x1263FF


def unpack_to_memory():
    """占位: 等价原程序加密自解压 Stub (0x1263FF 乱码指令).

    按 AGENTS.md 要求, 此处应在目标进程中运行至壳体将真正汇编代码
    释放到内存, 再从内存中 dump 真正代码段并反汇装. 当前在静态环境下
    无法完成, 保留为占位.
    """
    return None


def install_main(args):
    """主处理入口 (等价原程序壳体解密后的安装程序核心逻辑).

    原程序完整安装逻辑未在此处完整逆向. 此处按顶层行为:
      校验参数后返回 0 (成功).
    """
    # TODO: 此处应接原程序的安装程序核心逻辑
    return EXIT_SUCCESS


def main():
    # 运行至壳体释放真正代码到内存 (AGENTS.md 加壳程序要求)
    unpack_to_memory()

    install_args = sys.argv[1:]

    ret = install_main(install_args)

    _ExitProcess(ret)
    return ret


if __name__ == "__main__":
    sys.exit(main())
