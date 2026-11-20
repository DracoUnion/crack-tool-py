#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VBDecompilerPro_11.5_CrackedBy_GautamGreat\\VB.Decompiler.Pro.v10.0.KEYGEN-FFF.exe  ->  Python CLI 重写版

来源目录: D:\Program Files\crack-tool-dasm\VBDecompilerPro_11.5_CrackedBy_GautamGreat
目标文件: VB.Decompiler.Pro.v10.0.KEYGEN-FFF.exe (约 1 MB, 32-bit PE)

逆向依据 (x32dbg 反汇装, 基址 0x400000, 大小 0x37D000, PE 入口点 RVA
0x77A858 => 0x477A858, 共 1 个被识别函数, 分析不完整):
    程序加载并运行后在 0x4DEDF9 处执行 `div eax` 触发除零异常 (第一次机会),
    这是典型的 keygen/注册机保护行为 (或故意的异常路由). 入口点
    0x477A858 为程序启动代码. keygen 的核心密钥生成算法未在此处
    完整逆向. 此处按已确认的入口点行为编写等价的 Python CLI 框架:
      接受用户名/注册名作为命令行参数, 进入密钥生成主处理并返回退出码.

    后续如需完整还原, 需在忽略除零异常的环境中运行至密钥生成
    逻辑, 并从内存中逆向完整的算法.

本程序为纯 Python CLI, main.py 为唯一入口, 可直接用
`python main.py <用户名>` 运行.
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
ENTRY_POINT = 0x477A858


def runtime_init():
    """等价原程序入口点 0x477A858 的初始化部分."""
    # 此处仅做结构性等价
    return None


def keygen_main(username):
    """主处理入口 (等价原程序 keygen 密钥生成逻辑).

    原程序完整密钥生成算法未在此处完整逆向. 此处按顶层行为:
      若提供了用户名, 返回 0 (成功), 否则返回非零.
    """
    if username is None or username == "":
        return 1
    # TODO: 此处应接原程序的密钥生成算法
    return EXIT_SUCCESS


def main():
    username = sys.argv[1] if len(sys.argv) >= 2 else None

    runtime_init()

    ret = keygen_main(username)

    _ExitProcess(ret)
    return ret


if __name__ == "__main__":
    sys.exit(main())
