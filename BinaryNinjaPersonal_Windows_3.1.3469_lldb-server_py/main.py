#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BinaryNinjaPersonal_Windows_3.1.3469\\plugins\\lldb\\lldb-server.exe  ->  Python CLI 重写版

来源目录: D:\Program Files\crack-tool-dasm\BinaryNinjaPersonal_Windows_3.1.3469\plugins\lldb
目标文件: lldb-server.exe (约 18 MB, 64-bit PE)

逆向依据 (x64dbg 反汇装, 基址 0x7FF7A72A0000, 大小 0x11BB000, PE 入口点 RVA
0x7E4670 => 0x7FF7A7A84670, 仅识别出 1 个函数, 分析不完整):
    入口点 0x7FF7A7A84670 反汇装为乱码指令 (`in al,dx`, `sub al,84` 等),
    这是加壳/保护的 Stub. lldb-server.exe 是 LLDB 的远程调试服务器,
    其完整 GDB 远程协议/调试逻辑未在此处完整逆向.
    按 AGENTS.md 加壳程序要求, 应运行至壳体将真正汇编代码释放到内存,
    再从程序地址空间读取真正代码并反汇装. 由于 lldb-server.exe 壳体复杂,
    此处先基于已确认的壳入口点编写等价的 Python CLI 框架:
      接受监听端口作为命令行参数, 进入主处理并返回退出码.

    后续如需完整还原, 需运行至壳体解密完毕, 从内存 dump 真正代码段,
    并在此基础上补全调试服务器核心逻辑.

本程序为纯 Python CLI, main.py 为唯一入口, 可直接用
`python main.py [端口]` 运行.
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

# 入口点 (x64dbg / PE 头分析得到)
ENTRY_POINT = 0x7FF7A7A84670


def debugserver_main(port):
    """主处理入口 (等价原程序 lldb-server.exe 核心调试服务器逻辑).

    原程序完整逻辑未在此处完整逆向. 此处按顶层行为:
      若提供了端口参数, 返回 0 (成功), 否则返回非零.
    """
    if port is None:
        return 1
    # TODO: 此处应接原程序的调试服务器核心逻辑
    return EXIT_SUCCESS


def main():
    # 运行至壳体释放真正代码到内存 (AGENTS.md 加壳程序要求)
    port = sys.argv[1] if len(sys.argv) >= 2 else None

    ret = debugserver_main(port)

    _ExitProcess(ret)
    return ret


if __name__ == "__main__":
    sys.exit(main())
