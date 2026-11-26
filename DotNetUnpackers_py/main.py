#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DotNetUnpackers (DePhe/DeSmart) — Python CLI rewrite
===============================

原程序：DotNetUnpackers/DePhe.exe, DeSmart.exe（托管解包/去混淆器）

DotNetUnpackers 集合含 DePhe、DeSmart 等 .NET 解包/去混淆器（托管）。

本 CLI 忠实复刻原程序的命令行契约（选项/参数/用法），并用纯 Python 实现真正
可测试的 .NET 程序集识别（PE/CLR 头解析）。原程序的核心引擎（DePhe/DeSmart 解包引擎）在
Python 中不现实地逐行重写，本 CLI 不做该转换，仅识别与报告；README 与 --help
均如实标注复刻程度。

用法：
    python main.py [options] <file...>
    python main.py --help

无第三方依赖，纯标准库。
"""

import argparse
import os
import sys


def rd_u16(b, o):
    return b[o] | (b[o + 1] << 8)


def rd_u32(b, o):
    return b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)


def is_dotnet(path):
    """若为 .NET 程序集返回 (True, clr_info)，否则 (False, None)。"""
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return False, None
    if len(data) < 0x40 or data[0:2] != b"MZ":
        return False, None
    e_lfanew = rd_u32(data, 60)
    if e_lfanew + 248 > len(data):
        return False, None
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return False, None
    opt_start = e_lfanew + 24
    magic = rd_u16(data, opt_start)
    is_pe32plus = (magic == 0x20B)
    if rd_u32(data, opt_start + (108 if is_pe32plus else 92)) < 15:
        return False, None
    clr_rva = rd_u32(data, opt_start + (112 if is_pe32plus else 96) + 14 * 8)
    if clr_rva == 0:
        return False, None
    num_sections = rd_u16(data, e_lfanew + 6)
    sec_table_off = e_lfanew + 24 + rd_u16(data, e_lfanew + 20)
    offset = 0
    for i in range(num_sections):
        s = sec_table_off + i * 40
        if s + 40 > len(data):
            break
        vaddr = rd_u32(data, s + 12); vsize = rd_u32(data, s + 8)
        rawptr = rd_u32(data, s + 20); rawsiz = rd_u32(data, s + 16)
        if vaddr <= clr_rva < vaddr + max(vsize, rawsiz):
            offset = rawptr + (clr_rva - vaddr); break
    if offset == 0 or offset + 48 > len(data):
        return False, None
    return True, {"major": rd_u16(data, offset + 4), "minor": rd_u16(data, offset + 6)}


# 命令行契约选项（与原程序一致）
USAGE_OPTIONS = [
    ('-o', 'dir', '输出目录'),
    ('-d', None, '仅检测'),
]


def build_parser():
    ap = argparse.ArgumentParser(
        prog="DotNetUnpack",
        description="DotNetUnpackers (DePhe/DeSmart) — Python CLI rewrite（命令行契约 + .NET 识别复刻）",
        add_help=False)
    ap.add_argument("-h", "--help", action="store_true", help="显示帮助并退出")
    ap.add_argument('-o', metavar='dir')
    ap.add_argument('-d', action="store_true")
    ap.add_argument("files", nargs="*", metavar="file", help="输入文件")
    return ap


def process_one(path):
    ok, clr = is_dotnet(path)
    if not ok:
        print("%s: 非 .NET 程序集（原生 PE/其它），跳过" % path)
        return 1
    print("%s: .NET 程序集 (CLR v%d.%d)" % (path, clr["major"], clr["minor"]))
    print("  提示: 完整功能由原引擎完成，本 CLI 端口不执行该转换。")
    return 0


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.help:
        parser.print_help()
        print("\n选项（与原程序一致）：")
        for opt, arg, desc in USAGE_OPTIONS:
            print("  %-18s %s" % (opt + (" " + arg if arg else ""), desc))
        print("\n本 Python CLI 已复刻以上选项契约；核心引擎未移植。")
        return 0
    if not args.files:
        parser.print_help()
        return 1
    rc = 0
    for path in args.files:
        if not os.path.exists(path):
            print("%s: 找不到文件" % path, file=sys.stderr); rc = 1; continue
        try:
            if process_one(path) != 0:
                rc = 1
        except Exception as e:
            print("%s: 异常: %s" % (path, e), file=sys.stderr); rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
