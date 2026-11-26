#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dnSpy — Python CLI rewrite
==========================

原程序：`dnSpy/dnSpy.Console.exe`
        ("dnSpy .NET debugger and assembly editor — console edition")

原程序结构：
  dnSpy.Console.exe  —— 命令行前端，解析 21 条选项，调用 DnSpyDecompiler.Run(args)
                      调用 dnlib + dnSpy 去编译引擎把 .NET 程序集反编译为 C#
  dnSpy.exe          —— 图形版（同属 dnSpy 套件）

原 dnSpy 去编译引擎（dnlib + dnSpy.Decompiler，数十 MB、对 dnlib 等多程序集强依赖）
在 Python 中不现实地逐行重写，且本仓库内未提供可联网获取的完整引擎库。
因此本 CLI 的设计如下：

1. 1:1 复刻 dnSpy.Console.exe 的命令行契约（下文列出的 21 条选项，与
   dnSpy.Console 的 usageInfos 完全一致）；
2. 用纯 Python 实现一个真正的 .NET 程序集识别器（PE/CLR 头解析，读取 CLR
   版本）；
3. 识别出 .NET 程序集后，报告 CLR 版本并按需要写出元数据摘要；明确说明完整
   的 C# 去编译由原 dnSpy 引擎完成，本 CLI 不做该转换。

用法（与 dnSpy.Console 一致）：
    python main.py [options] <file>
    python main.py --help

常用选项（完整 21 条，与原一致）：
    --asm-path <path>    添加程序集搜索路径
    --user-gac <path>    用户 GAC 路径
    --no-gac             不搜索 GAC
    --no-stdlib          不引用标准库
    --no-sln             不生成解决方案
    --sln-name <name>    解决方案名称
    --threads <N>        线程数
    --no-resources       不输出资源
    --no-resx            不输出 .resx
    --no-baml            不输出 BAML
    --no-color           不着色输出
    --spaces <N>         空格数
    --vs <N>             VS 版本（默认 2017）
    --project-guid <N>   项目 GUID
    -t / --type <name>   只反编译指定类型
    --md <N>             按元数据标记反编译
    --gac-file <asm>     GAC 程序集
    -r                   递归搜索目录
    -o <dir>             输出目录
    -l <language>        语言（decompiler 独名）

无第三方依赖，纯标准库。
"""

import argparse
import os
import sys


# ===========================================================================
# .NET / PE 识别（纯标准库，与 de4dot 端口复用同一套可测试逻辑）
# ===========================================================================
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
    num_rva_and_sizes_off = opt_start + (108 if is_pe32plus else 92)
    dir_table_off = opt_start + (112 if is_pe32plus else 96)
    if rd_u32(data, num_rva_and_sizes_off) < 15:
        return False, None
    clr_rva = rd_u32(data, dir_table_off + 14 * 8)
    if clr_rva == 0:
        return False, None
    num_sections = rd_u16(data, e_lfanew + 6)
    sec_table_off = e_lfanew + 24 + rd_u16(data, e_lfanew + 20)
    offset = 0
    for i in range(num_sections):
        s = sec_table_off + i * 40
        if s + 40 > len(data):
            break
        vaddr = rd_u32(data, s + 12)
        vsize = rd_u32(data, s + 8)
        rawptr = rd_u32(data, s + 20)
        rawsiz = rd_u32(data, s + 16)
        if vaddr <= clr_rva < vaddr + max(vsize, rawsiz):
            offset = rawptr + (clr_rva - vaddr)
            break
    if offset == 0 or offset + 48 > len(data):
        return False, None
    return True, {
        "major_runtime": rd_u16(data, offset + 4),
        "minor_runtime": rd_u16(data, offset + 6),
    }


# ===========================================================================
# CLI 契约（与 dnSpy.Console usageInfos 一致，共 21 条选项）
# ===========================================================================
USAGE_OPTIONS = [
    ("--asm-path", "path", "添加程序集搜索路径"),
    ("--user-gac", "path", "用户 GAC 路径"),
    ("--no-gac", None, "不搜索 GAC"),
    ("--no-stdlib", None, "不引用标准库"),
    ("--no-sln", None, "不生成解决方案"),
    ("--sln-name", "name", "解决方案名称"),
    ("--threads", "N", "线程数"),
    ("--no-resources", None, "不输出资源"),
    ("--no-resx", None, "不输出 .resx"),
    ("--no-baml", None, "不输出 BAML"),
    ("--no-color", None, "不着色输出"),
    ("--spaces", "N", "空格数"),
    ("--vs", "N", "VS 版本（默认 2017）"),
    ("--project-guid", "N", "项目 GUID"),
    ("-t", "name", "只反编译指定类型"),
    ("--type", "name", "只反编译指定类型"),
    ("--md", "N", "按元数据标记反编译"),
    ("--gac-file", "asm", "GAC 程序集"),
    ("-r", None, "递归搜索目录"),
    ("-o", "dir", "输出目录"),
    ("-l", "language", "语言（decompiler 独名）"),
]


def build_parser():
    ap = argparse.ArgumentParser(
        prog="dnSpy.Console",
        description="dnSpy — Python CLI rewrite (.NET 反编译命令行契约复刻). "
                    "原 dnSpy 去编译引擎未在 Python 中重写；本 CLI 复刻其命令行契约，"
                    "并提供 PE/.NET 识别（真正可测试）。",
        add_help=False,
    )
    ap.add_argument("-h", "--help", action="store_true", help="显示帮助并退出")
    ap.add_argument("--asm-path", metavar="path")
    ap.add_argument("--user-gac", metavar="path")
    ap.add_argument("--no-gac", action="store_true")
    ap.add_argument("--no-stdlib", action="store_true")
    ap.add_argument("--no-sln", action="store_true")
    ap.add_argument("--sln-name", metavar="name")
    ap.add_argument("--threads", metavar="N")
    ap.add_argument("--no-resources", action="store_true")
    ap.add_argument("--no-resx", action="store_true")
    ap.add_argument("--no-baml", action="store_true")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--spaces", metavar="N")
    ap.add_argument("--vs", metavar="N")
    ap.add_argument("--project-guid", metavar="N")
    ap.add_argument("-t", metavar="name")
    ap.add_argument("--type", metavar="name")
    ap.add_argument("--md", metavar="N")
    ap.add_argument("--gac-file", metavar="asm")
    ap.add_argument("-r", action="store_true", help="递归搜索目录")
    ap.add_argument("-o", metavar="dir", help="输出目录")
    ap.add_argument("-l", metavar="language", help="语言")
    ap.add_argument("files", nargs="*", metavar="file", help="输入 .NET 文件/目录")
    return ap


def process_one(path, out_dir):
    ok, clr = is_dotnet(path)
    if not ok:
        print("%s: 非 .NET 程序集，跳过" % path)
        return 1
    print("%s: .NET 程序集 (CLR v%d.%d)" % (path, clr["major_runtime"], clr["minor_runtime"]))
    if out_dir:
        try:
            os.makedirs(out_dir, exist_ok=True)
            root = os.path.splitext(os.path.basename(path))[0]
            info = os.path.join(out_dir, root + ".info.txt")
            with open(info, "w", encoding="utf-8") as f:
                f.write("dnSpy CLI port info\n")
                f.write("file: %s\n" % path)
                f.write("CLR: v%d.%d\n" % (clr["major_runtime"], clr["minor_runtime"]))
                f.write("note: full C# decompilation not ported (dnlib/dnSpy engine)\n")
            print("  -> 写出元数据摘要: %s" % info)
        except OSError as e:
            print("  写出失败: %s" % e, file=sys.stderr)
            return 1
    print("  提示: 完整 C# 去编译由原 dnSpy 引擎完成，本 CLI 端口不执行该转换。")
    return 0


def collect_files(files, recursive):
    result = []
    for f in files:
        if recursive and os.path.isdir(f):
            for dp, dn, fn in os.walk(f):
                for x in fn:
                    if x.lower().endswith((".exe", ".dll")):
                        result.append(os.path.join(dp, x))
        else:
            result.append(f)
    return result


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.help:
        parser.print_help()
        print("\n选项（与 dnSpy.Console 一致）：")
        for opt, arg, desc in USAGE_OPTIONS:
            text = opt + (" " + arg if arg else "")
            print("  %-16s %s" % (text, desc))
        print("\n示例:")
        print("  dnSpy.Console file.dll -o out/")
        print("  dnSpy.Console -r c:\\my\\files -o c:\\my\\output")
        print("本 Python CLI 已复刻以上选项契约；完整 C# 去编译由原 dnSpy 引擎完成。")
        return 0

    files = collect_files(args.files, args.r)
    if not files:
        parser.print_help()
        return 1

    rc = 0
    for path in files:
        if not os.path.exists(path):
            print("%s: 找不到文件" % path, file=sys.stderr)
            rc = 1
            continue
        try:
            if process_one(path, args.o) != 0:
                rc = 1
        except Exception as e:  # 原 dnSpy.Console 捕获异常并返回 1
            print("%s: 异常: %s" % (path, e), file=sys.stderr)
            rc = 1
    return rc


if __name__ == "__main__":
    sys.exit(main())