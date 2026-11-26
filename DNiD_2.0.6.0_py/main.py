#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DNiD 2.0.6.0 / mU.DCMA — Python CLI rewrite
===========================================

本目录包含两个原程序，统一由本 CLI 提供：

1) DNiD2.exe  — "DNiD is a PE Identifier specifically targeting .NET
   compiled binaries. It has basically the same features as PEiD, only
   written in .NET."（.NET 加壳/混淆标识工具，类 PEiD）
   核心 clsScanner.Scan：读文件字节，把每条保护签名（字节模式，-1 为通配符）
   从偏移 0 顺序匹配，命中第一条即返回名称，否则 "Unknown or no protection!"。

2) mU.DCMA.exe — "DNiD Context Menu Adder Tool"（给 DNiD 加右键菜单）
   在 HKCR\*\shell\Scan with DNiD 2\command 写入 "<目录>\\DNiD2.exe %1"。

用法：
    # 扫描（默认）
    python main.py scan <file1> [file2 ...]
    python main.py <file1> [file2 ...]            # 省略 scan 子命令亦可

    # 右键菜单（mU.DCMA）
    python main.py menu <DNiD目录> [--remove] [--dry-run] [--root hkcr|hkcu]

说明：
- 原 DNiD2 用 Parallel.ForEach 返回“最后匹配项”（并发顺序不定）；本 CLI 改为
  确定性的“按声明顺序返回首匹配”。所有内部签名 item2 均为 false（从偏移 0 匹配）。
- menu 默认写入 HKCR（与 mU.DCMA 一致，通常需要管理员权限）；--dry-run 只打印
  不写入；--root hkcu 可改写到 HKCU\Software\Classes（当前用户，便于安全测试）。

无第三方依赖，纯标准库。签名库来自 signatures.py（自动从 DNiD2.exe 反编译提取）。
"""

import argparse
import os
import sys

from signatures import SIGNATURES

# ===========================================================================
# 一、DNiD2 签名扫描
# ===========================================================================
def search_bytes(data, pattern, start_offset=0):
    """FindPattern: naive scan with -1 wildcards，从 start_offset 开始。"""
    n = len(data)
    m = len(pattern)
    if n == 0 or m == 0 or start_offset > n - m or m > n:
        return False
    wild = [p == -1 for p in pattern]
    i = start_offset
    last = n - m
    while i <= last:
        if wild[0] or data[i] == pattern[0]:
            ok = True
            j = 1
            while j < m:
                if not wild[j] and data[i + j] != pattern[j]:
                    ok = False
                    break
                j += 1
            if ok:
                return True
        i += 1
    return False


def scan(data):
    """clsScanner.Scan(byte[])：顺序匹配，首匹配即返回，否则默认值。"""
    for display, pattern, _use_ep in SIGNATURES:
        if search_bytes(data, pattern, 0):
            return display
    return "Unknown or no protection!"


def scan_file(path):
    try:
        with open(path, "rb") as f:
            return scan(f.read())
    except OSError as e:
        return "Error: %s" % e


def cmd_scan(paths):
    results = []
    for path in paths:
        if not os.path.isfile(path):
            results.append((path, "Error: file not found"))
            continue
        results.append((path, scan_file(path)))
    for path, result in results:
        print("%s: %s" % (os.path.basename(path), result))
    return 0


# ===========================================================================
# 二、mU.DCMA 右键菜单
# ===========================================================================
MENU_KEY = r"*\shell\Scan with DNiD 2"
MENU_CMD = r"*\shell\Scan with DNiD 2\command"


def cmd_menu(directory, remove=False, dry_run=False, root="hkcr"):
    import winreg
    base = winreg.HKEY_CLASSES_ROOT if root == "hkcr" else winreg.HKEY_CURRENT_USER
    prefix = "" if root == "hkcr" else r"Software\Classes"
    full_cmd_key = (prefix + "\\" + MENU_CMD) if prefix else MENU_CMD
    full_menu_key = (prefix + "\\" + MENU_KEY) if prefix else MENU_KEY

    command_value = os.path.join(directory, "DNiD2.exe") + " %1"

    if dry_run:
        print("[dry-run] root=%s" % root)
        print("[dry-run] %s%s = %r" % (prefix + "\\" if prefix else "", MENU_CMD, command_value))
        return 0

    try:
        if remove:
            try:
                winreg.DeleteKey(base, full_cmd_key)
                print("[remove] deleted %s" % full_cmd_key)
            except FileNotFoundError:
                print("[remove] not present: %s" % full_cmd_key)
            try:
                winreg.DeleteKey(base, full_menu_key)
                print("[remove] deleted %s" % full_menu_key)
            except FileNotFoundError:
                pass
            print("Removed.")
            return 0

        # 对应 Registry.ClassesRoot.CreateSubKey(...\command) + SetValue("", ...)
        with winreg.CreateKey(base, full_cmd_key) as k:
            winreg.SetValueEx(k, "", 0, winreg.REG_SZ, command_value)
        print("All done!  (%s%s -> %r)" % (prefix + "\\" if prefix else "", MENU_CMD, command_value))
        return 0
    except OSError as e:
        print("Something went wrong.... :/  (%s)" % e, file=sys.stderr)
        return 1


# ===========================================================================
# 入口
# ===========================================================================
def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    ap = argparse.ArgumentParser(
        description="DNiD 2.0.6.0 / mU.DCMA — Python CLI rewrite.")
    sub = ap.add_subparsers(dest="cmd")

    p_scan = sub.add_parser("scan", help="识别 .NET 加壳/混淆（DNiD2）")
    p_scan.add_argument("files", nargs="+", metavar="FILE")

    p_menu = sub.add_parser("menu", help="添加/删除右键菜单（mU.DCMA）")
    p_menu.add_argument("directory", help="DNiD 所在目录（用于拼 DNiD2.exe 路径）")
    p_menu.add_argument("--remove", action="store_true", help="删除菜单项")
    p_menu.add_argument("--dry-run", action="store_true", help="只打印不写入")
    p_menu.add_argument("--root", choices=["hkcr", "hkcu"], default="hkcr",
                        help="写根（默认 hkcr，与 mU.DCMA 一致；hkcu 便于测试）")

    # 兼容：省略子命令时按 scan 处理
    if not argv or argv[0] not in ("scan", "menu", "-h", "--help"):
        args = ap.parse_args(["scan"] + argv)
        return cmd_scan(args.files)

    args = ap.parse_args(argv)
    if args.cmd == "scan":
        return cmd_scan(args.files)
    if args.cmd == "menu":
        return cmd_menu(args.directory, remove=args.remove,
                        dry_run=args.dry_run, root=args.root)
    ap.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())