#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DNiD 2.0.6.0 — Python CLI rewrite
=================================

原程序：DNiD_2.0.6.0/DNiD2.exe
        ("DNiD is a PE Identifier specifically targeting .NET compiled binaries.
         It has basically the same features as PEiD, only written in .NET")

原程序的核心是 clsScanner.Scan：读取文件字节，把每条保护签名（字节模式，
-1 表示通配符）从文件偏移 0 处顺序匹配，匹配到第一条就返回对应的保护厂商/名称，
否则返回 "Unknown or no protection!"。GUI 层仅负责拖放/显示，不影响判定逻辑。

注意：原程序用 Parallel.ForEach 并返回“最后匹配项”，因并发顺序不确定；
本 CLI 移植为确定性的“返回首匹配”（按 SignatureList.Add 的声明顺序）。

用法：
    python main.py <file1> [file2 ...]

输出：
    <文件名>: <保护识别结果>

示例：
    python main.py some_app.exe
    some_app.exe: ConfuserEx -> Ki

无第三方依赖，纯标准库。签名库来自 signatures.py（自动从 DNiD2.exe
反编译的 Signatures.SignaturesList 与 SignatureList.Add 调用顺序提取）。
"""

import argparse
import os
import sys

from signatures import SIGNATURES

# ---------------------------------------------------------------------------
# FindPattern: naive scan with -1 wildcards，从 start_offset 开始。
# 对应 clsScanner.FindPattern / SearchBytes。
# ---------------------------------------------------------------------------
def search_bytes(data, pattern, start_offset=0):
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


# ---------------------------------------------------------------------------
# clsScanner.Scan(byte[]): 顺序匹配所有签名，首匹配即返回，否则默认值。
# 内部所有条目 item2 均为 False，恒从偏移 0 开始；此处保留字段以便与源对齐。
# ---------------------------------------------------------------------------
def scan(data):
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


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="DNiD 2.0.6.0 — Python CLI rewrite. .NET 保护/加壳标识工具（类 PEiD）")
    ap.add_argument("files", nargs="+", metavar="FILE",
                    help="要识别的文件（可多个）")
    args = ap.parse_args(argv)

    results = []
    for path in args.files:
        if not os.path.isfile(path):
            results.append((path, "Error: file not found"))
            continue
        results.append((path, scan_file(path)))

    for path, result in results:
        print("%s: %s" % (os.path.basename(path), result))
    return 0


if __name__ == "__main__":
    sys.exit(main())