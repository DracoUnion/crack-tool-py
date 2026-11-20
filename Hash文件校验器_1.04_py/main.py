#!/usr/bin/env python3
"""
Hash文件校验器 1.04 — Python CLI rewrite

原程序：Hash文件校验器_1.04/Hash文件校验器_1.04.exe (by Robin Keir, keir.net, 2013)
支持 CRC32、MD5、SHA1 三种文件哈希算法。

纯 Python 实现（hashlib/zlib），无第三方依赖，输出格式与原程序一致。
"""

import argparse
import hashlib
import os
import sys
import zlib

CHUNK = 65536


def compute_hashes(path, algos):
    """返回 {algo: hexdigest} 以及文件大小。"""
    size = os.path.getsize(path)
    # 同时初始化所需哈希对象
    hashers = {}
    if "crc32" in algos:
        hashers["crc32"] = 0
    if "md5" in algos:
        hashers["md5"] = hashlib.md5()
    if "sha1" in algos:
        hashers["sha1"] = hashlib.sha1()

    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK)
            if not chunk:
                break
            if "crc32" in hashers:
                hashers["crc32"] = zlib.crc32(chunk, hashers["crc32"])
            if "md5" in hashers:
                hashers["md5"].update(chunk)
            if "sha1" in hashers:
                hashers["sha1"].update(chunk)

    result = {}
    if "crc32" in hashers:
        result["crc32"] = "%08X" % (hashers["crc32"] & 0xFFFFFFFF)
    if "md5" in hashers:
        result["md5"] = hashers["md5"].hexdigest()
    if "sha1" in hashers:
        result["sha1"] = hashers["sha1"].hexdigest()
    return size, result


def fmt_result(path, size, result, algos):
    lines = []
    lines.append(os.path.basename(path))
    lines.append("  Size : %d bytes" % size)
    if "crc32" in algos:
        lines.append("  CRC32: %s" % result["crc32"])
    if "md5" in algos:
        lines.append("  MD5  : %s" % result["md5"])
    if "sha1" in algos:
        lines.append("  SHA1 : %s" % result["sha1"])
    return "\n".join(lines)


def cmd_hash(args):
    algos = [a.strip().lower() for a in args.algo.split(",")]
    valid = {"crc32", "md5", "sha1", "all"}
    for a in algos:
        if a not in valid:
            print("Error: unknown algorithm '%s' (valid: crc32, md5, sha1, all)" % a, file=sys.stderr)
            return 1
    if "all" in algos:
        algos = ["crc32", "md5", "sha1"]

    out_lines = []
    for path in args.file:
        if not os.path.isfile(path):
            print("Error: file not found: %s" % path, file=sys.stderr)
            continue
        try:
            size, result = compute_hashes(path, algos)
        except OSError as e:
            print("Error: cannot read %s: %s" % (path, e), file=sys.stderr)
            continue
        out_lines.append(fmt_result(path, size, result, algos))
        out_lines.append("")

    output = "\n".join(out_lines).rstrip() + "\n"
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output)
        except OSError as e:
            print("Error: cannot write %s: %s" % (args.output, e), file=sys.stderr)
            return 1
    else:
        sys.stdout.write(output)
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="main.py",
        description="Hash文件校验器 1.04 — Python CLI 文件哈希校验工具（CRC32/MD5/SHA1）。",
    )
    p.add_argument("file", nargs="+", help="要计算哈希的文件路径（可多个）")
    p.add_argument("--algo", default="all",
                   help="指定算法：crc32 / md5 / sha1 / all（逗号分隔，默认 all）")
    p.add_argument("--output", help="将结果写入文本文件（每块一个文件）")
    p.set_defaults(func=cmd_hash)
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
