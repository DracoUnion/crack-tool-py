#!/usr/bin/env python3
"""
PasswareKit Forensic 32+64 便携版 — Python CLI rewrite

原程序：PasswareKitForensic 32+64 便携版 (商业密码恢复/取证软件，约 112 MB)
随附：kEy.txt（注册密钥）、网络流行资源字典.txt（常见弱密码字典）

本 CLI 按 PasswareKit 的核心用途（基于字典的密码恢复/破解）重写：
给定目标哈希与字典文件，逐行尝试多种哈希算法，找出匹配明文。
纯 Python 标准库实现，无第三方依赖。
"""

import argparse
import hashlib
import os
import sys

_HASH_ALGO = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}

KEY_INFO = """PasswareKit Forensic 32+64 便携版 — 注册信息（来自随附 kEy.txt）
------------------------------------------------------------
使用说明：
  1) Disconnect internet
  2) Disable auto updates
  Block program with your firewall

Key : ZNYLY-EG3PA-6JQ8Z-7J5SS-RMSM9-48CE2-N884D-TL4PK
"""


def read_lines(path):
    """读取字典文件，尝试 utf-8，失败则回退 gbk（兼容中文字典）。"""
    for enc in ("utf-8", "gbk", "latin-1"):
        try:
            with open(path, "r", encoding=enc) as f:
                return [line.rstrip("\r\n") for line in f]
        except (UnicodeDecodeError, LookupError):
            continue
    # 最后兜底：按字节读，逐行
    with open(path, "rb") as f:
        return [line.decode("latin-1").rstrip("\r\n") for line in f]


def cmd_crack(args):
    target = args.hash.strip().lower()
    if not os.path.isfile(args.dictfile):
        print("Error: dictionary file not found: %s" % args.dictfile, file=sys.stderr)
        return 1

    algos = [a.strip().lower() for a in args.algo.split(",")]
    valid = {"md5", "sha1", "sha256", "sha512", "all"}
    for a in algos:
        if a not in valid:
            print("Error: unknown algo '%s' (valid: md5, sha1, sha256, sha512, all)" % a, file=sys.stderr)
            return 1
    if "all" in algos:
        algos = ["md5", "sha1", "sha256", "sha512"]

    lines = read_lines(args.dictfile)
    total = 0
    found = None
    for word in lines:
        if word == "":
            continue
        total += 1
        wb = word.encode("utf-8")
        for algo in algos:
            if _HASH_ALGO[algo](wb).hexdigest() == target:
                found = (algo, word)
                break
        if found is not None:
            break

    if found is not None:
        algo, word = found
        print("Found: %s  (algo: %s)" % (word, algo))
        print("Tried %d candidates." % total)
        return 0
    print("Not found after %d candidates." % total, file=sys.stderr)
    return 1


def cmd_key(args):
    sys.stdout.write(KEY_INFO)
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="main.py",
        description="PasswareKit Forensic 32+64 — Python CLI 字典密码破解（纯 Python 标准库）。",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("crack", help="基于字典的密码破解")
    sp.add_argument("hash", help="目标哈希值")
    sp.add_argument("dictfile", help="字典文件路径（每行一个候选密码）")
    sp.add_argument("--algo", default="md5",
                    help="哈希算法：md5 / sha1 / sha256 / sha512 / all（默认 md5）")
    sp.set_defaults(func=cmd_crack)

    sp = sub.add_parser("key", help="显示随附 kEy.txt 中的注册密钥信息")
    sp.set_defaults(func=cmd_key)

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
