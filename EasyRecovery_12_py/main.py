#!/usr/bin/env python3
"""
EasyRecovery 12 — Python CLI rewrite

原程序：EasyRecovery_12/EasyRecovery12.exe (EasyRecovery 12 NSIS 安装程序，UPX 压缩)

本 CLI 按 EasyRecovery 的"数据恢复/undelete"定位重写：对给定二进制文件
(如磁盘镜像、raw 镜像) 做文件头签名扫描与文件雕刻(carve)，把识别出的
文件片段提取出来。纯 Python 标准库实现，无第三方依赖。
"""

import argparse
import json
import os
import sys

# 文件头签名：(扩展名, 描述, 魔术字节)
SIGNATURES = [
    ("jpg",  "JPEG image",                   b"\xff\xd8\xff"),
    ("png",  "PNG image",                    b"\x89\x50\x4e\x47"),
    ("gif",  "GIF image",                    b"\x47\x49\x46\x38"),
    ("bmp",  "BMP image",                    b"\x42\x4d"),
    ("ico",  "Windows icon",                 b"\x00\x00\x01\x00"),
    ("pdf",  "PDF document",                 b"\x25\x50\x44\x46"),
    ("zip",  "ZIP archive",                  b"\x50\x4b\x03\x04"),
    ("gz",   "GZIP archive",                 b"\x1f\x8b"),
    ("rar",  "RAR archive",                  b"\x52\x61\x72\x21"),
    ("7z",   "7-Zip archive",                b"\x37\x7a\xbc\xaf\x27\x1c"),
    ("exe",  "PE executable (MZ)",           b"\x4d\x5a"),
    ("mid",  "MIDI audio",                   b"\x4d\x54\x68\x64"),
    ("riff", "RIFF/WAV/AVI",                 b"\x52\x49\x46\x46"),
    ("swf",  "Shockwave Flash",              b"\x43\x57\x53"),
    ("swf",  "Shockwave Flash",              b"\x46\x57\x53"),
    ("sqlite","SQLite database",             b"\x53\x51\x4c\x69\x74\x65"),
    ("elf",  "ELF executable",               b"\x7f\x45\x4c\x46"),
]


def scan(path):
    """扫描文件，返回 [(offset, ext, desc)] 列表，按 offset 排序。"""
    if not os.path.isfile(path):
        print("Error: file not found: %s" % path, file=sys.stderr)
        sys.exit(1)
    with open(path, "rb") as f:
        data = f.read()
    hits = []
    for ext, desc, sig in SIGNATURES:
        start = 0
        while True:
            idx = data.find(sig, start)
            if idx == -1:
                break
            hits.append((idx, ext, desc))
            start = idx + 1
    hits.sort(key=lambda x: x[0])
    return hits


def cmd_scan(args):
    hits = scan(args.file)
    if args.json:
        out = [{"offset": "0x%08X" % off, "offset_dec": off, "type": ext, "desc": desc}
               for off, ext, desc in hits]
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        if not hits:
            print("No known file signatures found.")
        for off, ext, desc in hits:
            print("0x%08X  %-12s %s" % (off, ext, desc))
    return 0


def cmd_carve(args):
    path = args.file
    outdir = args.outdir
    if not os.path.isfile(path):
        print("Error: file not found: %s" % path, file=sys.stderr)
        return 1
    if not os.path.isdir(outdir):
        try:
            os.makedirs(outdir)
        except OSError as e:
            print("Error: cannot create outdir %s: %s" % (outdir, e), file=sys.stderr)
            return 1
    hits = scan(path)
    count = 0
    n = max(1, args.chunk)
    with open(path, "rb") as f:
        data = f.read()
    for off, ext, desc in hits:
        piece = data[off:off + n]
        if not piece:
            continue
        name = "%s_%08X.%s" % (ext, off, ext)
        outpath = os.path.join(outdir, name)
        with open(outpath, "wb") as f:
            f.write(piece)
        count += 1
    print("Carved %d file fragment(s) into %s" % (count, outdir))
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="main.py",
        description="EasyRecovery 12 — Python CLI 二进制文件签名扫描与雕刻（数据恢复定位）。",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("scan", help="扫描二进制文件中的文件头签名")
    sp.add_argument("file", help="要扫描的二进制文件路径")
    sp.add_argument("--json", action="store_true", help="以 JSON 输出")
    sp.set_defaults(func=cmd_scan)

    sp = sub.add_parser("carve", help="扫描并把签名处开始的 N 字节提取为独立文件")
    sp.add_argument("file", help="要扫描的二进制文件路径")
    sp.add_argument("outdir", help="输出目录")
    sp.add_argument("--chunk", type=int, default=4096,
                    help="每个片段提取的字节数 (默认 4096)")
    sp.set_defaults(func=cmd_carve)

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
