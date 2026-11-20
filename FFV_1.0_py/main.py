#!/usr/bin/env python3
"""
FFV v1.0 — Python CLI rewrite

原程序：FFV_1.0/FFV v1.0.exe (VB6, by yuanfang235, 2013)
文件头查看 / 文件类型识别工具。

显示文件名、大小、创建时间、修改时间，以及文件头的十六进制与
字符串表示；并根据内置文件头签名库（来自原程序随附的
“常见zip文件头.txt”及程序字符串）识别文件类型。

纯 Python 实现，无第三方依赖。
"""

import argparse
import binascii
import os
import sys
from datetime import datetime

# ---------------------------------------------------------------------------
# 内置文件头签名库（来源于原 FFV v1.0 程序及其随附参考文件）
# 每项：(扩展名列表, 签名字节, 描述)
# ---------------------------------------------------------------------------
SIGNATURES = [
    (["zip"], bytes.fromhex("504B0304"), "zip"),
    (["jar"], bytes.fromhex("504B0304"), "Java archive (zip-based)"),
    (["doc", "xls", "ppt"], bytes.fromhex("D0CF11E0A1B11AE1"), "Microsoft Office"),
    (["pdf"], bytes.fromhex("255044462D312E"), "Adobe Acrobat PDF"),
    (["png"], bytes.fromhex("89504E47"), "PNG image"),
    (["gif"], bytes.fromhex("47494638"), "GIF image"),
    (["bmp"], bytes.fromhex("424D"), "Windows / OS/2 BMP"),
    (["ico"], bytes.fromhex("00000100"), "Windows icon"),
    (["cur"], bytes.fromhex("00000200"), "Windows cursor"),
    (["tiff", "tif"], bytes.fromhex("49492A00"), "TIFF image"),
    (["jpg", "jpeg"], bytes.fromhex("FFD8FF"), "JPEG image"),
    (["psd"], bytes.fromhex("38425053"), "Adobe Photoshop"),
    (["rar"], bytes.fromhex("52617221"), "WinRAR archive"),
    (["cab"], bytes.fromhex("49536328"), "Microsoft CAB archive"),
    (["gz"], bytes.fromhex("1F8B08"), "GZIP archive"),
    (["avi"], bytes.fromhex("41564920"), "Microsoft Audio Video Interleave"),
    (["flv"], bytes.fromhex("464C5601"), "Flash video"),
    (["swf"], bytes.fromhex("435753"), "Shockwave Flash"),
    (["swf"], bytes.fromhex("465753"), "Shockwave Flash"),
    (["mp4"], bytes.fromhex("0000002066747970"), "MPEG-4 video"),
    (["mkv"], bytes.fromhex("1A45DFA3"), "Matroska video"),
    (["mov"], bytes.fromhex("6D6F6F76"), "QuickTime for Windows"),
    (["mpg"], bytes.fromhex("000001B3"), "MPEG video"),
    (["mpg"], bytes.fromhex("000001BA"), "MPEG video"),
    (["wav", "riff"], bytes.fromhex("52494646"), "Windows WAV/RIFF"),
    (["mid"], bytes.fromhex("4D546864"), "MIDI"),
    (["html"], bytes.fromhex("3C68746D6C3E"), "HTML"),
    (["xml"], bytes.fromhex("3C3F786D6C"), "XML"),
    (["rtf"], bytes.fromhex("7B5C727466"), "Rich Text"),
    (["chm"], bytes.fromhex("4954534603000000"), "HTML Help"),
    (["lnk"], bytes.fromhex("4C000000011402"), "Windows shortcut"),
    (["mdb"], bytes.fromhex("5374616E64617264204A"), "Microsoft Access"),
    (["pst"], bytes.fromhex("2142444E"), "Microsoft Outlook PST"),
    (["eml"], bytes.fromhex("44656C69766572792D646174653A"), "Outlook Express mail"),
    (["reg"], bytes.fromhex("5245474544495434"), "Windows registry file"),
    (["reg"], bytes.fromhex("FFFE570069006E00"), "Windows registry file (Unicode)"),
    (["pwl"], bytes.fromhex("E3828596"), "Windows 95/98 password list"),
    (["ram", "rm", "rmvb"], bytes.fromhex("2E524D46"), "RealAudio / RealMedia"),
    (["gho"], bytes.fromhex("FEEF0104"), "Norton Ghost image"),
    (["hlp"], bytes.fromhex("3F5F0300"), "Windows help"),
    (["obj"], bytes.fromhex("4C01"), "Object file"),
    (["wpd"], bytes.fromhex("FF575043"), "WordPerfect document"),
    (["cad"], bytes.fromhex("41433130"), "Softdek / Drafix CAD"),
]


def detect_type(head):
    """根据文件头字节匹配签名，返回 (扩展名, 描述) 或 None。"""
    for exts, sig, desc in SIGNATURES:
        if head.startswith(sig):
            return exts, desc
    return None


def fmt_hex(head, group=1):
    """将字节格式化为十六进制字符串，每 group 个字节一组。"""
    parts = []
    for i in range(0, len(head), group):
        parts.append("%02X" % head[i])
    return " ".join(parts)


def head_to_str(head):
    """文件头的可打印字符串表示；不可打印字符用 '.' 替代。"""
    out = []
    for b in head:
        if 32 <= b < 127:
            out.append(chr(b))
        else:
            out.append(".")
    return "".join(out)


def file_time(ts):
    """Unix epoch 时间戳转为可读字符串。"""
    try:
        return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return ""


def cmd_view(args):
    path = args.file
    if not os.path.isfile(path):
        print("Error: file not found: %s" % path, file=sys.stderr)
        return 1

    st = os.stat(path)
    size = st.st_size
    created = file_time(st.st_ctime)
    modified = file_time(st.st_mtime)

    n = max(1, args.hex_len)
    with open(path, "rb") as f:
        head = f.read(n)

    print("File     : %s" % os.path.basename(path))
    print("Path     : %s" % os.path.abspath(path))
    print("Size     : %d bytes" % size)
    print("Created  : %s" % created)
    print("Modified : %s" % modified)
    print()
    print("Head hex (%d bytes):" % len(head))
    print("  %s" % fmt_hex(head))
    print("Head str : %s" % head_to_str(head))
    print()

    hit = detect_type(head)
    if hit:
        exts, desc = hit
        print("Type     : %s  (%s)" % (", ".join(exts), desc))
    else:
        print("Type     : unknown (no matching signature)")
    return 0


def cmd_list(args):
    print("内置文件头签名 (共 %d 条)：" % len(SIGNATURES))
    print()
    for exts, sig, desc in SIGNATURES:
        print("  %-16s %-20s %s" % (", ".join(exts), sig.hex().upper(), desc))
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="main.py",
        description="FFV v1.0 — Python CLI 文件头查看 / 文件类型识别工具。",
    )
    p.add_argument("--list", action="store_true",
                   help="列出内置的所有文件头签名")
    p.add_argument("file", nargs="?", help="要查看的文件路径")
    p.add_argument("--hex-len", type=int, default=32,
                   help="显示文件头的十六进制字节数 (默认 32)")
    p.set_defaults(func=None)
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.list:
        return cmd_list(args)
    if not args.file:
        parser.print_help()
        return 1
    return cmd_view(args)


if __name__ == "__main__":
    sys.exit(main())
