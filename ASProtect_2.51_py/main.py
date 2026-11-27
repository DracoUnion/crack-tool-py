#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ASProtect.exe (ASProtect 2.51 protector by ASPack Software) -> Python CLI

来源目录: D:\\Program Files\\crack-tool-packer\\ASProtect_2.51
真实主程序: ASProtect.exe 自身被加壳 (多节高熵 8.0, .adata 节, ImageBase 0x167000)。
            同目录: aspr_keys.bin(120B 加密注册库), Password.txt("Password: ASPR"),
            Examples / Keygen / "Keygen RES"。

逆向依据 (PE 结构 + 字符串 + 公开格式):
  ASProtect 保护后: 原节高熵化, 追加 .adata 节 (解压/反调试/VM 桩), 入口改到 .adata;
  水印 "ASProtect", ".adata", "ASPack Software", aspr_keys.bin 保存注册密钥库。
  注册: 用户名+序列号 -> 校验 -> 写入 aspr_keys.bin (加密)。

  本 Python 实现为 ASProtect 的识别 / 结构分析 / 注册库信封解析工具 (纯标准库):
    - identify: 节名(.adata)+水印+EP 高熵 -> 判定 ASProtect 加壳;
    - analyze : 逐节熵/权限/数据目录/入口/TLS;
    - keys    : 解析 aspr_keys.bin 信封 (长度/熵/头部), 不伪造密钥;
    - version : 版本/水印字符串。
  说明: ASProtect 的 VM/反调试保护引擎为机器码, 本工具不重写保护算法 (不可行),
  聚焦可逆向的识别与文件格式; 与原始 unpacker 类工具互补。
  main.py 为唯一入口。

用法:
  python main.py identify <PE> [--json]
  python main.py analyze  <PE> [--json]
  python main.py keys     <aspr_keys.bin> [--json]
  python main.py version  <PE>
"""
import argparse
import json
import math
import os
import struct
import sys
from collections import Counter
from dataclasses import dataclass, field
from typing import List, Optional

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
WATERMARKS = (b"ASProtect", b".adata", b"ASPack Software", b"aspr_keys")
ADAT = ".adata"


def ent(b):
    if not b: return 0.0
    c = Counter(b); n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


@dataclass
class Section:
    name: str; virtual_size: int; virtual_address: int
    raw_size: int; raw_address: int; characteristics: int
    entropy: float = 0.0


@dataclass
class PeFile:
    path: str; data: bytes; image_base: int = 0; entry_rva: int = 0
    size_of_image: int = 0; is64: bool = False; subsystem: int = 0
    timestamp: int = 0; sections: List[Section] = field(default_factory=list)
    data_dirs: dict = field(default_factory=dict)
    is_pe: bool = True; error: Optional[str] = None


def parse_pe(data, path):
    pe = PeFile(path, data)
    if len(data) < 0x40 or data[:2] != b"MZ":
        pe.is_pe = False; pe.error = "not MZ"; return pe
    e = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e:e + 4] != b"PE\0\0":
        pe.is_pe = False; pe.error = "no PE sig"; return pe
    fh = e + 4
    nsec = struct.unpack_from("<H", data, fh + 2)[0]
    pe.timestamp = struct.unpack_from("<I", data, fh + 4)[0]
    szopt = struct.unpack_from("<H", data, fh + 16)[0]; opt = fh + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x10B:
        pe.entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        pe.image_base = struct.unpack_from("<I", data, opt + 28)[0]
        pe.size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
        pe.subsystem = struct.unpack_from("<H", data, opt + 68)[0]; dd = opt + 96
    elif magic == 0x20B:
        pe.is64 = True
        pe.entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        pe.image_base = struct.unpack_from("<Q", data, opt + 24)[0]
        pe.size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
        pe.subsystem = struct.unpack_from("<H", data, opt + 68)[0]; dd = opt + 112
    else:
        pe.is_pe = False; pe.error = "bad opt magic"; return pe
    for idx, nm in [(1, "import"), (2, "resource"), (5, "reloc"), (9, "tls")]:
        rva, sz = struct.unpack_from("<II", data, dd + idx * 8)
        pe.data_dirs[nm] = (rva, sz)
    st = opt + szopt
    for i in range(nsec):
        o = st + i * 40
        nm = data[o:o + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        vs, va, rs, ra = struct.unpack_from("<IIII", data, o + 8)
        ch = struct.unpack_from("<I", data, o + 36)[0]
        pe.sections.append(Section(nm, vs, va, rs, ra, ch, ent(data[ra:ra + rs]) if rs else 0.0))
    return pe


def watermark(data):
    for w in WATERMARKS:
        if w in data:
            return w.decode()
    return None


def sec_of_rva(pe, rva):
    for s in pe.sections:
        if s.virtual_address <= rva < s.virtual_address + max(s.virtual_size, s.raw_size):
            return s
    return None


def identify(pe):
    if not pe.is_pe:
        return {"file": pe.path, "is_pe": False, "error": pe.error}
    wm = watermark(pe.data)
    names = [s.name for s in pe.sections]
    has_adata = ADAT in [n.lower() for n in names]
    ep_sec = sec_of_rva(pe, pe.entry_rva)
    ep_high = bool(ep_sec and ep_sec.entropy > 7.2)
    high = [s.name for s in pe.sections if s.raw_size and s.entropy > 7.2]
    detected = has_adata or bool(wm) or (ep_high and high)
    return {"file": pe.path, "is_pe": True, "is64": pe.is64,
            "asprotect_detected": detected, "watermark": wm,
            "has_.adata": has_adata, "entry_section": ep_sec.name if ep_sec else None,
            "ep_high_entropy": ep_high, "high_entropy_sections": high,
            "num_sections": len(pe.sections), "sections": names,
            "image_base": hex(pe.image_base), "entry_rva": hex(pe.entry_rva)}


def analyze(pe):
    ep_sec = sec_of_rva(pe, pe.entry_rva)
    return {"file": pe.path, "is64": pe.is64, "subsystem": pe.subsystem,
            "image_base": hex(pe.image_base), "entry_rva": hex(pe.entry_rva),
            "size_of_image": hex(pe.size_of_image), "timestamp": pe.timestamp,
            "data_directories": {k: {"rva": hex(v[0]), "size": v[1]} for k, v in pe.data_dirs.items()},
            "sections": [{"name": s.name, "va": hex(s.virtual_address),
                          "vsize": hex(s.virtual_size), "rawsize": hex(s.raw_size),
                          "entropy": round(s.entropy, 3),
                          "flags": ("R" if s.characteristics & 0x40000000 else "-") +
                                   ("W" if s.characteristics & 0x80000000 else "-") +
                                   ("X" if s.characteristics & 0x20000000 else "-"),
                          "is_entry": (ep_sec is s)} for s in pe.sections]}


def parse_keys(path):
    data = open(path, "rb").read()
    return {"file": path, "size": len(data), "entropy": round(ent(data), 3),
            "header_hex": data[:16].hex(),
            "note": "aspr_keys.bin 为加密注册库 (ASProtect 私有密钥表); "
                    "此处仅解析信封, 不伪造/解密密钥。"}


def cmd_identify(a):
    pe = parse_pe(open(a.input, "rb").read(), a.input)
    r = identify(pe)
    print(json.dumps(r, indent=2) if a.json else
          f"{a.input}: ASProtect={r.get('asprotect_detected')} watermark={r.get('watermark')} "
          f"sections={r.get('sections')}")
    return EXIT_SUCCESS


def cmd_analyze(a):
    pe = parse_pe(open(a.input, "rb").read(), a.input)
    if not pe.is_pe: print("error:", pe.error, file=sys.stderr); return EXIT_FAILURE
    print(json.dumps(analyze(pe), indent=2) if a.json else
          f"{a.input}: {len(pe.sections)} sections, EP {hex(pe.entry_rva)} in "
          f"{sec_of_rva(pe, pe.entry_rva).name if sec_of_rva(pe, pe.entry_rva) else '?'}")
    for s in pe.sections:
        print(f"  {s.name:8s} va={s.virtual_address:#010x} vsz={s.virtual_size:#08x} "
              f"rsz={s.raw_size:#08x} H={s.entropy:.2f}")
    return EXIT_SUCCESS


def cmd_keys(a):
    print(json.dumps(parse_keys(a.input), indent=2) if a.json else
          f"{a.input}: {os.path.getsize(a.input)} bytes (encrypted registration store)")
    return EXIT_SUCCESS


def cmd_version(a):
    pe = parse_pe(open(a.input, "rb").read(), a.input)
    wm = watermark(pe.data)
    print(f"{a.input}: watermark={wm}")
    return EXIT_SUCCESS


def build_parser():
    p = argparse.ArgumentParser(prog="asprotect", description="ASProtect 2.51 protector analyzer - Python CLI")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, fn, arg in [("identify", cmd_identify, "PE"), ("analyze", cmd_analyze, "PE"),
                          ("version", cmd_version, "PE")]:
        sp = sub.add_parser(name); sp.add_argument("input", metavar=arg)
        sp.add_argument("--json", action="store_true"); sp.set_defaults(func=fn)
    kp = sub.add_parser("keys"); kp.add_argument("input"); kp.add_argument("--json", action="store_true")
    kp.set_defaults(func=cmd_keys)
    return p


def main(argv=None):
    a = build_parser().parse_args(argv)
    try: return a.func(a)
    except FileNotFoundError as e: print("error:", e, file=sys.stderr); return EXIT_FAILURE


if __name__ == "__main__":
    sys.exit(main())