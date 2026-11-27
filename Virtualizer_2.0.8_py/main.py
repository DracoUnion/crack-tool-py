#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Virtualizer.exe (Code Virtualizer 2.0.8.0, Oreans) -> Python CLI

来源目录: D:\\Program Files\\crack-tool-packer\\Virtualizer_2.0.8.0
真实主程序: Virtualizer.exe 自身被 Code Virtualizer 加壳 (随机命名节 ctvaqgom/vbokgcbq,
            高熵 ~8.0, ImageBase 0x278000)。同目录 CVLicense.dat(472B 加密许可),
            Examples / Include / Lib / custom_vms / StealthMode。

逆向依据 (PE 结构 + 字符串 + Code Virtualizer 公开特征):
  Code Virtualizer 把指定函数转成随机命名的虚拟机节 (如 ctvaqgom/vbokgcbq), 高熵,
  入口改到随机节; 水印 "Code Virtualizer", 许可存 CVLicense.dat (加密)。
  与 Code Virtualizer 2.2.2 同引擎 (Oreans)。

  本 Python 实现为 Code Virtualizer 的识别 / 结构分析 / 许可信封解析工具 (纯标准库):
    - identify: 随机命名节 + 高熵 + 水印 -> 判定 Code Virtualizer;
    - analyze : 逐节熵/权限/数据目录/入口;
    - license : 解析 CVLicense.dat 信封 (长度/熵/头部), 不伪造许可。
  说明: Code Virtualizer 的 VM 引擎为机器码, 本工具不重写虚拟化算法 (不可行),
  聚焦可逆向的识别与文件格式。
  main.py 为唯一入口。

用法:
  python main.py identify <PE> [--json]
  python main.py analyze  <PE> [--json]
  python main.py license  <CVLicense.dat> [--json]
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
WATERMARKS = (b"Code Virtualizer", b"CodeVirtualizer", b"CVLicense")
STD_SECTIONS = {".text", ".data", ".rdata", ".rsrc", ".reloc", ".idata", ".rsrc",
                ".bss", ".CRT", ".tls", ".edata", ".pdata", ".textbss", ""}


def ent(b):
    if not b: return 0.0
    c = Counter(b); n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


@dataclass
class Section:
    name: str; virtual_size: int; virtual_address: int
    raw_size: int; raw_address: int; characteristics: int; entropy: float = 0.0


@dataclass
class PeFile:
    path: str; data: bytes; image_base: int = 0; entry_rva: int = 0
    size_of_image: int = 0; is64: bool = False; subsystem: int = 0
    sections: List[Section] = field(default_factory=list)
    data_dirs: dict = field(default_factory=dict)
    is_pe: bool = True; error: Optional[str] = None


def parse_pe(data, path):
    pe = PeFile(path, data)
    if len(data) < 0x40 or data[:2] != b"MZ":
        pe.is_pe = False; pe.error = "not MZ"; return pe
    e = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e:e + 4] != b"PE\0\0":
        pe.is_pe = False; pe.error = "no PE sig"; return pe
    fh = e + 4; nsec = struct.unpack_from("<H", data, fh + 2)[0]
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
        rva, sz = struct.unpack_from("<II", data, dd + idx * 8); pe.data_dirs[nm] = (rva, sz)
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


def weird_sections(pe):
    return [s.name for s in pe.sections if s.name and s.name not in STD_SECTIONS
            and not s.name.startswith(".")]


def sec_of_rva(pe, rva):
    for s in pe.sections:
        if s.virtual_address <= rva < s.virtual_address + max(s.virtual_size, s.raw_size):
            return s
    return None


def identify(pe):
    if not pe.is_pe:
        return {"file": pe.path, "is_pe": False, "error": pe.error}
    wm = watermark(pe.data)
    weird = weird_sections(pe)
    ep_sec = sec_of_rva(pe, pe.entry_rva)
    ep_high = bool(ep_sec and ep_sec.entropy > 7.2)
    high = [s.name or "(unnamed)" for s in pe.sections if s.raw_size and s.entropy > 7.2]
    detected = bool(wm) or bool(weird) or (ep_high and high)
    return {"file": pe.path, "is_pe": True, "is64": pe.is64,
            "codevirtualizer_detected": detected, "watermark": wm,
            "random_named_sections": weird, "entry_section": ep_sec.name if ep_sec else None,
            "ep_high_entropy": ep_high, "high_entropy_sections": high,
            "num_sections": len(pe.sections), "image_base": hex(pe.image_base),
            "entry_rva": hex(pe.entry_rva)}


def analyze(pe):
    ep_sec = sec_of_rva(pe, pe.entry_rva)
    return {"file": pe.path, "is64": pe.is64, "subsystem": pe.subsystem,
            "image_base": hex(pe.image_base), "entry_rva": hex(pe.entry_rva),
            "size_of_image": hex(pe.size_of_image),
            "data_directories": {k: {"rva": hex(v[0]), "size": v[1]} for k, v in pe.data_dirs.items()},
            "sections": [{"name": s.name or "(unnamed)", "va": hex(s.virtual_address),
                          "vsize": hex(s.virtual_size), "rawsize": hex(s.raw_size),
                          "entropy": round(s.entropy, 3), "is_entry": (ep_sec is s),
                          "random_named": s.name in weird_sections(pe)} for s in pe.sections]}


def parse_license(path):
    data = open(path, "rb").read()
    return {"file": path, "size": len(data), "entropy": round(ent(data), 3),
            "header_hex": data[:16].hex(),
            "note": "CVLicense.dat 为 Code Virtualizer 加密许可; 仅解析信封, 不伪造许可。"}


def cmd_identify(a):
    pe = parse_pe(open(a.input, "rb").read(), a.input); r = identify(pe)
    print(json.dumps(r, indent=2) if a.json else
          f"{a.input}: CodeVirtualizer={r.get('codevirtualizer_detected')} "
          f"random_sections={r.get('random_named_sections')} watermark={r.get('watermark')}")
    return EXIT_SUCCESS


def cmd_analyze(a):
    pe = parse_pe(open(a.input, "rb").read(), a.input)
    if not pe.is_pe: print("error:", pe.error, file=sys.stderr); return EXIT_FAILURE
    print(json.dumps(analyze(pe), indent=2) if a.json else
          f"{a.input}: {len(pe.sections)} sections, EP {hex(pe.entry_rva)}")
    for s in pe.sections:
        print(f"  {(s.name or '(unnamed)'):10s} va={s.virtual_address:#010x} "
              f"vsz={s.virtual_size:#08x} rsz={s.raw_size:#08x} H={s.entropy:.2f}")
    return EXIT_SUCCESS


def cmd_license(a):
    print(json.dumps(parse_license(a.input), indent=2) if a.json else
          f"{a.input}: {os.path.getsize(a.input)} bytes (encrypted Code Virtualizer license (CVLicense.dat))")
    return EXIT_SUCCESS


def build_parser():
    p = argparse.ArgumentParser(prog="virtualizer", description="Code Virtualizer 2.2.2 analyzer - Python CLI")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, fn in [("identify", cmd_identify), ("analyze", cmd_analyze)]:
        sp = sub.add_parser(name); sp.add_argument("input"); sp.add_argument("--json", action="store_true")
        sp.set_defaults(func=fn)
    lp = sub.add_parser("license"); lp.add_argument("input"); lp.add_argument("--json", action="store_true")
    lp.set_defaults(func=cmd_license)
    return p


def main(argv=None):
    a = build_parser().parse_args(argv)
    try: return a.func(a)
    except FileNotFoundError as e: print("error:", e, file=sys.stderr); return EXIT_FAILURE


if __name__ == "__main__":
    sys.exit(main())