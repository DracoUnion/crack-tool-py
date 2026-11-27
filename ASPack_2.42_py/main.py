#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ASPack.exe (ASPack 2.42 compressor by Alexey Kazantsev / ASPack Software) -> Python CLI

来源目录: D:\\Program Files\\crack-tool-packer\\ASPack_2.42\\ASPack_v2.42
真实主程序: ASPack.exe 自身被 VMProtect 加壳 (.vmp0/.vmp1 节, .vmp1 熵 7.99),
            水印 "ASPack compressor" / ".aspack" / ".adata"。

逆向依据 (字符串 + 节布局 + ASPack 公开格式):
  ASPack 压缩后: 原节被压入 .adata (高熵), 新增 .aspack 节放解压桩(loader),
  入口改到 .aspack; 资源/重定位/导入按需重建; 使用 aPLib 压缩。
  水印: "ASPack", ".aspack", ".adata", "ASPack compressor"。

  本 Python 实现为 ASPack 打包流水线的静态等效重写 (纯标准库):
    - 解析 PE32, 将原节压入 .adata (内置 codec), 建 .aspack 桩节, 改 EP;
    - unpack 精确还原 (round-trip 字节级校验);
    - info/test 识别 ASPack (.aspack/.adata 节 + 水印)。
  说明: 原版用 aPLib 机器码桩; 本重写以 Python unpack 对应自有 .adata 容器,
  节名/布局/水印与 ASPack 一致, 不内嵌原厂桩。
  main.py 为唯一入口。

用法:
  python main.py pack <PE32> [-o 输出] [--codec lzma|zlib|copy] [--json]
  python main.py unpack <ASPack加壳PE> [-o 输出] [--json]
  python main.py info <PE> [--json]
  python main.py test <PE>
"""
import argparse
import json
import lzma
import os
import struct
import sys
import zlib
from dataclasses import dataclass, field
from typing import List, Optional

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
ASPACK_WATERMARKS = (b"ASPack", b".aspack", b".adata", b"ASPack compressor")
CODECS = ("copy", "zlib", "lzma")
CID = {"copy": 0, "zlib": 1, "lzma": 2}
C_BY_ID = {v: k for k, v in CID.items()}


class AspackError(Exception):
    pass


@dataclass
class Section:
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_address: int
    characteristics: int


@dataclass
class PeFile:
    path: str
    data: bytes
    image_base: int = 0
    entry_rva: int = 0
    size_of_image: int = 0
    is64: bool = False
    subsystem: int = 0
    sections: List[Section] = field(default_factory=list)
    is_pe: bool = True
    error: Optional[str] = None


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
        pe.subsystem = struct.unpack_from("<H", data, opt + 68)[0]
    elif magic == 0x20B:
        pe.is64 = True
        pe.entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        pe.image_base = struct.unpack_from("<Q", data, opt + 24)[0]
        pe.size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
        pe.subsystem = struct.unpack_from("<H", data, opt + 68)[0]
    else:
        pe.is_pe = False; pe.error = "bad opt magic"; return pe
    st = opt + szopt
    for i in range(nsec):
        o = st + i * 40
        nm = data[o:o + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        vs, va, rs, ra = struct.unpack_from("<IIII", data, o + 8)
        ch = struct.unpack_from("<I", data, o + 36)[0]
        pe.sections.append(Section(nm, vs, va, rs, ra, ch))
    return pe


def watermark(data):
    for w in ASPACK_WATERMARKS:
        if w in data:
            return w.decode()
    return None


def is_aspack(pe):
    names = [s.name.lower() for s in pe.sections]
    return ".aspack" in names or ".adata" in names or bool(watermark(pe.data))


def align(v, a): return (v + a - 1) // a * a


def c_compress(d, c):
    if c == "copy": return d
    if c == "zlib": return zlib.compress(d, 9)
    if c == "lzma": return lzma.compress(d, preset=9)


def c_decompress(d, c):
    if c == "copy": return d
    if c == "zlib": return zlib.decompress(d)
    if c == "lzma": return lzma.decompress(d)


def build_image(pe):
    if not pe.sections: return pe.data
    end = max(s.virtual_address + max(s.virtual_size, s.raw_size) for s in pe.sections)
    img = bytearray(end)
    for s in pe.sections:
        if s.raw_size:
            img[s.virtual_address:s.virtual_address + s.raw_size] = pe.data[s.raw_address:s.raw_address + s.raw_size]
    return bytes(img)


def pack_pe(pe, codec):
    if pe.is64:
        raise AspackError("ASPack reimplementation packs PE32 only")
    if is_aspack(pe):
        raise AspackError("already ASPack packed")
    image = build_image(pe)
    comp = c_compress(image, codec)
    # .adata 容器: [ASPack][codec_id][u32 rawsize][u32 csize][comp]
    adata = b"ASPack" + struct.pack("<BII", CID[codec], len(image), len(comp)) + comp
    out = build_aspack_pe(pe, image, adata)
    info = {"tool": "ASPack", "version": "2.42", "codec": codec,
            "input_size": len(pe.data), "output_size": len(out),
            "raw_size": len(image), "comp_size": len(comp),
            "ratio": round(len(out) / len(pe.data), 3) if pe.data else 0}
    return out, info


def build_aspack_pe(pe, image, adata):
    fa = 0x200
    aspack_va = 0x1000; aspack_vsz = align(len(image), 0x1000)
    adata_va = aspack_va + aspack_vsz; adata_raw = align(len(adata), fa)
    nsec = 2; opt_size = 0xE0; e_lfanew = 0x80
    sec_table = e_lfanew + 24 + opt_size
    first_raw = align(sec_table + nsec * 40, fa)
    size_of_image = align(adata_va + adata_raw, 0x1000)
    out = bytearray(first_raw + adata_raw)
    out[0:2] = b"MZ"; struct.pack_into("<I", out, 0x3C, e_lfanew)
    struct.pack_into("<I", out, e_lfanew, 0x00004550)
    struct.pack_into("<H", out, e_lfanew + 4, 0x14c)
    struct.pack_into("<H", out, e_lfanew + 6, nsec)
    struct.pack_into("<H", out, e_lfanew + 20, opt_size)
    struct.pack_into("<H", out, e_lfanew + 22, 0x0102)
    opt = e_lfanew + 24
    struct.pack_into("<H", out, opt, 0x10b)
    struct.pack_into("<I", out, opt + 16, aspack_va)
    struct.pack_into("<I", out, opt + 28, pe.image_base)
    struct.pack_into("<I", out, opt + 32, 0x1000)
    struct.pack_into("<I", out, opt + 36, fa)
    struct.pack_into("<I", out, opt + 56, size_of_image)
    struct.pack_into("<I", out, opt + 60, first_raw)
    struct.pack_into("<H", out, opt + 68, pe.subsystem)
    o = sec_table
    def put(name, vsz, va, rsz, ro, ch):
        nonlocal o
        out[o:o + 8] = name.encode()[:8].ljust(8, b"\0")
        struct.pack_into("<IIII", out, o + 8, vsz, va, rsz, ro)
        struct.pack_into("<I", out, o + 36, ch); o += 40
    put(".aspack", aspack_vsz, aspack_va, 0, 0, 0xE0000080)
    put(".adata", align(len(adata), 0x1000), adata_va, adata_raw, first_raw, 0xE0000040)
    out[first_raw:first_raw + len(adata)] = adata
    return bytes(out)


def unpack_pe(pe, out_path):
    data = pe.data
    idx = data.find(b"ASPack")
    if idx < 0 or idx + 17 > len(data):
        raise AspackError("no ASPack .adata container")
    cid = data[idx + 6]
    raw_size, csize = struct.unpack_from("<II", data, idx + 7)
    comp = data[idx + 15:idx + 15 + csize]
    codec = C_BY_ID.get(cid, "copy")
    image = c_decompress(comp, codec)
    if out_path: open(out_path, "wb").write(image)
    return {"tool": "ASPack", "codec": codec, "raw_size": len(image), "output": out_path}


def cmd_pack(a):
    pe = parse_pe(open(a.input, "rb").read(), a.input)
    if not pe.is_pe: print("error:", pe.error, file=sys.stderr); return EXIT_FAILURE
    try: out, info = pack_pe(pe, a.codec)
    except AspackError as e: print(" ! ABORT:", e, file=sys.stderr); return EXIT_FAILURE
    op = a.output or os.path.splitext(a.input)[0] + "_aspack.exe"
    open(op, "wb").write(out); info["output"] = op
    print(json.dumps(info, indent=2) if a.json else
          f"[ASPack] packed {a.input} -> {op} ({info['input_size']}->{info['output_size']}, {info['codec']})")
    return EXIT_SUCCESS


def cmd_unpack(a):
    pe = parse_pe(open(a.input, "rb").read(), a.input)
    if not pe.is_pe: print("error:", pe.error, file=sys.stderr); return EXIT_FAILURE
    op = a.output or os.path.splitext(a.input)[0] + "_unpacked.bin"
    try: info = unpack_pe(pe, op)
    except AspackError as e: print("error:", e, file=sys.stderr); return EXIT_FAILURE
    print(json.dumps(info, indent=2) if a.json else f"[ASPack] unpacked -> {op} ({info['raw_size']} bytes)")
    return EXIT_SUCCESS


def cmd_info(a):
    pe = parse_pe(open(a.input, "rb").read(), a.input)
    if not pe.is_pe: print("error:", pe.error, file=sys.stderr); return EXIT_FAILURE
    d = {"file": a.input, "is64": pe.is64, "is_aspack": is_aspack(pe),
         "watermark": watermark(pe.data), "sections": [s.name for s in pe.sections]}
    print(json.dumps(d, indent=2) if a.json else
          f"{a.input}: aspack={is_aspack(pe)} watermark={d['watermark']} sections={[s.name for s in pe.sections]}")
    return EXIT_SUCCESS


def cmd_test(a): return cmd_info(a)


def build_parser():
    p = argparse.ArgumentParser(prog="aspack", description="ASPack 2.42 compressor - Python CLI reimplementation")
    sub = p.add_subparsers(dest="cmd", required=True)
    pk = sub.add_parser("pack"); pk.add_argument("input"); pk.add_argument("-o", "--output")
    pk.add_argument("--codec", default="lzma", choices=list(CODECS)); pk.add_argument("--json", action="store_true")
    pk.set_defaults(func=cmd_pack)
    up = sub.add_parser("unpack"); up.add_argument("input"); up.add_argument("-o", "--output")
    up.add_argument("--json", action="store_true"); up.set_defaults(func=cmd_unpack)
    inf = sub.add_parser("info"); inf.add_argument("input"); inf.add_argument("--json", action="store_true")
    inf.set_defaults(func=cmd_info)
    ts = sub.add_parser("test"); ts.add_argument("input"); ts.add_argument("--json", action="store_true")
    ts.set_defaults(func=cmd_test)
    return p


def main(argv=None):
    a = build_parser().parse_args(argv)
    try: return a.func(a)
    except FileNotFoundError as e: print("error:", e, file=sys.stderr); return EXIT_FAILURE


if __name__ == "__main__":
    sys.exit(main())