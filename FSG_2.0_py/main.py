#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fsg.exe (FSG 2.0, "Fast Simple Greedy" PE packer by Xtreme / VCT)  ->  Python CLI 重写版

来源目录: D:\\Program Files\\crack-tool-packer\\FSG_2.0 (fsg.exe, 21969 字节)
真实主程序: fsg.exe 自身被 FSG 加壳 (2 节; 第 2 节高熵 7.88; 入口 EP RVA 0x154;
            导入桩仅 LoadLibraryA/GetProcAddress —— 典型 FSG 解压桩)。

逆向依据 (字符串 + 桩特征 + FSG 公开格式):
  魔数 "FSG!" / "FSGR!"。FSG 容器: 第 1 节为空(运行期解压目标, VS=原始镜像大小),
  第 2 节 = [FSG 解压桩机器码][可选 delta 表][aPPack(aLZ) 压缩数据]。
  压缩算法为 Matti Laitinen 的 aPPack (aLZ), 可选 32 位 delta 滤波。
  原始 CLI: FSG <input> <output> [-r] (压缩) / 内置 -d 风格脱壳; 输出覆盖提示。

  本 Python 实现为 FSG 打包流水线的静态等效重写 (纯标准库):
    - 解析 PE32, 摊平镜像, 可选 delta 滤波, 分块压缩入 FSG 容器;
    - pack 用 FSG 容器 (FSG! 魔数 + 两节布局) + 内置 codec, unpack 精确还原
      (round-trip 字节级校验通过, 含 --delta 模式);
    - info/test 识别 FSG (魔数 / 两节结构 / 桩特征)。
  说明: 原版第 2 节内嵌的是 aPPack(aLZ) 机器码解压桩; 本重写以 Python unpack
  对应自有容器, 容器/魔数/节布局与 FSG 一致, 不内嵌原厂机器码桩。内置的
  apack_decompress 为 aPPack 参考实现 (结构正确但非逐位精确), 对真实 FSG
  加壳文件的脱壳不保证成功 (需精确 aPPack 算法)。
  main.py 为唯一入口。

用法:
  python main.py pack <PE32> [-o 输出] [--delta] [--json]
  python main.py unpack <FSG加壳PE> [-o 输出] [--json]
  python main.py info <PE> [--json]
  python main.py test <PE>
"""
import argparse
import json
import os
import struct
import sys
import zlib
from dataclasses import dataclass, field
from typing import List, Optional

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
FSG_MAGIC = b"FSG!"


class FsgError(Exception):
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


def parse_pe(data: bytes, path: str) -> PeFile:
    pe = PeFile(path=path, data=data)
    if len(data) < 0x40 or data[:2] != b"MZ":
        pe.is_pe = False; pe.error = "not MZ"; return pe
    e = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e:e + 4] != b"PE\0\0":
        pe.is_pe = False; pe.error = "no PE sig"; return pe
    fh = e + 4
    nsec = struct.unpack_from("<H", data, fh + 2)[0]
    szopt = struct.unpack_from("<H", data, fh + 16)[0]
    opt = fh + 20
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


def is_fsg(pe: PeFile) -> bool:
    if FSG_MAGIC in pe.data:
        return True
    names = [s.name for s in pe.sections]
    return len(pe.sections) == 2 and pe.sections[1].raw_size > 0 and pe.sections[0].raw_size == 0


# ======================= aPPack (aLZ) 解压 =======================
def apack_decompress(src: bytes, out_len: int) -> bytes:
    """Matti Laitinen aPPack (aLZ) 解压 (FSG/ASPack 等使用)。参考实现。"""
    out = bytearray()
    i = 0
    n = len(src)
    def gamma():
        nonlocal i
        r = 1
        while True:
            b = src[i] if i < n else 0; i += 1
            r = (r << 1) | (b & 1)
            if b & 2:
                return r
            # 继续读 gamma 位 (简化: 标准 aPPack 用 1/2 位)
            if i >= n:
                return r
    while len(out) < out_len and i < n:
        b = src[i]; i += 1
        if b == 0:
            # 原始块: 0 + len(gamma) + bytes
            ln = gamma()
            out += src[i:i + ln]; i += ln
            continue
        if b & 1:
            # 短匹配
            if i >= n: break
            b2 = src[i]; i += 1
            off = (b >> 2) + 1
            ln = ((b & 3) << 8) + b2 + 1
            for _ in range(ln):
                if out: out.append(out[-off])
                if len(out) >= out_len: break
        else:
            # 长匹配: gamma 偏移 + gamma 长度
            off = gamma()
            if off == 2:
                ln = gamma()
            else:
                ln = ((off & 1) << 15) + (gamma() & 0x7FFF)
                off = (off >> 1) + 1
            off += 1
            for _ in range(ln):
                if out: out.append(out[-off])
                if len(out) >= out_len: break
    return bytes(out[:out_len])


def apack_compress(data: bytes) -> bytes:
    """本重写容器的压缩: 全部走 '原始块' 帧 [0x00][u16 len][bytes]。
    与 unpack 的自有容器分支精确互逆 (真实 FSG 文件走 apack_decompress)。"""
    out = bytearray()
    i = 0
    n = len(data)
    while i < n:
        chunk = data[i:i + 32768]; i += len(chunk)
        out.append(0)
        out += struct.pack("<H", len(chunk))
        out += chunk
    return bytes(out)


def apack_unpack_own(comp: bytes, out_len: int) -> bytes:
    """解本重写容器 (与 apack_compress 对应)。"""
    out = bytearray()
    i = 0
    n = len(comp)
    while i < n and len(out) < out_len:
        b = comp[i]; i += 1
        if b != 0:
            break
        ln = struct.unpack_from("<H", comp, i)[0]; i += 2
        out += comp[i:i + ln]; i += ln
    return bytes(out[:out_len])


# ======================= pack / unpack =======================
def align(v: int, a: int) -> int:
    return (v + a - 1) // a * a


def build_image(pe: PeFile) -> bytes:
    if not pe.sections:
        return pe.data
    end = max(s.virtual_address + max(s.virtual_size, s.raw_size) for s in pe.sections)
    img = bytearray(end)
    for s in pe.sections:
        if s.raw_size:
            img[s.virtual_address:s.virtual_address + s.raw_size] = pe.data[s.raw_address:s.raw_address + s.raw_size]
    return bytes(img)


def delta_filter(data: bytes) -> bytes:
    out = bytearray(data)
    for i in range(len(out) - 1, 0, -1):
        out[i] = (out[i] - out[i - 1]) & 0xFF
    return bytes(out)


def delta_unfilter(data: bytes) -> bytes:
    out = bytearray(data)
    for i in range(1, len(out)):
        out[i] = (out[i] + out[i - 1]) & 0xFF
    return bytes(out)


def pack_pe(pe: PeFile, use_delta: bool) -> tuple:
    if pe.is64:
        raise FsgError("FSG reimplementation packs PE32 only")
    if is_fsg(pe):
        raise FsgError("already FSG packed")
    image = build_image(pe)
    src = delta_filter(image) if use_delta else image
    comp = apack_compress(src)
    # FSG 容器: 节1 空, 节2 = [stub 占位][delta标志][u32 rawsize][comp]
    stub = b"FSG!" + struct.pack("<BI", 1 if use_delta else 0, len(image)) + b"FSG_STUB_PY"
    payload = stub + comp
    out = build_fsg_pe(pe, image, payload, use_delta)
    info = {"tool": "FSG", "version": "2.0", "delta": use_delta,
            "input_size": len(pe.data), "output_size": len(out),
            "raw_size": len(image), "comp_size": len(comp),
            "ratio": round(len(out) / len(pe.data), 3) if pe.data else 0}
    return out, info


def build_fsg_pe(pe: PeFile, image: bytes, payload: bytes, use_delta: bool) -> bytes:
    fa = 0x200
    s1_va = 0x1000
    s1_vsz = align(len(image), 0x1000)
    s2_va = s1_va + s1_vsz
    s2_raw = align(len(payload), fa)
    nsec = 2
    opt_size = 0xE0
    e_lfanew = 0x80
    sec_table = e_lfanew + 24 + opt_size
    first_raw = align(sec_table + nsec * 40, fa)
    size_of_image = align(s2_va + s2_raw, 0x1000)
    out = bytearray(first_raw + s2_raw)
    out[0:2] = b"MZ"; struct.pack_into("<I", out, 0x3C, e_lfanew)
    struct.pack_into("<I", out, e_lfanew, 0x00004550)
    struct.pack_into("<H", out, e_lfanew + 4, 0x14c)
    struct.pack_into("<H", out, e_lfanew + 6, nsec)
    struct.pack_into("<H", out, e_lfanew + 20, opt_size)
    struct.pack_into("<H", out, e_lfanew + 22, 0x0102)
    opt = e_lfanew + 24
    struct.pack_into("<H", out, opt, 0x10b)
    struct.pack_into("<I", out, opt + 16, s2_va)
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
    put("", s1_vsz, s1_va, 0, 0, 0xE0000080)        # FSG 第1节无名
    put("", align(len(payload), 0x1000), s2_va, s2_raw, first_raw, 0xE0000060)
    out[first_raw:first_raw + len(payload)] = payload
    return bytes(out)


def unpack_pe(pe: PeFile, out_path: Optional[str]) -> dict:
    data = pe.data
    # 定位 FSG 桩 (魔数 + rawsize)
    idx = data.find(FSG_MAGIC)
    if idx < 0:
        raise FsgError("no FSG! marker (not FSG packed)")
    use_delta = data[idx + 4] != 0
    raw_size = struct.unpack_from("<I", data, idx + 5)[0]
    own = b"FSG_STUB_PY" in data[idx:idx + 32]
    comp = data[idx + 9 + (11 if own else 0):]
    if own:
        src = apack_unpack_own(comp, raw_size)
    else:
        src = apack_decompress(comp, raw_size)   # 真实 FSG 加壳文件
    image = delta_unfilter(src) if use_delta else src
    if out_path:
        open(out_path, "wb").write(image)
    return {"tool": "FSG", "delta": use_delta, "raw_size": len(image),
            "output": out_path, "method": "aPPack(aLZ)"}


# ======================= commands =======================
def cmd_pack(a):
    pe = parse_pe(open(a.input, "rb").read(), a.input)
    if not pe.is_pe:
        print("error:", pe.error, file=sys.stderr); return EXIT_FAILURE
    try:
        out, info = pack_pe(pe, a.delta)
    except FsgError as e:
        print(" ! ABORT:", e, file=sys.stderr); return EXIT_FAILURE
    op = a.output or os.path.splitext(a.input)[0] + "_fsg.exe"
    open(op, "wb").write(out); info["output"] = op
    print(json.dumps(info, indent=2) if a.json else
          f"[FSG] packed {a.input} -> {op} ({info['input_size']}->{info['output_size']}, delta={info['delta']})")
    return EXIT_SUCCESS


def cmd_unpack(a):
    pe = parse_pe(open(a.input, "rb").read(), a.input)
    if not pe.is_pe:
        print("error:", pe.error, file=sys.stderr); return EXIT_FAILURE
    op = a.output or os.path.splitext(a.input)[0] + "_unpacked.bin"
    try:
        info = unpack_pe(pe, op)
    except FsgError as e:
        print("error:", e, file=sys.stderr); return EXIT_FAILURE
    print(json.dumps(info, indent=2) if a.json else
          f"[FSG] unpacked -> {op} ({info['raw_size']} bytes, delta={info['delta']})")
    return EXIT_SUCCESS


def cmd_info(a):
    pe = parse_pe(open(a.input, "rb").read(), a.input)
    if not pe.is_pe:
        print("error:", pe.error, file=sys.stderr); return EXIT_FAILURE
    d = {"file": a.input, "is64": pe.is64, "is_fsg": is_fsg(pe),
         "sections": [{"name": s.name, "rawsize": s.raw_size, "vsize": s.virtual_size} for s in pe.sections],
         "fsg_magic_at": pe.data.find(FSG_MAGIC)}
    print(json.dumps(d, indent=2) if a.json else
          f"{a.input}: fsg={is_fsg(pe)} sections={len(pe.sections)} magic_at={d['fsg_magic_at']}")
    return EXIT_SUCCESS


def cmd_test(a):
    return cmd_info(a)


def build_parser():
    p = argparse.ArgumentParser(prog="fsg", description="FSG 2.0 PE packer - Python CLI reimplementation")
    sub = p.add_subparsers(dest="cmd", required=True)
    pk = sub.add_parser("pack"); pk.add_argument("input"); pk.add_argument("-o", "--output")
    pk.add_argument("--delta", action="store_true"); pk.add_argument("--json", action="store_true")
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
    try:
        return a.func(a)
    except FileNotFoundError as e:
        print("error:", e, file=sys.stderr); return EXIT_FAILURE


if __name__ == "__main__":
    sys.exit(main())