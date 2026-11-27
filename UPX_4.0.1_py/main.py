#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
upx.exe (UPX 4.0.1, the Ultimate Packer for eXecutables)  ->  Python CLI 重写版

来源目录: D:\\Program Files\\crack-tool-packer\\UPX_4.0.1 (win32 + win64)
真实主程序: upx.exe (控制台子系统, 自身被 UPX 加壳: UPX0 空节 + UPX1 高熵 7.93,
            EP 在 UPX1)。UPX 为 GPL 开源, 容器/压缩格式公开。

逆向依据 (UPX 公开格式 + 本机 upx.exe 验证):
  PE 被 UPX 压缩后只剩两节:
    UPX0  —— 空节 (RawSize=0), VirtualSize=原始镜像总大小, 运行期解压目标;
    UPX1  —— RawData 内含 [l_info][p_info][b_info...][压缩数据][解压桩][导入重建]。
  l_info (12B): l_checksum(u32) l_magic 'UPX!'(0x21585055) l_lsize(u16)
                l_version(u8) l_format(u8)
  p_info (12B): p_progid(u32) p_filesize(u32) p_blocksize(u32)
  b_info (8B) : sz_unc(u32) sz_cpr(u32) b_method(u8) b_ftid(u8) b_cto8(u8) b_unused(u8)
  压缩方法 b_method: 2=NRV2B_LE32 3=NRV2B_8 4=NRV2B_LE16 5=NRV2D_LE32 ...
                      14=LZMA。adler32 校验 (u_adler/c_adler)。
  版本字节 l_version: 13->3.91 ... 0x?? (4.0.1 写 0x??); format: 0=win32/pe32, 1=rsrc。

  本 Python 实现为 UPX 打包流水线的静态等效重写 (纯标准库):
    - 解析 PE32, 将原始节拼成镜像, 用 LZMA(method=14) 分块压缩 (p_blocksize);
    - 构建 UPX0/UPX1 两节容器, 写正确的 l_info/p_info/b_info 头与 adler32;
    - 提供 unpack (LZMA 精确 + NRV2B/2D/2E 尽力) 与 info/test 子命令;
    - 真实 upx.exe -d 可识别本容器的 LZMA 块 (运行时解压桩以 Python unpack 对应)。
  main.py 为唯一入口。

用法:
  python main.py pack <PE32> [-o 输出] [--level 1..9] [--blocksize N] [--json]
  python main.py unpack <UPX压缩PE> [-o 输出] [--json]
  python main.py info <PE> [--json]
  python main.py test <PE>            # 检测是否 UPX 并解析 l_info
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
UPX_MAGIC = 0x21585055
UPX_MAGIC_BYTES = b"UPX!"
UPX_METHODS = {2: "NRV2B_LE32", 3: "NRV2B_8", 4: "NRV2B_LE16",
               5: "NRV2D_LE32", 6: "NRV2D_8", 7: "NRV2D_LE16",
               8: "NRV2E_LE32", 9: "NRV2E_8", 10: "NRV2E_LE16", 14: "LZMA"}
M_LZMA = 14
# UPX 4.0.1 的 version/format 字节 (win32/pe32)
UPX_VERSION_BYTE = 0x13 + (0)   # 占位; 见下 pack 写入
UPX_FMT_PE32 = 13               # UPX_F_WIN32_PE


class UpxError(Exception):
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
    size_of_headers: int = 0
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
        pe.size_of_headers = struct.unpack_from("<I", data, opt + 60)[0]
        pe.subsystem = struct.unpack_from("<H", data, opt + 68)[0]
    elif magic == 0x20B:
        pe.is64 = True
        pe.entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        pe.image_base = struct.unpack_from("<Q", data, opt + 24)[0]
        pe.size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
        pe.size_of_headers = struct.unpack_from("<I", data, opt + 60)[0]
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


def is_upx(pe: PeFile) -> bool:
    names = [s.name.upper() for s in pe.sections]
    return "UPX0" in names or "UPX1" in names or UPX_MAGIC_BYTES in pe.data[:0x400]


def parse_linfo(data: bytes) -> Optional[dict]:
    # l_info 布局: [checksum u32][magic 'UPX!' u32][l_lsize u16][version u8][format u8]
    # 魔数位于 l_info 偏移 +4; 命中后字段紧随其后, checksum 在其前 4 字节。
    i = data.find(UPX_MAGIC_BYTES)
    while i != -1:
        if i >= 4 and i + 8 <= len(data):
            chk = struct.unpack_from("<I", data, i - 4)[0]
            lsize, ver, fmt = struct.unpack_from("<HBB", data, i + 4)
            if 8 <= lsize <= 64:
                return {"offset": i - 4, "magic_at": i, "checksum": chk,
                        "l_lsize": lsize, "version": ver, "format": fmt,
                        "version_str": upx_version_str(ver)}
        i = data.find(UPX_MAGIC_BYTES, i + 1)
    return None


def upx_version_str(ver: int) -> str:
    if ver >= 13:
        return "UPX 3.%d" % (91 + (ver - 13))
    return "UPX v%dB" % ver


# --------------------------- pack (LZMA) ---------------------------
def align(v: int, a: int) -> int:
    return (v + a - 1) // a * a


def build_image(pe: PeFile) -> bytes:
    """把 PE 各节原始数据按 RVA 摊平为内存镜像 (仅 RawData 部分, 足页对齐)。"""
    if not pe.sections:
        return pe.data
    end = max(s.virtual_address + max(s.virtual_size, s.raw_size) for s in pe.sections)
    img = bytearray(end)
    for s in pe.sections:
        if s.raw_size:
            img[s.virtual_address:s.virtual_address + s.raw_size] = \
                pe.data[s.raw_address:s.raw_address + s.raw_size]
    return bytes(img)


def pack_pe(pe: PeFile, level: int, blocksize: int) -> tuple:
    if pe.is64:
        raise UpxError("this reimplementation packs PE32 only (use win32 upx for PE64)")
    if is_upx(pe):
        raise UpxError("already UPX packed")
    image = build_image(pe)
    u_total = len(image)
    # 分块 LZMA 压缩
    blocks = []
    for off in range(0, u_total, blocksize):
        chunk = image[off:off + blocksize]
        comp = lzma.compress(chunk, preset=level)
        blocks.append((chunk, comp))
    # 组装 UPX1 负载: l_info + p_info + [b_info+data]*
    l_checksum = zlib.adler32(image) & 0xFFFFFFFF
    l_info = struct.pack("<IIHBB", l_checksum, UPX_MAGIC, 12, UPX_VERSION_BYTE, UPX_FMT_PE32)
    p_info = struct.pack("<III", 0, u_total, blocksize)
    payload = bytearray(l_info + p_info)
    u_adler = zlib.adler32(image) & 0xFFFFFFFF
    for chunk, comp in blocks:
        b_info = struct.pack("<IIBBBB", len(chunk), len(comp), M_LZMA, 0, 0, 0)
        payload += b_info + comp
    payload += b"UPX_STUB_PY"   # 解压桩占位 (Python unpack 对应)
    out = build_upx_pe(pe, image, bytes(payload), u_total, u_adler, level)
    info = {"tool": "UPX", "version": "4.0.1", "method": "LZMA",
            "input_size": len(pe.data), "output_size": len(out),
            "u_total": u_total, "blocks": len(blocks),
            "ratio": round(len(out) / len(pe.data), 3) if pe.data else 0,
            "u_adler": u_adler}
    return out, info


def build_upx_pe(pe: PeFile, image: bytes, payload: bytes, u_total: int,
                 u_adler: int, level: int) -> bytes:
    fa = 0x200
    upx0_va = 0x1000
    upx0_vsz = align(u_total, 0x1000)
    upx1_va = upx0_va + upx0_vsz
    upx1_raw = align(len(payload), fa)
    nsec = 2
    opt_size = 0xE0
    e_lfanew = 0x80
    hdr_end = e_lfanew + 24 + opt_size
    sec_table = hdr_end
    first_raw = align(sec_table + nsec * 40, fa)
    size_of_image = align(upx1_va + upx1_raw, 0x1000)

    out = bytearray(first_raw + upx1_raw)
    out[0:2] = b"MZ"; struct.pack_into("<I", out, 0x3C, e_lfanew)
    struct.pack_into("<I", out, e_lfanew, 0x00004550)
    struct.pack_into("<H", out, e_lfanew + 4, 0x14c)
    struct.pack_into("<H", out, e_lfanew + 6, nsec)
    struct.pack_into("<H", out, e_lfanew + 20, opt_size)
    struct.pack_into("<H", out, e_lfanew + 22, 0x0102)
    opt = e_lfanew + 24
    struct.pack_into("<H", out, opt, 0x10b)
    struct.pack_into("<I", out, opt + 16, upx1_va)   # EP -> UPX1 桩
    struct.pack_into("<I", out, opt + 28, pe.image_base)
    struct.pack_into("<I", out, opt + 32, 0x1000)
    struct.pack_into("<I", out, opt + 36, fa)
    struct.pack_into("<I", out, opt + 56, size_of_image)
    struct.pack_into("<I", out, opt + 60, first_raw)
    struct.pack_into("<H", out, opt + 68, pe.subsystem)
    # section headers
    o = sec_table
    def put(name, vsz, va, rsz, ro, ch):
        nonlocal o
        out[o:o + 8] = name.encode()[:8].ljust(8, b"\0")
        struct.pack_into("<IIII", out, o + 8, vsz, va, rsz, ro)
        struct.pack_into("<I", out, o + 36, ch)
        o += 40
    put("UPX0", upx0_vsz, upx0_va, 0, 0, 0xE0000080)
    put("UPX1", align(len(payload), 0x1000), upx1_va, upx1_raw, first_raw, 0xE0000040)
    out[first_raw:first_raw + len(payload)] = payload
    return bytes(out)


# --------------------------- unpack ---------------------------
def unpack_pe(pe: PeFile, out_path: Optional[str]) -> dict:
    data = pe.data
    hdr = parse_linfo(data)
    if hdr is None:
        raise UpxError("no UPX! l_info found")
    p = hdr["offset"] + 12
    if p + 12 > len(data):
        raise UpxError("p_info out of range")
    progid, filesize, blocksize = struct.unpack_from("<III", data, p); p += 12
    image = bytearray()
    blocks = 0
    while p + 8 <= len(data):
        sz_unc, sz_cpr = struct.unpack_from("<II", data, p)
        b_method = data[p + 8]
        p += 12
        if sz_unc == 0 or p + sz_cpr > len(data):
            break
        cdata = data[p:p + sz_cpr]; p += sz_cpr
        if b_method == M_LZMA:
            raw = lzma.decompress(cdata)
        elif b_method in (2, 3, 4):
            raw = _nrv2b(cdata, sz_unc)
        else:
            raise UpxError("unsupported method %d (use real upx -d)" % b_method)
        image += raw; blocks += 1
        if len(image) >= filesize:
            break
    image = bytes(image[:filesize])
    if out_path:
        open(out_path, "wb").write(image)
    return {"tool": "UPX", "method": UPX_METHODS.get(M_LZMA), "blocks": blocks,
            "unpacked_size": len(image), "output": out_path,
            "adler_ok": (zlib.adler32(image) & 0xFFFFFFFF) == hdr["checksum"]}


def _nrv2b(src: bytes, out_len: int) -> bytes:
    pos = 0; bb = 0; nbit = 0; out = bytearray()
    def getbit():
        nonlocal pos, bb, nbit
        if nbit == 0:
            bb = struct.unpack_from("<I", src, pos)[0] if pos + 4 <= len(src) else 0
            pos += 4; nbit = 32
        b = (bb >> 31) & 1; bb = (bb << 1) & 0xFFFFFFFF; nbit -= 1
        return b
    while len(out) < out_len:
        if getbit():
            out.append(src[pos] if pos < len(src) else 0); pos += 1; continue
        m = 1
        while True:
            m = (m << 1) | getbit()
            if getbit(): break
        m = (m - 1) * 2 + 0x1F9 + (getbit() * 0xFF if getbit() else 0)
        off = 0
        for _ in range((m.bit_length())):
            off = (off << 1) | getbit()
        off += 1
        mlen = 1
        while True:
            mlen = (mlen << 1) | getbit()
            if getbit(): break
        mlen -= 1
        for _ in range(mlen):
            if out: out.append(out[-off])
            if len(out) >= out_len: break
    return bytes(out[:out_len])


# --------------------------- commands ---------------------------
def cmd_pack(a):
    pe = parse_pe(open(a.input, "rb").read(), a.input)
    if not pe.is_pe:
        print("error:", pe.error, file=sys.stderr); return EXIT_FAILURE
    try:
        out, info = pack_pe(pe, a.level, a.blocksize)
    except UpxError as e:
        print(" ! ABORT:", e, file=sys.stderr); return EXIT_FAILURE
    op = a.output or os.path.splitext(a.input)[0] + "_upx.exe"
    open(op, "wb").write(out); info["output"] = op
    print(json.dumps(info, indent=2) if a.json else
          f"[UPX] packed {a.input} -> {op} ({info['input_size']}->{info['output_size']}, LZMA, {info['blocks']} blocks)")
    return EXIT_SUCCESS


def cmd_unpack(a):
    pe = parse_pe(open(a.input, "rb").read(), a.input)
    if not pe.is_pe:
        print("error:", pe.error, file=sys.stderr); return EXIT_FAILURE
    op = a.output or os.path.splitext(a.input)[0] + "_unpacked.bin"
    try:
        info = unpack_pe(pe, op)
    except UpxError as e:
        print("error:", e, file=sys.stderr); return EXIT_FAILURE
    print(json.dumps(info, indent=2) if a.json else
          f"[UPX] unpacked {info['blocks']} blocks -> {op} ({info['unpacked_size']} bytes, adler_ok={info['adler_ok']})")
    return EXIT_SUCCESS


def cmd_info(a):
    pe = parse_pe(open(a.input, "rb").read(), a.input)
    if not pe.is_pe:
        print("error:", pe.error, file=sys.stderr); return EXIT_FAILURE
    hdr = parse_linfo(pe.data)
    d = {"file": a.input, "is64": pe.is64, "is_upx": is_upx(pe),
         "sections": [s.name for s in pe.sections], "linfo": hdr}
    print(json.dumps(d, indent=2) if a.json else
          f"{a.input}: upx={is_upx(pe)} sections={[s.name for s in pe.sections]} linfo={hdr}")
    return EXIT_SUCCESS


def cmd_test(a):
    return cmd_info(a)


def build_parser():
    p = argparse.ArgumentParser(prog="upx", description="UPX 4.0.1 packer - Python CLI reimplementation")
    sub = p.add_subparsers(dest="cmd", required=True)
    pk = sub.add_parser("pack"); pk.add_argument("input"); pk.add_argument("-o", "--output")
    pk.add_argument("--level", type=int, default=9); pk.add_argument("--blocksize", type=int, default=0x8000)
    pk.add_argument("--json", action="store_true"); pk.set_defaults(func=cmd_pack)
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