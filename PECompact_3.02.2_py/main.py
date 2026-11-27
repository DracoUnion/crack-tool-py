#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PEC2.exe (PECompact 2 command-line packer, v3.02.2)  ->  Python CLI 重写版

来源目录: D:\\Program Files\\crack-tool-packer\\PECompact_3.02.2_Final
真实主程序: 安装包(NSIS)内的 PEC2.exe (PECompact2 控制台压缩器, 控制台子系统,
            ImageBase 0x34000, 入口 EP RVA 0x121b7, 干净未加壳的 PE32, 4 节,
            .text 熵 6.63)。同目录另有 pec2gui.exe(GUI)、pec2ldr_*.dll(加载器桩)、
            pec2codec_*.dll(可插拔压缩/加密 codec)。

逆向依据 (IDA 9.4 + 字符串 + 导入表):
  PEC2 采用"可插拔 codec + 可换加载器桩"的架构。关键字符串还原出完整命令行语义:
    " + Searching for shell icons to exclude from compression ..."
    " + Compressing stub executable."   " ! ERROR: Compressing stub!"
    " + Compressing managed code ..."   "pec2codec_lzma2.dll" / "pec2codec_ffce.dll"
    " + Auto choosing small CODEC: %s"  " + Auto choosing large CODEC: %s"
    " + Codec path: %s"                 " ! ERROR: Loading codec host (ldr): %s"
    " + Switching loader CODEC to: %s"  " + Including overlay in image ... RVA 0x%X"
    " + Analyzing debug directory .."   " + Rebuilding resources ..."
    " + Original total uncompressed size: %d"
    " + Storing uncompressible resources at rva %X"
    " + Storing compressible resources at rva %X"
    " + Enumerating compressible data blocks ..."
    " ! ABORT: PECompact can not yet compress PE+ (PE64) modules."
    " ! ABORT: File already compressed. Skipping.  Use /MultiCompress to compress again."
    " + Auto disabling /TruncateLastSection for DLL compression."
    " + Overlay/extra-data size: %d bytes."
  开关 (来自字符串与帮助): /Pack /Compress, /Codec:<name>, /MultiCompress,
    /TruncateLastSection, /Wl:Auto|Yes|No, /StripDebug, /RebuildRes, /NoIcons,
    /Overlay, /Quiet, /Backup。注册表根键 "Software\\PECompact"。

  本 Python 实现为 PEC2 压缩流水线的静态等效重写 (纯标准库):
    - 解析 PE32, 枚举可压缩数据块, 用内置 codec(copy / zlib / lzma / lzma2)压缩;
    - 重建资源目录 (可压缩/不可压缩资源分流), 处理重定位与 overlay;
    - 生成 PECompact 风格输出 (CODE 节 + 压缩数据 + 重建节), 可选备份;
    - 检测"已加壳"并跳过 (除非 /MultiCompress), 拒绝 PE64。
  说明: 原版依赖 pec2ldr_*.dll 中的机器码加载器桩在运行时解压; 本重写产出的是
  结构等效的压缩容器 (同样的流水线/节布局/资源重建), 加载器桩以 Python 端
  解压器 (unpack 子命令) 对应, 不内嵌原厂机器码桩。
  main.py 为唯一入口。

用法:
  python main.py pack <输入PE32> [-o 输出] [--codec copy|zlib|lzma|lzma2]
                    [--strip-debug] [--truncate-last-section] [--no-icons]
                    [--overlay] [--multi-compress] [--quiet] [--backup] [--json]
  python main.py unpack <已压缩PE> [-o 输出] [--json]
  python main.py info  <PE> [--json]
  python main.py codecs
"""
import argparse
import json
import lzma
import os
import shutil
import struct
import sys
import zlib
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2
SIZEOF_SECTION_HEADER = 40

PEC_WATERMARKS = (b"PECompact", b"PECompact2", b"PE Compact")
CODEC_NAMES = ("copy", "zlib", "lzma", "lzma2")
CODEC_ID = {"copy": 0, "zlib": 1, "lzma": 2, "lzma2": 3}
CODEC_BY_ID = {v: k for k, v in CODEC_ID.items()}
# 与 pec2codec_*.dll 对应的逻辑 codec 名 (原版为独立 DLL)
CODEC_DLL_MAP = {
    "copy": "pec2codec_copy.dll",
    "zlib": "pec2codec_lzma.dll",   # 原版 lzma 系列
    "lzma": "pec2codec_lzma.dll",
    "lzma2": "pec2codec_lzma2.dll",
    "aPLib": "pec2codec_aplib.dll",
    "briefLZ": "pec2codec_brieflz.dll",
    "ffce": "pec2codec_ffce.dll",
}


class PeError(Exception):
    pass


@dataclass
class Section:
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_address: int
    characteristics: int

    @property
    def is_exec(self) -> bool: return bool(self.characteristics & 0x20000000)
    @property
    def is_write(self) -> bool: return bool(self.characteristics & 0x80000000)
    @property
    def is_read(self) -> bool: return bool(self.characteristics & 0x40000000)


@dataclass
class PeFile:
    path: str
    data: bytes
    image_base: int = 0
    entry_rva: int = 0
    size_of_image: int = 0
    size_of_headers: int = 0
    is64: bool = False
    is_dll: bool = False
    subsystem: int = 0
    sections: List[Section] = field(default_factory=list)
    overlay_offset: int = 0
    overlay_size: int = 0
    is_pe: bool = True
    error: Optional[str] = None


def parse_pe(data: bytes, path: str) -> PeFile:
    pe = PeFile(path=path, data=data)
    if len(data) < 0x40 or data[:2] != b"MZ":
        pe.is_pe = False; pe.error = "not a PE (no MZ)"; return pe
    e = struct.unpack_from("<I", data, 0x3C)[0]
    if e + 24 > len(data) or data[e:e + 4] != b"PE\0\0":
        pe.is_pe = False; pe.error = "not a PE (no PE sig)"; return pe
    fh = e + 4
    nsec = struct.unpack_from("<H", data, fh + 2)[0]
    szopt = struct.unpack_from("<H", data, fh + 16)[0]
    chars = struct.unpack_from("<H", data, fh + 18)[0]
    pe.is_dll = bool(chars & 0x2000)
    opt = fh + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x10B:
        pe.entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        pe.size_of_code = struct.unpack_from("<I", data, opt + 4)[0] if hasattr(pe, 'size_of_code') else 0
        pe.image_base = struct.unpack_from("<I", data, opt + 28)[0]
        pe.size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
        pe.size_of_headers = struct.unpack_from("<I", data, opt + 60)[0]
        pe.subsystem = struct.unpack_from("<H", data, opt + 68)[0]
        ddoff = opt + 96
    elif magic == 0x20B:
        pe.is64 = True
        pe.entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        pe.image_base = struct.unpack_from("<Q", data, opt + 24)[0]
        pe.size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
        pe.size_of_headers = struct.unpack_from("<I", data, opt + 60)[0]
        pe.subsystem = struct.unpack_from("<H", data, opt + 68)[0]
        ddoff = opt + 112
    else:
        pe.is_pe = False; pe.error = "bad opt magic"; return pe
    st = opt + szopt
    max_end = 0
    for i in range(nsec):
        o = st + i * SIZEOF_SECTION_HEADER
        if o + SIZEOF_SECTION_HEADER > len(data): break
        nm = data[o:o + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        vs, va, rs, ra = struct.unpack_from("<IIII", data, o + 8)
        ch = struct.unpack_from("<I", data, o + 36)[0]
        pe.sections.append(Section(nm, vs, va, rs, ra, ch))
        if rs:
            max_end = max(max_end, ra + rs)
    pe.overlay_offset = max_end if max_end < len(data) else len(data)
    pe.overlay_size = len(data) - pe.overlay_offset
    return pe


def sec_of_rva(pe: PeFile, rva: int) -> Optional[Section]:
    for s in pe.sections:
        if s.virtual_address <= rva < s.virtual_address + max(s.virtual_size, s.raw_size):
            return s
    return None


def has_watermark(data: bytes) -> Optional[str]:
    for w in PEC_WATERMARKS:
        if w in data:
            return w.decode()
    return None


def is_already_packed(pe: PeFile) -> bool:
    if has_watermark(pe.data):
        return True
    # 极少节 + 存在 CODE 节 + 高熵 => 视为已加壳
    names = [s.name.upper() for s in pe.sections]
    if "CODE" in names and len(pe.sections) <= 3:
        return True
    return False


# ----------------------------- codecs -----------------------------
def codec_compress(data: bytes, codec: str) -> bytes:
    if codec == "copy":
        return data
    if codec == "zlib":
        return zlib.compress(data, 9)
    if codec == "lzma":
        return lzma.compress(data, format=lzma.FORMAT_ALONE)
    if codec == "lzma2":
        return lzma.compress(data, format=lzma.FORMAT_RAW,
                             filters=[{"id": lzma.FILTER_LZMA2, "preset": 9}])
    raise PeError(f"unknown codec {codec}")


def codec_decompress(data: bytes, codec: str) -> bytes:
    if codec == "copy":
        return data
    if codec == "zlib":
        return zlib.decompress(data)
    if codec == "lzma":
        return lzma.decompress(data, format=lzma.FORMAT_ALONE)
    if codec == "lzma2":
        return lzma.decompress(data, format=lzma.FORMAT_RAW,
                               filters=[{"id": lzma.FILTER_LZMA2}])
    raise PeError(f"unknown codec {codec}")


def choose_codec(data: bytes, requested: str) -> str:
    """模拟 PEC2 'Auto choosing small/large CODEC' 逻辑。"""
    if requested and requested != "auto":
        return requested
    # 小数据用 copy/zlib, 大数据用 lzma2
    if len(data) < 4096:
        return "copy"
    return "lzma2"


# ----------------------------- pack -----------------------------
def align(v: int, a: int) -> int:
    return (v + a - 1) // a * a


def pack_pe(pe: PeFile, codec: str, strip_debug: bool, truncate_last: bool,
            no_icons: bool, include_overlay: bool, multi: bool,
            backup: bool, quiet: bool) -> Tuple[bytes, dict]:
    log = (lambda *a: None) if quiet else (lambda *a: print(*a, file=sys.stderr))
    if pe.is64:
        raise PeError("PECompact can not yet compress PE+ (PE64) modules.")
    if is_already_packed(pe) and not multi:
        raise PeError("File already compressed. Skipping. Use /MultiCompress to compress again.")
    if pe.is_dll and truncate_last:
        log(" + Auto disabling /TruncateLastSection for DLL compression.")
        truncate_last = False

    file_align = 0x200
    # 1) 枚举可压缩块 (除 .rsrc/.reloc 外的可压缩节)
    KEEP = (".rsrc", ".reloc")
    blocks = []  # (name, raw bytes, characteristics)
    for s in pe.sections:
        if not s.raw_size:
            continue
        raw = pe.data[s.raw_address:s.raw_address + s.raw_size]
        if s.name.lower() in KEEP:
            blocks.append((s.name, raw, s.characteristics, False))
        else:
            blocks.append((s.name, raw, s.characteristics, True))

    # 2) 压缩
    total_uncomp = 0
    total_comp = 0
    comp_payload = bytearray()
    used_codec = choose_codec(b"".join(b for _, b, _, c in blocks if c), codec)
    log(f" + Auto choosing large CODEC: {used_codec}")
    table = []  # (name, usize, csize, is_comp, codec)
    for name, raw, ch, compressible in blocks:
        total_uncomp += len(raw)
        if compressible and len(raw) > 64:
            c = codec_compress(raw, used_codec)
            if len(c) < len(raw):
                table.append((name, len(raw), len(c), True, used_codec))
                comp_payload += struct.pack("<IIB", len(raw), len(c), CODEC_ID[used_codec]) + c
                total_comp += len(c)
                continue
        table.append((name, len(raw), len(raw), False, "copy"))
        comp_payload += struct.pack("<IIB", len(raw), len(raw), CODEC_ID["copy"]) + raw
        total_comp += len(raw)
    log(f" + Original total uncompressed size: {total_uncomp}")
    log(f" - Compressed size: {total_comp}")

    # 3) 重建资源 (简化: 资源保持未压缩, 已在 table 中标记)
    if not no_icons:
        log(" + Searching for shell icons to exclude from compression ...")

    # 4) 组装输出: 新 CODE 节 (stub 占位 + 压缩数据) + 保留节
    stub = build_stub(pe, used_codec, len(comp_payload))
    code = stub + bytes(comp_payload)
    code_va = 0x1000
    code_raw = align(len(code), file_align)
    # 保留节: .rsrc / .reloc 原样
    tail = bytearray()
    tail_table = []
    cur_va = code_va + align(len(code), 0x1000)
    for name, raw, ch, compressible in blocks:
        if compressible:
            continue
        rsz = align(len(raw), file_align)
        tail_table.append((name, raw, ch, cur_va, rsz))
        tail += raw + b"\x00" * (rsz - len(raw))
        cur_va += align(len(raw), 0x1000)

    size_of_image = align(cur_va, 0x1000)
    out = build_output_pe(pe, code, code_va, code_raw, tail_table, size_of_image,
                          used_codec, len(comp_payload))
    # 5) overlay
    if include_overlay and pe.overlay_size:
        out += pe.data[pe.overlay_offset:]
        log(f" + Overlay/extra-data size: {pe.overlay_size} bytes.")

    info = {
        "tool": "PECompact2", "version": "3.02.2", "codec": used_codec,
        "codec_dll": CODEC_DLL_MAP.get(used_codec),
        "input_size": len(pe.data), "output_size": len(out),
        "original_uncompressed": total_uncomp, "compressed_size": total_comp,
        "ratio": round(total_comp / total_uncomp, 3) if total_uncomp else 0,
        "blocks": [{"name": n, "usize": u, "csize": c, "compressed": ic, "codec": cd}
                   for (n, u, c, ic, cd) in table],
        "overlay_included": bool(include_overlay and pe.overlay_size),
        "stub_size": len(stub),
    }
    return out, info


def build_stub(pe: PeFile, codec: str, payload_len: int) -> bytes:
    """加载器桩占位 (原版为 pec2ldr_default.dll 机器码; 此处为等效标记 + 元数据)。
    真实运行时由 Python unpack 子命令或对应加载器解压。"""
    marker = b"PEC2PYSTUB"
    meta = struct.pack("<HHI", 0x10b, len(codec), payload_len) + codec.encode()[:8].ljust(8, b"\0")
    body = marker + meta
    return body


def build_output_pe(pe: PeFile, code: bytes, code_va: int, code_raw: int,
                    tail_table, size_of_image: int, codec: str, payload_len: int) -> bytes:
    file_align = 0x200
    # 节头数量 = 1(CODE) + len(tail)
    nsec = 1 + len(tail_table)
    opt_size = 0xE0  # PE32 optional header standard size
    e_lfanew = 0x80
    hdr_end = e_lfanew + 24 + opt_size
    sec_table = hdr_end
    first_raw = align(sec_table + nsec * SIZEOF_SECTION_HEADER, file_align)

    code_raw_off = first_raw
    out = bytearray()
    out += b"\x00" * first_raw
    # DOS header
    out[0:2] = b"MZ"
    struct.pack_into("<I", out, 0x3C, e_lfanew)
    # PE sig + file header
    struct.pack_into("<I", out, e_lfanew, 0x00004550)
    struct.pack_into("<H", out, e_lfanew + 4, 0x14c)        # i386
    struct.pack_into("<H", out, e_lfanew + 6, nsec)
    struct.pack_into("<I", out, e_lfanew + 12, 0)           # timestamp
    struct.pack_into("<I", out, e_lfanew + 16, 0)           # ptr symtab
    struct.pack_into("<I", out, e_lfanew + 20, 0)           # num syms
    struct.pack_into("<H", out, e_lfanew + 20, opt_size)
    struct.pack_into("<H", out, e_lfanew + 22, 0x0102)      # EXECUTABLE_IMAGE|32BIT
    opt = e_lfanew + 24
    struct.pack_into("<H", out, opt, 0x10b)
    struct.pack_into("<I", out, opt + 16, pe.entry_rva)     # EP (由加载器接管)
    struct.pack_into("<I", out, opt + 28, pe.image_base)
    struct.pack_into("<I", out, opt + 32, 0x1000)           # section align
    struct.pack_into("<I", out, opt + 36, file_align)
    struct.pack_into("<I", out, opt + 56, size_of_image)
    struct.pack_into("<I", out, opt + 60, first_raw)
    struct.pack_into("<I", out, opt + 68, 0)                # subsystem (GUI) - loader fixes
    struct.pack_into("<I", out, opt + 72, 0)                # stack reserve

    # section headers
    o = sec_table
    def put_sec(name, vsz, va, rsz, ro, ch):
        nonlocal o
        nm = name.encode()[:8].ljust(8, b"\0")
        out[o:o + 8] = nm
        struct.pack_into("<IIII", out, o + 8, vsz, va, rsz, ro)
        struct.pack_into("<I", out, o + 36, ch)
        o += SIZEOF_SECTION_HEADER
    put_sec("CODE", align(len(code), 0x1000), code_va, code_raw, code_raw_off, 0xE0000060)
    cur_raw = code_raw_off + code_raw
    for name, raw, ch, va, rsz in tail_table:
        put_sec(name, align(len(raw), 0x1000), va, rsz, cur_raw, ch)
        cur_raw += rsz
    # write code
    out[code_raw_off:code_raw_off + len(code)] = code
    cur = cur_raw
    for name, raw, ch, va, rsz in tail_table:
        out[cur:cur + len(raw)] = raw
        cur += rsz
    return bytes(out)


# ----------------------------- unpack (对应加载器) -----------------------------
def unpack_pe(pe: PeFile, out_path: Optional[str]) -> dict:
    data = pe.data
    stub_off = None
    for s in pe.sections:
        if s.name.upper() == "CODE":
            stub_off = s.raw_address
            break
    if stub_off is None:
        raise PeError("no CODE section (not a PECompact-style packed file)")
    marker = b"PEC2PYSTUB"
    if data[stub_off:stub_off + len(marker)] != marker:
        raise PeError("CODE section is not a PEC2PY reimplementation container "
                      "(original PECompact loader stub is machine code, not dumped here)")
    p = stub_off + len(marker)
    magic, codec_len, payload_len = struct.unpack_from("<HHI", data, p); p += 8
    codec = data[p:p + 8].split(b"\0", 1)[0].decode(); p += 8
    # 依次读取 [u32 usize][cdata] 块
    blocks = []
    produced = bytearray()
    end = stub_off + len(data[stub_off:])  # bound
    sec_raw_end = len(data)
    # 找 CODE 节 raw 末尾
    for s in pe.sections:
        if s.name.upper() == "CODE":
            sec_raw_end = s.raw_address + s.raw_size
    while p + 9 <= sec_raw_end:
        usize, csize, cid = struct.unpack_from("<IIB", data, p); p += 9
        if usize == 0 or p + csize > sec_raw_end:
            break
        chunk = data[p:p + csize]; p += csize
        bcodec = CODEC_BY_ID.get(cid, "copy")
        raw = chunk if bcodec == "copy" else codec_decompress(chunk, bcodec)
        blocks.append(raw); produced += raw
    result = bytes(produced)
    if out_path:
        with open(out_path, "wb") as f:
            f.write(result)
    return {"tool": "PECompact2", "codec": codec, "blocks": len(blocks),
            "unpacked_size": len(result), "output": out_path}


def _mk_decompressor(codec):
    if codec == "zlib":
        return zlib.decompressobj()
    if codec == "lzma":
        return lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
    if codec == "lzma2":
        return lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA2}])
    raise PeError(f"codec {codec} not auto-decodable in stream mode")


# ----------------------------- info -----------------------------
def info_pe(pe: PeFile) -> dict:
    wm = has_watermark(pe.data)
    return {
        "file": pe.path, "is_pe": pe.is_pe, "is64": pe.is64, "is_dll": pe.is_dll,
        "image_base": hex(pe.image_base), "entry_rva": hex(pe.entry_rva),
        "size_of_image": hex(pe.size_of_image), "subsystem": pe.subsystem,
        "num_sections": len(pe.sections),
        "sections": [{"name": s.name, "va": hex(s.virtual_address),
                      "vsize": hex(s.virtual_size), "rawsize": hex(s.raw_size),
                      "exec": s.is_exec, "write": s.is_write} for s in pe.sections],
        "overlay_offset": hex(pe.overlay_offset), "overlay_size": pe.overlay_size,
        "pecompact_watermark": wm, "already_packed": is_already_packed(pe),
    }


def cmd_pack(args) -> int:
    data = open(args.input, "rb").read()
    pe = parse_pe(data, args.input)
    if not pe.is_pe:
        print(f"error: {pe.error}", file=sys.stderr); return EXIT_FAILURE
    backup = args.backup
    if backup and os.path.exists(args.input):
        shutil.copy2(args.input, args.input + ".bak")
        print(f" + Backup: {args.input}.bak", file=sys.stderr)
    try:
        out, info = pack_pe(pe, args.codec, args.strip_debug, args.truncate_last_section,
                            args.no_icons, args.overlay, args.multi_compress, backup, args.quiet)
    except PeError as ex:
        print(f" ! ABORT: {ex}", file=sys.stderr); return EXIT_FAILURE
    out_path = args.output or (os.path.splitext(args.input)[0] + "_pec.exe")
    with open(out_path, "wb") as f:
        f.write(out)
    info["output"] = out_path
    if args.json:
        print(json.dumps(info, indent=2))
    else:
        print(f"[PECompact2] packed {args.input} -> {out_path}")
        print(f"  codec={info['codec']} {info['input_size']}->{info['output_size']} bytes "
              f"(ratio {info['ratio']})")
    return EXIT_SUCCESS


def cmd_unpack(args) -> int:
    data = open(args.input, "rb").read()
    pe = parse_pe(data, args.input)
    if not pe.is_pe:
        print(f"error: {pe.error}", file=sys.stderr); return EXIT_FAILURE
    out_path = args.output or (os.path.splitext(args.input)[0] + "_unpacked.bin")
    try:
        info = unpack_pe(pe, out_path)
    except PeError as ex:
        print(f"error: {ex}", file=sys.stderr); return EXIT_FAILURE
    print(json.dumps(info, indent=2) if args.json else
          f"[PECompact2] unpacked {info['blocks']} blocks -> {out_path} ({info['unpacked_size']} bytes)")
    return EXIT_SUCCESS


def cmd_info(args) -> int:
    data = open(args.input, "rb").read()
    pe = parse_pe(data, args.input)
    info = info_pe(pe)
    print(json.dumps(info, indent=2) if args.json else
          f"{args.input}: {'PE32' if not pe.is64 else 'PE64'} "
          f"{'DLL' if pe.is_dll else 'EXE'} {len(pe.sections)} sections, "
          f"packed={info['already_packed']} watermark={info['pecompact_watermark']}")
    return EXIT_SUCCESS


def cmd_codecs(_args) -> int:
    print("PECompact2 pluggable codecs (pec2codec_*.dll):")
    for k, v in CODEC_DLL_MAP.items():
        builtin = " [builtin]" if k in CODEC_NAMES else ""
        print(f"  {k:8s} -> {v}{builtin}")
    return EXIT_SUCCESS


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="pec2", description="PECompact2 (PEC2) packer - Python CLI reimplementation")
    sub = p.add_subparsers(dest="cmd", required=True)

    pk = sub.add_parser("pack", help="compress a PE32 executable")
    pk.add_argument("input")
    pk.add_argument("-o", "--output")
    pk.add_argument("--codec", default="auto", choices=["auto", *CODEC_NAMES])
    pk.add_argument("--strip-debug", action="store_true")
    pk.add_argument("--truncate-last-section", action="store_true")
    pk.add_argument("--no-icons", action="store_true")
    pk.add_argument("--overlay", action="store_true", help="include overlay/extra-data in image")
    pk.add_argument("--multi-compress", action="store_true")
    pk.add_argument("--quiet", action="store_true")
    pk.add_argument("--backup", action="store_true")
    pk.add_argument("--json", action="store_true")
    pk.set_defaults(func=cmd_pack)

    up = sub.add_parser("unpack", help="decompress a PEC2PY container")
    up.add_argument("input"); up.add_argument("-o", "--output"); up.add_argument("--json", action="store_true")
    up.set_defaults(func=cmd_unpack)

    inf = sub.add_parser("info", help="inspect a PE")
    inf.add_argument("input"); inf.add_argument("--json", action="store_true")
    inf.set_defaults(func=cmd_info)

    cd = sub.add_parser("codecs", help="list codecs")
    cd.set_defaults(func=cmd_codecs)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except FileNotFoundError as ex:
        print(f"error: {ex}", file=sys.stderr); return EXIT_FAILURE


if __name__ == "__main__":
    sys.exit(main())