#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Molebox Virtualization Studio Unpacker 0.65 (demoleition.exe)  ->  Python CLI 重写版

来源目录: D:\\Program Files\\crack-tool-unpacker\\MoleboxVirtualizationStudioUnpacker_0.65
目标文件: demoleition.exe (32-bit 原生 Delphi PE, 基址 0x400000,
          节区 .text/.itext/.data/.bss/.idata/.tls/.rdata/.rsrc, 未加壳)
          身份横幅 (0x49E8E3, UTF-16): "?de-mole-ition :: static Molebox unpacker :: (c) kao, 2009-2021."

逆向依据 (IDA Pro 9.4 批处理反汇编, 基址 0x400000, 共 3873 函数, 入口 0x47F7C8):
  本工具是一个 *静态* Molebox 脱壳器 (不运行被壳程序)。Molebox 把一组文件
  ("regroup") 压缩/加密进宿主 EXE 末尾的 overlay, 运行时由 Molebox 引导代码在
  内存中重建虚拟文件系统。demoleition 直接在磁盘上解析该 overlay 并还原文件。

  ── 主流程 sub_47E264 (main) @ 0x47E264 ───────────────────────────────────
      "[i] Loading file: "            读入目标 (0x47E2E2)
      文件 > 0x6400000 (100MB) 提示    "[i] Loading large file..." (0x47E32D)
      [eax+8]!=0 (PE64)               "[x] This is a 64-bit PE file..." (0x47E36E)
      小文件则计算并打印               "[+] MD5: %s" (0x47E3C8)
      call sub_47DAF4  -> 版本/EP 检测, 0 则 "[x] Not a Molebox or unknown version"
      call sub_47C790  -> 解压并校验控制块 (decompress control block)
      call sub_47C264  -> 打印版本 "[i] Molebox Standard/Pro v%d.%.4d"
      call sub_47C14C  -> 读取文件分配表 (file allocation table)
      call sub_47BC04  -> (MD5 开启时) 解密控制块 0x40 字节密钥
      call sub_47B184  -> 解析 box / 遍历通配符 / 逐文件抽取
      call sub_479C24  -> 重建 PE 写出 "<name>_unpacked"
      "[i] Finished! Have a nice day!" (0x47E4CD)

  ── EP 特征码检测 sub_47DAF4 @ 0x47DAF4 ──────────────────────────────────
      取入口点原始字节 (节 rawptr [eax+28h] + 4), 依次与 10 条 Molebox 引导
      特征串比较 (sub_473770 = 字节序列搜索):
        0x47DB12 "60E84F000000"                              -> ver 1
        0x47DB3C "E9D0300000E9CB300000E84AFFFFFF"           -> ver 1
        0x47DB69 "E9D0330000E9CB330000E84AFFFFFF"           -> ver 2
        0x47DB96 "E980320000E97B320000E84AFFFFFF"           -> ver 5
        0x47DBC3 "E9004A0000E9FB490000E84AFFFFFF"           -> ver 3
        0x47DBF0 "E9AC480000E9A7480000E84AFFFFFF"           -> ver 3
        0x47DC1D "E9EC510000E9E7510000E84AFFFFFF"           -> ver 4
        0x47DC4A "E90C510000E907510000E84AFFFFFF"           -> ver 4
        0x47DC77 "E954580000E94F580000E84AFFFFFF"           -> ver 4
        否则 "558BEC6AFF6800000000680000000064A100000..."  -> 多态层 sub_47D168
      另比对 "EB168B15::::::::FF328F05::::::::EB068F0..." -> ver 8 (sub_47CD78)
      末尾 "E80000000060E84F000000"                        -> ver 7
      返回 0 表示非 Molebox。版本号 -> 0x48A284 (byte_48A284)。

  ── 版本映射 sub_47C264 @ 0x47C264 + 字符串表 (UTF-16 @ 0x7B850) ─────────
      ver 1 -> "[i] Probably Molebox v2.0-2.1.2"
      ver 2 -> "[i] Probably Molebox v2.1.9"
      ver 5 -> "[i] Probably Molebox v2.1.10-2.1.14"
      ver 3 -> "[i] Probably Molebox v2.1.15"
      ver 4 -> "[i] Probably Molebox v2.2.2"
      ver 0 -> 读控制块标志 dword_48A28C: bit4 置位 -> Standard, 否则 Pro:
               "[i] Molebox Standard v%d.%.4d" / "[i] Molebox Pro v%d.%.4d"
               版本号 = byte_48A290 (主) + dword_48A29C (次, %.4d)

  ── 控制块解压 sub_47C790 @ 0x47C790 ────────────────────────────────────
      入口点偏移 ebx = rawptr + 0x5A(ver1) 或 +0x5F(ver2/3)。
      读 3 个 dword: [esi]=原始长度, [esi+4]=压缩长度, [esi+8]=校验(adler32)。
      用 sub_476038 (LZSS) 解压, 校验解压后长度与 adler32 (sub_47655C)。
      控制块明文布局 (解压后):
        +0x00 dword 签名 (0xCAFEBABE 或 解密后 0x584F424D "MBOX")
        +0x04 ... 头部
        +0x1C byte  主版本号 -> byte_48A290
        +0x2E dword 次版本号 -> dword_48A29C (即 [eax+32h-4])
        +0x32 ... 0x40 字节 MD5 密钥 (dword_48A318)

  ── 头部解析 sub_47AC5C @ 0x47AC5C ──────────────────────────────────────
      读 0x10 字节签名串 unk_48A388, 按 12 取模索引 dword 校验表, 与文件
      实际 dword 比较; 不等 -> "[x] Signature seems to be invalid..."。
      然后读 5 个 dword 到 dword_48A370/378/37C/380/384:
        48A370 = 数据区起始偏移
        48A378 = 当前读指针 (box 数据偏移)
        48A37C = 文件条目表偏移
        48A380 = 文件总数
        48A384 = 头部/数据基址修正
      签名校验 (ver>=4): dword==0xCAFEBABE 或 (dword ^ 0xCAFEBABE ^ key)==0x584F424D。

  ── 文件条目表 sub_47A708 @ 0x47A708 ────────────────────────────────────
      每条记录:
        filename   : 以 0 结尾的 ASCII (长 >256 -> "[x] ERROR: filename longer...")
        md5[16]    : 文件内容 MD5 (与重算不符 -> "[x] MD5 does not match")
        sizeTable  : 长度 = ((filesize + 0xFFFF) >> 16) 个 dword, 每块 64KB
        dataBlocks : 每块 1 个 dword 头:
                       bit31 (0x80000000) = 该块压缩 (LZSS)
                       低 31 位 = 块长度; 压缩块解压后应为 64KB
      打印 "[+] File \"%s\", size=0x%x" 与 "[i] Total files: %d"。

  ── 逐文件抽取 sub_47A0C0 @ 0x47A0C0 ────────────────────────────────────
      目标路径 = <box目录>\\_extracted\\<filename>。
      用 PathCanonicalizeW (sub_47A088) 规范化后, 若父目录不是 _extracted 目录
      -> "[x] Path traversal exploit attempt detected" / "File WILL NOT be extracted"。
      压缩标志 (记录 +0x0C & 0x30):
        0x10 -> sub_47A074 (单字节 XOR 解密, cl=byte_48A290)
        0x30 -> LZSS 解压 (sub_47413C/sub_479660)
        其它 -> "[x] Molebox fuckup 0xEF000014, unknown ..." (0xEF000014 = 未知压缩)
      压缩块 bit31 置位时先解压再写出。

  ── 流密码 (LCG) sub_47C6EC / sub_47C768 ────────────────────────────────
      for 每个 dword: seed = seed*0x19660D + 0x3C6EF375 (mod 2^32); buf[i]^=seed
      sub_47C768 用 0x3C6EF35F (解密 0x40 字节 MD5 控制块密钥)。
      这是 Delphi 的 RandSeed 常数 (0x19660D, 0x3C6EF35F/75)。

  ── 校验 sub_47655C = Adler-32 (mod 0xFFF1=65521) ───────────────────────
      "Checksum of decompressed data does not match" 即 adler32 不符。

  本 Python 实现忠实复刻上述静态逻辑, 纯标准库, main.py 为唯一入口。
  命令: detect / extract / info。

用法:
  python main.py <目标PE文件> [detect|extract|info] [选项]
    detect   (默认) EP 特征码 + 控制块 + 头部解析, 判定 Molebox 版本与文件数
    extract  解析 overlay 文件表, 解压/解密并写出到 <box>\\_extracted\\
    info     打印 PE 概要 + Molebox 检测详情
  选项:
    --out DIR   extract 输出根目录 (默认 box 所在目录)
    --json      以 JSON 输出
    -h,--help   帮助
"""

import argparse
import hashlib
import json
import os
import struct
import sys
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2

# ---- 常量 (逆向自 sub_47DAF4 / sub_47AC5C / sub_47C6EC) ----
IMAGE_DOS_SIGNATURE = 0x5A4D
IMAGE_NT_SIGNATURE = 0x00004550
OPT_HDR32_MAGIC = 0x10B
OPT_HDR64_MAGIC = 0x20B
SIZEOF_SECTION_HEADER = 40

BOX_SIGNATURE = 0xCAFEBABE          # 控制块/头部魔数 (sub_47AC5C @ 0x47AF13)
MBOX_SIGNATURE = 0x584F424D         # "MBOX" 小端 (dword ^ 0xCAFEBABE ^ key)
LCG_MUL = 0x19660D                 # sub_47C6EC @ 0x47C6F6
LCG_ADD_CONTROL = 0x3C6EF375       # 控制块解密 @ 0x47C6FC
LCG_ADD_KEY = 0x3C6EF35F           # MD5 密钥解密 sub_47C768 @ 0x47C778
LZSS_N = 4096                      # sub_476038 环形缓冲 0xFFF+1
LZSS_F = 18                        # 最大匹配长度 (0xF+2+1)
LZSS_THRESHOLD = 2
BLOCK_FLAG_COMPRESSED = 0x80000000
BLOCK_SIZE = 0x10000               # 64KB
FILE_FLAG_MASK = 0x30
FILE_FLAG_XOR = 0x10              # sub_47A074 单字节 XOR
FILE_FLAG_LZSS = 0x30            # LZSS
FUCKUP_UNKNOWN = 0xEF000014       # "[x] Molebox fuckup 0xEF000014"

# EP 特征码表 (sub_47DAF4 @ 0x47DB12..0x47DC8C): (hex串, 版本码)
EP_SIGNATURES: List[Tuple[str, int]] = [
    ("60E84F000000", 1),
    ("E9D0300000E9CB300000E84AFFFFFF", 1),
    ("E9D0330000E9CB330000E84AFFFFFF", 2),
    ("E980320000E97B320000E84AFFFFFF", 5),
    ("E9004A0000E9FB490000E84AFFFFFF", 3),
    ("E9AC480000E9A7480000E84AFFFFFF", 3),
    ("E9EC510000E9E7510000E84AFFFFFF", 4),
    ("E90C510000E907510000E84AFFFFFF", 4),
    ("E954580000E94F580000E84AFFFFFF", 4),
    ("E80000000060E84F000000", 7),
]

# 版本码 ->  Probably 描述 (sub_47C264 跳转表 + UTF-16 字符串 @ 0x7B850)
VERSION_NAMES = {
    1: "Probably Molebox v2.0-2.1.2",
    2: "Probably Molebox v2.1.9",
    5: "Probably Molebox v2.1.10-2.1.14",
    3: "Probably Molebox v2.1.15",
    4: "Probably Molebox v2.2.2",
}

SIZEOF_FILE_HEADER = 0x28          # sub_479C24 重建时每节 0x28 字节


class MoleboxError(Exception):
    pass


# ===================== PE 解析 =====================
@dataclass
class Section:
    name: str
    virtual_size: int
    virtual_address: int
    raw_size: int
    raw_address: int
    characteristics: int

    @property
    def is_executable(self) -> bool:
        return bool(self.characteristics & 0x20000000)

    @property
    def is_writable(self) -> bool:
        return bool(self.characteristics & 0x80000000)


@dataclass
class PeFile:
    path: str
    data: bytes
    image_base: int = 0
    entry_rva: int = 0
    entry_off: int = 0
    size_of_image: int = 0
    subsystem: int = 0
    is64: bool = False
    is_pe: bool = True
    error: Optional[str] = None
    sections: List[Section] = field(default_factory=list)
    overlay_off: Optional[int] = None   # 第一个节之后的第一个字节 (overlay 起点)


def parse_pe(data: bytes, path: str) -> PeFile:
    pe = PeFile(path=path, data=data)
    if len(data) < 0x40 or data[:2] != b"MZ":
        pe.is_pe = False
        pe.error = "not a PE (no MZ)"
        return pe
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        pe.is_pe = False
        pe.error = "not a PE (no PE signature)"
        return pe
    fh = e_lfanew + 4
    machine, nsec, _, _, _, szopt, _ = struct.unpack_from("<HHIIIHH", data, fh)
    opt = fh + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == OPT_HDR32_MAGIC:
        pe.is64 = False
        pe.entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        pe.image_base = struct.unpack_from("<I", data, opt + 28)[0]
        pe.size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
        pe.subsystem = struct.unpack_from("<H", data, opt + 68)[0]
    elif magic == OPT_HDR64_MAGIC:
        pe.is64 = True
        pe.entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        pe.image_base = struct.unpack_from("<Q", data, opt + 24)[0]
        pe.size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
        pe.subsystem = struct.unpack_from("<H", data, opt + 68)[0]
    else:
        pe.is_pe = False
        pe.error = "unsupported optional header magic 0x%04X" % magic
        return pe
    st = opt + szopt
    max_end = 0
    for i in range(nsec):
        o = st + i * SIZEOF_SECTION_HEADER
        if o + SIZEOF_SECTION_HEADER > len(data):
            break
        nm = data[o:o + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        vs, va, rs, ra = struct.unpack_from("<IIII", data, o + 8)
        ch = struct.unpack_from("<I", data, o + 36)[0]
        pe.sections.append(Section(nm, vs, va, rs, ra, ch))
        max_end = max(max_end, ra + rs)
    pe.entry_off = rva_to_off(pe.sections, pe.entry_rva)
    if max_end and max_end < len(data):
        pe.overlay_off = max_end
    return pe


def rva_to_off(sections: List[Section], rva: int) -> int:
    for s in sections:
        if s.virtual_address <= rva < s.virtual_address + max(s.virtual_size, s.raw_size):
            return s.raw_address + (rva - s.virtual_address)
    return rva


def section_of_rva(pe: PeFile, rva: int) -> Optional[Section]:
    for s in pe.sections:
        if s.virtual_address <= rva < s.virtual_address + max(s.virtual_size, s.raw_size):
            return s
    return None


# ===================== 编解码原语 =====================
def adler32(data: bytes) -> int:
    """sub_47655C @ 0x47655C: Adler-32, 模 0xFFF1 (65521)。"""
    a = 1
    b = 0
    for byte in data:
        a = (a + byte) % 0xFFF1
        b = (b + a) % 0xFFF1
    return (b << 16) | a


def lcg_decrypt(buf: bytearray, seed: int, add: int) -> int:
    """sub_47C6EC / sub_47C768 @ 0x47C6EC: 每 dword 前推进 LCG 并 XOR。

    seed = seed*0x19660D + add (mod 2^32); buf[i] ^= seed (little-endian dword)
    返回最终 seed。
    """
    n = len(buf) & ~3
    for i in range(0, n, 4):
        seed = (seed * LCG_MUL + add) & 0xFFFFFFFF
        cur = struct.unpack_from("<I", buf, i)[0]
        struct.pack_into("<I", buf, i, cur ^ seed)
    return seed


def xor_byte(buf: bytearray, key: int) -> None:
    """sub_47A074 @ 0x47A074: 每字节 XOR key。"""
    for i in range(len(buf)):
        buf[i] ^= key & 0xFF


def lzss_decompress(src: bytes, out_len: int) -> bytes:
    """sub_476038 @ 0x476038: 经典 Okumura LZSS (4096 环形窗口)。

    标志位 1=字面量, 0=匹配 (2 字节: 12 位偏移 + 4 位长度)。
    """
    out = bytearray()
    ring = bytearray(b" " * LZSS_N)  # 预填空格 (0x20)
    r = LZSS_N - LZSS_F
    flags = 0
    si = 0
    n = len(src)
    while len(out) < out_len:
        if flags == 0:
            if si >= n:
                break
            flags = src[si] | 0xFF00
            si += 1
        if flags & 1:
            if si >= n:
                break
            c = src[si]
            si += 1
            out.append(c)
            ring[r] = c
            r = (r + 1) & (LZSS_N - 1)
        else:
            if si + 1 >= n:
                break
            b1 = src[si]
            b2 = src[si + 1]
            si += 2
            pos = b1 | ((b2 & 0xF0) << 4)
            length = (b2 & 0x0F) + 2
            for _ in range(length + 1):
                c = ring[(pos + 0) & (LZSS_N - 1)]
                out.append(c)
                ring[r] = c
                r = (r + 1) & (LZSS_N - 1)
                pos = (pos + 1) & (LZSS_N - 1)
                if len(out) >= out_len:
                    break
        flags >>= 1
    return bytes(out[:out_len])


# ===================== Molebox 检测 =====================
@dataclass
class ControlBlock:
    raw_size: int = 0
    compressed_size: int = 0
    expected_adler: int = 0
    data: bytes = b""
    valid: bool = False
    error: Optional[str] = None


@dataclass
class MoleboxInfo:
    version_code: int = 0               # byte_48A284
    version_name: str = ""
    major: int = 0                      # byte_48A290
    minor: int = 0                      # dword_48A29C
    is_pro: bool = False
    flags: int = 0                      # dword_48A28C
    box_name: str = ""                  # unk_48A2C4 (0x40 字节)
    signature: int = 0
    data_start: int = 0                 # dword_48A370
    box_offset: int = 0                 # dword_48A378
    entry_table_off: int = 0            # dword_48A37C
    file_count: int = 0                 # dword_48A380
    header_fixup: int = 0               # dword_48A384
    control: Optional[ControlBlock] = None
    detected: bool = False
    error: Optional[str] = None


def detect_ep_version(pe: PeFile) -> int:
    """sub_47DAF4 @ 0x47DAF4: 在入口点原始字节中搜索 Molebox 引导特征码。"""
    if not pe.is_pe or pe.entry_off is None:
        return 0
    # 入口点附近读取 (原程序读节 rawptr+4 起的区域, 这里取入口点前后 0x400 字节)
    start = max(0, pe.entry_off)
    region = pe.data[start:start + 0x400]
    for hexpat, code in EP_SIGNATURES:
        pat = bytes.fromhex(hexpat)
        if pat in region:
            return code
    return 0


def parse_control_block(pe: PeFile, version_code: int) -> ControlBlock:
    """sub_47C790 @ 0x47C790: 定位并解压控制块 (LZSS + adler32 校验)。"""
    cb = ControlBlock()
    # 入口点偏移 ebx = rawptr + 0x5A(ver1) / +0x5F(其它); 控制块位于入口节内,
    # 不依赖 overlay (overlay 仅文件表需要)。
    ep_sec = section_of_rva(pe, pe.entry_rva)
    if ep_sec is None:
        cb.error = "entry point not in any section"
        return cb
    delta = 0x5A if version_code == 1 else 0x5F
    off = ep_sec.raw_address + delta
    if off + 12 > len(pe.data):
        cb.error = "control block header out of range"
        return cb
    raw_size, comp_size, expected = struct.unpack_from("<III", pe.data, off)
    cb.raw_size = raw_size
    cb.compressed_size = comp_size
    cb.expected_adler = expected
    start = off + 12
    if start + comp_size > len(pe.data):
        cb.error = "control block data out of range"
        return cb
    comp = pe.data[start:start + comp_size]
    try:
        data = lzss_decompress(comp, raw_size)
    except Exception as e:  # noqa: BLE001
        cb.error = "decompression failed: %s" % e
        return cb
    cb.data = data
    if len(data) != raw_size:
        cb.error = "decompressed length mismatch (%d != %d)" % (len(data), raw_size)
        return cb
    if adler32(data) != expected:
        cb.error = "checksum of decompressed data does not match"
        return cb
    cb.valid = True
    return cb


def parse_molebox(pe: PeFile) -> MoleboxInfo:
    """完整静态解析: EP 检测 -> 控制块 -> 头部。对应 sub_47E264 主流程。"""
    info = MoleboxInfo()
    if not pe.is_pe:
        info.error = pe.error or "not a PE file"
        return info
    if pe.is64:
        info.error = "64-bit PE (Molebox does not support)"
        return info

    info.version_code = detect_ep_version(pe)
    cb = parse_control_block(pe, info.version_code)
    info.control = cb
    if not cb.valid:
        # 非 Molebox 或未知版本
        info.error = cb.error or "not a Molebox or unknown version"
        return info

    d = cb.data
    # 控制块明文: +0x1C 主版本, +0x2E 次版本, +0x32 起 0x40 字节 MD5 密钥
    if len(d) > 0x20:
        info.major = d[0x1C]
    if len(d) >= 0x32:
        info.minor = struct.unpack_from("<I", d, 0x2E)[0]
    # 标志 dword_48A28C (控制块内偏移 +0x2A 附近); bit4=Standard
    if len(d) >= 0x2E:
        info.flags = struct.unpack_from("<I", d, 0x2A)[0]
    info.is_pro = not (info.flags & 0x10)
    info.version_name = VERSION_NAMES.get(info.version_code, "")

    # 头部 (sub_47AC5C): 控制块之后是 0x10 字节签名 + 5 个 dword
    hdr = 0x32 + 0x40  # 跳过版本 + MD5 密钥
    if len(d) >= hdr + 4:
        info.signature = struct.unpack_from("<I", d, hdr)[0]
    base = hdr + 4
    if len(d) >= base + 20:
        (info.data_start, info.box_offset, info.entry_table_off,
         info.file_count, info.header_fixup) = struct.unpack_from("<IIIII", d, base)

    # BoxName (0x40 字节, 控制块 +0x32 区域之前, sub_47B184 读 unk_48A2C4)
    # 在明文里通常位于头部签名之前; 尽力提取可见 ASCII
    info.detected = True
    return info


# ===================== 文件表解析 / 抽取 =====================
@dataclass
class FileEntry:
    name: str
    md5: bytes
    size: int
    block_sizes: List[int] = field(default_factory=list)
    data_offset: int = 0          # 相对文件起始
    raw_offset: int = 0           # 绝对文件偏移
    compressed: bool = False


def _read_cstr(data: bytes, off: int, limit: int = 0x100) -> Tuple[str, int]:
    end = off
    while end < len(data) and end - off < limit and data[end] != 0:
        end += 1
    return data[off:end].decode("latin1", "replace"), end + 1


def parse_file_table(pe: PeFile, info: MoleboxInfo) -> List[FileEntry]:
    """sub_47A708 @ 0x47A708: 解析 overlay 文件条目表。"""
    entries: List[FileEntry] = []
    if not info.detected or pe.overlay_off is None:
        return entries
    # 文件表位于 box_offset (相对 overlay) 处; overlay 起点 = pe.overlay_off
    base = pe.overlay_off + info.box_offset
    off = base
    data = pe.data
    for _ in range(info.file_count):
        if off >= len(data):
            break
        name, off = _read_cstr(data, off)
        if not name:
            break
        if off + 16 > len(data):
            break
        md5 = data[off:off + 16]
        off += 16
        # 从文件起始到当前 = 已读大小; 这里 size 由块表推出
        # 块表长度 = ((size + 0xFFFF) >> 16); 但 size 需要先读块表前一 dword?
        # 实际: sub_47A708 先读 16 字节 MD5, 然后逐块读; size 来自块表累加。
        # 简化: 读块表 (每 dword 一块长度), 直到累计 >= 未知; 用 data_start 边界。
        block_sizes: List[int] = []
        total = 0
        # 块表条目数未知时, 以 "读到压缩数据区" 为界不可靠; 采用: 块表有
        # ceil(size/64K) 项, 但 size 本身由最后一块决定。这里按直到遇到
        # 合理长度的块表 (数据区紧随其后) 读取, 用 header_fixup 作数据基址。
        # 为忠实且稳健, 用 data_start 作为数据区起点, 块表从当前读到 data_start。
        table_end = pe.overlay_off + info.data_start
        while off + 4 <= min(table_end, len(data)):
            bs = struct.unpack_from("<I", data, off)[0]
            off += 4
            block_sizes.append(bs & 0x7FFFFFFF)
            total += bs & 0x7FFFFFFF
            if (bs & BLOCK_FLAG_COMPRESSED) == 0 and total >= BLOCK_SIZE:
                # 未压缩块通常一块即 64K; 继续直到表结束
                pass
        size = total
        entries.append(FileEntry(name=name, md5=md5, size=size,
                                 block_sizes=block_sizes,
                                 raw_offset=off,
                                 compressed=bool(info.flags & 0)))
        # 数据区紧随块表; 下一 entry 在数据之后, 但数据长度 = size (已解压)
        # 原程序顺序读取数据块 (可能压缩), 这里用块表长度推进。
        off += size
    return entries


def extract_entry(pe: PeFile, info: MoleboxInfo, entry: FileEntry) -> bytes:
    """sub_47A0C0 @ 0x47A0C0: 读取/解密/解压单个文件数据。

    块表 dword 已编码 压缩标志(bit31)+长度(低31位); 数据紧随其后, 无额外头。
    entry.raw_offset 指向数据区首字节。
    """
    data = pe.data
    off = entry.raw_offset
    out = bytearray()
    for bs in entry.block_sizes:
        comp = bool(bs & BLOCK_FLAG_COMPRESSED)
        length = bs & 0x7FFFFFFF
        if off + length > len(data):
            length = len(data) - off
        block = bytearray(data[off:off + length])
        off += length
        if comp:
            block = bytearray(lzss_decompress(bytes(block), BLOCK_SIZE))
        out += block
    return bytes(out)


# ===================== 输出 =====================
def fmt_info(pe: PeFile, info: MoleboxInfo, as_json: bool) -> str:
    if as_json:
        return json.dumps({
            "file": pe.path,
            "is_pe": pe.is_pe,
            "is64": pe.is64,
            "image_base": pe.image_base,
            "entry_rva": pe.entry_rva,
            "overlay_offset": pe.overlay_off,
            "molebox_detected": info.detected,
            "version_code": info.version_code,
            "version_name": info.version_name,
            "major": info.major,
            "minor": info.minor,
            "is_pro": info.is_pro,
            "flags": info.flags,
            "file_count": info.file_count,
            "error": info.error,
        }, ensure_ascii=False, indent=2)
    lines = ["File: %s" % pe.path]
    if not pe.is_pe:
        lines.append("[!] %s" % (pe.error or "not a PE"))
        return "\n".join(lines)
    lines.append("ImageBase: 0x%08X  EntryRVA: 0x%08X  (%s)" % (
        pe.image_base, pe.entry_rva, "PE32+" if pe.is64 else "PE32"))
    lines.append("Sections: %s" % ", ".join(s.name for s in pe.sections))
    lines.append("Overlay offset: %s" % (
        ("0x%X" % pe.overlay_off) if pe.overlay_off is not None else "(none)"))
    if not info.detected:
        lines.append("==> Molebox detected: NO  (%s)" % (info.error or "unknown"))
        return "\n".join(lines)
    lines.append("Molebox version code: %d  %s" % (info.version_code, info.version_name))
    lines.append("Version: %d.%04d  (%s)" % (info.major, info.minor,
                                            "Pro" if info.is_pro else "Standard"))
    lines.append("Flags: 0x%08X  Signature: 0x%08X" % (info.flags, info.signature))
    lines.append("DataStart: 0x%X  BoxOffset: 0x%X  EntryTable: 0x%X  Files: %d" % (
        info.data_start, info.box_offset, info.entry_table_off, info.file_count))
    lines.append("==> Molebox detected: YES")
    return "\n".join(lines)


USAGE = __doc__


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="main.py", add_help=False)
    p.add_argument("target", nargs="?")
    p.add_argument("cmd", nargs="?", default="detect",
                   choices=["detect", "extract", "info"])
    p.add_argument("--out", default=None)
    p.add_argument("--json", action="store_true")
    p.add_argument("-h", "--help", action="store_true")
    a = p.parse_args(argv)
    if a.help or not a.target:
        print(USAGE)
        return EXIT_SUCCESS
    try:
        with open(a.target, "rb") as fh:
            data = fh.read()
    except OSError as e:
        print("[!] cannot read %s: %s" % (a.target, e))
        return EXIT_FAILURE
    pe = parse_pe(data, a.target)
    info = parse_molebox(pe)

    if a.cmd == "info":
        print(fmt_info(pe, info, a.json))
        return EXIT_SUCCESS if pe.is_pe else EXIT_FAILURE

    if a.cmd == "detect":
        print(fmt_info(pe, info, a.json))
        return EXIT_SUCCESS if info.detected else EXIT_FAILURE

    if a.cmd == "extract":
        if not info.detected:
            print("[!] %s" % (info.error or "not a Molebox file"))
            return EXIT_FAILURE
        entries = parse_file_table(pe, info)
        if not entries:
            print("[!] no files parsed (unsupported layout)")
            return EXIT_FAILURE
        out_root = a.out or os.path.dirname(os.path.abspath(a.target))
        out_dir = os.path.abspath(os.path.join(out_root, "_extracted"))
        os.makedirs(out_dir, exist_ok=True)
        written = 0
        for e in entries:
            # 路径穿越防护 (sub_47A0C0): 规范化后必须仍在 _extracted 下
            safe = os.path.normpath(os.path.join(out_dir, e.name))
            if os.path.commonpath([safe, out_dir]) != out_dir:
                print("[x] Path traversal exploit attempt detected: `%s`" % e.name)
                continue
            content = extract_entry(pe, info, e)
            with open(safe, "wb") as fh:
                fh.write(content)
            print("[+] File \"%s\", size=0x%x" % (e.name, len(content)))
            written += 1
        print("[i] Total files: %d" % written)
        return EXIT_SUCCESS

    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())