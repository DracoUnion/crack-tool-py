#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AutoIt Extractor  (静态 AutoIt3 编译脚本 / 内嵌资源提取器) —— 纯 Python 3 复刻版
================================================================================

源程序 (逆向目标)  : D:\\Program Files\\crack-tool-unpacker\\AutoItExtractor\\AutoIt Extractor.exe
目标程序 (本文件)  : D:\\src\\crack-tool-py\\AutoItExtractor_py\\main.py   (唯一入口)
参考风格           : D:\\src\\crack-tool-py\\ASPackUnPacker_1.13_py\\main.py

--------------------------------------------------------------------------------
一、逆向来源与方法
--------------------------------------------------------------------------------
源程序是一个 .NET (C#) 32 位 GUI 程序，用于从 “AutoIt3 编译后的 EXE” 中还原出
AutoIt 源码脚本以及随脚本一起被打包进去的文件（FileInstall 资源）。

本次逆向通过自研的 dnlib_py 元数据/IL 引擎逐方法反汇编 (dumpil.py) 得到，关键方法：
  - AnalyzeFileHelper (方法 11)  整体探测流程：单字节 XOR 爆破 + 定位 AU3_HEADER
  - Unpack           (方法 17)  资源表解析（tag/path/size/checksum/time/data）
  - GetKeys          (方法 38)  按版本返回密钥集合
  - Keys .ctor       (方法 24/25/28)  三套密钥常量
  - ShittyEncoder    (方法 23/26/29)  异或混淆（三版本各一）
  - Decompress       (方法 22/27/30)  解压（三版本各一）
  - ExtractBits/CustomExtractBits/NextByte (方法 32/31/36)  LZSS 比特流读取
  - SRand/Next/InternalShit (方法 146/147/148)  EA05 的 MT19937 变体
  - Init0/Init1/Next/FPUStuff/Rotl (方法 153/152/154/151/150) EA06 的 System.Random 变体
  - Find/FindAll     (方法 50/51)  朴素子串查找

--------------------------------------------------------------------------------
二、AutoIt3 编译 EXE 的附加数据格式 (overlay)
--------------------------------------------------------------------------------
AutoIt3 编译器把 “脚本 + 内嵌文件” 压缩/加密后附加 (overlay) 到 EXE 末尾。整体格式：

  整个文件被逐字节 XOR 一个 “文件密钥”(0..255)。解码后：

  [ AU3_HEADER  16 字节 ]  固定魔数:
        a6 4d 4e bb 9d 69 4f ac 9c 49 56 0f 83 d3 4d 78
  [ 版本标签     8 字节 ]  以 "AU3!" 开头, 例如 "AU3!EA06" / "AU3!EA05" / "AU3!OLD"
  [ ... 资源表 ... ]       从偏移 40 开始 (EA05/EA06), 旧版从 21+key 开始
  [ 下一个 AU3 块 或 EOF ]  以 “下一个相同 8 字节版本标签” 或文件尾作为本块结束

  每个资源条目 (整数均为小端, 且各字段被对应密钥 XOR 混淆)：
        4 字节  (跳过, 每块前导)
        int32  TagSize        ^ keys.TagSize
        TagSize 字节  Tag      (Unicode 时字节数×2)   经 ShittyEncoder 解码
        int32  PathSize       ^ keys.PathSize
        PathSize 字节 Path     (Unicode 时×2)         经 ShittyEncoder 解码
        1 字节  IsCompressed
        int32  CompressedSize ^ keys.CompressedSize
        int32  DecompressedSize ^ keys.DecompressedSize
        int32  CheckSum       ^ keys.Checksum         (仅非 OLD 版)
        8 字节  CreationTime  (仅非 Unicode 版)
        8 字节  LastWriteTime (仅非 Unicode 版)
        CompressedSize 字节 Data  经 ShittyEncoder 解码后即为压缩流

  版本 → 密钥 (Keys):
        EA06 : TagSize 44476 Tag 45887 PathSize 63520 Path 62585
               Comp 34748 Decomp 34748 Checksum 42629 Data 9335 Unicode 1
        EA05 : TagSize 10684 Tag 41566 PathSize 10668 Path 62046
               Comp 17834 Decomp 17834 Checksum 50130 Data 8879 Unicode 0
        OLD  : 与 EA05 相同 (Legacy .ctor 直接链式调用 EA05 .ctor)

--------------------------------------------------------------------------------
三、ShittyEncoder (逐字节异或, 三版本)
--------------------------------------------------------------------------------
签名: ShittyEncoder(byte[] data, int key, int arg3, int arg4)
  EA06(#29): Init0(); k = key + (arg3 ? len/2 : 0); Init1(k); data[i] ^= Next()
  EA05(#26): k = key + (arg3 ? len : 2121); SRand(k);          data[i] ^= Next()
  Legacy(#23): k = key + (arg3 ? len : 2121);
               if arg4: 用 MSVC rand (Rand) 逐字节异或
               else:    SRand(k); data[i] ^= Next()   (MT19937 变体)

  Tag/Path 用 arg3=1 (故 EA06 加 len/2, EA05/Legacy 加 len)；Data 用 arg3=0。

--------------------------------------------------------------------------------
四、解压 (Decompress) —— 三种 LZSS/Huffman 变体
--------------------------------------------------------------------------------
解压前 RawData 首 4 字节必须是签名之一 ("EA06"/"EA05"/"JB01"/"JB00")，比特流从
偏移 8 开始。若 CompressedSize == DecompressedSize 则不压缩，数据原样使用。

  EA06(#30) 比特读取器 LZSS：  bit=ExtractBits(1); bit==1 → 字面量(8bit);
                              bit==0 → 匹配: dist=ExtractBits(15),
                              len=CustomExtractBits(); 从 outpos-dist 复制 len 字节
  EA05(#27) 同上但比特相反：  bit==0 → 字面量; bit!=0 → 匹配
  Legacy(#22) Huffman LZSS + JB01 特例 (本复刻对 Legacy 的 Huffman 分支优雅降级为
               “不支持”，仍能正确解析资源表与异或解码；EA05/EA06 完整支持)

  ExtractBits(n): 16 位大端字 (高字节在前) 的 MSB-first 比特读取器。
  CustomExtractBits(): 变长长度码 (基值 3/6/13/41 + 255 累加)。

--------------------------------------------------------------------------------
五、CLI
--------------------------------------------------------------------------------
    python main.py <target.exe> detect
    python main.py <target.exe> info
    python main.py <target.exe> extract [outdir]

仅使用 Python 标准库。
"""

import argparse
import os
import struct
import sys
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# ---------------------------------------------------------------------------
# 常量 (逆向自 .cctor / Keys .ctor)
# ---------------------------------------------------------------------------
AU3_HEADER = bytes.fromhex("a64d4ebb9d694fac9c49560f83d34d78")  # 16 字节魔数
AU3_SIGN = [struct.unpack("<I", s)[0] for s in (b"EA06", b"EA05", b"JB01", b"JB00")]

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2

# EA05 的 MT19937 变体参数 (方法 146/147/148)
MT_N = 624
MT_M = 397
MT_MATRIX_A = 0x9908B0DF
MT_MASK1 = (-12953427) & 0xFFFFFFFF   # 0xFF3A58AD
MT_MASK2 = (-8308) & 0xFFFFFFFF       # 0xFFFFDF8C


class UnsupportedCompression(Exception):
    """遇到本复刻未实现的压缩分支 (Legacy Huffman / JB01 原生解码) 时抛出。"""


# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------
@dataclass
class Keys:
    tag_size: int
    tag: int
    path_size: int
    path: int
    comp_size: int
    decomp_size: int
    checksum: int
    data: int
    unicode: int


# 三套密钥 (方法 25 / 28；Legacy 复用 EA05)
KEYS_EA05 = Keys(10684, 41566, 10668, 62046, 17834, 17834, 50130, 8879, 0)
KEYS_EA06 = Keys(44476, 45887, 63520, 62585, 34748, 34748, 42629, 9335, 1)
KEYS_LEGACY = KEYS_EA05  # Legacy .ctor 链式调用 EA05 .ctor


@dataclass
class Resource:
    tag: str = ""
    path: str = ""
    is_compressed: bool = False
    compressed_size: int = 0
    decompressed_size: int = 0
    checksum: int = 0
    creation_time: int = 0
    last_write_time: int = 0
    is_unicode: bool = False
    raw_data: bytes = b""          # 异或解码后的 (压缩) 数据
    data: Optional[bytes] = None   # 解压后的数据 (文件内容 / 脚本字节)
    source_code: Optional[str] = None  # 脚本源码 (仅脚本资源)
    error: Optional[str] = None

    @property
    def is_script(self) -> bool:
        return "SCRIPT" in self.tag.upper()

    @property
    def short_tag(self) -> str:
        return self.tag


@dataclass
class DetectResult:
    found: bool
    key: int = 0
    start: int = 0
    end: int = 0
    version: str = ""
    is_old: bool = False
    resources: List[Resource] = field(default_factory=list)
    error: Optional[str] = None


# ---------------------------------------------------------------------------
# 小端读取助手 (对应源程序的 ToInt32 / ToUInt32)
# ---------------------------------------------------------------------------
def to_int32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<i", buf, off)[0]


def to_uint32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def to_bool(b: int) -> bool:
    return b != 0


# ---------------------------------------------------------------------------
# 版本 → 密钥 / 编码器选择 (方法 38 GetKeys)
# ---------------------------------------------------------------------------
def get_keys(version: str) -> Optional[Keys]:
    if version == "AU3!EA06":
        return KEYS_EA06
    if version == "AU3!EA05":
        return KEYS_EA05
    if version == "AU3!OLD":
        return KEYS_LEGACY
    return None


def encoder_kind(version: str) -> str:
    if version == "AU3!EA06":
        return "ea06"
    if version == "AU3!EA05":
        return "ea05"
    return "legacy"


# ---------------------------------------------------------------------------
# EA05 的 MT19937 变体 (方法 146 SRand / 147 Next / 148 InternalShit)
# ---------------------------------------------------------------------------
class _MT:
    def __init__(self):
        self.nums = [0] * MT_N
        self.a = 0
        self.b = 0
        self.nxt = 0

    def srand(self, seed: int) -> None:
        self.nums = [0] * MT_N
        self.nums[0] = seed & 0xFFFFFFFF
        for i in range(1, MT_N):
            prev = self.nums[i - 1]
            self.nums[i] = (((prev ^ (prev >> 30)) * 1812433253) + i) & 0xFFFFFFFF
        self.a = 1
        self.b = 1

    def _internal(self) -> None:
        self.a = MT_N
        self.nxt = 0
        for i in range(0, 227):
            y = (self.nums[i] & 0x80000000) | (self.nums[i + 1] & 0x7FFFFFFF)
            v = self.nums[i + MT_M] ^ (y >> 1)
            if self.nums[i + 1] & 1:
                v ^= MT_MATRIX_A
            self.nums[i] = v & 0xFFFFFFFF
        for i in range(227, 623):
            y = (self.nums[i] & 0x80000000) | (self.nums[i + 1] & 0x7FFFFFFF)
            v = self.nums[i - 227] ^ (y >> 1)
            if self.nums[i + 1] & 1:
                v ^= MT_MATRIX_A
            self.nums[i] = v & 0xFFFFFFFF
        # i == 623
        y = (self.nums[623] & 0x80000000) | (self.nums[0] & 0x7FFFFFFF)
        v = self.nums[396] ^ (y >> 1)
        if self.nums[0] & 1:
            v ^= MT_MATRIX_A
        self.nums[623] = v & 0xFFFFFFFF

    def next(self) -> int:
        self.a = (self.a - 1) & 0xFFFFFFFF
        if self.a == 0:
            self._internal()
        i = self.nxt
        self.nxt = (self.nxt + 1) & 0xFFFFFFFF
        y = self.nums[i]
        y ^= y >> 11
        y ^= (y & MT_MASK1) << 7
        y &= 0xFFFFFFFF
        y ^= (y & MT_MASK2) << 15
        y &= 0xFFFFFFFF
        y ^= y >> 18
        y &= 0xFFFFFFFF
        return (y >> 1) & 0xFF


# ---------------------------------------------------------------------------
# EA06 的 System.Random 变体 (方法 150 Rotl / 151 FPUStuff / 152 Init1 /
#                              153 Init0 / 154 Next)
# ---------------------------------------------------------------------------
class _EA06RNG:
    def __init__(self):
        self.nums = [0] * 17
        self.nums2 = [0] * 17
        self.a = 0
        self.b = 0
        self.c = 0

    @staticmethod
    def _rotl(x: int, k: int) -> int:
        x &= 0xFFFFFFFF
        return ((x << (k & 31)) | (x >> ((32 - k) & 31))) & 0xFFFFFFFF

    def _fpu_stuff(self) -> float:
        x = (self._rotl(self.nums[self.a], 9) + self._rotl(self.nums[self.b], 13)) & 0xFFFFFFFF
        self.nums[self.a] = x
        self.a = (self.a - 1) & 0xFFFFFFFF
        if self.a >= 17:
            self.a = 16
        self.b = (self.b - 1) & 0xFFFFFFFF
        if self.b >= 17:
            self.b = 16
        # 周期检测：若状态回到初值则返回 0.0
        if self.nums[self.a] == self.nums2[0] and self.nums == self.nums2:
            return 0.0
        if self.c == 0:
            low = (x << 20) & 0xFFFFFFFF
            high = ((x >> 12) | 0x3FF00000) & 0xFFFFFFFF
            d = struct.unpack("<d", struct.pack("<II", low, high))[0]
            return d - 1.0
        elif self.c == 1:
            high = (x << 20) & 0xFFFFFFFF
            low = ((x >> 12) | 0x3FF00000) & 0xFFFFFFFF
            d = struct.unpack("<d", struct.pack("<II", low, high))[0]
            return d - 1.0
        else:
            v = float(x)
            if x >= 0x80000000:
                v += 4294967296.0
            return v * 2.328306436538696e-10

    def init1(self, seed: int) -> None:
        seed &= 0xFFFFFFFF
        for i in range(17):
            seed = (1 - 1403630843 * seed) & 0xFFFFFFFF
            self.nums[i] = seed
        self.a = 0
        self.b = 10
        self.nums2 = list(self.nums)
        for _ in range(9):
            self._fpu_stuff()

    def init0(self) -> None:
        self.init1((-559038242) & 0xFFFFFFFF)
        # 检测 double 1.0 的字节序布局；x86 小端下高 dword == 0x3FF00000 → C=0
        d = 1.0
        hi = struct.unpack("<I", struct.pack("<d", d)[4:])[0]
        lo = struct.unpack("<I", struct.pack("<d", d)[:4])[0]
        if hi == 0x3FF00000:
            self.c = 0
            return
        self.c = 1
        if lo == 0x3FF00000:
            self.c = 2

    def next(self) -> int:
        self._fpu_stuff()  # 丢弃一个
        v = int(256.0 * self._fpu_stuff())
        if v >= 256:
            return 255
        return v & 0xFF


# ---------------------------------------------------------------------------
# ShittyEncoder (方法 23/26/29)
# ---------------------------------------------------------------------------
def shitty_encoder(kind: str, data: bytearray, key: int, arg3: int, arg4: int) -> None:
    n = len(data)
    if kind == "ea06":
        rng = _EA06RNG()
        rng.init0()
        k = key + (n // 2 if arg3 else 0)
        rng.init1(k)
        for i in range(n):
            data[i] ^= rng.next()
    elif kind == "ea05":
        k = key + (n if arg3 else 2121)
        mt = _MT()
        mt.srand(k)
        for i in range(n):
            data[i] ^= mt.next()
    else:  # legacy
        k = key + (n if arg3 else 2121)
        if arg4:
            # MSVC rand LCG (Rand 类) —— 逐字节
            state = k & 0xFFFFFFFF
            for i in range(n):
                state = (state * 214013 + 2531011) & 0xFFFFFFFF
                data[i] ^= (state >> 16) & 0xFF
        else:
            mt = _MT()
            mt.srand(k)
            for i in range(n):
                data[i] ^= mt.next()


def decode_string(keys: Keys, kind: str, buf: bytes, off: int, size: int,
                  key: int, is_unicode: int) -> str:
    chunk = bytearray(buf[off:off + size])
    shitty_encoder(kind, chunk, key, 1, is_unicode)
    if keys.unicode:
        return chunk.decode("utf-16-le", errors="replace")
    return chunk.decode("latin-1", errors="replace")


# ---------------------------------------------------------------------------
# 比特读取器 (方法 32 ExtractBits / 31 CustomExtractBits / 36 NextByte)
# ---------------------------------------------------------------------------
class _BitReader:
    def __init__(self, data: bytes, pos: int):
        self.data = data
        self.pos = pos
        self.ans = 0
        self.count = 0

    def _next_byte(self) -> int:
        if self.pos >= len(self.data):
            self.pos += 1
            return 0
        b = self.data[self.pos]
        self.pos += 1
        return b

    def extract(self, n: int) -> int:
        self.ans &= 0xFFFF
        while n > 0:
            if self.count == 0:
                b = self._next_byte()
                self.ans |= (b << 8)
                self.ans |= self._next_byte()
                self.count = 16
            self.ans = (self.ans << 1) & 0xFFFFFFFF
            self.count -= 1
            n -= 1
        return (self.ans >> 16) & 0xFFFF

    def custom(self) -> int:
        value = 0
        x = self.extract(2)
        if x == 3:
            value = 3
            x = self.extract(3)
            if x == 7:
                value = 10
                x = self.extract(5)
                if x == 31:
                    value = 41
                    while True:
                        x = self.extract(8)
                        if x != 255:
                            break
                        value += 255
        return value + x + 3


# ---------------------------------------------------------------------------
# 解压 (方法 22/27/30)
# ---------------------------------------------------------------------------
def decompress(res: Resource, kind: str) -> None:
    raw = res.raw_data
    if res.compressed_size == 0 or res.compressed_size == res.decompressed_size:
        # 未压缩：数据即原样
        res.data = bytes(raw)
        _maybe_source(res)
        return
    if len(raw) < 4 or to_uint32(raw, 0) not in AU3_SIGN:
        res.error = "Invalid Compressed File Format!"
        return
    if kind == "legacy":
        # Legacy: Huffman / JB01 原生解码 —— 本复刻未实现
        raise UnsupportedCompression("Legacy Huffman/JB01 decompression not implemented")

    out = bytearray()
    out_size = res.decompressed_size
    br = _BitReader(raw, 8)
    if kind == "ea06":
        while len(out) < out_size:
            if br.extract(1) == 1:               # 字面量
                out.append(br.extract(8) & 0xFF)
            else:                                 # 匹配
                dist = br.extract(15)
                cnt = br.custom()
                src = len(out) - dist
                for _ in range(cnt):
                    out.append(out[src])
                    src += 1
    else:  # ea05 —— 比特相反
        while len(out) < out_size:
            if br.extract(1) == 0:               # 字面量
                out.append(br.extract(8) & 0xFF)
            else:                                 # 匹配
                dist = br.extract(15)
                cnt = br.custom()
                src = len(out) - dist
                for _ in range(cnt):
                    out.append(out[src])
                    src += 1
    res.data = bytes(out[:out_size])
    _maybe_source(res)


def _maybe_source(res: Resource) -> None:
    if not res.is_script or res.data is None:
        return
    if "UNICODE" in res.tag.upper() or res.is_unicode:
        res.source_code = res.data.decode("utf-16-le", errors="replace").rstrip("\x00")
    else:
        res.source_code = res.data.decode("latin-1", errors="replace")


# ---------------------------------------------------------------------------
# Unpack (方法 17) —— 解析资源表
# ---------------------------------------------------------------------------
def unpack(buf: bytes, is_old: bool, version: str) -> Tuple[Optional[List[Resource]], Optional[str]]:
    keys = get_keys(version)
    if keys is None:
        return None, "Unsupported AutoIt Type"
    kind = encoder_kind(version)
    is_unicode = keys.unicode
    resources: List[Resource] = []
    offset = 40

    if is_old:
        key = to_int32(buf, 17) ^ 64193
        data2 = bytearray(buf[21:21 + key])
        shitty_encoder(kind, data2, 50130, 1, is_unicode)
        if to_uint32(data2, 0) not in AU3_SIGN:
            is_unicode = 1
            data2 = bytearray(buf[21:21 + key])
            shitty_encoder(kind, data2, 50130, 1, 1)
        offset = 21 + key

    n = len(buf)
    while offset < n:
        offset += 4
        res = Resource(is_unicode=bool(is_unicode))
        if offset >= n:
            break
        # Tag
        tag_size = to_int32(buf, offset) ^ keys.tag_size
        offset += 4
        size = tag_size + (tag_size if is_unicode else 0)
        if size >= n - offset:
            break
        res.tag = decode_string(keys, kind, buf, offset, size, keys.tag, is_unicode)
        offset += size
        if offset >= n:
            break
        # Path
        path_size = to_int32(buf, offset) ^ keys.path_size
        offset += 4
        size2 = path_size + (path_size if is_unicode else 0)
        if size2 >= n - offset:
            break
        res.path = decode_string(keys, kind, buf, offset, size2, keys.path, is_unicode)
        offset += size2
        if offset >= n:
            break
        # IsCompressed
        res.is_compressed = to_bool(buf[offset])
        offset += 1
        if offset >= n:
            break
        # CompressedSize
        comp = to_int32(buf, offset) ^ keys.comp_size
        offset += 4
        res.compressed_size = comp
        if comp >= n - offset:
            return None, "Invalid Size of Compressed Resource"
        if offset >= n:
            break
        # DecompressedSize
        decomp = to_int32(buf, offset) ^ keys.decomp_size
        offset += 4
        res.decompressed_size = decomp
        # CheckSum (仅非 OLD)
        if not is_old:
            res.checksum = to_int32(buf, offset) ^ keys.checksum
            offset += 4
        # 时间戳 (仅非 Unicode)
        if not is_unicode:
            res.creation_time = (to_uint32(buf, offset) << 32) | to_uint32(buf, offset + 4)
            offset += 8
            res.last_write_time = (to_uint32(buf, offset) << 32) | to_uint32(buf, offset + 4)
            offset += 8
        # Data
        if comp > 0:
            data2 = bytearray(buf[offset:offset + comp])
            dkey = keys.data
            if is_old:
                dkey -= 2121
                for b in data2:
                    dkey += (b - 256 if b >= 128 else b)  # (sbyte)b
            shitty_encoder(kind, data2, dkey, 0, is_unicode)
            res.raw_data = bytes(data2)
            offset += comp
        resources.append(res)

    return resources, "OK"


# ---------------------------------------------------------------------------
# 探测 (方法 11 AnalyzeFileHelper) —— 单字节 XOR 爆破 + 定位
# ---------------------------------------------------------------------------
def analyze(data: bytes) -> DetectResult:
    # 1) 找到第一个使 AU3_HEADER 出现的 XOR 密钥
    chosen_key = -1
    decoded = None
    for key in range(256):
        dec = bytes(b ^ key for b in data)
        if AU3_HEADER in dec:
            chosen_key = key
            decoded = dec
            break
    if chosen_key < 0:
        return DetectResult(found=False, error="Script Not Found")

    # 2) 收集所有 header 位置，筛出后跟 "AU3!" 的
    positions = []
    start = 0
    while True:
        idx = decoded.find(AU3_HEADER, start)
        if idx < 0:
            break
        positions.append(idx)
        start = idx + 1

    blocks = []  # (start, end, version, is_old)
    last_idx = 0
    is_old = False
    version = ""
    for idx in positions:
        last_idx = idx
        tag8 = decoded[idx + 16:idx + 24]
        if tag8.startswith(b"AU3!"):
            end = decoded.find(tag8, idx + 25)
            if end < 0:
                end = len(decoded)
            blocks.append((idx, end, tag8.decode("latin-1"), False))

    if not blocks:
        # 没有合法 AU3! 标签 → 视为 OLD
        if last_idx > 0:
            end = len(decoded) - 4
            blocks.append((last_idx, end, "AU3!OLD", True))

    if not blocks:
        return DetectResult(found=False, error="Script Not Found")

    # 3) 解析第一个块 (源程序会解析全部；CLI 取首个有效块)
    last_err = None
    for (s, e, ver, old) in blocks:
        res, status = unpack(decoded[s:e], old, ver)
        if status == "OK" and res is not None:
            # 解压每个资源
            kind = encoder_kind(ver)
            for r in res:
                try:
                    decompress(r, kind)
                except UnsupportedCompression as ex:
                    r.error = str(ex)
                except Exception as ex:  # noqa: BLE001  保持健壮，不抛栈
                    r.error = "Decompress error: %s" % ex
            return DetectResult(found=True, key=chosen_key, start=s, end=e,
                                version=ver, is_old=old, resources=res)
        last_err = status
    return DetectResult(found=False, key=chosen_key, error=last_err or "Script Not Found")


# ---------------------------------------------------------------------------
# CLI 命令
# ---------------------------------------------------------------------------
def cmd_detect(path: str) -> int:
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as ex:
        print("Error: cannot read %s: %s" % (path, ex))
        return EXIT_FAILURE
    r = analyze(data)
    if not r.found:
        print("Not an AutoIt3 compiled executable: %s" % (r.error or "unknown"))
        return EXIT_FAILURE
    print("AutoIt3 script found")
    print("  XOR key   : 0x%02X (%d)" % (r.key, r.key))
    print("  version   : %s%s" % (r.version, " (OLD)" if r.is_old else ""))
    print("  block     : offset %d .. %d (%d bytes)" % (r.start, r.end, r.end - r.start))
    print("  resources : %d" % len(r.resources))
    return EXIT_SUCCESS


def cmd_info(path: str) -> int:
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as ex:
        print("Error: cannot read %s: %s" % (path, ex))
        return EXIT_FAILURE
    r = analyze(data)
    if not r.found:
        print("Not an AutoIt3 compiled executable: %s" % (r.error or "unknown"))
        return EXIT_FAILURE
    print("File      : %s" % path)
    print("Version   : %s" % r.version)
    print("XOR key   : 0x%02X" % r.key)
    print("Resources : %d" % len(r.resources))
    print("-" * 70)
    for i, res in enumerate(r.resources, 1):
        kind = "SCRIPT" if res.is_script else "FILE"
        print("[%d] %-6s tag=%r" % (i, kind, res.tag))
        if res.path:
            print("     path        : %s" % res.path)
        print("     compressed  : %d" % res.compressed_size)
        print("     decompressed: %d" % res.decompressed_size)
        if res.data is not None:
            print("     extracted   : %d bytes" % len(res.data))
        if res.error:
            print("     error       : %s" % res.error)
    return EXIT_SUCCESS


def _safe_name(name: str, fallback: str) -> str:
    name = (name or "").strip().replace("\x00", "")
    name = name.replace("\\", "/").split("/")[-1]
    if not name or name in (".", ".."):
        return fallback
    return name


def cmd_extract(path: str, outdir: Optional[str]) -> int:
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as ex:
        print("Error: cannot read %s: %s" % (path, ex))
        return EXIT_FAILURE
    r = analyze(data)
    if not r.found:
        print("Not an AutoIt3 compiled executable: %s" % (r.error or "unknown"))
        return EXIT_FAILURE

    base = outdir or (os.path.splitext(os.path.basename(path))[0] + "_extracted")
    os.makedirs(base, exist_ok=True)
    print("Extracting to: %s" % base)

    count = 0
    for i, res in enumerate(r.resources, 1):
        if res.is_script:
            if res.source_code is None and res.error:
                print("  [script %d] skipped: %s" % (i, res.error))
                continue
            text = res.source_code if res.source_code is not None else ""
            out = os.path.join(base, "script.au3")
            with open(out, "w", encoding="utf-8", errors="replace") as f:
                f.write(text)
            print("  [script %d] -> %s (%d chars)" % (i, out, len(text)))
            count += 1
        else:
            if res.data is None:
                if res.error:
                    print("  [file %d] skipped: %s" % (i, res.error))
                continue
            name = _safe_name(res.path, "file_%d.bin" % i)
            out = os.path.join(base, name)
            with open(out, "wb") as f:
                f.write(res.data)
            print("  [file %d] -> %s (%d bytes)" % (i, out, len(res.data)))
            count += 1

    if count == 0:
        print("No resources could be extracted.")
        return EXIT_FAILURE
    print("Done. %d file(s) written." % count)
    return EXIT_SUCCESS


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="main.py",
        description="AutoIt Extractor —— 从 AutoIt3 编译的 EXE 中静态提取脚本与内嵌文件。",
    )
    p.add_argument("target", help="目标 EXE 文件路径")
    p.add_argument("cmd", choices=["detect", "info", "extract"],
                   help="detect=检测 / info=列出资源 / extract=提取到目录")
    p.add_argument("outdir", nargs="?", default=None,
                   help="extract 的输出目录 (缺省为 <target>_extracted)")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    if not os.path.isfile(args.target):
        print("Error: file not found: %s" % args.target)
        return EXIT_USAGE
    if args.cmd == "detect":
        return cmd_detect(args.target)
    if args.cmd == "info":
        return cmd_info(args.target)
    return cmd_extract(args.target, args.outdir)


if __name__ == "__main__":
    sys.exit(main())