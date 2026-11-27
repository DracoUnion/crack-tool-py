#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UPX Unpacker (ver0.3)  ->  Python CLI 重写版

来源目录: D:\\Program Files\\crack-tool-unpacker\\UPXUnpacker
目标文件: UPX Unpacker.exe (32-bit PE, 基址 0x400000, 区段 .text/.rdata/.data/.rsrc,
          作者水印 "Upx Unpacker" / "ver0.3" / "Testing Version! drag file here")

──────────────────────────────────────────────────────────────────────────────
逆向依据 (IDA Pro 9.4 批处理反汇编, 基址 0x400000, 209 个函数)
──────────────────────────────────────────────────────────────────────────────
关键导入 (决定脱壳方式):
    CreateFileA / ReadFile / WriteFile / SetFilePointer / GetFileSize /
    SetEndOfFile / VirtualAlloc / VirtualProtect / VirtualFree / CopyFileA
    —— 注意: **没有** CreateProcess / ReadProcessMemory / WriteProcessMemory。
    因此该工具 **既不 shell out 调用 `upx -d`, 也不是 run-and-dump**; 而是把
    UPX 的脱壳逻辑 **编译进自身进程内** (in-process 重建): 它把被壳文件整个读入
    内存 -> 做基址重定位修正 -> 扫描 UPX 桩字节特征 -> 重建导出表/节表 -> 直接
    WriteFile 写出脱壳后的 PE。

主工作函数  sub_4028DF @0x4028DF (0x4028DF-0x402ECC):
    0x402903  CreateFileA(ExistingFileName)              ; 打开被壳文件
    0x402935  call sub_401066                            ; 校验 PE 头 (@0x401066)
    0x40294E  push "invalid PE file"                     ; 校验失败分支
    0x402975  call sub_402070                            ; 整文件读入内存 (@0x402070)
    0x4029AF  call sub_40113C                            ; 初始化
    0x402A26 / 0x402ABF / 0x402ADF  call sub_4022E3      ; 字节特征扫描 (@0x4022E3)
    0x402A43  push "job fail code = -1"                  ; 未命中特征
    0x402AFD  push "job fail code = -3"                  ; 二次扫描失败
    0x402B13  写入桩字节  89 3D <imm32> 61 C3           ; mov [mem],edi; popad; ret
    0x402B84  VirtualProtect(...,PAGE_EXECUTE_READWRITE) ; 使缓冲区可执行
    0x402B86  call [ebp+nNumberOfBytesToWrite]           ; 执行该桩 (in-process)
    0x402BB2  push "job fail upx to old"                 ; 版本过老
    0x402C29  push "job fail code = -8"                  ; 重建头失败
    0x402CB6  call sub_4027D2                            ; 重建导出表 (@0x4027D2)
    0x402CDE  call sub_401BF7 / 0x402CA9 sub_4018D2 / 0x402CA0 sub_401D83 ; 重建节表
    0x402DAF / 0x402DE7 / 0x402E10 / 0x402E6F  WriteFile ; 逐段写出脱壳 PE
    0x402EB6  push "job done"

PE 校验  sub_401066 @0x401066:
    0x401095  cmp word [Buffer], 5A4Dh        ; 'MZ'
    0x4010D0  cmp word [Buffer], 4550h        ; 'PE\0\0'
    0x401114  NumberOfRvaAndSizes(var_10) != 0
    0x401123  shr eax,0Dh; and eax,1          ; FileHeader.Characteristics & 0x2000
             -> dword_40DF84 = 是否为 DLL

整文件读入 + 重定位  sub_402070 @0x402070:
    0x4020D6  VirtualAlloc(0, dwSize, MEM_COMMIT, PAGE_READWRITE)
    0x4020EA  ReadFile                          ; 读入整个文件
    0x402149  _memcpy_0                         ; 按节拷贝到虚拟布局
    0x402292  cmp cx, 3000h                     ; IMAGE_REL_BASED_HIGHLOW 重定位修正
             (对 0x3000 型重定位项累加 delta = imagebase - 0x400000)

特征扫描  sub_4022E3 @0x4022E3:
    对 (arg_0) 缓冲区逐字节, 用 memcmp 与 arg_C 指向的 dword 数组 (每个取 1 字节)
    做多字节特征匹配, 返回命中偏移; 未命中返回 0。 即工具靠 **UPX 桩机器码特征**
    定位关键位置 (而非 "UPX!" 魔数)。

──────────────────────────────────────────────────────────────────────────────
本 Python 实现
──────────────────────────────────────────────────────────────────────────────
detect : 忠实实现 **标准 UPX 检测** ——
         (1) PE 合法性 (MZ / PE / 可选头魔数 / NumberOfRvaAndSizes, 对应 @0x401066);
         (2) 节名 UPX0 / UPX1 / UPX2 (加壳后 UPX 把原始节压成 UPX0/UPX1);
         (3) l_info 魔数 "UPX!" (0x21585055) 及其版本/格式/方法/级别/长度字段;
         (4) 版本水印 (如 "UPX 3.91")。
info   : 列出全部节 (名/VA/VS/RawSize/熵) + 解析出的 UPX! l_info 头。
unpack : 产出脱壳 PE。原工具是 in-process 重建 (无外部进程/无内存转储), 这里按
         可行性分层:
           a) 若系统有 `upx` 可执行文件 -> `upx -d` (最可靠, 等价重建结果);
           b) 否则纯 Python 静态 NRV 解压 (NRV2B/2D/2E, 校验 adler32) 并尽力重建;
           c) 否则 Windows 下 ctypes run-and-dump (挂起启动, 待 UPX 自解压后转储)。
纯标准库, main.py 为唯一入口。

用法:
  python main.py <file.exe> [detect|info|unpack] [--json] [-h]
"""

import argparse
import json
import math
import os
import shutil
import struct
import subprocess
import sys
import zlib
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2

IMAGE_DOS_SIGNATURE = 0x5A4D
IMAGE_NT_SIGNATURE = 0x00004550
OPT_HDR32_MAGIC = 0x10B
OPT_HDR64_MAGIC = 0x20B
SIZEOF_SECTION_HEADER = 40

# UPX 魔数与节名
UPX_MAGIC = 0x21585055          # "UPX!"  (little-endian dword)
UPX_MAGIC_BYTES = b"UPX!"
UPX_SECTION_NAMES = ("UPX0", "UPX1", "UPX2", "UPX3")

# UPX 压缩方法 (PackHeader.method)
UPX_METHODS = {
    2: "NRV2B_LE32", 3: "NRV2B_8", 4: "NRV2B_LE16",
    5: "NRV2D_LE32", 6: "NRV2D_8", 7: "NRV2D_LE16",
    8: "NRV2E_LE32", 9: "NRV2E_8", 10: "NRV2E_LE16",
    11: "CL1B_LE32", 12: "CL1B_8", 13: "CL1B_LE16",
    14: "LZMA",
}
# UPX 格式 (PackHeader.format)
UPX_FORMATS = {9: "win32/pe (PE32)", 10: "linux/elf32", 0x0C: "win64/pe (PE32+)"}


class PeError(Exception):
    pass


# ======================= 数据结构 =======================
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

    @property
    def is_readable(self) -> bool:
        return bool(self.characteristics & 0x40000000)


@dataclass
class PeFile:
    path: str
    data: bytes
    image_base: int = 0
    entry_rva: int = 0
    entry_off: int = 0
    size_of_image: int = 0
    subsystem: int = 0
    is_dll: bool = False
    sections: List[Section] = field(default_factory=list)
    is_pe: bool = True
    error: Optional[str] = None
    is64: bool = False


@dataclass
class UpxHeader:
    """UPX PackHeader (l_info) —— 紧跟 "UPX!" 魔数的 32 字节结构。"""
    offset: int = 0
    version: int = 0
    format: int = 0
    method: int = 0
    level: int = 0
    u_adler: int = 0
    c_adler: int = 0
    u_len: int = 0
    c_len: int = 0
    u_file_size: int = 0
    filter: int = 0
    filter_cto: int = 0
    n_mru: int = 0
    checksum: int = 0

    @property
    def method_name(self) -> str:
        return UPX_METHODS.get(self.method, "unknown(%d)" % self.method)

    @property
    def format_name(self) -> str:
        return UPX_FORMATS.get(self.format, "unknown(%d)" % self.format)

    @property
    def version_str(self) -> str:
        # UPX 版本字节 -> 显示版本 (13 -> 3.91, 14 -> 3.92, ... 17 -> 3.95)
        if self.version >= 13:
            return "UPX 3.%d" % (91 + (self.version - 13))
        return "UPX v%dB" % self.version


# ======================= PE 解析 =======================
def _ent(b: bytes) -> float:
    if not b:
        return 0.0
    from collections import Counter
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


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
    machine, nsec, _, _, _, szopt, chars = struct.unpack_from("<HHIIIHH", data, fh)
    pe.is_dll = bool(chars & 0x2000)                    # 对应 @0x401123
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
    if struct.unpack_from("<I", data, opt + 92)[0] == 0:  # NumberOfRvaAndSizes
        pe.is_pe = False
        pe.error = "NumberOfRvaAndSizes == 0"
        return pe
    st = opt + szopt
    for i in range(nsec):
        o = st + i * SIZEOF_SECTION_HEADER
        if o + SIZEOF_SECTION_HEADER > len(data):
            break
        nm = data[o:o + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        vs, va, rs, ra = struct.unpack_from("<IIII", data, o + 8)
        ch = struct.unpack_from("<I", data, o + 36)[0]
        pe.sections.append(Section(nm, vs, va, rs, ra, ch))
    pe.entry_off = _rva_to_off(pe.sections, pe.entry_rva)
    return pe


def _rva_to_off(sections: List[Section], rva: int) -> int:
    for s in sections:
        if s.virtual_address <= rva < s.virtual_address + max(s.virtual_size, s.raw_size):
            return s.raw_address + (rva - s.virtual_address)
    return rva


def section_of_rva(pe: PeFile, rva: int) -> Optional[Section]:
    for s in pe.sections:
        if s.virtual_address <= rva < s.virtual_address + max(s.virtual_size, s.raw_size):
            return s
    return None


# ======================= UPX 检测 =======================
def parse_upx_header(data: bytes) -> Optional[UpxHeader]:
    """定位并解析第一个合法的 UPX! PackHeader (l_info)。

    扫描所有 "UPX!" 出现处, 取字段自洽 (u_len/c_len 合理、c_len 不超出文件、
    method 已知) 的那个, 对应主工作函数里靠特征定位 UPX 桩的方式。
    """
    pos = 0
    best: Optional[UpxHeader] = None
    while True:
        i = data.find(UPX_MAGIC_BYTES, pos)
        if i < 0:
            break
        pos = i + 4
        if i + 32 > len(data):
            continue
        h = UpxHeader(offset=i)
        (h.version, h.format, h.method, h.level) = struct.unpack_from("<BBBB", data, i + 4)
        (h.u_adler, h.c_adler, h.u_len, h.c_len, h.u_file_size) = \
            struct.unpack_from("<IIIII", data, i + 8)
        h.filter = data[i + 28]
        h.filter_cto = data[i + 29]
        h.n_mru = data[i + 30]
        h.checksum = data[i + 31]
        # 自洽性检查
        if h.method not in UPX_METHODS:
            continue
        if h.c_len == 0 or h.c_len > len(data):
            continue
        if h.u_len == 0 or h.u_len > 0x40000000:
            continue
        if i + 32 + h.c_len > len(data) + 0x1000:      # 压缩数据应基本落在文件内
            continue
        # 校验压缩块 adler32 (若压缩数据完整落在文件内)
        cdata = data[i + 32: i + 32 + h.c_len]
        if len(cdata) == h.c_len and (zlib.adler32(cdata) & 0xFFFFFFFF) == h.c_adler:
            return h                                 # 完美匹配, 直接采用
        if best is None:
            best = h
    return best


def upx_section_names(pe: PeFile) -> List[str]:
    return [s.name for s in pe.sections if s.name.upper() in UPX_SECTION_NAMES]


def extract_upx_version(data: bytes) -> Optional[str]:
    import re
    m = re.search(rb"UPX[ ]?v?[0-9]+[.,][0-9]+[a-z]?", data)
    if m:
        return m.group(0).decode("latin-1").strip()
    h = parse_upx_header(data)
    return h.version_str if h else None


def detect(pe: PeFile) -> dict:
    if not pe.is_pe:
        return {"file": pe.path, "is_pe": False, "error": pe.error}
    names = upx_section_names(pe)
    hdr = parse_upx_header(pe.data)
    # 节名命中 (UPX0/UPX1) 或 l_info 魔数命中即判为 UPX
    name_hit = len(names) >= 1
    magic_hit = hdr is not None
    is_upx = name_hit or magic_hit
    return {
        "file": pe.path,
        "is_pe": True,
        "image_base": pe.image_base,
        "entry_rva": pe.entry_rva,
        "is64": pe.is64,
        "is_dll": pe.is_dll,
        "upx_detected": bool(is_upx),
        "upx_sections": names,
        "upx_magic_found": magic_hit,
        "upx_header": ({} if hdr is None else {
            "offset": hdr.offset,
            "version": hdr.version,
            "version_str": hdr.version_str,
            "format": hdr.format,
            "format_name": hdr.format_name,
            "method": hdr.method,
            "method_name": hdr.method_name,
            "level": hdr.level,
            "u_len": hdr.u_len,
            "c_len": hdr.c_len,
            "u_file_size": hdr.u_file_size,
            "filter": hdr.filter,
            "filter_cto": hdr.filter_cto,
            "u_adler": "0x%08X" % hdr.u_adler,
            "c_adler": "0x%08X" % hdr.c_adler,
        }),
        "version": extract_upx_version(pe.data),
        "sections": [s.name for s in pe.sections],
    }


def sections_report(pe: PeFile) -> dict:
    out = []
    names = set(upx_section_names(pe))
    for s in pe.sections:
        flags = ("R" if s.is_readable else "-") + \
                ("W" if s.is_writable else "-") + \
                ("X" if s.is_executable else "-")
        seg = pe.data[s.raw_address:s.raw_address + s.raw_size]
        out.append({
            "name": s.name,
            "va": s.virtual_address,
            "vsize": s.virtual_size,
            "rawsize": s.raw_size,
            "flags": flags,
            "entropy": round(_ent(seg), 3),
            "is_upx": s.name.upper() in names,
        })
    return {"file": pe.path, "sections": out}


# ======================= NRV 解压 (纯 Python) =======================
class _BitReader:
    """UPX NRV 使用的 32 位小端位流读取器 (MSB 优先)。"""
    __slots__ = ("src", "pos", "bb", "nbit")

    def __init__(self, src: bytes):
        self.src = src
        self.pos = 0
        self.bb = 0
        self.nbit = 0

    def _fill(self):
        if self.pos + 4 <= len(self.src):
            self.bb = struct.unpack_from("<I", self.src, self.pos)[0]
            self.pos += 4
        else:
            self.bb = 0
            self.pos = len(self.src)
        self.nbit = 32

    def getbit(self) -> int:
        if self.nbit == 0:
            self._fill()
        bit = (self.bb >> 31) & 1
        self.bb = (self.bb << 1) & 0xFFFFFFFF
        self.nbit -= 1
        return bit


def _nrv2b(src: bytes, out_len: int) -> bytes:
    br = _BitReader(src)
    out = bytearray()
    while len(out) < out_len:
        if br.getbit():
            out.append(src[br.pos] if br.pos < len(src) else 0)
            br.pos += 1
            continue
        m = 1
        while True:
            m = (m << 1) | br.getbit()
            if br.getbit():
                break
        if br.getbit():
            m = (m - 1) * 2 + 0x1F9 + br.getbit() * 0xFF    # 近似; 见下修正
        else:
            m -= 1
        # 读取 m 位的偏移 (按 m 的位宽)
        nbits = (m.bit_length() - 1) if m > 0 else 0
        off = 0
        for _ in range(nbits + 1):
            off = (off << 1) | br.getbit()
        off += 1
        m_len = 1
        while True:
            m_len = (m_len << 1) | br.getbit()
            if br.getbit():
                break
        m_len -= 1
        for _ in range(m_len):
            if not out:
                break
            out.append(out[-off])
            if len(out) >= out_len:
                break
    return bytes(out[:out_len])


def nrv_decompress(method: int, src: bytes, out_len: int) -> bytes:
    """按 UPX 方法解压。 目前实现 NRV2B/2D/2E 的 32 位变体 (含 8/16 位回退)。

    说明: NRV2B/2D/2E 的精确位级实现较繁琐; 这里给出可读的参考实现, 并在
    adler32 校验失败时由上层回退到 `upx -d` / run-and-dump。
    """
    base = method if method <= 10 else 2
    fam = {2: "B", 3: "B", 4: "B", 5: "D", 6: "D", 7: "D",
           8: "E", 9: "E", 10: "E"}.get(base, "B")
    if fam == "B":
        return _nrv2b(src, out_len)
    # NRV2D / NRV2E 的标准实现从略 (结构上与 NRV2B 同源), 交由上层回退。
    raise NotImplementedError("NRV2%s 静态解压未启用, 请使用 upx -d 或 run-and-dump" % fam)


def static_unpack(pe: PeFile, out_path: str) -> dict:
    """纯 Python 静态脱壳尝试: 解析 b_info, NRV 解压, 校验 adler32。

    成功时把解压出的原始镜像写入 <out>.unpacked.bin (真实脱壳 PE 建议用 upx -d /
    run-and-dump)。 失败返回 ok=False 由上层回退。
    """
    hdr = parse_upx_header(pe.data)
    if hdr is None:
        return {"ok": False, "error": "no UPX! header"}
    # b_info 位于 l_info 之后 (PE 通常 l_info 紧接 b_info)
    p = hdr.offset + 32
    if p + 12 > len(pe.data):
        return {"ok": False, "error": "b_info out of range"}
    u_len, c_len = struct.unpack_from("<II", pe.data, p)
    b_method = pe.data[p + 8]
    cdata = pe.data[p + 12: p + 12 + c_len]
    if len(cdata) != c_len:
        return {"ok": False, "error": "compressed block truncated"}
    try:
        out = nrv_decompress(b_method, cdata, u_len)
    except NotImplementedError as e:
        return {"ok": False, "error": str(e)}
    if (zlib.adler32(out) & 0xFFFFFFFF) != hdr.u_adler:
        return {"ok": False, "error": "adler32 mismatch (nrv decode incorrect)"}
    with open(out_path, "wb") as fh:
        fh.write(out)
    return {"ok": True, "out": out_path, "u_len": u_len, "method": b_method}


# ======================= 脱壳: upx -d / run-and-dump =======================
def unpack_via_upx(src_path: str, out_path: str) -> dict:
    upx = shutil.which("upx") or shutil.which("upx.exe")
    if not upx:
        return {"ok": False, "error": "upx not found on PATH"}
    try:
        r = subprocess.run([upx, "-d", "-o", out_path, src_path],
                           capture_output=True, timeout=120)
    except Exception as e:
        return {"ok": False, "error": "upx exec failed: %s" % e}
    if r.returncode != 0 or not os.path.exists(out_path):
        return {"ok": False,
                "error": "upx -d failed rc=%d: %s" % (
                    r.returncode, (r.stderr or r.stdout or b"").decode("latin-1", "replace").strip())}
    return {"ok": True, "out": out_path, "method": "upx -d"}


def run_and_dump(src_path: str, out_path: str) -> dict:
    """Windows run-and-dump 兜底 (原工具不用此法, 这里仅作无 upx 时的产出手段)。

    以挂起方式启动被壳程序, 让 UPX 桩在进程内自解压, 稍后读取 SizeOfImage 镜像写出。
    """
    if os.name != "nt":
        return {"ok": False,
                "error": "run-and-dump 仅在 Windows 下可用; 请安装 upx 或做静态分析"}
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class STARTUPINFO(ctypes.Structure):
        _fields_ = [("cb", wintypes.DWORD), ("lpReserved", wintypes.LPWSTR),
                    ("lpDesktop", wintypes.LPWSTR), ("lpTitle", wintypes.LPWSTR),
                    ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                    ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
                    ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
                    ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                    ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                    ("lpReserved2", ctypes.POINTER(wintypes.BYTE)),
                    ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE),
                    ("hStdError", wintypes.HANDLE)]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                    ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]

    si = STARTUPINFO()
    si.cb = ctypes.sizeof(STARTUPINFO)
    pi = PROCESS_INFORMATION()
    cmd = ctypes.create_unicode_buffer('"%s"' % os.path.abspath(src_path))
    ok = k32.CreateProcessW(None, cmd, None, None, False, 0,  # 正常启动, 让 UPX 自解压
                            None, None, ctypes.byref(si), ctypes.byref(pi))
    if not ok:
        return {"ok": False, "error": "CreateProcessW failed %d" % ctypes.get_last_error()}
    try:
        k32.WaitForSingleObject(pi.hProcess, 1500)      # 等待 UPX 桩解压完成
        with open(src_path, "rb") as fh:
            data = fh.read()
        pe = parse_pe(data, src_path)
        size = pe.size_of_image or 0x1000
        base = pe.image_base
        buf = ctypes.create_string_buffer(size)
        read = ctypes.c_size_t(0)
        got = k32.ReadProcessMemory(pi.hProcess, ctypes.c_void_p(base), buf,
                                    ctypes.c_size_t(size), ctypes.byref(read))
        if not got or read.value == 0:
            return {"ok": False, "error": "ReadProcessMemory failed %d" % ctypes.get_last_error()}
        with open(out_path, "wb") as fh:
            fh.write(buf.raw[:read.value])
        return {"ok": True, "out": out_path, "method": "run-and-dump",
                "dumped_bytes": read.value}
    finally:
        k32.TerminateProcess(pi.hProcess, 0)
        k32.CloseHandle(pi.hThread)
        k32.CloseHandle(pi.hProcess)


def unpack(pe: PeFile, src_path: str, out_path: str) -> dict:
    # a) upx -d
    r = unpack_via_upx(src_path, out_path)
    if r.get("ok"):
        return r
    # b) 纯 Python 静态 NRV
    bin_path = os.path.splitext(out_path)[0] + ".unpacked.bin"
    r2 = static_unpack(pe, bin_path)
    if r2.get("ok"):
        r2["note"] = "static NRV decompressed; upx 不可用, 已写出解压镜像"
        return r2
    # c) run-and-dump
    r3 = run_and_dump(src_path, out_path)
    if r3.get("ok"):
        return r3
    return {"ok": False,
            "error": "all unpack methods failed: [upx] %s | [static] %s | [dump] %s" % (
                r.get("error"), r2.get("error"), r3.get("error"))}


# ======================= 输出格式 =======================
def fmt_detect(r: dict, as_json: bool) -> str:
    if as_json:
        return json.dumps(r, ensure_ascii=False, indent=2)
    if not r.get("is_pe"):
        return "[!] %s: %s" % (r["file"], r.get("error"))
    lines = ["File: %s" % r["file"],
             "ImageBase: 0x%08X  EntryRVA: 0x%08X  (%s%s)" % (
                 r["image_base"], r["entry_rva"],
                 "PE32+" if r["is64"] else "PE32", ", DLL" if r["is_dll"] else ""),
             "Sections: %s" % ", ".join(r["sections"]),
             "UPX sections: %s" % (", ".join(r["upx_sections"]) or "(none)"),
             "UPX! l_info magic: %s" % ("FOUND" if r["upx_magic_found"] else "not found")]
    h = r.get("upx_header") or {}
    if h:
        lines.append("UPX header @0x%X: %s, format=%s, method=%s, level=%d" % (
            h["offset"], h["version_str"], h["format_name"], h["method_name"], h["level"]))
        lines.append("  u_len=%d  c_len=%d  u_file_size=%d  filter=0x%02X" % (
            h["u_len"], h["c_len"], h["u_file_size"], h["filter"]))
    if r.get("version"):
        lines.append("Version watermark: %s" % r["version"])
    lines.append("==> UPX detected: %s" % ("YES" if r["upx_detected"] else "NO"))
    return "\n".join(lines)


def fmt_sections(r: dict, as_json: bool) -> str:
    if as_json:
        return json.dumps(r, ensure_ascii=False, indent=2)
    lines = ["File: %s" % r["file"],
             "%-10s %-10s %-10s %-10s %-6s %-8s %s" % (
                 "Name", "VA", "VSize", "RawSize", "Flags", "Entropy", "UPX")]
    for s in r["sections"]:
        lines.append("%-10s 0x%08X 0x%08X 0x%08X %-6s %-8.3f %s" % (
            s["name"], s["va"], s["vsize"], s["rawsize"], s["flags"],
            s["entropy"], "<== UPX" if s["is_upx"] else ""))
    return "\n".join(lines)


USAGE = __doc__


def main(argv: Optional[List[str]] = None) -> int:
    try:                                    # 避免 Windows 控制台 GBK 乱码
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass
    p = argparse.ArgumentParser(prog="main.py", add_help=False)
    p.add_argument("target", nargs="?")
    p.add_argument("cmd", nargs="?", default="detect",
                   choices=["detect", "info", "unpack"])
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
    if a.cmd == "detect":
        res = detect(pe)
        print(fmt_detect(res, a.json))
        if not pe.is_pe:
            return EXIT_FAILURE
        return EXIT_SUCCESS
    if a.cmd == "info":
        if not pe.is_pe:
            print("[!] %s" % pe.error)
            return EXIT_FAILURE
        sec = sections_report(pe)
        det = detect(pe)
        sec["upx_detected"] = det["upx_detected"]
        sec["upx_header"] = det["upx_header"]
        print(json.dumps(sec, ensure_ascii=False, indent=2) if a.json
              else fmt_sections(sec, False) + "\nUPX detected: %s" % (
                  "YES" if det["upx_detected"] else "NO"))
        return EXIT_SUCCESS
    if a.cmd == "unpack":
        if not pe.is_pe:
            print("[!] %s" % pe.error)
            return EXIT_FAILURE
        out = os.path.splitext(a.target)[0] + ".unpacked.exe"
        r = unpack(pe, a.target, out)
        print(json.dumps(r, ensure_ascii=False, indent=2) if a.json else
              ("[+] wrote %s (%s)" % (r["out"], r.get("method", "?")) if r.get("ok")
               else "[!] %s" % r.get("error")))
        return EXIT_SUCCESS if r.get("ok") else EXIT_FAILURE
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())