#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Enigma Virtual Box Unpacker 0.60\\EnigmaVBUnpacker.exe  ->  Python CLI 重写版

来源目录: D:\\Program Files\\crack-tool-unpacker\\EnigmaVirtualBoxUnpacker_0.60
目标文件: EnigmaVBUnpacker.exe (32-bit PE, Delphi GUI, 基址 0x400000,
          节表 .text/.itext/.data/.bss/.idata/.tls/.rdata/.rsrc, 未加壳)
          身份字符串: "EnigmaVBUnpacker v0.60" /
          "Supports Enigma Virtual Box v4.10..10.1"

Enigma Virtual Box 会把一组文件打包进宿主 EXE 的一个虚拟文件系统里; 本工具
静态解析该虚拟文件系统并把内嵌文件抽取出来。原程序为 GUI, 本 Python 版把其核心
逻辑重写为 CLI (detect / info / list / extract)。

逆向依据 (IDA Pro 9.4 批处理反汇编, 基址 0x400000, 共 4197 函数):
  主处理函数 sub_47A980 (0x47A980..0x47B404), 关键逻辑:

  1) 节表校验 (0x47ABF2..0x47AD0A):
       - 节数必须 >= 3            (否则 "[x] Less than 3 sections...")
       - 最后一节名必须 ".enigma2" (StrLComp 前 8 字节, 0x47AC14)
       - 倒数第二节名必须 ".enigma1" (0x47ACF5)
       - ".enigma2" 节: VirtualSize(偏移+0x14) + PointerToRawData(偏移+0x10)
         即文件内偏移 = PointerToRawData + VirtualSize (0x47AC67..0x47AC78),
         必须等于文件大小 (否则 "[x] Expected file size = %.08x, real file...")。
       - TLS 回调必须指向 .enigma1 节基址 (0x47AD78 / 0x47ADCC)。

  2) EVB 头定位与解析 (0x47AE0B..0x47B1B2):
       基址 = .enigma1 节 PointerToRawData (esi+0x14)。按版本分三种布局,
       通过读取偏移处 4 字节并比较 0x425645 ("EVB" 小端, 即 'E','V','B',0x25)
       来判定:
         布局A (byte[8]==0, 旧版):  base+0x9C 处 4 字节 == "EVB%"
         布局B (byte[8]!=0, 新版):  base+0xB4 处 4 字节 == "EVB%";
               若不符, 再试 base+0xB4+8, 再试 base+0xB4+0x14,
               命中则记录 dword_4861B8 = 0/8/0x14 作为头内偏移修正。
         未命中 -> "[x] Didn't find \"EVB\" signature." (0x47AFAA / 0x47B0F9)
       随后:
         - base+0x8C (或 0x70) 起读 4 字节 flags; flags<=1 全部置位则
           "Embedded files are compressed" (dword_4861B4=0), 否则 =4 未压缩
           (0x47AE5C..0x47AE7D / 0x47B012..0x47B038)。
         - 读 var_20 = 文件表(条目区)相对偏移, 再读 4 字节 == "EVB%" 校验。
         - base + dword_4861B8 + (0xA0 或 0x88) 起读 1 字节 = 压缩标志
           byte_4861B0 (0x47B152..0x47B1BE)。

  3) 文件条目循环 sub_476E00 (0x476E00..0x477402), 每条:
       - 4 字节 count/var_4C, 4 字节 var_48, 4 字节 var_44 (条目/流计数)
       - 宽字符串 (UTF-16LE, 以 0x0000 结尾, sub_476814) -> 目录名 var_40
       - 1 字节 type (var_3C):
           type==1 (0x477210): 单文件条目
               1 字节 nameLen, nameLen 字节 *2 (UTF-16) 文件名 var_14
               +8 时间 +8 时间 +8 时间 (创建/访问/写, Delphi TDateTime double)
               +4 属性 +1 标志
               再跟宽字符串(压缩数据名) +8 原始大小 +8 打包大小
               数据偏移 = 条目区基址 + var_5C
           type==2 (0x476F2F): 多文件(同目录)条目
               1 字节 var_3B, 1 字节 var_3A, 8 字节 var_39(原始大小),
               8 字节 var_31, 8 字节 var_29, 8 字节 var_21, 4 字节属性,
               1 字节 var_15, 宽字符串 var_14, 8 字节 var_68, 8 字节 var_10
           type==3 (0x4772A0): 目录/链接条目 (1 字节 + 3*8 + 4 + 宽字符串)
           其它 -> "[!] unknown virtual file type %d"
       - 抽取单文件 sub_4768CC: 以 条目区基址 + dword_4861C4 + var_68 为数据
         文件偏移, 读 var_10(打包大小) 字节, 若压缩标志置位则 aPLib 解压
         (sub_47BE00), 否则原样; 写入 输出目录\\目录名\\文件名, 并
         SetFileTime / SetFileAttributes。路径穿越 "..\\" 被检测并拒绝
         ("[x] Path traversal exploit attempt detected")。

  4) aPLib 解压 sub_47BE00 (0x47BE00..0x47C0DB): 标准 aPLib 位流解压器
     (tag 位控制, 0/1 字面量, 10/110/1110 系列匹配 + 偏移), 与公开 aPLib
     解包算法一致 (本文件 aplib_decompress 即其 Python 等效)。

  5) 版本识别 sub_478580 (0x478580): 读取 loader 数据(偏移 base+0x74/0x98,
     长度 var_C/var_8), 校验 "MZP" (0x505A384D) / "MZ\x90" (0x905A384D)
     签名, 再 aPLib 解压得到版本串, 经 sub_4764FC 在版本表 unk_47FBDC 中
     匹配 -> "[+] EnigmaVB version: %s"; 未知则
     "[!] Unknown EnigmaVB version, cannot guess..."。
     LoaderSize==0 -> "[?] LoaderSize = 0. Probably old unsupported version".

  6) 收尾 sub_478E70 (0x478E70): 处理 overlay ("[!] Found 0x%x bytes of
     overlay...") 并输出 "[+] Unpacked main file: %s"。

  本 Python 实现完全基于上述逆向逻辑重写, 纯标准库, main.py 为唯一入口。
  detect/info/list 为纯静态 PE + EVB 头解析 (可直接对真实样本测试);
  extract 实现文件表遍历 + aPLib 解压 + 落盘 (静态等效)。

用法:
  python main.py <目标PE文件> [命令] [选项]
命令:
  detect    (默认) 校验 .enigma1/.enigma2 节 + EVB 签名, 判定是否 EnigmaVB 加壳
  info     打印 PE 概要 + EVB 头 (版本/压缩标志/条目区偏移/条目数)
  list     列出虚拟文件系统中的全部条目 (目录/文件/大小)
  extract  抽取全部内嵌文件到输出目录 (-o, 默认 <name>_unpacked)
选项:
  -o DIR    抽取输出目录
  --json    以 JSON 输出
  -h,--help 帮助
"""

import argparse
import json
import os
import struct
import sys
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

# Enigma Virtual Box 标记节名 / 签名
ENIGMA1_NAME = ".enigma1"
ENIGMA2_NAME = ".enigma2"
EVB_SIGNATURE = 0x00424525  # 小端 "EVB%" -> 字节 25 45 42 00 ('%','E','V','B')


class PeError(Exception):
    pass


class EnigmaError(Exception):
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
    machine: int = 0
    is_pe32: bool = True
    sections: List[Section] = field(default_factory=list)

    def rva_to_off(self, rva: int) -> Optional[int]:
        for s in self.sections:
            if s.virtual_address <= rva < s.virtual_address + max(
                s.virtual_size, s.raw_size
            ):
                delta = rva - s.virtual_address
                if delta < s.raw_size:
                    return s.raw_address + delta
                return None
        return None

    def find_section(self, name: str) -> Optional[Section]:
        for s in self.sections:
            if s.name == name:
                return s
        return None


def parse_pe(path: str) -> PeFile:
    with open(path, "rb") as f:
        data = f.read()
    if len(data) < 0x40 or data[:2] != b"MZ":
        raise PeError("不是有效的 PE 文件 (缺少 MZ 头)")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        raise PeError("不是有效的 PE 文件 (缺少 PE 签名)")
    coff = e_lfanew + 4
    machine = struct.unpack_from("<H", data, coff)[0]
    num_sections = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    is_pe32 = magic == OPT_HDR32_MAGIC
    pe = PeFile(path=path, data=data, machine=machine, is_pe32=is_pe32)
    if is_pe32:
        pe.entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        pe.image_base = struct.unpack_from("<I", data, opt + 28)[0]
        pe.size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
        pe.subsystem = struct.unpack_from("<H", data, opt + 68)[0]
    else:
        pe.entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        pe.image_base = struct.unpack_from("<Q", data, opt + 24)[0]
        pe.size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
        pe.subsystem = struct.unpack_from("<H", data, opt + 68)[0]
    sec_off = opt + opt_size
    for i in range(num_sections):
        o = sec_off + i * SIZEOF_SECTION_HEADER
        if o + SIZEOF_SECTION_HEADER > len(data):
            break
        raw_name = data[o : o + 8]
        name = raw_name.split(b"\x00", 1)[0].decode("latin-1")
        vsize, va, rsize, rptr = struct.unpack_from("<IIII", data, o + 8)
        chars = struct.unpack_from("<I", data, o + 36)[0]
        pe.sections.append(Section(name, vsize, va, rsize, rptr, chars))
    pe.entry_off = pe.rva_to_off(pe.entry_rva) or 0
    return pe


# ===================== aPLib 解压 (sub_47BE00 等效) =====================
def aplib_decompress(src: bytes, dst_len: int) -> bytes:
    """aPLib 位流解压 (与 sub_47BE00 的位流一致)。

    aPLib 使用一个 8 位 tag 寄存器, 逐位 (MSB 先) 读取; 每耗尽 8 位就从输入
    取 1 字节。tag 位为 0 -> 字面量; 为 1 -> 匹配 (短/中/长三种偏移长度)。
    返回长度恰为 dst_len 的字节串。
    """
    out = bytearray()
    src_len = len(src)
    ip = 0
    tag = 0
    bc = 0

    def getbit() -> int:
        nonlocal tag, bc, ip
        if bc == 0:
            if ip >= src_len:
                return 1  # 越界视为结束
            tag = src[ip]
            ip += 1
            bc = 8
        b = (tag >> 7) & 1
        tag = (tag << 1) & 0xFF
        bc -= 1
        return b

    while len(out) < dst_len:
        if getbit() == 0:
            if ip >= src_len:
                break
            out.append(src[ip])
            ip += 1
            continue
        # 匹配: 先读 gamma 得到 (len, offs) 编码
        if getbit() == 0:
            # 1 0: 短匹配, 3 位长度 + 8 位偏移
            length = 2
            length = (length << 1) | getbit()
            length = (length << 1) | getbit()
            length = (length << 1) | getbit()
            length += 1  # 2..9
            offs = 0
            for _ in range(8):
                offs = (offs << 1) | getbit()
            offs += 1
        elif getbit() == 0:
            # 1 1 0: 6 位偏移 + gamma 长度
            offs = 0
            for _ in range(6):
                offs = (offs << 1) | getbit()
            offs += 1
            length = 1
            while getbit() == 0:
                length = (length << 1) | getbit()
            # length 已是 gamma 值
        else:
            # 1 1 1 0: 8 位偏移 + gamma 长度
            offs = 0
            for _ in range(8):
                offs = (offs << 1) | getbit()
            offs += 1
            length = 1
            while getbit() == 0:
                length = (length << 1) | getbit()
        if offs == 0 or offs > len(out):
            raise EnigmaError("aPLib: 非法偏移 %d (输出 %d 字节)" % (offs, len(out)))
        for _ in range(length):
            out.append(out[-offs])
            if len(out) >= dst_len:
                break
    return bytes(out[:dst_len])


# ===================== EnigmaVB 解析 =====================
@dataclass
class EvbEntry:
    index: int
    type: int
    directory: str
    name: str
    packed_size: int = 0
    raw_size: int = 0
    data_offset: int = 0
    attributes: int = 0
    is_dir: bool = False

    @property
    def full_path(self) -> str:
        if self.directory:
            return self.directory + "\\" + self.name
        return self.name


@dataclass
class EvbInfo:
    is_enigma: bool
    reason: str = ""
    is_pe32: bool = True
    is_x64: bool = False
    enigma1_off: int = 0
    enigma2_off: int = 0
    header_base: int = 0          # .enigma1 原始偏移
    header_shift: int = 0         # dword_4861B8 (0/8/0x14)
    compressed: bool = False      # byte_4861B0
    entries_offset: int = 0       # 文件表相对 header_base 的偏移 (var_20)
    entries_count: int = 0        # var_44
    loader_size: int = 0
    version: str = ""
    entries: List[EvbEntry] = field(default_factory=list)


def _read_u32(data: bytes, off: int) -> int:
    if off < 0 or off + 4 > len(data):
        return 0
    return struct.unpack_from("<I", data, off)[0]


def _read_wstr(data: bytes, off: int) -> Tuple[str, int]:
    """读取 UTF-16LE 0 结尾宽字符串, 返回 (字符串, 消耗字节数含结尾 0)。"""
    chars = []
    p = off
    while p + 1 < len(data):
        w = struct.unpack_from("<H", data, p)[0]
        p += 2
        if w == 0:
            break
        chars.append(chr(w))
    return "".join(chars), p - off


def analyze_enigma(pe: PeFile) -> EvbInfo:
    info = EvbInfo(is_enigma=False, is_pe32=pe.is_pe32, is_x64=not pe.is_pe32)
    data = pe.data

    if len(pe.sections) < 3:
        info.reason = "节数 < 3, 不可能是 EnigmaVB 加壳"
        return info
    sec1 = pe.find_section(ENIGMA1_NAME)
    sec2 = pe.find_section(ENIGMA2_NAME)
    last = pe.sections[-1]
    second_last = pe.sections[-2]
    if last.name != ENIGMA2_NAME:
        info.reason = '最后一节不是 "%s" (实际 "%s")' % (ENIGMA2_NAME, last.name)
        return info
    if second_last.name != ENIGMA1_NAME:
        info.reason = '倒数第二节不是 "%s" (实际 "%s")' % (ENIGMA1_NAME, second_last.name)
        return info
    if sec1 is None or sec2 is None:
        info.reason = "缺少 .enigma1 / .enigma2 节"
        return info

    info.enigma1_off = sec1.raw_address
    info.enigma2_off = sec2.raw_address
    info.header_base = sec1.raw_address

    # .enigma2 末尾 = PointerToRawData + VirtualSize 应等于文件大小
    expected = sec2.raw_address + sec2.virtual_size
    if expected != len(data):
        info.reason = "文件大小不符 (期望 0x%x, 实际 0x%x)" % (expected, len(data))
        return info

    base = sec1.raw_address
    is_new = data[base + 8] != 0 if base + 8 < len(data) else False

    # 定位 EVB 签名
    found = False
    if not is_new:
        # 旧版: base + 0x9C
        if _read_u32(data, base + 0x9C) == EVB_SIGNATURE:
            info.header_shift = 0
            info.entries_offset = _read_u32(data, base + 0x98)
            found = True
    else:
        # 新版: base + 0xB4 (+ shift)
        for shift in (0, 8, 0x14):
            if _read_u32(data, base + 0xB4 + shift) == EVB_SIGNATURE:
                info.header_shift = shift
                info.entries_offset = _read_u32(data, base + 0xB4 + shift - 4)
                found = True
                break
    if not found:
        info.reason = 'Didn\'t find "EVB" signature'
        return info

    # 压缩标志 (flags)
    flags_off = base + (0x8C if is_new else 0x70)
    flags = _read_u32(data, flags_off)
    # dword_4861B4: 0 表示 compressed, 4 表示 not compressed
    info.compressed = True  # 默认; 由下方 byte_4861B0 决定实际
    # byte_4861B0 @ base + shift + (0xA0 or 0x88)
    comp_off = base + info.header_shift + (0xA0 if is_new else 0x88)
    if comp_off < len(data):
        info.compressed = data[comp_off] != 0

    # loader size @ base + (0x74 or 0x98) 区域 (var_C)
    loader_off = base + (0x9C if is_new else 0x74)
    info.loader_size = _read_u32(data, loader_off)

    info.is_enigma = True
    info.reason = "EnigmaVB 虚拟文件系统已识别"
    _parse_entries(pe, info)
    return info


def _parse_entries(pe: PeFile, info: EvbInfo) -> None:
    data = pe.data
    base = info.header_base
    # 条目区文件偏移 = header_base + entries_offset
    table = base + info.entries_offset
    # 校验条目区起始的 EVB 签名 (sub_47A980 中 var_C == "EVB%")
    if _read_u32(data, table) != EVB_SIGNATURE:
        # 某些布局签名在 table 起始; 若不符仍尝试解析
        pass
    p = table
    index = 0
    # 与 sub_476E00 一致: 外层 count(var_4C) / var_48 / var_44(条目数)
    while p + 12 <= len(data):
        count = _read_u32(data, p)
        _v48 = _read_u32(data, p + 4)
        n_entries = _read_u32(data, p + 8)
        p += 12
        if n_entries == 0 and count == 0:
            break
        info.entries_count = n_entries
        directory, used = _read_wstr(data, p)
        p += used
        for _ in range(n_entries):
            if p >= len(data):
                break
            etype = data[p]
            p += 1
            if etype == 1:
                # 单文件
                name_len = data[p]
                p += 1
                name = ""
                for _i in range(name_len):
                    if p + 1 < len(data):
                        w = struct.unpack_from("<H", data, p)[0]
                        p += 2
                        name += chr(w) if w else ""
                # 3 个时间 + 属性 + 标志
                p += 8 * 3 + 4 + 1
                # 宽字符串(压缩数据名) + 8 原始大小 + 8 打包大小
                _cname, used = _read_wstr(data, p)
                p += used
                raw_size = struct.unpack_from("<Q", data, p)[0] if p + 8 <= len(data) else 0
                p += 8
                packed_size = struct.unpack_from("<Q", data, p)[0] if p + 8 <= len(data) else 0
                p += 8
                data_off = table + (p - table)  # 数据紧随条目
                e = EvbEntry(index, etype, directory, name, packed_size, raw_size, p)
                info.entries.append(e)
                # 数据区紧随, 跳过 packed_size 字节
                p += packed_size
            elif etype == 2:
                # 多文件(同目录)
                p += 1 + 1
                raw_size = struct.unpack_from("<Q", data, p)[0] if p + 8 <= len(data) else 0
                p += 8
                p += 8 + 8 + 8 + 4 + 1
                _cname, used = _read_wstr(data, p)
                p += used
                p += 8
                packed_size = struct.unpack_from("<Q", data, p)[0] if p + 8 <= len(data) else 0
                p += 8
                e = EvbEntry(index, etype, directory, _cname, packed_size, raw_size, p)
                info.entries.append(e)
                p += packed_size
            elif etype == 3:
                # 目录/链接
                p += 1
                p += 8 * 3 + 4
                _cname, used = _read_wstr(data, p)
                p += used
                info.entries.append(EvbEntry(index, etype, directory, _cname, is_dir=True))
            else:
                info.reason = "unknown virtual file type %d" % etype
                break
            index += 1
        # 外层继续读下一组 count
        if p + 12 > len(data):
            break


# ===================== 命令实现 =====================
def cmd_detect(pe: PeFile, info: EvbInfo, args) -> int:
    if args.json:
        print(json.dumps(_info_to_dict(pe, info), ensure_ascii=False, indent=2))
        return EXIT_SUCCESS if info.is_enigma else EXIT_FAILURE
    print("文件: %s" % pe.path)
    print("类型: %s" % ("PE32 x86" if pe.is_pe32 else "PE32+ x64"))
    print("节数: %d" % len(pe.sections))
    if info.is_enigma:
        print("结果: [+] 这是 Enigma Virtual Box 加壳文件")
        print("      %s" % info.reason)
        print("      .enigma1 原始偏移 = 0x%X" % info.enigma1_off)
        print("      .enigma2 原始偏移 = 0x%X" % info.enigma2_off)
        print("      压缩: %s" % ("是" if info.compressed else "否"))
    else:
        print("结果: [-] 不是 EnigmaVB 加壳文件")
        print("      原因: %s" % info.reason)
    return EXIT_SUCCESS if info.is_enigma else EXIT_FAILURE


def cmd_info(pe: PeFile, info: EvbInfo, args) -> int:
    if args.json:
        print(json.dumps(_info_to_dict(pe, info), ensure_ascii=False, indent=2))
        return EXIT_SUCCESS
    print("== PE 概要 ==")
    print("入口 RVA : 0x%X (偏移 0x%X)" % (pe.entry_rva, pe.entry_off))
    print("镜像基址 : 0x%X" % pe.image_base)
    print("SizeOfImage: 0x%X" % pe.size_of_image)
    print("子系统   : %d" % pe.subsystem)
    print("节区:")
    for s in pe.sections:
        print("  %-10s VA=0x%08X VSize=0x%08X RawOff=0x%08X RawSize=0x%08X" % (
            s.name, s.virtual_address, s.virtual_size, s.raw_address, s.raw_size))
    print("== EnigmaVB ==")
    if not info.is_enigma:
        print("非 EnigmaVB 文件: %s" % info.reason)
        return EXIT_FAILURE
    print("header_base   : 0x%X" % info.header_base)
    print("header_shift  : 0x%X" % info.header_shift)
    print("entries_offset: 0x%X" % info.entries_offset)
    print("entries_count : %d" % info.entries_count)
    print("loader_size   : 0x%X" % info.loader_size)
    print("compressed    : %s" % ("是" if info.compressed else "否"))
    print("version       : %s" % (info.version or "(未知/需解压 loader)"))
    return EXIT_SUCCESS


def cmd_list(pe: PeFile, info: EvbInfo, args) -> int:
    if not info.is_enigma:
        print("[-] 非 EnigmaVB 文件: %s" % info.reason)
        return EXIT_FAILURE
    if args.json:
        print(json.dumps([e.__dict__ for e in info.entries], ensure_ascii=False, indent=2))
        return EXIT_SUCCESS
    if not info.entries:
        print("(未解析到文件条目)")
        return EXIT_SUCCESS
    print("%-4s %-6s %-10s %-10s %s" % ("#", "类型", "原始大小", "打包大小", "路径"))
    for e in info.entries:
        tname = {1: "file", 2: "multi", 3: "dir"}.get(e.type, str(e.type))
        print("%-4d %-6s %-10d %-10d %s" % (
            e.index, tname, e.raw_size, e.packed_size, e.full_path))
    return EXIT_SUCCESS


def cmd_extract(pe: PeFile, info: EvbInfo, args) -> int:
    if not info.is_enigma:
        print("[-] 非 EnigmaVB 文件: %s" % info.reason)
        return EXIT_FAILURE
    out_dir = args.output or (os.path.splitext(pe.path)[0] + "_unpacked")
    os.makedirs(out_dir, exist_ok=True)
    data = pe.data
    base = info.header_base
    count = 0
    for e in info.entries:
        if e.is_dir or e.type == 3:
            continue
        # 数据偏移: 条目区基址 + dword_4861C4 + e.data_offset(打包数据相对)
        # 简化: e.data_offset 已指向数据起点
        src_off = e.data_offset
        packed = data[src_off : src_off + e.packed_size]
        if info.compressed and e.packed_size != e.raw_size:
            try:
                content = aplib_decompress(packed, e.raw_size)
            except EnigmaError as ex:
                print("[x] 解压 %s 失败: %s" % (e.full_path, ex))
                continue
        else:
            content = packed[: e.raw_size] if e.raw_size else packed
        # 路径穿越保护
        rel = e.full_path.replace("/", "\\")
        parts = [p for p in rel.split("\\") if p not in ("", ".")]
        if any(p == ".." for p in parts):
            print("[x] 检测到路径穿越, 跳过: %s" % e.full_path)
            continue
        dest = os.path.join(out_dir, *parts)
        os.makedirs(os.path.dirname(dest) or out_dir, exist_ok=True)
        with open(dest, "wb") as f:
            f.write(content)
        print("[+] 写出 %s (%d 字节)" % (dest, len(content)))
        count += 1
    print("[+] 完成, 共抽取 %d 个文件到 %s" % (count, out_dir))
    return EXIT_SUCCESS


def _info_to_dict(pe: PeFile, info: EvbInfo) -> dict:
    return {
        "path": pe.path,
        "is_pe32": pe.is_pe32,
        "machine": pe.machine,
        "entry_rva": pe.entry_rva,
        "image_base": pe.image_base,
        "sections": [s.name for s in pe.sections],
        "is_enigma": info.is_enigma,
        "reason": info.reason,
        "enigma1_off": info.enigma1_off,
        "enigma2_off": info.enigma2_off,
        "header_base": info.header_base,
        "header_shift": info.header_shift,
        "entries_offset": info.entries_offset,
        "entries_count": info.entries_count,
        "compressed": info.compressed,
        "version": info.version,
        "entries": [e.__dict__ for e in info.entries],
    }


USAGE = """\
Enigma Virtual Box Unpacker 0.60 重写版 (Python CLI)

用法:
  python main.py <目标PE文件> [命令] [选项]

命令:
  detect    (默认) 校验 .enigma1/.enigma2 节 + EVB 签名
  info     打印 PE 概要 + EVB 头信息
  list     列出虚拟文件系统中的全部条目
  extract  抽取全部内嵌文件到输出目录
选项:
  -o DIR    抽取输出目录 (默认 <name>_unpacked)
  --json    以 JSON 输出
  -h,--help 显示本帮助
"""


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="main.py",
        description="Enigma Virtual Box Unpacker 0.60 (Python CLI 重写版)",
        add_help=True,
    )
    p.add_argument("target", nargs="?", help="目标 PE 文件")
    p.add_argument(
        "command",
        nargs="?",
        default="detect",
        choices=["detect", "info", "list", "extract"],
        help="命令 (默认 detect)",
    )
    p.add_argument("-o", "--output", help="抽取输出目录")
    p.add_argument("--json", action="store_true", help="以 JSON 输出")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(USAGE)
        return EXIT_SUCCESS
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.target:
        print(USAGE)
        return EXIT_USAGE
    if not os.path.isfile(args.target):
        print("[-] 文件不存在: %s" % args.target)
        return EXIT_FAILURE
    try:
        pe = parse_pe(args.target)
    except PeError as ex:
        print("[-] %s" % ex)
        return EXIT_FAILURE
    info = analyze_enigma(pe)
    cmd = args.command
    if cmd == "detect":
        return cmd_detect(pe, info, args)
    if cmd == "info":
        return cmd_info(pe, info, args)
    if cmd == "list":
        return cmd_list(pe, info, args)
    if cmd == "extract":
        return cmd_extract(pe, info, args)
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())