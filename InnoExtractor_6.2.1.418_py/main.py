#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
InnoExtractor 6.2.1.418\\InnoExtractor.exe  ->  Python CLI 重写版 (静态检测/信息/列表)

来源目录: D:\\Program Files\\crack-tool-unpacker\\InnoExtractor_6.2.1.418
目标文件: InnoExtractor.exe (32-bit 原生 Delphi PE, 基址 0x400000,
          区段 .text/.itext/.data/.bss/.idata/.didata/.tls/.rdata/.reloc/.rsrc, 未加壳)
          同目录引擎: Innounp.e32 (Inno Setup 解析核心, Delphi 编译的 PE32 控制台模块)
                      7z.dll / 7z.e32 / 7zSD.e32 (解压后端), Languages\\

逆向依据 (IDA Pro 9.4 批处理反汇编, 基址 0x400000):
  InnoExtractor.exe 本体是 GUI 前端 (菜单/语言资源), 真正的 Inno Setup 识别与解析
  由同目录的 Innounp.e32 引擎完成 (界面通过 "Innounp" / LoadLibrary 加载, 见
  .rdata 字符串 @0x5F11E4 "VersionInnounpClick"、@0x579D86 "FrmInnoExtractor_MnuArchivo")。
  因此检测算法地址取自 Innounp.e32:

  [检测主函数] sub_5738D0 @ 0x5738D0  —— "是否为 Inno Setup 安装程序"
      1) sub_55CDE8 取文件大小 esi;
      2) sub_55CF04(file, 0x30) 定位到偏移 0x30, sub_55CEDC 读 12 字节:
           cmp dword [buf+0], 6F6E6E49h   ; 即字节 "Inno" (49 6E 6E 6F)
           mov eax,[buf+8]; not eax; cmp eax,[buf+4] ; [buf+8] == ~([buf+4]) 校验
         -> 偏移 0x30 处为 "Inno" + 指针 T + (~T) 的完整性校验 (旧版 Inno 标识)。
      3) edx = T + 0x2C; sub edx, filesize; cmp edx,4; jg fail
         -> 要求 T 指向文件尾附近的 "引导偏移表" (|filesize-(T+0x2C)| <= 4)。
      4) 定位到 T 读 0x18(24) 字节, sub_4D5D68 在内部签名表(dword_5994A0)中匹配
         12 字节签名 (记录 +0x0A 处), 命中即确认。
      [现代 Inno 6.x 不再用 0x30 的 "Inno" 标识, 改用 6 字节签名 "rDlPtS"
       (72 44 6C 50 74 53) 标记引导偏移表, 见引擎内 93 处签名记录。]

  [版本解析] sub_575A4C @ 0x575A4C  —— 从数据头解析版本号
      读取 0x40 字节头, 比较:
          0x575A8B  "Inno Setup Setup Data ("        (var_10 = 0x18)
          0x575AA9  "My Inno Setup Extensions Setup Data (" (var_10 = 0x26)
      命中后跳过 '(' 到 ')' 取出 "x.x.x.x" 版本串 (0x575AC7-0x575B18),
      解析主/次/修订/构建 (0x575C2D: major*1000 + minor*100 + build),
      并在 0x575C43/0x575C5D 检测 " (u)" -> Unicode, " (Custom)" -> 自定义。

  [检测+版本报告] sub_575E8C @ 0x575E8C
      打开文件 -> 读 0x40 头 -> sub_575A4C 解析 -> 打印
      "=> Signature detected: " / "=> Version detected: " / " (Unicode)" / " (Custom)"。

  [引导偏移表结构] TMySetupLdrOffsetTable (packed record, 位于 "rDlPtS" 处):
      +0x00  ID[6]            = "rDlPtS"
      +0x06  Version: Byte    = 引导器版本
      +0x07  TotalSize: Int32 = 安装数据总大小
      +0x0B  OffsetSetupHeader: Int32 = setup 头 (数据头) 偏移
      +0x0F  CRCSetupHeader: Int32  = setup 头 CRC32
      (Inno 5.1.5+ 起该表被编码/混淆, 字段不再明文; 本工具做明文校验, 失败则标注。)

  本 Python 实现完全基于上述逆向逻辑重写, 纯标准库, main.py 为唯一入口。
  静态等效: detect/info/list 为纯静态 PE + Inno 标记分析 (可直接对真实样本测试);
  不做运行时解压 (InnoExtractor 本体也依赖 Innounp.e32/7z 后端解压, 超出静态范围)。

用法:
  python main.py <安装程序.exe> [命令]
命令:
  detect   (默认) PE 解析 + Inno 标记检测 + 版本, 判定是否 Inno Setup 安装程序
  info     完整信息: PE 区段 / 数据头偏移 / 版本 / Unicode / 引导偏移表
  list     列出内嵌 Inno 结构偏移 (数据头 / rDlPtS 引导表 / setup 头候选)
选项:
  --json   以 JSON 输出
  -h,--help 帮助
"""

import argparse
import json
import os
import re
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

# Inno Setup 引导偏移表签名 (引擎内 93 处签名记录, 见 sub_4D5D68 @ 0x4D5D68)
INNO_LDR_SIGNATURE = b"rDlPtS"                       # 72 44 6C 50 74 53
# 数据头标识 (sub_575A4C @ 0x575A8B / 0x575AA9)
INNO_DATA_MARKER = b"Inno Setup Setup Data ("
INNO_DATA_MARKER_EXT = b"My Inno Setup Extensions Setup Data ("
# 旧版标识: 偏移 0x30 处 "Inno" + 指针 + (~指针) (sub_5738D0 @ 0x573904)
INNO_LEGACY_MAGIC = b"Inno"
INNO_LEGACY_OFF = 0x30


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
    sections: List[Section] = field(default_factory=list)
    is_pe: bool = True
    error: Optional[str] = None
    is64: bool = False


@dataclass
class OffsetTable:
    """TMySetupLdrOffsetTable (位于 rDlPtS 处, packed)。"""
    off: int
    version: int
    total_size: int
    offset_setup_header: int
    crc_setup_header: int
    valid: bool
    note: str = ""


@dataclass
class InnoInfo:
    is_inno: bool = False
    method: str = ""                 # 命中的检测方式
    data_header_off: Optional[int] = None      # "Inno Setup Setup Data (" 偏移
    version: Optional[str] = None
    unicode: bool = False
    custom: bool = False
    ldr_off: Optional[int] = None    # rDlPtS 偏移
    offset_table: Optional[OffsetTable] = None
    legacy_ptr: Optional[int] = None  # 旧版 0x30 处指针 T
    all_data_headers: List[int] = field(default_factory=list)


# ===================== PE 解析 =====================
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
    if opt + 2 > len(data):
        pe.is_pe = False
        pe.error = "truncated optional header"
        return pe
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


def section_of_off(pe: PeFile, off: int) -> Optional[Section]:
    for s in pe.sections:
        if s.raw_address <= off < s.raw_address + max(s.raw_size, 1):
            return s
    return None


# ===================== Inno 检测 (对应 sub_5738D0 / sub_575A4C) =====================
def _find_all(data: bytes, needle: bytes) -> List[int]:
    out, i = [], data.find(needle)
    while i != -1:
        out.append(i)
        i = data.find(needle, i + 1)
    return out


def parse_offset_table(data: bytes, off: int) -> Optional[OffsetTable]:
    """解析 rDlPtS 处的 TMySetupLdrOffsetTable (packed)。

    结构: ID[6] + Version(1) + TotalSize(4) + OffsetSetupHeader(4) + CRCSetupHeader(4)。
    校验 TotalSize/OffsetSetupHeader 是否落在文件内; Inno 5.1.5+ 该表被编码, 校验失败。
    """
    if off < 0 or off + 6 > len(data) or data[off:off + 6] != INNO_LDR_SIGNATURE:
        return None
    if off + 19 > len(data):
        return None
    version = data[off + 6]
    total_size, off_hdr, crc = struct.unpack_from("<III", data, off + 7)
    size = len(data)
    valid = (0 < total_size <= size + 16) and (0 <= off_hdr < size)
    note = ""
    if not valid:
        note = "字段被编码/混淆 (Inno 5.1.5+), 非明文偏移表"
    return OffsetTable(off, version, total_size, off_hdr, crc, valid, note)


def parse_version(data: bytes, marker_off: int, marker_len: int) -> Tuple[Optional[str], bool, bool]:
    """从数据头 "Inno Setup Setup Data (x.x.x.x) (u/Custom)" 解析版本与标志。

    对应 sub_575A4C @ 0x575A4C: 跳过 '(' 找到 ')' 取版本串, 再检测 " (u)"/" (Custom)"。
    """
    start = marker_off + marker_len
    end = data.find(b")", start)
    if end == -1 or end - start > 40:
        return None, False, False
    ver_bytes = data[start:end].strip()
    version: Optional[str] = None
    m = re.match(rb"(\d+)\.(\d+)(?:\.(\d+))?(?:\.(\d+))?", ver_bytes)
    if m:
        parts = [g for g in m.groups() if g is not None]
        version = ".".join(p.decode("ascii", "replace") for p in parts)
    tail = data[end + 1:end + 24]
    uni = tail.lstrip().startswith(b"(u)") or (b" (u)" in tail)
    cust = b"(Custom)" in tail
    return version, uni, cust


def detect_inno(data: bytes) -> InnoInfo:
    """Inno Setup 安装程序检测 (忠实复刻 sub_5738D0 + sub_575A4C)。"""
    info = InnoInfo()
    size = len(data)

    # 1) 数据头 "Inno Setup Setup Data (" —— 最可靠, 直接给出版本 (sub_575A4C)
    dh = _find_all(data, INNO_DATA_MARKER)
    dh += _find_all(data, INNO_DATA_MARKER_EXT)
    dh.sort()
    info.all_data_headers = dh
    if dh:
        off = dh[0]
        marker_len = (len(INNO_DATA_MARKER_EXT)
                      if data[off:off + len(INNO_DATA_MARKER_EXT)] == INNO_DATA_MARKER_EXT
                      else len(INNO_DATA_MARKER))
        ver, uni, cust = parse_version(data, off, marker_len)
        info.is_inno = True
        info.method = "data-header"
        info.data_header_off = off
        info.version = ver
        info.unicode = uni
        info.custom = cust

    # 2) rDlPtS 引导偏移表签名 (现代 Inno, sub_5738D0 的签名表匹配)
    r = data.find(INNO_LDR_SIGNATURE)
    if r != -1:
        info.ldr_off = r
        info.offset_table = parse_offset_table(data, r)
        if not info.is_inno:
            info.is_inno = True
            info.method = "rDlPtS"

    # 3) 旧版标识: 偏移 0x30 "Inno" + 指针 T + (~T), T 指向尾部偏移表 (sub_5738D0)
    if not info.is_inno and size >= 0x3C:
        if data[INNO_LEGACY_OFF:INNO_LEGACY_OFF + 4] == INNO_LEGACY_MAGIC:
            a, b = struct.unpack_from("<II", data, INNO_LEGACY_OFF + 4)
            if a == ((~b) & 0xFFFFFFFF) and abs(size - (b + 0x2C)) <= 4:
                info.is_inno = True
                info.method = "legacy-inno-0x30"
                info.legacy_ptr = b
                info.offset_table = parse_offset_table(data, b) or \
                    _legacy_table(data, b)

    return info


def _legacy_table(data: bytes, off: int) -> Optional[OffsetTable]:
    """旧版偏移表 (0x30 指针处) 的宽松解析。"""
    if off < 0 or off + 19 > len(data):
        return None
    total_size, off_hdr, crc = struct.unpack_from("<III", data, off + 6)
    valid = 0 < total_size <= len(data) + 16 and 0 <= off_hdr < len(data)
    return OffsetTable(off, 0, total_size, off_hdr, crc, valid,
                       "" if valid else "字段被编码/混淆")


# ===================== 报告 =====================
def detect_report(pe: PeFile, info: InnoInfo) -> dict:
    if not pe.is_pe:
        return {"file": pe.path, "is_pe": False, "error": pe.error}
    r = {
        "file": pe.path,
        "is_pe": True,
        "image_base": pe.image_base,
        "entry_rva": pe.entry_rva,
        "is64": pe.is64,
        "file_size": len(pe.data),
        "inno_detected": info.is_inno,
        "method": info.method,
        "version": info.version,
        "unicode": info.unicode,
        "custom": info.custom,
        "data_header_off": info.data_header_off,
        "ldr_signature_off": info.ldr_off,
        "sections": [s.name for s in pe.sections],
    }
    return r


def info_report(pe: PeFile, info: InnoInfo) -> dict:
    r = detect_report(pe, info)
    r["legacy_ptr"] = info.legacy_ptr
    r["all_data_headers"] = info.all_data_headers
    if info.offset_table:
        t = info.offset_table
        r["offset_table"] = {
            "off": t.off, "version": t.version, "total_size": t.total_size,
            "offset_setup_header": t.offset_setup_header,
            "crc_setup_header": t.crc_setup_header, "valid": t.valid, "note": t.note,
        }
    return r


def list_report(pe: PeFile, info: InnoInfo) -> dict:
    """列出内嵌 Inno 结构偏移 (无法静态解压, 仅列结构位置)。"""
    items = []
    if info.data_header_off is not None:
        items.append({"kind": "data-header", "off": info.data_header_off,
                      "desc": "Inno Setup Setup Data (版本头)"})
    for h in info.all_data_headers:
        if h != info.data_header_off:
            items.append({"kind": "data-header", "off": h, "desc": "附加数据头"})
    if info.ldr_off is not None:
        items.append({"kind": "ldr-offset-table", "off": info.ldr_off,
                      "desc": "rDlPtS 引导偏移表"})
    if info.offset_table:
        t = info.offset_table
        if t.valid:
            items.append({"kind": "setup-header", "off": t.offset_setup_header,
                          "desc": "setup 头 (OffsetSetupHeader)"})
    return {
        "file": pe.path,
        "is_pe": pe.is_pe,
        "inno_detected": info.is_inno,
        "version": info.version,
        "structures": items,
        "sections": [{"name": s.name, "va": s.virtual_address,
                      "raw_off": s.raw_address, "raw_size": s.raw_size}
                     for s in pe.sections],
    }


# ===================== 输出格式 =====================
def fmt_detect(r: dict, as_json: bool) -> str:
    if as_json:
        return json.dumps(r, ensure_ascii=False, indent=2)
    if not r.get("is_pe"):
        return "[!] %s: %s" % (r["file"], r.get("error"))
    lines = ["File: %s" % r["file"],
             "ImageBase: 0x%08X  EntryRVA: 0x%08X  (%s)  size=%d" % (
                 r["image_base"], r["entry_rva"], "PE32+" if r["is64"] else "PE32",
                 r["file_size"]),
             "Sections: %s" % ", ".join(r["sections"]),
             "Inno method: %s" % (r["method"] or "(none)")]
    if r["inno_detected"]:
        if r["version"]:
            lines.append("Inno version: %s%s%s" % (
                r["version"], " (Unicode)" if r["unicode"] else "",
                " (Custom)" if r["custom"] else ""))
        if r["data_header_off"] is not None:
            lines.append("Data header @ 0x%X" % r["data_header_off"])
        if r["ldr_signature_off"] is not None:
            lines.append("rDlPtS @ 0x%X" % r["ldr_signature_off"])
    lines.append("==> Inno Setup detected: %s" % ("YES" if r["inno_detected"] else "NO"))
    return "\n".join(lines)


def fmt_info(r: dict, as_json: bool) -> str:
    if as_json:
        return json.dumps(r, ensure_ascii=False, indent=2)
    if not r.get("is_pe"):
        return "[!] %s: %s" % (r["file"], r.get("error"))
    lines = [fmt_detect(r, False), ""]
    if r.get("offset_table"):
        t = r["offset_table"]
        lines.append("OffsetTable @ 0x%X  ver=%d  valid=%s" % (t["off"], t["version"], t["valid"]))
        lines.append("  TotalSize=0x%X  OffsetSetupHeader=0x%X  CRC=0x%X" % (
            t["total_size"], t["offset_setup_header"], t["crc_setup_header"]))
        if t["note"]:
            lines.append("  note: %s" % t["note"])
    return "\n".join(lines)


def fmt_list(r: dict, as_json: bool) -> str:
    if as_json:
        return json.dumps(r, ensure_ascii=False, indent=2)
    lines = ["File: %s  Inno=%s  version=%s" % (
        r["file"], "YES" if r["inno_detected"] else "NO", r["version"] or "-"),
        "Embedded Inno structures:"]
    if not r["structures"]:
        lines.append("  (none found)")
    for it in r["structures"]:
        lines.append("  0x%08X  %-18s %s" % (it["off"], it["kind"], it["desc"]))
    lines.append("PE sections:")
    for s in r["sections"]:
        lines.append("  %-10s VA=0x%08X raw=0x%08X size=0x%X" % (
            s["name"], s["va"], s["raw_off"], s["raw_size"]))
    return "\n".join(lines)


USAGE = __doc__


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="main.py", add_help=False)
    p.add_argument("target", nargs="?")
    p.add_argument("cmd", nargs="?", default="detect",
                   choices=["detect", "info", "list"])
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
    info = detect_inno(data) if pe.is_pe else InnoInfo()

    if a.cmd == "detect":
        print(fmt_detect(detect_report(pe, info), a.json))
        if not pe.is_pe:
            return EXIT_FAILURE
        return EXIT_SUCCESS if info.is_inno else EXIT_FAILURE
    if a.cmd == "info":
        if not pe.is_pe:
            print("[!] %s" % pe.error)
            return EXIT_FAILURE
        print(fmt_info(info_report(pe, info), a.json))
        return EXIT_SUCCESS
    if a.cmd == "list":
        if not pe.is_pe:
            print("[!] %s" % pe.error)
            return EXIT_FAILURE
        print(fmt_list(list_report(pe, info), a.json))
        return EXIT_SUCCESS
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())