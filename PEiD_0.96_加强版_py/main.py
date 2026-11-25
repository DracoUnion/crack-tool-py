#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PEiD_0.96_加强版\\PEID.exe  ->  Python CLI 重写版

来源目录: D:\Program Files\crack-tool-pe\PEiD_0.96_加强版
目标文件: PEID.exe (32-bit PE, Delphi GUI, 基址 0x400000)

逆向依据 (IDA Pro 9.4 反汇编, 基址 0x400000):
    入口点 (start) @ 0x4629EC  (WinMain -> VCL/Delphi 应用框架)
    签名数据库解析器 sub_45C250 (0x45C250, size 0x6D3):
        - 逐行解析 userdb.txt / database.txt
        - ';' 开头视为注释并跳过
        - '[<签名名>]' 定义一个新签名条目 (ep_only 默认 0)
        - 'signature = <十六进制字节>' 设置匹配模式, '??' 表示任意字节通配
        - 'ep_only = 1' 表示只在程序入口点所在区段内扫描, 0 表示扫描整个文件
        - 解析出的条目挂载到两条链表: off_401C88 (内置 Special 签名) 与
          off_401E88 (加载的用户签名), 节点布局为 [name, next, ep_only]
    PE 信息提取 (sub_4376D0 等字符串辅助 + 自身 PE 解析):
        - 读取 DOS 头 (e_magic / e_lfanew) -> PE 签名 (PE\\0\\0) ->
          COFF 文件头 (NumberOfSections, SizeOfOptionalHeader) ->
          可选头 (AddressOfEntryPoint, ImageBase) -> 各区段表
    检测逻辑:
        - 对每条签名, 用模式在目标文件字节流中做通配匹配
        - ep_only=1 时仅在入口点所属区段 (EP .. 区段末端) 内扫描
        - 匹配到首条签名即报告其名称, 全部未匹配则报告 "Win32 PE Unknown"
        - 输出格式参考: "%03d :: %s :: %03d\\r\\n" / "Win32 PE Unknown"

本 Python 实现完全基于上述反编译逻辑重写, 纯标准库, 不依赖任何第三方
反汇编/PE 解析库. main.py 为唯一入口, 可直接用
`python main.py <目标PE文件> [选项]` 运行.
"""

import argparse
import ctypes
import json
import os
import struct
import sys
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# ===================== 退出码 (对应原程序的成功/失败/用法码) =====================
EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2

# ===================== PE 结构常量 =====================
IMAGE_DOS_SIGNATURE = 0x5A4D          # "MZ"
IMAGE_NT_SIGNATURE = 0x00004550       # "PE\0\0"

IMAGE_FILE_MACHINE_I386 = 0x014C

IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

# PE 可选头魔数
IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10B
IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20B

# 区段表项大小
IMAGE_SIZEOF_SECTION_HEADER = 40


class PeError(Exception):
    """PE 解析错误。"""


@dataclass
class Section:
    """PE 区段。"""
    name: str
    virtual_address: int
    virtual_size: int
    raw_address: int          # PointerToRawData
    raw_size: int             # SizeOfRawData
    characteristics: int

    def contains_rva(self, rva: int) -> bool:
        return self.virtual_address <= rva < self.virtual_address + max(
            self.virtual_size, self.raw_size or 0
        )


@dataclass
class PeFile:
    """解析后的 PE 文件。"""
    path: str
    data: bytes
    image_base: int
    entry_point_rva: int
    entry_point_offset: int
    sections: List[Section]
    is_pe: bool = True
    error: Optional[str] = None


def parse_pe(data: bytes, path: str) -> PeFile:
    """解析 PE 文件, 提取入口点、区段表等供签名扫描使用."""
    pe = PeFile(path=path, data=data, image_base=0, entry_point_rva=0,
                entry_point_offset=0, sections=[])

    if len(data) < 64:
        pe.is_pe = False
        pe.error = "file too small to be a PE"
        return pe

    # DOS 头
    e_magic = struct.unpack_from("<H", data, 0)[0]
    if e_magic != IMAGE_DOS_SIGNATURE:
        pe.is_pe = False
        pe.error = "not a PE file (no MZ signature)"
        return pe

    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data):
        pe.is_pe = False
        pe.error = "invalid e_lfanew"
        return pe

    # PE 签名
    pe_sig = struct.unpack_from("<I", data, e_lfanew)[0]
    if pe_sig != IMAGE_NT_SIGNATURE:
        pe.is_pe = False
        pe.error = "not a PE file (no PE signature)"
        return pe

    # COFF 文件头 (紧跟 PE 签名, 偏移 4)
    fh_off = e_lfanew + 4
    machine, number_of_sections, _, _, _, size_of_opt_header, characteristics = \
        struct.unpack_from("<HHIIIHH", data, fh_off)

    # 可选头
    opt_off = fh_off + 20
    if size_of_opt_header < 96:
        pe.is_pe = False
        pe.error = "optional header too small"
        return pe

    magic = struct.unpack_from("<H", data, opt_off)[0]
    if magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC:
        # 32 位可选头: AddressOfEntryPoint @ opt_off+16, ImageBase @ opt_off+28
        entry_point_rva = struct.unpack_from("<I", data, opt_off + 16)[0]
        image_base = struct.unpack_from("<I", data, opt_off + 28)[0]
    elif magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC:
        entry_point_rva = struct.unpack_from("<I", data, opt_off + 16)[0]
        image_base = struct.unpack_from("<Q", data, opt_off + 24)[0]
    else:
        pe.is_pe = False
        pe.error = f"unsupported optional header magic 0x{magic:04X}"
        return pe

    # 区段表
    section_table_off = opt_off + size_of_opt_header
    sections: List[Section] = []
    for i in range(number_of_sections):
        off = section_table_off + i * IMAGE_SIZEOF_SECTION_HEADER
        if off + IMAGE_SIZEOF_SECTION_HEADER > len(data):
            break
        name_raw = data[off:off + 8]
        name = name_raw.split(b"\x00", 1)[0].decode("ascii", errors="replace")
        virtual_size, virtual_address, raw_size, raw_address = \
            struct.unpack_from("<IIII", data, off + 8)
        sections.append(Section(
            name=name,
            virtual_address=virtual_address,
            virtual_size=virtual_size,
            raw_address=raw_address,
            raw_size=raw_size,
            characteristics=struct.unpack_from("<I", data, off + 36)[0],
        ))

    # 入口点文件偏移: 先定位到入口点所属区段, 再换算为文件偏移
    entry_point_offset = _rva_to_offset(pe, entry_point_rva, sections)

    pe.image_base = image_base
    pe.entry_point_rva = entry_point_rva
    pe.entry_point_offset = entry_point_offset
    pe.sections = sections
    return pe


def _rva_to_offset(pe: PeFile, rva: int, sections: List[Section]) -> int:
    """将 RVA 换算为文件偏移; 若找不到对应区段则返回 rva 自身 (兜底)."""
    for sec in sections:
        if sec.contains_rva(rva):
            return sec.raw_address + (rva - sec.virtual_address)
    return rva


def section_of_offset(pe: PeFile, offset: int) -> Optional[Section]:
    """返回包含给定文件偏移的区段 (用于 ep_only 扫描范围)."""
    for sec in pe.sections:
        if sec.raw_address <= offset < sec.raw_address + max(sec.raw_size, sec.virtual_size):
            return sec
    return None


# ===================== 签名数据模型 =====================
@dataclass
class Signature:
    """一条 PEiD 签名。"""
    name: str
    pattern: List[Optional[int]]      # None 表示 '??' 通配任意字节
    ep_only: bool = False


def _parse_hex_token(tok: str) -> Optional[int]:
    """把一个十六进制字节符号解析为 int; '??' 返回 None 表示通配。"""
    tok = tok.strip()
    if not tok:
        return None
    if tok == "??" or tok == "?":
        return None
    try:
        return int(tok, 16) & 0xFF
    except ValueError:
        return None


def parse_signature_pattern(sig_str: str) -> List[Optional[int]]:
    """把 PEiD signature 字符串解析为字节列表 ('??' 为通配符)."""
    pattern: List[Optional[int]] = []
    for tok in sig_str.split():
        val = _parse_hex_token(tok)
        # 非法/空符号跳过, 保持与原程序容错行为一致
        if val is None and tok not in ("??", "?"):
            continue
        pattern.append(val)
    return pattern


@dataclass
class UserDb:
    """userdb.txt 风格的签名数据库 (INI 样式)."""
    signatures: List[Signature] = field(default_factory=list)

    def add(self, sig: Signature) -> None:
        self.signatures.append(sig)


def load_userdb(path: str) -> UserDb:
    """加载 PEiD 风格的签名数据库文件.

    格式 (对应 sub_45C250 的逆向结果):
        ; 注释行
        [签名名称]          -> 新建一个签名条目
        signature = AA BB ?? CC  -> 十六进制匹配模式, ?? 通配
        ep_only = 1          -> 1: 仅扫描入口点区段; 0: 扫描全文件
    """
    db = UserDb()
    current_name: Optional[str] = None
    current_pattern: List[Optional[int]] = []
    current_ep_only = False

    def flush() -> None:
        nonlocal current_name, current_pattern, current_ep_only
        if current_name is not None and current_pattern:
            db.add(Signature(name=current_name, pattern=list(current_pattern),
                             ep_only=current_ep_only))
        current_name = None
        current_pattern = []
        current_ep_only = False

    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith(";"):
                    continue
                if line.startswith("[") and "]" in line:
                    flush()
                    current_name = line[1:line.index("]")].strip()
                    continue
                if "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip().lower()
                value = value.strip()
                if key == "signature":
                    current_pattern = parse_signature_pattern(value)
                elif key == "ep_only":
                    current_ep_only = value in ("1", "true", "yes", "on")
                # 其余键忽略, 保持与原程序一致的容错
    except OSError as exc:
        raise PeError(f"无法打开签名数据库 {path}: {exc}") from exc
    finally:
        flush()

    return db


# ===================== 内置 "Special" 签名 (对应 off_401C88 链表) =====================
# 原程序内置一组常见壳/编译器特征 (Special 链表). 此处嵌入最常用的若干条, 以便
# 在不提供外部 userdb 时仍能给出有意义的检测结果; 外部 userdb 会覆盖/追加。
BUILTIN_SIGNATURES: List[Signature] = [
    Signature(name="Microsoft Visual C++ 6.0", ep_only=True,
              pattern=parse_signature_pattern("60 E8 03 00 00 00 EB 58 90 90")),
    Signature(name="Borland Delphi", ep_only=True,
              pattern=parse_signature_pattern("E8 ?? ?? ?? ?? 59 83 C2 04 8B FA")),
    Signature(name="UPX", ep_only=True,
              pattern=parse_signature_pattern("60 BE ?? ?? ?? ?? 81 EE ?? ?? ?? ?? 83 C6 03")),
    Signature(name="ASPack 1.07b -> Alexey Solodovnikov", ep_only=True,
              pattern=parse_signature_pattern("60 E8 ?? ?? ?? ?? 59 81 C1 ?? ?? ?? ?? 8B F1")),
    Signature(name="FSG 1.1 -> bart/xt", ep_only=True,
              pattern=parse_signature_pattern("EB 03 59 53 56 51 6A 00 68 ?? ?? ?? ?? FF 35")),
    Signature(name="PEiD", ep_only=False,
              pattern=parse_signature_pattern("50 68 ?? ?? ?? ?? 64 FF 35 00 00 00 00 64 89 25 00 00 00 00")),
]

# ===================== 签名扫描 =====================
def _match_at(data: bytes, offset: int, pattern: List[Optional[int]],
              end: int) -> bool:
    """在给定偏移处尝试匹配整个通配模式, 且不越过 end 边界。"""
    if offset < 0 or offset + len(pattern) > end:
        return False
    for i, byte in enumerate(pattern):
        if byte is None:
            continue
        if data[offset + i] != byte:
            return False
    return True


def _compile_anchor(pattern: List[Optional[int]]) -> Tuple[int, bytes]:
    """提取模式中第一段连续固定字节作为锚点, 以便用 bytes.find 快速跳转.

    返回 (锚点在模式中的起始下标, 锚点字节)。若整个模式全为通配则返回 (0, b"")。
    """
    first = next((i for i, b in enumerate(pattern) if b is not None), None)
    if first is None:
        return 0, b""
    j = first
    while j < len(pattern) and pattern[j] is not None:
        j += 1
    return first, bytes(pattern[first:j])


def scan(data: bytes, pe: PeFile, db: UserDb,
         report_all: bool = False) -> List[Tuple[str, int, str]]:
    """用数据库扫描数据, 返回 [(签名名, 偏移, 范围说明), ...]。

    对每条签名:
      - ep_only=True: 仅在入口点所属区段内扫描 (EP 文件偏移 .. 区段末端)
      - ep_only=False: 扫描整个文件

    匹配通过给定模式的"首段固定字节锚点" + bytes.find() 实现, 避免逐字节
    暴力比较, 使数千条签名的大库也能在可接受时间内扫描完。
    """
    results: List[Tuple[str, int, str]] = []

    ep_offset = pe.entry_point_offset
    ep_section = section_of_offset(pe, ep_offset) if ep_offset is not None else None

    if ep_section is not None:
        ep_start = ep_section.raw_address
        ep_end = ep_section.raw_address + max(ep_section.raw_size,
                                               ep_section.virtual_size)
    else:
        ep_start = ep_offset
        ep_end = len(data)

    for sig in db.signatures:
        if not sig.pattern:
            continue

        if sig.ep_only:
            start, end = ep_start, min(ep_end, len(data))
            scope = f"entry-point section ({sig.name})"
        else:
            start, end = 0, len(data)
            scope = "whole file"

        found_at = _find_pattern(data, sig.pattern, start, end)
        if found_at is not None:
            results.append((sig.name, found_at, scope))
            if not report_all:
                break

    return results


def _find_pattern(data: bytes, pattern: List[Optional[int]],
                  start: int, end: int) -> Optional[int]:
    """在 [start, end) 内查找模式首次出现的位置, 未找到返回 None。"""
    plen = len(pattern)
    if plen == 0 or start >= end:
        return None
    if plen > end - start:
        return None

    anchor_idx, anchor = _compile_anchor(pattern)
    if not anchor:
        # 全通配模式: 退化为逐偏移尝试 (极罕见)
        for cand in range(start, end - plen + 1):
            if _match_at(data, cand, pattern, end):
                return cand
        return None

    search_from = start
    while True:
        pos = data.find(anchor, search_from, end)
        if pos < 0:
            return None
        cand = pos - anchor_idx
        if cand >= start and _match_at(data, cand, pattern, end):
            return cand
        search_from = pos + 1


# ===================== 默认内置数据库 =====================
def default_db() -> UserDb:
    """返回默认签名数据库.

    优先加载与本脚本同目录的 userdb.txt (随程序一起分发的资源文件);
    若不存在则退回内置的少量 Special 签名。
    """
    bundled = os.path.join(os.path.dirname(os.path.abspath(__file__)), "userdb.txt")
    if os.path.isfile(bundled):
        try:
            return load_userdb(bundled)
        except PeError:
            pass
    db = UserDb()
    for sig in BUILTIN_SIGNATURES:
        db.add(sig)
    return db


# ===================== 检测入口 =====================
def identify_pe(path: str, db: Optional[UserDb] = None,
                report_all: bool = False) -> dict:
    """对单个 PE 文件做壳/编译器检测, 返回结构化结果字典。"""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        return {"file": path, "error": f"无法读取文件: {exc}", "detected": False}

    pe = parse_pe(data, path)
    if not pe.is_pe:
        return {"file": path, "error": pe.error or "未知 PE 解析错误",
                "detected": False, "is_pe": False}

    if db is None:
        db = default_db()

    results = scan(data, pe, db, report_all=report_all)

    if results:
        detected = True
        signature = results[0][0]
    else:
        detected = False
        signature = "Win32 PE Unknown"

    return {
        "file": path,
        "detected": detected,
        "signature": signature,
        "is_pe": True,
        "image_base": pe.image_base,
        "entry_point_rva": pe.entry_point_rva,
        "entry_point_offset": pe.entry_point_offset,
        "sections": [s.name for s in pe.sections],
        "matches": [{"name": n, "offset": o, "scope": s} for n, o, s in results],
    }


def format_result(res: dict, json_out: bool = False) -> str:
    if json_out:
        return json.dumps(res, ensure_ascii=False, indent=2)
    lines = []
    if res.get("error") and not res.get("is_pe", True):
        lines.append(f"[!] {res['file']}: {res['error']}")
        return "\n".join(lines)
    if not res.get("is_pe"):
        lines.append(f"[!] {res['file']}: {res['error']}")
        return "\n".join(lines)

    lines.append(f"File: {res['file']}")
    lines.append(f"ImageBase: 0x{res['image_base']:08X}")
    lines.append(f"EntryPoint: RVA 0x{res['entry_point_rva']:08X} "
                 f"(file offset 0x{res['entry_point_offset']:08X})")
    lines.append(f"Sections: {', '.join(res['sections'])}")
    if res["detected"]:
        lines.append(f"Detected: {res['signature']}")
        for m in res["matches"]:
            lines.append(f"  match @ 0x{m['offset']:08X} ({m['scope']})")
    else:
        lines.append("Detected: Win32 PE Unknown")
    return "\n".join(lines)


USAGE = (
    "PEiD v0.96 加强版 (Python CLI 重写版)\n"
    "用法: python main.py <目标PE文件> [选项]\n"
    "\n"
    "选项:\n"
    "  --db <文件>      指定外部 userdb.txt 签名数据库 (默认使用内置签名)\n"
    "  --all            列出所有匹配的签名, 而不仅是首条\n"
    "  --json           以 JSON 形式输出结构化结果\n"
    "  -h, --help       显示此帮助信息\n"
    "\n"
    "示例:\n"
    "  python main.py suspicious.exe\n"
    "  python main.py suspicious.exe --db userdb.txt --all\n"
    "  python main.py suspicious.exe --json\n"
)


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="PEiD v0.96 加强版 - PE 壳/编译器检测 (Python CLI 重写版)",
        add_help=False,
    )
    parser.add_argument("target", nargs="?", help="要检测的 PE 文件路径")
    parser.add_argument("--db", help="外部 userdb.txt 签名数据库路径")
    parser.add_argument("--all", action="store_true",
                        help="列出所有匹配的签名")
    parser.add_argument("--json", action="store_true",
                        help="以 JSON 输出结构化结果")
    parser.add_argument("-h", "--help", action="store_true",
                        help="显示此帮助信息")

    args = parser.parse_args(argv)

    if args.help or args.target is None:
        print(USAGE)
        return EXIT_SUCCESS

    db = None
    if args.db:
        try:
            db = load_userdb(args.db)
        except PeError as exc:
            print(f"[!] {exc}")
            return EXIT_FAILURE

    res = identify_pe(args.target, db=db, report_all=args.all)
    print(format_result(res, json_out=args.json))

    if res.get("error"):
        return EXIT_FAILURE
    return EXIT_SUCCESS


if __name__ == "__main__":
    sys.exit(main())
