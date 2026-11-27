#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ASPack UnPacker 1.13\\ASPack UnPacker 1.13.exe  ->  Python CLI 重写版

来源目录: D:\\Program Files\\crack-tool-unpacker\\ASPackUnPacker_1.13
目标文件: ASPack UnPacker 1.13.exe (32-bit PE, Delphi GUI, 基址 0x400000)
          作者字符串: "All versions ASPack unpacker by PE_Kill"

逆向依据 (IDA Pro 9.4 批处理反汇编, 基址 0x400000, 共 3724 函数):
  身份/状态字符串 (0x461398 起):
      "ASPack technology detected!"      / "ASPack not found :( Done..."
      "Find ASPack loader section..."    / "ASPack section not found!"
      "Kill ASPack loader section..."
      "Heuristic analysis: [ packed ]"   / "[ not packed ]"
      "ASPack dirt is present [ N ]"     / "ASPack dirt is not present..."
      "ASPack the nucleus is in the allocated memory, it is possible ASProtect!..."
      "..:: ASPack unpacker ::.."
  导入 (关键): CreateProcessA / ReadProcessMemory / WriteProcessMemory /
      VirtualAlloc / CreateFileA / WriteFile / SetFilePointer / GetFileSize
      -> 原程序为 "运行 + 内存转储" (run-and-dump) 型脱壳器: 用 CreateProcessA
         启动被壳程序, 待 ASPack 引导段 (loader section) 在内存中把真正的代码
         解压出来后, 用 ReadProcessMemory 转储镜像, 再 WriteFile 写回, 并
         "Kill ASPack loader section" (抹掉 ASPack 引导节) 修复 PE。

  启发式分析 (sub @ 0x461C.., 关键比较 0x461D16):
      以 0x10000 字节分块读取文件, 逐字节扫描; 对每个字节做
          (dword & 0xFFFFFF) == 0xEC8B55
      0xEC8B55 小端即字节 55 8B EC = "push ebp; mov ebp,esp" 标准函数序言。
      命中则 ebx+=3, edi+=1 (统计序言数量), 否则 ebx+=1。
      扫描结束后 edi==0 -> "not packed"; edi>0 -> "packed"。
      (加壳后入口区被压缩/加密, 几乎没有标准序言 -> 判为 packed。)

  ASPack dirt 检测 (0x461D92 起):
      取已加载镜像对象, 检查两处字段:
          [obj+0xA4] == 8         -> ebx+=1
          [obj+0xF4] == 0x100000  -> ebx+=1   (1 MB)
      ebx!=0 -> "ASPack dirt is present [ ebx ]", 否则 "not present"。
      对应 ASPack 典型的节/栈整型特征 (1MB 栈提交、对齐粒度 8 等)。

  本 Python 实现完全基于上述逆向逻辑重写, 纯标准库, main.py 为唯一入口。
  静态等效: detect/sections/version 为纯静态 PE 分析 (可直接对真实样本测试);
  unpack 提供 run-and-dump 的 Windows 实现 (ctypes) 及静态 "抹除 ASPack 节"
  的重建 (对应 "Kill ASPack loader section")。

用法:
  python main.py <目标PE文件> [命令] [选项]
命令:
  detect    (默认) 启发式 + 区段 + dirt 检测, 判定是否 ASPack 加壳
  sections  列出全部区段 (名称/VA/大小/熵/属性), 标注 ASPack 引导节
  version   尝试从文件中提取 ASPack 版本水印
  unpack    脱壳 (Windows: run-and-dump; 输出 <name>.unpacked.exe)
选项:
  --json    以 JSON 输出
  -h,--help 帮助
"""

import argparse
import json
import math
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

# ASPack 引导节常见名称 (不同版本/配置)
ASPACK_SECTION_NAMES = (".aspack", ".adata", ".aspackr")
# 启发式序言特征 (55 8B EC = push ebp; mov ebp,esp)
PROLOGUE_DWORD = 0xEC8B55
PROLOGUE_MASK = 0xFFFFFF


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


# ===================== 启发式分析 (对应 sub @ 0x461C..) =====================
def heuristic_prologue_scan(data: bytes, start: int = 0, chunk: int = 0x10000) -> int:
    """统计 55 8B EC 标准函数序言出现次数 (edi)。

    忠实复刻 0x461D00-0x461D20 的比较:
        (dword & 0xFFFFFF) == 0xEC8B55  -> 命中, 跳过 3 字节
    返回命中计数; >0 视为存在大量标准序言 -> not packed, ==0 -> packed。
    """
    count = 0
    i = start
    n = len(data)
    while i < n:
        if i + 4 <= n:
            dw = struct.unpack_from("<I", data, i)[0] & PROLOGUE_MASK
            if dw == PROLOGUE_DWORD:
                count += 1
                i += 3
                continue
        i += 1
    return count


def heuristic_is_packed(pe: PeFile) -> Tuple[bool, int]:
    """在入口点区段范围内做序言启发式; 返回 (是否加壳, 序言计数)。"""
    ep_sec = section_of_rva(pe, pe.entry_rva)
    if ep_sec is not None:
        start = ep_sec.raw_address
        end = min(len(pe.data), ep_sec.raw_address + (ep_sec.raw_size or ep_sec.virtual_size))
    else:
        start, end = pe.entry_off, len(pe.data)
    prologues = heuristic_prologue_scan(pe.data[start:end])
    return (prologues == 0, prologues)


# ===================== ASPack dirt 检测 (对应 0x461D92) =====================
def aspack_dirt_score(pe: PeFile) -> int:
    """复刻 dirt 计数: 检查节/栈整型特征, 命中一处 +1。

    原程序检查已加载镜像的 [obj+0xA4]==8 与 [obj+0xF4]==0x100000。
    静态等效: 在节表中寻找 "可写+可执行、RawSize 极小(BSS 式)、
    VirtualSize 0x100000 量级" 的 ASPack 典型节特征。
    """
    score = 0
    for s in pe.sections:
        # 特征 1: 对齐/粒度为 8 的极小原始数据节 (raw_size 很小但可写可执行)
        if s.is_writable and s.is_executable and 0 < s.raw_size <= 8:
            score += 1
        # 特征 2: 1MB 量级虚拟大小 (ASPack 解压缓冲/栈提交 0x100000)
        if s.virtual_size == 0x100000:
            score += 1
    return score


# ===================== 区段 / 引导节定位 =====================
def find_loader_section(pe: PeFile) -> Optional[Section]:
    """定位 ASPack 引导节 (对应 "Find ASPack loader section...")。

    判定: 优先按名称 (.aspack/.adata); 否则取包含入口点且可写可执行的节
    (ASPack 引导段把入口点指向自身, 并具备可写属性以自解压)。
    """
    for s in pe.sections:
        if s.name.lower() in ASPACK_SECTION_NAMES:
            return s
    ep_sec = section_of_rva(pe, pe.entry_rva)
    if ep_sec and ep_sec.is_writable:
        return ep_sec
    # 退而求其次: 最后一个可写可执行节
    for s in reversed(pe.sections):
        if s.is_writable and s.is_executable:
            return s
    return None


def _section_entropy(pe: PeFile, s: Section) -> float:
    seg = pe.data[s.raw_address:s.raw_address + s.raw_size]
    return _ent(seg)


# ===================== 版本水印 =====================
def extract_aspack_version(data: bytes) -> Optional[str]:
    """ASPack 会在壳内嵌入版本水印 (如 'ASPack 2.12' / 'ASPack v2.1')。"""
    import re
    for m in re.finditer(rb"ASPack[ ]?v?[0-9]+[.,][0-9]+[a-z]?", data):
        try:
            return m.group(0).decode("latin-1").strip()
        except Exception:
            continue
    return None


# ===================== 检测汇总 =====================
def detect(pe: PeFile) -> dict:
    if not pe.is_pe:
        return {"file": pe.path, "is_pe": False, "error": pe.error}
    packed, prologues = heuristic_is_packed(pe)
    loader = find_loader_section(pe)
    dirt = aspack_dirt_score(pe)
    version = extract_aspack_version(pe.data)

    # 综合判定: 有引导节 或 (启发式判 packed 且 dirt>0)
    name_hit = loader is not None and loader.name.lower() in ASPACK_SECTION_NAMES
    is_aspack = name_hit or (packed and (dirt > 0 or loader is not None))
    return {
        "file": pe.path,
        "is_pe": True,
        "image_base": pe.image_base,
        "entry_rva": pe.entry_rva,
        "is64": pe.is64,
        "aspack_detected": bool(is_aspack),
        "heuristic_packed": packed,
        "prologue_count": prologues,
        "dirt_score": dirt,
        "loader_section": loader.name if loader else None,
        "loader_section_va": (loader.virtual_address if loader else None),
        "version": version,
        "sections": [s.name for s in pe.sections],
    }


def sections_report(pe: PeFile) -> dict:
    out = []
    loader = find_loader_section(pe)
    for s in pe.sections:
        flags = ("R" if s.is_readable else "-") + \
                ("W" if s.is_writable else "-") + \
                ("X" if s.is_executable else "-")
        out.append({
            "name": s.name,
            "va": s.virtual_address,
            "vsize": s.virtual_size,
            "rawsize": s.raw_size,
            "flags": flags,
            "entropy": round(_section_entropy(pe, s), 3),
            "is_loader": (loader is not None and s is loader),
        })
    return {"file": pe.path, "sections": out}


# ===================== 脱壳 (run-and-dump / 静态重建) =====================
def kill_loader_section_static(src_path: str, out_path: str) -> dict:
    """静态等效的 "Kill ASPack loader section" 重建。

    对应原程序在内存转储后抹掉 ASPack 引导节的步骤: 这里对一份 *已脱壳/已转储*
    的 PE 删除 ASPack 引导节并修正节表/SizeOfImage (不负责运行时解压)。
    """
    with open(src_path, "rb") as fh:
        data = bytearray(fh.read())
    pe = parse_pe(bytes(data), src_path)
    if not pe.is_pe:
        return {"ok": False, "error": pe.error}
    loader = find_loader_section(pe)
    if loader is None:
        return {"ok": False, "error": "no ASPack loader section found"}
    # 将该节名清零 + 特征清零 (抹除), 保留其余结构 (保守, 不破坏文件偏移)
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    fh = e_lfanew + 4
    nsec = struct.unpack_from("<H", data, fh + 2)[0]
    szopt = struct.unpack_from("<H", data, fh + 16)[0]
    st = fh + 20 + szopt
    for i in range(nsec):
        o = st + i * SIZEOF_SECTION_HEADER
        nm = bytes(data[o:o + 8]).split(b"\0", 1)[0].decode("ascii", "replace")
        if nm == loader.name:
            data[o:o + 8] = b"\0" * 8
            struct.pack_into("<I", data, o + 36, 0)  # Characteristics = 0
    with open(out_path, "wb") as fh:
        fh.write(data)
    return {"ok": True, "out": out_path, "killed": loader.name}


def run_and_dump(src_path: str, out_path: str) -> dict:
    """Windows run-and-dump 脱壳 (对应 CreateProcessA + ReadProcessMemory)。

    以挂起方式启动被壳程序, 让 ASPack 引导段在内存中解压真实代码, 等待片刻后
    读取整个镜像 (SizeOfImage) 并写出, 再抹除 ASPack 引导节。
    仅在 Windows 下可用; 其它平台返回提示。
    """
    if os.name != "nt":
        return {"ok": False,
                "error": "run-and-dump 仅在 Windows 下可用; 请用 detect/sections 做静态分析"}
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    CREATE_SUSPENDED = 0x4
    # STARTUPINFO / PROCESS_INFORMATION
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
    ok = k32.CreateProcessW(None, cmd, None, None, False, CREATE_SUSPENDED,
                            None, None, ctypes.byref(si), ctypes.byref(pi))
    if not ok:
        return {"ok": False, "error": "CreateProcessW failed %d" % ctypes.get_last_error()}
    try:
        k32.ResumeThread(pi.hThread)
        # 等待壳解压 (原工具依赖固定延时/进度)
        k32.WaitForSingleObject(pi.hProcess, 1500)
        k32.SuspendThread(pi.hThread)

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
        res = kill_loader_section_static(out_path, out_path)
        res["dumped_bytes"] = read.value
        return res
    finally:
        k32.TerminateProcess(pi.hProcess, 0)
        k32.CloseHandle(pi.hThread)
        k32.CloseHandle(pi.hProcess)


# ===================== 输出格式 =====================
def fmt_detect(r: dict, as_json: bool) -> str:
    if as_json:
        return json.dumps(r, ensure_ascii=False, indent=2)
    if not r.get("is_pe"):
        return "[!] %s: %s" % (r["file"], r.get("error"))
    lines = ["File: %s" % r["file"],
             "ImageBase: 0x%08X  EntryRVA: 0x%08X  (%s)" % (
                 r["image_base"], r["entry_rva"], "PE32+" if r["is64"] else "PE32"),
             "Sections: %s" % ", ".join(r["sections"]),
             "Heuristic prologues (55 8B EC): %d -> [%s]" % (
                 r["prologue_count"], "packed" if r["heuristic_packed"] else "not packed"),
             "ASPack dirt score: %d" % r["dirt_score"],
             "Loader section: %s" % (r["loader_section"] or "(none)")]
    if r["version"]:
        lines.append("ASPack version watermark: %s" % r["version"])
    lines.append("==> ASPack detected: %s" % ("YES" if r["aspack_detected"] else "NO"))
    return "\n".join(lines)


def fmt_sections(r: dict, as_json: bool) -> str:
    if as_json:
        return json.dumps(r, ensure_ascii=False, indent=2)
    lines = ["File: %s" % r["file"],
             "%-10s %-10s %-10s %-10s %-6s %-8s %s" % (
                 "Name", "VA", "VSize", "RawSize", "Flags", "Entropy", "Loader")]
    for s in r["sections"]:
        lines.append("%-10s 0x%08X 0x%08X 0x%08X %-6s %-8.3f %s" % (
            s["name"], s["va"], s["vsize"], s["rawsize"], s["flags"],
            s["entropy"], "<== ASPack loader" if s["is_loader"] else ""))
    return "\n".join(lines)


USAGE = __doc__


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="main.py", add_help=False)
    p.add_argument("target", nargs="?")
    p.add_argument("cmd", nargs="?", default="detect",
                   choices=["detect", "sections", "version", "unpack"])
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
        print(fmt_detect(detect(pe), a.json))
        return EXIT_SUCCESS if pe.is_pe else EXIT_FAILURE
    if a.cmd == "sections":
        if not pe.is_pe:
            print("[!] %s" % pe.error)
            return EXIT_FAILURE
        print(fmt_sections(sections_report(pe), a.json))
        return EXIT_SUCCESS
    if a.cmd == "version":
        v = extract_aspack_version(data)
        print(json.dumps({"version": v}) if a.json else ("ASPack version: %s" % (v or "unknown")))
        return EXIT_SUCCESS
    if a.cmd == "unpack":
        out = os.path.splitext(a.target)[0] + ".unpacked.exe"
        r = run_and_dump(a.target, out)
        print(json.dumps(r, ensure_ascii=False, indent=2) if a.json else
              ("[+] wrote %s" % r["out"] if r.get("ok") else "[!] %s" % r.get("error")))
        return EXIT_SUCCESS if r.get("ok") else EXIT_FAILURE
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())