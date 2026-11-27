#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
PECompactUnpacker\\Unpacker_PECompact.exe  ->  Python CLI 重写版

来源目录: D:\\Program Files\\crack-tool-unpacker\\PECompactUnpacker
目标文件: Unpacker_PECompact.exe (原始为 PECompact 加壳的 32-bit Delphi 7 程序,
          真实 ImageBase 0x400000, 入口 start @ 0x401000; 作者自述
          "Coded in Delphi 7 Enterprise - January 4th, 2014")。

逆向依据:
  原文件被 PECompact 加壳 (仅 2 节: CODE + .rsrc, CODE 高熵 8.0)。按 AGENTS.md
  流程用 run-and-dump (CreateProcess + ReadProcessMemory) 在内存释放真实代码后转储,
  再用 IDA Pro 9.4 反汇编 (脱壳镜像 0x400000, 35 函数)。关键字符串:
    "-c <PathPECompact> <PathDumped>"        (命令行: 输入被壳文件, 输出转储文件)
    "Rebuild sections (If compiler is found" (重建节, 若能识别编译器)
    "resources must be always uncompressed to get them complete. A relocations section"
    "G'sloader.exe"                          (辅助加载器, 用于运行+转储)
    "Error while reading the PE header of the target."
    "Error while trying to detect the EP section."
  脱壳流水线: 读 PE 头 -> 检测 EP 所在节 -> 用 G'sloader 运行并转储 -> 重建节
              (资源保持解压、处理重定位节) -> 写回。

  本 Python 实现为静态等效重写 (纯标准库): PECompact 检测 (CODE 节/高熵/EP 节)、
  节区与重定位/资源分析、待重建节定位, 并提供 run-and-dump (Windows, ctypes)。
  main.py 为唯一入口。

用法:
  python main.py <目标PE文件> [detect|info|sections|unpack] [--json]
"""

import argparse
import json
import math
import os
import struct
import sys
from dataclasses import dataclass, field
from typing import List, Optional

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2
SIZEOF_SECTION_HEADER = 40

# PECompact 常见节名
PEC_SECTION_NAMES = ("CODE", ".pec", ".pec1", "PEC2", ".text")
PEC_WATERMARKS = (b"PECompact", b"PECompact2", b"PE Compact")


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
    size_of_code: int = 0
    is64: bool = False
    sections: List[Section] = field(default_factory=list)
    is_pe: bool = True
    error: Optional[str] = None


def _ent(b: bytes) -> float:
    if not b: return 0.0
    from collections import Counter
    c = Counter(b); n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


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
    opt = fh + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x10B:
        pe.entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        pe.size_of_code = struct.unpack_from("<I", data, opt + 4)[0]
        pe.image_base = struct.unpack_from("<I", data, opt + 28)[0]
        pe.size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
    elif magic == 0x20B:
        pe.is64 = True
        pe.entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        pe.size_of_code = struct.unpack_from("<I", data, opt + 4)[0]
        pe.image_base = struct.unpack_from("<Q", data, opt + 24)[0]
        pe.size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
    else:
        pe.is_pe = False; pe.error = "bad opt magic"; return pe
    st = opt + szopt
    for i in range(nsec):
        o = st + i * SIZEOF_SECTION_HEADER
        if o + SIZEOF_SECTION_HEADER > len(data): break
        nm = data[o:o + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        vs, va, rs, ra = struct.unpack_from("<IIII", data, o + 8)
        ch = struct.unpack_from("<I", data, o + 36)[0]
        pe.sections.append(Section(nm, vs, va, rs, ra, ch))
    return pe


def sec_of_rva(pe: PeFile, rva: int) -> Optional[Section]:
    for s in pe.sections:
        if s.virtual_address <= rva < s.virtual_address + max(s.virtual_size, s.raw_size):
            return s
    return None


def sec_entropy(pe: PeFile, s: Section) -> float:
    return _ent(pe.data[s.raw_address:s.raw_address + s.raw_size])


def has_watermark(data: bytes) -> Optional[str]:
    for w in PEC_WATERMARKS:
        if w in data:
            return w.decode()
    return None


def detect(pe: PeFile) -> dict:
    if not pe.is_pe:
        return {"file": pe.path, "is_pe": False, "error": pe.error}
    wm = has_watermark(pe.data)
    ep_sec = sec_of_rva(pe, pe.entry_rva)
    # PECompact 特征: 极少节(2~3)、CODE 节、节高熵、入口在可写/高熵节
    code_sec = next((s for s in pe.sections if s.name.upper() == "CODE"), None)
    high_entropy = [s.name for s in pe.sections if s.raw_size and sec_entropy(pe, s) > 7.2]
    ep_high = bool(ep_sec and ep_sec.raw_size and sec_entropy(pe, ep_sec) > 7.2)
    few_sections = len(pe.sections) <= 3
    detected = bool(wm) or (few_sections and (code_sec is not None or ep_high) and bool(high_entropy))
    return {
        "file": pe.path, "is_pe": True,
        "image_base": pe.image_base, "entry_rva": pe.entry_rva,
        "is64": pe.is64, "num_sections": len(pe.sections),
        "pecompact_detected": detected, "watermark": wm,
        "entry_section": ep_sec.name if ep_sec else None,
        "ep_in_high_entropy_section": ep_high,
        "code_section": code_sec.name if code_sec else None,
        "high_entropy_sections": high_entropy,
        "sections": [s.name for s in pe.sections],
    }


def sections_detail(pe: PeFile) -> dict:
    ep_sec = sec_of_rva(pe, pe.entry_rva)
    out = []
    for s in pe.sections:
        flags = ("R" if s.is_read else "-") + ("W" if s.is_write else "-") + ("X" if s.is_exec else "-")
        out.append({"name": s.name, "va": s.virtual_address, "vsize": s.virtual_size,
                    "rawsize": s.raw_size, "flags": flags,
                    "entropy": round(sec_entropy(pe, s), 3),
                    "is_ep": (ep_sec is s),
                    "rebuild_hint": ("keep uncompressed (resource)" if s.name.lower() in (".rsrc", ".reloc")
                                     else "rebuild")})
    # 数据目录: 资源/重定位/导入
    data = pe.data
    e = struct.unpack_from("<I", data, 0x3C)[0]; opt = e + 24
    ddoff = opt + (96 if not pe.is64 else 112)
    dirs = {}
    for idx, nm in [(1, "import"), (2, "resource"), (5, "reloc"), (6, "security")]:
        rva, sz = struct.unpack_from("<II", data, ddoff + idx * 8)
        dirs[nm] = {"rva": rva, "size": sz}
    return {"file": pe.path, "sections": out, "data_directories": dirs}


def run_and_dump(src: str, out: str) -> dict:
    if os.name != "nt":
        return {"ok": False, "error": "run-and-dump 仅 Windows 可用"}
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class SI(ctypes.Structure):
        _fields_ = [(n, ctypes.c_void_p) for n in
                    ("cb","lpReserved","lpDesktop","lpTitle","dwX","dwY","dwXSize","dwYSize",
                     "dwXCountChars","dwYCountChars","dwFillAttribute","dwFlags","wShowWindow",
                     "cbReserved2","lpReserved2","hStdInput","hStdOutput","hStdError")]
    class PI(ctypes.Structure):
        _fields_ = [("hProcess", wintypes.HANDLE),("hThread", wintypes.HANDLE),
                    ("dwProcessId", wintypes.DWORD),("dwThreadId", wintypes.DWORD)]
    si = SI(); si.cb = ctypes.sizeof(SI); pi = PI()
    cmd = ctypes.create_unicode_buffer('"%s"' % os.path.abspath(src))
    if not k32.CreateProcessW(None, cmd, None, None, False, 0, None, None,
                              ctypes.byref(si), ctypes.byref(pi)):
        return {"ok": False, "error": "CreateProcessW %d" % ctypes.get_last_error()}
    try:
        k32.ResumeThread(pi.hThread)
        k32.WaitForSingleObject(pi.hProcess, 2500)
        pe = parse_pe(open(src, "rb").read(), src)
        buf = ctypes.create_string_buffer(pe.size_of_image)
        rd = ctypes.c_size_t(0)
        if k32.ReadProcessMemory(pi.hProcess, ctypes.c_void_p(pe.image_base), buf,
                                 ctypes.c_size_t(pe.size_of_image), ctypes.byref(rd)) and rd.value:
            open(out, "wb").write(buf.raw[:rd.value])
            return {"ok": True, "out": out, "bytes": rd.value}
        return {"ok": False, "error": "ReadProcessMemory %d" % ctypes.get_last_error()}
    finally:
        k32.TerminateProcess(pi.hProcess, 0)
        k32.CloseHandle(pi.hThread); k32.CloseHandle(pi.hProcess)


def _text(r: dict) -> str:
    if "sections" in r and "data_directories" in r:
        L = ["Sections: %s" % r["file"]]
        for s in r["sections"]:
            L.append("  %-8s VA 0x%08X VS 0x%08X RS 0x%08X [%s] ent %.3f%s  <%s>" % (
                s["name"], s["va"], s["vsize"], s["rawsize"], s["flags"], s["entropy"],
                " <EP" if s["is_ep"] else "", s["rebuild_hint"]))
        L.append("Data directories: %s" % r["data_directories"])
        return "\n".join(L)
    if not r.get("is_pe", True):
        return "[!] %s: %s" % (r["file"], r.get("error"))
    return "\n".join([
        "File: %s" % r["file"],
        "ImageBase 0x%08X EntryRVA 0x%08X (%s, %d sections)" % (
            r["image_base"], r["entry_rva"], "PE32+" if r["is64"] else "PE32", r["num_sections"]),
        "Sections: %s" % ", ".join(r["sections"]),
        "Watermark: %s" % r["watermark"],
        "Entry section: %s (high-entropy=%s)" % (r["entry_section"], r["ep_in_high_entropy_section"]),
        "CODE section: %s  high-entropy: %s" % (r["code_section"], r["high_entropy_sections"]),
        "==> PECompact detected: %s" % ("YES" if r["pecompact_detected"] else "NO"),
    ])


USAGE = __doc__


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="main.py", add_help=False)
    p.add_argument("target", nargs="?"); p.add_argument("cmd", nargs="?", default="detect",
                   choices=["detect", "info", "sections", "unpack"])
    p.add_argument("--json", action="store_true"); p.add_argument("-h", "--help", action="store_true")
    a = p.parse_args(argv)
    if a.help or not a.target:
        print(USAGE); return EXIT_SUCCESS
    try:
        data = open(a.target, "rb").read()
    except OSError as e:
        print("[!] %s" % e); return EXIT_FAILURE
    pe = parse_pe(data, a.target)
    if a.cmd == "unpack":
        out = os.path.splitext(a.target)[0] + ".unpacked.exe"
        r = run_and_dump(a.target, out)
        print(json.dumps(r, indent=2) if a.json else ("[+] %s" % r["out"] if r.get("ok") else "[!] %s" % r.get("error")))
        return EXIT_SUCCESS if r.get("ok") else EXIT_FAILURE
    r = sections_detail(pe) if a.cmd == "sections" else detect(pe)
    print(json.dumps(r, ensure_ascii=False, indent=2) if a.json else _text(r))
    return EXIT_SUCCESS if pe.is_pe else EXIT_FAILURE


if __name__ == "__main__":
    sys.exit(main())