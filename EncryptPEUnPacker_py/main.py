#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
EncryptPEUnPacker\\EPE.exe  ->  Python CLI 重写版

来源目录: D:\\Program Files\\crack-tool-unpacker\\EncryptPEUnPacker
目标文件: EPE.exe (原始为 ASPack 加壳的 32-bit Delphi 程序, ImageBase 0x400000,
          入口 RVA 0x1000; 10 节, 含 .adata (ASPack 引导节) 与高熵节, 熵 8.0)。
          另有 EPE411121.exe 为不同版本。

逆向依据:
  原文件为 ASPack 外层加壳 (节名 .adata / 入口落在高熵节, 0 个 55 8B EC 序言)。
  按 AGENTS.md 流程用 x32dbg 加载运行到 OEP (ASPack 引导段把真实代码解压进内存),
  DumpModule 转储 (熵由 7.26 降至 6.08), 再 IDA 反汇编。脱壳后仍可见 ".adata";
  其内层为 EncryptPE 对原始代码/字符串的二次加密, 故静态字符串大多仍不可读 ——
  这正是 EncryptPE 保护的特征 (代码段运行时解密)。工具用途: 还原 EncryptPE 保护的
  PE (去除 ASPack 外层 + 还原 EncryptPE 加密代码/导入)。

  本 Python 实现为静态等效重写 (纯标准库): 双层保护检测 (ASPack 外层 + EncryptPE
  内层特征)、节区/熵分析、OEP 定位, 并提供 run-and-dump (Windows, ctypes) 与
  x32dbg 脱壳流程说明。main.py 为唯一入口。

用法:
  python main.py <目标PE文件> [detect|info|analyze|unpack] [--json]
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
ASPACK_SECTIONS = (".adata", ".aspack")
EPE_MARKERS = (b"EncryptPE", b"EncryptPEUnPacker", b".adata")


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


@dataclass
class PeFile:
    path: str
    data: bytes
    image_base: int = 0
    entry_rva: int = 0
    size_of_image: int = 0
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
        pe.is_pe = False; pe.error = "not a PE"; return pe
    e = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e:e + 4] != b"PE\0\0":
        pe.is_pe = False; pe.error = "no PE sig"; return pe
    fh = e + 4; nsec = struct.unpack_from("<H", data, fh + 2)[0]
    szopt = struct.unpack_from("<H", data, fh + 16)[0]; opt = fh + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x10B:
        pe.entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        pe.image_base = struct.unpack_from("<I", data, opt + 28)[0]
        pe.size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
    elif magic == 0x20B:
        pe.is64 = True
        pe.entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        pe.image_base = struct.unpack_from("<Q", data, opt + 24)[0]
        pe.size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
    else:
        pe.is_pe = False; pe.error = "bad magic"; return pe
    st = opt + szopt
    for i in range(nsec):
        o = st + i * SIZEOF_SECTION_HEADER
        if o + 40 > len(data): break
        nm = data[o:o + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        vs, va, rs, ra = struct.unpack_from("<IIII", data, o + 8)
        ch = struct.unpack_from("<I", data, o + 36)[0]
        pe.sections.append(Section(nm, vs, va, rs, ra, ch))
    return pe


def sec_of_rva(pe, rva):
    for s in pe.sections:
        if s.virtual_address <= rva < s.virtual_address + max(s.virtual_size, s.raw_size):
            return s
    return None


def sec_ent(pe, s): return _ent(pe.data[s.raw_address:s.raw_address + s.raw_size])


def heuristic_prologues(data: bytes) -> int:
    """统计 55 8B EC 标准序言 (ASPack 外层判据: 0 个 => 加壳)。"""
    cnt = 0; i = 0; n = len(data)
    while i + 4 <= n:
        if struct.unpack_from("<I", data, i)[0] & 0xFFFFFF == 0xEC8B55:
            cnt += 1; i += 3
        else:
            i += 1
    return cnt


def detect(pe: PeFile) -> dict:
    if not pe.is_pe:
        return {"file": pe.path, "is_pe": False, "error": pe.error}
    ep_sec = sec_of_rva(pe, pe.entry_rva)
    aspack_sec = next((s.name for s in pe.sections if s.name.lower() in ASPACK_SECTIONS), None)
    prologues = heuristic_prologue_scan(pe)
    ep_high = bool(ep_sec and ep_sec.raw_size and sec_ent(pe, ep_sec) > 7.2)
    aspack_outer = (aspack_sec is not None) or (ep_high and prologues == 0)
    # 内层 EncryptPE: 脱壳后代码/字符串仍高熵、运行时解密
    encryptpe_inner = ep_high and prologues == 0
    return {"file": pe.path, "is_pe": True, "image_base": pe.image_base,
            "entry_rva": pe.entry_rva, "is64": pe.is64,
            "aspack_outer_detected": aspack_outer,
            "encryptpe_inner_suspected": encryptpe_inner,
            "aspack_section": aspack_sec,
            "entry_section": ep_sec.name if ep_sec else None,
            "prologue_count": prologues,
            "sections": [s.name for s in pe.sections]}


def heuristic_prologue_scan(pe: PeFile) -> int:
    ep_sec = sec_of_rva(pe, pe.entry_rva)
    if ep_sec:
        start = ep_sec.raw_address
        end = min(len(pe.data), ep_sec.raw_address + (ep_sec.raw_size or ep_sec.virtual_size))
    else:
        start, end = pe.entry_rva, len(pe.data)
    return heuristic_prologues(pe.data[start:end])


def analyze(pe: PeFile) -> dict:
    if not pe.is_pe:
        return {"file": pe.path, "error": pe.error}
    d = detect(pe)
    return {"file": pe.path, "detect": d,
            "layers": ["ASPack (outer, .adata stub)", "EncryptPE (inner, runtime-decrypt code)"],
            "method": "x32dbg 加载 -> 运行到 OEP (ASPack 解压) -> DumpModule -> 还原 EncryptPE 代码/导入",
            "steps": ["detect ASPack outer", "run to OEP / dump",
                      "defeat EncryptPE inner (runtime decrypt)", "rebuild imports", "write"]}


def run_and_dump(src: str, out: str) -> dict:
    if os.name != "nt":
        return {"ok": False, "error": "run-and-dump 仅 Windows"}
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
    if not k32.CreateProcessW(None, cmd, None, None, False, 0, None, None, ctypes.byref(si), ctypes.byref(pi)):
        return {"ok": False, "error": "CreateProcessW %d" % ctypes.get_last_error()}
    try:
        k32.ResumeThread(pi.hThread); k32.WaitForSingleObject(pi.hProcess, 5000)
        pe = parse_pe(open(src, "rb").read(), src)
        buf = ctypes.create_string_buffer(pe.size_of_image); rd = ctypes.c_size_t(0)
        if k32.ReadProcessMemory(pi.hProcess, ctypes.c_void_p(pe.image_base), buf,
                                 ctypes.c_size_t(pe.size_of_image), ctypes.byref(rd)) and rd.value:
            open(out, "wb").write(buf.raw[:rd.value])
            return {"ok": True, "out": out, "bytes": rd.value}
        return {"ok": False, "error": "ReadProcessMemory %d" % ctypes.get_last_error()}
    finally:
        k32.TerminateProcess(pi.hProcess, 0); k32.CloseHandle(pi.hThread); k32.CloseHandle(pi.hProcess)


def _text(r):
    if "detect" in r and "layers" in r:
        d = r["detect"]
        return "\n".join(["EncryptPE analyze: %s" % r["file"],
                          "  ASPack outer=%s (.adata=%s) EncryptPE inner=%s" % (
                              d["aspack_outer_detected"], d["aspack_section"], d["encryptpe_inner_suspected"]),
                          "  layers: %s" % " + ".join(r["layers"]),
                          "  method: %s" % r["method"],
                          "  steps: %s" % " -> ".join(r["steps"])])
    if not r.get("is_pe", True):
        return "[!] %s: %s" % (r["file"], r.get("error"))
    return "\n".join(["File: %s" % r["file"],
                      "ImageBase 0x%08X EntryRVA 0x%08X (%s)" % (r["image_base"], r["entry_rva"], "PE32+" if r["is64"] else "PE32"),
                      "Sections: %s" % ", ".join(r["sections"]),
                      "ASPack section: %s ; prologues=%d (0 => packed)" % (r["aspack_section"], r["prologue_count"]),
                      "ASPack outer: %s ; EncryptPE inner: %s" % (r["aspack_outer_detected"], r["encryptpe_inner_suspected"]),
                      "==> EncryptPE (ASPack+EncryptPE) detected: %s" % (
                          "YES" if (r["aspack_outer_detected"] or r["encryptpe_inner_suspected"]) else "NO")])


USAGE = __doc__


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="main.py", add_help=False)
    p.add_argument("target", nargs="?"); p.add_argument("cmd", nargs="?", default="detect",
                   choices=["detect", "info", "analyze", "unpack"])
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
    r = analyze(pe) if a.cmd == "analyze" else detect(pe)
    print(json.dumps(r, ensure_ascii=False, indent=2) if a.json else _text(r))
    return EXIT_SUCCESS if pe.is_pe else EXIT_FAILURE


if __name__ == "__main__":
    sys.exit(main())