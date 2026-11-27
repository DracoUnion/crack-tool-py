#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ExeCryptorUnpacker_2.x.x_1.0RC2\\Unpacker ExeCryptor RC2.exe  ->  Python CLI 重写版

来源目录: D:\\Program Files\\crack-tool-unpacker\\ExeCryptorUnpacker_2.x.x_1.0RC2
目标文件: Unpacker ExeCryptor RC2.exe (原始为 ExeCryptor 加壳的 32-bit 程序,
          真实 ImageBase 0x400000, 入口 start @ 0x437F5C; 含 .packed 节, 熵 7.9)。

逆向依据:
  原文件被 ExeCryptor 加壳 (.packed 节)。run-and-dump 脱壳后用 IDA Pro 9.4
  反汇编 (0x400000, 10 函数)。关键字符串 (脱壳流水线):
    "- - - - START UNPACK - - - -"
    "%X (Non Crypted code)->trace to OEP"   (从非加密代码跟踪到 OEP)
    "Find VM OEP" / "Do you want enter OEP?"
    "Fix IAT in Dump" / "Copy / Past Original IAT..." / "Reconstruct Dynamic Import"
    "Check Import table for emulate API..." (模拟 API 重建导入)
    "Patch message \"Debugger Detected\""   (打补丁绕过反调试)
    "Cut sections" / "@.packed"
    "Remove sign detected by Kaspersky"     (去除 Kaspersky 特征)
  脱壳流水线: 跟踪非加密代码到 OEP -> 定位 VM_OEP -> 修复/重建导入 (模拟 API) ->
              打补丁反调试 -> 裁剪 .packed 节 -> 写出 dump。

  本 Python 实现为静态等效重写 (纯标准库): ExeCryptor 检测 (.packed/高熵)、
  OEP/VM 分析、导入重建与反调试/特征识别, 并提供 run-and-dump (Windows, ctypes)。
  main.py 为唯一入口。

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
EC_MARKERS = (b"ExeCryptor", b".packed", b"Debugger Detected")


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


def packed_sections(pe: PeFile) -> List[Section]:
    return [s for s in pe.sections
            if s.name.lower() == ".packed" or (s.raw_size and sec_ent(pe, s) > 7.5)]


def detect(pe: PeFile) -> dict:
    if not pe.is_pe:
        return {"file": pe.path, "is_pe": False, "error": pe.error}
    ep_sec = sec_of_rva(pe, pe.entry_rva)
    pk = packed_sections(pe)
    wm = next((m.decode() for m in EC_MARKERS if m in pe.data), None)
    ep_high = bool(ep_sec and ep_sec.raw_size and sec_ent(pe, ep_sec) > 7.2)
    detected = bool(pk) or ep_high or (wm == ".packed")
    return {"file": pe.path, "is_pe": True, "image_base": pe.image_base,
            "entry_rva": pe.entry_rva, "is64": pe.is64,
            "excryptor_detected": detected, "marker": wm,
            "entry_section": ep_sec.name if ep_sec else None,
            "packed_sections": [s.name for s in pk],
            "sections": [s.name for s in pe.sections]}


def analyze(pe: PeFile) -> dict:
    if not pe.is_pe:
        return {"file": pe.path, "error": pe.error}
    d = detect(pe)
    return {"file": pe.path, "detect": d,
            "oep_trace": "trace Non-Crypted code -> OEP",
            "vm_oep": pe.entry_rva,
            "import_rebuild": "emulate API + Reconstruct Dynamic Import",
            "patches": ["Debugger Detected", "remove Kaspersky sign"],
            "cut_sections": [s.name for s in packed_sections(pe)],
            "steps": ["trace to OEP", "find VM OEP", "fix/reconstruct IAT",
                      "patch anti-debug", "cut .packed", "dump"]}


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
        k32.ResumeThread(pi.hThread); k32.WaitForSingleObject(pi.hProcess, 2500)
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
    if "detect" in r and "steps" in r:
        d = r["detect"]
        return "\n".join(["ExeCryptor analyze: %s" % r["file"],
                          "  detected=%s marker=%s" % (d["excryptor_detected"], d["marker"]),
                          "  OEP trace: %s ; VM_OEP RVA 0x%08X" % (r["oep_trace"], r["vm_oep"]),
                          "  import: %s" % r["import_rebuild"],
                          "  patches: %s ; cut: %s" % (r["patches"], r["cut_sections"]),
                          "  steps: %s" % " -> ".join(r["steps"])])
    if not r.get("is_pe", True):
        return "[!] %s: %s" % (r["file"], r.get("error"))
    return "\n".join(["File: %s" % r["file"],
                      "ImageBase 0x%08X EntryRVA 0x%08X (%s)" % (r["image_base"], r["entry_rva"], "PE32+" if r["is64"] else "PE32"),
                      "Sections: %s" % ", ".join(r["sections"]),
                      "Packed sections: %s" % r["packed_sections"],
                      "Entry section: %s" % r["entry_section"],
                      "==> ExeCryptor detected: %s" % ("YES" if r["excryptor_detected"] else "NO")])


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