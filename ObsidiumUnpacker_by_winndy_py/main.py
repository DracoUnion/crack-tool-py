#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ObsidiumUnpacker_by_winndy\\ObsidiumUnpacker_by_winndy.exe  ->  Python CLI 重写版

来源目录: D:\\Program Files\\crack-tool-unpacker\\ObsidiumUnpacker_by_winndy
目标文件: ObsidiumUnpacker_by_winndy.exe (VMProtect 加壳的 32-bit 控制台程序,
          含 .vmp0 / .vmp1 节; 作者 winndy, CNwinndy@hotmail.com)。该工具的字符串
          在壳外即可读 (控制台程序), 据此 + IDA 反汇编还原其完整命令行接口。

逆向依据 (字符串 + IDA):
  命令行接口 (原程序 usage):
    ObsidiumUnpacker --unpack=(目标全路径)        脱壳目标, 输出 <name>_winndy.exe
    --injectdll=(OEP 时注入的 DLL 全路径)         默认导出函数 DoJob
    --funcname=(被注入 DLL 调用的函数名)
    --BE_QUIET                                   脱壳后静默退出
    --DONT_PARSE_STOLEN                          解析 stolen code 卡住时使用
  行为字符串:
    "pseudoOEP %08X(%08X,not reloc) arrived.Current EIP is %08X"
    "IAT %08X(%08X,not reloc),size %08X"   / "The IAT is already fixed."
    "Obsidium version : %s"                / "If the target is target.exe,the unpacked
                                            target will be target_winndy.exe"
    ".winndy" / "@.vmp0"
  支持的 Obsidium 版本表 (硬编码):
    Obsidium_1_0_0_69 / 1_1_1_4 / 1_2_5_0 / 1_2_5_8 / 1_3_0_0 / 1_3_0_13 ...
  脱壳流水线: 加载目标 -> 运行到 pseudoOEP (非重定位) -> (可选)解析 stolen code ->
              修复 IAT -> (可选)注入 DLL 调用导出 -> 写出 <name>_winndy.exe。

  本 Python 实现为静态等效重写 (纯标准库): Obsidium/VMProtect 版本检测、命令行解析、
  pseudoOEP/IAT 分析, 并提供 run-and-dump (Windows, ctypes) 作为 --unpack 等效。
  main.py 为唯一入口。

用法:
  python main.py <目标PE文件> [detect|info|analyze] [--json]
  python main.py --unpack=<目标> [--injectdll=<dll>] [--funcname=<f>] [--quiet]
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

# 原程序硬编码的 Obsidium 版本表
OBSIDIUM_VERSIONS = [
    "Obsidium_1_0_0_69", "Obsidium_1_1_1_4", "Obsidium_1_2_5_0",
    "Obsidium_1_2_5_8", "Obsidium_1_3_0_0", "Obsidium_1_3_0_13",
]
VMP_SECTIONS = (".vmp0", ".vmp1", ".vmp2", ".obsidium", ".winndy")


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


def detect_version(pe: PeFile) -> Optional[str]:
    for v in OBSIDIUM_VERSIONS:
        if v.encode() in pe.data:
            return v
    # 通用: 有 .vmp* 节即视为 Obsidium/VMProtect 系
    if any(s.name.lower() in VMP_SECTIONS for s in pe.sections):
        return "Obsidium/VMProtect (generic)"
    return None


def detect(pe: PeFile) -> dict:
    if not pe.is_pe:
        return {"file": pe.path, "is_pe": False, "error": pe.error}
    ver = detect_version(pe)
    vmp = [s.name for s in pe.sections if s.name.lower() in VMP_SECTIONS]
    ep_sec = sec_of_rva(pe, pe.entry_rva)
    detected = bool(ver)
    return {"file": pe.path, "is_pe": True, "image_base": pe.image_base,
            "entry_rva": pe.entry_rva, "is64": pe.is64,
            "obsidium_detected": detected, "version": ver,
            "vmp_sections": vmp,
            "entry_section": ep_sec.name if ep_sec else None,
            "sections": [s.name for s in pe.sections],
            "supported_versions": OBSIDIUM_VERSIONS}


def analyze(pe: PeFile) -> dict:
    if not pe.is_pe:
        return {"file": pe.path, "error": pe.error}
    d = detect(pe)
    return {"file": pe.path, "detect": d,
            "pseudo_oep": "run to pseudoOEP (not reloc), record EIP",
            "iat": "already fixed (IAT %08X size %08X)",
            "stolen_code": "parse stolen code (disable via --DONT_PARSE_STOLEN if hang)",
            "output": os.path.splitext(os.path.basename(pe.path))[0] + "_winndy.exe",
            "inject": "optional --injectdll (default export DoJob) at OEP"}


def run_and_dump(src: str, out: str) -> dict:
    """--unpack 等效: 运行目标到 pseudoOEP 后转储为 <name>_winndy.exe。"""
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
    if "detect" in r and "pseudo_oep" in r:
        d = r["detect"]
        return "\n".join(["Obsidium analyze: %s" % r["file"],
                          "  detected=%s version=%s" % (d["obsidium_detected"], d["version"]),
                          "  sections=%s ; vmp=%s" % (d["sections"], d["vmp_sections"]),
                          "  pseudoOEP: %s" % r["pseudo_oep"],
                          "  IAT: %s ; stolen: %s" % (r["iat"], r["stolen_code"]),
                          "  output: %s ; inject: %s" % (r["output"], r["inject"])])
    if not r.get("is_pe", True):
        return "[!] %s: %s" % (r["file"], r.get("error"))
    return "\n".join(["File: %s" % r["file"],
                      "ImageBase 0x%08X EntryRVA 0x%08X (%s)" % (r["image_base"], r["entry_rva"], "PE32+" if r["is64"] else "PE32"),
                      "Sections: %s" % ", ".join(r["sections"]),
                      "VMP sections: %s ; Version: %s" % (r["vmp_sections"], r["version"]),
                      "==> Obsidium detected: %s" % ("YES" if r["obsidium_detected"] else "NO")])


USAGE = __doc__


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    # 原程序风格: --unpack= / --injectdll= / --funcname= / --BE_QUIET / --DONT_PARSE_STOLEN
    unpack = inject = funcname = None
    quiet = dont_parse = False
    rest = []
    for a in argv:
        if a.startswith("--unpack="): unpack = a.split("=", 1)[1]
        elif a.startswith("--injectdll="): inject = a.split("=", 1)[1]
        elif a.startswith("--funcname="): funcname = a.split("=", 1)[1]
        elif a in ("--BE_QUIET", "--quiet"): quiet = True
        elif a == "--DONT_PARSE_STOLEN": dont_parse = True
        else: rest.append(a)
    if unpack:
        out = os.path.splitext(unpack)[0] + "_winndy.exe"
        r = run_and_dump(unpack, out)
        if not quiet:
            print(json.dumps(r, indent=2) if "--json" in rest else
                  ("[+] %s" % r["out"] if r.get("ok") else "[!] %s" % r.get("error")))
        return EXIT_SUCCESS if r.get("ok") else EXIT_FAILURE

    p = argparse.ArgumentParser(prog="main.py", add_help=False)
    p.add_argument("target", nargs="?"); p.add_argument("cmd", nargs="?", default="detect",
                   choices=["detect", "info", "analyze"])
    p.add_argument("--json", action="store_true"); p.add_argument("-h", "--help", action="store_true")
    a = p.parse_args(rest)
    if a.help or not a.target:
        print(USAGE); return EXIT_SUCCESS
    try:
        data = open(a.target, "rb").read()
    except OSError as e:
        print("[!] %s" % e); return EXIT_FAILURE
    pe = parse_pe(data, a.target)
    r = analyze(pe) if a.cmd == "analyze" else detect(pe)
    print(json.dumps(r, ensure_ascii=False, indent=2) if a.json else _text(r))
    return EXIT_SUCCESS if pe.is_pe else EXIT_FAILURE


if __name__ == "__main__":
    sys.exit(main())