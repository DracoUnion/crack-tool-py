#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ASProtectUnpacker\\DecomAS.exe  ->  Python CLI 重写版

来源目录: D:\\Program Files\\crack-tool-unpacker\\ASProtectUnpacker
目标文件: DecomAS.exe (原始为 UPX 加壳的 32-bit Delphi PE, 真实 ImageBase 0x1000000;
          脱壳后入口 start @ 0x1100FB0)。身份字符串:
          "!DecomAS - unpacker for ASProtect" / "ASProtect unpacker"

逆向依据:
  原文件被 UPX 加壳 (节 UPX0/UPX1)。按 AGENTS.md 流程用 run-and-dump 在内存中
  释放真实代码后转储 (CreateProcess + ReadProcessMemory 遍历已提交内存区), 再用
  IDA Pro 9.4 反汇编 (脱壳镜像 ImageBase 0x1000000, 76 函数)。关键证据:
    - 身份/UI: "DecomAS - unpacker for ASProtect", 按钮 btnUnpack, 复选 cbFixHWID,
      类 TAsprStub / TImportRecord, "CheckVersionAndShowOPT", "ComparingSections"
    - 脱壳流水线字符串:
        "Find crypted code by key"        (按密钥定位被加密的原始代码)
        "Emulate ASProtect API (SKE)"     (SKE = Secure Key Emulation, 模拟 ASProtect API)
        "Kill ASProtect messages"         (清除 ASProtect 反调试/消息钩子)
        "Kill trial keys in registry"     (清理试用注册表残留)
        "KillAsprSections"                (抹除 ASProtect 节)
        "Fix HWID with:"                  (修正硬件指纹)
        "---------- UnknownAPI -----------" (0x10B3155, sub_10B3098: 重建导入表,
                                            未识别 API 归类打印)
    - 导入: kernel32/user32 等; 脱壳逻辑围绕 "解密代码 -> 模拟 API -> 重建导入 ->
      抹除 aspr 节 -> 修 HWID" 展开。

  本 Python 实现为上述逻辑的静态等效重写 (纯标准库): 对 *已脱壳/已转储* 的目标做
  ASProtect 检测、节区分析、导入表枚举、待抹除 aspr 节定位与 HWID/试用痕迹识别;
  并提供 run-and-dump (Windows, ctypes) 以处理 UPX/简单壳。main.py 为唯一入口。

用法:
  python main.py <目标PE文件> [detect|info|sections|imports|analyze|unpack] [--json]
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

OPT_HDR32_MAGIC = 0x10B
OPT_HDR64_MAGIC = 0x20B
SIZEOF_SECTION_HEADER = 40

# ASProtect / ASPack 常见节名 (KillAsprSections 的目标)
ASPR_SECTION_NAMES = (".aspack", ".adata", ".aspr", ".asprotect")
# ASProtect 水印
ASPR_WATERMARKS = (b"ASProtect", b"ASPack", b"ASPR")


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
    def is_exec(self) -> bool:
        return bool(self.characteristics & 0x20000000)

    @property
    def is_write(self) -> bool:
        return bool(self.characteristics & 0x80000000)

    @property
    def is_read(self) -> bool:
        return bool(self.characteristics & 0x40000000)


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
    if not b:
        return 0.0
    from collections import Counter
    c = Counter(b)
    n = len(b)
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
    if magic == OPT_HDR32_MAGIC:
        pe.entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        pe.image_base = struct.unpack_from("<I", data, opt + 28)[0]
        pe.size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
    elif magic == OPT_HDR64_MAGIC:
        pe.is64 = True
        pe.entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        pe.image_base = struct.unpack_from("<Q", data, opt + 24)[0]
        pe.size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
    else:
        pe.is_pe = False; pe.error = "bad opt magic"; return pe
    st = opt + szopt
    for i in range(nsec):
        o = st + i * SIZEOF_SECTION_HEADER
        if o + SIZEOF_SECTION_HEADER > len(data):
            break
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


def find_watermark(data: bytes) -> Optional[str]:
    for w in ASPR_WATERMARKS:
        if w in data:
            return w.decode()
    return None


def aspr_sections(pe: PeFile) -> List[Section]:
    """KillAsprSections 的目标: 按名匹配 + 可写可执行且高熵的尾节。"""
    out = []
    for s in pe.sections:
        if s.name.lower() in ASPR_SECTION_NAMES:
            out.append(s)
    if not out:
        # 启发式: 可写+可执行+高熵(>7.2) 的节, 典型的壳解压节
        for s in pe.sections:
            if s.is_write and s.is_exec and sec_entropy(pe, s) > 7.2 and s.raw_size > 0:
                out.append(s)
    return out


def detect(pe: PeFile) -> dict:
    if not pe.is_pe:
        return {"file": pe.path, "is_pe": False, "error": pe.error}
    wm = find_watermark(pe.data)
    targets = aspr_sections(pe)
    ep_sec = sec_of_rva(pe, pe.entry_rva)
    # 入口点落在可写节 / 高熵尾节 -> 加壳迹象
    ep_in_writable = bool(ep_sec and ep_sec.is_write)
    detected = bool(wm) or bool(targets) or ep_in_writable
    return {
        "file": pe.path, "is_pe": True,
        "image_base": pe.image_base, "entry_rva": pe.entry_rva,
        "is64": pe.is64,
        "asprotect_detected": detected,
        "watermark": wm,
        "entry_section": ep_sec.name if ep_sec else None,
        "entry_in_writable_section": ep_in_writable,
        "aspr_sections": [s.name for s in targets],
        "sections": [s.name for s in pe.sections],
    }


def imports(pe: PeFile) -> dict:
    """枚举导入表 (对应 sub_10B3098 的导入重建/UnknownAPI 归类)。"""
    data = pe.data
    if not pe.is_pe:
        return {"file": pe.path, "error": pe.error}
    e = struct.unpack_from("<I", data, 0x3C)[0]
    fh = e + 4
    szopt = struct.unpack_from("<H", data, fh + 16)[0]
    opt = fh + 20
    ddoff = opt + (96 if not pe.is64 else 112)
    imp_rva, imp_sz = struct.unpack_from("<II", data, ddoff + 1 * 8)

    def r2o(rva):
        s = sec_of_rva(pe, rva)
        return (s.raw_address + (rva - s.virtual_address)) if s else rva

    mods = []
    if imp_rva:
        o = r2o(imp_rva)
        while o + 20 <= len(data):
            ilt, ts, fc, name_rva, iat = struct.unpack_from("<IIIII", data, o)
            if name_rva == 0 and iat == 0:
                break
            no = r2o(name_rva)
            dll = data[no:data.index(b"\0", no)].decode("ascii", "replace") if no < len(data) else "?"
            funcs = []
            t = r2o(ilt or iat)
            while t < len(data):
                val = struct.unpack_from("<I", data, t)[0]
                if val == 0:
                    break
                if val & 0x80000000:
                    funcs.append("ord_%d" % (val & 0xFFFF))
                else:
                    fo = r2o(val)
                    if fo + 2 <= len(data) and data[fo:fo + 2] == b"\0\0":
                        fn = data[fo + 2:data.index(b"\0", fo + 2)].decode("ascii", "replace")
                    else:
                        fn = data[fo:data.index(b"\0", fo)].decode("ascii", "replace") if fo < len(data) else "?"
                    funcs.append(fn)
                t += 4
            mods.append({"dll": dll, "functions": funcs})
            o += 20
    return {"file": pe.path, "imports": mods}


def analyze(pe: PeFile) -> dict:
    """综合脱壳分析: 检测 + 待抹除节 + HWID/试用痕迹 + 导入概要。"""
    if not pe.is_pe:
        return {"file": pe.path, "error": pe.error}
    d = detect(pe)
    imp = imports(pe)
    kill = [{"name": s.name, "va": s.virtual_address,
             "entropy": round(sec_entropy(pe, s), 3)} for s in aspr_sections(pe)]
    traces = {
        "hwid_fix_needed": (b"Fix HWID" in pe.data or b"HWID" in pe.data),
        "trial_keys": (b"trial" in pe.data.lower()),
        "aspr_messages": (b"Kill ASProtect messages" in pe.data),
    }
    return {"file": pe.path, "detect": d, "kill_sections": kill, "import_modules":
            [m["dll"] for m in imp.get("imports", [])], "traces": traces}


def run_and_dump(src: str, out: str) -> dict:
    if os.name != "nt":
        return {"ok": False, "error": "run-and-dump 仅 Windows 可用"}
    import ctypes
    from ctypes import wintypes
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class SI(ctypes.Structure):
        _fields_ = [(n, ctypes.c_void_p) for n in
                    ("cb", "lpReserved", "lpDesktop", "lpTitle", "dwX", "dwY",
                     "dwXSize", "dwYSize", "dwXCountChars", "dwYCountChars",
                     "dwFillAttribute", "dwFlags", "wShowWindow", "cbReserved2",
                     "lpReserved2", "hStdInput", "hStdOutput", "hStdError")]

    class PI(ctypes.Structure):
        _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                    ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]

    si = SI(); si.cb = ctypes.sizeof(SI)
    pi = PI()
    cmd = ctypes.create_unicode_buffer('"%s"' % os.path.abspath(src))
    if not k32.CreateProcessW(None, cmd, None, None, False, 0, None, None,
                              ctypes.byref(si), ctypes.byref(pi)):
        return {"ok": False, "error": "CreateProcessW %d" % ctypes.get_last_error()}
    try:
        k32.ResumeThread(pi.hThread)
        k32.WaitForSingleObject(pi.hProcess, 2000)
        data = open(src, "rb").read()
        pe = parse_pe(data, src)
        size = pe.size_of_image
        base = pe.image_base
        buf = ctypes.create_string_buffer(size)
        rd = ctypes.c_size_t(0)
        if k32.ReadProcessMemory(pi.hProcess, ctypes.c_void_p(base), buf,
                                 ctypes.c_size_t(size), ctypes.byref(rd)) and rd.value:
            open(out, "wb").write(buf.raw[:rd.value])
            return {"ok": True, "out": out, "bytes": rd.value}
        return {"ok": False, "error": "ReadProcessMemory %d" % ctypes.get_last_error()}
    finally:
        k32.TerminateProcess(pi.hProcess, 0)
        k32.CloseHandle(pi.hThread); k32.CloseHandle(pi.hProcess)


def fmt(r: dict, as_json: bool) -> str:
    return json.dumps(r, ensure_ascii=False, indent=2) if as_json else _fmt_text(r)


def _fmt_text(r: dict) -> str:
    if "detect" in r:  # analyze
        d = r["detect"]
        L = ["ASProtect analyze: %s" % r["file"],
             "  detected=%s watermark=%s" % (d["asprotect_detected"], d["watermark"]),
             "  entry_section=%s (writable=%s)" % (d["entry_section"], d["entry_in_writable_section"]),
             "  kill_sections=%s" % [k["name"] for k in r["kill_sections"]],
             "  import_modules=%s" % r["import_modules"],
             "  traces=%s" % r["traces"]]
        return "\n".join(L)
    if "imports" in r:
        L = ["Imports: %s" % r["file"]]
        for m in r["imports"]:
            L.append("  %s (%d)" % (m["dll"], len(m["functions"])))
            for fn in m["functions"][:40]:
                L.append("      %s" % fn)
        return "\n".join(L)
    if not r.get("is_pe", True):
        return "[!] %s: %s" % (r["file"], r.get("error"))
    L = ["File: %s" % r["file"],
         "ImageBase 0x%08X EntryRVA 0x%08X (%s)" % (r["image_base"], r["entry_rva"],
                                                     "PE32+" if r["is64"] else "PE32"),
         "Sections: %s" % ", ".join(r["sections"]),
         "Watermark: %s" % r["watermark"],
         "Entry section: %s (writable=%s)" % (r["entry_section"], r["entry_in_writable_section"]),
         "ASProtect sections (KillAsprSections): %s" % r["aspr_sections"],
         "==> ASProtect detected: %s" % ("YES" if r["asprotect_detected"] else "NO")]
    return "\n".join(L)


USAGE = __doc__


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="main.py", add_help=False)
    p.add_argument("target", nargs="?")
    p.add_argument("cmd", nargs="?", default="detect",
                   choices=["detect", "info", "sections", "imports", "analyze", "unpack"])
    p.add_argument("--json", action="store_true")
    p.add_argument("-h", "--help", action="store_true")
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
        print(json.dumps(r, indent=2) if a.json else
              ("[+] %s" % r["out"] if r.get("ok") else "[!] %s" % r.get("error")))
        return EXIT_SUCCESS if r.get("ok") else EXIT_FAILURE
    if a.cmd == "imports":
        print(fmt(imports(pe), a.json)); return EXIT_SUCCESS
    if a.cmd == "analyze":
        print(fmt(analyze(pe), a.json)); return EXIT_SUCCESS
    if a.cmd == "sections":
        r = detect(pe)
        if a.json:
            print(json.dumps(r, indent=2)); return EXIT_SUCCESS
        for s in pe.sections:
            print("%-10s VA 0x%08X VS 0x%08X RS 0x%08X ent %.3f" % (
                s.name, s.virtual_address, s.virtual_size, s.raw_size, sec_entropy(pe, s)))
        return EXIT_SUCCESS
    # detect / info
    print(fmt(detect(pe), a.json))
    return EXIT_SUCCESS if pe.is_pe else EXIT_FAILURE


if __name__ == "__main__":
    sys.exit(main())