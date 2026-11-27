#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CoolDumpper (loader.exe)  ->  Python CLI 重写版

来源目录: D:\\Program Files\\crack-tool-unpacker\\CoolDumpper
目标文件: loader.exe (32-bit PE, C++ Builder/Delphi 混合 GUI, 基址 0x400000,
          入口 0x42D458, 作者 "skylly", 标题串
          "CoolDumpper - All Packers Generic Unpacker")
          tool\\ 下为插件 DLL (upx/aspack/... 各脱壳插件) 与 loaddll.exe 装载器。

逆向依据 (IDA Pro 9.4 批处理反汇编, 基址 0x400000, 共 1425 函数):
  本工具是一个"运行 + 内存转储"型通用脱壳器 (LordPE 式 dumper)。
  关键字符串 (0x40B658 起):
      "CoolDumpper - All Packers Generic Unpacker"
      "dumped.exe" / "dumped.dll"                       (0x401650 / 0x40165C)
      "region//region%08x.ron"                          (0x40B7DC, 区段转储命名)
      "BaseAddr     Size     Type       State          Protect" (0x40B830)
      "Dump, Start: %08X, Size: %08X"                   (0x40B880)
      "Dump, OEP: %08X, IID Start: %08X, IID Size: %08X" (0x40B9B0)
      "OEP: %08X, IAT: %08X"                            (0x40B994)
  导入 (关键): OpenProcess / ReadProcessMemory / VirtualQueryEx /
      VirtualProtectEx / GlobalAlloc / CreateFileA / WriteFile /
      SetFilePointer / CreateToolhelp32Snapshot / Process32First/Next /
      Module32First/Next / CreateProcessA / WriteProcessMemory / ResumeThread。
      -> 证实为 run-and-dump: 启动/附加目标, 等壳在内存解压, 用
         ReadProcessMemory 把镜像/区段读出, WriteFile 落盘, 再重建 PE。

  算法 (IDA 地址):
  1) 进程枚举  sub_41B710 @0x41B710:
       CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS) -> Process32First/Next
       逐一把 szExeFile 与目标名 (wsprintfA "%s") 用 lstrcmpiA 比较,
       命中返回 th32ProcessID; 否则 0。
  2) 命令分发  sub_41B80F @0x41B80F (arg_0 = 命令号):
       0x465 -> sub_4239CB (loadexe/附加)
       0x466 -> sub_422C90 (整镜像 dump, 见下)
       0x468 -> sub_41C685 / sub_41C6CD
       0x469 -> CreateDirectoryA("region") + sub_41A7BF (区段 dump)
       0x46A -> sub_422C90
       0x46B -> sub_41A6E9 (写内存/硬件断点相关)
  3) 区段遍历  sub_41A7BF @0x41A7BF:
       OpenProcess(0x400) -> 从地址 0 起循环 VirtualQueryEx(0x1C 结构),
       按 Type(State) 分类 MEM_IMAGE/MEM_MAPPED/MEM_PRIVATE,
       按 State 分类 MEM_COMMIT/RESERVE/FREE, 按 AllocationProtect 打印
       PAGE_*; 对 MEM_PRIVATE+MEM_COMMIT 区段调用 sub_41AA68 逐个转储到
       region/region%08x.ron; 地址推进 = BaseAddress + RegionSize。
  4) 区段写出  sub_41AA68 @0x41AA68:
       OpenProcess(0x1F0FFF) -> GlobalAlloc(0x40, dwBytes) ->
       ReadProcessMemory(BaseAddress, dwBytes) -> CreateFileA(CREATE_ALWAYS) ->
       WriteFile(buffer, dwBytes) -> CloseHandle -> GlobalFree。
  5) 整镜像 dump  sub_422C90 @0x422C90:
       取进程路径 "\\" 分割取文件名, 拼 "dumped.exe"/"dumped.dll",
       调 sub_423757 读镜像, 再调 sub_422F88 写盘。
  6) 读镜像  sub_423757 @0x423757:
       OpenProcess(0x1F0FFF) -> VirtualProtectEx(lpAddress, dwSize, PAGE_
       _READWRITE) -> 按 0x1000 对齐 dwSize -> GlobalAlloc ->
       ReadProcessMemory(lpAddress, dwSize) 整块读入。
  7) 写镜像/重建  sub_422F88 @0x422F88:
       CreateFileA(GENERIC_WRITE) -> WriteFile(lpBuffer, [esi+0xB0]) 落盘原始
       镜像 -> sub_424E6C 做 PE 重建 (节表对齐 / RVA2Offset / IAT 修正)。
  8) CRC/保存  sub_41B4BA @0x41B4BA (SaveAsFunc): 读 0x40 头 + 0xF8 节表,
       在镜像内 memcmp 扫描 4 字节 CRC 特征, 命中区间回填 (CRC addr: %0Xh)。

  本 Python 实现完全基于上述逆向逻辑重写, 纯标准库, main.py 为唯一入口。
  info 为纯静态 PE 分析 (可直接对真实样本测试); dump 提供 Windows run-and-
  dump 的 ctypes 实现 (CreateProcess 挂起启动 + 等待壳解压 + VirtualQueryEx
  区段遍历 + ReadProcessMemory + WriteFile), 输出 <name>.dumped.exe。

用法:
  python main.py <目标PE文件> info|dump
命令:
  info   (默认) 解析 PE 头/节表/入口, 标注 .skylly 自定义节, 给出加壳/区段概览
  dump   Windows: 运行并转储目标进程镜像 -> <name>.dumped.exe
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

# 自定义节名 (该 EXE 带 .skylly 自定义节, 轻度保护/水印)
CUSTOM_SECTION_NAMES = (".skylly",)


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


# ===================== info: 静态 PE 概览 =====================
def find_custom_section(pe: PeFile) -> Optional[Section]:
    """定位自定义节 (.skylly 等), 对应原程序对加壳/水印节的识别。"""
    for s in pe.sections:
        if s.name.lower() in CUSTOM_SECTION_NAMES:
            return s
    return None


def info_report(pe: PeFile) -> dict:
    if not pe.is_pe:
        return {"file": pe.path, "is_pe": False, "error": pe.error}
    custom = find_custom_section(pe)
    ep_sec = section_of_rva(pe, pe.entry_rva)
    out = []
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
            "rawptr": s.raw_address,
            "flags": flags,
            "entropy": round(_ent(seg), 3),
            "is_custom": bool(custom is not None and s is custom),
            "is_entry": bool(ep_sec is not None and s is ep_sec),
        })
    return {
        "file": pe.path,
        "is_pe": True,
        "image_base": pe.image_base,
        "entry_rva": pe.entry_rva,
        "entry_off": pe.entry_off,
        "size_of_image": pe.size_of_image,
        "subsystem": pe.subsystem,
        "is64": pe.is64,
        "machine": "x64" if pe.is64 else "x86",
        "custom_section": custom.name if custom else None,
        "entry_section": ep_sec.name if ep_sec else None,
        "sections": out,
    }


# ===================== dump: run-and-dump (对应 sub_422C90/423757/422F88) =====================
def _find_pid_by_name(name: str) -> int:
    """对应 sub_41B710: CreateToolhelp32Snapshot + Process32First/Next 按名查 PID。"""
    import ctypes
    from ctypes import wintypes

    TH32CS_SNAPPROCESS = 0x2

    class PROCESSENTRY32(ctypes.Structure):
        _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                    ("th32ProcessID", wintypes.DWORD),
                    ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                    ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                    ("th32ParentProcessID", wintypes.DWORD),
                    ("pcPriClassBase", ctypes.c_long), ("dwFlags", wintypes.DWORD),
                    ("szExeFile", ctypes.c_char * 260)]

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == wintypes.HANDLE(-1).value or snap == -1:
        return 0
    try:
        pe = PROCESSENTRY32()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32)
        ok = k32.Process32First(snap, ctypes.byref(pe))
        target = name.lower()
        while ok:
            exe = pe.szExeFile.decode("ascii", "replace")
            if exe.lower() == target:
                return pe.th32ProcessID
            ok = k32.Process32Next(snap, ctypes.byref(pe))
        return 0
    finally:
        k32.CloseHandle(snap)


def run_and_dump(src_path: str, out_path: str, wait_ms: int = 1500,
                 region_dir: Optional[str] = None) -> dict:
    """Windows run-and-dump 整镜像转储。

    忠实复刻:
      sub_41B710  按名/直接启动定位进程
      sub_423757  OpenProcess(0x1F0FFF) + VirtualProtectEx + ReadProcessMemory
      sub_422F88  CreateFileA + WriteFile 落盘原始镜像
    以挂起方式启动被壳程序, 让壳在内存中解压真实代码, 等待片刻后读取整个
    镜像 (SizeOfImage) 并写出。仅在 Windows 下可用。
    """
    if os.name != "nt":
        return {"ok": False,
                "error": "run-and-dump 仅在 Windows 下可用; 请用 info 做静态分析"}
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    k32.CreateProcessW.restype = wintypes.BOOL
    k32.ReadProcessMemory.restype = wintypes.BOOL
    k32.WriteFile.restype = wintypes.BOOL
    k32.VirtualQueryEx.restype = ctypes.c_size_t

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

    class MEMORY_BASIC_INFORMATION32(ctypes.Structure):
        _fields_ = [("BaseAddress", wintypes.DWORD), ("AllocationBase", wintypes.DWORD),
                    ("AllocationProtect", wintypes.DWORD), ("RegionSize", wintypes.DWORD),
                    ("State", wintypes.DWORD), ("Protect", wintypes.DWORD),
                    ("Type", wintypes.DWORD)]

    CREATE_SUSPENDED = 0x4
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
        # 等待壳解压 (原工具依赖固定延时/进度, 对应 wait)
        k32.WaitForSingleObject(pi.hProcess, wait_ms)
        k32.SuspendThread(pi.hThread)

        with open(src_path, "rb") as fh:
            data = fh.read()
        pe = parse_pe(data, src_path)
        size = pe.size_of_image or 0x1000
        base = pe.image_base

        # 让目标镜像可写 (对应 sub_423757 的 VirtualProtectEx)
        old = wintypes.DWORD(0)
        k32.VirtualProtectEx(pi.hProcess, ctypes.c_void_p(base),
                             ctypes.c_size_t(size), 0x40, ctypes.byref(old))

        # 整块读取 (对应 sub_423757 ReadProcessMemory)
        buf = ctypes.create_string_buffer(size)
        read = ctypes.c_size_t(0)
        got = k32.ReadProcessMemory(pi.hProcess, ctypes.c_void_p(base), buf,
                                    ctypes.c_size_t(size), ctypes.byref(read))
        if not got or read.value == 0:
            return {"ok": False,
                    "error": "ReadProcessMemory failed %d" % ctypes.get_last_error()}

        # 落盘原始镜像 (对应 sub_422F88 WriteFile)
        with open(out_path, "wb") as fh:
            fh.write(buf.raw[:read.value])

        # 可选: 区段遍历转储 (对应 sub_41A7BF + sub_41AA68)
        regions = []
        if region_dir:
            regions = _dump_regions(k32, pi.hProcess, MEMORY_BASIC_INFORMATION32,
                                    region_dir)
        return {"ok": True, "out": out_path, "pid": pi.dwProcessId,
                "image_base": base, "size_of_image": size,
                "dumped_bytes": read.value, "regions": regions}
    finally:
        k32.TerminateProcess(pi.hProcess, 0)
        k32.CloseHandle(pi.hThread)
        k32.CloseHandle(pi.hProcess)


def _dump_regions(k32, h_process, MBI32, region_dir: str) -> List[dict]:
    """对应 sub_41A7BF: 从地址 0 起 VirtualQueryEx 遍历, 转储 MEM_PRIVATE/
    MEM_COMMIT 区段到 region/region%08x.ron (sub_41AA68)。"""
    import ctypes
    from ctypes import wintypes
    os.makedirs(region_dir, exist_ok=True)
    out = []
    addr = 0
    mbi = MBI32()
    while addr < 0x7FFFFFFF:
        res = k32.VirtualQueryEx(h_process, ctypes.c_void_p(addr),
                                 ctypes.byref(mbi), ctypes.sizeof(mbi))
        if res != ctypes.sizeof(mbi):
            break
        base = mbi.BaseAddress
        rsize = mbi.RegionSize
        # MEM_PRIVATE(0x20000) 且 MEM_COMMIT(0x1000) -> 转储
        if mbi.Type == 0x20000 and mbi.State == 0x1000 and rsize > 0:
            gbuf = ctypes.create_string_buffer(rsize)
            rd = ctypes.c_size_t(0)
            if k32.ReadProcessMemory(h_process, ctypes.c_void_p(base), gbuf,
                                     ctypes.c_size_t(rsize), ctypes.byref(rd)) and rd.value:
                name = "region%08x.ron" % base
                with open(os.path.join(region_dir, name), "wb") as fh:
                    fh.write(gbuf.raw[:rd.value])
                out.append({"base": base, "size": rd.value, "file": name})
        nxt = base + rsize
        if nxt <= addr:
            break
        addr = nxt
    return out


# ===================== 输出格式 =====================
def fmt_info(r: dict, as_json: bool) -> str:
    if as_json:
        return json.dumps(r, ensure_ascii=False, indent=2)
    if not r.get("is_pe"):
        return "[!] %s: %s" % (r["file"], r.get("error"))
    lines = ["File: %s" % r["file"],
             "ImageBase: 0x%08X  EntryRVA: 0x%08X  SizeOfImage: 0x%X  (%s)" % (
                 r["image_base"], r["entry_rva"], r["size_of_image"], r["machine"]),
             "Entry section: %s   Custom section: %s" % (
                 r["entry_section"] or "(none)", r["custom_section"] or "(none)"),
             "%-10s %-10s %-10s %-10s %-10s %-6s %-8s %s" % (
                 "Name", "VA", "VSize", "RawSize", "RawPtr", "Flags", "Entropy", "Note")]
    for s in r["sections"]:
        note = []
        if s["is_custom"]:
            note.append("<== custom")
        if s["is_entry"]:
            note.append("<== entry")
        lines.append("%-10s 0x%08X 0x%08X 0x%08X 0x%08X %-6s %-8.3f %s" % (
            s["name"], s["va"], s["vsize"], s["rawsize"], s["rawptr"],
            s["flags"], s["entropy"], " ".join(note)))
    lines.append("==> sections: %d" % len(r["sections"]))
    return "\n".join(lines)


USAGE = __doc__


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="main.py", add_help=False)
    p.add_argument("target", nargs="?")
    p.add_argument("cmd", nargs="?", default="info", choices=["info", "dump"])
    p.add_argument("--json", action="store_true")
    p.add_argument("--wait", type=int, default=1500,
                   help="dump: 等待壳解压的毫秒数 (默认 1500)")
    p.add_argument("--regions", action="store_true",
                   help="dump: 同时做区段遍历转储到 <name>.regions/")
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
    if a.cmd == "info":
        print(fmt_info(info_report(pe), a.json))
        return EXIT_SUCCESS if pe.is_pe else EXIT_FAILURE
    if a.cmd == "dump":
        out = os.path.splitext(a.target)[0] + ".dumped.exe"
        region_dir = (os.path.splitext(a.target)[0] + ".regions") if a.regions else None
        r = run_and_dump(a.target, out, wait_ms=a.wait, region_dir=region_dir)
        if a.json:
            print(json.dumps(r, ensure_ascii=False, indent=2))
        elif r.get("ok"):
            print("[+] dumped %d bytes -> %s (pid=%d, base=0x%08X, size=0x%X)" % (
                r["dumped_bytes"], r["out"], r["pid"], r["image_base"],
                r["size_of_image"]))
            if region_dir and r.get("regions") is not None:
                print("[+] regions dumped: %d -> %s" % (len(r["regions"]), region_dir))
        else:
            print("[!] %s" % r.get("error"))
        return EXIT_SUCCESS if r.get("ok") else EXIT_FAILURE
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())