#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Advanced Loader Generator 1.50 (汉化版)  —— 纯 Python 3 复刻 (CLI 版, 仅标准库)
================================================================================

源程序 (逆向目标):
    D:\\Program Files\\crack-tool-patcher\\AdvancedLoaderGenerator_1.50_汉化版\\
        AdvancedLoaderGenerator1.50汉化版.exe        (x86, 218624 字节)

本文件 (目标程序 / 唯一入口):
    D:\\src\\crack-tool-py\\advancedloadergenerator_py\\main.py

--------------------------------------------------------------------------------
一、逆向来源: ASPack 壳 stub 的静态证据
--------------------------------------------------------------------------------
源 EXE 是 "Advanced Loader Generator 1.50 (汉化版)" —— 一个用来 *生成* 小型
Loader / 补丁加载器的 GUI 工具 (即 "patcher → loader builder")。它本身被 ASPack
压缩, 真正的程序逻辑在运行时才解压到内存, 磁盘文件里只剩下 ASPack 解壳 stub。

静态 (IDA, /d/temp/ida_out/t02.exe.asm) 只能读到 stub 的痕迹, 用于证明身份/能力:

  * PE 头: ImageBase = 0x400000, TimeDateStamp = 0x4011B0BE (2004-01-23),
            PE32 (0x10B), 2 个节区, 节名均为 ".ASPack":
                .ASPack  VA 0x00001000  VSize 0x0010B000  Raw 0x0      (bss/解压目标)
                .ASPack  VA 0x0010C000  VSize 0x00035341  Raw 0x200    (stub 代码)
  * 导入表 (仅 kernel32.dll, 其余 API 全部 GetProcAddress 动态解析):
                LoadLibraryA   GetProcAddress   VirtualAlloc
                VirtualProtect VirtualFree      GetModuleHandleA
    这四个内存类 API (VirtualAlloc/Protect/Free) 正是 "内存补丁 / 反调试 / 解码"
    的典型 stub 依赖; 真正业务用的 CreateProcess / WriteProcessMemory /
    RegSetValueEx / MessageBox 等在壳解开后才通过 GetProcAddress 取得。
  * 可读字符串 (UTF-16LE): "LOADER" (见 asm: aAInstaller / 'LOADER'),
            "DATA", "INSTALLER" —— 与 "生成 Loader" 的用途一致 (stub 里也残留
            "A\\tINSTALLER" 之类的早期 Installer 变体名)。
  * 动态字符串表: 'GetModuleHandleA' 'LoadLibraryA' 'GetProcAddress'
            'VirtualAlloc' 'VirtualFree' 'VirtualProtect' —— 供 stub 自行 API 解析。

--------------------------------------------------------------------------------
二、被复刻程序的 "生成器" 特性集 (LAG / Advanced Loader 家族通识)
--------------------------------------------------------------------------------
这类工具产出的 Loader 在被双击运行时, 依次做:
  1. 可选地弹出 关于/启动 Splash 提示 (splash text);
  2. 定位目标 EXE (按文件名), 可选 *等待* 目标进程出现 (wait);
  3. 解析目标 PE 的节表, 把 {文件偏移 offset | 绝对地址 VA | 相对地址 RVA}
     换算成运行期真实地址 (模块基址 + RVA, 自动适配 ASLR);
  4. 用 WriteProcessMemory 打内存补丁 (字节替换), 或对磁盘文件做静态补丁;
  5. 可选做 注册表补丁 (registry patches);
  6. 启动 / 放行 目标进程。

本复刻把上述特性拆成 3 个子命令 (stdlib 实现, 无 GUI):

    generate --target <name.exe> --patch <spec.json> -o loader.py
        生成一个 *自包含* 的 Python Loader 脚本 (内嵌配置 + 节表 + ctypes
        运行期 WriteProcessMemory 补丁器, 并对模块基址做解析/ASLR 修正),
        同时写出同名 .json 配置副本。Loader 也自带 --static 静态文件补丁回退。

    applyfile <target.exe> <spec.json> [-o out]
        静态补丁: 读目标 PE, 用节表把 VA/RVA 换算成文件偏移 (offset 直用),
        写出打好补丁的副本 (默认 <target>.patched.exe)。

    info <pe>
        打印 PE 节区表与 VA / RVA / 文件偏移 的映射, 以及若干换算示例。

spec.json 结构 (三种 patch 二选一类型皆可混用):
    {
      "patches": [
        {"type": "offset", "addr": "0x1234", "bytes": "90 90"},
        {"type": "rva",    "addr": "0x1A2B", "bytes": "EB 0E"},
        {"type": "va",     "addr": "0x401000", "bytes": "C3"}
      ],
      "registry": [
        {"path": "HKCU\\\\Software\\\\Demo", "name": "Reg", "type": "REG_DWORD", "data": 1}
      ],
      "wait": true,
      "splash": "Advanced Loader"
    }

特性 → 子命令 映射:
    offset/va/rva 字节补丁 ............ generate (内存) + applyfile (静态)
    模块基址解析 / ASLR 修正 .......... generate 产出的 Loader (ctypes)
    静态文件补丁回退 .................. applyfile + Loader 的 --static
    注册表补丁 ........................ generate 产出的 Loader (winreg)
    等待目标进程 / 启动目标 ........... generate 产出的 Loader
    Splash / 关于提示 ................. generate 产出的 Loader (MessageBoxW)
    PE 节表 / 地址换算 ................ info + applyfile 内部换算

--------------------------------------------------------------------------------
三、加壳 stub 的静态局限 (诚实声明)
--------------------------------------------------------------------------------
源 EXE 为 ASPack 压缩, 本复刻 *不* 反编译壳内业务逻辑 (那需要脱壳 DUMP 后重建),
而是基于 (a) stub 的导入/字符串/节区证据, (b) "Advanced Loader Generator / LAG
家族" 的公开特性集, 重建其 *核心行为契约*: 把一个 patch spec 编译成可运行的
Loader, 提供 内存补丁 + 静态补丁 + 地址换算 + 注册表/等待/Splash。GUI 外壳、
图标注入、资源节拼接等展示层细节不在本 CLI 复刻范围内。

运行环境: Windows (ctypes/winreg); 纯解析子命令 (info) 跨平台。
"""

import argparse
import json
import os
import struct
import sys
import re

__version__ = "1.50-py"

EXIT_OK = 0
EXIT_ERR = 1

IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000


# =============================================================================
# 一、PE 解析器 (节表 + VA/RVA/文件偏移 双向换算)
# =============================================================================
class Section:
    __slots__ = ("name", "vaddr", "vsize", "raw_off", "raw_size", "chars")

    def __init__(self, name, vaddr, vsize, raw_off, raw_size, chars):
        self.name = name
        self.vaddr = vaddr            # RVA of section start
        self.vsize = vsize            # virtual size
        self.raw_off = raw_off        # file offset of raw data
        self.raw_size = raw_size      # raw size in file
        self.chars = chars

    @property
    def span(self):
        # 映射时用 max(vsize, raw_size) 更稳妥
        return max(self.vsize, self.raw_size)

    def flags(self):
        f = []
        if self.chars & IMAGE_SCN_MEM_EXECUTE:
            f.append("X")
        if self.chars & IMAGE_SCN_MEM_READ:
            f.append("R")
        if self.chars & IMAGE_SCN_MEM_WRITE:
            f.append("W")
        return "".join(f) or "-"

    def __repr__(self):
        return "<Section %s va=%#x off=%#x>" % (self.name, self.vaddr, self.raw_off)


class PE:
    def __init__(self, data, path="<mem>"):
        self.data = data
        self.path = path
        self.ok = False
        self.is_pe32plus = False
        self.image_base = 0
        self.entry_point = 0
        self.size_of_image = 0
        self.section_align = 0
        self.file_align = 0
        self.num_sections = 0
        self.sections = []
        self._parse()

    def _u16(self, off):
        return struct.unpack_from("<H", self.data, off)[0]

    def _u32(self, off):
        return struct.unpack_from("<I", self.data, off)[0]

    def _parse(self):
        d = self.data
        if len(d) < 0x40 or d[:2] != b"MZ":
            return
        e_lfanew = self._u32(0x3C)
        if e_lfanew + 24 > len(d) or d[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            return
        coff = e_lfanew + 4
        self.num_sections = self._u16(coff + 2)
        opt_size = self._u16(coff + 16)
        opt = coff + 20
        if opt + 2 > len(d):
            return
        magic = self._u16(opt)
        if magic == 0x10B:            # PE32
            self.is_pe32plus = False
            self.image_base = self._u32(opt + 28)
            self.section_align = self._u32(opt + 32)
            self.file_align = self._u32(opt + 36)
            self.size_of_image = self._u32(opt + 56)
            self.entry_point = self._u32(opt + 16)
            dd_off = opt + 96
        elif magic == 0x20B:          # PE32+
            self.is_pe32plus = True
            self.image_base = struct.unpack_from("<Q", d, opt + 24)[0]
            self.section_align = self._u32(opt + 32)
            self.file_align = self._u32(opt + 36)
            self.size_of_image = self._u32(opt + 56)
            self.entry_point = self._u32(opt + 16)
            dd_off = opt + 112
        else:
            return

        sec_off = opt + opt_size
        for i in range(self.num_sections):
            o = sec_off + i * 40
            if o + 40 > len(d):
                break
            raw = d[o:o + 8]
            name = raw.rstrip(b"\x00").decode("latin-1", "replace")
            vsize, vaddr, raw_size, raw_off = struct.unpack_from("<IIII", d, o + 8)
            chars = self._u32(o + 36)
            self.sections.append(Section(name, vaddr, vsize, raw_off, raw_size, chars))
        self.ok = True

    # ---- 地址换算 ----------------------------------------------------------
    def rva_to_offset(self, rva):
        # 落在节区头 (headers) 内: RVA 即文件偏移
        for s in self.sections:
            if s.vaddr <= rva < s.vaddr + s.span:
                if s.raw_size == 0:
                    # 无原始数据的节 (如 .bss / 壳解压区), 无法定位文件偏移
                    return None
                delta = rva - s.vaddr
                if delta >= s.raw_size:
                    return None
                return s.raw_off + delta
        if 0 <= rva < (self.sections[0].vaddr if self.sections else 0x1000):
            return rva
        return None

    def offset_to_rva(self, off):
        for s in self.sections:
            if s.raw_size and s.raw_off <= off < s.raw_off + s.raw_size:
                return s.vaddr + (off - s.raw_off)
        # 头部
        if 0 <= off < (self.sections[0].raw_off if self.sections else 0x400):
            return off
        return None

    def va_to_offset(self, va):
        return self.rva_to_offset(va - self.image_base)

    def offset_to_va(self, off):
        rva = self.offset_to_rva(off)
        return None if rva is None else self.image_base + rva

    def find_section(self, rva):
        for s in self.sections:
            if s.vaddr <= rva < s.vaddr + s.span:
                return s
        return None


def load_pe(path):
    with open(path, "rb") as f:
        data = f.read()
    return PE(data, path)


# =============================================================================
# 二、spec 解析 (地址 / 字节串 / 归一化)
# =============================================================================
def parse_addr(v):
    """接受 int / 十进制字符串 / '0x..' / '401000h' / '0X..'。"""
    if isinstance(v, int):
        return v
    s = str(v).strip()
    if not s:
        raise ValueError("empty address")
    if s.lower().endswith("h"):
        return int(s[:-1], 16)
    return int(s, 0)


def parse_hex_bytes(s):
    """接受 '90 90'、'909090'、'0x90,0x90'、'\\\\x90\\\\x90'、int 列表、bytes。"""
    if isinstance(s, (bytes, bytearray)):
        return bytes(s)
    if isinstance(s, (list, tuple)):
        return bytes(int(x) for x in s)
    t = str(s)
    t = re.sub(r"0x", "", t, flags=re.I)
    t = re.sub(r"\\x", "", t, flags=re.I)
    t = re.sub(r"[\s,;:_\-]", "", t)
    if not t:
        return b""
    if len(t) % 2:
        raise ValueError("odd number of hex digits in bytes: %r" % s)
    return bytes.fromhex(t)


def normalize_spec(spec):
    """把 spec 归一化为 {patches:[{type,addr:int,data:bytes}], registry, wait, splash}。"""
    if not isinstance(spec, dict):
        raise ValueError("spec must be a JSON object")
    patches = []
    for i, p in enumerate(spec.get("patches", []) or []):
        if not isinstance(p, dict):
            raise ValueError("patch[%d] must be object" % i)
        ptype = str(p.get("type", "offset")).lower()
        if ptype not in ("offset", "va", "rva"):
            raise ValueError("patch[%d] bad type %r (offset|va|rva)" % (i, ptype))
        if "addr" not in p:
            raise ValueError("patch[%d] missing 'addr'" % i)
        addr = parse_addr(p["addr"])
        raw_bytes = p.get("bytes", p.get("data", ""))
        data = parse_hex_bytes(raw_bytes)
        if not data:
            raise ValueError("patch[%d] empty bytes" % i)
        patches.append({"type": ptype, "addr": addr, "data": data})

    registry = []
    for i, r in enumerate(spec.get("registry", []) or []):
        if not isinstance(r, dict) or "path" not in r:
            raise ValueError("registry[%d] needs 'path'" % i)
        registry.append({
            "path": str(r["path"]),
            "name": str(r.get("name", "")),
            "type": str(r.get("type", "REG_SZ")).upper(),
            "data": r.get("data", ""),
        })

    return {
        "patches": patches,
        "registry": registry,
        "wait": bool(spec.get("wait", False)),
        "splash": str(spec.get("splash", "")),
    }


def load_spec(path):
    with open(path, "r", encoding="utf-8") as f:
        return normalize_spec(json.load(f))


def patch_file_offset(pe, patch):
    """把一条 patch 换算成目标文件偏移 (失败返回 None)。"""
    t = patch["type"]
    a = patch["addr"]
    if t == "offset":
        return a
    if t == "rva":
        return pe.rva_to_offset(a)
    if t == "va":
        return pe.va_to_offset(a)
    return None


# =============================================================================
# 三、静态补丁 (applyfile)
# =============================================================================
def apply_file_patch(target, spec, out=None):
    pe = load_pe(target)
    if not pe.ok:
        raise ValueError("not a valid PE: %s" % target)
    buf = bytearray(pe.data)
    report = []
    changed = 0
    for i, p in enumerate(spec["patches"]):
        off = patch_file_offset(pe, p)
        data = p["data"]
        if off is None:
            report.append({"i": i, "type": p["type"], "addr": p["addr"],
                           "ok": False, "err": "cannot map to file offset"})
            continue
        if off < 0 or off + len(data) > len(buf):
            report.append({"i": i, "type": p["type"], "addr": p["addr"],
                           "off": off, "ok": False, "err": "out of file bounds"})
            continue
        original = bytes(buf[off:off + len(data)])
        buf[off:off + len(data)] = data
        changed += 1
        report.append({"i": i, "type": p["type"], "addr": p["addr"], "off": off,
                       "ok": True, "before": original.hex(), "after": data.hex()})

    if out is None:
        base, ext = os.path.splitext(target)
        out = base + ".patched" + (ext or ".exe")
    with open(out, "wb") as f:
        f.write(buf)
    return {"target": target, "output": out, "applied": changed,
            "total": len(spec["patches"]), "patches": report}


# =============================================================================
# 四、生成 Loader (自包含 Python 脚本)
# =============================================================================
LOADER_TEMPLATE = r'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Generated Loader by Advanced Loader Generator (Py replica)

Target     : @@TARGET_NAME@@
Patches    : @@N_PATCHES@@ (offset/va/rva)
Registry   : @@N_REG@@
Wait       : @@WAIT@@
Splash     : @@SPLASH_SHORT@@

Runtime: locate/launch target, resolve module base (ASLR-aware), apply
in-memory byte patches via WriteProcessMemory. Static file-patch fallback
via --static OUT. Stdlib + ctypes/winreg only.

Usage:
    python loader.py               # normal: launch/wait, patch memory
    python loader.py --pid 1234    # patch an already-running pid
    python loader.py --static out.exe   # patch the file on disk instead
    python loader.py --dry-run     # show resolved addresses, do not write
"""
import sys, os, json, time, ctypes
from ctypes import wintypes

CONFIG = @@CONFIG@@

PREFERRED_BASE = @@IMAGE_BASE@@
# [name, rva, vsize, raw_off, raw_size]
SECTIONS = @@SECTIONS@@

# ---------------------------------------------------------------------------
def off_to_rva(off):
    for name, va, vs, ro, rs in SECTIONS:
        if rs and ro <= off < ro + rs:
            return va + (off - ro)
    return off  # headers

def patch_to_rva(p):
    t = p["type"]; a = p["addr"]
    if t == "rva":
        return a
    if t == "va":
        return a - PREFERRED_BASE
    if t == "offset":
        return off_to_rva(a)
    return None

# ---------------------------------------------------------------------------
class PROCESSENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD), ("th32DefaultHeapID", ctypes.c_void_p),
                ("th32ModuleID", wintypes.DWORD), ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD), ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD), ("szExeFile", ctypes.c_char * 260)]

class MODULEENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD), ("th32ModuleID", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD), ("GlblcntUsage", wintypes.DWORD),
                ("ProccntUsage", wintypes.DWORD), ("modBaseAddr", ctypes.c_void_p),
                ("modBaseSize", wintypes.DWORD), ("hModule", ctypes.c_void_p),
                ("szModule", ctypes.c_char * 256), ("szExePath", ctypes.c_char * 260)]

k32 = ctypes.windll.kernel32
TH32CS_SNAPPROCESS = 0x2
TH32CS_SNAPMODULE = 0x8 | 0x10
INVALID_HANDLE = ctypes.c_void_p(-1).value

def _snap(flags, pid=0):
    h = k32.CreateToolhelp32Snapshot(flags, pid)
    return None if h in (INVALID_HANDLE, 0, None) else h

def find_pid(exe_name):
    h = _snap(TH32CS_SNAPPROCESS)
    if not h:
        return None
    try:
        e = PROCESSENTRY32(); e.dwSize = ctypes.sizeof(e)
        if not k32.Process32First(h, ctypes.byref(e)):
            return None
        while True:
            if e.szExeFile.decode("latin-1", "replace").lower() == exe_name.lower():
                return e.th32ProcessID
            if not k32.Process32Next(h, ctypes.byref(e)):
                return None
    finally:
        k32.CloseHandle(h)

def module_base(pid, exe_name):
    h = _snap(TH32CS_SNAPMODULE, pid)
    if not h:
        return None
    try:
        m = MODULEENTRY32(); m.dwSize = ctypes.sizeof(m)
        if not k32.Module32First(h, ctypes.byref(m)):
            return None
        first = None
        while True:
            nm = m.szModule.decode("latin-1", "replace")
            if first is None:
                first = ctypes.cast(m.modBaseAddr, ctypes.c_void_p).value
            if nm.lower() == exe_name.lower():
                return ctypes.cast(m.modBaseAddr, ctypes.c_void_p).value
            if not k32.Module32Next(h, ctypes.byref(m)):
                return first  # fall back to main module
    finally:
        k32.CloseHandle(h)

def write_mem(pid, addr, data):
    PROCESS_ALL = 0x0008 | 0x0010 | 0x0020 | 0x0400   # VM_OP|VM_WRITE|VM_READ|QUERY
    h = k32.OpenProcess(PROCESS_ALL, False, pid)
    if not h:
        raise OSError("OpenProcess(%d) failed: %d" % (pid, ctypes.get_last_error() or k32.GetLastError()))
    try:
        PAGE_EXECUTE_READWRITE = 0x40
        old = wintypes.DWORD(0)
        size = len(data)
        k32.VirtualProtectEx(h, ctypes.c_void_p(addr), size,
                             PAGE_EXECUTE_READWRITE, ctypes.byref(old))
        written = ctypes.c_size_t(0)
        buf = ctypes.create_string_buffer(data, size)
        ok = k32.WriteProcessMemory(h, ctypes.c_void_p(addr), buf, size,
                                    ctypes.byref(written))
        k32.VirtualProtectEx(h, ctypes.c_void_p(addr), size, old.value,
                             ctypes.byref(wintypes.DWORD(0)))
        if not ok:
            raise OSError("WriteProcessMemory@%#x failed: %d" % (addr, ctypes.get_last_error() or k32.GetLastError()))
        return written.value
    finally:
        k32.CloseHandle(h)

def apply_registry():
    if not CONFIG.get("registry"):
        return
    try:
        import winreg
    except Exception as e:
        print("[!] registry patches skipped (winreg): %s" % e); return
    TYPE = {"REG_SZ": winreg.REG_SZ, "REG_DWORD": winreg.REG_DWORD,
            "REG_BINARY": winreg.REG_BINARY, "REG_EXPAND_SZ": winreg.REG_EXPAND_SZ}
    for r in CONFIG["registry"]:
        path, name = r["path"], r.get("name", "")
        hive_map = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
        root_s, _, sub = path.partition("\\")
        hive = hive_map.get(root_s.upper().replace("HKEY_CURRENT_USER", "HKCU")
                            .replace("HKEY_LOCAL_MACHINE", "HKLM"), winreg.HKEY_CURRENT_USER)
        val = r.get("data", "")
        vt = TYPE.get(r.get("type", "REG_SZ").upper(), winreg.REG_SZ)
        try:
            k = winreg.CreateKeyEx(hive, sub, 0, winreg.KEY_SET_VALUE)
            if vt == winreg.REG_DWORD:
                val = int(val, 0) if not isinstance(val, int) else val
            elif vt == winreg.REG_BINARY:
                if isinstance(val, str):
                    val = bytes.fromhex(val.replace(" ", ""))
            winreg.SetValueEx(k, name, 0, vt, val)
            winreg.CloseKey(k)
            print("[+] REG %s\\%s = %r" % (path, name, val))
        except Exception as e:
            print("[!] REG %s\\%s failed: %s" % (path, name, e))

def splash():
    txt = CONFIG.get("splash") or ""
    if not txt:
        return
    try:
        ctypes.windll.user32.MessageBoxW(0, txt, "@@TARGET_NAME@@", 0x40)
    except Exception:
        print("[splash] %s" % txt)

def launch(exe_path):
    si = ctypes.create_string_buffer(104)
    pi = ctypes.create_string_buffer(24)
    cmd = ctypes.create_unicode_buffer('"%s"' % exe_path)
    ok = ctypes.windll.kernel32.CreateProcessW(
        None, cmd, None, None, False, 0, None,
        os.path.dirname(exe_path) or None,
        ctypes.byref(si), ctypes.byref(pi))
    return bool(ok)

def local_target():
    here = os.path.dirname(os.path.abspath(__file__))
    p = os.path.join(here, CONFIG["target"])
    if os.path.exists(p):
        return p
    return CONFIG["target"]

def do_static(out_path):
    tgt = local_target()
    if not os.path.exists(tgt):
        print("[!] static: target not found: %s" % tgt); return 1
    with open(tgt, "rb") as f:
        buf = bytearray(f.read())
    n = 0
    for p in CONFIG["patches"]:
        rva = patch_to_rva(p)
        off = p["addr"] if p["type"] == "offset" else off_from_rva(rva)
        if off is None or off + len(p["bytes"]) > len(buf):
            print("[!] static patch off=%r skipped" % off); continue
        data = bytes.fromhex(p["bytes"])
        buf[off:off + len(data)] = data
        n += 1
        print("[+] static off=%#x <- %s" % (off, p["bytes"]))
    with open(out_path, "wb") as f:
        f.write(buf)
    print("[+] wrote %s (%d patches)" % (out_path, n))
    return 0

def off_from_rva(rva):
    for name, va, vs, ro, rs in SECTIONS:
        if va <= rva < va + max(vs, rs) and rs:
            return ro + (rva - va)
    return rva

def main(argv):
    args = list(argv[1:])
    dry = "--dry-run" in args
    pid_arg = None; static_out = None
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--pid" and i + 1 < len(args):
            pid_arg = int(args[i + 1]); i += 2; continue
        if a == "--static" and i + 1 < len(args):
            static_out = args[i + 1]; i += 2; continue
        i += 1

    if static_out:
        return do_static(static_out)

    splash(); apply_registry()

    target = CONFIG["target"]
    exe_path = local_target()
    pid = pid_arg or find_pid(target)
    launched = False
    if pid is None:
        if not os.path.exists(exe_path):
            print("[!] target not found: %s" % exe_path); return 1
        if not dry:
            print("[*] launching %s" % exe_path)
            launch(exe_path); launched = True
        budget = 15.0 if CONFIG.get("wait", True) else 5.0
        t0 = time.time()
        while pid is None and time.time() - t0 < budget:
            pid = find_pid(target); time.sleep(0.2)
        if pid is None:
            print("[!] target process not found (wait=%s)" % CONFIG.get("wait")); return 1

    base = module_base(pid, target)
    if base is None:
        print("[!] cannot resolve module base for pid %d" % pid); return 1
    delta = base - PREFERRED_BASE
    print("[*] pid=%d base=%#x delta=%#x" % (pid, base, delta))

    for p in CONFIG["patches"]:
        rva = patch_to_rva(p)
        addr = base + rva if rva is not None else None
        data = bytes.fromhex(p["bytes"])
        if addr is None:
            print("[!] unresolved patch %r skipped" % p); continue
        try:
            if dry:
                print("[dry] %#x <- %s" % (addr, p["bytes"]))
            else:
                n = write_mem(pid, addr, data)
                print("[+] mem %#x <- %s (%d bytes)" % (addr, p["bytes"], n))
        except Exception as e:
            print("[!] mem patch %#x failed: %s" % (addr, e))

    print("[+] done.")
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))
'''


def _q(s):
    """JSON-quote a python string for embedding."""
    return json.dumps(s, ensure_ascii=False)


def generate_loader(target, spec, out):
    pe = load_pe(target)
    if not pe.ok:
        raise ValueError("target is not a valid PE (need section table): %s" % target)
    target_name = os.path.basename(target)

    # 把归一化 patch 转成 loader 需要的 hex 串形式
    cfg_patches = [{"type": p["type"], "addr": p["addr"], "bytes": p["data"].hex()}
                   for p in spec["patches"]]
    config = {
        "target": target_name,
        "patches": cfg_patches,
        "registry": spec["registry"],
        "wait": spec["wait"],
        "splash": spec["splash"],
    }
    sections = [[s.name, s.vaddr, s.vsize, s.raw_off, s.raw_size] for s in pe.sections]

    txt = LOADER_TEMPLATE
    txt = txt.replace("@@TARGET_NAME@@", target_name)
    # 用 repr 嵌入 (JSON 的 true/false 不是合法 Python 字面量)
    txt = txt.replace("@@CONFIG@@", repr(config))
    txt = txt.replace("@@IMAGE_BASE@@", hex(pe.image_base))
    txt = txt.replace("@@SECTIONS@@", repr(sections))
    txt = txt.replace("@@N_PATCHES@@", str(len(cfg_patches)))
    txt = txt.replace("@@N_REG@@", str(len(spec["registry"])))
    txt = txt.replace("@@WAIT@@", str(spec["wait"]))
    txt = txt.replace("@@SPLASH_SHORT@@", (spec["splash"] or "-")[:40])

    with open(out, "w", encoding="utf-8") as f:
        f.write(txt)
    # 同名配置副本
    cfg_path = os.path.splitext(out)[0] + ".config.json"
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)

    # 语法自检 (compile)
    compile(txt, out, "exec")
    return {"loader": out, "config": cfg_path, "target": target_name,
            "patches": len(cfg_patches), "registry": len(spec["registry"]),
            "image_base": hex(pe.image_base)}


# =============================================================================
# 五、info
# =============================================================================
def build_info(pe):
    info = {
        "path": pe.path,
        "valid": pe.ok,
        "format": "PE32+" if pe.is_pe32plus else "PE32",
        "image_base": pe.image_base,
        "entry_point_rva": pe.entry_point,
        "entry_point_va": pe.image_base + pe.entry_point,
        "section_alignment": pe.section_align,
        "file_alignment": pe.file_align,
        "size_of_image": pe.size_of_image,
        "num_sections": pe.num_sections,
        "sections": [],
    }
    for s in pe.sections:
        info["sections"].append({
            "name": s.name,
            "rva": s.vaddr,
            "va": pe.image_base + s.vaddr,
            "vsize": s.vsize,
            "raw_off": s.raw_off,
            "raw_size": s.raw_size,
            "flags": s.flags(),
            "rva_range": [s.vaddr, s.vaddr + s.span],
            "file_range": [s.raw_off, s.raw_off + s.raw_size],
        })
    return info


def text_info(info):
    out = []
    out.append("PE info : %s" % info["path"])
    out.append("  format      : %s" % info["format"])
    out.append("  image base  : %#010x" % info["image_base"])
    out.append("  entry (RVA) : %#x  -> VA %#x" % (info["entry_point_rva"], info["entry_point_va"]))
    out.append("  align       : section=%#x file=%#x" % (info["section_alignment"], info["file_alignment"]))
    out.append("  size image  : %#x   sections=%d" % (info["size_of_image"], info["num_sections"]))
    out.append("")
    out.append("  %-10s %-10s %-10s %-10s %-10s %-6s  %s" %
               ("NAME", "VA", "RVA", "VSIZE", "RAW_OFF/RawSz", "FLAGS", "RVA->Off"))
    for s in info["sections"]:
        out.append("  %-10s %#-9x %#-9x %#-9x %#x/%-8x %-6s  %#x..%#x -> %#x..%#x" % (
            s["name"], s["va"], s["rva"], s["vsize"], s["raw_off"], s["raw_size"],
            s["flags"], s["rva_range"][0], s["rva_range"][1],
            s["file_range"][0], s["file_range"][1]))
    # 换算示例: 每个节区首地址
    out.append("")
    out.append("  conversion samples (VA <-> RVA <-> file offset):")
    for s in info["sections"]:
        out.append("    VA %#x  =>  RVA %#x  =>  offset %#x" %
                   (s["va"], s["rva"], s["raw_off"]))
    return "\n".join(out)


# =============================================================================
# 六、CLI
# =============================================================================
USAGE_NOTE = "Advanced Loader Generator 1.50 (Py replica) — patcher→loader builder"


def build_parser():
    p = argparse.ArgumentParser(
        prog="main.py",
        description=USAGE_NOTE,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=("examples:\n"
                "  python main.py info target.exe\n"
                "  python main.py applyfile target.exe spec.json -o patched.exe\n"
                "  python main.py generate --target target.exe --patch spec.json -o loader.py\n"))
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    pg = sub.add_parser("generate", help="emit a self-contained loader script + JSON config")
    pg.add_argument("--target", required=True, help="target exe (used for section table / name)")
    pg.add_argument("--patch", required=True, help="spec JSON file")
    pg.add_argument("-o", "--out", required=True, help="output loader script path")
    pg.add_argument("--json", action="store_true", help="machine-readable result")

    pa = sub.add_parser("applyfile", help="static patch: write a patched copy of target")
    pa.add_argument("target", help="target exe")
    pa.add_argument("patch", help="spec JSON file")
    pa.add_argument("-o", "--out", default=None, help="output path (default <target>.patched.exe)")
    pa.add_argument("--json", action="store_true")

    pi = sub.add_parser("info", help="show PE sections and VA/RVA/offset mapping")
    pi.add_argument("pe", help="PE file")
    pi.add_argument("--json", action="store_true")
    return p


def cmd_generate(a):
    spec = load_spec(a.patch)
    r = generate_loader(a.target, spec, a.out)
    if a.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        print("[+] generated loader : %s" % r["loader"])
        print("[+] config copy      : %s" % r["config"])
        print("[+] target / patches : %s / %d (image base %s)" %
              (r["target"], r["patches"], r["image_base"]))
        print("[+] registry patches : %d" % r["registry"])
    return EXIT_OK


def cmd_applyfile(a):
    spec = load_spec(a.patch)
    r = apply_file_patch(a.target, spec, a.out)
    if a.json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        print("static patch %s  (%d/%d applied)" %
              (r["target"], r["applied"], r["total"]))
        for p in r["patches"]:
            if p.get("ok"):
                print("  [%d] %-6s addr=%#x off=%#x  %s -> %s" % (
                    p["i"], p["type"], p["addr"], p["off"], p["before"], p["after"]))
            else:
                print("  [%d] %-6s addr=%#x  FAILED: %s" % (
                    p["i"], p["type"], p["addr"], p["err"]))
        print("=> written: %s" % r["output"])
    return EXIT_OK if r["applied"] == r["total"] else EXIT_ERR


def cmd_info(a):
    pe = load_pe(a.pe)
    if not pe.ok:
        print("[!] not a valid PE: %s" % a.pe)
        return EXIT_ERR
    info = build_info(pe)
    print(json.dumps(info, ensure_ascii=False, indent=2) if a.json else text_info(info))
    return EXIT_OK


def main(argv=None):
    parser = build_parser()
    a = parser.parse_args(argv)
    try:
        if a.cmd == "generate":
            return cmd_generate(a)
        if a.cmd == "applyfile":
            return cmd_applyfile(a)
        if a.cmd == "info":
            return cmd_info(a)
    except FileNotFoundError as e:
        print("[!] file not found: %s" % e)
        return EXIT_ERR
    except (ValueError, json.JSONDecodeError) as e:
        print("[!] %s" % e)
        return EXIT_ERR
    parser.print_help()
    return EXIT_ERR


if __name__ == "__main__":
    sys.exit(main())
