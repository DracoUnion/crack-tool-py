#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LAG Loader Generater 1.3.002155  ->  Python CLI 重写版
========================================================

来源目录 : D:\\Program Files\\crack-tool-patcher\\LAGLoaderGenerater_1.3.002155
目标文件 : LAGLOAD.exe (x86, UPX 变体加壳, 基址 0x400000)
作者     : golds7n[LAG]   (feedback: 5261314[at]sohu.com)
文档     : Readme.txt (GBK)

Readme 功能 (原文要点):
  1. Single process and multithread dynamic patch technology
     单进程与多线程动态补丁技术
  2. Easily patch Exe, Dll, Ocx etc. / 可补丁 EXE、DLL、OCX
  3. Compatible with asm, vb, vc, vfp, pb, pascal etc.
  4. More convenient and stability for packed program / 加壳程序更稳定
  1.3.002155: + support long string input / + D.Sense self define / + minor bug
  1.3      : + fix high cpu over some protector / + assign icon /
             + file drag support / + configuration save bug fix
  1.2      : + fix boundimport resolve bug / + fix load check bug /
             + use advanced thread control / + add autosave/autoload config
  1.1      : + fix load bug with some pe files / + add VA/RVA function /
             + long hex string copy & paste
  1.0      : Base

加壳存根静态信息 (IDA 反汇编 /d/temp/ida_out/t07.exe.asm):
  该 EXE 为 UPX 变体压缩, IDA 只能看到解压存根。存根导入 (kernel32):
      LoadLibraryA / GetProcAddress / VirtualAlloc / VirtualProtect /
      VirtualFree / GetModuleHandleA
  -> 这正是"动态补丁加载器"运行期所需原语: 定位模块 -> 改内存保护 ->
     写入补丁字节 -> 恢复保护 -> 继续运行。存根无应用层字符串 (仅 "UTF-16LE"),
     真实业务逻辑在压缩段内, 静态反汇编无法还原。
  => 因此本项目不重写 GUI, 而是重写其核心"生成加载器 / 应用补丁"能力为 CLI。

功能 -> 子命令映射:
  [1.1] VA/RVA function ............ info / generate / applyfile 的地址换算核心
  [1.1] long hex string ............ spec 的 bytes 字段支持长十六进制串
  [1.0] patch Exe/Dll/Ocx .......... generate (动态, 支持 module 字段=任意模块)
  [1.0] single/multi-thread dynamic  generate 生成的 loader 运行期写内存
  [1.2] autosave/autoload config ... generate 同时产出 *.config.json
  [1.3] assign icon / drag ......... GUI 专属, 本 CLI 以 --target 取代
  applyfile ........................ 静态变体: 不启动进程, 直接改文件副本

子命令:
  generate  --target NAME --patch SPEC.json [-o loader.py]
            读取 JSON 补丁清单, 生成一个自包含的 Python "loader" 脚本
            (运行期用 ctypes ReadProcessMemory/WriteProcessMemory + 模块基址
            解析做动态补丁; 找不到进程时自动回退为静态文件补丁)。
            同时输出同名 *.config.json。
  applyfile TARGET.exe SPEC.json [-o out]
            静态变体: 用节表把 VA/RVA 换算成文件偏移, 写入目标副本。
  info PE [--va 0x..] [--rva 0x..]
            打印节表 + VA/RVA/offset 映射。

限制 (packed-stub static limitation):
  原 EXE 加壳, 静态反汇编仅见存根, 无法还原 GUI 与真实补丁引擎; 本重写依据
  Readme 行为规格 + 存根导入, 实现等价的"生成加载器 + 应用字节补丁"内核。

仅使用标准库 (stdlib only)。
"""

import argparse
import json
import os
import struct
import sys

# --------------------------------------------------------------------------- #
# 常量
# --------------------------------------------------------------------------- #
IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000


class PEError(Exception):
    """PE 解析错误。"""


# --------------------------------------------------------------------------- #
# 数值 / 字节解析 (对应 readme "long hex string" 与 "VA/RVA")
# --------------------------------------------------------------------------- #
def parse_int(value):
    """把 int / '0x1234' / '1234' / '4660' 统一成 int。"""
    if isinstance(value, bool):
        raise ValueError("bool 不是合法整数: %r" % (value,))
    if isinstance(value, int):
        return value
    s = str(value).strip()
    if not s:
        raise ValueError("空整数")
    neg = False
    if s[0] in "+-":
        neg = s[0] == "-"
        s = s[1:].strip()
    s2 = s.replace("_", "")
    if s2.lower().startswith("0x"):
        n = int(s2, 16)
    elif s2.lower().startswith("0b"):
        n = int(s2, 2)
    elif s2.lower().startswith("0o"):
        n = int(s2, 8)
    else:
        try:
            n = int(s2, 10)
        except ValueError:
            n = int(s2, 16)  # 退化: 当成十六进制
    return -n if neg else n


def parse_bytes(value):
    """把 '90 90 C3' / '9090C3' / '90,90,195' / [0x90,0xC3] 统一成 bytes。"""
    if isinstance(value, (bytes, bytearray)):
        return bytes(value)
    if isinstance(value, (list, tuple)):
        out = bytearray()
        for x in value:
            n = parse_int(x)
            if n < 0 or n > 0xFF:
                raise ValueError("字节值越界: %r" % (x,))
            out.append(n)
        return bytes(out)
    s = str(value).strip()
    if s.lower().startswith("0x"):
        s = s[2:]
    for ch in (" ", "\t", "\r", "\n", ",", ":", "-", "_"):
        s = s.replace(ch, "")
    if s == "":
        return b""
    if len(s) % 2 != 0:
        raise ValueError("十六进制串长度必须为偶数: %r" % (value,))
    try:
        return bytes.fromhex(s)
    except ValueError as exc:
        raise ValueError("非法十六进制字节串: %r (%s)" % (value, exc))


# --------------------------------------------------------------------------- #
# 真正的 PE 解析器 (VA <-> RVA <-> 文件偏移)
# --------------------------------------------------------------------------- #
class PEImage(object):
    """最小但可用的 PE32/PE32+ 解析器, 负责 VA/RVA/文件偏移互换。"""

    def __init__(self, data, name="<memory>"):
        self.data = bytes(data)
        self.name = name
        self.sections = []  # list of dict
        self.image_base = 0
        self.image_size = 0
        self.entry_rva = 0
        self.machine = 0
        self.is_64 = False
        self._parse()

    # -- 内部解析 ---------------------------------------------------------- #
    def _u16(self, off):
        return struct.unpack_from("<H", self.data, off)[0]

    def _u32(self, off):
        return struct.unpack_from("<I", self.data, off)[0]

    def _parse(self):
        d = self.data
        if len(d) < 0x40 or d[:2] != b"MZ":
            raise PEError("%s: 不是 PE (缺少 MZ)" % self.name)
        e_lfanew = self._u32(0x3C)
        if e_lfanew + 24 > len(d):
            raise PEError("%s: e_lfanew 越界" % self.name)
        if d[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            raise PEError("%s: 缺少 PE 签名" % self.name)
        coff = e_lfanew + 4
        self.machine = self._u16(coff)
        num_sections = self._u16(coff + 2)
        size_opt = self._u16(coff + 16)
        opt = coff + 20
        if opt + 2 > len(d):
            raise PEError("%s: 可选头越界" % self.name)
        magic = self._u16(opt)
        if magic == 0x20B:  # PE32+
            self.is_64 = True
            self.image_base = self._u32(opt + 24) | (self._u32(opt + 28) << 32)
            self.image_size = self._u32(opt + 56)
            self.entry_rva = self._u32(opt + 16)
            num_dirs_off = opt + 108
        elif magic == 0x10B:  # PE32
            self.is_64 = False
            self.image_base = self._u32(opt + 28)
            self.image_size = self._u32(opt + 56)
            self.entry_rva = self._u32(opt + 16)
            num_dirs_off = opt + 92
        else:
            raise PEError("%s: 未知可选头 magic 0x%X" % (self.name, magic))
        sec = opt + size_opt
        for i in range(num_sections):
            off = sec + i * 40
            if off + 40 > len(d):
                break
            name_raw = d[off:off + 8]
            sname = name_raw.split(b"\x00", 1)[0].decode("latin1", "replace")
            vsize = self._u32(off + 8)
            vaddr = self._u32(off + 12)
            rsize = self._u32(off + 16)
            rptr = self._u32(off + 20)
            chars = self._u32(off + 36)
            self.sections.append({
                "name": sname,
                "vsize": vsize,
                "vaddr": vaddr,
                "rsize": rsize,
                "rptr": rptr,
                "chars": chars,
            })

    # -- 地址换算 ---------------------------------------------------------- #
    def rva_to_offset(self, rva):
        if rva < 0:
            raise PEError("RVA 不能为负: 0x%X" % rva)
        for s in self.sections:
            span = max(s["vsize"], s["rsize"])
            if s["vaddr"] <= rva < s["vaddr"] + span:
                delta = rva - s["vaddr"]
                if delta < s["rsize"]:
                    return s["rptr"] + delta
                # 落在 .bss 类未文件映射区
                raise PEError(
                    "RVA 0x%X 位于节 %s 的未文件映射区 (delta 0x%X >= raw 0x%X)"
                    % (rva, s["name"], delta, s["rsize"]))
        # 头部
        if rva < self.sections[0]["vaddr"] if self.sections else True:
            if rva < 0x1000:
                return rva
        raise PEError("RVA 0x%X 不在任何节内" % rva)

    def va_to_rva(self, va):
        return va - self.image_base

    def va_to_offset(self, va):
        return self.rva_to_offset(self.va_to_rva(va))

    def rva_to_va(self, rva):
        return self.image_base + rva

    def offset_to_rva(self, off):
        for s in self.sections:
            if s["rptr"] <= off < s["rptr"] + s["rsize"]:
                return s["vaddr"] + (off - s["rptr"])
        if off < (self.sections[0]["rptr"] if self.sections else 0x200):
            return off
        raise PEError("文件偏移 0x%X 不在任何节内" % off)

    # -- 展示 -------------------------------------------------------------- #
    def section_flags(self, s):
        c = s["chars"]
        flags = []
        if c & IMAGE_SCN_CNT_CODE:
            flags.append("CODE")
        if c & IMAGE_SCN_MEM_EXECUTE:
            flags.append("X")
        if c & IMAGE_SCN_MEM_READ:
            flags.append("R")
        if c & IMAGE_SCN_MEM_WRITE:
            flags.append("W")
        return "".join(flags)

    def describe(self):
        lines = []
        lines.append("PE: %s" % self.name)
        lines.append("  machine      : 0x%04X (%s)" % (
            self.machine, "x86" if self.machine == IMAGE_FILE_MACHINE_I386 else "?"))
        lines.append("  PE32+        : %s" % ("yes" if self.is_64 else "no"))
        lines.append("  image base   : 0x%X" % self.image_base)
        lines.append("  image size   : 0x%X" % self.image_size)
        lines.append("  entry RVA    : 0x%X (VA 0x%X)" % (
            self.entry_rva, self.rva_to_va(self.entry_rva)))
        lines.append("  sections     : %d" % len(self.sections))
        lines.append("  %-9s %-10s %-10s %-10s %-10s %-6s" % (
            "Name", "VA", "VSize", "RawOff", "RawSize", "Flags"))
        for s in self.sections:
            lines.append("  %-9s 0x%08X 0x%08X 0x%08X 0x%08X %-6s" % (
                s["name"], s["vaddr"], s["vsize"], s["rptr"],
                s["rsize"], self.section_flags(s)))
        return "\n".join(lines)


def load_pe(path):
    with open(path, "rb") as f:
        return PEImage(f.read(), path)


# --------------------------------------------------------------------------- #
# 补丁规格 (spec) 规范化
# --------------------------------------------------------------------------- #
def normalize_spec(spec, target_override=None):
    """把 JSON spec 解析为 (target_name, [patch dict])。

    支持两种顶层结构:
      A) 直接是 patch 列表:  [ {rva/va, bytes, module?, wait?}, ... ]
      B) 对象: { "target": "x.exe", "patches": [ ... ] }
    patch dict 规范化字段: rva(int|None), va(int|None), bytes(bytes),
                           module(str|None), wait(int ms, 默认 0)
    """
    target = target_override
    raw_patches = None
    if isinstance(spec, dict):
        if target is None:
            target = spec.get("target") or spec.get("name")
        raw_patches = spec.get("patches")
        if raw_patches is None:
            raw_patches = spec.get("patch")
    elif isinstance(spec, list):
        raw_patches = spec
    else:
        raise ValueError("spec 顶层必须是 list 或 object")

    if raw_patches is None:
        raise ValueError("spec 中缺少 patches 列表")
    if not isinstance(raw_patches, list):
        raise ValueError("patches 必须是列表")

    patches = []
    for i, item in enumerate(raw_patches):
        if not isinstance(item, dict):
            raise ValueError("第 %d 个 patch 不是对象" % i)
        rva = item.get("rva")
        va = item.get("va")
        if rva is None and va is None:
            raise ValueError("第 %d 个 patch 缺少 rva 或 va" % i)
        rva_i = parse_int(rva) if rva is not None else None
        va_i = parse_int(va) if va is not None else None
        if "bytes" not in item and "hex" not in item:
            raise ValueError("第 %d 个 patch 缺少 bytes 字段" % i)
        raw_bytes = item.get("bytes", item.get("hex"))
        data = parse_bytes(raw_bytes)
        module = item.get("module")
        if module is not None:
            module = str(module)
        wait = parse_int(item.get("wait", 0) or 0)
        patches.append({
            "rva": rva_i,
            "va": va_i,
            "bytes": data,
            "module": module,
            "wait": wait,
        })
    return target, patches


def patch_target_desc(p):
    """人类可读的补丁位置描述。"""
    if p["rva"] is not None:
        loc = "RVA 0x%X" % p["rva"]
        if p["va"] is not None:
            loc += " (VA 0x%X)" % p["va"]
    else:
        loc = "VA 0x%X" % p["va"]
    mod = (" module=%s" % p["module"]) if p["module"] else ""
    wait = (" wait=%dms" % p["wait"]) if p["wait"] else ""
    return "%s bytes=%s%s%s" % (loc, p["bytes"].hex(), mod, wait)


# --------------------------------------------------------------------------- #
# 子命令: info
# --------------------------------------------------------------------------- #
def cmd_info(args):
    pe = load_pe(args.pe)
    print(pe.describe())
    if args.va is not None:
        va = parse_int(args.va)
        rva = pe.va_to_rva(va)
        try:
            off = pe.va_to_offset(va)
            offs = "0x%X" % off
        except PEError as exc:
            offs = "<%s>" % exc
        print("\n  VA   0x%08X -> RVA 0x%08X -> offset %s" % (va, rva, offs))
    if args.rva is not None:
        rva = parse_int(args.rva)
        try:
            off = pe.rva_to_offset(rva)
            offs = "0x%X" % off
        except PEError as exc:
            offs = "<%s>" % exc
        print("  RVA  0x%08X -> VA   0x%08X -> offset %s" % (
            rva, pe.rva_to_va(rva), offs))
    return 0


# --------------------------------------------------------------------------- #
# 子命令: applyfile (静态变体)
# --------------------------------------------------------------------------- #
def default_out_path(target, suffix="_patched"):
    base, ext = os.path.splitext(target)
    return base + suffix + (ext or ".exe")


def cmd_applyfile(args):
    with open(args.target, "rb") as f:
        data = bytearray(f.read())
    pe = PEImage(bytes(data), args.target)
    with open(args.spec, "r", encoding="utf-8") as f:
        spec = json.load(f)
    _target, patches = normalize_spec(spec, target_override=args.target)

    # 预检查: 先算好所有 (offset, bytes) 再统一写入
    writes = []
    for i, p in enumerate(patches):
        if p["rva"] is not None:
            rva = p["rva"]
        else:
            rva = pe.va_to_rva(p["va"])
        try:
            off = pe.rva_to_offset(rva)
        except PEError as exc:
            raise PEError("第 %d 个 patch: %s" % (i, exc))
        end = off + len(p["bytes"])
        if end > len(data):
            raise PEError(
                "第 %d 个 patch 写越界: off 0x%X + %d > 文件大小 0x%X"
                % (i, off, len(p["bytes"]), len(data)))
        writes.append((i, rva, off, p["bytes"]))

    for i, rva, off, b in writes:
        data[off:off + len(b)] = b
        print("  patch[%d] RVA 0x%08X -> offset 0x%08X  (%d bytes)" % (
            i, rva, off, len(b)))

    out = args.out or default_out_path(args.target)
    with open(out, "wb") as f:
        f.write(data)
    print("[+] 已写出静态补丁文件: %s (%d 处补丁)" % (out, len(writes)))
    return 0


# --------------------------------------------------------------------------- #
# 子命令: generate (生成自包含 loader 脚本 + JSON config)
# --------------------------------------------------------------------------- #
def _pyrepr(obj):
    """生成稳定的 Python 字面量 (用于嵌入 loader)。"""
    return repr(obj)


def build_loader_text(target, patches, config):
    """用模板拼出自包含 loader 脚本文本。"""
    # patches 转成可序列化的纯数据 (bytes -> hex 串)
    ser_patches = []
    for p in patches:
        ser_patches.append({
            "rva": p["rva"],
            "va": p["va"],
            "hex": p["bytes"].hex(),
            "module": p["module"],
            "wait": p["wait"],
        })
    target_repr = _pyrepr(target or "")
    patches_repr = _pyrepr(ser_patches)
    config_repr = _pyrepr(config)
    text = LOADER_TEMPLATE
    text = text.replace("@@TARGET@@", target_repr)
    text = text.replace("@@PATCHES@@", patches_repr)
    text = text.replace("@@CONFIG@@", config_repr)
    text = text.replace("@@NPATCH@@", str(len(ser_patches)))
    return text


def cmd_generate(args):
    with open(args.patch, "r", encoding="utf-8") as f:
        spec = json.load(f)
    target, patches = normalize_spec(spec, target_override=args.target)
    if not target:
        # 退而用 spec 文件名 (去掉扩展名) 作为目标名
        target = os.path.splitext(os.path.basename(args.patch))[0] + ".exe"

    config = {
        "generator": "lagloader_py (LAG Loader Generater 1.3.002155 rewrite)",
        "target": target,
        "patch_count": len(patches),
        "patches": [
            {
                "rva": p["rva"],
                "va": p["va"],
                "hex": p["bytes"].hex(),
                "module": p["module"],
                "wait": p["wait"],
            }
            for p in patches
        ],
    }

    loader_text = build_loader_text(target, patches, config)
    out = args.out or "loader_generated.py"
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write(loader_text)

    cfg_path = os.path.splitext(out)[0] + ".config.json"
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(config, f, indent=2, ensure_ascii=False)

    print("[+] 目标: %s" % target)
    for i, p in enumerate(patches):
        print("    patch[%d] %s" % (i, patch_target_desc(p)))
    print("[+] 已生成 loader: %s" % out)
    print("[+] 已生成配置   : %s" % cfg_path)
    print("[i] 用法: python %s            # 动态补丁 (附加到运行中的进程)"
          % out)
    print("         python %s --static   # 静态补丁 (改文件副本, 无需进程)" % out)
    print("         python %s --dry-run  # 只计算地址/偏移, 不写入" % out)
    return 0


# --------------------------------------------------------------------------- #
# 生成 loader 的内嵌模板 (自包含, 仅 stdlib)
# --------------------------------------------------------------------------- #
LOADER_TEMPLATE = r'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""AUTO-GENERATED loader  (lagloader_py / LAG Loader Generater 1.3.002155 rewrite)

目标 Target : @@TARGET@@
补丁数量     : @@NPATCH@@

运行模式:
  python <this>            动态补丁: 找到目标进程, 等模块加载, 用
                           WriteProcessMemory 写入补丁字节 (VirtualProtectEx
                           临时放开写权限), 然后继续/退出。
  python <this> --static   静态补丁: 不启动进程, 直接对目标文件副本按
                           RVA->文件偏移写入 (PE 节表换算)。
  python <this> --dry-run  只计算并打印每处补丁的地址/偏移, 不写任何东西。
  python <this> --pid N    指定已运行进程 PID (跳过按名查找)。
  python <this> --config F 从 JSON 配置载入补丁清单 (覆盖内嵌清单)。

仅使用标准库 (ctypes / struct / json / argparse)。
"""
import argparse
import ctypes
import json
import os
import struct
import sys
from ctypes import wintypes

TARGET = @@TARGET@@
PATCHES = @@PATCHES@@
CONFIG = @@CONFIG@@

TH32CS_SNAPPROCESS = 0x00000002
TH32CS_SNAPMODULE = 0x00000008
TH32CS_SNAPMODULE32 = 0x00000010
PROCESS_ALL_ACCESS = 0x1F0FFF
PAGE_EXECUTE_READWRITE = 0x40


# ============================ 最小 PE 解析器 =============================== #
class PEImage(object):
    def __init__(self, data, name="<mem>"):
        self.data = bytes(data)
        self.name = name
        self.sections = []
        self.image_base = 0
        self.is_64 = False
        self._parse()

    def _u16(self, o):
        return struct.unpack_from("<H", self.data, o)[0]

    def _u32(self, o):
        return struct.unpack_from("<I", self.data, o)[0]

    def _parse(self):
        d = self.data
        if len(d) < 0x40 or d[:2] != b"MZ":
            raise ValueError("%s: 非 PE" % self.name)
        pe = self._u32(0x3C)
        if d[pe:pe + 4] != b"PE\x00\x00":
            raise ValueError("%s: 无 PE 签名" % self.name)
        coff = pe + 4
        nsec = self._u16(coff + 2)
        sizeopt = self._u16(coff + 16)
        opt = coff + 20
        magic = self._u16(opt)
        if magic == 0x20B:
            self.is_64 = True
            self.image_base = self._u32(opt + 24) | (self._u32(opt + 28) << 32)
        elif magic == 0x10B:
            self.image_base = self._u32(opt + 28)
        else:
            raise ValueError("%s: 未知 magic 0x%X" % (self.name, magic))
        sec = opt + sizeopt
        for i in range(nsec):
            o = sec + i * 40
            if o + 40 > len(d):
                break
            self.sections.append({
                "name": d[o:o + 8].split(b"\x00", 1)[0].decode("latin1", "replace"),
                "vsize": self._u32(o + 8),
                "vaddr": self._u32(o + 12),
                "rsize": self._u32(o + 16),
                "rptr": self._u32(o + 20),
            })

    def rva_to_offset(self, rva):
        for s in self.sections:
            span = max(s["vsize"], s["rsize"])
            if s["vaddr"] <= rva < s["vaddr"] + span:
                delta = rva - s["vaddr"]
                if delta < s["rsize"]:
                    return s["rptr"] + delta
                raise ValueError("RVA 0x%X 在未文件映射区" % rva)
        if rva < 0x1000:
            return rva
        raise ValueError("RVA 0x%X 不在任何节" % rva)

    def va_to_rva(self, va):
        return va - self.image_base


def load_pe_file(path):
    with open(path, "rb") as f:
        return PEImage(f.read(), path)


# ============================ 动态补丁 (Windows) =========================== #
_k32 = None
_psapi = None


def _k():
    global _k32
    if _k32 is None:
        _k32 = ctypes.windll.kernel32
    return _k32


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", ctypes.c_wchar * 260),
    ]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("th32ModuleID", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("GlblcntUsage", wintypes.DWORD),
        ("ProccntUsage", wintypes.DWORD),
        ("modBaseAddr", ctypes.POINTER(ctypes.c_byte)),
        ("modBaseSize", wintypes.DWORD),
        ("hModule", wintypes.HMODULE),
        ("szModule", ctypes.c_wchar * 256),
        ("szExePath", ctypes.c_wchar * 260),
    ]


def find_pid_by_name(name):
    """按可执行文件名 (如 foo.exe) 查找 PID, 找不到返回 None。"""
    name_l = name.lower()
    snap = _k().CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == -1:
        return None
    try:
        entry = PROCESSENTRY32W()
        entry.dwSize = ctypes.sizeof(entry)
        ok = _k().Process32FirstW(snap, ctypes.byref(entry))
        while ok:
            if entry.szExeFile.lower() == name_l:
                return entry.th32ProcessID
            ok = _k().Process32NextW(snap, ctypes.byref(entry))
    finally:
        _k().CloseHandle(snap)
    return None


def module_base(pid, module_name):
    """返回模块在目标进程中的基址; 找不到返回 None。

    module_name 为 None 或空 -> 返回主 exe 模块基址。
    """
    snap = _k().CreateToolhelp32Snapshot(
        TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    if snap == -1:
        return None
    try:
        me = MODULEENTRY32W()
        me.dwSize = ctypes.sizeof(me)
        ok = _k().Module32FirstW(snap, ctypes.byref(me))
        first = True
        while ok:
            base = ctypes.cast(me.modBaseAddr, ctypes.c_void_p).value
            if not module_name:
                if first:
                    return base
                first = False
            elif me.szModule.lower() == module_name.lower():
                return base
            ok = _k().Module32NextW(snap, ctypes.byref(me))
    finally:
        _k().CloseHandle(snap)
    return None


def write_memory(pid, address, data):
    """在目标进程 address 处写入 data, 返回是否成功。"""
    k = _k()
    h = k.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h:
        raise OSError("OpenProcess 失败 (err=%d)" % ctypes.get_last_error())
    try:
        old = wintypes.DWORD(0)
        k.VirtualProtectEx(h, ctypes.c_void_p(address), len(data),
                           PAGE_EXECUTE_READWRITE, ctypes.byref(old))
        written = ctypes.c_size_t(0)
        ok = k.WriteProcessMemory(h, ctypes.c_void_p(address), data,
                                  len(data), ctypes.byref(written))
        k.VirtualProtectEx(h, ctypes.c_void_p(address), len(data),
                           old.value, ctypes.byref(old))
        if not ok or written.value != len(data):
            raise OSError("WriteProcessMemory 失败 (err=%d)" %
                          ctypes.get_last_error())
    finally:
        k.CloseHandle(h)
    return True


# ============================ 补丁应用核心 ================================= #
def _resolve_rva(p, image_base):
    if p.get("rva") is not None:
        return int(p["rva"])
    return int(p["va"]) - image_base


def _default_image_base():
    """尽力从磁盘上的目标文件读取 ImageBase, 失败回退 0x400000。"""
    for cand in (TARGET,):
        if cand and os.path.exists(cand):
            try:
                return load_pe_file(cand).image_base
            except Exception:
                pass
    return 0x400000


def apply_static(patches, out_path, dry):
    """静态: 读目标文件, 用节表把 RVA 换算成偏移, 写入副本。"""
    if not os.path.exists(TARGET):
        raise FileNotFoundError("找不到目标文件: %s" % TARGET)
    with open(TARGET, "rb") as f:
        data = bytearray(f.read())
    pe = PEImage(bytes(data), TARGET)
    plan = []
    for i, p in enumerate(patches):
        rva = _resolve_rva(p, pe.image_base)
        off = pe.rva_to_offset(rva)
        b = bytes.fromhex(p["hex"])
        plan.append((i, rva, off, b))
    if dry:
        for i, rva, off, b in plan:
            print("  [dry] patch[%d] RVA 0x%08X -> offset 0x%08X (%d bytes)"
                  % (i, rva, off, len(b)))
        print("[dry] 静态模式, 未写入。目标 %s, 输出将到 %s" % (TARGET, out_path))
        return
    for i, rva, off, b in plan:
        data[off:off + len(b)] = b
        print("  patch[%d] RVA 0x%08X -> offset 0x%08X (%d bytes)"
              % (i, rva, off, len(b)))
    with open(out_path, "wb") as f:
        f.write(data)
    print("[+] 静态补丁完成: %s (%d 处)" % (out_path, len(plan)))


def apply_dynamic(patches, pid, dry):
    """动态: 附加到进程, 等模块加载, 写内存。"""
    if not pid:
        pid = find_pid_by_name(TARGET)
    if not pid:
        raise RuntimeError("未找到运行中的进程: %s" % TARGET)
    print("[*] 目标进程 PID = %d" % pid)
    image_base = _default_image_base()
    # 逐补丁解析模块基址并写入
    for i, p in enumerate(patches):
        rva = _resolve_rva(p, image_base)
        mod = p.get("module") or TARGET
        base = None
        waited = 0
        step = 50
        maxwait = int(p.get("wait", 0) or 0)
        # 等到模块出现 (或超时)
        while True:
            base = module_base(pid, mod)
            if base:
                break
            if waited >= maxwait:
                break
            import time
            time.sleep(step / 1000.0)
            waited += step
        if not base:
            raise RuntimeError("模块 %s 未加载 (等待 %dms 后超时)" % (mod, maxwait))
        addr = base + rva
        b = bytes.fromhex(p["hex"])
        if dry:
            print("  [dry] patch[%d] %s base=0x%X + RVA 0x%X = 0x%X (%d bytes)"
                  % (i, mod, base, rva, addr, len(b)))
            continue
        write_memory(pid, addr, b)
        print("  patch[%d] 写入 0x%X (%s + 0x%X) %d bytes"
              % (i, addr, mod, rva, len(b)))
    if dry:
        print("[dry] 动态模式, 未写入。")
    else:
        print("[+] 动态补丁完成: %d 处" % len(patches))


# ============================ 入口 ======================================= #
def _load_config(path):
    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    return cfg.get("patches", cfg if isinstance(cfg, list) else [])


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="AUTO-GENERATED loader for %s (lagloader_py)" % TARGET)
    ap.add_argument("--static", action="store_true",
                    help="静态补丁: 改文件副本, 不需要运行进程")
    ap.add_argument("--dry-run", action="store_true",
                    help="只计算地址/偏移, 不写入")
    ap.add_argument("--pid", type=int, default=0, help="指定目标进程 PID")
    ap.add_argument("--config", default="", help="从 JSON 载入补丁清单")
    ap.add_argument("-o", "--out", default="",
                    help="静态模式输出路径 (默认 <target>_patched<ext>)")
    args = ap.parse_args(argv)

    patches = _load_config(args.config) if args.config else PATCHES
    if not patches:
        print("[-] 无补丁")
        return 1

    out = args.out
    if not out:
        base, ext = os.path.splitext(TARGET)
        out = base + "_patched" + (ext or ".exe")

    if args.static:
        apply_static(patches, out, args.dry_run)
    else:
        try:
            apply_dynamic(patches, args.pid, args.dry_run)
        except Exception as exc:
            print("[!] 动态补丁失败: %s" % exc)
            print("[i] 可改用 --static 做静态文件补丁。")
            return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
'''


# --------------------------------------------------------------------------- #
# 命令行
# --------------------------------------------------------------------------- #
def build_parser():
    p = argparse.ArgumentParser(
        prog="lagloader_py",
        description="LAG Loader Generater 1.3.002155 的 Python CLI 重写 "
                    "(动态补丁加载器生成 / 静态字节补丁 / PE 地址换算)")
    sub = p.add_subparsers(dest="cmd")

    g = sub.add_parser("generate", help="生成自包含 Python loader 脚本 + JSON 配置")
    g.add_argument("--target", required=True, help="目标可执行文件名 (如 foo.exe)")
    g.add_argument("--patch", required=True, help="JSON 补丁清单 (spec)")
    g.add_argument("-o", "--out", default="loader_generated.py",
                   help="输出 loader 脚本路径 (默认 loader_generated.py)")
    g.set_defaults(func=cmd_generate)

    a = sub.add_parser("applyfile", help="静态变体: VA/RVA->文件偏移并写入副本")
    a.add_argument("target", help="目标 PE 文件")
    a.add_argument("spec", help="JSON 补丁清单")
    a.add_argument("-o", "--out", default="", help="输出路径 (默认 <target>_patched<ext>)")
    a.set_defaults(func=cmd_applyfile)

    i = sub.add_parser("info", help="打印节表 + VA/RVA/offset 映射")
    i.add_argument("pe", help="PE 文件")
    i.add_argument("--va", default=None, help="要换算的 VA (0x..)")
    i.add_argument("--rva", default=None, help="要换算的 RVA (0x..)")
    i.set_defaults(func=cmd_info)
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    try:
        return args.func(args)
    except (PEError, ValueError, OSError, FileNotFoundError) as exc:
        print("[-] 错误: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())