#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
XH 补丁制作工具 V1.3.6  ->  Python CLI 重写版
(XH补丁制作工具1.3.6 / XH补丁制作工具 V1.3.6.exe)

来源目录:
  D:\\Program Files\\crack-tool-patcher\\XH补丁制作工具_1.3.6\\XH 补丁制作工具1.3.6\\
主程序  : XH补丁制作工具 V1.3.6.exe  (~11 MB, x86 PE32, VMProtect .vmp0 加壳)
          同目录另有: 配置数据.ini / Inline Hook\\ / OD插件\\ / dat\\ / skin\\ /
          tools\\ / update\\patch.dat

逆向依据 (静态: 配置文件 + 字符串 + 文档, 未反汇编 VM):
  - 配置数据.ini              : [皮肤] [数据] [更新] [用户信息] [vip] 五个节, 驱动界面
                                与默认行为。关键项:
                                  默认数据页面=EXE数据
                                  添加数据后清空OD代码/EXE数据/DLL数据/特征数据=是
                                  文件名=...\\XH补丁制作工具 V1.3.6.exe (自更新源)
  - Inline Hook\\*.dll.txt    : 按 DLL 组织的可挂 API 数据库, 每行一个函数名
                                (kernel32 / user32 / wininet / ws2_32 / winsock32 /
                                 advpai32 —— 注意原文件名拼写为 advpai32.dll.txt)
  - Inline Hook\\便捷HOOK.txt : "dll|func|note" 每行一条的便捷挂点
                                (如 user32.dll|MessageBoxA|信息框函数)
  - OD插件\\调用方法.txt      : OD 插件用法 (A.dll 放 OD 插件目录; TX.exe + Patch.ini
                                放 OD 目录; 配置 Patch.ini 的 ini文件=)
  - 字符串证据               : 'Inline Hook', '\\Inline Hook\\', '*.dll.txt',
                                '@\\Inline Hook\\', 'HOOK.txt', 'XHPatcher',
                                '\\update\\patch.dat', ';VipPatch',
                                节名 '.text' / '@.data' / '.vmp0'

VMProtect 说明:
  主程序为 VMProtect 保护, 静态反汇编只能看到 VM 解释器存根、导入表与字符串,
  字节补丁生成与 Inline Hook 挂点生成的真实指令级逻辑封装在 VM 字节码内, 未被
  反汇编。本重写为"按文档/字符串/已知 XH 行为重构"的离线工具: 一个真正解析 PE
  并打字节补丁的补丁器 + 一个基于 Inline Hook API 数据库的 5 字节 E9 JMP 内联
  挂点方案生成器。不依赖 VM 反汇编结果。

功能定位 与 特征 -> 子命令 映射:
  - 离线对目标 EXE/DLL 打字节补丁 (offset / RVA / VA)        -> apply
  - 查看 PE 节区、CRC32/MD5、VA<->RVA<->文件偏移 映射          -> info
  - 从 Inline Hook 数据库选 DLL+API, 生成 5 字节 E9 rel32 到
    代码洞 + pushad/popad 蹦床(trampoline) scaffold 方案       -> hook
    (hook --list 列出数据库全部 API)
  - 查看指定 DLL 的可挂 API 列表                              -> checkhook

依赖: 纯 Python 标准库 (无第三方依赖). main.py 为唯一入口.
用法: python main.py <子命令> ...
"""

import argparse
import hashlib
import json
import os
import struct
import sys
import zlib

# ---------------------------------------------------------------------------
# 常量
# ---------------------------------------------------------------------------

TOOL_NAME = "XH 补丁制作工具 V1.3.6"
TOOL_INTERNAL = "XHPatcher"

# Inline Hook API 数据库的候选目录 (按优先级)。
# 1) 环境变量 XH_INLINE_HOOK_DIR 覆盖
# 2) 原始安装目录
# 3) 本脚本同级的 "Inline Hook" 目录 (随程序分发时)
DEFAULT_DB_DIRS = [
    os.path.join(
        r"D:\Program Files\crack-tool-patcher",
        "XH补丁制作工具_1.3.6",
        "XH 补丁制作工具1.3.6",
        "Inline Hook",
    ),
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "Inline Hook"),
]

# 找不到外部数据库时使用的内嵌最小数据库 (dll -> [func, ...])。
EMBEDDED_DB = {
    "user32.dll": [
        "MessageBoxA", "MessageBoxW", "MessageBoxExA", "MessageBoxExW",
        "CreateWindowExA", "CreateWindowExW", "GetMessageA", "DispatchMessageA",
        "SetWindowTextA", "GetWindowTextA", "CallWindowProcA",
    ],
    "kernel32.dll": [
        "CreateFileA", "CreateFileW", "ReadFile", "WriteFile", "CloseHandle",
        "GetProcAddress", "LoadLibraryA", "LoadLibraryW", "VirtualProtect",
        "VirtualAlloc", "GetModuleHandleA", "Sleep", "ExitProcess",
    ],
    "ws2_32.dll": ["socket", "connect", "send", "recv", "WSAStartup", "closesocket"],
    "wininet.dll": ["InternetOpenA", "InternetConnectA", "HttpOpenRequestA",
                    "HttpSendRequestA", "InternetReadFile"],
    "advapi32.dll": ["RegOpenKeyExA", "RegQueryValueExA", "RegSetValueExA",
                     "CreateProcessA", "OpenProcessToken"],
}


# ---------------------------------------------------------------------------
# PE 解析 (PE32 / PE32+)
# ---------------------------------------------------------------------------

class PEError(Exception):
    pass


class Section(object):
    __slots__ = ("name", "vsize", "vaddr", "rawsize", "rawptr", "chars")

    def __init__(self, name, vsize, vaddr, rawsize, rawptr, chars):
        self.name = name
        self.vsize = vsize
        self.vaddr = vaddr
        self.rawsize = rawsize
        self.rawptr = rawptr
        self.chars = chars

    @property
    def va_start(self):
        return self.vaddr  # RVA

    def contains_rva(self, rva):
        span = max(self.vsize, self.rawsize)
        return self.vaddr <= rva < self.vaddr + span


class PE(object):
    """极简 PE 解析器, 只实现本工具需要的部分 (节表 / VA<->RVA<->offset)。"""

    def __init__(self, data, path=None):
        self.data = data
        self.path = path
        self._parse()

    # -- 基础工具 ---------------------------------------------------------
    @staticmethod
    def _u16(b, o):
        return struct.unpack_from("<H", b, o)[0]

    @staticmethod
    def _u32(b, o):
        return struct.unpack_from("<I", b, o)[0]

    @staticmethod
    def _u64(b, o):
        return struct.unpack_from("<Q", b, o)[0]

    def _parse(self):
        d = self.data
        if len(d) < 0x40 or d[0:2] != b"MZ":
            raise PEError("不是有效的 PE 文件 (缺少 MZ 头)")
        self.e_lfanew = self._u32(d, 0x3C)
        if self.e_lfanew + 24 > len(d) or d[self.e_lfanew:self.e_lfanew + 4] != b"PE\x00\x00":
            raise PEError("找不到 PE 签名 (e_lfanew=0x%X)" % self.e_lfanew)

        coff = self.e_lfanew + 4
        self.machine = self._u16(d, coff + 0)
        self.num_sections = self._u16(d, coff + 2)
        self.timestamp = self._u32(d, coff + 4)
        self.size_opt = self._u16(d, coff + 16)
        self.characteristics = self._u16(d, coff + 18)

        opt = coff + 20  # 可选头起始
        self.opt_off = opt
        if opt + 2 > len(d):
            raise PEError("可选头截断")
        self.magic = self._u16(d, opt)
        self.is64 = (self.magic == 0x20B)
        if self.magic == 0x10B:       # PE32
            self.entry_rva = self._u32(d, opt + 16)
            self.image_base = self._u32(d, opt + 28)
            self.section_align = self._u32(d, opt + 32)
            self.file_align = self._u32(d, opt + 36)
            self.size_image = self._u32(d, opt + 56)
            self.subsystem = self._u16(d, opt + 68)
        elif self.magic == 0x20B:     # PE32+
            self.entry_rva = self._u32(d, opt + 16)
            self.image_base = self._u64(d, opt + 24)
            self.section_align = self._u32(d, opt + 32)
            self.file_align = self._u32(d, opt + 36)
            self.size_image = self._u32(d, opt + 56)
            self.subsystem = self._u16(d, opt + 68)
        else:
            raise PEError("未知可选头魔数 0x%X" % self.magic)

        # 节表
        sec = opt + self.size_opt
        self.sections = []
        for i in range(self.num_sections):
            off = sec + i * 40
            if off + 40 > len(d):
                break
            raw_name = d[off:off + 8]
            name = raw_name.split(b"\x00", 1)[0].decode("latin-1", "replace")
            vsize = self._u32(d, off + 8)
            vaddr = self._u32(d, off + 12)
            rawsize = self._u32(d, off + 16)
            rawptr = self._u32(d, off + 20)
            chars = self._u32(d, off + 36)
            self.sections.append(Section(name, vsize, vaddr, rawsize, rawptr, chars))

    # -- 地址转换 ---------------------------------------------------------
    def rva_to_offset(self, rva):
        for s in self.sections:
            if s.contains_rva(rva):
                return s.rawptr + (rva - s.vaddr)
        # 头部区域 (PE 头本身), 文件偏移 == RVA
        hdr = self.e_lfanew + 24 + self.size_opt + self.num_sections * 40
        if 0 <= rva < hdr:
            return rva
        raise PEError("RVA 0x%X 不落在任何节区或头部内" % rva)

    def va_to_rva(self, va):
        if va < self.image_base:
            raise PEError("VA 0x%X 小于映像基址 0x%X" % (va, self.image_base))
        return va - self.image_base

    def va_to_offset(self, va):
        return self.rva_to_offset(self.va_to_rva(va))

    def rva_to_va(self, rva):
        return self.image_base + rva

    def offset_to_rva(self, off):
        for s in self.sections:
            if s.rawptr <= off < s.rawptr + s.rawsize:
                return s.vaddr + (off - s.rawptr)
        return off  # 头部

    # -- 摘要 -------------------------------------------------------------
    def crc32(self):
        return zlib.crc32(self.data) & 0xFFFFFFFF

    def md5(self):
        return hashlib.md5(self.data).hexdigest()

    def machine_name(self):
        return {
            0x14C: "i386 (x86)",
            0x8664: "x86-64",
            0xAA64: "ARM64",
            0x1C0: "ARM",
        }.get(self.machine, "0x%X" % self.machine)

    def subsystem_name(self):
        return {
            1: "NATIVE", 2: "WINDOWS_GUI", 3: "WINDOWS_CUI",
            5: "OS2_CUI", 7: "POSIX_CUI", 9: "WINDOWS_CE_GUI",
            10: "EFI_APPLICATION", 11: "EFI_BOOT_SERVICE_DRIVER",
            12: "EFI_RUNTIME_DRIVER", 13: "EFI_ROM",
            14: "XBOX", 16: "WINDOWS_BOOT_APPLICATION",
        }.get(self.subsystem, str(self.subsystem))


# ---------------------------------------------------------------------------
# Inline Hook API 数据库
# ---------------------------------------------------------------------------

class HookDB(object):
    """解析 Inline Hook 目录下的 *.txt (每行一个函数名) 与 便捷HOOK.txt
    (dll|func|note) 两种格式, 合并为 dll -> [func...] 的映射。"""

    def __init__(self, db_dir=None):
        self.dir = None
        self.source = "embedded"
        self.entries = {}   # dll_lower -> {"dll": 原始名, "funcs": [(func, note), ...]}
        self.order = []     # dll_lower 顺序
        if db_dir is None:
            db_dir = self._locate()
        if db_dir and os.path.isdir(db_dir):
            self._load_dir(db_dir)
            self.dir = db_dir
            self.source = "file"
        else:
            self._load_embedded()

    # -- 定位数据库目录 ---------------------------------------------------
    @staticmethod
    def _locate():
        env = os.environ.get("XH_INLINE_HOOK_DIR")
        if env and os.path.isdir(env):
            return env
        for d in DEFAULT_DB_DIRS:
            if os.path.isdir(d):
                return d
        return None

    def _add(self, dll, func, note=""):
        key = dll.lower()
        if key not in self.entries:
            self.entries[key] = {"dll": dll, "funcs": []}
            self.order.append(key)
        # 去重 (同 func 保留首个; 但非空 note 可升级空 note)
        for idx, (f, n) in enumerate(self.entries[key]["funcs"]):
            if f.lower() == func.lower():
                if note and not n:
                    self.entries[key]["funcs"][idx] = (f, note)
                return
        self.entries[key]["funcs"].append((func, note))

    def _load_dir(self, db_dir):
        try:
            names = os.listdir(db_dir)
        except OSError:
            return
        # 先读 "dll|func|note" 文件 (便捷HOOK 等), 让备注优先;
        # 再读 "<dll>.dll.txt" 每行一个函数的数据库文件。
        def has_pipe(fn):
            p = os.path.join(db_dir, fn)
            try:
                if not os.path.isfile(p):
                    return False
                return "|" in _read_text(p)
            except OSError:
                return False

        ordered = sorted(names, key=lambda fn: (0 if has_pipe(fn) else 1, fn.lower()))
        for fn in ordered:
            if not fn.lower().endswith(".txt"):
                continue
            path = os.path.join(db_dir, fn)
            if not os.path.isfile(path):
                continue
            text = _read_text(path)
            # 便捷HOOK / 任意含 '|' 的文件 -> dll|func|note
            if "|" in text:
                for line in text.splitlines():
                    line = line.strip()
                    if not line or line.startswith(";") or line.startswith("#"):
                        continue
                    parts = line.split("|")
                    if len(parts) >= 2 and parts[0].strip() and parts[1].strip():
                        note = parts[2].strip() if len(parts) > 2 else ""
                        self._add(parts[0].strip(), parts[1].strip(), note)
                continue
            # <dll>.dll.txt -> 每行一个函数
            base = fn[:-4]  # 去掉 .txt
            dll = base if base.lower().endswith(".dll") else base + ".dll"
            for line in text.splitlines():
                fn_name = line.strip()
                if not fn_name or fn_name.startswith(";") or fn_name.startswith("#"):
                    continue
                self._add(dll, fn_name, "")

    def _load_embedded(self):
        for dll, funcs in EMBEDDED_DB.items():
            for f in funcs:
                self._add(dll, f, "")

    # -- 查询 -------------------------------------------------------------
    def dlls(self):
        return [self.entries[k]["dll"] for k in self.order]

    def funcs(self, dll):
        key = dll.lower()
        if not key.endswith(".dll"):
            key += ".dll"
        e = self.entries.get(key)
        return e["funcs"] if e else None

    def find(self, dll, func):
        key = dll.lower()
        if not key.endswith(".dll"):
            key += ".dll"
        e = self.entries.get(key)
        if not e:
            return None
        for f, note in e["funcs"]:
            if f.lower() == func.lower():
                return (e["dll"], f, note)
        return None

    def total(self):
        return sum(len(self.entries[k]["funcs"]) for k in self.order)


def _read_text(path):
    """读取文本, 优先 GBK (原程序中文环境), 回退 UTF-8 / latin-1。"""
    for enc in ("gbk", "utf-8-sig", "utf-8", "latin-1"):
        try:
            with open(path, "r", encoding=enc) as f:
                return f.read()
        except (UnicodeDecodeError, LookupError):
            continue
        except OSError:
            return ""
    return ""


# ---------------------------------------------------------------------------
# 字节补丁 project.json 解析
# ---------------------------------------------------------------------------

def _parse_bytes(spec):
    """把 patch 的字节字段解析为 bytes。支持:
       "bytes": "90 EB CC" / "90EBCC"  -> 十六进制串
       "bytes": [0x90, 0xEB]           -> 整数列表
       "data" : 同上
    """
    if spec is None:
        raise ValueError("补丁缺少字节数据 (bytes/data)")
    if isinstance(spec, (list, tuple)):
        return bytes(int(x) & 0xFF for x in spec)
    if isinstance(spec, str):
        s = "".join(spec.split())  # 去空白
        if s.lower().startswith("0x"):
            s = s[2:]
        if len(s) % 2 != 0:
            raise ValueError("十六进制串长度必须为偶数: %r" % spec)
        try:
            return bytes.fromhex(s)
        except ValueError:
            raise ValueError("无法解析十六进制字节: %r" % spec)
    raise ValueError("不支持的字节字段类型: %r" % type(spec))


def _patch_offset(pe, patch, default_image_base):
    """根据补丁描述计算文件偏移。返回 (offset, kind)。"""
    if "offset" in patch:
        return int(patch["offset"], 0) if isinstance(patch["offset"], str) else int(patch["offset"]), "offset"
    if "rva" in patch:
        rva = int(patch["rva"], 0) if isinstance(patch["rva"], str) else int(patch["rva"])
        return pe.rva_to_offset(rva), "rva"
    if "va" in patch:
        va = int(patch["va"], 0) if isinstance(patch["va"], str) else int(patch["va"])
        ib = patch.get("image_base", default_image_base)
        if ib is None:
            ib = pe.image_base
        rva = va - int(ib)
        if rva < 0:
            raise PEError("VA 0x%X 小于 image_base 0x%X" % (va, ib))
        return pe.rva_to_offset(rva), "va"
    raise ValueError("补丁必须包含 offset / rva / va 之一")


# ---------------------------------------------------------------------------
# 子命令实现
# ---------------------------------------------------------------------------

def cmd_info(args):
    path = args.pe
    with open(path, "rb") as f:
        data = f.read()
    pe = PE(data, path)

    print("PE 信息: %s" % path)
    print("  文件大小      : %d 字节 (0x%X)" % (len(data), len(data)))
    print("  机器类型      : %s (0x%X)" % (pe.machine_name(), pe.machine))
    print("  可选头        : %s (magic=0x%X)" % ("PE32+" if pe.is64 else "PE32", pe.magic))
    print("  时间戳        : 0x%08X" % pe.timestamp)
    print("  入口点 RVA    : 0x%08X  (VA 0x%X)" % (pe.entry_rva, pe.rva_to_va(pe.entry_rva)))
    print("  映像基址      : 0x%X" % pe.image_base)
    print("  节对齐/文件对齐: 0x%X / 0x%X" % (pe.section_align, pe.file_align))
    print("  SizeOfImage   : 0x%X" % pe.size_image)
    print("  子系统        : %s" % pe.subsystem_name())
    print("  节数          : %d" % pe.num_sections)
    print("  CRC32         : %08X" % pe.crc32())
    print("  MD5           : %s" % pe.md5())
    print()

    print("节区表:")
    print("  %-9s %-10s %-10s %-10s %-10s %-10s" %
          ("名称", "VA(RVA)", "VSize", "RawPtr", "RawSize", "Flags"))
    for s in pe.sections:
        print("  %-9s 0x%08X 0x%08X 0x%08X 0x%08X 0x%08X" %
              (s.name or "<none>", s.vaddr, s.vsize, s.rawptr, s.rawsize, s.chars))
    print()

    print("VA / RVA / 文件偏移 映射:")
    print("  %-9s %-22s %-22s %-22s" %
          ("名称", "VA 范围", "RVA 范围", "文件偏移范围"))
    for s in pe.sections:
        span = max(s.vsize, s.rawsize)
        va0 = pe.rva_to_va(s.vaddr)
        va1 = pe.rva_to_va(s.vaddr + span)
        print("  %-9s 0x%08X-0x%08X 0x%08X-0x%08X 0x%08X-0x%08X" %
              (s.name or "<none>", va0, va1, s.vaddr, s.vaddr + span,
               s.rawptr, s.rawptr + s.rawsize))
    # 入口点映射
    try:
        eo = pe.rva_to_offset(pe.entry_rva)
        print("\n  入口点: RVA 0x%08X -> 文件偏移 0x%08X" % (pe.entry_rva, eo))
    except PEError as e:
        print("\n  入口点映射失败: %s" % e)
    return 0


def cmd_apply(args):
    target = args.target
    proj_path = args.project
    with open(target, "rb") as f:
        data = bytearray(f.read())
    pe = PE(bytes(data), target)

    with open(proj_path, "r", encoding="utf-8") as f:
        proj = json.load(f)

    patches = proj.get("patches")
    if patches is None and isinstance(proj, list):
        patches = proj
    if not isinstance(patches, list):
        raise ValueError("project.json 缺少 patches 数组")

    default_ib = proj.get("image_base") if isinstance(proj, dict) else None

    applied = 0
    print("目标: %s  (image_base=0x%X)" % (target, pe.image_base))
    print("补丁项目: %s  共 %d 条" % (proj_path, len(patches)))
    for i, patch in enumerate(patches):
        off, kind = _patch_offset(pe, patch, default_ib)
        raw = patch.get("bytes", patch.get("data"))
        blob = _parse_bytes(raw)
        if off < 0 or off + len(blob) > len(data):
            raise PEError("第 %d 条补丁越界: offset 0x%X + %d > 文件大小 0x%X"
                          % (i, off, len(blob), len(data)))
        old = bytes(data[off:off + len(blob)])
        data[off:off + len(blob)] = blob
        applied += 1
        print("  [%d] %-6s @0x%08X  %s  (原: %s)" %
              (i, kind, off, blob.hex(" "), old.hex(" ") if old else "-"))

    out = args.output or (target + ".patched")
    with open(out, "wb") as f:
        f.write(data)
    print("\n已应用 %d 条补丁 -> %s" % (applied, out))
    print("新 CRC32: %08X   MD5: %s" %
          (zlib.crc32(bytes(data)) & 0xFFFFFFFF, hashlib.md5(bytes(data)).hexdigest()))
    return 0


def _fmt_stub(hook_addr, cave_addr, tramp_addr, orig5):
    """生成内联挂点的字节模板与说明。返回 (plan_lines, concrete 是否可算)。"""
    lines = []
    concrete = None
    # 1) 目标处的 5 字节 JMP E9 rel32 -> handler(cave)
    rel_to_handler = cave_addr - (hook_addr + 5)
    jmp = b"\xE9" + struct.pack("<i", rel_to_handler)
    lines.append("目标处 (覆盖 API 头 5 字节) @ 0x%08X:" % hook_addr)
    lines.append("    %s          ; E9 rel32 -> 0x%08X (handler/code cave)" %
                 (jmp.hex(" "), cave_addr))
    lines.append("    ; rel32 = cave - (hook+5) = 0x%08X - 0x%08X = %d (0x%08X)" %
                 (cave_addr, hook_addr + 5, rel_to_handler, rel_to_handler & 0xFFFFFFFF))
    lines.append("")

    # 2) 蹦床 (trampoline) 在 code cave: pushad + 原5字节 + popad + jmp 回 hook+5
    tramp = b"\x60" + orig5 + b"\x61"          # pushad / <orig5> / popad
    back = (hook_addr + 5) - (tramp_addr + len(tramp) + 4)
    jmp_back = b"\xE9" + struct.pack("<i", back)
    lines.append("蹦床 (trampoline) @ 0x%08X  (执行原始 5 字节后跳回):" % tramp_addr)
    lines.append("    60                      ; pushad")
    lines.append("    %s      ; 原始 5 字节 (被覆盖的 API 序言)" % orig5.hex(" "))
    lines.append("    61                      ; popad")
    lines.append("    %s   ; E9 rel32 -> 0x%08X (hook+5)" %
                 (jmp_back.hex(" "), hook_addr + 5))
    lines.append("    ; rel32_back = (hook+5) - (tramp+7+4) = %d (0x%08X)" %
                 (back, back & 0xFFFFFFFF))
    lines.append("")

    # 3) 完整蹦床字节串
    full_tramp = tramp + jmp_back
    lines.append("蹦床完整字节 (%d 字节): %s" % (len(full_tramp), full_tramp.hex(" ")))
    concrete = {
        "hook_jmp": jmp,
        "trampoline": full_tramp,
        "rel_to_handler": rel_to_handler,
        "rel_back": back,
    }
    return lines, concrete


def cmd_hook(args):
    db = HookDB(args.db_dir)
    if args.list:
        return _hook_list(db)

    dll = args.dll
    func = args.func
    hit = db.find(dll, func)
    if not hit:
        # 给出最相近的建议
        key = dll.lower()
        if not key.endswith(".dll"):
            key += ".dll"
        e = db.entries.get(key)
        if not e:
            sys.stderr.write("错误: 数据库中没有 DLL '%s' (可用: %s)\n" %
                             (dll, ", ".join(db.dlls())))
        else:
            names = [f for f, _ in e["funcs"]]
            import difflib
            close = difflib.get_close_matches(func, names, n=5, cutoff=0.4)
            sys.stderr.write("错误: %s 中找不到函数 '%s'.\n" % (e["dll"], func))
            if close:
                sys.stderr.write("  最相近: %s\n" % ", ".join(close))
        return 2

    real_dll, real_func, note = hit
    print("Inline Hook 方案: %s!%s" % (real_dll, real_func))
    if note:
        print("  备注: %s" % note)
    print("  数据库: %s (%s, 共 %d 个 API)" %
          (db.dir or "<embedded>", db.source, db.total()))
    print()

    # 地址参数 (可选)。未给出时用占位地址, 仅演示 rel32 计算。
    hook_addr = _addr(args.hook_addr, 0x00401000)
    cave_addr = _addr(args.cave_addr, 0x00500000)
    tramp_addr = _addr(args.tramp_addr, cave_addr + 0x100)
    orig5 = _parse_bytes(args.orig_bytes) if args.orig_bytes else b"\x55\x8B\xEC\x83\xEC"
    if len(orig5) != 5:
        sys.stderr.write("警告: 原始字节应为 5 字节, 实际 %d 字节\n" % len(orig5))
        orig5 = (orig5 + b"\x90" * 5)[:5]

    stub_lines, concrete = _fmt_stub(hook_addr, cave_addr, tramp_addr, orig5)
    print("\n".join(stub_lines))
    print("说明: 5 字节 E9 是 x86 近跳转, 覆盖 API 头 5 字节; 代码洞(cave)通常")
    print("      追加在目标模块 .text 末尾或新加节; 若原始 5 字节内含相对 call/jmp")
    print("      (E8/E9/EB/70-7F), 蹦床里需把 rel 修正为相对蹦床的新位置。")
    if args.assemble:
        print()
        print("NASM 风格清单 (占位地址, 用 --hook-addr/--cave-addr 改):")
        print("  ; --- 目标处 ---")
        print("  hook_addr:  jmp handler        ; E9 -> cave")
        print("  ; --- handler (cave) ---")
        print("handler:    pushad")
        print("            ; 你的 Hook 逻辑 / call 用户过程")
        print("            popad")
        print("            jmp trampoline")
        print("  ; --- trampoline (cave) ---")
        print("trampoline: pushad")
        print("            %s   ; 原始 5 字节" % orig5.hex(" "))
        print("            popad")
        print("            jmp hook_addr+5")
    return 0


def _hook_list(db):
    print("Inline Hook 可用 API (来源: %s [%s])" % (db.dir or "<embedded>", db.source))
    print("共 %d 个 DLL / %d 个 API\n" % (len(db.order), db.total()))
    for k in db.order:
        e = db.entries[k]
        funcs = e["funcs"]
        print("== %s  (%d) ==" % (e["dll"], len(funcs)))
        # 每行 6 个, 紧凑输出
        names = [f for f, _ in funcs]
        for i in range(0, len(names), 6):
            print("  " + "  ".join("%-22s" % n for n in names[i:i + 6]))
        print()
    return 0


def cmd_checkhook(args):
    db = HookDB(args.db_dir)
    dll = args.dll
    funcs = db.funcs(dll)
    if funcs is None:
        sys.stderr.write("错误: 数据库中没有 DLL '%s'\n可用: %s\n" %
                         (dll, ", ".join(db.dlls())))
        return 2
    print("%s  可挂 API (%d 个)  [来源: %s]" %
          (real_dll_name(db, dll), len(funcs), db.dir or "<embedded>"))
    for i, (f, note) in enumerate(funcs):
        if note:
            print("  %4d  %-32s %s" % (i, f, note))
        else:
            print("  %4d  %s" % (i, f))
    return 0


def _addr(val, default):
    if val is None:
        return default
    if isinstance(val, str):
        return int(val, 0)
    return int(val)


def real_dll_name(db, dll):
    key = dll.lower()
    if not key.endswith(".dll"):
        key += ".dll"
    e = db.entries.get(key)
    return e["dll"] if e else dll


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------

def build_parser():
    p = argparse.ArgumentParser(
        prog="main.py",
        description="%s -> Python CLI 重写版 (离线 PE 字节补丁 + Inline Hook 方案生成)" % TOOL_NAME,
        epilog="子命令: apply / info / hook / checkhook",
    )
    sub = p.add_subparsers(dest="cmd", metavar="<命令>")

    # apply
    pa = sub.add_parser("apply", help="按 project.json 对目标 PE 打字节补丁 (offset/rva/va)")
    pa.add_argument("target", help="目标 EXE/DLL 文件")
    pa.add_argument("project", help="补丁项目 JSON (含 patches 数组)")
    pa.add_argument("-o", "--output", help="输出文件 (默认 <target>.patched)")
    pa.set_defaults(handler=cmd_apply)

    # info
    pi = sub.add_parser("info", help="显示 PE 节区 / CRC32 / MD5 / VA-RVA-offset 映射")
    pi.add_argument("pe", help="PE 文件")
    pi.set_defaults(handler=cmd_info)

    # hook
    ph = sub.add_parser("hook", help="为指定 DLL+API 生成 5 字节 E9 内联挂点方案")
    ph.add_argument("dll", nargs="?", help="DLL 名 (如 user32.dll)")
    ph.add_argument("func", nargs="?", help="函数名 (如 MessageBoxA)")
    ph.add_argument("--list", action="store_true", help="列出数据库中所有可用 API")
    ph.add_argument("--db-dir", help="Inline Hook 数据库目录 (覆盖默认)")
    ph.add_argument("--hook-addr", help="API 入口 VA (默认 0x00401000 占位)")
    ph.add_argument("--cave-addr", help="代码洞 VA (默认 0x00500000 占位)")
    ph.add_argument("--tramp-addr", help="蹦床 VA (默认 cave+0x100)")
    ph.add_argument("--orig-bytes", help="被覆盖的原始 5 字节 (hex), 默认 55 8B EC 83 EC")
    ph.add_argument("--assemble", action="store_true", help="额外打印 NASM 风格清单")
    ph.set_defaults(handler=cmd_hook)

    # checkhook
    pc = sub.add_parser("checkhook", help="列出指定 DLL 的全部可挂 API")
    pc.add_argument("dll", help="DLL 名 (如 kernel32.dll)")
    pc.add_argument("--db-dir", help="Inline Hook 数据库目录 (覆盖默认)")
    pc.set_defaults(handler=cmd_checkhook)

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 0
    try:
        return args.handler(args)
    except (PEError, ValueError, OSError, json.JSONDecodeError) as e:
        sys.stderr.write("错误: %s\n" % e)
        return 1


if __name__ == "__main__":
    sys.exit(main())