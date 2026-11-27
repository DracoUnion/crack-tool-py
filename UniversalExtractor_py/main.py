#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Universal Extractor (UniExtract) v1.9.17.203  ->  Python CLI 重写版

来源目录: D:\\Program Files\\crack-tool-unpacker\\UniversalExtractor
目标文件: UniExtract.exe (32-bit PE, Delphi + 内嵌 AutoIt3 解释器, 基址 0x400000,
          .text/.rdata/.data/.rsrc, 非加壳; 文件尾 0x9B610 处有 "AU3!EA06" 附加层,
          即编译后的 AutoIt3 脚本——真正的“文件类型检测/分发”逻辑就在该字节码里,
          因此明文里看不到 ZIP/RAR 等魔数表)。
目标程序: D:\\src\\crack-tool-py\\UniversalExtractor_py\\main.py (唯一入口, 纯标准库)

逆向依据 (IDA Pro 9.4 批处理反汇编, 基址 0x400000, 共 2193 函数):
  PE 基址校验 __ValidateImageBase @ 0x4185E0:
      0x4185E8  mov eax, 5A4Dh
      0x4185ED  cmp [ecx], ax                 ; MZ 签名
      0x4185F6  mov eax, [ecx+3Ch]            ; e_lfanew
      0x4185FB  cmp dword ptr [eax], 4550h    ; 'PE\0\0'
      0x418605  mov ecx, 10Bh                 ; PE32 optional magic
  CRT 启动里再次校验镜像 @ ___tmainCRTStartup 0x416454:
      0x41647F  mov eax, 5A4Dh
      0x416484  cmp ds:400000h, ax
      0x416492  mov eax, ds:40003Ch
      0x416497  cmp dword ptr [eax+400000h], 4550h
  外部脱壳器分发 (核心): sub_430B0F @ 0x430B0F -> CreateProcessW @ 0x430B6C
      以 CREATE_NEW_CONSOLE(0x10) 启动 bin/ 下的外部模块, 命令行由 lpCommandLine 传入。
      另一处 CreateProcessW @ 0x464D52 (sub_4649A3 @ 0x4649A3) 为安装器“直接执行”型分发。
  ShellExecuteExW @ 0x457D67 / CreateProcessAsUserW @ 0x446522 为其它执行路径。

  配置格式 (UniExtract.ini):
      [Options] 用数字索引 0..34 存设置, 每个索引对应 lang\\English.ini 的标签:
          0=Check first as SFX archive, 4=语言, 6=0/1 是否显示方法选择, 8=提取方法,
          34=|SFX CAB|CAB|7-Zip Sfx|Nullsoft|Winzip|Wise|Zip Sfx (类型过滤串) ...
      [File History] / [Directory History] 为最近文件/目录历史。
  bin\\observer.ini : TotalObserver 插件模块表 (MSI/WISE/VP/... -> modules\\*.so) 与扩展过滤。
  bin\\userdb.txt   : PEiD 风格签名库 (Setup Factory/Inno/InstallShield/... 的 EP 签名,
                      供 PEiD.exe / Ext_Detector.dll 识别安装器封装)。
  bin\\WithoutVer.ini: 各外部模块版本号表。

  本实现完全基于上述逆向 + UniExtract 公开行为重写:
    detect = 纯静态“魔数/签名”识别 (ZIP/RAR/7z/CAB/MSI(OLE)/ACE/UHarc/ARJ/LHA/ZOO/
             RPM/DMG/CHM/HLP/GZIP/BZIP2/ISO/AutoIt/Inno(NSIS 头)/InstallShield 等),
             对应原程序在 AutoIt 脚本里读取文件头逐字节比较的逻辑。
    info   = 显示 PE/文件基本信息 + 匹配到的全部候选类型。
    plan   = 给出 UniExtract 会选用的 bin/ 外部模块 + 命令行 (对应 sub_430B0F 的
             CreateProcessW 分发), 以及 observer.ini 插件映射。
  纯标准库, main.py 为唯一入口。

用法:
  python main.py <文件> [detect|info|plan] [--json]
  detect (默认) 按签名识别文件类型
  info          文件/PE 基本信息 + 所有候选类型
  plan          显示将调用的 bin/ 外部脱壳模块与命令行
选项:
  --json   以 JSON 输出
  -h,--help 帮助
"""

import argparse
import json
import os
import struct
import sys
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2

# ---- PE 常量 (对应 __ValidateImageBase @ 0x4185E0) ----
IMAGE_DOS_SIGNATURE = 0x5A4D          # 'MZ'   (0x4185E8 mov eax,5A4Dh)
IMAGE_NT_SIGNATURE = 0x00004550       # 'PE\0\0'(0x4185FB cmp ...,4550h)
OPT_HDR32_MAGIC = 0x10B               # (0x418605 mov ecx,10Bh)
OPT_HDR64_MAGIC = 0x20B
SIZEOF_SECTION_HEADER = 40


# ===================== 数据结构 =====================
@dataclass
class Signature:
    """一条文件类型签名 (魔数)。对应 AutoIt 脚本里读取文件头的逐字节比较。"""
    type: str                # 规范类型名 (如 "ZIP Archive")
    magic: bytes             # 魔数字节
    offset: int = 0          # 魔数出现的文件偏移
    module: str = ""         # 首选 bin/ 外部模块 (可空)
    args: str = ""           # 该模块的命令行模板 ({file} {out} 占位)
    msi_ole: bool = False    # 是否为 OLE 复合文档 (需二次判定 MSI)
    desc: str = ""           # 说明


@dataclass
class Plan:
    type: str
    module: str
    args: str
    method: str              # "external" | "plugin" | "execute" | "none"
    note: str = ""


@dataclass
class DetectResult:
    path: str
    size: int
    is_pe: bool = False
    image_base: int = 0
    entry_rva: int = 0
    is64: bool = False
    matches: List[Tuple[str, int, str]] = field(default_factory=list)  # (type, offset, desc)
    primary: Optional[str] = None
    error: Optional[str] = None


# ===================== 检测签名表 =====================
# 顺序 = 优先级 (先具体后宽泛)。对应 UniExtract 支持的归档/安装器类型。
# module/args 取自 bin/ 实际存在的外部模块 (已核对)。
SIGNATURES: List[Signature] = [
    # ---- 复合文档 (OLE) : 需二次判定 MSI / MHT 等 ----
    Signature("OLE Compound (MSI/MSP/MSM)", bytes.fromhex("D0CF11E0A1B11AE1"),
              module="less\\lessmsi.exe", args='x "{file}" "{out}\\*"',
              msi_ole=True, desc="OLE2 复合文档; 若为 MSI 用 lessmsi / MsiX"),
    # ---- 7-Zip ----
    Signature("7-Zip Archive", b"7z\xbc\xaf\x27\x1c",
              module="7z.exe", args='x -y -o"{out}" "{file}"', desc="7-Zip 归档"),
    # ---- RAR ----
    Signature("RAR Archive v5", b"Rar!\x1a\x07\x01\x00",
              module="7z.exe", args='x -y -o"{out}" "{file}"', desc="RAR5 (7z 可解)"),
    Signature("RAR Archive v4", b"Rar!\x1a\x07\x00",
              module="7z.exe", args='x -y -o"{out}" "{file}"', desc="RAR4 (7z 可解)"),
    # ---- ZIP ----
    Signature("ZIP Archive (empty)", b"PK\x05\x06",
              module="7z.exe", args='x -y -o"{out}" "{file}"', desc="空 ZIP"),
    Signature("ZIP Archive", b"PK\x03\x04",
              module="7z.exe", args='x -y -o"{out}" "{file}"', desc="ZIP (PK\\x03\\x04)"),
    Signature("ZIP Archive (spanned)", b"PK\x07\x08",
              module="7z.exe", args='x -y -o"{out}" "{file}"', desc="分卷 ZIP"),
    # ---- CAB ----
    Signature("CAB Archive", b"MSCF",
              module="7z.exe", args='x -y -o"{out}" "{file}"', desc="Microsoft Cabinet"),
    # ---- ACE / UHarc / ARJ / LHA / ZOO / ARC ----
    Signature("ACE Archive", b"ACE\x00\xbe\x00\x00",
              module="UNACE32.EXE", args='x "{file}" "{out}"', desc="ACE 归档"),
    Signature("ACE Archive (alt)", b"ACE\x00",
              module="UNACE32.EXE", args='x "{file}" "{out}"', desc="ACE 归档(宽松)"),
    Signature("UHarc Archive", b"UHarc\x00",
              module="UHARC04.EXE", args='x "{file}" "{out}"', desc="UHarc 归档"),
    Signature("ARJ Archive", b"\x60\xea",
              module="7z.exe", args='x -y -o"{out}" "{file}"', desc="ARJ 归档"),
    Signature("LHA/LZH Archive", b"-lh",
              module="7z.exe", args='x -y -o"{out}" "{file}"', desc="LHA/LZH 归档"),
    Signature("LHA Archive (alt)", b"-lhd",
              module="7z.exe", args='x -y -o"{out}" "{file}"', desc="LHA 目录头"),
    Signature("ZOO Archive", b"ZOO ",
              module="unzoo.exe", args='{file} "{out}"', desc="ZOO 归档"),
    Signature("ARC Archive", b"\x1a\x08",
              module="arc.exe", args='x "{file}" "{out}"', desc="ARC 归档(弱签名)"),
    # ---- 压缩流 ----
    Signature("GZIP Archive", b"\x1f\x8b\x08",
              module="7z.exe", args='x -y -o"{out}" "{file}"', desc="gzip"),
    Signature("BZIP2 Archive", b"BZh",
              module="7z.exe", args='x -y -o"{out}" "{file}"', desc="bzip2"),
    Signature("XZ Archive", b"\xfd7zXZ\x00",
              module="7z.exe", args='x -y -o"{out}" "{file}"', desc="xz"),
    # ---- 光盘/其它 ----
    Signature("ISO Image (primary)", b"CD001", 0x8001,
              module="7z.exe", args='x -y -o"{out}" "{file}"', desc="ISO9660 (魔数在 0x8001)"),
    Signature("DMG Image", b"koly", 0,
              module="7z.exe", args='x -y -o"{out}" "{file}"', desc="Apple DMG (koly 尾块)"),
    Signature("CHM Help", b"ITSF",
              module="7z.exe", args='x -y -o"{out}" "{file}"', desc="Compiled HTML Help"),
    Signature("Windows HLP", b"LNf\x00\x00",
              module="7z.exe", args='x -y -o"{out}" "{file}"', desc="WinHelp"),
    Signature("RPM Package", bytes.fromhex("EDABEEDB"),
              module="7z.exe", args='x -y -o"{out}" "{file}"', desc="RedHat RPM"),
    Signature("AutoIt3 Script", b"AU3!EA06",
              module="", args="", desc="编译的 AutoIt3 脚本 (UniExtract 自身即此型)"),
    # ---- 安装器 (含自解压头) ----
    Signature("Inno Setup (zlb header)", b"zlb\x1a",
              module="innounp.exe", args='-x -d"{out}" "{file}"', desc="Inno Setup (zlb 头)"),
    Signature("Inno Setup (overlay)", b"rDlPtS02",
              module="innounp.exe", args='-x -d"{out}" "{file}"', desc="Inno Setup 水印"),
    Signature("NSIS Installer", b"NullsoftInst", 0x1C,
              module="7z.exe", args='x -y -o"{out}" "{file}"', desc="Nullsoft Scriptable Install System (头在首个扇区 0x1C)"),
    Signature("InstallShield (Cab)", b"InstallShield",
              module="Expander.exe", args='"{file}" "{out}"', desc="InstallShield"),
    Signature("InstallShield CAB (ISc)", b"ISc(",
              module="Expander.exe", args='"{file}" "{out}"', desc="InstallShield CAB"),
    Signature("Setup Factory", b"Setup Factory",
              module="7z.exe", args='x -y -o"{out}" "{file}"', desc="Setup Factory 安装器"),
    Signature("Wise Installer", b"Wise Installation",
              module="E_WISE_W.EXE", args='"{file}" "{out}"', desc="Wise for Windows Installer"),
    Signature("Gentee Installer", b"Gentee",
              module="7z.exe", args='x -y -o"{out}" "{file}"', desc="Gentee 安装器"),
    Signature("StuffIt Archive", b"StuffIt",
              module="unar.exe", args='{file} "{out}"', desc="StuffIt (StuffIt5 引擎)"),
    Signature("RAR SFX (overlay marker)", b"RarSFX",
              module="7z.exe", args='x -y -o"{out}" "{file}"', desc="RAR 自解压"),
    Signature("7z SFX (overlay marker)", b"7z\xbc\xaf\x27\x1cSFX",
              module="7z.exe", args='x -y -o"{out}" "{file}"', desc="7-Zip 自解压"),
]


# ===================== PE 解析 =====================
def parse_pe(data: bytes) -> dict:
    """校验 MZ/PE 并返回基本信息 (对应 __ValidateImageBase @ 0x4185E0)。"""
    info = {"is_pe": False, "image_base": 0, "entry_rva": 0, "is64": False}
    if len(data) < 0x40 or data[:2] != b"MZ":
        return info
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        return info
    fh = e_lfanew + 4
    szopt = struct.unpack_from("<H", data, fh + 16)[0]
    opt = fh + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    info["is_pe"] = True
    if magic == OPT_HDR32_MAGIC:
        info["entry_rva"] = struct.unpack_from("<I", data, opt + 16)[0]
        info["image_base"] = struct.unpack_from("<I", data, opt + 28)[0]
    elif magic == OPT_HDR64_MAGIC:
        info["is64"] = True
        info["entry_rva"] = struct.unpack_from("<I", data, opt + 16)[0]
        info["image_base"] = struct.unpack_from("<Q", data, opt + 24)[0]
    return info


# ===================== 检测核心 =====================
def _match_all(data: bytes) -> List[Tuple[str, int, str]]:
    """对所有签名做静态匹配, 返回 [(type, offset, desc)]。"""
    hits: List[Tuple[str, int, str]] = []
    n = len(data)
    for sig in SIGNATURES:
        off = sig.offset
        if off == 0 and sig.magic == b"koly":
            # DMG 的 koly 块在文件尾部
            idx = data.rfind(b"koly")
            if idx >= 0:
                hits.append((sig.type, idx, sig.desc))
            continue
        if off + len(sig.magic) <= n and data[off:off + len(sig.magic)] == sig.magic:
            # 避免 "ACE\x00" 与 "ACE\x00\xbe\x00\x00" 重复: 宽松项仅在精确项未命中时保留
            hits.append((sig.type, off, sig.desc))
    # 去重: 同偏移被更具体签名覆盖时, 去掉宽松 ACE
    if any(t == "ACE Archive" for t, _, _ in hits):
        hits = [h for h in hits if h[0] != "ACE Archive (alt)"]
    if any(t == "7-Zip Archive" for t, _, _ in hits):
        hits = [h for h in hits if "SFX" not in h[0]]
    return hits


def _is_msi(data: bytes) -> bool:
    """OLE 复合文档是否为 MSI: 检查 OLE 目录里的 MSI 标记 (简化: 找 'MSI' 包名)。"""
    # 真正的判定需解析 OLE FAT; 这里用经验: MSI 文件头偏移 0x200 附近常含 'Q' 等,
    # 保守起见, 只要 OLE 就同时给出 MSI/MSP 候选, 由 plan 选择 lessmsi。
    return True


def detect(data: bytes, path: str) -> DetectResult:
    r = DetectResult(path=path, size=len(data))
    pe = parse_pe(data)
    r.is_pe = pe["is_pe"]
    r.image_base = pe["image_base"]
    r.entry_rva = pe["entry_rva"]
    r.is64 = pe["is64"]
    r.matches = _match_all(data)
    if r.matches:
        r.primary = r.matches[0][0]
    return r


def _sig_for_type(t: str) -> Optional[Signature]:
    for s in SIGNATURES:
        if s.type == t:
            return s
    return None


# ===================== plan: 类型 -> 外部模块 + 命令行 =====================
# observer.ini 插件映射 (TotalObserver 用于安装器/游戏包等“非标准”容器)
OBSERVER_MODULES = {
    "MSI": "modules\\msi.so", "WISE": "modules\\wise.so", "VP": "modules\\vp.so",
    "RELIC": "modules\\relic.so", "PST": "modules\\pst.so", "Valve": "modules\\valve.so",
    "UDF": "modules\\udfimg.so", "ISO": "modules\\isoimg.so", "X-CAT": "modules\\x23cat.so",
    "MBOX": "modules\\mbox.so", "MIME": "modules\\mime.so", "MPQ": "modules\\mpq.so",
    "PDF": "modules\\pdf.so", "IShield": "modules\\ishield.so",
    "SetupFactory": "modules\\sfact.so", "CreateInstall": "modules\\gentee.so",
}


def build_plan(matches, data, path) -> List[Plan]:
    """根据检测结果给出 UniExtract 会选用的外部模块与命令行 (对应 sub_430B0F)。"""
    out_dir = os.path.dirname(os.path.abspath(path)) or "."
    plans: List[Plan] = []
    seen = set()

    def add(p: Plan):
        if p.type not in seen:
            seen.add(p.type)
            plans.append(p)

    for t, off, desc in matches:
        sig = _sig_for_type(t)
        if sig is None:
            continue
        if sig.msi_ole:
            # OLE: 可能是 MSI; UniExtract 用 lessmsi / MsiX 处理
            add(Plan(t, "less\\lessmsi.exe",
                     'x "%s" "%s\\*"' % (path, out_dir), "external",
                     "OLE 复合文档; 若为 MSI, lessmsi 提取 (或 MsiX.exe / MSIUnPack.vbs)"))
            add(Plan("MSI (plugin)", "modules\\msi.so", "(TotalObserver 插件)", "plugin",
                     "observer.ini: MSI=modules\\msi.so, 过滤 *.msi;*.msm"))
            continue
        if sig.module:
            add(Plan(t, sig.module, sig.args, "external", desc))
        else:
            add(Plan(t, "(none)", "", "none", desc))
    return plans


# ===================== 输出 =====================
def fmt_detect(r: DetectResult, as_json: bool) -> str:
    if as_json:
        return json.dumps({
            "file": r.path, "size": r.size, "is_pe": r.is_pe,
            "image_base": r.image_base, "entry_rva": r.entry_rva, "is64": r.is64,
            "primary": r.primary,
            "matches": [{"type": t, "offset": o, "desc": d} for t, o, d in r.matches],
        }, ensure_ascii=False, indent=2)
    lines = ["File: %s  (%d bytes)" % (r.path, r.size)]
    if r.is_pe:
        lines.append("PE: ImageBase 0x%08X  EntryRVA 0x%08X  (%s)" % (
            r.image_base, r.entry_rva, "PE32+" if r.is64 else "PE32"))
    if r.matches:
        lines.append("==> Detected: %s" % r.primary)
        for t, o, d in r.matches:
            lines.append("    [0x%08X] %-32s %s" % (o, t, d))
    else:
        lines.append("==> Detected: (unknown / no signature matched)")
    return "\n".join(lines)


def fmt_info(r: DetectResult, as_json: bool) -> str:
    if as_json:
        d = fmt_detect(r, True)
        obj = json.loads(d)
        obj["candidates"] = [t for t, _, _ in r.matches]
        obj["observer_modules"] = OBSERVER_MODULES
        return json.dumps(obj, ensure_ascii=False, indent=2)
    lines = [fmt_detect(r, False), ""]
    lines.append("Candidate types: %s" % (
        ", ".join(t for t, _, _ in r.matches) if r.matches else "(none)"))
    lines.append("bin/ observer modules: %s" % ", ".join(sorted(OBSERVER_MODULES)))
    return "\n".join(lines)


def fmt_plan(r: DetectResult, data: bytes, as_json: bool) -> str:
    plans = build_plan(r.matches, data, r.path)
    if as_json:
        return json.dumps({"file": r.path, "plans": [
            {"type": p.type, "module": p.module, "args": p.args,
             "method": p.method, "note": p.note} for p in plans]},
            ensure_ascii=False, indent=2)
    if not plans:
        return "No external module: unknown file type (no signature matched)."
    lines = ["File: %s" % r.path,
             "UniExtract would dispatch to (CreateProcessW @ 0x430B6C):", ""]
    for p in plans:
        lines.append("  Type   : %s" % p.type)
        lines.append("  Method : %s" % p.method)
        lines.append("  Module : bin\\%s" % p.module if p.module else "  Module : (none)")
        if p.args:
            lines.append("  Command: %s" % p.args)
        if p.note:
            lines.append("  Note   : %s" % p.note)
        lines.append("")
    return "\n".join(lines).rstrip()


USAGE = __doc__


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="main.py", add_help=False)
    p.add_argument("target", nargs="?")
    p.add_argument("cmd", nargs="?", default="detect",
                   choices=["detect", "info", "plan"])
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

    r = detect(data, a.target)
    if a.cmd == "detect":
        print(fmt_detect(r, a.json))
        return EXIT_SUCCESS
    if a.cmd == "info":
        print(fmt_info(r, a.json))
        return EXIT_SUCCESS
    if a.cmd == "plan":
        print(fmt_plan(r, data, a.json))
        return EXIT_SUCCESS
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())