#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Armageddon 2.2 (Armadillo 脱壳器)  ->  Python CLI 重写版

来源目录: D:\\Program Files\\crack-tool-unpacker\\Armageddon_2.2\\Armageddon_v2.2final
目标文件: Armageddon.exe (32-bit 原生 Delphi PE, 基址 0x400000,
          区段 .text/CODE/.rdata/.data/DATA/BSS/.rsrc/.reloc, 未加壳)
          配套: BeaEngine.dll(反汇编引擎) / disasm.dll(导出 _Assemble@24) /
                Nanolib.dll(导出 _Init@12/_Analyze@16/_MakeLog@4/_WriteTableToFile@4
                + C++ 名称 ?DoNanomites@@/?Populate@@/?DoLogNanomites@@/?PopulateLog@@) /
                ARImpRec.DLL(ArtTeam Import Reconstructor, 导出
                SearchAndRebuildImports@28 / RebuildSectionsFromArmadillo@12 /
                GetNameFileOptimized@8 / UnpackPdataSection@12 —— 见 Readme.txt)

逆向依据 (IDA Pro 9.4 批处理反汇编, 基址 0x400000, 1598 函数, 入口 0x4051AB):
  本工具是 condzero 的 Armageddon 的 GUI 重写, 真正干活的是外部 DLL:
  它用 CreateProcessA 以挂起/调试方式启动被 Armadillo 保护的程序, 在
  Armadillo VM 把真正的代码解密/解压到内存后, 用 ReadProcessMemory 转储
  整个镜像 (CreateDump), 修复 Nanomites(INT3 断点) / IAT / 代码拼接,
  还原 OEP, 再交给 ARImpRec.DLL 重建导入表, 最后 WriteFile 落地。

  == Armadillo 检测 (sub_424D40 @0x424D40 "DetermineArmSections") ==
    1) 读文件头 0x1000 字节; 校验 IMAGE_DOS_SIGNATURE(0x5A4D)、
       IMAGE_NT_SIGNATURE(0x4550), 以及位于 e_lfanew+0x1A 的 "SR" 标记
       (0x425096: cmp [ebx+1Ah], 5253h; 不匹配则 0x42512F 报
        "Not an armadillo protected file!")。
       e_lfanew+0x1A = OptionalHeader+2 = MajorLinkerVersion/MinorLinkerVersion,
       Armadillo 把该处改写成 'S'(0x53),'R'(0x52) 作为指纹。
    2) 遍历节表 (每节 0x28 字节, 名称 8 字节, 0x425180 起循环), 把节名
       转大写后按名 + Characteristics 归类 (strncmp, 0x4251A4 起):
         .PDATA/PDATA            -> pdata   (char 0x0C0000040..0x0C1000000 且 rawsize!=0)
         .TEXT/.CODE/TEXT/CODE   -> text    (char 0x0E0000020..0x0E1000000 或 0x060000020..0x061000000)
         .ITEXT/ITEXT            -> itext   (同上, 第二代码段)
         .RDATA/RDATA            -> rdata   (char 0x040000040..0x051000000)
         .TEXT1/TEXT1            -> text1   (0x42574C: 第二 .text, Armadillo VM 外壳段)
         .ADATA/ADATA            -> adata   (0x42584C: 代码拼接段, 仅当已存在 text1 时)
         .RSRC/.RELOC/.DEBUG/.BSS/.TLS/.DATA/.IDATA/.DATA1 -> 各自角色
         UPX0/UPX1              -> UPX 压缩 (0x425360/0x4253AE, 先解压)
    3) 设计意图: Armadillo 会把 OEP 搬进 .text1, 用 .adata 做代码拼接,
       并保留 .pdata; 缺 .text1/.adata 或 "SR" 缺失即非 Armadillo。

  == 运行期确认 (sub_415500 @0x415500, 引用 0x41B099) ==
    调用 sub_424D40 后, 要求 .pdata(dword_46A4A8) 与 .text(dword_473B04)
    均存在, 且入口点落在 .text1 区间 [dword_4791CC, dword_47881C+size) 内;
    否则报 "This doesn't appear to be an Armadillo protected program!"(0x41B099)
    + "The EP is not within the range of PE section .text1"(0x41B0C2)。
    随后 "Tracing to OEP..."(0x4164A2) 单步/断点跟踪到 OEP, 再 CreateDump。

  == Nanomites 修复 ==
    Nanomite = Armadillo 插入代码流中的 INT3(0xCC) 断点, 由 VM 接管。
    0x45D2FC "No 0xCC Opcode Found, No INT3 Breakpoint Found";
    0x421774/0x4217C9 "%s INT3 processed..." / "%s INT3 resolved...";
    sub_4211F0/sub_4218E0 遍历 INT3 表(dword_4694FC)逐条处理并还原;
    反汇编由 BeaEngine.dll + disasm.dll(_Assemble@24, 0x4175E0/0x4214B4) 完成;
    Nanolib.dll 的 ?DoNanomites@@/?Populate@@(0x42A5D0/0x42A6B5) 负责分析/填表。

  == IAT 消除 / 重定向 / 重建 ==
    DetermineIATElimination(sub_41D980 @0x41D980, "IAT Elimination Disabled!"
      0x41E0E9): Armadillo 会消除/搬走原始导入表; DoIATElimination 选一个可用
      节(.idata/.data1/.bss/.Reloc, 0x41DE43 起)用 VirtualAlloc+VirtualProtectEx
      +WriteProcessMemory 重建 IAT; "IAT elimination section: %s"(0x41E10A),
      "No usable PE section available for IAT elimination"(0x460C40)。
    IAT Variable/Fixed Redirection(sub_41EAD0/其它, 0x41F09E/0x41E3F0):
      "IAT Variable Redirection Disabled!" / "IAT Fixed Redirection Disabled!"。
    最终导入表由 ARImpRec.DLL 的 SearchAndRebuildImports@28 重建
      (sub_4237F0 @0x4237F0: "Rebuilding Imports..."0x423FFE,
       "Rebuilding Sections..."0x424068, GetNameFileOptimized)。
    输出 "IAT RVA: %08X"(0x45ECF0) / "IAT Size: %08X"(0x45ED00) /
      "OEP VA/RVA"(0x45ED10/0x45ED1C)。

  本 Python 实现完全基于上述逆向逻辑重写, 纯标准库, main.py 为唯一入口。
  由于原版脱壳依赖 Windows + 多个外部 DLL + 运行被壳程序, 本实现做 *静态等效*:
    detect   静态 Armadillo 检测 (MZ/PE/SR 指纹 + 节角色分类 + EP 是否在 .text1)
    info     PE 头 / 节表 / 角色 / 数据目录 全量信息
    analyze  Nanomite(0xCC) 扫描 + IAT 消除/重定向分析 + OEP/拼接/UPX 判定

用法:
  python main.py <目标PE文件> [detect|info|analyze] [--json]
命令:
  detect  (默认) Armadillo 检测, 给出是否加壳及依据
  info    列出 PE 头、节表(含 Armadillo 角色标注)、导入目录
  analyze Nanomite / IAT / OEP / 代码拼接 综合分析
选项:
  --json  以 JSON 输出
  -h,--help 帮助
"""

import argparse
import json
import math
import struct
import sys
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2

IMAGE_DOS_SIGNATURE = 0x5A4D
IMAGE_NT_SIGNATURE = 0x0004550
IMAGE_SR_SIGNATURE = 0x5253          # 'S'(0x53),'R'(0x52) = Armadillo 指纹
OPT_HDR32_MAGIC = 0x10B
OPT_HDR64_MAGIC = 0x20B
SIZEOF_SECTION_HEADER = 40

# Armadillo 在 e_lfanew+0x1A 写入 "SR" (OptionalHeader+2 = 链接器版本)
ARMADILLO_SR_OFFSET = 0x1A

# 节 Characteristics 范围 (直接取自 sub_424D40 的 cmp 边界)
EXEC_WR_RANGE = (0x0E0000020, 0x0E1000000)   # 可执行+读+写 (text)
EXEC_RD_RANGE = (0x060000020, 0x061000000)   # 代码+可执行+读 (text/CODE)
RDATA_RANGE = (0x040000040, 0x051000000)     # 只读数据 (rdata)
DATA_RANGE = (0x0C0000040, 0x0C1000000)      # 可读可写已初始化数据 (data/idata/pdata)

# Armadillo 关键节名 (大写, 去前导点后比较)
SEC_TEXT = ("TEXT", "CODE")
SEC_ITEXT = ("ITEXT",)
SEC_TEXT1 = ("TEXT1",)
SEC_ADATA = ("ADATA",)          # 代码拼接段
SEC_RDATA = ("RDATA",)
SEC_PDATA = ("PDATA",)
SEC_RSRC = ("RSRC",)
SEC_RELOC = ("RELOC",)
SEC_BSS = ("BSS",)
SEC_DATA = ("DATA",)
SEC_IDATA = ("IDATA",)
SEC_DATA1 = ("DATA1",)


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
    role: str = "?"           # Armadillo 角色 (text/text1/adata/...)

    @property
    def is_executable(self) -> bool:
        return bool(self.characteristics & 0x20000000)

    @property
    def is_writable(self) -> bool:
        return bool(self.characteristics & 0x80000000)

    @property
    def is_readable(self) -> bool:
        return bool(self.characteristics & 0x40000000)

    @property
    def vspan(self) -> int:
        return max(self.virtual_size, self.raw_size)


@dataclass
class PeFile:
    path: str
    data: bytes
    image_base: int = 0
    entry_rva: int = 0
    entry_off: int = 0
    size_of_image: int = 0
    subsystem: int = 0
    linker_version: int = 0
    is64: bool = False
    sections: List[Section] = field(default_factory=list)
    import_rva: int = 0
    import_size: int = 0
    is_pe: bool = True
    error: Optional[str] = None


def _ent(b: bytes) -> float:
    if not b:
        return 0.0
    from collections import Counter
    c = Counter(b)
    n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def _rva_to_off(sections: List[Section], rva: int) -> int:
    for s in sections:
        if s.virtual_address <= rva < s.virtual_address + s.vspan:
            return s.raw_address + (rva - s.virtual_address)
    return rva


def section_of_rva(pe: "PeFile", rva: int) -> Optional[Section]:
    for s in pe.sections:
        if s.virtual_address <= rva < s.virtual_address + s.vspan:
            return s
    return None


def _in_range(v: int, rng: Tuple[int, int]) -> bool:
    return rng[0] <= v <= rng[1]


def parse_pe(data: bytes, path: str) -> PeFile:
    pe = PeFile(path=path, data=data)
    if len(data) < 0x40 or data[:2] != b"MZ":
        pe.is_pe = False
        pe.error = "not a PE (no MZ / IMAGE_DOS_SIGNATURE)"
        return pe
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\0\0":
        pe.is_pe = False
        pe.error = "not a PE (no PE signature / IMAGE_NT_SIGNATURE)"
        return pe
    pe.linker_version = struct.unpack_from("<H", data, e_lfanew + ARMADILLO_SR_OFFSET)[0]
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
        dd = opt + 96
    elif magic == OPT_HDR64_MAGIC:
        pe.is64 = True
        pe.entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        pe.image_base = struct.unpack_from("<Q", data, opt + 24)[0]
        pe.size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
        pe.subsystem = struct.unpack_from("<H", data, opt + 68)[0]
        dd = opt + 112
    else:
        pe.is_pe = False
        pe.error = "unsupported optional header magic 0x%04X" % magic
        return pe
    # 数据目录第 1 项 = 导入表
    if dd + 16 <= len(data):
        pe.import_rva, pe.import_size = struct.unpack_from("<II", data, dd + 8)
    st = opt + szopt
    for i in range(nsec):
        o = st + i * SIZEOF_SECTION_HEADER
        if o + SIZEOF_SECTION_HEADER > len(data):
            break
        nm = data[o:o + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        vs, va, rs, ra = struct.unpack_from("<IIII", data, o + 8)
        ch = struct.unpack_from("<I", data, o + 36)[0]
        sec = Section(nm, vs, va, rs, ra, ch)
        sec.role = classify_section(sec)
        pe.sections.append(sec)
    pe.entry_off = _rva_to_off(pe.sections, pe.entry_rva)
    return pe


# ===================== 节角色分类 (对应 sub_424D40) =====================
def _base(name: str) -> str:
    return name.lstrip(".").upper()


def classify_section(s: Section) -> str:
    """按节名 + Characteristics 归类, 严格复刻 sub_424D40 的判定顺序。

    返回: text/itext/text1/adata/rdata/pdata/rsrc/reloc/bss/data/idata/
          data1/tls/debug/upx0/upx1/?
    """
    b = _base(s.name)
    ch = s.characteristics
    # UPX
    if b in ("UPX0",):
        return "upx0"
    if b in ("UPX1",):
        return "upx1"
    # .PDATA / PDATA
    if b in SEC_PDATA:
        if _in_range(ch, DATA_RANGE) and s.raw_size != 0:
            return "pdata"
        return "pdata"
    # .TEXT/.CODE/TEXT/CODE
    if b in SEC_TEXT:
        if _in_range(ch, EXEC_WR_RANGE) or _in_range(ch, EXEC_RD_RANGE):
            return "text"
        if s.role == "?":
            return "text"
    # .ITEXT/ITEXT
    if b in SEC_ITEXT:
        if _in_range(ch, EXEC_WR_RANGE) or _in_range(ch, EXEC_RD_RANGE):
            return "itext"
        return "itext"
    # .RDATA/RDATA
    if b in SEC_RDATA:
        if _in_range(ch, RDATA_RANGE):
            return "rdata"
        return "rdata"
    # .TEXT1/TEXT1 -> 第二代码段
    if b in SEC_TEXT1:
        return "text1"
    # .ADATA/ADATA -> 代码拼接段
    if b in SEC_ADATA:
        if _in_range(ch, EXEC_WR_RANGE) or _in_range(ch, EXEC_RD_RANGE):
            return "adata"
        return "adata"
    if b in SEC_RSRC:
        return "rsrc"
    if b in SEC_RELOC:
        return "reloc"
    if b == "DEBUG":
        return "debug"
    if b in SEC_BSS:
        return "bss"
    if b == "TLS":
        return "tls"
    if b in SEC_IDATA:
        return "idata"
    if b in SEC_DATA1:
        return "data1"
    if b in SEC_DATA:
        return "data"
    return "?"


def _roles(pe: PeFile) -> dict:
    out: dict = {}
    for s in pe.sections:
        out.setdefault(s.role, s)
    return out


# ===================== Armadillo 检测 =====================
@dataclass
class DetectReport:
    file: str
    is_pe: bool
    error: Optional[str] = None
    image_base: int = 0
    entry_rva: int = 0
    is64: bool = False
    linker_version: int = 0
    mz_ok: bool = False
    pe_ok: bool = False
    sr_signature: bool = False
    has_text: bool = False
    has_text1: bool = False
    has_adata: bool = False
    has_pdata: bool = False
    has_upx: bool = False
    ep_in_text1: Optional[bool] = None
    is_armadillo: bool = False
    verdict: str = ""


def detect(pe: PeFile) -> DetectReport:
    r = DetectReport(file=pe.path, is_pe=pe.is_pe, error=pe.error)
    if not pe.is_pe:
        return r
    r.image_base = pe.image_base
    r.entry_rva = pe.entry_rva
    r.is64 = pe.is64
    r.linker_version = pe.linker_version
    r.mz_ok = pe.data[:2] == b"MZ"
    r.pe_ok = True  # parse_pe 已校验
    # "SR" 指纹 (sub_424D40 @0x425096)
    r.sr_signature = (pe.linker_version == IMAGE_SR_SIGNATURE)
    roles = _roles(pe)
    r.has_text = "text" in roles
    r.has_text1 = "text1" in roles
    r.has_adata = "adata" in roles
    r.has_pdata = "pdata" in roles
    r.has_upx = ("upx0" in roles) or ("upx1" in roles)
    # EP 是否在 .text1 (sub_415500 @0x41B041)
    if r.has_text1:
        t1 = roles["text1"]
        r.ep_in_text1 = t1.virtual_address <= pe.entry_rva < t1.virtual_address + t1.vspan
    # 综合判定 (静态等效):
    #   必要条件 = SR 指纹 (否则 0x42512F "Not an armadillo protected file!")
    #   确认条件 = 存在 .text1(或 .adata) 且 .pdata/.text 齐备 且 EP 落在 .text1
    static_hit = r.sr_signature and (r.has_text1 or r.has_adata)
    full_hit = (r.sr_signature and r.has_text1 and r.has_pdata and r.has_text
                and (r.ep_in_text1 is True))
    r.is_armadillo = bool(static_hit or full_hit)
    if not r.sr_signature:
        r.verdict = "非 Armadillo: e_lfanew+0x1A 链接器版本=0x%04X, 非 'SR'(0x5253)" % r.linker_version
    elif r.is_armadillo:
        r.verdict = "Armadillo: SR 指纹 + %s%s%s%s" % (
            ".text1" if r.has_text1 else "",
            " + .adata" if r.has_adata else "",
            " + .pdata" if r.has_pdata else "",
            " + EP∈.text1" if r.ep_in_text1 else "")
    else:
        r.verdict = "疑似 Armadillo(SR 命中)但缺 .text1/.adata 或 .pdata/.text"
    return r


# ===================== Nanomite / IAT 分析 =====================
@dataclass
class NanomiteReport:
    scanned_sections: List[str] = field(default_factory=list)
    cc_count: int = 0
    density: float = 0.0
    first_addrs: List[int] = field(default_factory=list)
    note: str = ""


@dataclass
class IatReport:
    import_rva: int = 0
    import_size: int = 0
    iat_rva: int = 0
    iat_size: int = 0
    descriptors: int = 0
    eliminated: bool = False
    redirected: bool = False
    redirect_section: Optional[str] = None
    modules: List[str] = field(default_factory=list)
    note: str = ""


@dataclass
class AnalyzeReport:
    file: str
    is_pe: bool
    error: Optional[str] = None
    is_armadillo: bool = False
    nanomites: Optional[NanomiteReport] = None
    iat: Optional[IatReport] = None
    oep_rva: int = 0
    oep_section: Optional[str] = None
    oep_in_text1: Optional[bool] = None
    splicing_section: Optional[str] = None
    second_text: Optional[str] = None
    upx: bool = False


def analyze_nanomites(pe: PeFile, limit: int = 16) -> NanomiteReport:
    """静态 Nanomite 扫描 (等效 BeaEngine 找 INT3/0xCC)。

    原版用 BeaEngine.dll 反汇编代码段, 把独立的 INT3(0xCC) 记为 Nanomite
    (0x45D2FC/sub_4211F0)。静态近似: 在可执行节里统计 0xCC 字节。
    """
    rep = NanomiteReport()
    exec_secs = [s for s in pe.sections if s.is_executable and s.role in
                 ("text", "itext", "text1", "adata", "code", "?")]
    total = 0
    for s in exec_secs:
        seg = pe.data[s.raw_address:s.raw_address + s.raw_size]
        rep.scanned_sections.append(s.name)
        cnt = seg.count(0xCC)
        total += cnt
        for i, byte in enumerate(seg):
            if byte == 0xCC and len(rep.first_addrs) < limit:
                rep.first_addrs.append(s.virtual_address + i)
    rep.cc_count = total
    rep.density = (total / max(1, sum(len(pe.data[s.raw_address:s.raw_address + s.raw_size])
                                      for s in exec_secs)))
    rep.note = ("0xCC(INT3) 计数 %d; 真实 Nanomite 需 BeaEngine 反汇编区分独立 INT3"
                % total)
    return rep


def analyze_iat(pe: PeFile) -> IatReport:
    """静态 IAT 分析 (等效 DetermineIATElimination / Redirection)。

    Armadillo 常消除/搬走导入表 (sub_41D980), 或把 FirstThunk 重定向进
    .adata/.text1。这里解析导入描述符, 判定 eliminated / redirected。
    """
    rep = IatReport(import_rva=pe.import_rva, import_size=pe.import_size)
    if pe.import_rva == 0:
        rep.eliminated = True
        rep.note = "导入目录 RVA=0 -> IAT 已被消除 (需 ARImpRec 重建)"
        return rep
    off = _rva_to_off(pe.sections, pe.import_rva)
    data = pe.data
    desc = []
    i = 0
    while off + 20 <= len(data) and i < 256:
        oft, _t, _f, name_rva, first = struct.unpack_from("<IIIII", data, off + i * 20)
        if oft == 0 and name_rva == 0 and first == 0:
            break
        desc.append((oft, name_rva, first))
        i += 1
    rep.descriptors = len(desc)
    if not desc:
        rep.eliminated = True
        rep.note = "无有效导入描述符 -> IAT 已被消除/重定向"
        return rep
    rep.iat_rva = desc[0][2] or desc[0][0]
    rep.iat_size = len(desc) * 4
    # 模块名
    for _oft, name_rva, _first in desc:
        noff = _rva_to_off(pe.sections, name_rva)
        if 0 <= noff < len(data):
            end = data.find(b"\0", noff, noff + 64)
            if end > noff:
                rep.modules.append(data[noff:end].decode("ascii", "replace"))
    # 重定向判定: FirstThunk 落在 Armadillo 段
    sec = section_of_rva(pe, rep.iat_rva)
    if sec is not None and sec.role in ("adata", "text1", "itext"):
        rep.redirected = True
        rep.redirect_section = sec.name
        rep.note = "IAT 被重定向进 %s (Armadillo 段)" % sec.name
    else:
        rep.note = "导入表 %d 个描述符, 模块: %s" % (
            len(desc), ", ".join(rep.modules[:8]) or "?")
    return rep


def analyze(pe: PeFile) -> AnalyzeReport:
    rep = AnalyzeReport(file=pe.path, is_pe=pe.is_pe, error=pe.error)
    if not pe.is_pe:
        return rep
    det = detect(pe)
    rep.is_armadillo = det.is_armadillo
    rep.oep_rva = pe.entry_rva
    ep_sec = section_of_rva(pe, pe.entry_rva)
    rep.oep_section = ep_sec.name if ep_sec else None
    rep.oep_in_text1 = det.ep_in_text1
    roles = _roles(pe)
    if "adata" in roles:
        rep.splicing_section = roles["adata"].name
    if "text1" in roles:
        rep.second_text = roles["text1"].name
    rep.upx = det.has_upx
    rep.nanomites = analyze_nanomites(pe)
    rep.iat = analyze_iat(pe)
    return rep


# ===================== 输出格式 =====================
def fmt_detect(r: DetectReport, as_json: bool) -> str:
    if as_json:
        return json.dumps(r.__dict__, ensure_ascii=False, indent=2)
    if not r.is_pe:
        return "[!] %s: %s" % (r.file, r.error)
    lines = ["File: %s" % r.file,
             "ImageBase: 0x%08X  EntryRVA: 0x%08X  (%s)" % (
                 r.image_base, r.entry_rva, "PE32+" if r.is64 else "PE32"),
             "LinkerVersion @e_lfanew+0x1A: 0x%04X  ->  SR 指纹: %s" % (
                 r.linker_version, "命中('SR')" if r.sr_signature else "未命中"),
             "Sections: .text=%s  .text1=%s  .adata=%s  .pdata=%s  UPX=%s" % (
                 r.has_text, r.has_text1, r.has_adata, r.has_pdata, r.has_upx),
             "EP∈.text1: %s" % (r.ep_in_text1 if r.ep_in_text1 is not None else "n/a"),
             "==> %s" % r.verdict]
    lines.append("==> Armadillo detected: %s" % ("YES" if r.is_armadillo else "NO"))
    return "\n".join(lines)


def fmt_info(pe: PeFile, as_json: bool) -> str:
    if not pe.is_pe:
        return "[!] %s" % pe.error
    if as_json:
        return json.dumps({
            "file": pe.path, "image_base": pe.image_base, "entry_rva": pe.entry_rva,
            "size_of_image": pe.size_of_image, "subsystem": pe.subsystem,
            "linker_version": pe.linker_version, "is64": pe.is64,
            "import_rva": pe.import_rva, "import_size": pe.import_size,
            "sections": [s.__dict__ for s in pe.sections],
        }, ensure_ascii=False, indent=2)
    lines = ["File: %s" % pe.path,
             "ImageBase: 0x%08X  EntryRVA: 0x%08X  SizeOfImage: 0x%X  Subsys: %d  (%s)" % (
                 pe.image_base, pe.entry_rva, pe.size_of_image, pe.subsystem,
                 "PE32+" if pe.is64 else "PE32"),
             "LinkerVersion: 0x%04X   ImportDir: RVA=0x%X Size=0x%X" % (
                 pe.linker_version, pe.import_rva, pe.import_size),
             "%-10s %-10s %-10s %-10s %-6s %-8s %-6s %s" % (
                 "Name", "VA", "VSize", "RawSize", "Flags", "Entropy", "Role", ""),
             "-" * 78]
    for s in pe.sections:
        flags = ("R" if s.is_readable else "-") + \
                ("W" if s.is_writable else "-") + \
                ("X" if s.is_executable else "-")
        seg = pe.data[s.raw_address:s.raw_address + s.raw_size]
        lines.append("%-10s 0x%08X 0x%08X 0x%08X %-6s %-8.3f %-6s" % (
            s.name, s.virtual_address, s.virtual_size, s.raw_size, flags,
            _ent(seg), s.role))
    return "\n".join(lines)


def fmt_analyze(r: AnalyzeReport, as_json: bool) -> str:
    if as_json:
        return json.dumps(r.__dict__, ensure_ascii=False, indent=2)
    if not r.is_pe:
        return "[!] %s: %s" % (r.file, r.error)
    n = r.nanomites
    it = r.iat
    lines = ["File: %s   Armadillo: %s" % (r.file, "YES" if r.is_armadillo else "NO"),
             "OEP: RVA=0x%X  section=%s  in .text1=%s" % (
                 r.oep_rva, r.oep_section, r.oep_in_text1),
             "2nd text(.text1): %s   CodeSplicing(.adata): %s   UPX: %s" % (
                 r.second_text, r.splicing_section, r.upx),
             "-- Nanomites (INT3/0xCC 静态扫描) --",
             "  scanned: %s" % (", ".join(n.scanned_sections) or "(none)"),
             "  0xCC count: %d  density: %.4f%%" % (n.cc_count, n.density * 100),
             "  first addrs: %s" % ", ".join("0x%08X" % a for a in n.first_addrs),
             "  note: %s" % n.note,
             "-- IAT --",
             "  ImportDir RVA=0x%X Size=0x%X  descriptors=%d" % (
                 it.import_rva, it.import_size, it.descriptors),
             "  IAT RVA=0x%X Size=0x%X" % (it.iat_rva, it.iat_size),
             "  eliminated=%s  redirected=%s (%s)" % (
                 it.eliminated, it.redirected, it.redirect_section or "-"),
             "  modules: %s" % (", ".join(it.modules) or "(none)"),
             "  note: %s" % it.note]
    return "\n".join(lines)


USAGE = __doc__


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="main.py", add_help=False)
    p.add_argument("target", nargs="?")
    p.add_argument("cmd", nargs="?", default="detect",
                   choices=["detect", "info", "analyze"])
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
    pe = parse_pe(data, a.target)
    if a.cmd == "detect":
        rep = detect(pe)
        print(fmt_detect(rep, a.json))
        return EXIT_SUCCESS if (pe.is_pe) else EXIT_FAILURE
    if a.cmd == "info":
        if not pe.is_pe:
            print("[!] %s" % pe.error)
            return EXIT_FAILURE
        print(fmt_info(pe, a.json))
        return EXIT_SUCCESS
    if a.cmd == "analyze":
        rep = analyze(pe)
        print(fmt_analyze(rep, a.json))
        return EXIT_SUCCESS if pe.is_pe else EXIT_FAILURE
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())