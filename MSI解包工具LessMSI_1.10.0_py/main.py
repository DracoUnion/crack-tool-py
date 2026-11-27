#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
LessMSI 1.10.0 (MSI 解包工具)  ->  Python CLI 重写版

来源目录: D:\\Program Files\\crack-tool-unpacker\\MSI解包工具LessMSI_1.10.0
目标程序: lessmsi.exe (32-bit .NET 程序集, 基址 0x400000) + lessmsi.core.dll
          作者/版权: "Copyright Scott Willeke 2004-2013"  (程序集版本 1.10.0.0)
          同目录依赖: wix.dll / wixcab.dll (WiX, CAB 解析 MSCabinet)
                      mspack.dll / libmspackn.dll (libmspack, MSZIP/LZX 解压)
                      LessIO.dll (Path/FileSystem 封装)

逆向依据 (ILSpy 8.2 反编译 lessmsi.exe + lessmsi.core.dll, 两个 .NET 程序集):
  ------------------------------------------------------------------------
  CLI 入口 Program.Main (exe.cs): 命令字典
      "x" / "/x" -> ExtractCommand   抽取
      "l"        -> ListTableCommand 以 CSV 打印某张 MSI 表 (-t 指定表名)
      "v"        -> ShowVersionCommand 打印 Property 表的 ProductVersion
      "o"        -> OpenGuiCommand   启动 lessmsi-gui.exe
      "h"        -> ShowHelpCommand  帮助
  返回码: Success=0 / UnexpectedError=-1 / InvalidCommandLineOption=-2 /
          UnrecognizedCommand=-3。

  抽取管线 Wixtracts.ExtractFiles (core.cs) —— 本工具复刻的核心:
    1) new Database(msi) 通过 Windows Installer COM 打开 MSI 数据库。
    2) MsiFile.CreateMsiFilesFromMSI: 执行 SQL "SELECT * FROM `File`",
       联读 `Component` / `Directory` 表, 得到每个文件的长名、大小、以及
       目标目录 (MsiDirectory.GetPath 递归拼接)。
    3) CabsFromMsiToDisk: 执行 "SELECT * FROM `Media`", 取第 5 列(Cabinet)。
       若名字以 '#' 开头 -> 内嵌 CAB: ExtractCabFromPackageTraditionalWay
       执行 "SELECT * FROM `_Streams` WHERE `Name`='<cab>'" 读出流(第 2 列)
       写入临时 .cab 文件。
       若传统方式抛异常(无 _Streams 表) -> 走 **备用路径**:
           OleStorageFile(msi) 把 MSI 当作 OLE 结构化存储 (CFB) 打开,
           枚举所有流, 用 OleStorageFile.IsCabStream 逐个检查流首 4 字节
           是否等于 "MSCF", 命中即认定为 CAB 并拷到磁盘。
       (名字不以 '#' 开头 -> 外部 CAB, 在 MSI 同级目录查找。)
    4) MergeCabs: 用 wixcab 的 MSCabinet 读取 Flags (bit0=有上一段 Prev,
       bit1=有下一段 Next), 把多段 CAB 串接。
    5) 逐个 MSCabinet.GetFiles() 枚举 MSCompressedFile, 对目标文件调用
       file.ExtractTo(target) 解压(MSZIP/LZX) 写出到目标目录。

  CFB / OLE 结构化存储 (OleStorageFile, core.cs):
      构造函数用 ole32!StgIsStorageFile 判定是否结构化存储; 通过反射调用
      System.IO.Packaging.StorageRoot.Open 打开, GetStreams() 返回所有流。
      IsCabStream 读取流前 4 字节与 "MSCF" 比较 —— 这就是识别内嵌 CAB 的
      关键(与流名无关, 因为 MSI 把 CFB 目录里的流名编码成了非常规字符,
      真正的逻辑名在 _Streams 表中; 本工具因此完全按 MSCF 魔数识别 CAB,
      忠实于原程序的备用路径)。

  ------------------------------------------------------------------------
  本 Python 实现完全基于上述逆向逻辑重写, 纯标准库, main.py 为唯一入口。
  由于原程序依赖 Windows Installer COM(msi.dll) 与 libmspack(wixcab/mspack),
  本实现用纯 Python 复刻了其中可在静态层面等价的部分:
    * CFB (Compound File Binary) 读取器: 解析头 / FAT / DIFAT / 目录项 /
      mini-FAT / mini 流, 枚举并读取全部流 (对应 OleStorageFile.GetStreams)。
    * CAB 解析器: 解析 MSCF 头 / Folder / File 记录 (对应 wixcab MSCabinet)。
    * MSZIP (type=1) 解压器: 逐 CFD 块 "CK"+raw-deflate, 用 32KB 历史字典
      续接 (对应 libmspack 的 mszipd)。type=0(存储) 直接拷贝。
   unsupported: LZX(type=3)/Quantum(type=2) 解压未实现(算法复杂且任务只要求
  MSZIP); 对这类 CAB 仍会把原始 .cab 落盘(= "extract embedded CABs"), 并
  明确提示仅解压不支持。

  命令:
    detect  判定是否 OLE 结构化存储 / MSI, 报告扇区大小、流数量、内嵌 CAB 数
    info    列出全部流(名称/大小/类型), 并对每个内嵌 CAB 解析头、列出
            压缩方式、文件夹数与文件清单
    extract 抽取内嵌 CAB 到 outdir, 再用 MSZIP 解压出其中文件
  用法: python main.py <file.msi> [detect|info|extract] [outdir] [--json]
"""

import argparse
import json
import os
import struct
import sys
import zlib
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2

# OLE 结构化存储 (CFB) 魔数
CFB_MAGIC = bytes.fromhex("d0cf11e0a1b11ae1")
# CAB 魔数
CAB_MAGIC = b"MSCF"
# 目录项类型
STGTY_EMPTY = 0
STGTY_STORAGE = 1
STGTY_STREAM = 2
STGTY_LOCKBYTES = 3
STGTY_PROPERTY = 4
STGTY_ROOT = 5
# 特殊扇区号
FREESECT = 0xFFFFFFFF
ENDOFCHAIN = 0xFFFFFFFE
FATSECT = 0xFFFFFFFD
DIFSECT = 0xFFFFFFFC
MAXREGSECT = 0xFFFFFFFA

# CAB 压缩类型 (typeCompress 低字节)
CAB_COMP_NONE = 0
CAB_COMP_MSZIP = 1
CAB_COMP_QUANTUM = 2
CAB_COMP_LZX = 3

COMP_NAME = {
    CAB_COMP_NONE: "NONE(存储)",
    CAB_COMP_MSZIP: "MSZIP",
    CAB_COMP_QUANTUM: "Quantum",
    CAB_COMP_LZX: "LZX",
}


class CfbError(Exception):
    pass


class CabError(Exception):
    pass


# ============================ CFB / OLE 读取器 ============================
@dataclass
class DirEntry:
    index: int
    name: str
    type: int
    start_sector: int
    size: int
    left: int = FREESECT
    right: int = FREESECT
    child: int = FREESECT

    @property
    def is_stream(self) -> bool:
        return self.type == STGTY_STREAM

    @property
    def is_storage(self) -> bool:
        return self.type in (STGTY_STORAGE, STGTY_ROOT)


@dataclass
class Stream:
    entry: DirEntry
    data: bytes

    @property
    def name(self) -> str:
        return self.entry.name

    @property
    def size(self) -> int:
        return self.entry.size


class CompoundFile:
    """纯 Python 实现的 OLE 结构化存储 (CFB) 读取器。

    对应 lessmsi.core.dll 中 OleStorageFile 通过
    System.IO.Packaging.StorageRoot 打开并 GetStreams() 的能力。
    """

    def __init__(self, data: bytes):
        self.data = data
        self._parse_header()
        self._read_fat()
        self._read_directory()
        self._read_minifat()
        self._read_ministream()

    # ---------- 头 ----------
    def _parse_header(self) -> None:
        d = self.data
        if len(d) < 512 or d[:8] != CFB_MAGIC:
            raise CfbError("不是 OLE 结构化存储文件 (CFB 魔数不匹配)")
        self.sector_shift = struct.unpack_from("<H", d, 0x1E)[0]
        self.mini_sector_shift = struct.unpack_from("<H", d, 0x20)[0]
        self.sector_size = 1 << self.sector_shift
        self.mini_sector_size = 1 << self.mini_sector_shift
        self.num_fat_sectors = struct.unpack_from("<I", d, 0x2C)[0]
        self.first_dir_sector = struct.unpack_from("<I", d, 0x30)[0]
        self.mini_stream_cutoff = struct.unpack_from("<I", d, 0x38)[0]
        self.first_minifat_sector = struct.unpack_from("<I", d, 0x3C)[0]
        self.num_minifat_sectors = struct.unpack_from("<I", d, 0x40)[0]
        self.first_difat_sector = struct.unpack_from("<I", d, 0x44)[0]
        self.num_difat_sectors = struct.unpack_from("<I", d, 0x48)[0]
        if self.sector_size not in (512, 4096):
            raise CfbError("不支持的扇区大小: %d" % self.sector_size)

    def _sector(self, idx: int) -> bytes:
        off = (idx + 1) * self.sector_size
        return self.data[off:off + self.sector_size]

    # ---------- FAT / DIFAT ----------
    def _read_fat(self) -> None:
        d = self.data
        per = self.sector_size // 4
        difat = list(struct.unpack_from("<109I", d, 0x4C))
        nxt = self.first_difat_sector
        guard = 0
        while nxt not in (ENDOFCHAIN, FREESECT) and guard <= self.num_difat_sectors:
            sec = self._sector(nxt)
            vals = struct.unpack("<%dI" % per, sec)
            difat.extend(vals[:-1])
            nxt = vals[-1]
            guard += 1
        self.fat: List[int] = []
        for fs in difat[:self.num_fat_sectors]:
            if fs in (FREESECT, ENDOFCHAIN):
                continue
            self.fat.extend(struct.unpack("<%dI" % per, self._sector(fs)))

    def _chain(self, start: int) -> List[int]:
        out: List[int] = []
        c = start
        seen = set()
        while c not in (ENDOFCHAIN, FREESECT) and c < len(self.fat):
            if c in seen:
                break
            seen.add(c)
            out.append(c)
            c = self.fat[c]
            if len(out) > len(self.fat) + 4:
                break
        return out

    def _read_chain(self, start: int, size: Optional[int] = None) -> bytes:
        b = b"".join(self._sector(i) for i in self._chain(start))
        return b if size is None else b[:size]

    # ---------- 目录 ----------
    def _read_directory(self) -> None:
        dirdata = self._read_chain(self.first_dir_sector)
        self.entries: List[DirEntry] = []
        for i in range(0, len(dirdata) - 127, 128):
            e = dirdata[i:i + 128]
            nlen = struct.unpack_from("<H", e, 64)[0]
            name = ""
            if nlen >= 2:
                name = e[:nlen - 2].decode("utf-16-le", "replace")
            typ = e[66]
            left, right, child = struct.unpack_from("<III", e, 68)
            start = struct.unpack_from("<I", e, 116)[0]
            size = struct.unpack_from("<Q", e, 120)[0]
            self.entries.append(DirEntry(i // 128, name, typ, start, size,
                                         left, right, child))
        if not self.entries or self.entries[0].type != STGTY_ROOT:
            raise CfbError("目录中缺少 Root Entry")

    def _read_minifat(self) -> None:
        per = self.sector_size // 4
        self.minifat: List[int] = []
        if self.first_minifat_sector in (ENDOFCHAIN, FREESECT):
            return
        for i in self._chain(self.first_minifat_sector):
            self.minifat.extend(struct.unpack("<%dI" % per, self._sector(i)))

    def _read_ministream(self) -> None:
        root = self.entries[0]
        self.ministream = self._read_chain(root.start_sector, root.size)

    def _read_mini(self, start: int, size: int) -> bytes:
        out = bytearray()
        c = start
        seen = set()
        while c not in (ENDOFCHAIN, FREESECT) and c < len(self.minifat):
            if c in seen:
                break
            seen.add(c)
            off = c * self.mini_sector_size
            out += self.ministream[off:off + self.mini_sector_size]
            c = self.minifat[c]
        return bytes(out[:size])

    # ---------- 公共接口 ----------
    def streams(self) -> List[Stream]:
        """返回全部非空流 (STGTY_STREAM), 按目录项顺序。"""
        result = []
        for e in self.entries:
            if not e.is_stream or e.size == 0:
                continue
            if e.size < self.mini_stream_cutoff:
                data = self._read_mini(e.start_sector, e.size)
            else:
                data = self._read_chain(e.start_sector, e.size)
            result.append(Stream(e, data))
        return result

    @staticmethod
    def is_cab_stream(s: Stream) -> bool:
        """对应 OleStorageFile.IsCabStream: 流首 4 字节 == 'MSCF'。"""
        return s.data[:4] == CAB_MAGIC


# ============================ CAB 解析 / 解压 ============================
@dataclass
class CabFolder:
    coff_cab_start: int      # 该文件夹首个 CFD 在 cab 中的绝对偏移
    ccfdata: int             # CFD 块数量
    type_compress: int       # 原始 16 位值
    comp: int = 0            # 低字节: 压缩类型
    window: int = 0          # 高字节: 窗口大小(位数)

    @property
    def comp_name(self) -> str:
        return COMP_NAME.get(self.comp, "未知(%d)" % self.comp)


@dataclass
class CabFile:
    name: str
    cb_file: int             # 解压后大小
    uoff_folder_start: int   # 在所属文件夹解压数据中的偏移
    i_folder: int            # 所属文件夹索引


@dataclass
class Cab:
    data: bytes
    cb_cabinet: int = 0
    coff_files: int = 0
    version_minor: int = 0
    version_major: int = 0
    folders: List[CabFolder] = field(default_factory=list)
    files: List[CabFile] = field(default_factory=list)
    flags: int = 0
    set_id: int = 0
    i_cabinet: int = 0
    _folder_cache: dict = field(default_factory=dict)

    def parse(self) -> "Cab":
        d = self.data
        if d[:4] != CAB_MAGIC:
            raise CabError("不是 CAB 文件 (MSCF 魔数不匹配)")
        (self.cb_cabinet,) = struct.unpack_from("<I", d, 8)
        (self.coff_files,) = struct.unpack_from("<I", d, 16)
        self.version_minor = d[24]
        self.version_major = d[25]
        (c_folders,) = struct.unpack_from("<H", d, 26)
        (c_files,) = struct.unpack_from("<H", d, 28)
        (self.flags,) = struct.unpack_from("<H", d, 30)
        (self.set_id,) = struct.unpack_from("<H", d, 32)
        (self.i_cabinet,) = struct.unpack_from("<I", d, 34)
        off = 36
        if self.flags & 0x4:  # 保留字段存在
            cb_cf_header, cb_cf_folder, cb_cf_data = struct.unpack_from("<HHH", d, off)
            off += 6
        for _ in range(c_folders):
            coff, ccfdata, typec = struct.unpack_from("<IHH", d, off)
            off += 8
            self.folders.append(CabFolder(coff, ccfdata, typec,
                                          comp=typec & 0xFF, window=(typec >> 8) & 0xFF))
        for _ in range(c_files):
            cb_file, uoff, ifolder = struct.unpack_from("<IIH", d, off)
            off += 10
            off += 6  # date / time / attribs
            e = d.index(b"\x00", off)
            name = d[off:e].decode("latin-1")
            off = e + 1
            self.files.append(CabFile(name, cb_file, uoff, ifolder))
        return self

    # ---------- 解压 ----------
    def decompress_folder(self, idx: int) -> bytes:
        """解压单个文件夹, 返回拼接后的数据。

        type=0 直接拷贝; type=1 (MSZIP) 逐块 "CK"+raw-deflate, 用 32KB
        历史字典续接 (等价 libmspack mszipd)。
        """
        if idx in self._folder_cache:
            return self._folder_cache[idx]
        f = self.folders[idx]
        d = self.data
        coff = f.coff_cab_start
        out = bytearray()
        hist = b""
        for _ in range(f.ccfdata):
            if coff + 8 > len(d):
                raise CabError("CFD 块越界")
            cb_data, cb_uncomp = struct.unpack_from("<HH", d, coff + 4)
            coff += 8
            block = d[coff:coff + cb_data]
            coff += cb_data
            if f.comp == CAB_COMP_NONE:
                out += block
            elif f.comp == CAB_COMP_MSZIP:
                if block[:2] == b"CK":
                    block = block[2:]
                if hist:
                    dobj = zlib.decompressobj(-15, zdict=hist)
                else:
                    dobj = zlib.decompressobj(-15)
                piece = dobj.decompress(block) + dobj.flush()
                out += piece
                hist = (hist + piece)[-32768:]
            else:
                raise CabError("%s 压缩未支持 (仅 MSZIP/NONE)" % f.comp_name)
        self._folder_cache[idx] = bytes(out)
        return self._folder_cache[idx]

    def extract_file(self, cf: CabFile) -> bytes:
        data = self.decompress_folder(cf.i_folder)
        return data[cf.uoff_folder_start:cf.uoff_folder_start + cf.cb_file]

    def extract_all(self) -> List[Tuple[CabFile, bytes]]:
        """返回 [(文件, 内容)]。遇到不支持的压缩会抛 CabError。"""
        results = []
        for cf in self.files:
            results.append((cf, self.extract_file(cf)))
        return results


# ============================ 工具函数 ============================
def safe_name(name: str) -> str:
    """把可能含乱码/非法字符的流名转成可安全显示/落盘的形式。"""
    if not name:
        return "<empty>"
    out = []
    for ch in name:
        o = ord(ch)
        if 0x20 <= o < 0x7F and ch not in '\\/:*?"<>|':
            out.append(ch)
        else:
            out.append("\\u%04x" % o)
    return "".join(out)


def open_cfb(path: str) -> CompoundFile:
    with open(path, "rb") as fh:
        data = fh.read()
    return CompoundFile(data)


def find_cab_streams(cfb: CompoundFile) -> List[Stream]:
    return [s for s in cfb.streams() if cfb.is_cab_stream(s)]


# ============================ 命令实现 ============================
def cmd_detect(path: str, as_json: bool) -> int:
    with open(path, "rb") as fh:
        head = fh.read(8)
    if head != CFB_MAGIC:
        r = {"file": path, "is_cfb": False,
             "magic": head.hex(), "error": "CFB 魔数不匹配, 非 OLE 结构化存储"}
        print(json.dumps(r, ensure_ascii=False, indent=2) if as_json
              else "[!] %s: 不是 OLE 结构化存储 (CFB) 文件" % path)
        return EXIT_FAILURE
    cfb = open_cfb(path)
    streams = cfb.streams()
    cabs = find_cab_streams(cfb)
    r = {
        "file": path,
        "is_cfb": True,
        "is_msi": True,
        "sector_size": cfb.sector_size,
        "mini_sector_size": cfb.mini_sector_size,
        "num_streams": len(streams),
        "num_cab_streams": len(cabs),
        "cab_streams": [
            {"name": safe_name(s.name), "size": s.size,
             "folders": _safe_cab_meta(s.data)}
            for s in cabs
        ],
        "all_streams": [
            {"name": safe_name(s.name), "size": s.size,
             "is_cab": cfb.is_cab_stream(s)}
            for s in streams
        ],
    }
    if as_json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
    else:
        print("File           : %s" % path)
        print("类型           : OLE 结构化存储 (CFB) / MSI 数据库")
        print("扇区/迷你扇区  : %d / %d 字节" % (cfb.sector_size, cfb.mini_sector_size))
        print("流总数         : %d" % len(streams))
        print("内嵌 CAB 流    : %d" % len(cabs))
        for s in cabs:
            meta = _safe_cab_meta(s.data)
            print("  - CAB 流 %-20s %10d 字节  %s" %
                  (safe_name(s.name), s.size, meta))
        print("==> MSI / OLE 结构化存储: YES")
    return EXIT_SUCCESS


def _safe_cab_meta(data: bytes) -> str:
    try:
        cab = Cab(data).parse()
        comps = ",".join(sorted({f.comp_name for f in cab.folders}))
        return "folders=%d files=%d comp=%s" % (len(cab.folders), len(cab.files), comps)
    except Exception as e:
        return "(CAB 解析失败: %s)" % e


def cmd_info(path: str, as_json: bool) -> int:
    cfb = open_cfb(path)
    streams = cfb.streams()
    rows = []
    for s in streams:
        is_cab = cfb.is_cab_stream(s)
        row = {"name": safe_name(s.name), "size": s.size, "is_cab": is_cab}
        if is_cab:
            try:
                cab = Cab(s.data).parse()
                row["cab"] = {
                    "folders": len(cab.folders),
                    "files": len(cab.files),
                    "compression": sorted({f.comp_name for f in cab.folders}),
                    "file_list": [cf.name for cf in cab.files],
                }
            except Exception as e:
                row["cab"] = {"error": str(e)}
        rows.append(row)
    r = {"file": path, "num_streams": len(streams), "streams": rows}
    if as_json:
        print(json.dumps(r, ensure_ascii=False, indent=2))
        return EXIT_SUCCESS
    print("File: %s  (共 %d 个流)" % (path, len(streams)))
    print("%-3s %-40s %-12s %s" % ("#", "Stream Name", "Size", "Type"))
    for i, row in enumerate(rows):
        typ = "CAB(MSCF)" if row["is_cab"] else "stream"
        print("%-3d %-40s %-12d %s" % (i, row["name"][:40], row["size"], typ))
        if row["is_cab"] and "cab" in row and "error" not in row["cab"]:
            c = row["cab"]
            print("      -> folders=%d files=%d compression=%s"
                  % (c["folders"], c["files"], ",".join(c["compression"])))
            for fn in c["file_list"][:12]:
                print("         . %s" % fn)
            if len(c["file_list"]) > 12:
                print("         ... 共 %d 个文件" % len(c["file_list"]))
    return EXIT_SUCCESS


def _unique_path(outdir: str, name: str) -> str:
    """避免重名: 若存在则追加 .duplicateN (对应 LessMSI 的重复文件处理)。"""
    base = os.path.join(outdir, name)
    if not os.path.exists(base):
        return base
    n = 0
    while True:
        n += 1
        cand = "%s.duplicate%d" % (base, n)
        if not os.path.exists(cand):
            return cand


def cmd_extract(path: str, outdir: Optional[str], as_json: bool) -> int:
    if not outdir:
        outdir = os.path.splitext(os.path.basename(path))[0] + "_extracted"
    os.makedirs(outdir, exist_ok=True)
    cfb = open_cfb(path)
    cabs = find_cab_streams(cfb)
    if not cabs:
        msg = "未在 MSI 中发现内嵌 CAB (MSCF) 流"
        print(json.dumps({"file": path, "error": msg}, ensure_ascii=False, indent=2)
              if as_json else "[!] %s" % msg)
        return EXIT_FAILURE

    report = {"file": path, "outdir": outdir, "cabs": [], "extracted": []}
    for ci, s in enumerate(cabs, 1):
        # 1) 先把内嵌 CAB 原样落盘 (= "extract embedded CABs")
        cab_name = "embedded_%d.cab" % ci
        cab_path = os.path.join(outdir, cab_name)
        with open(cab_path, "wb") as fh:
            fh.write(s.data)
        entry = {"cab": cab_name, "src_stream": safe_name(s.name),
                 "size": s.size, "files": [], "note": None}
        # 2) 尝试解压
        try:
            cab = Cab(s.data).parse()
        except Exception as e:
            entry["note"] = "CAB 解析失败: %s" % e
            report["cabs"].append(entry)
            continue
        unsupported = [f.comp_name for f in cab.folders
                       if f.comp not in (CAB_COMP_NONE, CAB_COMP_MSZIP)]
        if unsupported:
            entry["note"] = ("CAB 已落盘, 但使用了未支持的压缩 %s; "
                             "仅 MSZIP/NONE 可解压" % ",".join(sorted(set(unsupported))))
            report["cabs"].append(entry)
            continue
        try:
            all_files = cab.extract_all()
            for fi, (cf, content) in enumerate(all_files, 1):
                out_path = _unique_path(outdir, os.path.basename(cf.name) or cf.name)
                with open(out_path, "wb") as fh:
                    fh.write(content)
                entry["files"].append({"name": cf.name, "size": len(content)})
                report["extracted"].append(out_path)
                if not as_json:
                    print("[%d/%d] %s -> %s (%d 字节)"
                          % (fi, len(all_files), cab_name, cf.name, len(content)))
        except CabError as e:
            entry["note"] = str(e)
        report["cabs"].append(entry)

    if as_json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        total = len(report["extracted"])
        print("[+] 输出目录: %s" % outdir)
        print("[+] 内嵌 CAB: %d 个, 解压文件: %d 个" % (len(cabs), total))
        for e in report["cabs"]:
            if e["note"]:
                print("    ! %s: %s" % (e["cab"], e["note"]))
    return EXIT_SUCCESS


# ============================ 入口 ============================
USAGE = __doc__


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="main.py", add_help=False)
    p.add_argument("target", nargs="?", help="MSI 文件路径")
    p.add_argument("cmd", nargs="?", default="detect",
                   choices=["detect", "info", "extract"])
    p.add_argument("outdir", nargs="?", default=None, help="extract 输出目录")
    p.add_argument("--json", action="store_true", help="以 JSON 输出")
    p.add_argument("-h", "--help", action="store_true", help="显示帮助")
    a = p.parse_args(argv)
    if a.help or not a.target:
        print(USAGE)
        return EXIT_SUCCESS
    if not os.path.isfile(a.target):
        print("[!] 无法读取文件: %s" % a.target)
        return EXIT_FAILURE
    try:
        if a.cmd == "detect":
            return cmd_detect(a.target, a.json)
        if a.cmd == "info":
            return cmd_info(a.target, a.json)
        if a.cmd == "extract":
            return cmd_extract(a.target, a.outdir, a.json)
    except CfbError as e:
        print("[!] CFB 错误: %s" % e)
        return EXIT_FAILURE
    except CabError as e:
        print("[!] CAB 错误: %s" % e)
        return EXIT_FAILURE
    except OSError as e:
        print("[!] 文件错误: %s" % e)
        return EXIT_FAILURE
    return EXIT_USAGE


if __name__ == "__main__":
    # 尽量使用 UTF-8 输出, 避免 GBK 控制台对乱码流名报错
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    sys.exit(main())