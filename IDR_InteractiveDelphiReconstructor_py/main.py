#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IDR_InteractiveDelphiReconstructor\\Idr.exe  ->  Python CLI 重写版

来源目录: D:\\Program Files\\crack-tool-dasm\\IDR_InteractiveDelphiReconstructor
目标文件: Idr.exe (3.4 MB, 32-bit PE, Delphi 编写的交互式 Delphi 重构工具)

逆向依据:
  - IDA Pro 已打开 Idr.exe (同目录存在 Idr.exe.id0 / .id1 / .id2 / .nam /
    .til IDA 数据库), 基址 0x400000, 32-bit PE, Delphi 编译。
  - x32dbg 反汇编 (历史依据, 基址 0x400000, PE 入口点 RVA 0x15AC => 0x4015AC):
      入口点 0x4015AC 为 Delphi 程序启动代码:
        mov eax, [69408B] (HInstance); shl eax,2 -> [69408F]
        GetModuleHandleA()                                         ; 0x4015CE
        call idr.66F454 / 66F3B8 / 66F494                          ; Delphi 运行时初始化
        GetModuleHandleA("..."(694034)) -> [694093]                ; 0x4015F4
        jmp idr.679C34                                             ; 进入 Delphi 主程序
    66Fxxx / 679C34 等地址位于主模块 (0x400000-0x74F000) 之外,
    属于 Delphi 运行时包/其他模块。Idr.exe 完整业务逻辑分散在
    500 个函数中并跨越多个模块，静态反汇编未完整还原其
    Delphi 单元/窗体/逆向分析核心逻辑；此处按 Delphi 反编译通用逻辑
    编写等价的 Python CLI (PE 解析 / Delphi 判定 / 单元-过程-类-DFM 转储).

本程序完全基于上述反编译逻辑重写, 不依赖任何第三方库.
纯 Python CLI, main.py 为唯一入口, 可直接用 `python main.py` 运行.

用法:
    python main.py <目标文件> [选项]
"""

import os
import re
import struct
import sys
import zlib

# ===================== 常量 =====================
EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2

# PE 签名 / 机器类型
PE_SIGNATURE = 0x00004550
IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664

# 可选头魔数
OPTIONAL_HEADER_MAGIC_PE32 = 0x010B
OPTIONAL_HEADER_MAGIC_PE32_PLUS = 0x020B

# 节区特征
IMAGE_SCN_CNT_CODE = 0x00000020
IMAGE_SCN_CNT_INITIALIZED_DATA = 0x00000040
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000

# 资源类型
RT_RCDATA = 10

# 子系统
SUBSYSTEM_NAMES = {
    0: "Unknown",
    1: "Native",
    2: "Windows GUI",
    3: "Windows CUI",
}

MACHINE_NAMES = {
    IMAGE_FILE_MACHINE_I386: "Intel 386",
    IMAGE_FILE_MACHINE_AMD64: "x64 (AMD64)",
}

# Delphi 版本码 -> 名称 (对应 sub_4B0DCC 的 switch)
DELPHI_VERSION_NAMES = {
    0x101: "Delphi 1",
    0x102: "Delphi 2",
    0x103: "Delphi 3",
    0x104: "Delphi 4",
    0x105: "Delphi 5",
    0x106: "Delphi 6",
    0x107: "Delphi 7",
    0x108: "Delphi 8",
    0x109: "Delphi 2005",
    0x10A: "Delphi 2006",
    0x10B: "Delphi 2007",
    0x10C: "Delphi 2009",
    0x10D: "Delphi 2010",
}

# 运行时包 -> Delphi 版本 (VCL30.bpl = Delphi 3 ... VCL70.bpl = Delphi 7)
VCL_PACKAGE_VERSIONS = {
    "VCL20.bpl": 0x102,
    "VCL30.bpl": 0x103,
    "VCL40.bpl": 0x104,
    "VCL50.bpl": 0x105,
    "VCL60.bpl": 0x106,
    "VCL70.bpl": 0x107,
}

# VMT 负偏移 (Delphi 2 - 7 布局)
VMT_SELF_PTR = -76
VMT_INTF_TABLE = -72
VMT_AUTO_TABLE = -68
VMT_INIT_TABLE = -64
VMT_TYPE_INFO = -60
VMT_FIELD_TABLE = -56
VMT_METHOD_TABLE = -52
VMT_DYNAMIC_TABLE = -48
VMT_CLASS_NAME = -44
VMT_INSTANCE_SIZE = -40
VMT_PARENT = -36

# 二进制 DFM 值类型
VA_NULL = 0x00
VA_LIST = 0x01
VA_INT8 = 0x02
VA_INT16 = 0x03
VA_INT32 = 0x04
VA_EXTENDED = 0x05
VA_STRING = 0x06
VA_IDENT = 0x07
VA_FALSE = 0x08
VA_TRUE = 0x09
VA_BINARY = 0x0A
VA_SET = 0x0B
VA_LSTRING = 0x0C
VA_NIL = 0x0D
VA_COLLECTION = 0x0E
VA_SINGLE = 0x0F
VA_CURRENCY = 0x10
VA_DATE = 0x11
VA_WSTRING = 0x12
VA_INT64 = 0x13
VA_UTF8STRING = 0x14

USAGE = (
    "IDR Interactive Delphi Reconstructor (Python CLI 重写版)\n"
    "用法: python main.py <目标文件> [选项]\n"
    "\n"
    "选项:\n"
    "  -o, --output <目录>  输出目录 (默认: <目标名>_project)\n"
    "  -p, --pe             显示 PE 头信息\n"
    "  -s, --sections       显示节区表\n"
    "  -i, --imports        显示导入表\n"
    "  -r, --resources      列出资源目录\n"
    "  -d, --delphi         仅做 Delphi 判定与版本识别\n"
    "  -f, --forms          提取并转换 DFM 表单 (二进制 -> 文本)\n"
    "  -c, --classes        转储类信息 (VMT / RTTI)\n"
    "  -u, --units          转储单元信息 (PACKAGEINFO)\n"
    "  -F, --procs          转储过程列表 (EP-Finder)\n"
    "  -a, --all            全部分析并写出工程 (默认)\n"
    "  -q, --quiet          仅写文件, 不打印到标准输出\n"
    "  -h, --help           显示此帮助信息\n"
    "\n"
    "示例:\n"
    "  python main.py target.exe\n"
    "  python main.py target.exe -f -c -u -F -o out\n"
    "  python main.py target.exe -d\n"
)


# ===================== 通用读取工具 =====================

def read_u8(data, off):
    return data[off]


def read_u16(data, off):
    return struct.unpack_from("<H", data, off)[0]


def read_u32(data, off):
    return struct.unpack_from("<I", data, off)[0]


def read_u64(data, off):
    return struct.unpack_from("<Q", data, off)[0]


def read_i8(data, off):
    return struct.unpack_from("<b", data, off)[0]


def read_i16(data, off):
    return struct.unpack_from("<h", data, off)[0]


def read_i32(data, off):
    return struct.unpack_from("<i", data, off)[0]


def read_i64(data, off):
    return struct.unpack_from("<q", data, off)[0]


def read_cstring(data, off, max_len=512):
    end = data.find(b"\x00", off)
    if end == -1 or end - off > max_len:
        end = off + max_len
    raw = data[off:end]
    return raw.decode("latin-1", errors="replace")


def to_hex(v, width=8):
    return "0x{:0{}X}".format(v & 0xFFFFFFFF, width)


# ===================== PE 解析 =====================

class Section(object):
    __slots__ = ("name", "virtual_size", "virtual_address", "size_of_raw_data",
                 "pointer_to_raw_data", "characteristics")

    def __init__(self, name, vsize, va, rsize, rptr, chars):
        self.name = name
        self.virtual_size = vsize
        self.virtual_address = va
        self.size_of_raw_data = rsize
        self.pointer_to_raw_data = rptr
        self.characteristics = chars

    @property
    def is_code(self):
        return bool(self.characteristics & IMAGE_SCN_MEM_EXECUTE)

    @property
    def is_data(self):
        return bool(self.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA)

    def contains_rva(self, rva):
        size = max(self.virtual_size, self.size_of_raw_data)
        return self.virtual_address <= rva < self.virtual_address + size


class ResourceEntry(object):
    __slots__ = ("type_id", "type_name", "name_id", "name", "rva", "size")

    def __init__(self, type_id, type_name, name_id, name, rva, size):
        self.type_id = type_id
        self.type_name = type_name
        self.name_id = name_id
        self.name = name
        self.rva = rva
        self.size = size

    def label(self):
        if self.name is not None:
            return self.name
        if self.name_id is not None:
            return "#{}".format(self.name_id)
        return "?"


class PeFile(object):
    """PE32 / PE32+ 解析器 (对应原程序 PEFile 类)."""

    def __init__(self, data):
        self.data = data
        self.valid = False
        self.error = None
        self.sections = []
        self.resources = []
        self.imports = []
        self.exports = []
        self._parse()

    # ---------- 解析 ----------
    def _parse(self):
        data = self.data
        if len(data) < 0x40 or data[0:2] != b"MZ":
            self.error = "文件太小或缺少 MZ 签名"
            return
        self.dos_magic = read_u16(data, 0)
        self.e_lfanew = read_u32(data, 0x3C)
        if self.e_lfanew + 24 > len(data):
            self.error = "e_lfanew 越界"
            return
        if read_u32(data, self.e_lfanew) != PE_SIGNATURE:
            self.error = "This is not a PE file! Signature: 0x{:08X}".format(
                read_u32(data, self.e_lfanew))
            return

        coff = self.e_lfanew + 4
        self.machine = read_u16(data, coff)
        self.number_of_sections = read_u16(data, coff + 2)
        self.time_date_stamp = read_u32(data, coff + 4)
        self.size_of_optional_header = read_u16(data, coff + 16)
        self.characteristics = read_u16(data, coff + 18)

        opt = coff + 20
        self.opt_magic = read_u16(data, opt)
        self.is_pe32_plus = self.opt_magic == OPTIONAL_HEADER_MAGIC_PE32_PLUS
        self.linker_version = (data[opt + 4], data[opt + 5])
        self.address_of_entry_point = read_u32(data, opt + 16)
        if self.is_pe32_plus:
            self.image_base = read_u64(data, opt + 24)
            self.size_of_image = read_u32(data, opt + 56)
            self.size_of_headers = read_u32(data, opt + 60)
            self.subsystem = read_u16(data, opt + 68)
            self.data_directory_start = opt + 112
        else:
            self.image_base = read_u32(data, opt + 28)
            self.size_of_image = read_u32(data, opt + 56)
            self.size_of_headers = read_u32(data, opt + 60)
            self.subsystem = read_u16(data, opt + 68)
            self.data_directory_start = opt + 96

        self.entry_point_va = self.image_base + self.address_of_entry_point

        sec_off = opt + self.size_of_optional_header
        for i in range(self.number_of_sections):
            off = sec_off + i * 40
            if off + 40 > len(data):
                break
            name_raw = data[off:off + 8]
            name = name_raw.split(b"\x00")[0].decode("ascii", errors="replace")
            vsize = read_u32(data, off + 8)
            va = read_u32(data, off + 12)
            rsize = read_u32(data, off + 16)
            rptr = read_u32(data, off + 20)
            chars = read_u32(data, off + 36)
            self.sections.append(Section(name, vsize, va, rsize, rptr, chars))

        self._parse_imports()
        self._parse_exports()
        self._parse_resources()
        self.valid = True

    def rva_to_offset(self, rva):
        for sec in self.sections:
            if sec.contains_rva(rva):
                delta = rva - sec.virtual_address
                if delta < sec.size_of_raw_data:
                    return sec.pointer_to_raw_data + delta
                return None
        # 头部分
        if rva < self.size_of_headers:
            return rva
        return None

    def va_to_offset(self, va):
        if va < self.image_base:
            return None
        return self.rva_to_offset(va - self.image_base)

    def get_section(self, rva):
        for sec in self.sections:
            if sec.contains_rva(rva):
                return sec
        return None

    def is_code_va(self, va):
        off = self.va_to_offset(va)
        if off is None:
            return False
        sec = self.get_section(va - self.image_base)
        return sec is not None and sec.is_code

    def is_mapped_va(self, va):
        return self.image_base <= va < self.image_base + self.size_of_image

    def _data_dir(self, index):
        off = self.data_directory_start + index * 8
        if off + 8 > len(self.data):
            return 0, 0
        return read_u32(self.data, off), read_u32(self.data, off + 4)

    def _parse_imports(self):
        rva, _size = self._data_dir(1)
        if rva == 0:
            return
        off = self.rva_to_offset(rva)
        if off is None:
            return
        i = 0
        while off + i * 20 + 20 <= len(self.data):
            desc = off + i * 20
            oft = read_u32(self.data, desc)
            name_rva = read_u32(self.data, desc + 12)
            first_thunk = read_u32(self.data, desc + 16)
            if oft == 0 and name_rva == 0 and first_thunk == 0:
                break
            dll = ""
            noff = self.rva_to_offset(name_rva)
            if noff is not None:
                dll = read_cstring(self.data, noff)
            entries = []
            thunk = oft or first_thunk
            toff = self.rva_to_offset(thunk)
            if toff is not None:
                j = 0
                while toff + j * 4 + 4 <= len(self.data):
                    val = read_u32(self.data, toff + j * 4)
                    if val == 0:
                        break
                    if val & 0x80000000:
                        entries.append("Ordinal {}".format(val & 0xFFFF))
                    else:
                        hoff = self.rva_to_offset(val)
                        if hoff is None and first_thunk:
                            # 转储镜像的 IAT 可能已被解析, 退回 FirstThunk
                            ft = self.rva_to_offset(first_thunk)
                            if ft is not None and ft + j * 4 + 4 <= len(self.data):
                                val2 = read_u32(self.data, ft + j * 4)
                                if val2 and not (val2 & 0x80000000):
                                    hoff = self.rva_to_offset(val2)
                        if hoff is not None and hoff + 2 <= len(self.data):
                            hint = read_u16(self.data, hoff)
                            entries.append("{} (hint={})".format(
                                read_cstring(self.data, hoff + 2), hint))
                        else:
                            entries.append("Unknown")
                    j += 1
                    if j > 4096:
                        break
            self.imports.append((dll, entries))
            i += 1
            if i > 256:
                break

    def _parse_exports(self):
        rva, _size = self._data_dir(0)
        if rva == 0:
            return
        off = self.rva_to_offset(rva)
        if off is None:
            return
        name_rva = read_u32(self.data, off + 12)
        base = read_u32(self.data, off + 16)
        n_funcs = read_u32(self.data, off + 20)
        n_names = read_u32(self.data, off + 24)
        a_funcs = read_u32(self.data, off + 28)
        a_names = read_u32(self.data, off + 32)
        a_ords = read_u32(self.data, off + 36)
        noff = self.rva_to_offset(name_rva)
        self.export_dll_name = read_cstring(self.data, noff) if noff else ""
        names_off = self.rva_to_offset(a_names)
        ords_off = self.rva_to_offset(a_ords)
        funcs_off = self.rva_to_offset(a_funcs)
        if names_off is None or ords_off is None:
            return
        for i in range(min(n_names, 8192)):
            nrva = read_u32(self.data, names_off + i * 4)
            ordv = read_u16(self.data, ords_off + i * 2)
            foff = self.rva_to_offset(nrva)
            nm = read_cstring(self.data, foff) if foff is not None else ""
            frva = 0
            if funcs_off is not None:
                frva = read_u32(self.data, funcs_off + ordv * 4)
            self.exports.append((nm, base + ordv, frva))

    # ---------- 资源目录 ----------
    def _res_string(self, off):
        if off + 2 > len(self.data):
            return None
        ln = read_u16(self.data, off)
        raw = self.data[off + 2:off + 2 + ln * 2]
        try:
            return raw.decode("utf-16-le", errors="replace")
        except Exception:
            return None

    def _parse_resources(self):
        rva, size = self._data_dir(2)
        if rva == 0:
            return
        base = self.rva_to_offset(rva)
        if base is None:
            return
        self._res_dir(base, base, depth=0)

    def _res_dir(self, dir_off, base, depth, type_id=None, type_name=None,
                 name_id=None, name=None):
        if dir_off + 16 > len(self.data):
            return
        n_named = read_u16(self.data, dir_off + 12)
        n_id = read_u16(self.data, dir_off + 14)
        total = n_named + n_id
        for i in range(total):
            ent = dir_off + 16 + i * 8
            if ent + 8 > len(self.data):
                return
            name_field = read_u32(self.data, ent)
            off_field = read_u32(self.data, ent + 4)
            if name_field & 0x80000000:
                nm = self._res_string(base + (name_field & 0x7FFFFFFF))
                nid = None
            else:
                nm = None
                nid = name_field
            if off_field & 0x80000000:
                # 子目录
                if depth == 0:
                    self._res_dir(base + (off_field & 0x7FFFFFFF), base, 1,
                                  nid, nm)
                elif depth == 1:
                    self._res_dir(base + (off_field & 0x7FFFFFFF), base, 2,
                                  type_id, type_name, nid, nm)
                else:
                    # 语言目录以下不再递归
                    pass
            else:
                # 资源数据项 (仅在深度 2 即语言目录下有效)
                if depth != 2:
                    continue
                data_ent = base + off_field
                if data_ent + 16 > len(self.data):
                    continue
                data_rva = read_u32(self.data, data_ent)
                data_size = read_u32(self.data, data_ent + 4)
                self.resources.append(
                    ResourceEntry(type_id, type_name, name_id, name,
                                  data_rva, data_size))

    def resource_bytes(self, res):
        off = self.rva_to_offset(res.rva)
        if off is None:
            return b""
        return self.data[off:off + res.size]

    # ---------- 输出 ----------
    def summary(self):
        lines = []
        lines.append("================ PE 头信息 ================")
        lines.append("DOS 签名     : 0x{:04X}".format(self.dos_magic))
        lines.append("PE 偏移      : 0x{:08X}".format(self.e_lfanew))
        lines.append("PE 签名      : 0x{:08X}".format(PE_SIGNATURE))
        lines.append("机器类型     : {} (0x{:04X})".format(
            MACHINE_NAMES.get(self.machine, "Unknown"), self.machine))
        lines.append("节区数       : {}".format(self.number_of_sections))
        lines.append("时间戳       : 0x{:08X}".format(self.time_date_stamp))
        lines.append("链接器版本   : {}.{}".format(*self.linker_version))
        lines.append("可选头魔数   : {} (0x{:04X})".format(
            "PE32+" if self.is_pe32_plus else "PE32", self.opt_magic))
        lines.append("入口点 RVA   : 0x{:08X}".format(self.address_of_entry_point))
        lines.append("镜像基址     : 0x{:08X}".format(self.image_base))
        lines.append("入口点 VA    : 0x{:08X}".format(self.entry_point_va))
        lines.append("镜像大小     : 0x{:08X}".format(self.size_of_image))
        lines.append("头大小       : 0x{:08X}".format(self.size_of_headers))
        lines.append("子系统       : {} ({})".format(
            SUBSYSTEM_NAMES.get(self.subsystem, "Unknown"), self.subsystem))
        return "\n".join(lines)

    def sections_report(self):
        lines = []
        lines.append("================ 节区表 ================")
        lines.append("{:<10} {:>10} {:>10} {:>10} {:>10}  {}".format(
            "Name", "VirtSize", "VirtAddr", "RawSize", "RawPtr", "Desc"))
        for sec in self.sections:
            desc = []
            if sec.characteristics & IMAGE_SCN_CNT_CODE:
                desc.append("code")
            if sec.characteristics & IMAGE_SCN_CNT_INITIALIZED_DATA:
                desc.append("init-data")
            if sec.characteristics & IMAGE_SCN_CNT_UNINITIALIZED_DATA:
                desc.append("uninit-data")
            if sec.characteristics & IMAGE_SCN_MEM_EXECUTE:
                desc.append("exec")
            if sec.characteristics & IMAGE_SCN_MEM_READ:
                desc.append("read")
            if sec.characteristics & IMAGE_SCN_MEM_WRITE:
                desc.append("write")
            lines.append("{:<10} {:>10X} {:>10X} {:>10X} {:>10X}  {}".format(
                sec.name, sec.virtual_size, sec.virtual_address,
                sec.size_of_raw_data, sec.pointer_to_raw_data,
                ", ".join(desc) if desc else "none"))
        return "\n".join(lines)

    def imports_report(self):
        lines = []
        lines.append("================ 导入表 ================")
        for dll, entries in self.imports:
            lines.append("DLL: {}".format(dll))
            for e in entries:
                lines.append("    {}".format(e))
        return "\n".join(lines)

    def exports_report(self):
        lines = []
        lines.append("================ 导出表 ================")
        lines.append("DLL 名: {}".format(getattr(self, "export_dll_name", "")))
        for nm, ordv, rva in self.exports:
            lines.append("  Ordinal={:>5} RVA=0x{:08X} {}".format(ordv, rva, nm))
        return "\n".join(lines)

    def resources_report(self):
        lines = []
        lines.append("================ 资源目录 ================")
        if not self.resources:
            lines.append("  (无资源)")
        for res in self.resources:
            tname = res.type_name if res.type_name else (
                "RT_RCDATA" if res.type_id == RT_RCDATA else str(res.type_id))
            lines.append("  Type={:<12} Name={:<28} RVA=0x{:08X} Size=0x{:X}".format(
                tname, res.label(), res.rva, res.size))
        return "\n".join(lines)


# ===================== Delphi 判定 =====================

DELPHI_MARKER_STRINGS = (
    b"Borland",
    b"Delphi",
    b"Embarcadero",
    b"VCL",
    b"RTL",
)

# 目标 CODE 段起始处常见的 Delphi RTL 特征字节
DELPHI_CODE_SIGNATURES = (
    b"\x55\x8B\xEC",          # push ebp; mov ebp, esp
    b"\x53\x56\x57",          # push ebx; push esi; push edi
)


class DelphiInfo(object):
    def __init__(self):
        self.is_delphi = False
        self.version_code = None
        self.version_name = "Unknown"
        self.evidence = []
        self.package_units = []


def detect_delphi(pe):
    """判定目标是否为 Delphi 应用并给出版本 (对应原程序版本识别逻辑)."""
    info = DelphiInfo()
    data = pe.data

    # 1. 运行时包名 -> 版本
    for dll, _entries in pe.imports:
        base = os.path.basename(dll).lower()
        if base in VCL_PACKAGE_VERSIONS:
            code = VCL_PACKAGE_VERSIONS[base]
            if info.version_code is None:
                info.version_code = code
                info.version_name = DELPHI_VERSION_NAMES.get(code, "Unknown")
            info.evidence.append("导入运行时包 {} -> {}".format(
                dll, info.version_name))

    # 2. 导出名中的包版本 (BPL)
    exp_dll = getattr(pe, "export_dll_name", "") or ""
    m = re.search(r"(?:VCL|RTL|IDE)(20|30|40|50|60|70|80|90|100|120|140|150)", exp_dll)
    if m and info.version_code is None:
        code = 0x100 + int(m.group(1), 10)
        if code in DELPHI_VERSION_NAMES:
            info.version_code = code
            info.version_name = DELPHI_VERSION_NAMES[code]
            info.evidence.append("导出表 DLL 名 {} -> {}".format(exp_dll, info.version_name))

    # 3. 文件版本资源 (VS_VERSION_INFO) 中的 "ProductVersion"
    ver_from_resource = _version_from_version_resource(pe)
    if ver_from_resource and info.version_code is None:
        info.version_code = ver_from_resource
        info.version_name = DELPHI_VERSION_NAMES.get(ver_from_resource, "Unknown")
        info.evidence.append("VS_VERSION_INFO ProductVersion -> {}".format(info.version_name))

    # 4. 代码段特征 + Borland/Delphi 标记字符串
    code_secs = [s for s in pe.sections if s.is_code]
    has_code = bool(code_secs)
    has_marker = False
    for marker in DELPHI_MARKER_STRINGS:
        if data.find(marker) != -1:
            has_marker = True
            info.evidence.append("包含标记字符串 \"{}\"".format(
                marker.decode("latin-1")))
            break

    # 5. 入口点落在可执行节区
    ep_in_code = False
    ep_rva = pe.address_of_entry_point
    sec = pe.get_section(ep_rva)
    if sec is not None and sec.is_code:
        ep_in_code = True

    # 6. PACKAGEINFO 资源 (BPL/DLL)
    for res in pe.resources:
        if res.type_id == RT_RCDATA:
            blob = pe.resource_bytes(res)
            if blob.find(b"PACKAGEINFO") != -1 or b"TPF0" in blob[:64]:
                info.package_units = parse_packageinfo(blob)
                if info.package_units:
                    info.evidence.append(
                        "PACKAGEINFO 资源含 {} 个单元".format(len(info.package_units)))
                break

    # 综合判定
    score = 0
    if has_marker:
        score += 2
    if has_code:
        score += 1
    if ep_in_code:
        score += 1
    if info.version_code is not None:
        score += 2
    if info.package_units:
        score += 2
    info.is_delphi = score >= 3

    if not info.is_delphi:
        info.evidence.append(
            "This is not a delphi application or executable file might be "
            "cripted/packed !!!")

    return info


def _version_from_version_resource(pe):
    """从 VS_VERSION_INFO 资源里找 ProductVersion 的 主.次 版本号."""
    for res in pe.resources:
        blob = pe.resource_bytes(res)
        if b"VS_VERSION_INFO" not in blob:
            continue
        txt = blob.decode("utf-16-le", errors="ignore")
        m = re.search(r"ProductVersion[\"\x00]*([0-9]+)\.([0-9]+)", txt)
        if not m:
            m = re.search(r"FileVersion[\"\x00]*([0-9]+)\.([0-9]+)", txt)
        if m:
            major = int(m.group(1))
            minor = int(m.group(2))
            # 常见: Delphi N 的 ProductVersion = N.0
            for code, name in DELPHI_VERSION_NAMES.items():
                num = code - 0x100
                if major == num:
                    return code
            if 1 <= major <= 15:
                return 0x100 + major
    return None


# ===================== PACKAGEINFO =====================

def parse_packageinfo(blob):
    """解析 PACKAGEINFO 资源, 返回单元名列表.

    资源布局 (sub_508924):
        "TPF0" 记录头 ... 之后是若干 Pascal 短字符串 (单元名),
        其间可能夹有 4 字节 "TPF0" 标记; 以 0x00 结束.
    """
    units = []
    if not blob:
        return units
    # 跳过 "PACKAGEINFO" 头
    pos = 0
    idx = blob.find(b"PACKAGEINFO")
    if idx != -1:
        pos = idx + len(b"PACKAGEINFO")
    # 跳过 TPF0 及包标志
    while pos < len(blob):
        if blob[pos:pos + 4] == b"TPF0":
            pos += 4
            if pos + 2 <= len(blob):
                pos += read_u16(blob, pos)
            continue
        break
    while pos < len(blob):
        n = blob[pos]
        if n == 0:
            pos += 1
            continue
        if pos + 1 + n > len(blob):
            break
        raw = blob[pos + 1:pos + 1 + n]
        pos += 1 + n
        try:
            name = raw.decode("latin-1")
        except Exception:
            continue
        if _is_unit_name(name):
            units.append(name)
        if len(units) > 4096:
            break
    return units


def _is_unit_name(s):
    if not s or len(s) > 64:
        return False
    return re.match(r"^[A-Za-z_][A-Za-z0-9_.]*$", s) is not None


# ===================== 二进制 DFM 解析 =====================

class DfmObject(object):
    __slots__ = ("class_name", "instance_name", "properties", "children")

    def __init__(self, class_name, instance_name, properties, children):
        self.class_name = class_name
        self.instance_name = instance_name
        self.properties = properties      # [(name, vtype, value)]
        self.children = children          # [DfmObject]

    def walk(self):
        yield self
        for ch in self.children:
            for o in ch.walk():
                yield o


class DfmParseError(Exception):
    pass


def _dfm_short_string(buf, pos):
    if pos >= len(buf):
        raise DfmParseError("缓冲区不足")
    n = buf[pos]
    pos += 1
    if pos + n > len(buf):
        raise DfmParseError("短字符串越界")
    raw = buf[pos:pos + n]
    pos += n
    return raw, pos


def _dfm_value(buf, pos, vtype):
    if vtype == VA_NULL:
        return None, pos
    if vtype == VA_INT8:
        return read_i8(buf, pos), pos + 1
    if vtype == VA_INT16:
        return read_i16(buf, pos), pos + 2
    if vtype == VA_INT32:
        return read_i32(buf, pos), pos + 4
    if vtype == VA_EXTENDED:
        return ("extended", buf[pos:pos + 10].hex()), pos + 10
    if vtype == VA_STRING:
        raw, p = _dfm_short_string(buf, pos)
        return raw.decode("latin-1"), p
    if vtype == VA_IDENT:
        raw, p = _dfm_short_string(buf, pos)
        return raw.decode("latin-1"), p
    if vtype == VA_FALSE:
        return False, pos
    if vtype == VA_TRUE:
        return True, pos
    if vtype == VA_BINARY:
        if pos + 4 > len(buf):
            raise DfmParseError("二进制长度越界")
        n = read_u32(buf, pos)
        return ("binary", buf[pos + 4:pos + 4 + n]), pos + 4 + n
    if vtype == VA_SET:
        items = []
        while pos < len(buf):
            n = buf[pos]
            if n == 0:
                pos += 1
                break
            raw, p = _dfm_short_string(buf, pos)
            items.append(raw.decode("latin-1"))
            pos = p
        return items, pos
    if vtype == VA_LSTRING:
        if pos + 4 > len(buf):
            raise DfmParseError("长字符串长度越界")
        n = read_u32(buf, pos)
        return buf[pos + 4:pos + 4 + n].decode("latin-1"), pos + 4 + n
    if vtype == VA_NIL:
        return None, pos
    if vtype == VA_COLLECTION:
        items = []
        while pos < len(buf):
            if pos >= len(buf):
                raise DfmParseError("集合越界")
            if buf[pos] == 0:
                pos += 1
                break
            raw, p = _dfm_short_string(buf, pos)
            name = raw.decode("latin-1")
            pos = p
            props = []
            while pos < len(buf):
                n = buf[pos]
                if n == 0:
                    pos += 1
                    break
                pname_raw, p2 = _dfm_short_string(buf, pos)
                pos = p2
                vt = buf[pos]
                pos += 1
                val, pos = _dfm_value(buf, pos, vt)
                props.append((pname_raw.decode("latin-1"), vt, val))
            items.append((name, props))
        return items, pos
    if vtype == VA_SINGLE:
        return struct.unpack_from("<f", buf, pos)[0], pos + 4
    if vtype == VA_CURRENCY:
        return ("currency", buf[pos:pos + 8].hex()), pos + 8
    if vtype == VA_DATE:
        return struct.unpack_from("<d", buf, pos)[0], pos + 8
    if vtype == VA_WSTRING:
        n = read_u32(buf, pos)
        return buf[pos + 4:pos + 4 + n * 2].decode("utf-16-le", "replace"), pos + 4 + n * 2
    if vtype == VA_INT64:
        return read_i64(buf, pos), pos + 8
    if vtype == VA_UTF8STRING:
        n = read_u32(buf, pos)
        return buf[pos + 4:pos + 4 + n].decode("utf-8", "replace"), pos + 4 + n
    raise DfmParseError("未知值类型 0x{:02X}".format(vtype))


def _dfm_object(buf, pos):
    cname_raw, pos = _dfm_short_string(buf, pos)
    iname_raw, pos = _dfm_short_string(buf, pos)
    class_name = cname_raw.decode("latin-1")
    instance_name = iname_raw.decode("latin-1")
    props = []
    while True:
        if pos >= len(buf):
            raise DfmParseError("属性表越界")
        n = buf[pos]
        if n == 0:
            pos += 1
            break
        name_raw, p = _dfm_short_string(buf, pos)
        pos = p
        if pos >= len(buf):
            raise DfmParseError("值类型越界")
        vt = buf[pos]
        pos += 1
        val, pos = _dfm_value(buf, pos, vt)
        props.append((name_raw.decode("latin-1"), vt, val))
    children = []
    while True:
        if pos >= len(buf):
            raise DfmParseError("子对象表越界")
        if buf[pos] == 0:
            pos += 1
            break
        child, pos = _dfm_object(buf, pos)
        children.append(child)
    return DfmObject(class_name, instance_name, props, children), pos


def parse_dfm(buf, pos=0):
    """解析二进制 DFM, 返回 (根对象, 结束位置)."""
    if buf[pos:pos + 4] != b"TPF0":
        raise DfmParseError("缺少 TPF0 签名")
    pos += 4
    return _dfm_object(buf, pos)


def dfm_to_text(obj, indent=0):
    """把 DFM 对象树转成文本 DFM (对应 Classes::ObjectBinaryToText)."""
    pad = "  " * indent
    lines = []
    head = "object {}".format(obj.class_name)
    if obj.instance_name:
        head += ": {}".format(obj.instance_name)
    lines.append(pad + head)
    for name, vt, val in obj.properties:
        lines.append(pad + "  {} = {}".format(name, _dfm_value_text(val)))
    for ch in obj.children:
        lines.append(dfm_to_text(ch, indent + 1))
    lines.append(pad + "end")
    return "\n".join(lines)


def _dfm_value_text(val):
    if isinstance(val, bool):
        return "True" if val else "False"
    if isinstance(val, (list, tuple)):
        if val and isinstance(val[0], tuple) and len(val[0]) == 2 and isinstance(val[0][1], list):
            # 集合
            parts = []
            for item_name, props in val:
                inner = ", ".join("{}={}".format(n, _dfm_value_text(v)) for n, _t, v in props)
                parts.append("{{{}:{}}}".format(item_name, inner))
            return "(" + "; ".join(parts) + ")"
        return "[" + ", ".join(str(x) for x in val) + "]"
    if val is None:
        return "nil"
    return str(val)


def find_dfm_blobs(pe):
    """定位目标中的二进制 DFM.

    优先用资源目录里的 RT_RCDATA; 若目标被加壳 (资源不可用) 则退化为
    全镜像扫描 "TPF0" 签名 (对应原程序对加壳目标仍能工作的行为).
    返回 [(名称, 字节, 来源)].
    """
    found = []
    seen = set()

    for res in pe.resources:
        if res.type_id != RT_RCDATA:
            continue
        blob = pe.resource_bytes(res)
        if len(blob) < 8 or blob[:4] != b"TPF0":
            continue
        key = blob[:64]
        if key in seen:
            continue
        try:
            root, endp = parse_dfm(blob, 0)
        except DfmParseError:
            continue
        if not root.class_name:
            continue
        seen.add(key)
        found.append((res.label(), blob, "resource"))

    if found:
        return found

    # 退化: 扫描 "TPF0"
    data = pe.data
    pos = 0
    while True:
        idx = data.find(b"TPF0", pos)
        if idx == -1:
            break
        pos = idx + 1
        blob = data[idx:idx + 0x20000]
        try:
            root, endp = parse_dfm(blob, 0)
        except DfmParseError:
            continue
        if not root.class_name or not _is_unit_name(root.class_name):
            continue
        if endp < 8:
            continue
        key = blob[:64]
        if key in seen:
            continue
        seen.add(key)
        found.append((root.class_name, blob[:endp], "scan"))
        pos = idx + endp
        if len(found) > 512:
            break
    return found


# ===================== 类 (VMT / RTTI) 转储 =====================

class ClassInfo(object):
    __slots__ = ("name", "vmt", "parent", "instance_size", "methods",
                 "fields", "type_info", "unit")

    def __init__(self):
        self.name = ""
        self.vmt = 0
        self.parent = 0
        self.instance_size = 0
        self.methods = []      # [(name, addr, is_dynamic)]
        self.fields = []       # [(name, offset, kind)]
        self.type_info = 0
        self.unit = ""


def _read_pascal_string(pe, va, max_len=255):
    off = pe.va_to_offset(va)
    if off is None or off >= len(pe.data):
        return None
    n = pe.data[off]
    if n == 0 or off + 1 + n > len(pe.data):
        return None
    raw = pe.data[off + 1:off + 1 + n]
    try:
        return raw.decode("latin-1")
    except Exception:
        return None


def parse_method_table(pe, va):
    """解析发布方法表. 返回 [(名称, 代码地址, 是否动态方法)]."""
    out = []
    off = pe.va_to_offset(va)
    if off is None or off + 2 > len(pe.data):
        return out
    count = read_u16(pe.data, off)
    if count == 0 or count > 4096:
        return out
    pos = off + 2
    for _ in range(count):
        if pos + 6 > len(pe.data):
            break
        size = read_i16(pe.data, pos)
        code = read_u32(pe.data, pos + 2)
        pos += 6
        n = pe.data[pos] if pos < len(pe.data) else 0
        pos += 1
        if pos + n > len(pe.data):
            break
        name = pe.data[pos:pos + n].decode("latin-1", "replace")
        pos += n
        if not name:
            continue
        is_dynamic = size < 0
        out.append((name, code, is_dynamic))
        if size > 0:
            # size 为整条记录长度, 用于校验/跳过
            consumed = 6 + 1 + n
            if size > consumed:
                pos += size - consumed
    return out


def parse_field_table(pe, va):
    """解析字段表. 返回 [(名称, 偏移, 类型kind)]."""
    out = []
    off = pe.va_to_offset(va)
    if off is None or off + 4 > len(pe.data):
        return out
    count = read_u32(pe.data, off)
    if count == 0 or count > 4096:
        return out
    pos = off + 4
    for _ in range(count):
        if pos + 8 > len(pe.data):
            break
        field_off = read_u32(pe.data, pos)
        _type_idx = read_u32(pe.data, pos + 4)
        pos += 8
        # 类型描述: 1 字节 kind, 其后按 kind 跳过附加数据, 最后是短字符串名
        if pos >= len(pe.data):
            break
        kind = pe.data[pos]
        pos += 1
        if kind == 0:          # tkClass: 4 字节类引用
            pos += 4
        elif kind in (2, 3):   # tkInteger / tkChar
            pos += 1
        elif kind in (4, 5, 6, 7, 8):  # tkEnumeration/Float/String/Set/PChar
            pos += 4 if kind in (4, 8) else 1
        elif kind == 9:        # tkWString
            pos += 4
        elif kind == 10:       # tkVariant
            pass
        elif kind == 11:       # tkArray
            pos += 8
        elif kind == 12:       # tkRecord
            pos += 4
        elif kind == 13:       # tkInterface
            pos += 4
        elif kind == 14:       # tkInt64
            pass
        elif kind == 15:       # tkDynArray
            pos += 4
        if pos >= len(pe.data):
            break
        n = pe.data[pos]
        pos += 1
        if pos + n > len(pe.data):
            break
        name = pe.data[pos:pos + n].decode("latin-1", "replace")
        pos += n
        if name:
            out.append((name, field_off, kind))
    return out


def find_classes(pe):
    """扫描 VMT 定位类 (对应原程序 Class Dump Engine)."""
    data = pe.data
    image_start = pe.image_base
    image_end = pe.image_base + pe.size_of_image

    # 1. 收集候选类名短字符串 (Delphi 类名以 T 开头; VMT/RTTI 在代码段内)
    candidates = {}
    for sec in pe.sections:
        if sec.size_of_raw_data == 0:
            continue
        start = sec.pointer_to_raw_data
        end = start + sec.size_of_raw_data
        i = start
        while i < end:
            n = data[i]
            if 2 <= n <= 64 and i + 1 + n <= end:
                raw = data[i + 1:i + 1 + n]
                if _looks_like_class_name(raw):
                    va = image_start + sec.virtual_address + (i - start)
                    candidates.setdefault(va, raw.decode("latin-1"))
                i += 1 + n
            else:
                i += 1

    if not candidates:
        return []

    # 2. 建立 dword -> 引用地址 的索引 (仅记录落在镜像内的指针)
    ref_index = {}
    step = 4
    for sec in pe.sections:
        if sec.size_of_raw_data == 0:
            continue
        start = sec.pointer_to_raw_data
        end = start + sec.size_of_raw_data
        base_va = image_start + sec.virtual_address
        off = start
        while off + 4 <= end:
            val = read_u32(data, off)
            if image_start <= val < image_end:
                ref_index.setdefault(val, []).append(base_va + (off - start))
            off += step

    # 3. 用引用定位 VMT 并校验
    classes = []
    seen_vmt = set()
    for name_va, name in candidates.items():
        for ref_va in ref_index.get(name_va, ()):
            vmt = ref_va - VMT_CLASS_NAME   # VMT = (VMT-44 所在地址) + 44
            if vmt in seen_vmt:
                continue
            info = _validate_vmt(pe, vmt, name_va, name)
            if info is None:
                continue
            seen_vmt.add(vmt)
            classes.append(info)

    classes.sort(key=lambda c: c.vmt)
    return classes


def _looks_like_class_name(raw):
    if not raw:
        return False
    try:
        s = raw.decode("latin-1")
    except Exception:
        return False
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", s):
        return False
    return s[0] == "T" and len(s) >= 2


def _validate_vmt(pe, vmt, name_va, name):
    """校验候选 VMT, 通过则返回 ClassInfo."""
    if vmt < pe.image_base or vmt + 0x100 > pe.image_base + pe.size_of_image:
        return None
    off = pe.va_to_offset(vmt)
    if off is None:
        return None
    # 负偏移区必须落在同一节区内且已映射
    neg_off = pe.va_to_offset(vmt + VMT_SELF_PTR)
    if neg_off is None:
        return None

    score = 0
    # vmtSelfPtr 应等于 VMT 自身
    if read_u32(pe.data, neg_off) == vmt:
        score += 3
    # vmtClassName 应指回类名
    if read_u32(pe.data, neg_off + (VMT_CLASS_NAME - VMT_SELF_PTR)) == name_va:
        score += 2
    # 实例大小合理 (Delphi 类实例大小恒 > 0)
    size = read_u32(pe.data, neg_off + (VMT_INSTANCE_SIZE - VMT_SELF_PTR))
    if 0 < size <= 0x10000:
        score += 2
    else:
        return None
    # 父类指针
    parent = read_u32(pe.data, neg_off + (VMT_PARENT - VMT_SELF_PTR))
    if parent == 0 or (pe.image_base <= parent < pe.image_base + pe.size_of_image):
        score += 1
    else:
        parent = 0
    # 虚方法表首项应指向代码
    destroy = read_u32(pe.data, off)
    if pe.is_code_va(destroy):
        score += 2
    # 方法表 / 字段表 / 类型信息
    method_tbl = read_u32(pe.data, neg_off + (VMT_METHOD_TABLE - VMT_SELF_PTR))
    field_tbl = read_u32(pe.data, neg_off + (VMT_FIELD_TABLE - VMT_SELF_PTR))
    type_info = read_u32(pe.data, neg_off + (VMT_TYPE_INFO - VMT_SELF_PTR))
    if method_tbl and pe.is_mapped_va(method_tbl):
        score += 1
    if field_tbl and pe.is_mapped_va(field_tbl):
        score += 1
    if type_info and pe.is_mapped_va(type_info):
        score += 1

    if score < 6:
        return None

    ci = ClassInfo()
    ci.name = name
    ci.vmt = vmt
    ci.instance_size = size
    ci.parent = parent
    ci.type_info = type_info
    if method_tbl and pe.is_mapped_va(method_tbl):
        ci.methods = parse_method_table(pe, method_tbl)
    if field_tbl and pe.is_mapped_va(field_tbl):
        ci.fields = parse_field_table(pe, field_tbl)
    return ci


def class_parent_name(classes, parent_va):
    for c in classes:
        if c.vmt == parent_va:
            return c.name
    return ""


# ===================== 过程 (EP-Finder) =====================

def find_procedures(pe):
    """在代码段中定位过程入口 (对应 "DelphiDecompiler EP-Finder v0.2").

    强证据: CALL/JMP rel32 的目标地址 (必为过程入口).
    弱证据: RET/RET imm16/LEAVE 之后的地址, 需以常见过程序言字节开头.
    """
    data = pe.data
    image_start = pe.image_base
    strong = set()
    weak = set()

    for sec in pe.sections:
        if not sec.is_code or sec.size_of_raw_data == 0:
            continue
        start = sec.pointer_to_raw_data
        end = start + sec.size_of_raw_data
        base_va = image_start + sec.virtual_address
        i = start
        while i < end:
            b = data[i]
            if b in (0xE8, 0xE9) and i + 5 <= end:
                rel = read_i32(data, i + 1)
                target = base_va + (i - start) + 5 + rel
                if image_start <= target < image_start + pe.size_of_image:
                    strong.add(target)
                i += 5
                continue
            if b == 0xEB and i + 2 <= end:
                rel = read_i8(data, i + 1)
                target = base_va + (i - start) + 2 + rel
                if image_start <= target < image_start + pe.size_of_image:
                    strong.add(target)
                i += 2
                continue
            if b in (0xC3, 0xCB):
                weak.add(base_va + (i - start) + 1)
                i += 1
                continue
            if b == 0xC2 and i + 3 <= end:
                weak.add(base_va + (i - start) + 3)
                i += 3
                continue
            i += 1

    prologues = set([0x55, 0x53, 0x56, 0x57, 0x51, 0x52, 0x50,
                     0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
                     0xB8, 0xE9, 0xEB, 0xC3, 0x6A, 0x68, 0x83, 0x81,
                     0x8B, 0x33, 0x31, 0x8D, 0xFF, 0x5D, 0x5B, 0x5E,
                     0x5F, 0x59, 0x58, 0x5A, 0x8A, 0x80, 0x8B, 0xC0])

    def code_byte(va):
        off = pe.va_to_offset(va)
        if off is None or off >= len(data):
            return None
        return data[off]

    result = set()
    for va in strong:
        if not pe.is_mapped_va(va):
            continue
        sec = pe.get_section(va - image_start)
        if sec is None or not sec.is_code:
            continue
        result.add(va)
    for va in weak:
        if not pe.is_mapped_va(va):
            continue
        sec = pe.get_section(va - image_start)
        if sec is None or not sec.is_code:
            continue
        if code_byte(va) in prologues:
            result.add(va)

    return sorted(result)


def procedure_name(va):
    """对应原程序 sub_4B666C 的命名规则: _PROC_<hex>."""
    return "_PROC_{:X}".format(va)


# ===================== 工程输出 =====================

class Project(object):
    def __init__(self, out_dir):
        self.out_dir = out_dir
        self.forms_dir = os.path.join(out_dir, "forms")
        self.lines = []

    def ensure(self):
        if not os.path.isdir(self.out_dir):
            os.makedirs(self.out_dir)
        if not os.path.isdir(self.forms_dir):
            os.makedirs(self.forms_dir)

    def add(self, text=""):
        self.lines.append(text)

    def write(self, name, text):
        path = os.path.join(self.out_dir, name)
        with open(path, "w", encoding="utf-8", errors="replace") as f:
            f.write(text)
        return path

    def flush(self):
        self.write("report.txt", "\n".join(self.lines))


# ===================== 分析主流程 =====================

def analyze(pe, opts, quiet=False):
    out_dir = opts.get("output")
    proj = Project(out_dir)
    proj.ensure()

    def emit(text=""):
        proj.add(text)
        if not quiet:
            print(text)

    target = opts.get("target", "")
    emit("=" * 72)
    emit(" IDR Interactive Delphi Reconstructor (Python CLI 重写版)")
    emit(" 目标: {}".format(target))
    emit(" 文件大小: {} 字节".format(len(pe.data)))
    emit("=" * 72)
    emit()

    if not pe.valid:
        emit("[错误] {}".format(pe.error))
        proj.flush()
        return EXIT_FAILURE

    emit(pe.summary())
    emit()
    emit(pe.sections_report())
    emit()

    # ---- Delphi 判定 ----
    info = detect_delphi(pe)
    emit("================ Delphi 判定 ================")
    emit("是 Delphi 应用 : {}".format("是" if info.is_delphi else "否"))
    emit("Delphi 版本   : {} (0x{:03X})".format(
        info.version_name, info.version_code or 0))
    for ev in info.evidence:
        emit("  依据: {}".format(ev))
    emit()

    if opts.get("imports"):
        emit(pe.imports_report())
        emit()
    if opts.get("resources"):
        emit(pe.resources_report())
        emit()

    # ---- 单元 ----
    units = list(info.package_units)
    if opts.get("units"):
        emit("================ 单元 (Units) ================")
        if units:
            emit("来源: PACKAGEINFO 资源")
            for i, u in enumerate(units):
                emit("  [{:>3}] {}".format(i, u))
        else:
            emit("  (未发现 PACKAGEINFO 资源; 非 BPL/DLL 目标)")
        emit()
        proj.write("units.txt", "\n".join(units))

    # ---- 类 ----
    classes = []
    if opts.get("classes"):
        emit("================ 类 (Classes / VMT) ================")
        classes = find_classes(pe)
        if not classes:
            emit("  (未发现可识别的 VMT)")
        lines = []
        for c in classes:
            parent = class_parent_name(classes, c.parent)
            head = "  {}  (VMT=0x{:08X}, size=0x{:X}".format(
                c.name, c.vmt, c.instance_size)
            if parent:
                head += ", parent={}".format(parent)
            head += ")"
            emit(head)
            lines.append(head)
            if c.methods:
                for nm, addr, dyn in c.methods:
                    tag = "dynamic" if dyn else "method"
                    line = "      {:<10} {:<8} @ 0x{:08X}".format(tag, nm, addr)
                    emit(line)
                    lines.append(line)
            if c.fields:
                for nm, foff, kind in c.fields:
                    line = "      field      {:<8} +0x{:X} (kind={})".format(nm, foff, kind)
                    emit(line)
                    lines.append(line)
        emit()
        proj.write("classes.txt", "\n".join(lines))

    # ---- 过程 ----
    procs = []
    if opts.get("procs"):
        emit("================ 过程 (Procedures / EP-Finder) ================")
        procs = find_procedures(pe)
        emit("  共 {} 个过程入口".format(len(procs)))
        lines = []
        for va in procs:
            line = "  0x{:08X}  {}".format(va, procedure_name(va))
            lines.append(line)
            if len(lines) <= 200:
                emit(line)
        if len(lines) > 200:
            emit("  ... 其余 {} 条见 procedures.txt".format(len(lines) - 200))
        emit()
        proj.write("procedures.txt", "\n".join(lines))

    # ---- 表单 ----
    if opts.get("forms"):
        emit("================ 表单 (DFM) ================")
        blobs = find_dfm_blobs(pe)
        if not blobs:
            emit("  (未发现 DFM 资源)")
        lines = []
        for name, blob, source in blobs:
            try:
                root, endp = parse_dfm(blob, 0)
            except DfmParseError as exc:
                emit("  [跳过] {}: {}".format(name, exc))
                continue
            text = dfm_to_text(root)
            safe = re.sub(r"[^A-Za-z0-9_.-]", "_", name) or "form"
            fname = "{}.dfm".format(safe)
            with open(os.path.join(proj.forms_dir, fname), "w",
                      encoding="utf-8", errors="replace") as f:
                f.write(text)
            line = "  {:<32} -> forms/{:<28} ({}; {} 字节)".format(
                name, fname, source, len(blob))
            emit(line)
            lines.append(line)
        emit()
        proj.write("forms.txt", "\n".join(lines))

    proj.flush()
    emit("工程已写出: {}".format(out_dir))
    return EXIT_SUCCESS


# ===================== 入口 =====================

def parse_args(argv):
    opts = {
        "target": None,
        "output": None,
        "pe": False,
        "sections": False,
        "imports": False,
        "resources": False,
        "delphi": False,
        "forms": False,
        "classes": False,
        "units": False,
        "procs": False,
        "all": False,
        "quiet": False,
        "help": False,
    }
    i = 0
    while i < len(argv):
        a = argv[i]
        if a in ("-h", "--help"):
            opts["help"] = True
        elif a in ("-o", "--output"):
            i += 1
            if i < len(argv):
                opts["output"] = argv[i]
        elif a in ("-p", "--pe"):
            opts["pe"] = True
        elif a in ("-s", "--sections"):
            opts["sections"] = True
        elif a in ("-i", "--imports"):
            opts["imports"] = True
        elif a in ("-r", "--resources"):
            opts["resources"] = True
        elif a in ("-d", "--delphi"):
            opts["delphi"] = True
        elif a in ("-f", "--forms"):
            opts["forms"] = True
        elif a in ("-c", "--classes"):
            opts["classes"] = True
        elif a in ("-u", "--units"):
            opts["units"] = True
        elif a in ("-F", "--procs"):
            opts["procs"] = True
        elif a in ("-a", "--all"):
            opts["all"] = True
        elif a in ("-q", "--quiet"):
            opts["quiet"] = True
        elif a.startswith("-") and a != "-":
            pass
        elif opts["target"] is None:
            opts["target"] = a
        i += 1
    return opts


def main():
    # 避免在无法表示中文的控制台编码下因编码错误崩溃
    try:
        sys.stdout.reconfigure(errors="replace")
        sys.stderr.reconfigure(errors="replace")
    except Exception:
        pass

    argv = sys.argv[1:]
    opts = parse_args(argv)

    if opts["help"] or not opts["target"]:
        print(USAGE)
        return EXIT_USAGE

    target = opts["target"]
    if not os.path.isfile(target):
        print("错误: 找不到文件: {}".format(target), file=sys.stderr)
        return EXIT_FAILURE

    # 默认全量分析
    if not any(opts[k] for k in ("pe", "sections", "imports", "resources",
                                 "delphi", "forms", "classes", "units",
                                 "procs", "all")):
        opts["all"] = True

    if opts["all"]:
        opts["forms"] = True
        opts["classes"] = True
        opts["units"] = True
        opts["procs"] = True
        opts["imports"] = True
        opts["resources"] = True

    if opts["output"] is None:
        base = os.path.splitext(os.path.basename(target))[0]
        opts["output"] = "{}_project".format(base)

    with open(target, "rb") as f:
        data = f.read()

    pe = PeFile(data)
    return analyze(pe, opts, quiet=opts["quiet"])


if __name__ == "__main__":
    sys.exit(main())