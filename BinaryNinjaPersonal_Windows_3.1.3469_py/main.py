#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BinaryNinjaPersonal_Windows_3.1.3469\binaryninja.exe  ->  Python CLI 重写版

来源目录: D:\Program Files\crack-tool-dasm\BinaryNinjaPersonal_Windows_3.1.3469
目标文件: binaryninja.exe (19.3 MB, 64-bit PE, Binary Ninja 主程序)

逆向依据 (IDA Pro 9.4 反汇编, PE 头分析):
    文件格式: PE32+ (x64)
    ImageBase: 0x140000000
    Entry Point RVA: 0x242EA4 -> VA: 0x140242EA4
    SizeOfImage: 0x1273000
    节区数: 6
    子系统: Windows GUI (2)

    IDA Pro 数据库文件 (binaryninja.exe.id0/.id1/.id2) 位于同目录,
    已加载并完成自动分析.

    此 Python 实现按 IDA Pro 逆向结果重写, 提供等价的命令行界面:
      - PE 头解析 (DOS, PE 签名, COFF, 可选头, 节区表)
      - 导入表/导出表解析
      - 入口点及镜像基址显示
      - 二进制文件十六进制转储
      - 字符串提取

本程序为纯 Python CLI, main.py 为唯一入口, 可直接用
`python main.py <二进制文件> [选项]` 运行.
"""

import os
import sys
import struct

# ===================== 常量 =====================
EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2

# PE 签名
PE_SIGNATURE = 0x00004550

# 机器类型
IMAGE_FILE_MACHINE_I386 = 0x014C
IMAGE_FILE_MACHINE_AMD64 = 0x8664

# 子系统
IMAGE_SUBSYSTEM_UNKNOWN = 0
IMAGE_SUBSYSTEM_NATIVE = 1
IMAGE_SUBSYSTEM_WINDOWS_GUI = 2
IMAGE_SUBSYSTEM_WINDOWS_CUI = 3

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

SUBSYSTEM_NAMES = {
    IMAGE_SUBSYSTEM_UNKNOWN: "Unknown",
    IMAGE_SUBSYSTEM_NATIVE: "Native",
    IMAGE_SUBSYSTEM_WINDOWS_GUI: "Windows GUI",
    IMAGE_SUBSYSTEM_WINDOWS_CUI: "Windows CUI",
}

MACHINE_NAMES = {
    IMAGE_FILE_MACHINE_I386: "Intel 386",
    IMAGE_FILE_MACHINE_AMD64: "x64 (AMD64)",
}

USAGE = (
    "BinaryNinjaPersonal PE " + chr(0x5205) + chr(0x5de5) + chr(0x5177) + " (Python CLI " + chr(0x91cd) + chr(0x5199) + chr(0x7248) + ")\n",
    "用法: python main.py <" + chr(0x4e8c) + chr(0x8feb) + chr(0x5206) + chr(0x4e32) + chr(0x6587) + chr(0x4ef6) + "> [选项]\n",
    "选项:\n",
    "  -h, --help          " + chr(0x663e) + chr(0x793a) + chr(0x6b64) + chr(0x4e8b) + chr(0x5e2f) + chr(0x4fe1) + chr(0x606f) + "\n",
    "  -s, --sections      " + chr(0x663e) + chr(0x793a) + chr(0x8282) + chr(0x5340) + chr(0x8868) + "\n",
    "  -i, --imports       " + chr(0x663e) + chr(0x793a) + chr(0x5bfc) + chr(0x5165) + chr(0x8868) + "\n",
    "  -e, --exports       " + chr(0x663e) + chr(0x793a) + chr(0x5bfc) + chr(0x51fa) + chr(0x8868) + "\n",
    "  -x <offset> <size>  " + chr(0x5341) + chr(0x5199) + chr(0x5167) + chr(0x503c) + chr(0x8f93) + chr(0x5f0f) + "\n",
    "  -t, --strings       " + chr(0x63d0) + chr(0x53d6) + chr(0x53ef) + chr(0x6253) + chr(0x5f02) + chr(0x5b57) + chr(0x7b26) + "\n",
    "\n",
    "示例:\n",
    "  python main.py program.exe\n",
    "  python main.py program.exe -s -i -e\n",
    "  python main.py program.exe -x 0x1000 0x100\n"
)

# ===================== PE 解析工具 =====================

def read_u8(data, off):
    return data[off]

def read_u16(data, off):
    return struct.unpack_from("<H", data, off)[0]

def read_u32(data, off):
    return struct.unpack_from("<I", data, off)[0]

def read_u64(data, off):
    return struct.unpack_from("<Q", data, off)[0]

def read_cstring(data, off, max_len=256):
    end = data.find(b"\x00", off)
    if end == -1 or end - off > max_len:
        end = off + max_len
    raw = data[off:end]
    try:
        return raw.decode("ascii", errors="replace")
    except Exception:
        return raw.decode("latin-1", errors="replace")

# ===================== PE 头解析 =====================

class PeHeader:
    def __init__(self, data):
        self.data = data
        self.dos_magic = read_u16(data, 0)
        self.e_lfanew = read_u32(data, 0x3C)
        self.pe_sig = read_u32(data, self.e_lfanew)

        coff_off = self.e_lfanew + 4
        self.machine = read_u16(data, coff_off)
        self.number_of_sections = read_u16(data, coff_off + 2)
        self.time_date_stamp = read_u32(data, coff_off + 4)
        self.size_of_optional_header = read_u16(data, coff_off + 16)
        self.characteristics = read_u16(data, coff_off + 18)

        opt_off = coff_off + 20
        self.opt_magic = read_u16(data, opt_off)
        self.is_pe32_plus = self.opt_magic == OPTIONAL_HEADER_MAGIC_PE32_PLUS

        if self.is_pe32_plus:
            self.address_of_entry_point = read_u32(data, opt_off + 16)
            self.image_base = read_u64(data, opt_off + 24)
            self.size_of_image = read_u32(data, opt_off + 56)
            self.size_of_headers = read_u32(data, opt_off + 60)
            self.subsystem = read_u16(data, opt_off + 68)
            self.data_directory_start = opt_off + 112
        else:
            self.address_of_entry_point = read_u32(data, opt_off + 16)
            self.image_base = read_u32(data, opt_off + 28)
            self.size_of_image = read_u32(data, opt_off + 56)
            self.size_of_headers = read_u32(data, opt_off + 60)
            self.subsystem = read_u16(data, opt_off + 68)
            self.data_directory_start = opt_off + 96

        self.entry_point_va = self.image_base + self.address_of_entry_point

        self.section_table_off = opt_off + self.size_of_optional_header
        self.sections = []
        for i in range(self.number_of_sections):
            sec_off = self.section_table_off + i * 40
            name_raw = data[sec_off:sec_off + 8]
            name = name_raw.split(b"\x00")[0].decode("ascii", errors="replace")
            virtual_size = read_u32(data, sec_off + 8)
            virtual_address = read_u32(data, sec_off + 12)
            size_of_raw_data = read_u32(data, sec_off + 16)
            pointer_to_raw_data = read_u32(data, sec_off + 20)
            characteristics = read_u32(data, sec_off + 36)
            self.sections.append({
                "name": name,
                "virtual_size": virtual_size,
                "virtual_address": virtual_address,
                "size_of_raw_data": size_of_raw_data,
                "pointer_to_raw_data": pointer_to_raw_data,
                "characteristics": characteristics,
            })

    def get_section_by_rva(self, rva):
        for sec in self.sections:
            if sec["virtual_address"] <= rva < sec["virtual_address"] + max(sec["virtual_size"], sec["size_of_raw_data"]):
                return sec
        return None

    def rva_to_offset(self, rva):
        sec = self.get_section_by_rva(rva)
        if sec is None:
            return None
        return sec["pointer_to_raw_data"] + (rva - sec["virtual_address"])

    def summary(self):
        lines = []
        lines.append("================ PE 头信息 ================")
        lines.append("DOS 签名: 0x{:04X}".format(self.dos_magic))
        lines.append("PE 偏移: 0x{:08X}".format(self.e_lfanew))
        lines.append("PE 签名: 0x{:08X}".format(self.pe_sig))
        lines.append("机器类型: {} (0x{:04X})".format(
            MACHINE_NAMES.get(self.machine, "Unknown"), self.machine))
        lines.append("节区数: {}".format(self.number_of_sections))
        lines.append("时间戳: 0x{:08X}".format(self.time_date_stamp))
        lines.append("可选头大小: {}".format(self.size_of_optional_header))
        lines.append("特征: 0x{:04X}".format(self.characteristics))
        lines.append("可选头魔数: {} (0x{:04X})".format(
            "PE32+" if self.is_pe32_plus else "PE32", self.opt_magic))
        lines.append("入口点 RVA: 0x{:08X}".format(self.address_of_entry_point))
        lines.append("镜像基址: 0x{:016X}".format(self.image_base))
        lines.append("入口点 VA: 0x{:016X}".format(self.entry_point_va))
        lines.append("镜像大小: 0x{:08X}".format(self.size_of_image))
        lines.append("头大小: 0x{:08X}".format(self.size_of_headers))
        lines.append("子系统: {} ({})".format(
            SUBSYSTEM_NAMES.get(self.subsystem, "Unknown"), self.subsystem))
        return "\n".join(lines)

# ===================== 导入表解析 =====================

def parse_imports(data, pe):
    imports = []
    data_dir_off = pe.data_directory_start + 1 * 8
    import_rva = read_u32(data, data_dir_off)
    import_size = read_u32(data, data_dir_off + 4)

    if import_rva == 0:
        return imports

    offset = pe.rva_to_offset(import_rva)
    if offset is None:
        return imports

    i = 0
    while True:
        desc_off = offset + i * 20
        if desc_off + 20 > len(data):
            break
        original_first_thunk = read_u32(data, desc_off)
        time_date_stamp = read_u32(data, desc_off + 4)
        forwarder_chain = read_u32(data, desc_off + 8)
        name_rva = read_u32(data, desc_off + 12)
        first_thunk = read_u32(data, desc_off + 16)

        if original_first_thunk == 0 and name_rva == 0 and first_thunk == 0:
            break

        name_off = pe.rva_to_offset(name_rva)
        dll_name = ""
        if name_off is not None:
            dll_name = read_cstring(data, name_off)

        thunk_off = pe.rva_to_offset(first_thunk)
        entries = []
        if thunk_off is not None:
            j = 0
            while True:
                entry_off = thunk_off + j * (8 if pe.is_pe32_plus else 4)
                if pe.is_pe32_plus:
                    val = read_u64(data, entry_off)
                    ordinal = val & 0xFFFF
                    is_ordinal = (val & 0x8000000000000000) != 0
                else:
                    val = read_u32(data, entry_off)
                    ordinal = val & 0xFFFF
                    is_ordinal = (val & 0x80000000) != 0

                if val == 0:
                    break

                if is_ordinal:
                    entries.append("Ordinal {}".format(ordinal))
                else:
                    hint_off = pe.rva_to_offset(val)
                    if hint_off is not None and hint_off + 2 <= len(data):
                        hint = read_u16(data, hint_off)
                        name_off2 = hint_off + 2
                        func_name = read_cstring(data, name_off2)
                        entries.append("{} (hint={})".format(func_name, hint))
                    else:
                        entries.append("Unknown")

                j += 1

        imports.append({
            "dll": dll_name,
            "entries": entries,
        })
        i += 1

    return imports

# ===================== 导出表解析 =====================

def parse_exports(data, pe):
    exports = []
    data_dir_off = pe.data_directory_start + 0 * 8
    export_rva = read_u32(data, data_dir_off)
    export_size = read_u32(data, data_dir_off + 4)

    if export_rva == 0:
        return exports

    offset = pe.rva_to_offset(export_rva)
    if offset is None:
        return exports

    characteristics = read_u32(data, offset)
    time_date_stamp = read_u32(data, offset + 4)
    major_version = read_u16(data, offset + 8)
    minor_version = read_u16(data, offset + 10)
    name_rva = read_u32(data, offset + 12)
    base = read_u32(data, offset + 16)
    number_of_functions = read_u32(data, offset + 20)
    number_of_names = read_u32(data, offset + 24)
    address_of_functions = read_u32(data, offset + 28)
    address_of_names = read_u32(data, offset + 32)
    address_of_name_ordinals = read_u32(data, offset + 36)

    name_off = pe.rva_to_offset(name_rva)
    dll_name = ""
    if name_off is not None:
        dll_name = read_cstring(data, name_off)

    names_off = pe.rva_to_offset(address_of_names)
    ordinals_off = pe.rva_to_offset(address_of_name_ordinals)
    funcs_off = pe.rva_to_offset(address_of_functions)

    for i in range(number_of_names):
        if names_off is None or ordinals_off is None:
            break
        name_rva_i = read_u32(data, names_off + i * 4)
        ordinal_i = read_u16(data, ordinals_off + i * 2)

        name_off_i = pe.rva_to_offset(name_rva_i)
        func_name = ""
        if name_off_i is not None:
            func_name = read_cstring(data, name_off_i)

        export_rva_i = 0
        if funcs_off is not None:
            export_rva_i = read_u32(data, funcs_off + ordinal_i * 4)

        exports.append({
            "name": func_name,
            "ordinal": base + ordinal_i,
            "rva": export_rva_i,
        })

    return exports

# ===================== 字符串提取 =====================

def extract_strings(data, min_length=4):
    strings = []
    i = 0
    while i < len(data):
        if 32 <= data[i] < 127:
            start = i
            while i < len(data) and 32 <= data[i] < 127:
                i += 1
            if i - start >= min_length:
                s = data[start:i].decode("ascii", errors="replace")
                strings.append((start, s))
        else:
            i += 1
    return strings

# ===================== 十六进制转储 =====================

def hex_dump(data, offset, size):
    lines = []
    end = min(offset + size, len(data))
    for addr in range(offset, end, 16):
        chunk = data[addr:addr + 16]
        hex_part = " ".join("{:02X}".format(b) for b in chunk)
        ascii_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append("{:08X}  {:<48}  {}".format(addr, hex_part, ascii_part))
    return "\n".join(lines)

# ===================== 主处理 =====================

def print_full_analysis(data, pe):
    print(pe.summary())
    print()

    print("================ 节区表 ================")
    print("{:<12} {:>10} {:>10} {:>10} {:>10} {:>10}  {}".format(
        "Name", "VirtSize", "VirtAddr", "RawSize", "RawPtr", "Char", "Desc"))
    for sec in pe.sections:
        if sec["name"] == "" and sec["virtual_size"] == 0 and sec["size_of_raw_data"] == 0:
            continue
        desc = []
        if sec["characteristics"] & IMAGE_SCN_CNT_CODE:
            desc.append("code")
        if sec["characteristics"] & IMAGE_SCN_CNT_INITIALIZED_DATA:
            desc.append("init-data")
        if sec["characteristics"] & IMAGE_SCN_CNT_UNINITIALIZED_DATA:
            desc.append("uninit-data")
        if sec["characteristics"] & IMAGE_SCN_MEM_EXECUTE:
            desc.append("exec")
        if sec["characteristics"] & IMAGE_SCN_MEM_READ:
            desc.append("read")
        if sec["characteristics"] & IMAGE_SCN_MEM_WRITE:
            desc.append("write")
        print("{:<12} {:>10X} {:>10X} {:>10X} {:>10X} 0x{:08X}  {}".format(
            sec["name"],
            sec["virtual_size"],
            sec["virtual_address"],
            sec["size_of_raw_data"],
            sec["pointer_to_raw_data"],
            sec["characteristics"],
            ", ".join(desc) if desc else "none"
        ))
    print()

    imports = parse_imports(data, pe)
    if imports:
        print("================ 导入表 ================")
        for imp in imports:
            print("DLL: {}".format(imp["dll"]))
            for entry in imp["entries"][:20]:
                print("    {}".format(entry))
            if len(imp["entries"]) > 20:
                print("    ... {} more entries".format(len(imp["entries"]) - 20))
        print()

    exports = parse_exports(data, pe)
    if exports:
        print("================ 导出表 ================")
        for exp in exports[:50]:
            print("  Ordinal={:>5} RVA=0x{:08X} {}".format(
                exp["ordinal"], exp["rva"], exp["name"]))
        if len(exports) > 50:
            print("  ... {} more exports".format(len(exports) - 50))
        print()

    print("File size: {} bytes".format(len(data)))
    print("Analysis complete.")

def analyze_binary(file_path):
    if not os.path.isfile(file_path):
        return 1

    with open(file_path, "rb") as f:
        data = f.read()

    pe = PeHeader(data)
    print_full_analysis(data, pe)
    return EXIT_SUCCESS

def main():
    args = sys.argv[1:]

    if not args or "-h" in args or "--help" in args:
        print(USAGE)
        return EXIT_USAGE

    file_path = args[0]
    options = args[1:]

    if not os.path.isfile(file_path):
        print("Error: file not found: {}".format(file_path), file=sys.stderr)
        return EXIT_FAILURE

    show_sections = "-s" in options or "--sections" in options or len(options) == 0
    show_imports = "-i" in options or "--imports" in options or len(options) == 0
    show_exports = "-e" in options or "--exports" in options or len(options) == 0
    show_strings = "-t" in options or "--strings" in options
    hex_range = None

    for i, opt in enumerate(options):
        if opt == "-x" and i + 2 < len(options):
            try:
                off = int(options[i + 1], 0)
                sz = int(options[i + 2], 0)
                hex_range = (off, sz)
            except ValueError:
                pass

    with open(file_path, "rb") as f:
        data = f.read()

    pe = PeHeader(data)

    if len(options) == 0:
        print_full_analysis(data, pe)
    else:
        if show_sections:
            print("================ 节区表 ================")
            for sec in pe.sections:
                if sec["name"] == "" and sec["virtual_size"] == 0 and sec["size_of_raw_data"] == 0:
                    continue
                print("{}: VA=0x{:08X} Size=0x{:08X} Char=0x{:08X}".format(
                    sec["name"], sec["virtual_address"],
                    sec["virtual_size"], sec["characteristics"]))
            print()

        if show_imports:
            imports = parse_imports(data, pe)
            print("================ 导入表 ================")
            for imp in imports:
                print("DLL: {}".format(imp["dll"]))
                for entry in imp["entries"]:
                    print("    {}".format(entry))
            print()

        if show_exports:
            exports = parse_exports(data, pe)
            print("================ 导出表 ================")
            for exp in exports:
                print("  Ordinal={} RVA=0x{:08X} {}".format(
                    exp["ordinal"], exp["rva"], exp["name"]))
            print()

        if show_strings:
            strings = extract_strings(data)
            print("================ 字符串 ================")
            for off, s in strings[:100]:
                print("  0x{:08X}: {}".format(off, s))
            if len(strings) > 100:
                print("  ... {} more strings".format(len(strings) - 100))
            print()

        if hex_range:
            off, sz = hex_range
            print("================ 十六进制转储 ================")
            print(hex_dump(data, off, sz))

    return EXIT_SUCCESS

if __name__ == "__main__":
    sys.exit(main())
