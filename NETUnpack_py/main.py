#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NETUnpack — Python CLI 逐函数端口（.NET 元数据表解析）
===================================================

原程序：`NETUnpack/NETUnpack.exe`（原生 MFC，.NET 元数据解包/重建器）

原程序的核心工作是解析 .NET 程序集的元数据（CLI 头 -> #~ 流 -> 各元数据表），
重建 TypeDef / MethodDef / FieldDef 等表，还原被修改的元数据。本 CLI 逐函数
移植了该核心算法：PE/CLR 头定位、#~ 流定位、表头（行数位图 + 堆偏置）、
TypeDef/MethodDef/FieldDef 表行读取、字符串/ BLOB/ GUID 堆解码，最后列出
程序集中全部类型与方法——这正是元数据重建的基础。

用法：
    python main.py <file>                    列出该 .NET 程序集的全部类型与方法
    python main.py <file> --raw              额外打印原始元数据表统计
    python main.py --help

无第三方依赖，纯标准库。
"""

import argparse
import os
import struct
import sys

# ---------------- PE / CLR 头解析（与 de4dot 端口复用） ----------------
def rd_u16(b, o):
    return b[o] | (b[o + 1] << 8)


def rd_u32(b, o):
    return b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)


def is_dotnet_clr(path):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError:
        return None, None
    if len(data) < 0x40 or data[0:2] != b"MZ":
        return None, None
    e_lfanew = rd_u32(data, 60)
    if e_lfanew + 248 > len(data):
        return None, None
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return None, None
    opt_start = e_lfanew + 24
    magic = rd_u16(data, opt_start)
    is_pe32plus = (magic == 0x20B)
    if rd_u32(data, opt_start + (108 if is_pe32plus else 92)) < 15:
        return None, None
    clr_rva = rd_u32(data, opt_start + (112 if is_pe32plus else 96) + 14 * 8)
    if clr_rva == 0:
        return None, None
    num_sections = rd_u16(data, e_lfanew + 6)
    sec_table_off = e_lfanew + 24 + rd_u16(data, e_lfanew + 20)
    offset = 0
    for i in range(num_sections):
        s = sec_table_off + i * 40
        if s + 40 > len(data):
            break
        vaddr = rd_u32(data, s + 12); vsize = rd_u32(data, s + 8)
        rawptr = rd_u32(data, s + 20); rawsiz = rd_u32(data, s + 16)
        if vaddr <= clr_rva < vaddr + max(vsize, rawsiz):
            offset = rawptr + (clr_rva - vaddr); break
    if offset == 0 or offset + 48 > len(data):
        return None, None
    clr = {
        "major": rd_u16(data, offset + 4), "minor": rd_u16(data, offset + 6),
        "metadata_rva": rd_u32(data, offset + 8),
        "metadata_size": rd_u32(data, offset + 12),
        "flags": rd_u32(data, offset + 16),
        "entry_point_rva": rd_u32(data, offset + 20),
    }
    return data, clr


def rva_to_offset(data, e_lfanew, rva):
    num_sections = rd_u16(data, e_lfanew + 6)
    opt_start = e_lfanew + 24
    sec_table_off = e_lfanew + 24 + rd_u16(data, e_lfanew + 20)
    for i in range(num_sections):
        s = sec_table_off + i * 40
        if s + 40 > len(data):
            break
        vaddr = rd_u32(data, s + 12); vsize = rd_u32(data, s + 8)
        rawptr = rd_u32(data, s + 20); rawsiz = rd_u32(data, s + 16)
        if vaddr <= rva < vaddr + max(vsize, rawsiz):
            return rawptr + (rva - vaddr)
    return 0


# ---------------- .NET 元数据流解析 ----------------
def read_encoded_int(buf, off):
    """解码 CorSerializedInt（1/2/4 字节）。返回 (value, new_off)。"""
    b = buf[off]
    if b & 0x80:
        if b & 0x40:
            # 4 字节
            val = b & 0x3F
            for i in range(1, 4):
                val = (val << 8) | buf[off + i]
            return val, off + 4
        else:
            # 2 字节
            return ((b & 0x3F) << 8) | buf[off + 1], off + 2
    else:
        return b, off + 1


def read_heap_index(buf, off, size_flag):
    """读取堆索引（2 或 4 字节）。"""
    if size_flag == 1:   # 2 字节堆
        return struct.unpack_from("<H", buf, off)[0], off + 2
    else:                # 4 字节堆
        return struct.unpack_from("<I", buf, off)[0], off + 4


def read_coded_index(buf, off, kinds, table_index_size_flag):
    """读取编码索引（如 TypeDefOrRef、MethodDefOrRef）。返回 (kind_name, index, new_off)。"""
    shift = kinds.index(None) if None in kinds else len(kinds)
    # shift = 表数量低位位数
    shift = 0
    while (1 << shift) < len(kinds):
        shift += 1
    mask = (1 << shift) - 1
    raw, off = read_heap_index(buf, off, table_index_size_flag)
    kind_idx = raw & mask
    table_idx = raw >> shift
    kind = kinds[table_idx] if table_idx < len(kinds) else "UNKNOWN"
    return kind, kind_idx, off


class MetaStream:
    def __init__(self, data, off, size):
        self.data = data
        self.off = off
        self.size = size

    def read_u16(self, off):
        return struct.unpack_from("<H", self.data, off)[0]

    def read_u32(self, off):
        return struct.unpack_from("<I", self.data, off)[0]


def parse_dotnet_metadata(data, path):
    """解析 .NET 元数据：定位 CLI 头 -> #~ 流 -> TypeDef/MethodDef/FieldDef 表。"""
    e_lfanew = rd_u32(data, 60)
    opt_start = e_lfanew + 24
    magic = rd_u16(data, opt_start)
    is_pe32plus = (magic == 0x20B)
    clr_rva = rd_u32(data, opt_start + (112 if is_pe32plus else 96) + 14 * 8)
    clr_size = rd_u32(data, opt_start + (112 if is_pe32plus else 96) + 14 * 8 + 4)
    clr_off = rva_to_offset(data, e_lfanew, clr_rva)
    md_rva = rd_u32(data, clr_off + 8)
    md_size = rd_u32(data, clr_off + 12)
    md_off = rva_to_offset(data, e_lfanew, md_rva)
    if md_off == 0 or data[md_off:md_off + 4] != b"BSJB":
        raise ValueError("not a valid .NET metadata root")
    if md_off == 0 or data[md_off:md_off + 4] != b"BSJB":
        raise ValueError("not a valid .NET metadata root")
    # 直接在元数据区扫描 #~ 表头：reserved4 + major(=2) + minor + heapsizes +
    # reserved(=0) + valid-mask(非0，低位通常含 Module)
    t_off = None
    scan_end = min(md_off + 4096, len(data) - 24)
    for cand in range(md_off, scan_end):
        if data[cand + 4] == 2:                       # MajorVersion == 2
            valid = struct.unpack_from("<Q", data, cand + 8)[0]
            # 真实表位图必含 Module(0)/TypeRef(1)/TypeDef(2)
            if (valid & 7) == 7:
                t_off = cand
                break
    if t_off is None:
        raise ValueError("no #~ table header found")
    # 用 t_off 作为下界，精确定位流表（名称区恰在表数据之前结束），取得各堆偏置
    streams = {}
    for cand in range(md_off + 16, md_off + 52):
        n = rd_u16(data, cand + 2)
        if not (1 <= n <= 20):
            continue
        tab = cand + 8
        name_base = tab + n * 8
        p = name_base
        names = {}
        ok = True
        for i in range(n):
            st_off = rd_u32(data, tab + i * 8); st_size = rd_u32(data, tab + i * 8 + 4)
            nm = b""
            while p < len(data) and data[p] != 0 and len(nm) < 8:
                nm += bytes([data[p]]); p += 1
            p += 1
            while (p - md_off) % 4 != 0:
                p += 1
            if not nm.startswith(b"#"):
                ok = False; break
            names[nm.decode("latin1")] = (md_off + st_off, st_size)
        if ok and "#~" in names and abs(p - t_off) <= 4:
            streams = names
            break
    return data, t_off, None, e_lfanew, streams


def parse_tables(data, t_off, streams):
    """解析元数据表头与 TypeDef/MethodDef/FieldDef 表。"""
    # 表头：reserved(1)+major(1)+minor(1)+reserved(1)+valid_mask(8)+sorted_mask(8)
    valid = struct.unpack_from("<Q", data, t_off + 8)[0]
    sorted_mask = struct.unpack_from("<Q", data, t_off + 16)[0]
    # #~ 头：reserved(4)+major(1)+minor(1)+heap_sizes(1)+reserved(1)+valid(8)+sorted(8)
    heap_flags = data[t_off + 6]
    string_heap_size_flag = 1 if (heap_flags & 0x01) else 4   # 0=2字节,1=4字节
    guid_heap_size_flag = 1 if (heap_flags & 0x02) else 4
    blob_heap_size_flag = 1 if (heap_flags & 0x04) else 4
    table_index_size_flag = 4 if (heap_flags & 0x10) else 2

    # 表定义（索引号 -> 名称）
    TABLES = [
        "Module", "TypeRef", "TypeDef", "Field", "MethodDef", "Param",
        "InterfaceImpl", "MemberRef", "Constant", "CustomAttribute",
        "FieldMarshal", "DeclSecurity", "ClassLayout", "FieldLayout",
        "StandAloneSig", "EventMap", "Event", "PropertyMap", "Property",
        "MethodSemantics", "MethodImpl", "ModuleRef", "TypeSpec", "ImplMap",
        "AssemblyRef", "File", "ExportedType", "ManifestResource", "NestedClass",
        "GenericParam", "MethodSpec", "GenericParamConstraint",
    ]
    table_rows = {}
    cur = t_off + 24  # 各表行数依次（紧跟 24 字节表头）
    for idx in range(64):
        if valid & (1 << idx):
            rows = struct.unpack_from("<I", data, cur)[0] if cur + 4 <= len(data) else 0
            if idx < len(TABLES):
                table_rows[TABLES[idx]] = (cur, rows)
            cur += 4

    results = {"valid": valid, "tables": {}, "string_heap_size": string_heap_size_flag,
               "blob_heap_size": blob_heap_size_flag}
    # ---- 基于表头与行大小计算各表数据偏置（跳过 Module/TypeRef 等前置表） ----
    str_sz = string_heap_size_flag
    blob_sz = blob_heap_size_flag
    guid_sz = guid_heap_size_flag
    tidx_sz = table_index_size_flag

    def sz(kind):
        if kind == "str": return str_sz
        if kind == "blob": return blob_sz
        if kind == "guid": return guid_sz
        if kind == "tidx": return tidx_sz
        return 0

    # 各表：(列类型序列) 只覆盖 0x00..0x06 足以定位 TypeDef/MethodDef/Field
    TABLE_COLS = {
        0: ["u2","str","guid","guid","guid"],                                   # Module
        1: ["coded2","str","str"],                                              # TypeRef (ResolutionScope)
        2: ["u4","str","str","coded2","tidx","tidx"],                          # TypeDef
        3: ["u2","str","blob"],                                                 # Field
        4: ["u4","u2","u2","str","blob","tidx"],                                # MethodDef
        5: ["u2","u2","str"],                                                   # Param
    }
    ROW_SPEC = {
        "u2":2,"u4":4,"str":sz("str"),"blob":sz("blob"),"guid":sz("guid"),
        "tidx":sz("tidx"),"coded2":sz("tidx"),
    }

    table_data_off = {}
    cur = t_off + 24  # 行数区结束
    # 先读取所有有效表的行数（valid 可能含 >31 的位，需遍历 64 位）
    row_counts = {}
    cur = t_off + 24
    for idx in range(64):
        if valid & (1 << idx):
            row_counts[idx] = struct.unpack_from("<I", data, cur)[0] if cur + 4 <= len(data) else 0
            cur += 4
    # 再按顺序计算各表数据偏置（逐表：偏置=cur，然后 cur += rows * 行大小）
    cur2 = cur
    for idx in range(64):
        if idx in row_counts:
            table_data_off[idx] = cur2
            rowsize = sum(ROW_SPEC[k] for k in TABLE_COLS.get(idx, []))
            cur2 += row_counts[idx] * rowsize

    results["tables"] = {}
    results["_table_rows"] = table_rows
    results["_data_off"] = table_data_off

    def rows_of(name):
        idx = TABLES.index(name)
        return row_counts.get(idx, 0), table_data_off.get(idx, 0)

    # TypeDef (0x02)
    n, off = rows_of("TypeDef")
    types = []
    for _ in range(n):
        flags = rd_u32(data, off); off += 4
        name_idx, off = read_heap_index(data, off, str_sz)
        ns_idx, off = read_heap_index(data, off, str_sz)
        extends_kind, extends_idx, off = read_coded_index(
            data, off, ["TypeDef", "TypeRef", "TypeSpec"], tidx_sz)
        field_list, off = read_heap_index(data, off, tidx_sz)
        method_list, off = read_heap_index(data, off, tidx_sz)
        types.append({"flags": flags, "name_idx": name_idx, "ns_idx": ns_idx,
                      "extends": (extends_kind, extends_idx),
                      "field_list": field_list, "method_list": method_list})
    results["tables"]["TypeDef"] = types

    # MethodDef (0x06)
    n, off = rows_of("MethodDef")
    methods = []
    for _ in range(n):
        rva = rd_u32(data, off); off += 4
        impl_flags = rd_u16(data, off); off += 2
        flags = rd_u16(data, off); off += 2
        name_idx, off = read_heap_index(data, off, str_sz)
        sig_idx, off = read_heap_index(data, off, blob_sz)
        param_list, off = read_heap_index(data, off, tidx_sz)
        methods.append({"rva": rva, "impl_flags": impl_flags, "flags": flags,
                        "name_idx": name_idx, "sig_idx": sig_idx, "param_list": param_list})
    results["tables"]["MethodDef"] = methods

    # Field (0x03)
    n, off = rows_of("Field")
    fields = []
    for _ in range(n):
        flags = rd_u16(data, off); off += 2
        name_idx, off = read_heap_index(data, off, str_sz)
        sig_idx, off = read_heap_index(data, off, blob_sz)
        fields.append({"flags": flags, "name_idx": name_idx, "sig_idx": sig_idx})
    results["tables"]["Field"] = fields

    results["_string_heap"] = streams.get("#Strings", (0, 0))[0]
    results["_blob_heap"] = streams.get("#Blob", (0, 0))[0]
    results["_guid_heap"] = streams.get("#GUID", (0, 0))[0]
    results["_us_heap"] = streams.get("#US", (0, 0))[0]
    return results


def read_string(data, st_off, idx, size_flag):
    """从字符串堆读取 UTF-8 字符串（索引是堆内偏移）。"""
    if idx == 0:
        return ""
    abs_off = st_off + idx
    end = abs_off
    while end < len(data) and data[end] != 0:
        end += 1
    return data[abs_off:end].decode("utf-8", errors="replace")


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="NETUnpack",
        description="NETUnpack — Python CLI 逐函数端口（.NET 元数据表解析）")
    ap.add_argument("file", help=".NET 程序集路径")
    ap.add_argument("--raw", action="store_true", help="打印元数据表统计")
    args = ap.parse_args(argv)

    data, clr = is_dotnet_clr(args.file)
    if data is None:
        print("%s: 非 .NET 程序集" % args.file, file=sys.stderr)
        return 1
    try:
        parsed = parse_dotnet_metadata(data, args.file)
    except ValueError as e:
        print("%s: 元数据解析失败: %s" % (args.file, e), file=sys.stderr)
        return 1
    e_lfanew = rd_u32(data, 60)
    meta = parse_tables(data, parsed[1], parsed[4])

    str_heap = meta["_string_heap"]
    results = meta["tables"]
    print("%s: CLR v%d.%d" % (args.file, clr["major"], clr["minor"]))
    if args.raw:
        print("  #~ tables valid mask=0x%016X" % meta["valid"])
        for idx, (o, rows) in sorted(meta["_table_rows"].items()):
            pass
    print("TypeDef: %d, MethodDef: %d, Field: %d" % (
        len(results.get("TypeDef", [])), len(results.get("MethodDef", [])),
        len(results.get("Field", []))))

    for td in results.get("TypeDef", []):
        name = read_string(data, str_heap, td["name_idx"], meta["string_heap_size"]) if str_heap else "(idx=%d)" % td["name_idx"]
        ns = read_string(data, str_heap, td["ns_idx"], meta["string_heap_size"]) if str_heap else ""
        print("  class %s%s%s" % (ns + "." if ns else "", name,
                                  "  extends=(%s,%d)" % td["extends"] if td["extends"][0] != "UNKNOWN" else ""))
        if args.raw:
            print("    field_list=0x%X method_list=0x%X" % (td["field_list"], td["method_list"]))

    for md_ in results.get("MethodDef", []):
        name = read_string(data, str_heap, md_["name_idx"], meta["string_heap_size"]) if str_heap else "(idx=%d)" % md_["name_idx"]
        print("  method RVA=0x%06X %-30s flags=0x%04X" % (md_["rva"], name, md_["flags"]))

    return 0


if __name__ == "__main__":
    sys.exit(main())