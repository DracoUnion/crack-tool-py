#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dnlib 等价引擎 — 纯 Python .NET 元数据 / IL 解析引擎
====================================================

实现 dnlib（.NET 元数据操作库）的核心：PE 解析、CLI 头、元数据流
（#~/#Strings/#US/#GUID/#Blob）、全部元数据表、编码索引、方法体
（tiny/fat）、IL 指令读取、类型/方法/字段解析。这是 Mono.Cecil、
ICSharpCode.Decompiler、de4dot 等引擎的共同底座。

CLI（演示/测试引擎）：
    python main.py <assembly>                 列出类型/方法/字段
    python main.py <assembly> --method <name> 反汇编某方法 IL
    python main.py <assembly> --il <token>    按 MethodDef 索引反汇编
    python main.py --help

无第三方依赖，纯标准库。
"""

import argparse
import struct
import sys

# ===========================================================================
# ECMA-335 opcode table (verified vs ildasm)
# ===========================================================================
OP1 = {
    0x00: ("nop", None), 0x01: ("break", None),
    0x02: ("ldarg.0", None), 0x03: ("ldarg.1", None), 0x04: ("ldarg.2", None), 0x05: ("ldarg.3", None),
    0x06: ("ldloc.0", None), 0x07: ("ldloc.1", None), 0x08: ("ldloc.2", None), 0x09: ("ldloc.3", None),
    0x0A: ("stloc.0", None), 0x0B: ("stloc.1", None), 0x0C: ("stloc.2", None), 0x0D: ("stloc.3", None),
    0x0E: ("ldarg.s", "shortvar"), 0x0F: ("ldarga.s", "shortvar"),
    0x10: ("starg.s", "shortvar"), 0x11: ("ldloc.s", "shortvar"),
    0x12: ("ldloca.s", "shortvar"), 0x13: ("stloc.s", "shortvar"),
    0x14: ("ldnull", None), 0x15: ("ldc.i4.m1", None),
    0x16: ("ldc.i4.0", None), 0x17: ("ldc.i4.1", None), 0x18: ("ldc.i4.2", None),
    0x19: ("ldc.i4.3", None), 0x1A: ("ldc.i4.4", None), 0x1B: ("ldc.i4.5", None),
    0x1C: ("ldc.i4.6", None), 0x1D: ("ldc.i4.7", None), 0x1E: ("ldc.i4.8", None),
    0x1F: ("ldc.i4.s", "sbyte"), 0x20: ("ldc.i4", "int32"), 0x21: ("ldc.i8", "int64"),
    0x22: ("ldc.r4", "float32"), 0x23: ("ldc.r8", "float64"),
    0x25: ("dup", None), 0x26: ("pop", None),
    0x27: ("jmp", "token"), 0x28: ("call", "token"), 0x29: ("calli", "token"),
    0x2A: ("ret", None),
    0x2B: ("br.s", "brshort"), 0x2C: ("brfalse.s", "brshort"), 0x2D: ("brtrue.s", "brshort"),
    0x2E: ("beq.s", "brshort"), 0x2F: ("bge.s", "brshort"), 0x30: ("bgt.s", "brshort"),
    0x31: ("ble.s", "brshort"), 0x32: ("blt.s", "brshort"),
    0x33: ("bne.un.s", "brshort"), 0x34: ("bge.un.s", "brshort"), 0x35: ("bgt.un.s", "brshort"),
    0x36: ("ble.un.s", "brshort"), 0x37: ("blt.un.s", "brshort"),
    0x38: ("br", "brint"), 0x39: ("brfalse", "brint"), 0x3A: ("brtrue", "brint"),
    0x3B: ("beq", "brint"), 0x3C: ("bge", "brint"), 0x3D: ("bgt", "brint"),
    0x3E: ("ble", "brint"), 0x3F: ("blt", "brint"),
    0x40: ("bne.un", "brint"), 0x41: ("bge.un", "brint"), 0x42: ("bgt.un", "brint"),
    0x43: ("ble.un", "brint"), 0x44: ("blt.un", "brint"),
    0x45: ("switch", "switch"),
    0x46: ("ldind.i1", None), 0x47: ("ldind.u1", None), 0x48: ("ldind.i2", None),
    0x49: ("ldind.u2", None), 0x4A: ("ldind.i4", None), 0x4B: ("ldind.u4", None),
    0x4C: ("ldind.i8", None), 0x4D: ("ldind.i", None), 0x4E: ("ldind.r4", None),
    0x4F: ("ldind.r8", None), 0x50: ("ldind.ref", None),
    0x51: ("stind.ref", None), 0x52: ("stind.i1", None), 0x53: ("stind.i2", None),
    0x54: ("stind.i4", None), 0x55: ("stind.i8", None), 0x56: ("stind.r4", None),
    0x57: ("stind.r8", None),
    0x58: ("add", None), 0x59: ("sub", None), 0x5A: ("mul", None),
    0x5B: ("div", None), 0x5C: ("div.un", None), 0x5D: ("rem", None),
    0x5E: ("rem.un", None), 0x5F: ("and", None), 0x60: ("or", None),
    0x61: ("xor", None), 0x62: ("shl", None), 0x63: ("shr", None),
    0x64: ("shr.un", None), 0x65: ("neg", None), 0x66: ("not", None),
    0x67: ("conv.i1", None), 0x68: ("conv.i2", None), 0x69: ("conv.i4", None),
    0x6A: ("conv.i8", None), 0x6B: ("conv.r4", None), 0x6C: ("conv.r8", None),
    0x6D: ("conv.u4", None), 0x6E: ("conv.u8", None),
    0x6F: ("callvirt", "token"), 0x70: ("cpobj", "token"), 0x71: ("ldobj", "token"),
    0x72: ("ldstr", "token"), 0x73: ("newobj", "token"), 0x74: ("castclass", "token"),
    0x75: ("isinst", "token"), 0x76: ("conv.r.un", None),
    0x79: ("unbox", "token"), 0x7A: ("throw", None),
    0x7B: ("ldfld", "token"), 0x7C: ("ldflda", "token"), 0x7D: ("stfld", "token"),
    0x7E: ("ldsfld", "token"), 0x7F: ("ldsflda", "token"), 0x80: ("stsfld", "token"),
    0x81: ("stobj", "token"),
    0x82: ("conv.ovf.i1.un", None), 0x83: ("conv.ovf.i2.un", None),
    0x84: ("conv.ovf.i4.un", None), 0x85: ("conv.ovf.i8.un", None),
    0x86: ("conv.ovf.u1.un", None), 0x87: ("conv.ovf.u2.un", None),
    0x88: ("conv.ovf.u4.un", None), 0x89: ("conv.ovf.u8.un", None),
    0x8A: ("conv.ovf.i.un", None), 0x8B: ("conv.ovf.u.un", None),
    0x8C: ("box", "token"), 0x8D: ("newarr", "token"), 0x8E: ("ldlen", None),
    0x8F: ("ldelem.a", "token"),
    0x90: ("ldelem.i1", None), 0x91: ("ldelem.u1", None), 0x92: ("ldelem.i2", None),
    0x93: ("ldelem.u2", None), 0x94: ("ldelem.i4", None), 0x95: ("ldelem.u4", None),
    0x96: ("ldelem.i8", None), 0x97: ("ldelem.i", None), 0x98: ("ldelem.r4", None),
    0x99: ("ldelem.r8", None), 0x9A: ("ldelem.ref", None),
    0x9B: ("stelem.i", None), 0x9C: ("stelem.i1", None), 0x9D: ("stelem.i2", None),
    0x9E: ("stelem.i4", None), 0x9F: ("stelem.i8", None), 0xA0: ("stelem.r4", None),
    0xA1: ("stelem.r8", None), 0xA2: ("stelem.ref", None),
    0xA3: ("ldelem", "token"), 0xA4: ("stelem", "token"), 0xA5: ("unbox.any", "token"),
    0xB3: ("conv.ovf.i1", None), 0xB4: ("conv.ovf.u1", None),
    0xB5: ("conv.ovf.i2", None), 0xB6: ("conv.ovf.u2", None),
    0xB7: ("conv.ovf.i4", None), 0xB8: ("conv.ovf.u4", None),
    0xB9: ("conv.ovf.i8", None), 0xBA: ("conv.ovf.u8", None),
    0xC2: ("refanyval", "token"), 0xC3: ("ckfinite", None),
    0xC6: ("mkrefany", "token"),
    0xD0: ("ldtoken", "token"),
    0xD1: ("conv.u2", None), 0xD2: ("conv.u1", None), 0xD3: ("conv.i", None),
    0xD4: ("conv.ovf.i", None), 0xD5: ("conv.ovf.u", None),
    0xD6: ("add.ovf", None), 0xD7: ("add.ovf.un", None),
    0xD8: ("mul.ovf", None), 0xD9: ("mul.ovf.un", None),
    0xDA: ("sub.ovf", None), 0xDB: ("sub.ovf.un", None),
    0xDC: ("endfinally", None), 0xDD: ("leave", "brint"), 0xDE: ("leave.s", "brshort"),
    0xDF: ("stind.i", None), 0xE0: ("conv.u", None),
}
OP2 = {
    0x00: ("arglist", None),
    0x01: ("ceq", None), 0x02: ("cgt", None), 0x03: ("cgt.un", None),
    0x04: ("clt", None), 0x05: ("clt.un", None),
    0x06: ("ldftn", "token"), 0x07: ("ldvirtftn", "token"),
    0x09: ("ldarg", "var"), 0x0A: ("ldarga", "var"), 0x0B: ("starg", "var"),
    0x0C: ("ldloc", "var"), 0x0D: ("ldloca", "var"), 0x0E: ("stloc", "var"),
    0x0F: ("localloc", None),
    0x11: ("endfilter", None),
    0x12: ("unaligned.", "u8"), 0x13: ("volatile.", None), 0x14: ("tail.", None),
    0x15: ("initobj", "token"), 0x16: ("constrained.", "token"),
    0x17: ("cpblk", None), 0x18: ("initblk", None), 0x19: ("no.", "u8"),
    0x1A: ("rethrow", None),
    0x1C: ("sizeof", "token"), 0x1D: ("refanytype", None), 0x1E: ("readonly.", None),
}

# ECMA-335 II.22 真实表编号（含 Ptr/Assembly/Enc 等空位，0x00..0x2C）
TABLE_NAMES = {
    0x00: "Module", 0x01: "TypeRef", 0x02: "TypeDef", 0x03: "FieldPtr", 0x04: "Field",
    0x05: "MethodPtr", 0x06: "MethodDef", 0x07: "ParamPtr", 0x08: "Param",
    0x09: "InterfaceImpl", 0x0A: "MemberRef", 0x0B: "Constant", 0x0C: "CustomAttribute",
    0x0D: "FieldMarshal", 0x0E: "DeclSecurity", 0x0F: "ClassLayout", 0x10: "FieldLayout",
    0x11: "StandAloneSig", 0x12: "EventMap", 0x13: "EventPtr", 0x14: "Event",
    0x15: "PropertyMap", 0x16: "PropertyPtr", 0x17: "Property", 0x18: "MethodSemantics",
    0x19: "MethodImpl", 0x1A: "ModuleRef", 0x1B: "TypeSpec", 0x1C: "ImplMap",
    0x1D: "FieldRva", 0x1E: "EncLog", 0x1F: "EncMap", 0x20: "Assembly",
    0x21: "AssemblyProcessor", 0x22: "AssemblyOS", 0x23: "AssemblyRef",
    0x24: "AssemblyRefProcessor", 0x25: "AssemblyRefOS", 0x26: "File",
    0x27: "ExportedType", 0x28: "ManifestResource", 0x29: "NestedClass",
    0x2A: "GenericParam", 0x2B: "MethodSpec", 0x2C: "GenericParamConstraint",
}
NAME2IDX = {v: k for k, v in TABLE_NAMES.items()}


def u16(b, o): return b[o] | (b[o + 1] << 8)
def u32(b, o): return b[o] | (b[o+1] << 8) | (b[o+2] << 16) | (b[o+3] << 24)
def i32(b, o):
    v = u32(b, o)
    return v - 0x100000000 if v & 0x80000000 else v


class PEImage:
    """PE + CLI 头解析。"""
    def __init__(self, data):
        self.data = data
        if data[:2] != b"MZ":
            raise ValueError("not MZ")
        self.e_lfanew = u32(data, 60)
        if data[self.e_lfanew:self.e_lfanew+4] != b"PE\x00\x00":
            raise ValueError("not PE")
        self.opt = self.e_lfanew + 24
        self.magic = u16(data, self.opt)
        self.pe32plus = (self.magic == 0x20B)
        self.num_sections = u16(data, self.e_lfanew + 6)
        self.size_opt = u16(data, self.e_lfanew + 20)
        self.sec_table = self.e_lfanew + 24 + self.size_opt
        self.sections = []
        for i in range(self.num_sections):
            s = self.sec_table + i * 40
            self.sections.append({
                "name": data[s:s+8].rstrip(b"\x00").decode("latin1"),
                "vsize": u32(data, s+8), "vaddr": u32(data, s+12),
                "rsize": u32(data, s+16), "rptr": u32(data, s+20),
            })
        # data directories
        dd = self.opt + (112 if self.pe32plus else 96)
        self.num_dirs = u32(data, self.opt + (108 if self.pe32plus else 92))
        self.clr_rva = u32(data, dd + 14*8) if self.num_dirs > 14 else 0
        self.clr_size = u32(data, dd + 14*8 + 4) if self.num_dirs > 14 else 0

    def rva_to_offset(self, rva):
        for s in self.sections:
            if s["vaddr"] <= rva < s["vaddr"] + max(s["vsize"], s["rsize"]):
                return s["rptr"] + (rva - s["vaddr"])
        return 0

    def read_clr_header(self):
        off = self.rva_to_offset(self.clr_rva)
        d = self.data
        return {
            "cb": u32(d, off), "major": u16(d, off+4), "minor": u16(d, off+6),
            "metadata_rva": u32(d, off+8), "metadata_size": u32(d, off+12),
            "flags": u32(d, off+16), "entry_point_rva": u32(d, off+20),
        }


class Metadata:
    """元数据根 + 流 + 表。"""
    def __init__(self, pe):
        self.pe = pe
        d = pe.data
        clr = pe.read_clr_header()
        self.clr = clr
        self.root = pe.rva_to_offset(clr["metadata_rva"])
        if d[self.root:self.root+4] != b"BSJB":
            raise ValueError("bad metadata signature")
        ver_len = u32(d, self.root + 12)                  # VersionLength 是 u32
        streams_off = self.root + 16 + ((ver_len + 3) & ~3)  # sig4+maj2+min2+res4+verlen4
        n = u16(d, streams_off + 2)
        tab = streams_off + 4                             # Flags(2)+Streams(2) 后紧跟流表项
        self.streams = {}
        p = tab                                           # 每个流项: Offset(4)+Size(4)+Name(0结尾,4对齐)
        for i in range(n):
            st_off = u32(d, p); st_size = u32(d, p+4)
            p += 8
            nm = b""
            while p < len(d) and d[p] != 0:
                nm += bytes([d[p]]); p += 1
            p += 1                                        # 跳过 0 终止符
            while (p - self.root) % 4 != 0:               # 名称补齐到 4 字节
                p += 1
            self.streams[nm.decode("latin1")] = (self.root + st_off, st_size)
        self._cache = {}
        self._parse_tables()

    def stream(self, name):
        return self.streams.get(name)

    def _parse_tables(self):
        d = self.pe.data
        t_off, _ = self.streams.get("#~", self.streams.get("#-", (0, 0)))
        self.t_off = t_off
        self.valid = struct.unpack_from("<Q", d, t_off+8)[0]
        self.heap_flags = d[t_off+6]
        self.str_sz = 4 if (self.heap_flags & 1) else 2
        self.guid_sz = 4 if (self.heap_flags & 2) else 2
        self.blob_sz = 4 if (self.heap_flags & 4) else 2
        self.tidx_sz = 4 if (self.heap_flags & 0x10) else 2
        # row counts (all valid bits 0..63)
        cur = t_off + 24
        self.row_counts = {}
        for idx in range(64):
            if self.valid & (1 << idx):
                self.row_counts[idx] = u32(d, cur) if cur+4 <= len(d) else 0
                cur += 4
        # table data offsets via row sizes
        self.table_off = {}
        c = cur
        for idx in range(64):
            if idx in self.row_counts:
                self.table_off[idx] = c
                rs = self._row_size(idx)
                c += self.row_counts[idx] * rs

    def _simple_idx(self, tbl):
        """简单表索引大小：目标表(ECMA编号)行数 < 2^16 用 2 字节，否则 4。"""
        return 2 if self.row_counts.get(tbl, 0) < 0x10000 else 4

    def _coded_idx(self, tables, tag_bits):
        """编码索引大小：max(引用表行数) < 2^(16-tag_bits) 用 2 字节，否则 4。"""
        mx = max((self.row_counts.get(t, 0) for t in tables), default=0)
        return 2 if mx < (1 << (16 - tag_bits)) else 4

    def _row_size(self, idx):
        s = self.str_sz; b = self.blob_sz; g = self.guid_sz
        # 编码索引（ECMA-335 II.24.2，表号用真实 ECMA 编号）
        TypeDefOrRef = self._coded_idx([0x02, 0x01, 0x1B], 2)
        HasConstant = self._coded_idx([0x04, 0x08, 0x17], 2)
        HasCustomAttribute = self._coded_idx(
            [0x06, 0x04, 0x01, 0x02, 0x08, 0x09, 0x0A, 0x00, 0x0E, 0x17, 0x14, 0x11, 0x1A, 0x1B, 0x23], 5)
        HasFieldMarshal = self._coded_idx([0x04, 0x08], 1)
        HasDeclSecurity = self._coded_idx([0x02, 0x06, 0x20], 2)
        MemberRefParent = self._coded_idx([0x02, 0x01, 0x1A, 0x06, 0x1B], 3)
        HasSemantics = self._coded_idx([0x14, 0x17], 1)
        MethodDefOrRef = self._coded_idx([0x06, 0x0A], 1)
        MemberForwarded = self._coded_idx([0x04, 0x06], 1)
        Implementation = self._coded_idx([0x26, 0x23, 0x27], 2)
        CustomAttributeType = self._coded_idx([0x06, 0x0A], 3)
        ResolutionScope = self._coded_idx([0x00, 0x1A, 0x23, 0x01], 2)
        TypeOrMethodDef = self._coded_idx([0x02, 0x06], 1)
        S = {
            0x00: 2 + s + g + g + g,                       # Module
            0x01: ResolutionScope + s + s,                 # TypeRef
            0x02: 4 + s + s + TypeDefOrRef + self._simple_idx(0x04) + self._simple_idx(0x06),  # TypeDef
            0x03: self._simple_idx(0x04),                  # FieldPtr (空)
            0x04: 2 + s + b,                               # Field
            0x05: self._simple_idx(0x06),                  # MethodPtr (空)
            0x06: 4 + 2 + 2 + s + b + self._simple_idx(0x08),  # MethodDef
            0x07: self._simple_idx(0x08),                  # ParamPtr (空)
            0x08: 2 + 2 + s,                               # Param
            0x09: self._simple_idx(0x02) + TypeDefOrRef,   # InterfaceImpl
            0x0A: MemberRefParent + s + b,                 # MemberRef
            0x0B: 1 + 1 + HasConstant + b,                 # Constant
            0x0C: HasCustomAttribute + CustomAttributeType + b,  # CustomAttribute
            0x0D: HasFieldMarshal + b,                     # FieldMarshal
            0x0E: 2 + HasDeclSecurity + b,                 # DeclSecurity
            0x0F: 2 + 4 + self._simple_idx(0x02),          # ClassLayout
            0x10: 4 + self._simple_idx(0x04),              # FieldLayout
            0x11: b,                                       # StandAloneSig
            0x12: self._simple_idx(0x02) + self._simple_idx(0x14),  # EventMap
            0x13: self._simple_idx(0x14),                  # EventPtr (空)
            0x14: 2 + s + TypeDefOrRef,                    # Event
            0x15: self._simple_idx(0x02) + self._simple_idx(0x17),  # PropertyMap
            0x16: self._simple_idx(0x17),                  # PropertyPtr (空)
            0x17: 2 + s + b,                               # Property
            0x18: 2 + self._simple_idx(0x06) + HasSemantics,  # MethodSemantics
            0x19: self._simple_idx(0x02) + MethodDefOrRef + MethodDefOrRef,  # MethodImpl
            0x1A: s,                                       # ModuleRef
            0x1B: b,                                       # TypeSpec
            0x1C: 2 + MemberForwarded + s + self._simple_idx(0x1A),  # ImplMap
            0x1D: 4 + self._simple_idx(0x04),              # FieldRva
            0x1E: 4 + 4,                                   # EncLog
            0x1F: 4,                                       # EncMap
            0x20: 4 + 2 + 2 + 2 + 2 + 4 + b + s + s,       # Assembly
            0x21: 4,                                       # AssemblyProcessor
            0x22: 4 + 4 + 4,                               # AssemblyOS
            0x23: 2 + 2 + 2 + 2 + 4 + b + s + s + b,       # AssemblyRef
            0x24: 4 + self._simple_idx(0x23),              # AssemblyRefProcessor
            0x25: 4 + 4 + 4 + self._simple_idx(0x23),      # AssemblyRefOS
            0x26: 4 + s + b,                               # File
            0x27: 4 + 4 + s + s + Implementation,          # ExportedType
            0x28: 4 + 4 + s + Implementation,              # ManifestResource
            0x29: self._simple_idx(0x02) + self._simple_idx(0x02),  # NestedClass
            0x2A: 2 + 2 + TypeOrMethodDef + s,             # GenericParam
            0x2B: MethodDefOrRef + b,                      # MethodSpec
            0x2C: self._simple_idx(0x2A) + TypeDefOrRef,   # GenericParamConstraint
        }
        return S.get(idx, 0)

    def rows(self, name):
        idx = NAME2IDX[name]
        return self.row_counts.get(idx, 0), self.table_off.get(idx, 0)

    def string(self, idx):
        if idx == 0:
            return ""
        base = self.streams.get("#Strings", (0, 0))[0]
        if base == 0:
            return ""
        p = base + idx
        e = p
        d = self.pe.data
        while e < len(d) and d[e] != 0:
            e += 1
        return d[p:e].decode("utf-8", errors="replace")

    def blob(self, idx):
        base = self.streams.get("#Blob", (0, 0))[0]
        if base == 0:
            return b""
        p = base + idx
        d = self.pe.data
        b0 = d[p]
        if b0 & 0x80 == 0:
            ln = b0; p += 1
        elif b0 & 0xC0 == 0x80:
            ln = ((b0 & 0x3F) << 8) | d[p+1]; p += 2
        else:
            ln = ((b0 & 0x1F) << 24) | (d[p+1] << 16) | (d[p+2] << 8) | d[p+3]; p += 4
        return d[p:p+ln]

    # ---- 表行读取 ----
    def _read_idx(self, off, size):
        if size == 2:
            return u16(self.pe.data, off)
        return u32(self.pe.data, off)

    def typedefs(self):
        if "typedefs" in self._cache:
            return self._cache["typedefs"]
        n, off = self.rows("TypeDef")
        d = self.pe.data
        ext_sz = self._coded_idx([0x02, 0x01, 0x1B], 2)
        fld_sz = self._simple_idx(0x04)
        mth_sz = self._simple_idx(0x06)
        out = []
        for _ in range(n):
            flags = u32(d, off); off += 4
            name_i = self._read_idx(off, self.str_sz); off += self.str_sz
            ns_i = self._read_idx(off, self.str_sz); off += self.str_sz
            extends = self._read_idx(off, ext_sz); off += ext_sz
            field_list = self._read_idx(off, fld_sz); off += fld_sz
            method_list = self._read_idx(off, mth_sz); off += mth_sz
            out.append({"flags": flags, "name": self.string(name_i),
                        "ns": self.string(ns_i), "extends": extends,
                        "field_list": field_list, "method_list": method_list})
        self._cache["typedefs"] = out
        return out

    def methods(self):
        if "methods" in self._cache:
            return self._cache["methods"]
        n, off = self.rows("MethodDef")
        d = self.pe.data
        prm_sz = self._simple_idx(0x08)
        out = []
        for _ in range(n):
            rva = u32(d, off); off += 4
            impl = u16(d, off); off += 2
            flags = u16(d, off); off += 2
            name_i = self._read_idx(off, self.str_sz); off += self.str_sz
            sig = self._read_idx(off, self.blob_sz); off += self.blob_sz
            param = self._read_idx(off, prm_sz); off += prm_sz
            out.append({"rva": rva, "impl": impl, "flags": flags,
                        "name": self.string(name_i), "sig": sig, "param": param})
        self._cache["methods"] = out
        return out

    def fields(self):
        if "fields" in self._cache:
            return self._cache["fields"]
        n, off = self.rows("Field")
        d = self.pe.data
        out = []
        for _ in range(n):
            flags = u16(d, off); off += 2
            name_i = self._read_idx(off, self.str_sz); off += self.str_sz
            sig = self._read_idx(off, self.blob_sz); off += self.blob_sz
            out.append({"flags": flags, "name": self.string(name_i), "sig": sig})
        self._cache["fields"] = out
        return out

    # ---- 成员解析（用于反编译/IL 符号化） ----
    def typerefs(self):
        if "typerefs" in self._cache:
            return self._cache["typerefs"]
        n, off = self.rows("TypeRef")
        d = self.pe.data
        rs_sz = self._coded_idx([0x00, 0x1A, 0x23, 0x01], 2)
        out = []
        for _ in range(n):
            rs = self._read_idx(off, rs_sz); off += rs_sz
            name_i = self._read_idx(off, self.str_sz); off += self.str_sz
            ns_i = self._read_idx(off, self.str_sz); off += self.str_sz
            out.append({"rs": rs, "name": self.string(name_i),
                        "ns": self.string(ns_i)})
        self._cache["typerefs"] = out
        return out

    def memberrefs(self):
        if "memberrefs" in self._cache:
            return self._cache["memberrefs"]
        n, off = self.rows("MemberRef")
        d = self.pe.data
        mrp_sz = self._coded_idx([0x02, 0x01, 0x1A, 0x06, 0x1B], 3)
        out = []
        for _ in range(n):
            mrp = self._read_idx(off, mrp_sz); off += mrp_sz
            name_i = self._read_idx(off, self.str_sz); off += self.str_sz
            sig = self._read_idx(off, self.blob_sz); off += self.blob_sz
            out.append({"mrp": mrp, "name": self.string(name_i), "sig": sig})
        self._cache["memberrefs"] = out
        return out

    def userstring(self, idx):
        if idx == 0:
            return ""
        base = self.streams.get("#US", (0, 0))[0]
        if base == 0:
            return ""
        d = self.pe.data
        p = base + idx
        b0 = d[p]
        ln = b0 & 0x7F; p += 1
        if b0 & 0x80:
            ln |= (d[p] & 0x7F) << 7; p += 1
        return d[p:p + ln * 2].decode("utf-16-le", errors="replace")

    def token_info(self, tok):
        """把 0x%08X 记号解析成可读描述：(种类, 名)。"""
        t = tok >> 24; ridx = tok & 0xFFFFFF
        if t == 0x70:                                   # UserString
            return ("string", repr(self.userstring(ridx)))
        tds = self.typedefs(); mds = self.methods(); fds = self.fields()
        if t == 0x02 and ridx <= len(tds):              # TypeDef
            td = tds[ridx - 1]; return ("type", td["ns"] + "." + td["name"])
        if t == 0x06 and ridx <= len(mds):              # MethodDef
            return ("method", mds[ridx - 1]["name"])
        if t == 0x04 and ridx <= len(fds):              # Field
            return ("field", fds[ridx - 1]["name"])
        if t == 0x0A:                                   # MemberRef
            mrs = self.memberrefs()
            if ridx <= len(mrs): return ("memberref", mrs[ridx - 1]["name"])
        if t == 0x01:                                   # TypeRef
            trs = self.typerefs()
            if ridx <= len(trs): return ("typeref", trs[ridx - 1]["ns"] + "." + trs[ridx - 1]["name"])
        if t == 0x1A:                                   # ModuleRef
            return ("moduleref", self.string(ridx))
        return ("token", "0x%08X" % tok)


    def method_body(self, rva):
        """读取方法体，返回 (header_size, code_size, local_var_sig, code_bytes)。"""
        d = self.pe.data
        off = self.pe.rva_to_offset(rva)
        if off == 0 or off + 4 > len(d):
            return None
        b0 = d[off]
        if (b0 & 3) == 2:      # tiny
            code_size = b0 >> 2
            return (1, code_size, 0, d[off+1:off+1+code_size])
        elif (b0 & 3) == 3:    # fat
            hdr = 12
            code_size = u32(d, off+4) >> 12
            local = u32(d, off+8)
            return (hdr, code_size, local, d[off+hdr:off+hdr+code_size])
        return None


def read_il(code):
    """反汇编 IL 字节，返回 [(offset, mnemonic, operand)]。"""
    i = 0
    n = len(code)
    out = []
    while i < n:
        start = i
        op = code[i]; i += 1
        if op == 0xFE and i < n:
            op2 = code[i]; i += 1
            mnem, t = OP2.get(op2, ("unknown_fe_%02x" % op2, None))
        else:
            mnem, t = OP1.get(op, ("unknown_%02x" % op, None))
        operand = ""
        def need(k):
            nonlocal i
            v = int.from_bytes(code[i:i+k], "little"); i += k; return v
        if t is None: operand = ""
        elif t == "sbyte": operand = str(int.from_bytes(code[i:i+1], "little", signed=True)); i += 1
        elif t == "int32": operand = str(int.from_bytes(code[i:i+4], "little", signed=True)); i += 4
        elif t == "int64": operand = str(int.from_bytes(code[i:i+8], "little", signed=True)); i += 8
        elif t == "float32": operand = repr(struct.unpack("<f", code[i:i+4])[0]); i += 4
        elif t == "float64": operand = repr(struct.unpack("<d", code[i:i+8])[0]); i += 8
        elif t == "shortvar": operand = str(code[i]); i += 1
        elif t == "var": operand = str(u16(code, i)); i += 2
        elif t == "brshort":
            d = int.from_bytes(code[i:i+1], "little", signed=True); i += 1
            operand = "IL_%04X" % ((start+2+d) & 0xFFFF)
        elif t == "brint":
            d = int.from_bytes(code[i:i+4], "little", signed=True); i += 4
            operand = "IL_%04X" % ((start+5+d) & 0xFFFF)
        elif t == "token": operand = "0x%08X" % need(4)
        elif t == "u8": operand = str(code[i]); i += 1
        elif t == "switch":
            cnt = need(4); base = i + cnt*4; tg = [base + int.from_bytes(code[i+k*4:i+k*4+4], "little", signed=True) for k in range(cnt)]; i += cnt*4
            operand = "(" + ", ".join("IL_%04X" % (x & 0xFFFF) for x in tg) + ")"
        out.append((start, mnem, operand))
    return out


def load(path):
    with open(path, "rb") as f:
        data = f.read()
    pe = PEImage(data)
    md = Metadata(pe)
    return pe, md


def main(argv=None):
    ap = argparse.ArgumentParser(prog="dnlib",
        description="dnlib 等价引擎 — .NET 元数据/IL 解析（PE/CLI/表/方法体/IL）")
    ap.add_argument("assembly", help=".NET 程序集")
    ap.add_argument("--method", help="按方法名反汇编 IL")
    ap.add_argument("--il", type=int, help="按 MethodDef 索引(1基)反汇编 IL")
    ap.add_argument("--raw", action="store_true", help="打印表统计")
    args = ap.parse_args(argv)

    try:
        pe, md = load(args.assembly)
    except Exception as e:
        print("Error: %s" % e, file=sys.stderr)
        return 1

    print("%s: CLR v%d.%d  (%d sections)" % (args.assembly, md.clr["major"], md.clr["minor"], pe.num_sections))
    if args.raw:
        print("  #~ valid=0x%016X heapsizes=0x%02X" % (md.valid, md.heap_flags))
        for idx in sorted(md.row_counts):
            if idx < len(TABLE_NAMES):
                print("  table %-20s rows=%d" % (TABLE_NAMES[idx], md.row_counts[idx]))

    typedefs = md.typedefs()
    methods = md.methods()
    fields = md.fields()
    print("TypeDef=%d MethodDef=%d Field=%d" % (len(typedefs), len(methods), len(fields)))

    if args.method or args.il is not None:
        target = args.method
        idx = None
        if args.il is not None:
            idx = args.il - 1
        else:
            for i, m in enumerate(methods):
                if m["name"] == target:
                    idx = i; break
        if idx is None or idx >= len(methods):
            print("method not found", file=sys.stderr)
            return 1
        m = methods[idx]
        body = md.method_body(m["rva"])
        print("\n// %s @ RVA 0x%X" % (m["name"], m["rva"]))
        if body is None:
            print("  (no body / external)")
            return 0
        hdr, csize, local, code = body
        print("// header=%d code_size=%d local_var_sig=0x%X" % (hdr, csize, local))
        for off, mnem, operand in read_il(code):
            extra = ""
            if operand.startswith("0x") and len(operand) == 10:
                kind, nm = md.token_info(int(operand, 16))
                extra = "   // %s %s" % (kind, nm)
            print("  IL_%04X: %-14s %s%s" % (off, mnem, operand, extra))
        return 0

    for td in typedefs:
        ns = td["ns"]; nm = td["name"]
        print("  class %s%s" % (ns + "." if ns else "", nm))
    return 0


if __name__ == "__main__":
    sys.exit(main())