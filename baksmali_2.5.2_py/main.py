#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
baksmali 2.5.2  ->  Python 重写版 (CLI)
================================================================================
逆向依据 (目录 baksmali_2.5.2/baksmali-2.5.2.jar, 主类
  org.jf.baksmali.Main): baksmali 是 dex -> smali 反汇编器 (smali 的反向).
  用法: baksmali [options] <dex/apk/zip>  输出 .smali 目录.
  本重写复刻其核心: 解析 DEX 文件 (header / string_ids / type_ids /
  proto_ids / field_ids / method_ids / class_defs / code_items), 把每个
  class 反汇编为 smali 文本 (.class/.super/.implements/.field/.method + 指令).
  main.py 为唯一入口, 纯标准库.

用法:
  python main.py --selftest
  python main.py disasm <classes.dex> [outdir]      # dex -> smali
  python main.py header <classes.dex>
  python main.py strings <classes.dex>
  python main.py classes <classes.dex>
"""

import sys
import os
import struct

# ============================================================ DEX 头部
class DexError(Exception):
    pass


TYPE_CODES = {
    0x00: "V", 0x01: "Z", 0x02: "B", 0x03: "S", 0x04: "C", 0x05: "I",
    0x06: "J", 0x07: "F", 0x08: "D", 0x09: "L", 0x0A: "[",
}

# Dalvik 操作码表: opcode -> (mnemonic, format)
# 仅列出常用完整集合 (0x00..0xFF 标准 Dalvik)
OPCODES = {
    0x00: ("nop", "10x"), 0x01: ("move", "12x"), 0x02: ("move/from16", "22x"),
    0x03: ("move/16", "32x"), 0x04: ("move-wide", "12x"), 0x05: ("move-wide/from16", "22x"),
    0x06: ("move-wide/16", "32x"), 0x07: ("move-object", "12x"), 0x08: ("move-object/from16", "22x"),
    0x09: ("move-object/16", "32x"), 0x0a: ("move-result", "11x"), 0x0b: ("move-result-wide", "11x"),
    0x0c: ("move-result-object", "11x"), 0x0d: ("move-exception", "11x"),
    0x0e: ("return-void", "10x"), 0x0f: ("return", "11x"), 0x10: ("return-wide", "11x"),
    0x11: ("return-object", "11x"), 0x12: ("const/4", "11n"), 0x13: ("const/16", "21s"),
    0x14: ("const", "31i"), 0x15: ("const/high16", "21h"), 0x16: ("const-wide/16", "21s"),
    0x17: ("const-wide/32", "31i"), 0x18: ("const-wide", "51l"), 0x19: ("const-wide/high16", "21h"),
    0x1a: ("const-string", "21c"), 0x1b: ("const-string/jumbo", "31c"),
    0x1c: ("const-class", "21c"), 0x1d: ("monitor-enter", "11x"), 0x1e: ("monitor-exit", "11x"),
    0x1f: ("check-cast", "21c"), 0x20: ("instance-of", "22c"), 0x21: ("array-length", "12x"),
    0x22: ("new-instance", "21c"), 0x23: ("new-array", "22c"), 0x24: ("filled-new-array", "35c"),
    0x25: ("filled-new-array/range", "3rc"), 0x26: ("fill-array-data", "31t"),
    0x27: ("throw", "11x"), 0x28: ("goto", "10t"), 0x29: ("goto/16", "20t"),
    0x2a: ("goto/32", "30t"), 0x2b: ("packed-switch", "31t"), 0x2c: ("sparse-switch", "31t"),
    0x2d: ("cmpl-float", "23x"), 0x2e: ("cmpg-float", "23x"), 0x2f: ("cmpl-double", "23x"),
    0x30: ("cmpg-double", "23x"), 0x31: ("cmp-long", "23x"),
    0x32: ("if-eq", "22t"), 0x33: ("if-ne", "22t"), 0x34: ("if-lt", "22t"),
    0x35: ("if-ge", "22t"), 0x36: ("if-gt", "22t"), 0x37: ("if-le", "22t"),
    0x38: ("if-eqz", "21t"), 0x39: ("if-nez", "21t"), 0x3a: ("if-ltz", "21t"),
    0x3b: ("if-gez", "21t"), 0x3c: ("if-gtz", "21t"), 0x3d: ("if-lez", "21t"),
    0x44: ("aget", "23x"), 0x45: ("aget-wide", "23x"), 0x46: ("aget-object", "23x"),
    0x47: ("aget-boolean", "23x"), 0x48: ("aget-byte", "23x"), 0x49: ("aget-char", "23x"),
    0x4a: ("aget-short", "23x"), 0x4b: ("aput", "23x"), 0x4c: ("aput-wide", "23x"),
    0x4d: ("aput-object", "23x"), 0x4e: ("aput-boolean", "23x"), 0x4f: ("aput-byte", "23x"),
    0x50: ("aput-char", "23x"), 0x51: ("aput-short", "23x"),
    0x52: ("iget", "22c"), 0x53: ("iget-wide", "22c"), 0x54: ("iget-object", "22c"),
    0x55: ("iget-boolean", "22c"), 0x56: ("iget-byte", "22c"), 0x57: ("iget-char", "22c"),
    0x58: ("iget-short", "22c"), 0x59: ("iput", "22c"), 0x5a: ("iput-wide", "22c"),
    0x5b: ("iput-object", "22c"), 0x5c: ("iput-boolean", "22c"), 0x5d: ("iput-byte", "22c"),
    0x5e: ("iput-char", "22c"), 0x5f: ("iput-short", "22c"),
    0x60: ("sget", "21c"), 0x61: ("sget-wide", "21c"), 0x62: ("sget-object", "21c"),
    0x63: ("sget-boolean", "21c"), 0x64: ("sget-byte", "21c"), 0x65: ("sget-char", "21c"),
    0x66: ("sget-short", "21c"), 0x67: ("sput", "21c"), 0x68: ("sput-wide", "21c"),
    0x69: ("sput-object", "21c"), 0x6a: ("sput-boolean", "21c"), 0x6b: ("sput-byte", "21c"),
    0x6c: ("sput-char", "21c"), 0x6d: ("sput-short", "21c"),
    0x6e: ("invoke-virtual", "35c"), 0x6f: ("invoke-super", "35c"),
    0x70: ("invoke-direct", "35c"), 0x71: ("invoke-static", "35c"),
    0x72: ("invoke-interface", "35c"), 0x74: ("invoke-virtual/range", "3rc"),
    0x75: ("invoke-super/range", "3rc"), 0x76: ("invoke-direct/range", "3rc"),
    0x77: ("invoke-static/range", "3rc"), 0x78: ("invoke-interface/range", "3rc"),
    0x7b: ("neg-int", "12x"), 0x7c: ("not-int", "12x"), 0x7d: ("neg-long", "12x"),
    0x7e: ("not-long", "12x"), 0x7f: ("neg-float", "12x"), 0x80: ("neg-double", "12x"),
    0x81: ("int-to-long", "12x"), 0x82: ("int-to-float", "12x"), 0x83: ("int-to-double", "12x"),
    0x84: ("long-to-int", "12x"), 0x85: ("long-to-float", "12x"), 0x86: ("long-to-double", "12x"),
    0x87: ("float-to-int", "12x"), 0x88: ("float-to-long", "12x"), 0x89: ("float-to-double", "12x"),
    0x8a: ("double-to-int", "12x"), 0x8b: ("double-to-long", "12x"), 0x8c: ("double-to-float", "12x"),
    0x8d: ("int-to-byte", "12x"), 0x8e: ("int-to-char", "12x"), 0x8f: ("int-to-short", "12x"),
    0x90: ("add-int", "23x"), 0x91: ("sub-int", "23x"), 0x92: ("mul-int", "23x"),
    0x93: ("div-int", "23x"), 0x94: ("rem-int", "23x"), 0x95: ("and-int", "23x"),
    0x96: ("or-int", "23x"), 0x97: ("xor-int", "23x"), 0x98: ("shl-int", "23x"),
    0x99: ("shr-int", "23x"), 0x9a: ("ushr-int", "23x"), 0x9b: ("add-long", "23x"),
    0x9c: ("sub-long", "23x"), 0x9d: ("mul-long", "23x"), 0x9e: ("div-long", "23x"),
    0x9f: ("rem-long", "23x"), 0xa0: ("and-long", "23x"), 0xa1: ("or-long", "23x"),
    0xa2: ("xor-long", "23x"), 0xa3: ("shl-long", "23x"), 0xa4: ("shr-long", "23x"),
    0xa5: ("ushr-long", "23x"), 0xa6: ("add-float", "23x"), 0xa7: ("sub-float", "23x"),
    0xa8: ("mul-float", "23x"), 0xa9: ("div-float", "23x"), 0xaa: ("rem-float", "23x"),
    0xab: ("add-double", "23x"), 0xac: ("sub-double", "23x"), 0xad: ("mul-double", "23x"),
    0xae: ("div-double", "23x"), 0xaf: ("rem-double", "23x"),
    0xb0: ("add-int/2addr", "12x"), 0xb1: ("sub-int/2addr", "12x"),
    0xb2: ("mul-int/2addr", "12x"), 0xb3: ("div-int/2addr", "12x"),
    0xb4: ("rem-int/2addr", "12x"), 0xb5: ("and-int/2addr", "12x"),
    0xb6: ("or-int/2addr", "12x"), 0xb7: ("xor-int/2addr", "12x"),
    0xb8: ("shl-int/2addr", "12x"), 0xb9: ("shr-int/2addr", "12x"),
    0xba: ("ushr-int/2addr", "12x"), 0xbb: ("add-long/2addr", "12x"),
    0xbc: ("sub-long/2addr", "12x"), 0xbd: ("mul-long/2addr", "12x"),
    0xbe: ("div-long/2addr", "12x"), 0xbf: ("rem-long/2addr", "12x"),
    0xc0: ("and-long/2addr", "12x"), 0xc1: ("or-long/2addr", "12x"),
    0xc2: ("xor-long/2addr", "12x"), 0xc3: ("shl-long/2addr", "12x"),
    0xc4: ("shr-long/2addr", "12x"), 0xc5: ("ushr-long/2addr", "12x"),
    0xc6: ("add-float/2addr", "12x"), 0xc7: ("sub-float/2addr", "12x"),
    0xc8: ("mul-float/2addr", "12x"), 0xc9: ("div-float/2addr", "12x"),
    0xca: ("rem-float/2addr", "12x"), 0xcb: ("add-double/2addr", "12x"),
    0xcc: ("sub-double/2addr", "12x"), 0xcd: ("mul-double/2addr", "12x"),
    0xce: ("div-double/2addr", "12x"), 0xcf: ("rem-double/2addr", "12x"),
    0xd0: ("add-int/lit16", "22s"), 0xd1: ("rsub-int", "22s"),
    0xd2: ("mul-int/lit16", "22s"), 0xd3: ("div-int/lit16", "22s"),
    0xd4: ("rem-int/lit16", "22s"), 0xd5: ("and-int/lit16", "22s"),
    0xd6: ("or-int/lit16", "22s"), 0xd7: ("xor-int/lit16", "22s"),
    0xd8: ("add-int/lit8", "22b"), 0xd9: ("rsub-int/lit8", "22b"),
    0xda: ("mul-int/lit8", "22b"), 0xdb: ("div-int/lit8", "22b"),
    0xdc: ("rem-int/lit8", "22b"), 0xdd: ("and-int/lit8", "22b"),
    0xde: ("or-int/lit8", "22b"), 0xdf: ("xor-int/lit8", "22b"),
    0xe0: ("shl-int/lit8", "22b"), 0xe1: ("shr-int/lit8", "22b"),
    0xe2: ("ushr-int/lit8", "22b"),
    0xf0: ("invoke-polymorphic", "45cc"), 0xf1: ("invoke-polymorphic/range", "4rcc"),
    0xf2: ("invoke-custom", "35c"), 0xf3: ("invoke-custom/range", "3rc"),
    0xf4: ("const-method-handle", "21c"), 0xf5: ("const-method-type", "21c"),
}

# 指令宽度 (以 16-bit code unit 计), 按 format
FORMAT_WIDTH = {
    "10x": 1, "12x": 1, "11n": 1, "11x": 1, "10t": 1,
    "20t": 2, "22x": 2, "21t": 2, "21s": 2, "21h": 2, "21c": 2, "23x": 2, "22b": 2,
    "22t": 2, "22s": 2, "22c": 2, "31i": 3, "31t": 3, "31c": 3, "32x": 3, "30t": 3,
    "35c": 3, "3rc": 3, "45cc": 4, "4rcc": 4, "51l": 5,
}


class DEX:
    def __init__(self, data):
        self.d = data
        self._parse_header()
        self.strings = self._read_strings()
        self.types = self._read_types()
        self.protos = self._read_protos()
        self.fields = self._read_fields()
        self.methods = self._read_methods()
        self.classes = self._read_classes()

    def u4(self, o): return struct.unpack_from("<I", self.d, o)[0]
    def u2(self, o): return struct.unpack_from("<H", self.d, o)[0]
    def u1(self, o): return self.d[o]

    def _parse_header(self):
        d = self.d
        if d[:4] != b"dex\n":
            raise DexError("不是 DEX 文件 (magic=%r)" % d[:8])
        self.magic = d[:8]
        self.checksum = self.u4(8)
        self.file_size = self.u4(0x20)
        self.header_size = self.u4(0x24)
        self.endian_tag = self.u4(0x28)
        self.string_ids_size = self.u4(0x38); self.string_ids_off = self.u4(0x3C)
        self.type_ids_size = self.u4(0x40); self.type_ids_off = self.u4(0x44)
        self.proto_ids_size = self.u4(0x48); self.proto_ids_off = self.u4(0x4C)
        self.field_ids_size = self.u4(0x50); self.field_ids_off = self.u4(0x54)
        self.method_ids_size = self.u4(0x58); self.method_ids_off = self.u4(0x5C)
        self.class_defs_size = self.u4(0x60); self.class_defs_off = self.u4(0x64)
        self.data_size = self.u4(0x68); self.data_off = self.u4(0x6C)

    def _uleb128(self, o):
        result = 0; shift = 0
        while True:
            b = self.d[o]; o += 1
            result |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                break
            shift += 7
        return result, o

    def _sleb128(self, o):
        result = 0; shift = 0
        while True:
            b = self.d[o]; o += 1
            result |= (b & 0x7F) << shift
            shift += 7
            if (b & 0x80) == 0:
                if b & 0x40:
                    result |= -(1 << shift)
                break
        return result, o

    def _read_strings(self):
        out = []
        for i in range(self.string_ids_size):
            off = self.u4(self.string_ids_off + i * 4)
            n, p = self._uleb128(off)
            end = self.d.find(b"\0", p)
            out.append(self.d[p:end].decode("utf-8", "replace"))
        return out

    def _read_types(self):
        return [self.strings[self.u4(self.type_ids_off + i * 4)]
                for i in range(self.type_ids_size)]

    def _read_protos(self):
        out = []
        for i in range(self.proto_ids_size):
            o = self.proto_ids_off + i * 12
            shorty = self.strings[self.u4(o)]
            ret = self.types[self.u4(o + 4)]
            params_off = self.u4(o + 8)
            params = []
            if params_off:
                sz = self.u4(params_off)
                for j in range(sz):
                    params.append(self.types[self.u2(params_off + 4 + j * 2)])
            out.append((shorty, ret, params))
        return out

    def _read_fields(self):
        out = []
        for i in range(self.field_ids_size):
            o = self.field_ids_off + i * 8
            cls = self.types[self.u2(o)]
            typ = self.types[self.u2(o + 2)]
            name = self.strings[self.u4(o + 4)]
            out.append((cls, name, typ))
        return out

    def _read_methods(self):
        out = []
        for i in range(self.method_ids_size):
            o = self.method_ids_off + i * 8
            cls = self.types[self.u2(o)]
            proto = self.protos[self.u2(o + 2)]
            name = self.strings[self.u4(o + 4)]
            out.append((cls, name, proto))
        return out

    def _read_classes(self):
        out = []
        for i in range(self.class_defs_size):
            o = self.class_defs_off + i * 32
            cls_idx = self.u4(o)
            access = self.u4(o + 4)
            super_idx = self.u4(o + 8)
            interfaces_off = self.u4(o + 12)
            source_idx = self.u4(o + 16)
            annotations_off = self.u4(o + 20)
            class_data_off = self.u4(o + 24)
            interfaces = []
            if interfaces_off:
                sz = self.u4(interfaces_off)
                interfaces = [self.types[self.u2(interfaces_off + 4 + j * 2)] for j in range(sz)]
            out.append({
                "class": self.types[cls_idx], "access": access,
                "super": self.types[super_idx] if super_idx != 0xFFFFFFFF else None,
                "interfaces": interfaces,
                "source": self.strings[source_idx] if source_idx != 0xFFFFFFFF else None,
                "class_data_off": class_data_off,
            })
        return out


# ============================================================ smali 反汇编
def type_to_smali(t):
    """类型描述符 -> smali 类型简写 (基本类型去 L;)。"""
    return t


def method_signature(cls, name, proto):
    shorty, ret, params = proto
    return "%s->%s(%s)%s" % (cls, name, "".join(params), ret)


def field_signature(cls, name, typ):
    return "%s->%s:%s" % (cls, name, typ)


class SmaliWriter:
    def __init__(self, dex):
        self.dex = dex
        self.lines = []

    def emit(self, s=""):
        self.lines.append(s)

    def disasm_class(self, cdef):
        d = self.dex
        cls = cdef["class"]
        self.emit(".class %s %s" % (_access_flags(cdef["access"]), cls))
        if cdef["super"]:
            self.emit(".super %s" % cdef["super"])
        for itf in cdef["interfaces"]:
            self.emit(".implements %s" % itf)
        if cdef["source"]:
            self.emit(".source \"%s\"" % cdef["source"])
        self.emit("")
        # class_data
        cdo = cdef["class_data_off"]
        fields = []
        methods = []
        if cdo:
            self._parse_class_data(cdo, fields, methods)
        for f in fields:
            self.emit(".field %s" % f)
        if fields:
            self.emit("")
        for m in methods:
            self._disasm_method(m)

    def _parse_class_data(self, off, fields, methods):
        d = self.dex
        sf, o = d._uleb128(off)
        inf, o = d._uleb128(o)
        dm, o = d._uleb128(o)
        vm, o = d._uleb128(o)
        idx = 0
        for _ in range(sf):
            diff, o = d._uleb128(o); idx += diff
            acc, o = d._uleb128(o)
            cls, name, typ = d.fields[idx]
            fields.append(".field %s %s:%s" % (_access_flags(acc), name, typ))
        idx = 0
        for _ in range(inf):
            diff, o = d._uleb128(o); idx += diff
            acc, o = d._uleb128(o)
            cls, name, typ = d.fields[idx]
            fields.append(".field %s %s:%s" % (_access_flags(acc), name, typ))
        idx = 0
        methods_data = []
        for _ in range(dm):
            diff, o = d._uleb128(o); idx += diff
            acc, o = d._uleb128(o)
            code_off, o = d._uleb128(o)
            methods_data.append((idx, acc, code_off, False))
        idx = 0
        for _ in range(vm):
            diff, o = d._uleb128(o); idx += diff
            acc, o = d._uleb128(o)
            code_off, o = d._uleb128(o)
            methods_data.append((idx, acc, code_off, True))
        for midx, acc, code_off, is_virtual in methods_data:
            cls, name, proto = d.methods[midx]
            methods.append((acc, cls, name, proto, code_off))

    def _disasm_method(self, m):
        acc, cls, name, proto, code_off = m
        self.emit("")
        self.emit(".method %s %s" % (_access_flags(acc), method_signature(cls, name, proto)))
        if code_off:
            self._disasm_code(code_off)
        self.emit(".end method")

    def _disasm_code(self, code_off):
        d = self.dex
        registers = d.u2(code_off)
        ins = d.u2(code_off + 2)
        outs = d.u2(code_off + 4)
        insns_size = d.u4(code_off + 12)
        insns_off = code_off + 16
        self.emit("    .registers %d" % registers)
        p = insns_off
        i = 0
        while i < insns_size:
            cu = d.u2(p)
            op = cu & 0xFF
            if op not in OPCODES:
                # 可能是 payload/nop 数据, 跳过
                self.emit("    .word 0x%04x" % cu)
                p += 2; i += 1
                continue
            mnem, fmt = OPCODES[op]
            width = FORMAT_WIDTH.get(fmt, 1)
            text = self._format_insn(mnem, fmt, cu, d.u2(p + 2) if width >= 2 else 0,
                                     d.u4(p + 2) if width >= 3 else 0, p, i)
            self.emit("    " + text)
            p += width * 2
            i += width

    def _format_insn(self, mnem, fmt, cu, w2, w3, insns_off, idx):
        d = self.dex
        A = (cu >> 8) & 0xF
        B = (cu >> 12) & 0xF
        C = cu & 0xFF
        if fmt == "10x":
            return mnem
        if fmt == "12x":
            return "%s v%d, v%d" % (mnem, A, B)
        if fmt == "11n":
            lit = B if B < 8 else B - 16
            return "%s v%d, #%d" % (mnem, A, lit)
        if fmt == "11x":
            return "%s v%d" % (mnem, A)
        if fmt == "10t":
            off = A if A < 8 else A - 256
            return "%s :goto_%d" % (mnem, idx + 1 + off)
        if fmt == "20t":
            off = w2 if w2 < 0x8000 else w2 - 0x10000
            return "%s :goto_%d" % (mnem, idx + off)
        if fmt == "22x":
            return "%s v%d, v%d" % (mnem, A, w2)
        if fmt == "21t":
            off = w2 if w2 < 0x8000 else w2 - 0x10000
            return "%s v%d, :goto_%d" % (mnem, A, idx + off)
        if fmt == "21s":
            v = w2 if w2 < 0x8000 else w2 - 0x10000
            return "%s v%d, #%d" % (mnem, A, v)
        if fmt == "21h":
            v = w2 if w2 < 0x8000 else w2 - 0x10000
            return "%s v%d, #0x%x" % (mnem, A, v & 0xFFFFFFFF)
        if fmt == "21c":
            if mnem.startswith("const-string"):
                sidx = w2
                return "%s v%d, \"%s\"" % (mnem, A, _escape(d.strings[sidx]))
            if mnem == "const-class":
                return "%s v%d, %s" % (mnem, A, d.types[w2])
            if mnem.startswith("sget") or mnem.startswith("sput"):
                return "%s v%d, %s" % (mnem, A, field_signature(*d.fields[w2]))
            if mnem in ("const-method-handle", "const-method-type"):
                return "%s v%d, %s" % (mnem, A, d.strings[w2])
            return "%s v%d, 0x%x" % (mnem, A, w2)
        if fmt == "22c":
            return "%s v%d, v%d, %s" % (mnem, A, B, field_signature(*d.fields[w2]))
        if fmt == "23x":
            return "%s v%d, v%d, v%d" % (mnem, A, B, C)
        if fmt == "22b":
            lit = C if C < 0x80 else C - 256
            return "%s v%d, v%d, #%d" % (mnem, A, B, lit)
        if fmt == "22t":
            off = w2 if w2 < 0x8000 else w2 - 0x10000
            return "%s v%d, v%d, :goto_%d" % (mnem, A, B, idx + off)
        if fmt == "22s":
            lit = w2 if w2 < 0x8000 else w2 - 0x10000
            return "%s v%d, v%d, #%d" % (mnem, A, B, lit)
        if fmt in ("31i", "31t", "31c"):
            val = w3
            if fmt == "31i":
                if val >= 0x80000000: val -= 0x100000000
                return "%s v%d, #%d" % (mnem, A, val)
            if fmt == "31t":
                return "%s v%d, :goto_%d" % (mnem, A, idx + val)
            if fmt == "31c":
                return "%s v%d, \"%s\"" % (mnem, A, _escape(d.strings[val]))
        if fmt == "32x":
            return "%s v%d, v%d" % (mnem, A, w3 & 0xFFFF)
        if fmt == "30t":
            return "%s :goto_%d" % (mnem, idx + w3)
        if fmt == "35c":
            # 35c: A|G|op BBBB F|E|D|C  (A=寄存器数, 依次 C,D,E,F,G)
            cnt = B  # (cu>>12)&0xF
            third = (w3 >> 16) & 0xFFFF
            regs = [third & 0xF, (third >> 4) & 0xF, (third >> 8) & 0xF,
                    (third >> 12) & 0xF, A]
            regs = regs[:cnt]
            if mnem.startswith("new"):
                tgt = d.types[w2]
            else:
                tgt = method_signature(*d.methods[w2])
            return "%s {%s}, %s" % (mnem, ", ".join("v%d" % r for r in regs), tgt)
        if fmt == "3rc":
            # 3rc: AA|op BBBB CCCC
            cnt = (cu >> 8) & 0xFF
            first = (w3 >> 16) & 0xFFFF
            regs = ["v%d" % (first + k) for k in range(cnt)]
            tgt = method_signature(*d.methods[w2])
            return "%s {%s}, %s" % (mnem, ", ".join(regs), tgt)
        if fmt == "51l":
            return "%s v%d, #%d" % (mnem, A, w3)
        return "%s (0x%02x)" % (mnem, cu & 0xFF)


def _access_flags(a):
    flags = []
    for bit, name in [(0x1, "public"), (0x2, "private"), (0x4, "protected"),
                      (0x8, "static"), (0x10, "final"), (0x20, "synchronized"),
                      (0x40, "volatile"), (0x80, "bridge"), (0x100, "native"),
                      (0x200, "interface"), (0x400, "abstract"), (0x800, "strictfp"),
                      (0x1000, "synthetic"), (0x2000, "annotation"), (0x4000, "enum"),
                      (0x10000, "constructor")]:
        if a & bit:
            flags.append(name)
    return " ".join(flags)


def _escape(s):
    return s.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")


def disasm_dex(data):
    dex = DEX(data)
    w = SmaliWriter(dex)
    out = []
    for cdef in dex.classes:
        w.lines = []
        w.disasm_class(cdef)
        out.append((cdef["class"], "\n".join(w.lines)))
    return dex, out


# ============================================================ CLI
def selftest():
    # 用合成 DEX 验证解析 (构造 header + 少量 string/type/method)
    ok = 0; fail = 0
    def check(n, c):
        nonlocal ok, fail
        print("  [%s] %s" % ("OK " if c else "ERR", n)); ok += 1 if c else 0; fail += 0 if c else 1
    # 检查操作码表完整度
    check("操作码表 >= 200", len(OPCODES) >= 200)
    check("含 move-result", 0x0a in OPCODES)
    check("含 invoke-virtual", 0x6e in OPCODES)
    check("含 const-string", 0x1a in OPCODES)
    check("含 if-eqz", 0x38 in OPCODES)
    check("含 return-void", 0x0e in OPCODES)
    # 构造最小合法 DEX 头
    hdr = bytearray(0x70)
    hdr[0:8] = b"dex\n035\0"
    struct.pack_into("<I", hdr, 0x20, 0x70)
    struct.pack_into("<I", hdr, 0x24, 0x70)
    struct.pack_into("<I", hdr, 0x28, 0x12345678)
    try:
        dex = DEX(bytes(hdr))
        check("解析空 DEX", dex.class_defs_size == 0)
    except Exception as ex:
        check("解析空 DEX (%s)" % ex, False)
    # 格式宽度自检
    check("const-string 宽度=2", FORMAT_WIDTH["21c"] == 2)
    check("invoke-virtual 宽度=3", FORMAT_WIDTH["35c"] == 3)
    check("const-wide 宽度=5", FORMAT_WIDTH["51l"] == 5)
    print("结果: %d 通过, %d 失败" % (ok, fail))
    return 0 if fail == 0 else 1


def main():
    a = sys.argv[1:]
    if "--selftest" in a:
        return selftest()
    if not a or a[0] in ("-h", "--help"):
        print(__doc__); return 0
    cmd = a[0]
    if cmd in ("disasm", "header", "strings", "classes"):
        data = open(a[1], "rb").read()
        if cmd == "header":
            dex = DEX(data)
            print("magic:", dex.magic)
            print("file_size: 0x%x" % dex.file_size)
            print("strings: %d, types: %d, methods: %d, classes: %d" %
                  (dex.string_ids_size, dex.type_ids_size, dex.method_ids_size, dex.class_defs_size))
        elif cmd == "strings":
            dex = DEX(data)
            for s in dex.strings:
                print(s)
        elif cmd == "classes":
            dex = DEX(data)
            for c in dex.classes:
                print(c["class"], "extends", c["super"])
        else:
            dex, classes = disasm_dex(data)
            outdir = a[2] if len(a) > 2 else "out"
            os.makedirs(outdir, exist_ok=True)
            for cls_name, text in classes:
                path = os.path.join(outdir, cls_name[1:-1] + ".smali")
                os.makedirs(os.path.dirname(path), exist_ok=True)
                open(path, "w", encoding="utf-8").write(text)
            print("已反汇编 %d 个类到 %s" % (len(classes), outdir))
        return 0
    print(__doc__); return 0


if __name__ == "__main__":
    sys.exit(main() or 0)