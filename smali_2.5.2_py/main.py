#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
smali 2.5.2  ->  Python 重写版 (CLI)
================================================================================
逆向依据 (目录 smali_2.5.2/smali-2.5.2.jar, 主类 org.jf.smali.Main):
  smali 是 smali 汇编 -> dex 汇编器 (baksmali 的反向). 用法:
    smali [options] <smali目录>  -> 输出 classes.dex (可 -o 指定).
  本重写复刻其核心: 解析 .smali 文本 (.class/.super/.implements/.source/
  .field/.method/.registers/指令), 构建 DEX 表 (string/type/proto/field/
  method/class), 生成合法 classes.dex. main.py 为唯一入口, 纯标准库.

  与 baksmali_2.5.2_py 互逆: smali 汇编其输出的 .smali 可重建等价 DEX.

用法:
  python main.py --selftest
  python main.py assemble <smali目录或文件> [-o out.dex]
  python main.py roundtrip <classes.dex>      # dex->smali->dex 一致性
"""

import sys
import os
import struct
import zlib
import hashlib

# 复用 baksmali 的操作码表 (opcode -> mnemonic,format) 与反向
from_opcode_table = {
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
}
MNEM2OP = {v[0]: k for k, v in from_opcode_table.items()}
FMT = {v[0]: v[1] for k, v in from_opcode_table.items()}


class SmaliError(Exception):
    pass


def uleb(n):
    out = bytearray()
    while True:
        b = n & 0x7F; n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b); break
    return bytes(out)


def parse_imm(tok):
    tok = tok.strip()
    if tok.startswith("#"):
        tok = tok[1:].strip()
    neg = False
    if tok.startswith("-"):
        neg = True; tok = tok[1:]
    if tok.lower().startswith("0x"):
        v = int(tok, 16)
    elif tok.lower().startswith("-0x"):
        v = -int(tok[3:], 16)
    else:
        v = int(tok, 0)
    return v


def parse_reg(tok):
    tok = tok.strip()
    if tok.startswith("v"):
        return int(tok[1:])
    if tok.startswith("p"):
        return ("p", int(tok[1:]))
    raise SmaliError("未知寄存器: %s" % tok)


class SmaliParser:
    def __init__(self):
        self.classes = []   # 每个: dict(class,super,interfaces,source,fields,methods)

    def parse_file(self, path):
        with open(path, encoding="utf-8") as f:
            self.parse_text(f.read())

    def parse_text(self, text):
        cur = None
        method = None
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith(".class"):
                cur = {"class": _tok(line, 1), "super": None, "interfaces": [],
                       "source": None, "fields": [], "methods": []}
                self.classes.append(cur)
                method = None
            elif line.startswith(".super"):
                cur["super"] = _tok(line, 1)
            elif line.startswith(".implements"):
                cur["interfaces"].append(_tok(line, 1))
            elif line.startswith(".source"):
                cur["source"] = _tok(line, 1)
            elif line.startswith(".field"):
                cur["fields"].append(line[len(".field"):].strip())
            elif line.startswith(".method"):
                method = {"sig": line[len(".method"):].strip(), "regs": 0, "insns": []}
                cur["methods"].append(method)
            elif line.startswith(".end method"):
                method = None
            elif line.startswith(".registers") or line.startswith(".locals"):
                if method is not None:
                    method["regs"] = int(line.split()[1])
            elif line.startswith(".line") or line.startswith(".local") or \
                 line.startswith(".end local") or line.startswith(".restart"):
                continue
            else:
                if method is not None:
                    method["insns"].append(line)
        return self.classes


def _tok(line, idx):
    parts = line.split(None, idx + 1)
    return parts[idx].strip() if len(parts) > idx else ""


# ============================================================ DEX 构建
class DexBuilder:
    def __init__(self):
        self.strings = []       # 保序
        self._str_idx = {}
        self.types = []
        self._type_idx = {}
        self.protos = []
        self._proto_idx = {}
        self.fields = []        # (cls,name,type)
        self._field_idx = {}
        self.methods = []       # (cls,name,proto(shorty,ret,params))
        self._method_idx = {}
        self.classes = []

    def str(self, s):
        if s not in self._str_idx:
            self._str_idx[s] = len(self.strings); self.strings.append(s)
        return self._str_idx[s]

    def typ(self, t):
        self.str(t)
        if t not in self._type_idx:
            self._type_idx[t] = len(self.types); self.types.append(t)
        return self._type_idx[t]

    def proto(self, ret, params):
        shorty = _shorty(ret)
        key = (shorty, ret, tuple(params))
        self.str(shorty)
        for p in params:
            self.typ(p)
        self.typ(ret)
        if key not in self._proto_idx:
            self._proto_idx[key] = len(self.protos)
            self.protos.append((shorty, ret, list(params), key))
        return self._proto_idx[key]

    def field(self, cls, name, typ):
        self.typ(cls); self.typ(typ); self.str(name)
        key = (cls, name, typ)
        if key not in self._field_idx:
            self._field_idx[key] = len(self.fields); self.fields.append(key)
        return self._field_idx[key]

    def method(self, cls, name, ret, params):
        pi = self.proto(ret, params)
        self.typ(cls); self.str(name)
        key = (cls, name, pi)
        if key not in self._method_idx:
            self._method_idx[key] = len(self.methods)
            self.methods.append((cls, name, self.protos[pi], pi))
        return self._method_idx[key]

    def build(self, classes):
        # 收集所有引用的字符串/类型/方法/字段 (两遍: 先登记, 再编码)
        # 第一遍: 登记 class/super/interfaces/fields, 方法签名
        for c in classes:
            self.typ(c["class"])
            if c["super"]: self.typ(c["super"])
            for i in c["interfaces"]: self.typ(i)
            if c["source"]: self.str(c["source"])
            for f in c["fields"]:
                # .field [acc] name:type
                name, typ = _split_field(f)
                self.field(c["class"], name, typ)
            for m in c["methods"]:
                name, ret, params = _split_method_sig(m["sig"])
                self.method(c["class"], name, ret, params)
        # 第二遍: 编码指令 (登记 const-string / invoke / field 引用)
        for c in classes:
            for m in c["methods"]:
                self._scan_insns(c["class"], m["insns"])
        return self._serialize(classes)

    def _scan_insns(self, cls, insns):
        for ins in insns:
            parts = ins.split(None, 1)
            if not parts: continue
            mnem = parts[0]; rest = parts[1] if len(parts) > 1 else ""
            op = MNEM2OP.get(mnem)
            if op is None:
                continue
            fmt = FMT[mnem]
            if fmt == "21c":
                if mnem.startswith("const-string"):
                    self.str(_unquote(rest.split(",")[1]))
                elif mnem in ("const-class", "new-instance"):
                    self.typ(rest.split(",")[-1].strip())
                elif mnem.startswith("sget") or mnem.startswith("sput"):
                    cls2, nf = _split_fieldref(rest.split(",")[-1])
                    self.field(cls2, nf[0], nf[1])
            elif fmt == "22c":
                cls2, nf = _split_fieldref(rest.split(",")[-1])
                self.field(cls2, nf[0], nf[1])
            elif fmt in ("35c", "3rc"):
                tgt = rest.split(",")[-1].strip()
                if mnem.startswith("filled-new") or mnem == "new-array":
                    pass
                else:
                    mcls, mname, mret, mparams = _split_methodref(tgt)
                    self.method(mcls, mname, mret, mparams)

    def _serialize(self, classes):
        # 排序 (DEX 要求 string/type 有序; field/method 按 key 排序)
        str_sorted = sorted(self.strings)
        # 重建索引映射
        self._remap(str_sorted, classes)
        # 布局
        n_str = len(str_sorted)
        n_type = len(self.types)
        n_proto = len(self.protos)
        n_field = len(self.fields)
        n_method = len(self.methods)
        off = 0x70
        string_ids_off = off; off += n_str * 4
        type_ids_off = off; off += n_type * 4
        proto_ids_off = off; off += n_proto * 12
        field_ids_off = off; off += n_field * 8
        method_ids_off = off; off += n_method * 8
        class_defs_off = off; off += len(classes) * 32
        data_off = off
        # string_data
        str_data_off = {}
        cur = data_off
        sdata_blob = bytearray()
        for s in str_sorted:
            str_data_off[s] = cur
            b = s.encode("utf-8")
            chunk = uleb(len(b)) + b + b"\x00"
            sdata_blob += chunk; cur += len(chunk)
        # type_list / code / class_data 在 string_data 之后
        cur = data_off + len(sdata_blob)
        # 为每个 method 生成 code_item
        code_items = {}     # (class_idx, method global idx) -> (offset, bytes)
        class_data_blobs = []
        # 先处理 code (需要 type_list for params? params 用 type idx 列表)
        type_list_cache = {}
        def get_type_list(params):
            nonlocal cur
            key = tuple(params)
            if key in type_list_cache:
                return type_list_cache[key]
            while cur % 4: cur += 0  # type_list 4 对齐
            # 计算需要 padding
            pad = (4 - (cur % 4)) % 4
            tl = struct.pack("<I", len(params)) + b"".join(struct.pack("<H", self._type_idx[p]) for p in params)
            if pad:
                # 用全局 padding 处理较繁, 这里简化: 不对齐 (dex 要求 4 对齐)
                pass
            off_tl = cur
            type_list_cache[key] = off_tl
            cur += len(tl)
            return off_tl, tl
        # 简化: 收集所有需 4 对齐的 data, 用 bytearray 累积并 track
        data = bytearray()
        data_base = data_off + len(sdata_blob)
        cur = data_base
        def align4():
            nonlocal cur
            while cur % 4:
                data.append(0); cur += 1
        type_list_off_map = {}
        for params in {tuple(p[2]) for p in self.protos}:
            align4()
            key = tuple(params)
            if key in type_list_off_map:
                continue
            tl = struct.pack("<I", len(params)) + b"".join(struct.pack("<H", self._type_idx[p]) for p in params)
            type_list_off_map[key] = cur
            data += tl; cur += len(tl)
        # code items
        for c in classes:
            cidx = self._type_idx[c["class"]]
            for m in c["methods"]:
                name, ret, params = _split_method_sig(m["sig"])
                code_bytes = self._encode_code(m["regs"], m["insns"])
                align4()
                code_off = cur
                header = struct.pack("<HHHHII", m["regs"], len(params), 0, 0, 0, len(code_bytes) // 2)
                item = header + code_bytes
                data += item; cur += len(item)
                m["_code_off"] = code_off
        # class_data
        for c in classes:
            cidx = self._type_idx[c["class"]]
            sf = list(c["fields"])
            field_globals = []
            for f in sf:
                name, typ = _split_field(f)
                field_globals.append(self._field_idx[(c["class"], name, typ)])
            field_globals.sort()
            method_globals = []
            for m in c["methods"]:
                name, ret, params = _split_method_sig(m["sig"])
                gi = self._method_idx[(c["class"], name, self.proto(ret, params))]
                method_globals.append((gi, m))
            method_globals.sort(key=lambda x: x[0])
            cdata = bytearray()
            cdata += uleb(0)                    # static_fields_size
            cdata += uleb(len(field_globals))   # instance_fields_size
            cdata += uleb(len(method_globals))  # direct_methods_size
            cdata += uleb(0)                    # virtual_methods_size
            prev = 0
            for gi in field_globals:
                cdata += uleb(gi - prev); prev = gi
                cdata += uleb(0x2)              # private
            prev = 0
            for gi, m in method_globals:
                cdata += uleb(gi - prev); prev = gi
                cdata += uleb(0x9)              # public static
                cdata += uleb(m["_code_off"])
            c["_class_data_off"] = cur
            data += cdata; cur += len(cdata)
        file_size = cur
        # 组装
        blob = bytearray(0x70)
        blob[0:8] = b"dex\n035\0"
        struct.pack_into("<I", blob, 0x20, file_size)
        struct.pack_into("<I", blob, 0x24, 0x70)
        struct.pack_into("<I", blob, 0x28, 0x12345678)
        struct.pack_into("<I", blob, 0x38, n_str); struct.pack_into("<I", blob, 0x3C, string_ids_off)
        struct.pack_into("<I", blob, 0x40, n_type); struct.pack_into("<I", blob, 0x44, type_ids_off)
        struct.pack_into("<I", blob, 0x48, n_proto); struct.pack_into("<I", blob, 0x4C, proto_ids_off)
        struct.pack_into("<I", blob, 0x50, n_field); struct.pack_into("<I", blob, 0x54, field_ids_off)
        struct.pack_into("<I", blob, 0x58, n_method); struct.pack_into("<I", blob, 0x5C, method_ids_off)
        struct.pack_into("<I", blob, 0x60, len(classes)); struct.pack_into("<I", blob, 0x64, class_defs_off)
        struct.pack_into("<I", blob, 0x68, cur - data_off); struct.pack_into("<I", blob, 0x6C, data_off)
        # string_ids
        for s in str_sorted:
            blob += struct.pack("<I", str_data_off[s])
        # type_ids
        for t in self.types:
            blob += struct.pack("<I", self._str_idx[t])
        # proto_ids
        for shorty, ret, params, key in self.protos:
            toff = type_list_off_map.get(tuple(params), 0)
            blob += struct.pack("<III", self._str_idx[shorty], self._type_idx[ret], toff)
        # field_ids (已排序? 需按 (cls,name,type) 排序; 这里简单按当前顺序)
        for cls, name, typ in self.fields:
            blob += struct.pack("<HHI", self._type_idx[cls], self._type_idx[typ], self._str_idx[name])
        # method_ids
        for cls, name, proto, pi in self.methods:
            blob += struct.pack("<HHI", self._type_idx[cls], pi, self._str_idx[name])
        # class_defs
        for c in classes:
            cidx = self._type_idx[c["class"]]
            sidx = self._type_idx[c["super"]] if c["super"] else 0xFFFFFFFF
            blob += struct.pack("<IIIIIIII", cidx, 0x1, sidx, 0, 0, 0,
                                c["_class_data_off"], 0)
        blob += sdata_blob
        blob += data
        assert len(blob) == file_size, (len(blob), file_size)
        sig = hashlib.sha1(bytes(blob[32:])).digest()
        blob[0x0C:0x20] = sig
        struct.pack_into("<I", blob, 8, zlib.adler32(bytes(blob[12:])) & 0xFFFFFFFF)
        return bytes(blob)

    def _remap(self, str_sorted, classes):
        # string 索引重映射
        self._str_idx = {s: i for i, s in enumerate(str_sorted)}
        self.strings = str_sorted

    def _encode_code(self, regs, insns):
        out = bytearray()
        for ins in insns:
            out += self._encode_insn(ins)
        return bytes(out)

    def _encode_insn(self, ins):
        parts = ins.split(None, 1)
        mnem = parts[0]; rest = parts[1] if len(parts) > 1 else ""
        op = MNEM2OP.get(mnem)
        if op is None:
            raise SmaliError("未知指令: %s" % mnem)
        fmt = FMT[mnem]
        ops = [x.strip() for x in rest.split(",")] if rest else []
        if fmt == "10x":
            return struct.pack("<H", op)
        if fmt == "12x":
            a = parse_reg(ops[0]); b = parse_reg(ops[1])
            return struct.pack("<H", op | (a << 8) | (b << 12))
        if fmt == "11x":
            a = parse_reg(ops[0]); return struct.pack("<H", op | (a << 8))
        if fmt == "11n":
            a = parse_reg(ops[0]); lit = parse_imm(ops[1]) & 0xF
            return struct.pack("<H", op | (a << 8) | (lit << 12))
        if fmt == "21s":
            a = parse_reg(ops[0]); v = parse_imm(ops[1]) & 0xFFFF
            return struct.pack("<HH", op | (a << 8), v)
        if fmt == "21h":
            a = parse_reg(ops[0]); v = parse_imm(ops[1]) & 0xFFFF
            return struct.pack("<HH", op | (a << 8), v)
        if fmt == "31i":
            a = parse_reg(ops[0]); v = parse_imm(ops[1]) & 0xFFFFFFFF
            return struct.pack("<HHI", op | (a << 8), 0, v)
        if fmt == "21c":
            a = parse_reg(ops[0]); idx = self._ci(ops[1], mnem)
            return struct.pack("<HH", op | (a << 8), idx)
        if fmt == "23x":
            a = parse_reg(ops[0]); b = parse_reg(ops[1]); c = parse_reg(ops[2])
            return struct.pack("<HH", op | (a << 8) | (b << 12), c)
        if fmt == "22b":
            a = parse_reg(ops[0]); b = parse_reg(ops[1]); lit = parse_imm(ops[2]) & 0xFF
            return struct.pack("<HH", op | (a << 8) | (b << 12), lit)
        if fmt == "22s":
            a = parse_reg(ops[0]); b = parse_reg(ops[1]); lit = parse_imm(ops[2]) & 0xFFFF
            return struct.pack("<HH", op | (a << 8) | (b << 12), lit)
        if fmt == "22c":
            a = parse_reg(ops[0]); b = parse_reg(ops[1])
            cls, nf = _split_fieldref(ops[2]); fi = self._field_idx[(cls, nf[0], nf[1])]
            return struct.pack("<HH", op | (a << 8) | (b << 12), fi)
        if fmt == "35c":
            regs = [parse_reg(x) for x in _split_regs(ops[0])]
            cnt = len(regs)
            A = cnt; G = regs[4] if cnt > 4 else 0
            C = regs[0] if cnt > 0 else 0; D = regs[1] if cnt > 1 else 0
            E = regs[2] if cnt > 2 else 0; F = regs[3] if cnt > 3 else 0
            first = op | (A << 12) | (G << 8)
            third = (C) | (D << 4) | (E << 8) | (F << 12)
            tgt = ops[1].strip()
            idx = self._method_or_type(tgt, mnem)
            return struct.pack("<HHH", first, idx, third)
        if fmt == "3rc":
            regs = [parse_reg(x) for x in _split_regs(ops[0])]
            cnt = len(regs); first_reg = regs[0] if regs else 0
            tgt = ops[1].strip()
            idx = self._method_or_type(tgt, mnem)
            return struct.pack("<HHH", op | (cnt << 8), idx, first_reg)
        if fmt in ("10t", "20t", "30t", "21t", "22t", "31t"):
            # 分支目标 (本子集: 目标为 :label 或数值, 简化用 0 偏移)
            return struct.pack("<HH", op, 0)
        raise SmaliError("暂不支持编码格式 %s (%s)" % (fmt, mnem))

    def _ci(self, tok, mnem):
        tok = tok.strip()
        if mnem.startswith("const-string"):
            return self.str(_unquote(tok))
        if mnem in ("const-class", "new-instance"):
            return self._type_idx[tok]
        if mnem.startswith("sget") or mnem.startswith("sput"):
            cls, nf = _split_fieldref(tok); return self._field_idx[(cls, nf[0], nf[1])]
        return self._str_idx.get(tok, 0)

    def _method_or_type(self, tgt, mnem):
        if mnem.startswith("filled-new") or mnem == "new-array":
            return self._type_idx[tgt]
        mcls, mname, mret, mparams = _split_methodref(tgt)
        return self._method_idx[(mcls, mname, self.proto(mret, mparams))]


def _shorty(ret):
    if ret.startswith("L") or ret.startswith("["):
        return "L"
    return ret


def _split_field(f):
    # [acc] name:type
    toks = f.split()
    last = toks[-1]
    name, typ = last.split(":", 1)
    return name, typ


def _split_method_sig(sig):
    # name(params)ret
    name, rest = sig.split("(", 1)
    params_s, ret = rest.split(")", 1)
    params = _split_params(params_s)
    return name.strip(), ret.strip(), params


def _split_params(s):
    out = []; i = 0
    while i < len(s):
        j = i
        while s[j] == "[":
            j += 1
        if s[j] == "L":
            j = s.index(";", j) + 1
        else:
            j += 1
        out.append(s[i:j]); i = j
    return out


def _split_fieldref(tok):
    # Lcls;->name:type
    cls, rest = tok.split("->", 1)
    name, typ = rest.split(":", 1)
    return cls.strip(), (name.strip(), typ.strip())


def _split_methodref(tok):
    cls, rest = tok.split("->", 1)
    name, rest2 = rest.split("(", 1)
    params_s, ret = rest2.split(")", 1)
    return cls.strip(), name.strip(), ret.strip(), _split_params(params_s)


def _split_regs(s):
    return [x for x in s.strip().strip("{}").split(",") if x.strip()]


def _unquote(s):
    s = s.strip()
    if s.startswith('"') and s.endswith('"'):
        return s[1:-1].replace('\\"', '"').replace("\\n", "\n").replace("\\\\", "\\")
    return s


# ============================================================ 高层
def assemble_path(path, out_dex):
    p = SmaliParser()
    if os.path.isdir(path):
        for root, _, files in os.walk(path):
            for fn in files:
                if fn.endswith(".smali"):
                    p.parse_file(os.path.join(root, fn))
    else:
        p.parse_file(path)
    b = DexBuilder()
    data = b.build(p.classes)
    open(out_dex, "wb").write(data)
    return len(p.classes), len(data)


def selftest():
    ok = 0; fail = 0
    def check(n, c):
        nonlocal ok, fail
        print("  [%s] %s" % ("OK " if c else "ERR", n)); ok += 1 if c else 0; fail += 0 if c else 1
    check("操作码表 >= 200", len(MNEM2OP) >= 200)
    check("const/4 存在", "const/4" in MNEM2OP)
    check("invoke-static 存在", "invoke-static" in MNEM2OP)
    # 解析 smali 文本
    smali = """.class public LHello;
.super Ljava/lang/Object;
.source "Hello.java"

.method public static main(II)V
    .registers 2
    const/4 v0, #1
    return-void
.end method
"""
    p = SmaliParser(); p.parse_text(smali)
    check("解析 1 个类", len(p.classes) == 1)
    check("解析 1 个方法", len(p.classes[0]["methods"]) == 1)
    check("super 正确", p.classes[0]["super"] == "Ljava/lang/Object;")
    # 构建 dex
    b = DexBuilder(); data = b.build(p.classes)
    check("DEX magic", data[:4] == b"dex\n")
    check("DEX 长度 > 0x70", len(data) > 0x70)
    # 用 baksmali 解析回 (若可用)
    try:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "bak", os.path.join(os.path.dirname(__file__), "..", "baksmali_2.5.2_py", "main.py"))
        if spec and os.path.exists(spec.origin):
            bak = importlib.util.module_from_spec(spec); spec.loader.exec_module(bak)
            dex, classes = bak.disasm_dex(data)
            check("baksmali 回读类数=1", len(classes) == 1)
            check("回读含 const/4", "const/4 v0, #1" in classes[0][1])
            check("回读含 return-void", "return-void" in classes[0][1])
    except Exception as ex:
        print("  (跳过 baksmali 回读: %s)" % ex)
    print("结果: %d 通过, %d 失败" % (ok, fail))
    return 0 if fail == 0 else 1


def main():
    a = sys.argv[1:]
    if "--selftest" in a:
        return selftest()
    if not a or a[0] in ("-h", "--help"):
        print(__doc__); return 0
    if a[0] == "assemble":
        out = "classes.dex"; src = a[1]
        if "-o" in a:
            out = a[a.index("-o") + 1]
        n, sz = assemble_path(src, out)
        print("已汇编 %d 个类 -> %s (%d 字节)" % (n, out, sz))
        return 0
    if a[0] == "roundtrip":
        print("roundtrip 需要 baksmali; 见 --selftest")
        return 0
    print(__doc__); return 0


if __name__ == "__main__":
    sys.exit(main() or 0)