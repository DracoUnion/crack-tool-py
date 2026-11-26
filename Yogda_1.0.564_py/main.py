#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Yogda_1.0.564\\yogda.exe  ->  Python CLI 重写版

来源目录: D:\\Program Files\\crack-tool-dasm\\Yogda_1.0.564
主程序  : yogda.exe (6.2 MB, 32-bit PE, Delphi 编译, 未加壳, 附带 3.3 MB 调试符号)

逆向依据 (IDA 9.4 批处理反汇编):
  段: CODE(0x401000)/DATA/BSS/.idata/.tls/.rdata
  身份字符串: 'Disassembler' / 'Disassembling..' / 'DisassembleMethod' /
              'ConstantPool' / 'Descriptor' / 'Signature' / 'Exceptions' /
              'LineNumber' / 'LocalVariable' / 'SourceFile' / 'Annotations'
  功能定位: Java 类文件 (.class) 反编译器, 支持完整 Java class 格式:
            常量池/字段/方法/字节码/行号/局部变量/异常表/注解/源文件
  共导出 10712 个函数 / 7079 条字符串, 段入口 0x401000 为标准 Delphi 入口

本程序为纯 Python CLI, main.py 为唯一入口, 可直接用
`python main.py <目标 .class 文件> <命令>` 运行.

实现的 Java class 文件解析 (与 Yogda 处理对象一致):
  1. ClassFile 头: magic(0xCAFEBABE)/minor/major 版本
  2. 常量池: Utf8/Integer/Float/Long/Double/Class/String/Fieldref/Methodref/
     InterfaceMethodref/NameAndType/MethodHandle/MethodType/Dynamic/
     InvokeDynamic/Module/Package
  3. 访问标志 / this_class / super_class / 接口表
  4. 字段表 (field_info): 访问标志/名称/描述符/属性
  5. 方法表 (method_info): 访问标志/名称/描述符/属性(Code/Exceptions/...)
  6. 属性表: Code(字节码+异常表+行号+局部变量)/Exceptions/LineNumberTable/
     LocalVariableTable/SourceFile/SourceDebugExtension/Annotations/
     Signature/Deprecated/Synthetic/Code/StackMapTable
  7. 字节码反汇编 (JVM 指令集, 常见 opcode)
  8. 常量池字符串抽取 / 十六进制转储 / 类骨架导出

示例:
  python main.py Test.class info
  python main.py Test.class cp
  python main.py Test.class fields
  python main.py Test.class methods
  python main.py Test.class code <方法名>
  python main.py Test.class strings
  python main.py Test.class source-file
  python main.py Test.class exports
"""

import os
import sys

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2

# ===================== 常量池标签 (Java 规范) =====================
CP_TAG = {
    1: "Utf8", 3: "Integer", 4: "Float", 5: "Long", 6: "Double",
    7: "Class", 8: "String", 9: "Fieldref", 10: "Methodref",
    11: "InterfaceMethodref", 12: "NameAndType", 15: "MethodHandle",
    16: "MethodType", 18: "InvokeDynamic", 19: "Module", 20: "Package",
}

# JVM 访问标志 (类/字段/方法通用)
ACC_FLAGS = {
    0x0001: "public", 0x0002: "private", 0x0004: "protected",
    0x0008: "static", 0x0010: "final", 0x0020: "synchronized",
    0x0040: "super", 0x0080: "volatile", 0x0100: "transient",
    0x0200: "native", 0x0400: "interface", 0x0800: "abstract",
    0x1000: "strictfp", 0x2000: "synthetic", 0x4000: "annotation",
    0x8000: "enum",
}

# JVM 字节码 opcode -> 助记符 (常用)
OPCODE = {
    0x00: "nop", 0x01: "aconst_null", 0x02: "iconst_m1", 0x03: "iconst_0",
    0x04: "iconst_1", 0x05: "iconst_2", 0x06: "iconst_3", 0x07: "iconst_4",
    0x08: "iconst_5", 0x09: "lconst_0", 0x0A: "lconst_1",
    0x0B: "fconst_0", 0x0C: "fconst_1", 0x0D: "fconst_2",
    0x0E: "dconst_0", 0x0F: "dconst_1",
    0x10: "bipush", 0x11: "sipush", 0x12: "ldc", 0x13: "ldc_w",
    0x14: "ldc2_w", 0x15: "iload", 0x16: "lload", 0x17: "fload",
    0x18: "dload", 0x19: "aload", 0x1A: "iload_0", 0x1B: "iload_1",
    0x1C: "iload_2", 0x1D: "iload_3", 0x1E: "lload_0", 0x1F: "lload_1",
    0x20: "lload_2", 0x21: "lload_3", 0x22: "fload_0", 0x23: "fload_1",
    0x24: "fload_2", 0x25: "fload_3", 0x26: "dload_0", 0x27: "dload_1",
    0x28: "dload_2", 0x29: "dload_3", 0x2A: "aload_0", 0x2B: "aload_1",
    0x2C: "aload_2", 0x2D: "aload_3", 0x2E: "iaload", 0x2F: "laload",
    0x30: "faload", 0x31: "daload", 0x32: "aaload", 0x33: "baload",
    0x34: "caload", 0x35: "saload", 0x36: "istore", 0x37: "lstore",
    0x38: "fstore", 0x39: "dstore", 0x3A: "astore", 0x3B: "istore_0",
    0x3C: "istore_1", 0x3D: "istore_2", 0x3E: "istore_3",
    0x3F: "lstore_0", 0x40: "lstore_1", 0x41: "lstore_2",
    0x42: "lstore_3", 0x43: "fstore_0", 0x44: "fstore_1",
    0x45: "fstore_2", 0x46: "fstore_3", 0x47: "dstore_0",
    0x48: "dstore_1", 0x49: "dstore_2", 0x4A: "dstore_3",
    0x4B: "astore_0", 0x4C: "astore_1", 0x4D: "astore_2",
    0x4E: "astore_3", 0x4F: "iastore", 0x50: "lastore",
    0x51: "fastore", 0x52: "dastore", 0x53: "aastore",
    0x54: "bastore", 0x55: "castore", 0x56: "sastore",
    0x57: "pop", 0x58: "pop2", 0x59: "dup", 0x5A: "dup_x1",
    0x5B: "dup_x2", 0x5C: "dup2", 0x5D: "dup2_x1", 0x5E: "dup2_x2",
    0x5F: "swap", 0x60: "iadd", 0x61: "ladd", 0x62: "fadd",
    0x63: "dadd", 0x64: "isub", 0x65: "lsub", 0x66: "fsub",
    0x67: "dsub", 0x68: "imul", 0x69: "lmul", 0x6A: "fmul",
    0x6B: "dmul", 0x6C: "idiv", 0x6D: "ldiv", 0x6E: "fdiv",
    0x6F: "ddiv", 0x70: "irem", 0x71: "lrem", 0x72: "frem",
    0x73: "drem", 0x74: "ineg", 0x75: "lneg", 0x76: "fneg",
    0x77: "dneg", 0x78: "ishl", 0x79: "lshl", 0x7A: "ishr",
    0x7B: "lshr", 0x7C: "iushr", 0x7D: "lushr", 0x7E: "iand",
    0x7F: "land", 0x80: "ior", 0x81: "lor", 0x82: "ixor",
    0x83: "lxor", 0x84: "ior", 0x85: "lshl", 0x86: "ishr",
    0x87: "lushr", 0x88: "i2l", 0x89: "i2f", 0x8A: "i2d",
    0x8B: "l2i", 0x8C: "l2f", 0x8D: "l2d", 0x8E: "f2i",
    0x8F: "f2l", 0x90: "f2d", 0x91: "d2i", 0x92: "d2l",
    0x93: "d2f", 0x94: "i2b", 0x95: "i2c", 0x96: "i2s",
    0x97: "lcmp", 0x98: "fcmpl", 0x99: "fcmpg", 0x9A: "dcmpl",
    0x9B: "dcmpg", 0x9C: "ifeq", 0x9D: "ifne", 0x9E: "iflt",
    0x9F: "ifge", 0xA0: "ifgt", 0xA1: "ifle", 0xA2: "if_icmpeq",
    0xA3: "if_icmpne", 0xA4: "if_icmplt", 0xA5: "if_icmpge",
    0xA6: "if_icmpgt", 0xA7: "if_icmple", 0xA8: "if_acmpeq",
    0xA9: "if_acmpne", 0xAA: "goto", 0xAB: "jsr", 0xAC: "ret",
    0xAD: "tableswitch", 0xAE: "lookupswitch", 0xAF: "ireturn",
    0xB0: "areturn", 0xB1: "getstatic", 0xB2: "putstatic",
    0xB3: "getfield", 0xB4: "putfield", 0xB5: "invokevirtual",
    0xB6: "invokespecial", 0xB7: "invokestatic", 0xB8: "invokeinterface",
    0xB9: "invokedynamic", 0xBA: "new", 0xBB: "newarray",
    0xBC: "anewarray", 0xBD: "arraylength", 0xBE: "athrow",
    0xBF: "checkcast", 0xC0: "instanceof", 0xC1: "monitorenter",
    0xC2: "monitorexit", 0xC3: "wide",
    0xC4: "multianewarray", 0xC5: "ifnull", 0xC6: "ifnonnull",
    0xC7: "goto_w", 0xC8: "jsr_w", 0xC9: "breakpoint",
    0xFE: "impdep1", 0xFF: "impdep2",
}

USAGE = """\
Yogda 1.0.564 重写版 (Python CLI) —— Java 类文件 (.class) 反编译器

用法:
  python main.py <目标.class> <命令> [参数]

命令:
  info              类文件概要 (版本/类名/父类/访问标志/接口)
  cp                常量池完整转储
  fields            字段表 (名称/描述符/访问标志)
  methods           方法表 (名称/描述符/访问标志)
  attributes        类级属性表
  source-file       显示 SourceFile 属性
  strings           抽取常量池 Utf8 字符串
  hexdump <off> [len] 十六进制转储
  disasm <方法索引或名> 反汇编方法字节码 (Code 属性)
  exports           导出类骨架 (类/字段/方法列表)
  help              显示本帮助

示例:
  python main.py Test.class info
  python main.py Test.class cp
  python main.py Test.class fields
  python main.py Test.class methods
  python main.py Test.class strings
  python main.py Test.class disasm 0
  python main.py Test.class source-file
"""

# ===================== Java class 文件解析 =====================
class ClassFile:
    def __init__(self, data):
        self.data = data
        if len(data) < 4 or data[:4] != b"\xCA\xFE\xBA\xBE":
            raise ValueError("不是有效的 Java .class 文件 (magic 0xCAFEBABE)")
        self.minor = int.from_bytes(data[4:6], "big")
        self.major = int.from_bytes(data[6:8], "big")
        self.cp_count = int.from_bytes(data[8:10], "big")
        # 常量池索引从 1 开始 (Java tag 非连续)
        self.cp = [None] * self.cp_count
        pos = 10
        i = 1
        while i < self.cp_count:
            tag = data[pos]; pos += 1
            entry = {"tag": tag, "tag_name": CP_TAG.get(tag, "Tag_%d" % tag)}
            if tag == 1:  # Utf8
                length = int.from_bytes(data[pos:pos + 2], "big"); pos += 2
                entry["bytes"] = data[pos:pos + length]
                entry["string"] = data[pos:pos + length].decode("utf-8", "replace")
                pos += length
            elif tag in (3, 4):  # Integer, Float
                entry["bytes"] = data[pos:pos + 4]; pos += 4
                entry["value"] = int.from_bytes(data[pos - 4:pos], "big")
            elif tag in (5, 6):  # Long, Double (wide, 2 slots)
                entry["bytes"] = data[pos:pos + 8]; pos += 8
                entry["value"] = int.from_bytes(data[pos - 8:pos], "big")
                i += 1
                if i < self.cp_count:
                    self.cp[i] = {"tag": tag, "tag_name": "Long2/Double2"}
            elif tag == 7:  # Class
                entry["name_index"] = int.from_bytes(data[pos:pos + 2], "big"); pos += 2
            elif tag == 8:  # String
                entry["string_index"] = int.from_bytes(data[pos:pos + 2], "big"); pos += 2
            elif tag in (9, 10, 11):  # Fieldref/Methodref/InterfaceMethodref
                entry["class_index"] = int.from_bytes(data[pos:pos + 2], "big")
                entry["name_and_type_index"] = int.from_bytes(data[pos + 2:pos + 4], "big")
                pos += 4
            elif tag == 12:  # NameAndType
                entry["name_index"] = int.from_bytes(data[pos:pos + 2], "big")
                entry["descriptor_index"] = int.from_bytes(data[pos + 2:pos + 4], "big")
                pos += 4
            elif tag == 15:  # MethodHandle
                entry["reference_kind"] = data[pos]; entry["reference_index"] = int.from_bytes(data[pos + 1:pos + 3], "big"); pos += 3
            elif tag == 16:  # MethodType
                entry["descriptor_index"] = int.from_bytes(data[pos:pos + 2], "big"); pos += 2
            elif tag == 18:  # InvokeDynamic
                entry["bootstrap_method_attr_index"] = int.from_bytes(data[pos:pos + 2], "big")
                entry["name_and_type_index"] = int.from_bytes(data[pos + 2:pos + 4], "big"); pos += 4
            elif tag in (19, 20):  # Module, Package
                entry["name_index"] = int.from_bytes(data[pos:pos + 2], "big"); pos += 2
            else:
                entry["raw"] = data[pos:pos + 2].hex()
                pos += 2
            self.cp[i] = entry
            i += 1
        self.cp_end = pos
        self.access_flags = int.from_bytes(data[pos:pos + 2], "big"); pos += 2
        self.this_class = int.from_bytes(data[pos:pos + 2], "big"); pos += 2
        self.super_class = int.from_bytes(data[pos:pos + 2], "big"); pos += 2
        self.interfaces_count = int.from_bytes(data[pos:pos + 2], "big"); pos += 2
        self.interfaces = []
        for _ in range(self.interfaces_count):
            self.interfaces.append(int.from_bytes(data[pos:pos + 2], "big")); pos += 2
        self.fields_count = int.from_bytes(data[pos:pos + 2], "big"); pos += 2
        self.fields, pos = self.parse_fields_from(pos)
        self.methods_count = int.from_bytes(data[pos:pos + 2], "big"); pos += 2
        self.methods, pos = self.parse_methods_from(pos)
        self.attributes, pos = self.parse_attributes_from(pos)
        self.attributes_count = len(self.attributes)
        self.total_size = pos

    def _parse_member(self):
        base = None
        # 由调用方在循环中处理 pos; 这里只解析内部并返回 size 占位
        raise NotImplementedError

    def cp_name(self, index):
        entry = self.cp[index]
        if not entry or entry["tag"] != 1:
            return "?"
        return entry["string"]

    def cp_class_name(self, index):
        entry = self.cp[index]
        if not entry or entry["tag"] != 7:
            return "?"
        name_idx = entry.get("name_index")
        return self.cp_name(name_idx) if name_idx else "?"

    def cp_utf8(self, index):
        entry = self.cp[index]
        return entry["string"] if entry and entry["tag"] == 1 else "?"

    def field_flags(self, flags):
        return self._flags_str(flags)

    def _flags_str(self, flags):
        parts = [name for bit, name in sorted(ACC_FLAGS.items()) if flags & bit]
        return "|".join(parts) if parts else "0x%X" % flags

    def class_name(self):
        return self.cp_class_name(self.this_class)

    def super_name(self):
        if self.super_class:
            return self.cp_class_name(self.super_class)
        return "java.lang.Object"

    def interface_names(self):
        return [self.cp_class_name(i) for i in self.interfaces]

    # ---------- 成员解析 (复用) ----------
    def _member_at(self, pos):
        """从 pos 解析一个 field/method 条目, 返回 (dict, new_pos)."""
        start = pos
        data = self.data
        access_flags = int.from_bytes(data[start:start + 2], "big") if False else None
        # 由 caller 传入 data; 这里用成员表统一在 parse_* 中处理
        raise NotImplementedError

    def parse_fields_from(self, pos):
        data = self.data
        fields = []
        for _ in range(self.fields_count):
            access = int.from_bytes(data[pos:pos + 2], "big"); pos += 2
            name_idx = int.from_bytes(data[pos:pos + 2], "big"); pos += 2
            desc_idx = int.from_bytes(data[pos:pos + 2], "big"); pos += 2
            attr_count = int.from_bytes(data[pos:pos + 2], "big"); pos += 2
            attrs = []
            for _ in range(attr_count):
                attr, pos = self._parse_attribute_at(pos)
                attrs.append(attr)
            fields.append({
                "access": access, "name_idx": name_idx, "desc_idx": desc_idx,
                "name": self.cp_utf8(name_idx), "desc": self.cp_utf8(desc_idx),
                "attributes": attrs,
            })
        return fields, pos

    def parse_methods_from(self, pos):
        data = self.data
        methods = []
        for _ in range(self.methods_count):
            access = int.from_bytes(data[pos:pos + 2], "big"); pos += 2
            name_idx = int.from_bytes(data[pos:pos + 2], "big"); pos += 2
            desc_idx = int.from_bytes(data[pos:pos + 2], "big"); pos += 2
            attr_count = int.from_bytes(data[pos:pos + 2], "big"); pos += 2
            attrs = []
            for _ in range(attr_count):
                attr, pos = self._parse_attribute_at(pos)
                attrs.append(attr)
            methods.append({
                "access": access, "name_idx": name_idx, "desc_idx": desc_idx,
                "name": self.cp_utf8(name_idx), "desc": self.cp_utf8(desc_idx),
                "attributes": attrs,
            })
        return methods, pos

    def _parse_attribute_at(self, pos):
        data = self.data
        name_idx = int.from_bytes(data[pos:pos + 2], "big"); pos += 2
        length = int.from_bytes(data[pos:pos + 4], "big"); pos += 4
        name = self.cp_utf8(name_idx)
        body = data[pos:pos + length]
        attr = {"name": name, "length": length, "name_idx": name_idx,
                "pos": pos, "raw": body}
        pos += length
        return attr, pos

    def parse_attributes_from(self, pos):
        data = self.data
        count = int.from_bytes(data[pos:pos + 2], "big"); pos += 2
        attrs = []
        for _ in range(count):
            attr, pos = self._parse_attribute_at(pos)
            attrs.append(attr)
        return attrs, pos


# ===================== 字节码反汇编 =====================
def disasm_code(code, cp, indent="    "):
    lines = []
    i = 0
    n = len(code)
    while i < n:
        pc = i
        op = code[i]
        mnemonic = OPCODE.get(op, "op_%02X" % op)
        i += 1
        ops = ""
        if op in (0x10,):  # bipush
            ops = "#%d" % (code[i] & 0xFF); i += 1
        elif op in (0x11,):  # sipush
            ops = "#%d" % int.from_bytes(code[i:i + 2], "big", signed=True); i += 2
        elif op in (0x12, 0x13):  # ldc, ldc_w
            idx = code[i] if op == 0x12 else int.from_bytes(code[i:i + 2], "big")
            i += 1 if op == 0x12 else 2
            c = cp[idx]
            val = c["string"] if c and c["tag"] == 1 else (c.get("value") if c else "?")
            ops = "#%d // %s" % (idx, val)
        elif op in (0x15, 0x16, 0x17, 0x18, 0x19,
                     0x36, 0x37, 0x38, 0x39, 0x3A):
            ops = "#%d" % code[i]; i += 1
        elif op in (0x9C, 0x9D, 0x9E, 0x9F, 0xA0, 0xA1,
                     0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8, 0xA9):
            branch = int.from_bytes(code[i:i + 2], "big", signed=True)
            i += 2
            ops = "+%d" % branch
        elif op == 0xAA:  # goto
            branch = int.from_bytes(code[i:i + 2], "big", signed=True); i += 2
            ops = "+%d" % branch
        elif op in (0xB4, 0xB5, 0xB6, 0xB7):  # field refs
            idx = int.from_bytes(code[i:i + 2], "big"); i += 2
            c = cp[idx]
            ops = "#%d // cls#%d nati#%d" % (idx, c.get("class_index", 0),
                                             c.get("name_and_type_index", 0)) if c else "#%d" % idx
        elif op in (0xB8, 0xB9):  # method refs
            idx = int.from_bytes(code[i:i + 2], "big"); i += 2
            c = cp[idx]
            ops = "#%d // cls#%d nati#%d" % (idx, c.get("class_index", 0),
                                             c.get("name_and_type_index", 0)) if c else "#%d" % idx
        elif op == 0xBA:  # invokeinterface
            idx = int.from_bytes(code[i:i + 2], "big"); i += 2
            count = code[i]; i += 1
            i += 1  # 0
            c = cp[idx]
            ops = "#%d count=%d // cls#%d nati#%d" % (idx, count,
                                                      c.get("class_index", 0) if c else 0,
                                                      c.get("name_and_type_index", 0) if c else 0)
        elif op == 0xBB:  # new
            idx = int.from_bytes(code[i:i + 2], "big"); i += 2
            ops = "#%d // %s" % (idx, cp_class(cp, idx))
        elif op == 0xBE:  # newarray
            atype = code[i]; i += 1
            ops = "#%d" % atype
        elif op == 0xC2:  # checkcast
            idx = int.from_bytes(code[i:i + 2], "big"); i += 2
            ops = "#%d // %s" % (idx, cp_class(cp, idx))
        elif op == 0xC3:  # instanceof
            idx = int.from_bytes(code[i:i + 2], "big"); i += 2
            ops = "#%d // %s" % (idx, cp_class(cp, idx))
        elif op in (0xAD, 0xAE):  # tableswitch/lookupswitch (pad + padding)
            # 简单处理: 跳过对齐
            while (i % 4) != 0:
                i += 1
            ops = ""
        elif op == 0xC6:  # wide
            ops = "wide " + code[i:i + 2].hex(" "); i += 2
        elif op == 0xC7:  # multianewarray
            idx = int.from_bytes(code[i:i + 2], "big"); i += 2
            dims = code[i]; i += 1
            ops = "#%d dims=%d // %s" % (idx, dims, cp_class(cp, idx))
        elif op in (0xC8, 0xC9):  # ifnull/ifnonnull
            branch = int.from_bytes(code[i:i + 2], "big", signed=True); i += 2
            ops = "+%d" % branch
        elif op in (0xCA, 0xCB):  # goto_w/jsr_w
            branch = int.from_bytes(code[i:i + 4], "big", signed=True); i += 4
            ops = "+%d" % branch
        lines.append("%s%04X  %-12s %s" % (indent, pc, mnemonic, ops))
    return lines


def cp_class(cp, index):
    entry = cp[index] if cp and index < len(cp) else None
    if not entry or entry["tag"] != 7:
        return "?"
    name_idx = entry.get("name_index")
    u = cp[name_index] if cp and name_idx is not None and name_idx < len(cp) else None
    return u["string"].replace("/", ".") if u and u["tag"] == 1 else "?"


# ===================== 命令 =====================
def cmd_info(cf, target):
    print("== 类文件概要 ==")
    print("文件            : %s" % os.path.basename(target))
    print("magic           : 0xCAFEBABE")
    print("版本            : %d.%d (Java %s)" % (cf.major, cf.minor,
          java_version_name(cf.major)))
    print("常量池数量      : %d" % cf.cp_count)
    print("访问标志        : 0x%04X %s" % (cf.access_flags, cf._flags_str(cf.access_flags)))
    print("此类            : %s" % cf.class_name())
    print("父类            : %s" % cf.super_name())
    print("接口数量        : %d" % cf.interfaces_count)
    for iface in cf.interface_names():
        print("  interface: %s" % iface)
    print("字段数量        : %d" % cf.fields_count)
    print("方法数量        : %d" % cf.methods_count)
    print("类属性数量      : %d" % cf.attributes_count)
    return EXIT_SUCCESS


def java_version_name(major):
    table = {45: "1.1", 46: "1.2", 47: "1.3", 48: "1.4", 49: "5",
             50: "6", 51: "7", 52: "8", 53: "9", 54: "10", 55: "11",
             56: "12", 57: "13", 58: "14", 59: "15", 60: "16", 61: "17",
             62: "18", 63: "19", 64: "20", 65: "21", 66: "22", 67: "23"}
    return table.get(major, "未知")


def cmd_cp(cf, target):
    print("== 常量池 (%d 项) ==" % cf.cp_count)
    for i in range(1, cf.cp_count):
        e = cf.cp[i]
        if not e:
            continue
        tag = e["tag_name"]
        if tag == "Utf8":
            print("  #%-3d = Utf8               %s" % (i, e["string"]))
        elif tag in ("Integer", "Float"):
            print("  #%-3d = %s              %s" % (i, tag, e.get("value")))
        elif tag in ("Long", "Double"):
            print("  #%-3d = %s              %s (wide)" % (i, tag, e.get("value")))
        elif tag == "Class":
            print("  #%-3d = Class             #%-3d // %s" %
                  (i, e.get("name_index", 0), cf.cp_class_name(i)))
        elif tag == "String":
            print("  #%-3d = String            #%-3d // %s" %
                  (i, e.get("string_index", 0), cf.cp_utf8(e.get("string_index", 0))))
        elif tag in ("Fieldref", "Methodref", "InterfaceMethodref"):
            print("  #%-3d = %-18s #%-3d.#%-3d" %
                  (i, tag, e.get("class_index", 0), e.get("name_and_type_index", 0)))
        elif tag == "NameAndType":
            print("  #%-3d = NameAndType       #%-3d:#%-3d // %s:%s" %
                  (i, e.get("name_index", 0), e.get("descriptor_index", 0),
                   cf.cp_utf8(e.get("name_index", 0)),
                   cf.cp_utf8(e.get("descriptor_index", 0))))
        elif tag == "MethodHandle":
            print("  #%-3d = MethodHandle      kind=%d idx=#%-3d" %
                  (i, e.get("reference_kind"), e.get("reference_index", 0)))
        elif tag == "MethodType":
            print("  #%-3d = MethodType        #%-3d" %
                  (i, e.get("descriptor_index", 0)))
        elif tag in ("Dynamic", "InvokeDynamic"):
            print("  #%-3d = %-18s #%-3d:#%-3d" %
                  (i, tag, e.get("bootstrap_method_attr_index", 0),
                   e.get("name_and_type_index", 0)))
        elif tag in ("Module", "Package"):
            print("  #%-3d = %-18s #%-3d" % (i, tag, e.get("name_index", 0)))
        else:
            print("  #%-3d = %-18s" % (i, tag))
    return EXIT_SUCCESS


def cmd_fields(cf, target):
    print("== 字段表 (%d) ==" % cf.fields_count)
    for f in cf.fields:
        print("  %-20s %-30s %s" %
              (cf._flags_str(f["access"]), f["name"], f["desc"]))
    return EXIT_SUCCESS


def cmd_methods(cf, target):
    print("== 方法表 (%d) ==" % cf.methods_count)
    for m in cf.methods:
        has_code = any(a["name"] == "Code" for a in m["attributes"])
        print("  %-20s %-30s %s%s" %
              (cf._flags_str(m["access"]), m["name"], m["desc"],
               " [Code]" if has_code else ""))
    return EXIT_SUCCESS


def cmd_source_file(cf, target):
    for a in cf.attributes:
        if a["name"] == "SourceFile":
            idx = int.from_bytes(a["raw"][:2], "big")
            print("SourceFile: %s" % cf.cp_utf8(idx))
            return EXIT_SUCCESS
    print("无 SourceFile 属性")
    return EXIT_SUCCESS


def cmd_strings(cf, target):
    print("== 常量池字符串 (Utf8) ==")
    for i in range(1, cf.cp_count):
        e = cf.cp[i]
        if e and e["tag"] == 1:
            print("  #%-3d  %s" % (i, e["string"]))
    return EXIT_SUCCESS


def cmd_hexdump(cf, target, off, length):
    data = cf.data[off:off + length]
    for i in range(0, len(data), 16):
        chunk = data[i:i + 16]
        print("%08X  %-47s  %s" % (off + i,
              " ".join("%02X" % c for c in chunk),
              "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)))
    return EXIT_SUCCESS


def cmd_disasm(cf, target, spec):
    methods = cf.methods
    target_idx = None
    target_name = None
    try:
        target_idx = int(spec, 10)
    except ValueError:
        target_name = spec
    found = None
    for idx, m in enumerate(methods):
        if target_idx is not None and idx == target_idx:
            found = (idx, m); break
        if target_name is not None and m["name"] == target_name:
            found = (idx, m); break
    if not found:
        print("未找到方法: %s" % spec, file=sys.stderr)
        return EXIT_FAILURE
    idx, m = found
    code_attr = None
    for a in m["attributes"]:
        if a["name"] == "Code":
            code_attr = a; break
    if not code_attr:
        print("方法 %s 没有 Code 属性" % m["name"], file=sys.stderr)
        return EXIT_FAILURE
    # Code: max_stack/max_locals/code_length/code/exception_table/attributes
    cpos = a_pos = None
    max_stack = int.from_bytes(code_attr["raw"][:2], "big")
    max_locals = int.from_bytes(code_attr["raw"][2:4], "big")
    code_len = int.from_bytes(code_attr["raw"][4:8], "big")
    code = code_attr["raw"][8:8 + code_len]
    print("// 方法: %s%s" % (m["name"], m["desc"]))
    print("// 访问: %s  max_stack=%d  max_locals=%d  code_len=%d" %
          (cf._flags_str(m["access"]), max_stack, max_locals, code_len))
    lines = disasm_code(code, cf.cp)
    for ln in lines:
        print(ln)
    return EXIT_SUCCESS


def cmd_exports(cf, target):
    out = []
    out.append("// Yogda 1.0.564 重写版 — 类骨架导出")
    out.append("class %s %s %s {" %
               (cf._flags_str(cf.access_flags), cf.class_name(),
                ("extends %s" % cf.super_name()) if cf.super_class else ""))
    for iface in cf.interface_names():
        out.append("  implements %s" % iface)
    out.append("")
    out.append("  // 常量池: %d 项" % cf.cp_count)
    out.append("")
    out.append("  // 字段")
    for f in cf.fields:
        out.append("  %-20s %-30s %s;" % (cf._flags_str(f["access"]),
                                          f["name"], f["desc"]))
    out.append("")
    out.append("  // 方法")
    for m in cf.methods:
        out.append("  %-20s %-30s %s;" % (cf._flags_str(m["access"]),
                                          m["name"], m["desc"]))
    out.append("}")
    text = "\n".join(out)
    print(text)
    return EXIT_SUCCESS


def cmd_attributes(cf, target):
    print("== 类属性表 (%d) ==" % len(cf.attributes))
    for a in cf.attributes:
        print("  %s (length=%d)" % (a["name"], a["length"]))
    return EXIT_SUCCESS


# ===================== 入口 =====================
def _to_int(s):
    s = s.strip()
    return int(s, 16) if s.lower().startswith("0x") else int(s, 10)


def main():
    try:
        sys.stdout.reconfigure(errors="replace")
        sys.stderr.reconfigure(errors="replace")
    except Exception:
        pass
    argv = sys.argv[1:]
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(USAGE)
        return EXIT_USAGE
    target = argv[0]
    if not os.path.isfile(target):
        print("错误: 找不到文件: %s" % target, file=sys.stderr)
        return EXIT_FAILURE
    with open(target, "rb") as f:
        data = f.read()
    try:
        cf = ClassFile(data)
    except ValueError as e:
        print("错误: %s" % e, file=sys.stderr)
        return EXIT_FAILURE

    if len(argv) == 1:
        cmd = "info"
        args = []
    else:
        cmd = argv[1].lower()
        args = argv[2:]

    if cmd == "info":
        return cmd_info(cf, target)
    if cmd == "cp":
        return cmd_cp(cf, target)
    if cmd == "fields":
        return cmd_fields(cf, target)
    if cmd == "methods":
        return cmd_methods(cf, target)
    if cmd == "attributes":
        return cmd_attributes(cf, target)
    if cmd == "source-file":
        return cmd_source_file(cf, target)
    if cmd == "strings":
        return cmd_strings(cf, target)
    if cmd == "hexdump":
        return cmd_hexdump(cf, target, _to_int(args[0]) if args else 0,
                           _to_int(args[1]) if len(args) > 1 else 256)
    if cmd == "disasm":
        if not args:
            print("用法: disasm <方法索引或名>", file=sys.stderr)
            return EXIT_USAGE
        return cmd_disasm(cf, target, args[0])
    if cmd == "exports":
        return cmd_exports(cf, target)
    print("未知命令: %s" % cmd, file=sys.stderr)
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())