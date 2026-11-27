#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mono.Cecil 等价引擎 — .NET 程序集对象模型（纯 Python）
====================================================

原程序：被 de4dot / 众多混淆器与反射工具引用的 `Mono.Cecil.dll`

Mono.Cecil 是 .NET 程序集读写对象模型库：`ModuleDefinition.ReadModule(path)`
读入模块，暴露 `Types / Methods / Fields / Body.Instructions` 等对象。de4dot、
Mono.Cecil 生态的几乎所有工具都构建于其上。本 CLI 用纯标准库（复用同仓
`dnlib_py` 元数据引擎）复刻其**读取侧对象模型**：

  - `ModuleDefinition.ReadModule(path)`
  - `ModuleDefinition.Types` -> `TypeDefinition`（Name/Namespace/FullName/
    Methods/Fields/NestedTypes）
  - `TypeDefinition.Methods` -> `MethodDefinition`（Name/DeclaringType/Body）
  - `MethodDefinition.Body` -> `MethodBody.Instructions` -> `Instruction`
    （OpCode / Operand / Offset）
  - `ILProcessor` 占位（读取侧只读）

诚实说明：Cecil 的**写入**（ILProcessor.Emit / WriteModule 重写程序集）需要
完整元数据写入器，超出本核心范围；本 CLI 是其读取侧对象模型的忠实子集。

用法：
    python main.py <assembly>                    列出类型/方法（Cecil 风格）
    python main.py <assembly> --type <t> --method <m>   导出方法 IL
    python main.py <assembly> --il <n>           按 MethodDef 索引导出 IL

无第三方依赖，纯标准库（导入同仓 dnlib_py 引擎）。
"""

import argparse
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "dnlib_py"))
import main as dnlib  # noqa: E402


class Instruction:
    """Cecil Instruction：OpCode / Operand / Offset。"""
    __slots__ = ("OpCode", "Operand", "Offset")

    def __init__(self, offset, mnem, operand, md=None):
        self.Offset = offset
        self.OpCode = mnem
        self.Operand = operand
        if md is not None and isinstance(operand, str) and operand.startswith("0x") and len(operand) == 10:
            kind, nm = md.token_info(int(operand, 16))
            self.Operand = "%s (%s)" % (operand, nm)

    def __str__(self):
        if self.Operand:
            return "IL_%04X: %-14s %s" % (self.Offset, self.OpCode, self.Operand)
        return "IL_%04X: %s" % (self.Offset, self.OpCode)


class MethodBody:
    def __init__(self, instructions):
        self.Instructions = instructions


class MethodDefinition:
    def __init__(self, name, declaring_type, rva, impl, md):
        self.Name = name
        self.DeclaringType = declaring_type
        self.RVA = rva
        self.ImplFlags = impl
        self._md = md
        self._body = None
        self._body_loaded = False

    @property
    def Body(self):
        if not self._body_loaded:
            self._body_loaded = True
            b = self._md.method_body(self.RVA)
            if b and b[1] > 0:
                code = b[3]
                instrs = [Instruction(off, mn, op, self._md)
                          for off, mn, op in dnlib.read_il(code)]
                self._body = MethodBody(instrs)
        return self._body


class FieldDefinition:
    def __init__(self, name, flags):
        self.Name = name
        self.Attributes = flags


class TypeDefinition:
    def __init__(self, name, ns, flags, md):
        self.Name = name
        self.Namespace = ns
        self.Attributes = flags
        self._md = md
        self.Methods = []
        self.Fields = []
        self.NestedTypes = []

    @property
    def FullName(self):
        return (self.Namespace + "." + self.Name) if self.Namespace else self.Name


class ModuleDefinition:
    def __init__(self, path):
        self.path = path
        self._pe, self._md = dnlib.load(path)
        self.Types = []
        self._build()

    @classmethod
    def ReadModule(cls, path):
        return cls(path)

    def _build(self):
        md = self._md
        tds = md.typedefs()
        mds = md.methods()
        fds = md.fields()
        # 建立 TypeDefinition 对象（按 TypeDef 顺序）
        type_objs = []
        for td in tds:
            t = TypeDefinition(td["name"], td["ns"], td["flags"], md)
            type_objs.append((td, t))
            self.Types.append(t)
        # 分配方法/字段到其声明类型（按 TypeDef 的 method_list/field_list 区间）
        for i, (td, t) in enumerate(type_objs):
            m_start = td["method_list"] - 1
            m_end = type_objs[i + 1][0]["method_list"] - 1 if i + 1 < len(type_objs) else len(mds)
            for mi in range(m_start, min(m_end, len(mds))):
                m = mds[mi]
                t.Methods.append(MethodDefinition(m["name"], t, m["rva"], m["impl"], md))
            f_start = td["field_list"] - 1
            f_end = type_objs[i + 1][0]["field_list"] - 1 if i + 1 < len(type_objs) else len(fds)
            for fi in range(f_start, min(f_end, len(fds))):
                t.Fields.append(FieldDefinition(fds[fi]["name"], fds[fi]["flags"]))

    def get_type(self, fullname):
        for t in self.Types:
            if t.FullName == fullname or t.Name == fullname:
                return t
        return None


def main(argv=None):
    ap = argparse.ArgumentParser(prog="Mono.Cecil",
        description="Mono.Cecil 等价引擎 — .NET 程序集对象模型（读取侧，基于 dnlib_py）")
    ap.add_argument("assembly", help=".NET 程序集")
    ap.add_argument("--type", help="类型名（Name 或 FullName）")
    ap.add_argument("--method", help="方法名")
    ap.add_argument("--il", type=int, help="按 MethodDef 索引(1基)导出 IL")
    args = ap.parse_args(argv)

    try:
        mod = ModuleDefinition.ReadModule(args.assembly)
    except Exception as e:
        print("Error: %s" % e, file=sys.stderr)
        return 1

    if args.il is not None:
        mds = mod._md.methods()
        idx = args.il - 1
        if idx < 0 or idx >= len(mds):
            print("method not found", file=sys.stderr); return 1
        m = mds[idx]
        body = mod._md.method_body(m["rva"])
        print("// " + m["name"])
        if not body:
            print("  (no body)"); return 0
        for off, mn, op in dnlib.read_il(body[3]):
            ins = Instruction(off, mn, op, mod._md)
            print("  " + str(ins))
        return 0

    if args.type:
        t = mod.get_type(args.type)
        if t is None:
            print("type not found", file=sys.stderr); return 1
        if args.method:
            for m in t.Methods:
                if m.Name == args.method:
                    print("// " + t.FullName + "::" + m.Name)
                    if m.Body:
                        for ins in m.Body.Instructions:
                            print("  " + str(ins))
                    else:
                        print("  (no body)")
                    return 0
            print("method not found", file=sys.stderr); return 1
        print("type " + t.FullName + "  methods=%d fields=%d" % (len(t.Methods), len(t.Fields)))
        for m in t.Methods:
            print("  method " + m.Name)
        return 0

    # 默认：列出类型与方法
    for t in mod.Types:
        print("type %s  (methods=%d fields=%d)" % (t.FullName, len(t.Methods), len(t.Fields)))
    return 0


if __name__ == "__main__":
    sys.exit(main())