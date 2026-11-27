#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ILSpy / ICSharpCode.Decompiler 等价引擎 — IL -> C# 反编译核心（纯 Python）
=======================================================================

原程序：`ILSpy_7.2.1.6856_bin/ILSpy.exe`（前端）+ `ICSharpCode.Decompiler.dll`（引擎）

ILSpy 的 `ILSpy.exe` 只是 GUI 前端，真正的反编译由 ICSharpCode.Decompiler
完成：读程序集元数据 + 方法体 IL，做栈式表达式重建、类型推断、控制流结构化，
输出 C#。本 CLI 逐函数复刻其**表达式反编译核心**（基于 dnlib_py 引擎）：

  - 基于 IL 求值栈的表达式树重建（ldc.i4/ldstr/ldarg/ldfld/ldsfld/call/
    callvirt/newobj/castclass/box/unbox/算术/比较/分支…）
  - 运算符优先级与括号最小化
  - 记号解析（成员/类型/字符串）复用 dnlib_py
  - 简单方法体 -> C# 表达式 / return / 赋值语句

诚实说明：完整 ICSharpCode.Decompiler（数十万行、完整类型系统、泛型、
LINQ、async/await、控制流结构化、资源/WinForms 反编译）无法逐行移植。
本 CLI 是其**表达式反编译核心**的忠实子集，对简单方法产出真实可读 C#。

用法：
    python main.py <assembly> --method <name>   反编译某方法为 C#
    python main.py <assembly> --il <n>          按 MethodDef 索引(1基)
    python main.py <assembly> --list            列出全部方法
    python main.py <assembly> --all -o out.cs   反编译全部有方法体的方法

无第三方依赖，纯标准库（复用同仓 dnlib_py 引擎）。
"""

import argparse
import os
import sys

# 复用 dnlib_py 引擎（同仓兄弟目录）
_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "dnlib_py"))
import main as dnlib  # noqa: E402


# 运算符优先级（C#）：数字越大越“紧”
PREC = {
    "or": 1, "||": 1,
    "and": 2, "&&": 2,
    "bitor": 3, "|": 3,
    "bitxor": 4, "^": 4,
    "bitand": 5, "&": 5,
    "eq": 6, "==": 6, "ne": 6, "!=": 6,
    "lt": 7, "<": 7, "le": 7, "<=": 7, "gt": 7, ">": 7, "ge": 7, ">=": 7,
    "shl": 8, "<<": 8, "shr": 8, ">>": 8,
    "add": 9, "+": 9, "sub": 9, "-": 9,
    "mul": 10, "*": 10, "div": 10, "/": 10, "rem": 10, "%": 10,
}
# IL 算术/比较助记符 -> (C# 运算符, 优先级名)
BINOPS = {
    "add": ("+", "add"), "sub": ("-", "sub"), "mul": ("*", "mul"),
    "div": ("/", "div"), "div.un": ("/", "div"), "rem": ("%", "rem"),
    "rem.un": ("%", "rem"),
    "and": ("&", "bitand"), "or": ("|", "bitor"), "xor": ("^", "bitxor"),
    "shl": ("<<", "shl"), "shr": (">>", "shr"), "shr.un": (">>", "shr"),
    "ceq": ("==", "eq"), "cgt": (">", "gt"), "clt": ("<", "lt"),
    "cgt.un": (">", "gt"), "clt.un": ("<", "lt"),
    "beq": ("==", "eq"), "bne.un": ("!=", "ne"),
    "bge": (">=", "ge"), "bgt": (">", "gt"), "ble": ("<=", "le"), "blt": ("<", "lt"),
    "bge.un": (">=", "ge"), "bgt.un": (">", "gt"), "ble.un": ("<=", "le"), "blt.un": ("<", "lt"),
}


class Expr:
    """C# 表达式节点：持有源码串与优先级。"""
    __slots__ = ("src", "prec", "ty")

    def __init__(self, src, prec=100, ty="object"):
        self.src = src
        self.prec = prec
        self.ty = ty

    def paren(self, need_prec):
        if self.prec < need_prec:
            return "(" + self.src + ")"
        return self.src


class Decompiler:
    def __init__(self, md):
        self.md = md
        self._tds = md.typedefs()
        self._mds = md.methods()
        self._fds = md.fields()

    def member(self, tok):
        """返回 (kind, name) —— 复用 dnlib 的记号解析。"""
        return self.md.token_info(tok)

    def decompile_method(self, m):
        body = self.md.method_body(m["rva"])
        if body is None or body[1] == 0:
            return None
        _, _, _, code = body
        return self._eval(code)

    def _eval(self, code):
        """栈式重建：返回 C# 语句行列表。"""
        md = self.md
        ins = list(dnlib.read_il(code))
        stack = []          # List[Expr]
        lines = []
        i = 0
        n = len(ins)
        while i < n:
            off, mnem, operand = ins[i]
            base = mnem.rstrip(".")
            # ---- 常量 / 加载 ----
            if mnem.startswith("ldc.i4"):
                v = 0
                if mnem == "ldc.i4.m1": v = -1
                elif mnem.startswith("ldc.i4."):
                    try: v = int(mnem.split(".")[-1])
                    except ValueError: v = 0
                elif operand:
                    v = int(operand)
                stack.append(Expr(str(v), 100, "int"))
            elif mnem == "ldc.i8":
                stack.append(Expr(operand + "L", 100, "long"))
            elif mnem == "ldc.r4" or mnem == "ldc.r8":
                stack.append(Expr(operand, 100, "double"))
            elif mnem == "ldstr":
                kind, s = self.member(int(operand, 16))
                stack.append(Expr(s, 100, "string"))
            elif mnem == "ldnull":
                stack.append(Expr("null", 100, "object"))
            elif mnem.startswith("ldarg"):
                idx = self._arg_index(mnem, operand)
                stack.append(Expr(self._arg_name(idx), 100, "object"))
            elif mnem.startswith("ldloc"):
                idx = self._loc_index(mnem, operand)
                stack.append(Expr("loc" + str(idx), 100, "object"))
            # ---- 字段 ----
            elif mnem in ("ldfld", "ldsfld", "ldflda", "ldsflda"):
                kind, name = self.member(int(operand, 16))
                if mnem in ("ldsfld", "ldsflda"):
                    stack.append(Expr(name, 100, "object"))
                else:
                    recv = stack.pop() if stack else Expr("this", 100)
                    stack.append(Expr(recv.paren(11) + "." + name, 11, "object"))
            elif mnem in ("stfld", "stsfld"):
                kind, name = self.member(int(operand, 16))
                val = stack.pop() if stack else Expr("0")
                if mnem == "stsfld":
                    lines.append("%s = %s;" % (name, val.src))
                else:
                    recv = stack.pop() if stack else Expr("this")
                    lines.append("%s.%s = %s;" % (recv.src, name, val.src))
            # ---- 调用 / 对象 ----
            elif mnem in ("call", "callvirt", "newobj", "jmp"):
                kind, name = self.member(int(operand, 16))
                hasthis, argc = self._sig_info(int(operand, 16))
                args = [stack.pop() for _ in range(argc)][::-1] if argc else []
                arg_src = ", ".join(a.src for a in args)
                # 属性 getter 折叠：get_X() -> .X
                if name.startswith("get_") and argc == 0:
                    prop = name[4:]
                    if hasthis:
                        recv = stack.pop() if stack else Expr("this")
                        stack.append(Expr(recv.paren(11) + "." + prop, 11, "object"))
                    else:
                        stack.append(Expr(prop, 100, "object"))
                elif mnem == "newobj":
                    stack.append(Expr("new " + name + "(" + arg_src + ")", 100, name))
                elif hasthis:
                    recv = stack.pop() if stack else Expr("this")
                    sep = "" if name.startswith(".") else "."
                    if name in (".ctor", ".cctor"):
                        recv = Expr("base", 100)  # 基类构造函数调用
                    stack.append(Expr(recv.paren(11) + sep + name + "(" + arg_src + ")", 11, "object"))
                else:
                    stack.append(Expr(name + "(" + arg_src + ")", 100, "object"))
            elif mnem in ("castclass", "isinst", "box", "unbox", "unbox.any"):
                kind, name = self.member(int(operand, 16))
                e = stack.pop() if stack else Expr("null")
                if mnem in ("box", "unbox", "unbox.any"):
                    stack.append(Expr(e.src, e.prec, "object"))
                else:
                    stack.append(Expr("(" + name + ")" + e.paren(11), 11, name))
            # ---- 一元 / 转换 ----
            elif mnem == "neg":
                e = stack.pop() if stack else Expr("0")
                stack.append(Expr("-" + e.paren(11), 11, e.ty))
            elif mnem == "not":
                e = stack.pop() if stack else Expr("0")
                stack.append(Expr("~" + e.paren(11), 11, e.ty))
            elif mnem.startswith("conv."):
                e = stack.pop() if stack else Expr("0")
                ty = {"conv.i1": "sbyte", "conv.i2": "short", "conv.i4": "int",
                      "conv.i8": "long", "conv.r4": "float", "conv.r8": "double",
                      "conv.u1": "byte", "conv.u2": "ushort", "conv.u4": "uint",
                      "conv.u8": "ulong"}.get(mnem, "object")
                stack.append(Expr("(" + ty + ")" + e.paren(11), 11, ty))
            # ---- 二元 ----
            elif mnem in BINOPS:
                op, p = BINOPS[mnem]
                b = stack.pop() if stack else Expr("0")
                a = stack.pop() if stack else Expr("0")
                stack.append(Expr(a.paren(PREC[p]) + " " + op + " " + b.paren(PREC[p] + 1),
                                  PREC[p], a.ty))
            elif mnem == "dup":
                if stack: stack.append(stack[-1])
            elif mnem == "pop":
                if stack: stack.pop()
            # ---- 分支 / 返回 ----
            elif mnem == "ret":
                if stack:
                    lines.append("return " + stack.pop().src + ";")
                else:
                    lines.append("return;")
            elif mnem in ("br", "br.s"):
                pass  # 无条件跳转：核心版忽略（直线化）
            elif mnem in ("brfalse", "brtrue", "brfalse.s", "brtrue.s"):
                e = stack.pop() if stack else Expr("false")
                cond = ("!" + e.paren(11)) if mnem.startswith("brfalse") else e.src
                lines.append("if (" + cond + ") goto " + operand + ";")
            elif mnem in ("switch",):
                e = stack.pop() if stack else Expr("0")
                lines.append("switch (" + e.src + ") { /* %s */ }" % operand)
            elif mnem in ("leave", "leave.s", "endfinally", "endfilter"):
                pass
            else:
                # 未覆盖：尽量弹栈保持平衡（保守：不弹）
                pass
            i += 1
        # 收尾：把残留栈顶作为表达式语句（如方法末尾无 ret 的表达式）
        if not lines and stack:
            lines.append(stack.pop().src + ";")
        return lines or ["// (empty)"]

    # ---- helpers ----
    def _arg_index(self, mnem, operand):
        if mnem == "ldarg.0": return 0
        if mnem == "ldarg.1": return 1
        if mnem == "ldarg.2": return 2
        if mnem == "ldarg.3": return 3
        if operand:
            try: return int(operand)
            except ValueError: return 0
        return 0

    def _arg_name(self, idx):
        return "arg" + str(idx) if idx else "this"

    def _loc_index(self, mnem, operand):
        if mnem.startswith("ldloc."):
            s = mnem.split(".")[-1]
            try: return int(s)
            except ValueError: return 0
        if operand:
            try: return int(operand)
            except ValueError: return 0
        return 0

    def _compressed(self, b, o):
        """解 ECMA 压缩无符号整数，返回 (值, 新偏移)。"""
        b0 = b[o]
        if b0 & 0x80 == 0:
            return b0, o + 1
        if b0 & 0xC0 == 0x80:
            return ((b0 & 0x3F) << 8) | b[o + 1], o + 2
        return ((b0 & 0x1F) << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3], o + 4

    def _sig_info(self, tok):
        """解析方法签名头：返回 (hasthis, 参数个数)。"""
        t = tok >> 24; ridx = tok & 0xFFFFFF
        blobidx = None
        if t == 0x06 and ridx <= len(self._mds):
            blobidx = self._mds[ridx - 1]["sig"]
        elif t == 0x0A:
            mrs = self.md.memberrefs()
            if ridx <= len(mrs):
                blobidx = mrs[ridx - 1]["sig"]
        if blobidx is None:
            return (False, 0)
        b = self.md.blob(blobidx)
        if len(b) < 2:
            return (False, 0)
        hasthis = bool(b[0] & 0x20)
        pc, _ = self._compressed(b, 1)
        return (hasthis, pc)


def main(argv=None):
    ap = argparse.ArgumentParser(prog="ILSpy",
        description="ILSpy/ICSharpCode.Decompiler 等价引擎 — IL->C# 反编译核心（基于 dnlib_py）")
    ap.add_argument("assembly", help=".NET 程序集")
    ap.add_argument("--method", help="反编译指定方法名")
    ap.add_argument("--il", type=int, help="按 MethodDef 索引(1基)反编译")
    ap.add_argument("--list", action="store_true", help="列出全部方法")
    ap.add_argument("--all", action="store_true", help="反编译全部有方法体的方法")
    ap.add_argument("-o", "--output", help="输出到文件")
    args = ap.parse_args(argv)

    try:
        pe, md = dnlib.load(args.assembly)
    except Exception as e:
        print("Error: %s" % e, file=sys.stderr)
        return 1

    dec = Decompiler(md)
    methods = md.methods()

    def emit(m):
        lines = dec.decompile_method(m)
        if lines is None:
            return None
        out = ["// " + m["name"]]
        out += ["    " + ln for ln in lines]
        return "\n".join(out)

    chunks = []
    if args.list:
        for i, m in enumerate(methods):
            print("%4d  %s" % (i + 1, m["name"]))
        return 0

    if args.il is not None:
        idx = args.il - 1
        if idx < 0 or idx >= len(methods):
            print("method not found", file=sys.stderr); return 1
        txt = emit(methods[idx])
        print(txt if txt else "(no body)")
        return 0

    if args.method:
        for m in methods:
            if m["name"] == args.method:
                txt = emit(m)
                print(txt if txt else "(no body)")
                return 0
        print("method not found", file=sys.stderr); return 1

    if args.all:
        for m in methods:
            txt = emit(m)
            if txt:
                chunks.append(txt)
        text = "\n\n".join(chunks)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(text + "\n")
            print("wrote %s (%d methods)" % (args.output, len(chunks)), file=sys.stderr)
        else:
            print(text)
        return 0

    ap.print_help(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())