#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
de4dot.code 去混淆引擎核心（分析侧）— 纯 Python
================================================

原程序：`de4dot_2.0.3/bin/de4dot.cui.dll` -> `de4dot.code` 引擎（Mono.Cecil 基）

de4dot.code 的完整去混淆（数百条混淆器规则、字符串解密、控制流去混淆、
代理方法移除、写回程序集）无法逐行移植。本模块实现其**分析核心**：用
dnlib_py 解析元数据 + 方法体 IL，识别常见混淆特征并给出证据：

  - 字符串加密：返回 string、带 int/token 参数、被多处用常量整数调用的方法
    （经典 `string Decrypt(int id)` 模式）
  - 代理/转发方法：方法体仅 `ldarg.0; call Target; ret`
  - 控制流平坦化：含 >=5 目标 switch 且存在回边跳转
  - 标识符重命名：全符号 / 极短随机名 的类型/方法/字段统计
  - P/Invoke：pinvokeimpl 方法计数

这是“检测 + 证据”引擎；真正的字节级改写需完整元数据写入器，超出本核心范围。
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(_HERE, "..", "dnlib_py"))
import main as dnlib  # noqa: E402


def _is_weird_name(name):
    """真正像随机/重命名的标识符：全符号/数字，或极短且无字母。"""
    if not name:
        return False
    has_letter = any(("a" <= c <= "z") or ("A" <= c <= "Z") for c in name)
    if has_letter and any(ord(c) > 126 for c in name):   # 含非 ASCII 的可疑
        return True
    if not has_letter:                                    # 全符号/数字
        return True
    if len(name) <= 2 and name[0] not in "_.<>@":         # 极短随机名
        return True
    return False


def _compressed(b, o):
    b0 = b[o]
    if b0 & 0x80 == 0:
        return b0, o + 1
    if b0 & 0xC0 == 0x80:
        return ((b0 & 0x3F) << 8) | b[o + 1], o + 2
    return ((b0 & 0x1F) << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3], o + 4


def _sig_paramcount_ret(md, blobidx):
    """解析方法签名头：(参数个数, 返回类型字节)。"""
    if blobidx is None:
        return (0, None)
    b = md.blob(blobidx)
    if len(b) < 2:
        return (0, None)
    pc, o = _compressed(b, 1)
    ret = b[o] if o < len(b) else None
    return (pc, ret)


def analyze(path):
    """解析程序集并返回混淆分析报告 dict。"""
    pe, md = dnlib.load(path)
    methods = md.methods()
    tds = md.typedefs()
    fds = md.fields()

    bodies = {}
    for i, m in enumerate(methods):
        b = md.method_body(m["rva"])
        if b and b[1] > 0:
            bodies[i] = (m, b[3])

    report = {
        "file": path, "is_dotnet": True,
        "clr": "v%d.%d" % (md.clr["major"], md.clr["minor"]),
        "counts": {"typedef": len(tds), "methoddef": len(methods), "field": len(fds)},
        "string_decryptors": [], "proxy_methods": [], "flattened": [],
        "renamed": {"types": 0, "methods": 0, "fields": 0, "examples": []},
        "pinvoke": 0,
    }

    # ---- 重命名统计（严格）----
    for td in tds:
        if _is_weird_name(td["name"]):
            report["renamed"]["types"] += 1
            if len(report["renamed"]["examples"]) < 5:
                report["renamed"]["examples"].append("type:" + td["name"][:24])
    for m in methods:
        if _is_weird_name(m["name"]):
            report["renamed"]["methods"] += 1
            if len(report["renamed"]["examples"]) < 8:
                report["renamed"]["examples"].append("method:" + m["name"][:24])
        if m["impl"] & 0x1000:
            report["pinvoke"] += 1
    for f in fds:
        if _is_weird_name(f["name"]):
            report["renamed"]["fields"] += 1

    # ---- 候选字符串解密器：返回 string(0x0E) 且带 >=1 参数 ----
    decrypt_candidates = set()
    for m in methods:
        pc, ret = _sig_paramcount_ret(md, m["sig"])
        if ret == 0x0E and pc >= 1:
            decrypt_candidates.add(m["name"])

    # ---- 逐方法 IL 模式识别 ----
    call_evidence = {}   # name -> set(常量调用点偏移)
    for i, (m, code) in bodies.items():
        ins = dnlib.read_il(code)
        # 代理方法：ldarg.0 ; call/callvirt ; ret
        if (len(ins) == 3 and ins[0][1] == "ldarg.0"
                and ins[1][1] in ("call", "callvirt") and ins[2][1] == "ret"):
            report["proxy_methods"].append(m["name"])
        # 控制流平坦化
        for x in ins:
            if x[1] == "switch":
                tgt = x[2].strip("()").split(", ")
                has_back = any(y[1] in ("br", "br.s") and y[2].startswith("IL_")
                               and int(y[2][3:], 16) < y[0] for y in ins)
                if len(tgt) >= 5 and has_back and m["name"] not in report["flattened"]:
                    report["flattened"].append(m["name"])
                break
        # 字符串解密调用证据：call 候选方法且前一指令为 ldc.i4（常量 id）
        prev = None
        for off, mn, op in ins:
            if mn in ("call", "callvirt") and op.startswith("0x"):
                kind, nm = md.token_info(int(op, 16))
                if kind in ("method", "memberref") and nm in decrypt_candidates and prev == "ldc.i4":
                    call_evidence.setdefault(nm, set()).add(off)
            prev = mn

    for nm, ev in call_evidence.items():
        if len(ev) >= 2:
            report["string_decryptors"].append({"name": nm, "calls": len(ev)})

    # ---- 汇总判定（代理同类型转发属正常重构，不计分；只作为情报上报）----
    score = (len(report["string_decryptors"]) * 5 +
             len(report["flattened"]) * 3 +
             (3 if report["renamed"]["methods"] > 20 else
              (1 if report["renamed"]["methods"] > 5 else 0)) +
             (1 if report["pinvoke"] else 0))
    report["obfuscated"] = score >= 5
    report["score"] = score
    return report


def format_report(rep):
    L = []
    L.append("File: %s  (CLR %s)" % (rep["file"], rep["clr"]))
    c = rep["counts"]
    L.append("  TypeDef=%d MethodDef=%d Field=%d  PInvoke=%d" %
             (c["typedef"], c["methoddef"], c["field"], rep["pinvoke"]))
    L.append("  Obfuscated: %s (score=%d)" % ("YES" if rep["obfuscated"] else "no", rep["score"]))
    if rep["string_decryptors"]:
        L.append("  String decryptors:")
        for d in rep["string_decryptors"][:8]:
            L.append("    - %s (const-int calls: %d)" % (d["name"], d["calls"]))
    if rep["proxy_methods"]:
        L.append("  Proxy/forwarder methods: %d  e.g. %s" %
                 (len(rep["proxy_methods"]), ", ".join(rep["proxy_methods"][:5])))
    if rep["flattened"]:
        L.append("  Control-flow flattened: %d  e.g. %s" %
                 (len(rep["flattened"]), ", ".join(rep["flattened"][:5])))
    r = rep["renamed"]
    if r["types"] or r["methods"] or r["fields"]:
        L.append("  Renamed identifiers: types=%d methods=%d fields=%d  e.g. %s" %
                 (r["types"], r["methods"], r["fields"], ", ".join(r["examples"][:4])))
    return "\n".join(L)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python deobfuscate_core.py <assembly>")
        sys.exit(2)
    print(format_report(analyze(sys.argv[1])))