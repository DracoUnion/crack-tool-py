#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
The Enigma Protector v6.80 x64 (The Enigma Protector, Inno Setup 安装包) -> Python CLI

来源目录: D:\\Program Files\\crack-tool-packer\\TheEnigmaProtector_6.80_x64
真实主程序: "The Enigma Protector v6.80 x64.exe" 是 Inno Setup 5.5.0 安装包
            (含 "Inno Setup" 串 + rDlPtS 加载器偏移表魔数), 真正的 Enigma 打包器 EXE
            在安装包内 (需 innoextract 取出)。同目录 license5_x64.dat 为 base64 许可。

逆向依据 (PE 结构 + Inno 特征 + base64 许可解码):
  - Inno 安装包: "Inno Setup" 标识 + rDlPtS 魔数 + CODE/DATA/BSS/.idata/.tls/.rdata/
    .reloc/.rsrc 节 (Inno 典型布局)。
  - license5_x64.dat: base64 文本, 解码后含 "LCX tab (<email>)" + 授权密钥 +
    "-----BEGIN CERTIFICATE-----" X.509 证书链 (TAGGANT ROOT CA)。
  - Enigma 保护后: 追加 .enigma 节 (VM/反调试), 入口改到 .enigma; 水印 "The Enigma Protector"。

  本 Python 实现为 Enigma 安装包识别 / Inno 结构解析 / base64 许可解析工具 (纯标准库):
    - identify: 识别 Inno 安装包 + 版本 + Enigma 水印;
    - inno    : 解析 Inno 结构 (版本/rDlPtS/节表);
    - license : base64 解码 license5_x64.dat, 提取用户/密钥/证书;
    - analyze : 通用 PE 节/熵分析 (对取出的 Enigma 主程序或已加壳目标)。
  说明: Enigma 的 VM/反调试引擎为机器码, 本工具不重写保护算法; 真实打包器 EXE 在
  Inno 安装包内, 需用 innoextract 取出后再用 analyze/identify 分析。
  main.py 为唯一入口。

用法:
  python main.py identify <PE> [--json]
  python main.py inno     <Inno安装包> [--json]
  python main.py license  <license5_x64.dat> [--json]
  python main.py analyze  <PE> [--json]
"""
import argparse
import base64
import json
import math
import os
import re
import struct
import sys
from collections import Counter
from dataclasses import dataclass, field
from typing import List, Optional

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
ENIGMA_WATERMARKS = (b"The Enigma Protector", b".enigma", b"Enigma Protector")
INNO_MAGIC = b"rDlPtS"


def ent(b):
    if not b: return 0.0
    c = Counter(b); n = len(b)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


@dataclass
class Section:
    name: str; virtual_size: int; virtual_address: int
    raw_size: int; raw_address: int; characteristics: int; entropy: float = 0.0


@dataclass
class PeFile:
    path: str; data: bytes; image_base: int = 0; entry_rva: int = 0
    size_of_image: int = 0; is64: bool = False; subsystem: int = 0
    sections: List[Section] = field(default_factory=list)
    is_pe: bool = True; error: Optional[str] = None


def parse_pe(data, path):
    pe = PeFile(path, data)
    if len(data) < 0x40 or data[:2] != b"MZ":
        pe.is_pe = False; pe.error = "not MZ"; return pe
    e = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e:e + 4] != b"PE\0\0":
        pe.is_pe = False; pe.error = "no PE sig"; return pe
    fh = e + 4; nsec = struct.unpack_from("<H", data, fh + 2)[0]
    szopt = struct.unpack_from("<H", data, fh + 16)[0]; opt = fh + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x10B:
        pe.entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        pe.image_base = struct.unpack_from("<I", data, opt + 28)[0]
        pe.size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
        pe.subsystem = struct.unpack_from("<H", data, opt + 68)[0]
    elif magic == 0x20B:
        pe.is64 = True
        pe.entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        pe.image_base = struct.unpack_from("<Q", data, opt + 24)[0]
        pe.size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
        pe.subsystem = struct.unpack_from("<H", data, opt + 68)[0]
    else:
        pe.is_pe = False; pe.error = "bad opt magic"; return pe
    st = opt + szopt
    for i in range(nsec):
        o = st + i * 40
        nm = data[o:o + 8].split(b"\0", 1)[0].decode("ascii", "replace")
        vs, va, rs, ra = struct.unpack_from("<IIII", data, o + 8)
        ch = struct.unpack_from("<I", data, o + 36)[0]
        pe.sections.append(Section(nm, vs, va, rs, ra, ch, ent(data[ra:ra + rs]) if rs else 0.0))
    return pe


def watermark(data):
    for w in ENIGMA_WATERMARKS:
        if w in data:
            return w.decode()
    return None


def is_inno(data):
    return (b"Inno Setup" in data) or (INNO_MAGIC in data)


def inno_version(data):
    m = re.search(rb"Inno Setup[^\x00]{0,40}", data)
    # 常见版本串 "Inno Setup Setup Data (5.5.0)"
    m2 = re.search(rb"Inno Setup Setup Data \(([0-9.]+)\)", data)
    if m2:
        return m2.group(1).decode()
    return m.group(0).decode("latin1", "replace") if m else None


def sec_of_rva(pe, rva):
    for s in pe.sections:
        if s.virtual_address <= rva < s.virtual_address + max(s.virtual_size, s.raw_size):
            return s
    return None


def identify(pe):
    if not pe.is_pe:
        return {"file": pe.path, "is_pe": False, "error": pe.error}
    wm = watermark(pe.data)
    inno = is_inno(pe.data)
    ep_sec = sec_of_rva(pe, pe.entry_rva)
    return {"file": pe.path, "is_pe": True, "is64": pe.is64,
            "is_inno_installer": inno, "inno_version": inno_version(pe.data) if inno else None,
            "enigma_watermark": wm,
            "enigma_detected": bool(wm) or inno,
            "entry_section": ep_sec.name if ep_sec else None,
            "num_sections": len(pe.sections), "sections": [s.name for s in pe.sections],
            "note": ("Inno 安装包: 真正的 Enigma 打包器 EXE 在包内, 需 innoextract 取出"
                     if inno else "已加壳/已脱壳的 PE")}


def inno_report(pe):
    return {"file": pe.path, "is_inno": is_inno(pe.data),
            "version": inno_version(pe.data),
            "has_rDlPtS": INNO_MAGIC in pe.data,
            "sections": [{"name": s.name, "va": hex(s.virtual_address),
                          "rawsize": hex(s.raw_size), "vsize": hex(s.virtual_size)} for s in pe.sections],
            "note": "Inno 安装包; 用 innoextract 或 /VERYSILENT 安装取出内部 Enigma 主程序。"}


def parse_license(path):
    b = open(path, "rb").read()
    try:
        raw = base64.b64decode(b + b"===")
    except Exception as e:
        return {"file": path, "error": "base64 decode failed: %s" % e}
    text = raw.decode("latin1", "replace")
    user = re.search(r"LCX tab \(([^)]+)\)", text)
    key = re.search(r"LCX tab \([^)]+\)\s*\n\s*([A-Z0-9]{20,})", text)
    cert = "-----BEGIN CERTIFICATE-----" in text
    cn = re.search(r"CN=([^\r\n]+)", text)
    return {"file": path, "encoded_size": len(b), "decoded_size": len(raw),
            "entropy": round(ent(raw), 3),
            "user": user.group(1) if user else None,
            "license_key": key.group(1)[:64] if key else None,
            "has_certificate": cert,
            "cert_subject_cn": cn.group(1) if cn else None,
            "note": "license5_x64.dat = base64(用户 + 授权密钥 + X.509 证书链)"}


def analyze(pe):
    ep_sec = sec_of_rva(pe, pe.entry_rva)
    return {"file": pe.path, "is64": pe.is64, "subsystem": pe.subsystem,
            "image_base": hex(pe.image_base), "entry_rva": hex(pe.entry_rva),
            "sections": [{"name": s.name or "(unnamed)", "va": hex(s.virtual_address),
                          "vsize": hex(s.virtual_size), "rawsize": hex(s.raw_size),
                          "entropy": round(s.entropy, 3), "is_entry": (ep_sec is s)} for s in pe.sections]}


def load(a):
    return parse_pe(open(a.input, "rb").read(), a.input)


def cmd_identify(a):
    r = identify(load(a))
    print(json.dumps(r, indent=2) if a.json else
          f"{a.input}: inno={r.get('is_inno_installer')} enigma={r.get('enigma_detected')} "
          f"ver={r.get('inno_version')} watermark={r.get('enigma_watermark')}")
    return EXIT_SUCCESS


def cmd_inno(a):
    r = inno_report(load(a))
    print(json.dumps(r, indent=2) if a.json else
          f"{a.input}: Inno={r['is_inno']} version={r['version']} rDlPtS={r['has_rDlPtS']}")
    return EXIT_SUCCESS


def cmd_license(a):
    print(json.dumps(parse_license(a.input), indent=2) if a.json else
          f"{a.input}: base64 license")
    return EXIT_SUCCESS


def cmd_analyze(a):
    pe = load(a)
    if not pe.is_pe: print("error:", pe.error, file=sys.stderr); return EXIT_FAILURE
    print(json.dumps(analyze(pe), indent=2) if a.json else
          f"{a.input}: {len(pe.sections)} sections, EP {hex(pe.entry_rva)}")
    return EXIT_SUCCESS


def build_parser():
    p = argparse.ArgumentParser(prog="enigma", description="The Enigma Protector 6.80 analyzer - Python CLI")
    sub = p.add_subparsers(dest="cmd", required=True)
    for name, fn in [("identify", cmd_identify), ("inno", cmd_inno),
                     ("analyze", cmd_analyze), ("license", cmd_license)]:
        sp = sub.add_parser(name); sp.add_argument("input"); sp.add_argument("--json", action="store_true")
        sp.set_defaults(func=fn)
    return p


def main(argv=None):
    a = build_parser().parse_args(argv)
    try: return a.func(a)
    except FileNotFoundError as e: print("error:", e, file=sys.stderr); return EXIT_FAILURE


if __name__ == "__main__":
    sys.exit(main())