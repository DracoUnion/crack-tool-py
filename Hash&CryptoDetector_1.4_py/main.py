#!/usr/bin/env python3
"""
Hash & Crypto Detector 1.4 — Python CLI rewrite

原程序：Hash&CryptoDetector_1.4/Hash & Crypto Detector v1.4/HCD.exe
(Mr. Paradox, AT4RE, 2009)

PE 文件签名扫描器：检测嵌入的哈希/加密算法特征、编译器及壳/保护标识。
纯 Python 标准库实现（struct），无第三方依赖。

注意：原 HCD.exe 被 PECompact2 壳保护，其内置签名库无法直接提取；
本 CLI 按 HCD 功能描述重写，内置一套常见的编译器/壳/保护/加密特征字节串。
"""

import argparse
import json
import os
import re
import struct
import sys

# ---------------------------------------------------------------------------
# PE 最小解析器（标准库）
# ---------------------------------------------------------------------------
class PE:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()
        self.size = len(self.data)
        self.parse()

    def parse(self):
        d = self.data
        if self.size < 64 or d[0:2] != b"MZ":
            raise ValueError("not a PE file (missing MZ signature)")
        self.e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
        if self.e_lfanew + 24 > self.size or d[self.e_lfanew:self.e_lfanew + 4] != b"PE\x00\x00":
            raise ValueError("not a PE file (missing PE signature)")
        coff = self.e_lfanew + 4
        self.machine = struct.unpack_from("<H", d, coff)[0]
        self.number_of_sections = struct.unpack_from("<H", d, coff + 2)[0]
        self.time_date_stamp = struct.unpack_from("<I", d, coff + 8)[0]
        self.size_of_optional_header = struct.unpack_from("<H", d, coff + 16)[0]
        self.characteristics = struct.unpack_from("<H", d, coff + 18)[0]
        opt = coff + 20
        self.opt_magic = struct.unpack_from("<H", d, opt)[0]  # 0x10b PE32, 0x20b PE32+
        self.address_of_entry_point = struct.unpack_from("<I", d, opt + 16)[0]
        self.image_base = struct.unpack_from("<I", d, opt + 28)[0]
        # section table starts after optional header
        sec_start = opt + self.size_of_optional_header
        self.sections = []
        for i in range(self.number_of_sections):
            s = sec_start + i * 40
            name = d[s:s + 8].rstrip(b"\x00").decode("latin-1")
            vsize = struct.unpack_from("<I", d, s + 8)[0]
            vaddr = struct.unpack_from("<I", d, s + 12)[0]
            rawsize = struct.unpack_from("<I", d, s + 16)[0]
            rawptr = struct.unpack_from("<I", d, s + 20)[0]
            self.sections.append({
                "name": name,
                "virtual_size": vsize,
                "virtual_address": vaddr,
                "raw_size": rawsize,
                "raw_ptr": rawptr,
            })

    def section_containing(self, rva):
        for sec in self.sections:
            if sec["virtual_address"] <= rva < sec["virtual_address"] + max(sec["virtual_size"], sec["raw_size"]):
                return sec
        return None

    def rva_to_offset(self, rva):
        sec = self.section_containing(rva)
        if sec is None:
            return None
        return sec["raw_ptr"] + (rva - sec["virtual_address"])

    def get_bytes(self, offset, length):
        if offset < 0 or offset + length > self.size:
            return None
        return self.data[offset:offset + length]

    def all_bytes(self):
        return self.data

    def va_of_offset(self, offset):
        """粗略：找 offset 属于哪个节的 VA（仅用于展示）。"""
        for sec in self.sections:
            if sec["raw_ptr"] <= offset < sec["raw_ptr"] + sec["raw_size"]:
                return sec["virtual_address"] + (offset - sec["raw_ptr"])
        return None


# ---------------------------------------------------------------------------
# 特征签名库（按 HCD 功能描述整理的常见特征）
# ---------------------------------------------------------------------------
MACHINE_MAP = {
    0x014c: "x86 (i386)",
    0x014d: "Windows CE",
    0x0162: "MIPS R3000",
    0x0166: "MIPS LE",
    0x0168: "MIPS16",
    0x0169: "MIPS FPU",
    0x0184: "Alpha AXP",
    0x01a2: "Hitachi SH3",
    0x01a3: "Hitachi SH3 DSP",
    0x01a6: "Hitachi SH4",
    0x01a8: "Hitachi SH5",
    0x01c2: "ARM little endian",
    0x01c4: "ARM Thumb/Thumb-2",
    0x01c5: "ARM FPU",
    0x01f0: "PowerPC LE",
    0x0200: "IA64",
    0x0266: "MIPS FPU16",
    0x0284: "Alpha 64",
    0x0366: "M32R LE",
    0x0466: "ARM64 LE",
    0x0520: "RISC-V 64 LE",
    0x8664: "x64 (AMD64)",
}

COMPILER_SIGS = [
    (re.compile(rb"Borland|Delphi|Turbo|CodeGear", re.I), "Borland Delphi / C++Builder"),
    (re.compile(rb"MSVBVM|Visual Basic|VB5|VB6|vba", re.I), "Visual Basic"),
    (re.compile(rb"Microsoft Visual C\+\+|MSVC|msvcrt|MSVCP", re.I), "Microsoft Visual C++"),
    (re.compile(rb"GCC|MinGW|mingw|gcc_", re.I), "GCC / MinGW"),
    (re.compile(rb"AutoIt3|AutoIt", re.I), "AutoIt"),
    (re.compile(rb"NSIS", re.I), "NSIS Installer"),
    (re.compile(rb"Inno Setup|innosetup", re.I), "Inno Setup Installer"),
    (re.compile(rb"InstallShield", re.I), "InstallShield"),
    (re.compile(rb"Python|python", re.I), "Python (PyInstaller/py2exe)"),
    (re.compile(rb"Mono|mono", re.I), ".NET / Mono"),
    (re.compile(rb"PureBasic", re.I), "PureBasic"),
    (re.compile(rb"PowerBuilder", re.I), "PowerBuilder"),
]

PACKER_PROTECTOR_SIGS = [
    (re.compile(rb"UPX", re.I), "UPX packer"),
    (re.compile(rb"PECompact", re.I), "PECompact packer"),
    (re.compile(rb"ASPack|aspack", re.I), "ASPack packer"),
    (re.compile(rb"Themida|themida", re.I), "Themida protector"),
    (re.compile(rb"VMProtect|vmprotect", re.I), "VMProtect protector"),
    (re.compile(rb"Armadillo|armadillo", re.I), "Armadillo protector"),
    (re.compile(rb"Obsidium|obsidium", re.I), "Obsidium protector"),
    (re.compile(rb"Enigma|enigma", re.I), "Enigma Protector"),
    (re.compile(rb"ASProtect|asprotect", re.I), "ASProtect protector"),
    (re.compile(rb"PELock|pelock", re.I), "PELock protector"),
    (re.compile(rb"PE-Pack|pepack", re.I), "PE-Pack packer"),
    (re.compile(rb"PEPayload|PEiD|peid", re.I), "PEiD scanner marker"),
    (re.compile(rb"NSPack|nspack", re.I), "NSPack packer"),
    (re.compile(rb"PEBundle|pebundle", re.I), "PEBundle"),
    (re.compile(rb"ShrinkIt|shrinkit", re.I), "ShrinkIt"),
]

# 加密 / 哈希算法特征字节（片段，用于启发式定位）
CRYPTO_SIGS = [
    (b"\x67\x45\x23\x01\xef\xcd\xab\x89\x98\xba\xdc\xfe\x10\x32\x54\x76", "MD5 / SHA1 init constants"),
    (b"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5\x30\x01\x67\x2b", "AES S-box prefix"),
    (b"\x01\x23\x45\x67\x89\xab\xcd\xef", "MD5 init little-endian dwords"),
]


def extract_strings(data, min_len=4):
    """提取 ASCII 可打印字符串。"""
    strings = []
    for m in re.finditer(rb"[\x20-\x7E]{%d,}" % min_len, data):
        strings.append((m.start(), m.group().decode("ascii")))
    return strings


def scan_pe(pe, deep=False):
    results = {
        "file": os.path.basename(pe.path),
        "size": pe.size,
        "machine": MACHINE_MAP.get(pe.machine, "unknown (0x%04x)" % pe.machine),
        "entry": "0x%08X" % pe.address_of_entry_point,
        "image_base": "0x%08X" % pe.image_base,
        "sections": [s["name"] for s in pe.sections],
        "detections": [],
    }
    data = pe.all_bytes()

    # 编译器
    for pat, name in COMPILER_SIGS:
        if pat.search(data):
            results["detections"].append({"type": "compiler", "name": name})

    # 壳 / 保护
    for pat, name in PACKER_PROTECTOR_SIGS:
        if pat.search(data):
            results["detections"].append({"type": "packer/protector", "name": name})

    # 字符串中也再匹配一遍编译器/壳（覆盖分段存储的情况）
    for off, s in extract_strings(data):
        for pat, name in COMPILER_SIGS + PACKER_PROTECTOR_SIGS:
            if pat.search(s.encode("ascii")):
                entry = {"type": "string", "name": name, "string": s}
                # 去重
                if entry not in results["detections"]:
                    results["detections"].append(entry)

    # 加密/哈希特征字节
    if deep:
        for sig, name in CRYPTO_SIGS:
            idx = data.find(sig)
            if idx != -1:
                va = pe.va_of_offset(idx)
                results["detections"].append({
                    "type": "crypto",
                    "name": name,
                    "offset": idx,
                    "va": ("0x%08X" % va) if va is not None else None,
                    "signature": sig.hex().upper(),
                })

    return results


def fmt_results(results, deep=False):
    lines = []
    lines.append("File     : %s" % results["file"])
    lines.append("Size     : %d bytes" % results["size"])
    lines.append("Machine  : %s" % results["machine"])
    lines.append("Entry    : %s" % results["entry"])
    lines.append("ImageBase: %s" % results["image_base"])
    lines.append("Sections : %s" % ", ".join(results["sections"]))
    lines.append("")
    dets = results["detections"]
    if not dets:
        lines.append("No hash/crypto/compiler/packer signatures detected.")
    else:
        # 分类显示
        by_type = {}
        for d in dets:
            by_type.setdefault(d["type"], []).append(d)
        for t in ("compiler", "packer/protector", "crypto", "string"):
            if t not in by_type:
                continue
            label = {"compiler": "[Compiler]",
                     "packer/protector": "[Packer/Protector]",
                     "crypto": "[Crypto]",
                     "string": "[String]"}[t]
            for d in by_type[t]:
                if t == "crypto":
                    lines.append("%s %s (sig %s, offset %s, VA %s)" % (
                        label, d["name"], d["signature"],
                        d.get("offset"), d.get("va")))
                elif t == "string":
                    lines.append("%s %s  (string: %s)" % (label, d["name"], d["string"]))
                else:
                    lines.append("%s %s" % (label, d["name"]))
    return "\n".join(lines)


def cmd_scan(args):
    path = args.file
    if not os.path.isfile(path):
        print("Error: file not found: %s" % path, file=sys.stderr)
        return 1
    try:
        pe = PE(path)
    except ValueError as e:
        print("Error: %s" % e, file=sys.stderr)
        return 1
    results = scan_pe(pe, deep=args.deep)
    if args.json:
        print(json.dumps(results, ensure_ascii=False, indent=2))
    else:
        print(fmt_results(results, deep=args.deep))
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="main.py",
        description="Hash & Crypto Detector 1.4 — Python CLI PE 签名扫描器（标准库实现）。",
    )
    p.add_argument("file", help="要扫描的 PE 文件路径")
    p.add_argument("--deep", action="store_true",
                   help="深度扫描：定位加密特征字节偏移与 VA")
    p.add_argument("--json", action="store_true", help="以 JSON 输出")
    p.set_defaults(func=cmd_scan)
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
