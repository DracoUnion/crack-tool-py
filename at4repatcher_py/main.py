#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
at4repatcher_py / main.py  --  single-entry, stdlib-only Python CLI
====================================================================

Static-only re-implementation of the core patch engine of
AT4RE Patcher v0.7.6 (coded by Agmcz & Sn!per X, 2014-2018).

Reverse-engineering basis
-------------------------
The original tool ("AT4RE Patcher.exe") is a Delphi GUI application. This
CLI was written against the behaviour documented in the shipped
"Main Features.txt" / "Release Info.txt" and against the UNPACKED original:

    /d/temp/ida_out/at4re_upx.exe   (UPX-unpacked at OEP, ~6.8 MB, Delphi PE32)

Unpacked image facts (static analysis, no debugger used):
  - PE32, optional-header magic 0x10B, Machine 0x14C (IMAGE_FILE_MACHINE_I386)
  - ImageBase 0x00400000, SectionAlignment 0x1000, FileAlignment 0x200
  - Sections: CODE, DATA, BSS, .idata, .tls, .rdata, .reloc, .rsrc
  - Imported DLLs: KERNEL32, advapi32, comctl32, comdlg32, gdi32, gdiplus,
    ole32, oleaut32, shell32, user32, version, winmm   (classic Delphi GUI app)
  - Feature strings found in the image include: "File Offset", "Hosts Patch",
    "Serial Sniffer", "Registry Patch", "Placeholders", "Loader", ...
  - The packed original (t01.exe.asm) shows only the UPX stub (UPX0/UPX1
    segments, no import list), so all analysis is anchored on the unpacked
    binary released after unpacking.

Main Features -> subcommands (coverage map)
-------------------------------------------
apply  : Multi-file patcher; patch modes File Offset / Virtual Address (VA)
         / Relative Virtual Address (RVA); Search & Replace; file Size /
         CRC32 / MD5 check; registry patch entries (recorded only); output
         written with the original file date/time preserved.
info   : PE32 / PE32+ header, section table, VA / RVA / file-offset map,
         entry point, CRC32 / MD5 / size.
sniff  : Serial sniffer heuristic - scans a file for serial-like strings and
         structures (best-effort, heuristic only).
verify : File checks only (Size / CRC32 / MD5) against a project file.

Static-only scope (intentionally NOT implemented here)
-----------------------------------------------------
GUI, skins, music, hosts-file patcher, attach-file installer, loader
generation, patching a running process or loaded DLL, real Windows registry
writes, UPX / external packer commands, NFO gating, target auto-detection
from path/registry, Windows version check.  This tool never writes to the
real registry and never touches a live process; it is a static file rewriter.

Project JSON schema (used by apply / verify)
--------------------------------------------
{
  "metadata": {"name": "...", "version": 9, "author": "...", "info": "..."},
  "filecheck": {"size": 123456, "crc32": "DEADBEEF", "md5": "0123..."},
  "entries": [
    {"mode": "offset", "addr": 1234, "bytes": "DEADBEEF"},
    {"mode": "va",     "addr": 4198450, "bytes": "90 90"},
    {"mode": "rva",    "addr": 4660, "bytes": "CC"},
    {"mode": "searchreplace", "search": "DE AD ?? BE", "replace": "90 90 90 90",
     "count": -1, "comment": "nop out check"}
  ],
  "registry": [
    {"root": "HKLM", "path": "Software\\X", "name": "Serial",
     "type": "REG_SZ", "data": "AAAA-BBBB", "bitness": 32, "placeholder": false}
  ],
  "output": "patched.exe"
}
- addr accepts int or string ("0x1000" / "4096").
- bytes / search / replace are hex strings; spaces optional; search may use
  "??" / "?" / "*" as a wildcard byte.
- count: -1 = all occurrences, N = first N.
- registry entries are recorded in the report (placeholders resolved with
  metadata when present); they are NOT written to the live registry.

Only main.py is the program entry point. No third-party packages, no network,
no git, no debugger.
"""

import argparse
import hashlib
import json
import os
import re
import struct
import sys
import zlib


# --------------------------------------------------------------------------- #
# Errors
# --------------------------------------------------------------------------- #
class PEError(Exception):
    """Raised when a file is not a parseable PE32 / PE32+ image."""


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def parse_int(value):
    """Accept int, or a string like '0x1000' / '4096' / '1_000'."""
    if isinstance(value, bool):
        raise ValueError("boolean is not a valid integer")
    if isinstance(value, int):
        return value
    s = str(value).strip()
    if not s:
        raise ValueError("empty integer")
    return int(s, 0)


def parse_hex_bytes(text, what="bytes"):
    """Parse a hex string ('DEADBEEF', 'DE AD BE EF') into bytes."""
    s = str(text).strip()
    for ch in (" ", "-", ":", "\t", "\n", "\r"):
        s = s.replace(ch, "")
    if not s:
        return b""
    if len(s) % 2 != 0:
        raise ValueError("%s: odd number of hex digits (%d)" % (what, len(s)))
    try:
        return bytes.fromhex(s)
    except ValueError as exc:
        raise ValueError("%s: invalid hex string: %s" % (what, exc))


def parse_pattern(text):
    """Parse a search pattern into a list of ints or None (wildcard byte).

    Tokens are whitespace/hyphen separated hex byte pairs; '??', '?' or '*'
    is a single wildcard byte.
    """
    s = str(text).replace("-", " ").replace(",", " ")
    toks = s.split()
    if not toks:
        raise ValueError("empty search pattern")
    pat = []
    for t in toks:
        if t in ("??", "?", "*"):
            pat.append(None)
        else:
            if len(t) != 2:
                raise ValueError("pattern token %r is not a byte / wildcard" % t)
            pat.append(int(t, 16))
    return pat


def pattern_len(pat):
    return len(pat)


def find_pattern(data, pat, start=0):
    """Yield offsets where `pat` (list of int|None) matches `data`."""
    n = len(pat)
    if n == 0 or n > len(data):
        return
    first = pat[0]
    i = start
    end = len(data) - n
    while i <= end:
        if first is None or data[i] == first:
            ok = True
            for j in range(1, n):
                b = pat[j]
                if b is not None and data[i + j] != b:
                    ok = False
                    break
            if ok:
                yield i
        i += 1


def fmt_hex(value, width=0):
    if width:
        return "0x%%0%dX" % width % value
    return "0x%X" % value


# --------------------------------------------------------------------------- #
# PE parser (PE32 + PE32+)
# --------------------------------------------------------------------------- #
class PEImage(object):
    """Minimal, dependency-free PE32 / PE32+ reader.

    Only what a patcher needs: headers, sections and address conversion
    between file offset, RVA and VA.
    """

    MACHINE_NAMES = {
        0x014C: "IMAGE_FILE_MACHINE_I386",
        0x8664: "IMAGE_FILE_MACHINE_AMD64",
        0x01C4: "IMAGE_FILE_MACHINE_ARMNT",
        0xAA64: "IMAGE_FILE_MACHINE_ARM64",
        0x0200: "IMAGE_FILE_MACHINE_IA64",
    }

    DIR_NAMES = [
        "EXPORT", "IMPORT", "RESOURCE", "EXCEPTION", "SECURITY", "BASERELOC",
        "DEBUG", "ARCHITECTURE", "GLOBALPTR", "TLS", "LOAD_CONFIG",
        "BOUND_IMPORT", "IAT", "DELAY_IMPORT", "COM_DESCRIPTOR", "RESERVED",
    ]

    def __init__(self, path):
        self.path = path
        with open(path, "rb") as fh:
            self.data = fh.read()
        if len(self.data) < 0x40:
            raise PEError("%s: file too small to be a PE image" % path)
        if self.data[0:2] != b"MZ":
            raise PEError("%s: missing MZ signature" % path)

        e_lfanew = struct.unpack_from("<I", self.data, 0x3C)[0]
        if e_lfanew + 24 > len(self.data):
            raise PEError("%s: e_lfanew out of range" % path)
        if self.data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            raise PEError("%s: missing PE\\0\\0 signature" % path)

        coff = e_lfanew + 4
        (self.machine, self.num_sections, self.timestamp,
         self.ptr_symtab, self.num_symbols, self.opt_size,
         self.characteristics) = struct.unpack_from("<HHIIIHH", self.data, coff)

        opt = coff + 20
        if opt + 2 > len(self.data):
            raise PEError("%s: optional header truncated" % path)
        magic = struct.unpack_from("<H", self.data, opt)[0]
        self.is_pe32plus = (magic == 0x20B)
        if magic == 0x10B:
            self.pe_type = "PE32"
        elif magic == 0x20B:
            self.pe_type = "PE32+"
        else:
            raise PEError("%s: unknown optional-header magic 0x%X" % (path, magic))

        if self.is_pe32plus:
            # PE32+ optional header layout
            self.image_base = struct.unpack_from("<Q", self.data, opt + 24)[0]
            self.section_align = struct.unpack_from("<I", self.data, opt + 32)[0]
            self.file_align = struct.unpack_from("<I", self.data, opt + 36)[0]
            self.size_of_image = struct.unpack_from("<I", self.data, opt + 56)[0]
            self.size_of_headers = struct.unpack_from("<I", self.data, opt + 60)[0]
            self.entry_rva = struct.unpack_from("<I", self.data, opt + 16)[0]
            ndir_off = opt + 108
            dir_off = opt + 112
        else:
            # PE32 optional header layout
            self.image_base = struct.unpack_from("<I", self.data, opt + 28)[0]
            self.section_align = struct.unpack_from("<I", self.data, opt + 32)[0]
            self.file_align = struct.unpack_from("<I", self.data, opt + 36)[0]
            self.size_of_image = struct.unpack_from("<I", self.data, opt + 56)[0]
            self.size_of_headers = struct.unpack_from("<I", self.data, opt + 60)[0]
            self.entry_rva = struct.unpack_from("<I", self.data, opt + 16)[0]
            ndir_off = opt + 92
            dir_off = opt + 96

        self.num_dirs = struct.unpack_from("<I", self.data, ndir_off)[0]
        self.data_dirs = []
        for i in range(self.num_dirs):
            rva, size = struct.unpack_from("<II", self.data, dir_off + 8 * i)
            self.data_dirs.append((rva, size))

        self.sections = []
        sec = opt + self.opt_size
        for i in range(self.num_sections):
            base = sec + 40 * i
            if base + 40 > len(self.data):
                raise PEError("%s: section table truncated" % path)
            raw_name = self.data[base:base + 8]
            name = raw_name.rstrip(b"\x00").decode("latin-1", "replace")
            (virtual_size, virtual_address, size_raw, ptr_raw,
             ptr_reloc, ptr_linenum, num_reloc, num_linenum,
             chars) = struct.unpack_from("<IIIIIIHHI", self.data, base + 8)
            self.sections.append({
                "name": name,
                "virtual_size": virtual_size,
                "virtual_address": virtual_address,
                "size_raw": size_raw,
                "ptr_raw": ptr_raw,
                "characteristics": chars,
            })

    # -- address conversion ------------------------------------------------- #
    def _section_for_rva(self, rva):
        for sec in self.sections:
            span = max(sec["virtual_size"], sec["size_raw"])
            if sec["virtual_address"] <= rva < sec["virtual_address"] + span:
                return sec
        # Headers live before the first section.
        if rva < self.size_of_headers:
            return None
        return None

    def rva_to_offset(self, rva):
        """Convert an RVA to a file offset. None if not file-backed."""
        if rva < self.size_of_headers:
            return rva  # headers are mapped 1:1 at the start of the file
        sec = self._section_for_rva(rva)
        if sec is None:
            return None
        delta = rva - sec["virtual_address"]
        if delta >= sec["size_raw"]:
            return None  # zero-initialised tail (e.g. .bss) has no file data
        off = sec["ptr_raw"] + delta
        if off >= len(self.data):
            return None
        return off

    def va_to_offset(self, va):
        """Convert an absolute VA (image base included) to a file offset."""
        return self.rva_to_offset(va - self.image_base)

    def offset_to_rva(self, offset):
        for sec in self.sections:
            if sec["size_raw"] and sec["ptr_raw"] <= offset < sec["ptr_raw"] + sec["size_raw"]:
                return sec["virtual_address"] + (offset - sec["ptr_raw"])
        if offset < self.size_of_headers:
            return offset
        return None

    def describe(self):
        lines = []
        lines.append("File            : %s" % self.path)
        lines.append("Size            : %d bytes (0x%X)" % (len(self.data), len(self.data)))
        lines.append("CRC32           : %08X" % (zlib.crc32(self.data) & 0xFFFFFFFF))
        lines.append("MD5             : %s" % hashlib.md5(self.data).hexdigest().upper())
        lines.append("PE type         : %s" % self.pe_type)
        lines.append("Machine         : %s (0x%04X)" % (
            self.MACHINE_NAMES.get(self.machine, "UNKNOWN"), self.machine))
        try:
            ts = self.timestamp
            lines.append("TimeDateStamp   : %d (%s UTC)" % (
                ts, _fmt_time(ts)))
        except Exception:
            pass
        lines.append("ImageBase       : %s" % fmt_hex(self.image_base))
        lines.append("SectionAlign    : %s" % fmt_hex(self.section_align))
        lines.append("FileAlign       : %s" % fmt_hex(self.file_align))
        lines.append("SizeOfImage     : %s" % fmt_hex(self.size_of_image))
        lines.append("SizeOfHeaders   : %s" % fmt_hex(self.size_of_headers))
        lines.append("EntryPoint RVA  : %s" % fmt_hex(self.entry_rva))
        ep_off = self.rva_to_offset(self.entry_rva)
        ep_va = self.image_base + self.entry_rva
        lines.append("EntryPoint VA   : %s" % fmt_hex(ep_va))
        lines.append("EntryPoint Off  : %s" % (
            fmt_hex(ep_off) if ep_off is not None else "<not file-backed>"))
        lines.append("Sections        : %d" % self.num_sections)
        lines.append("")
        lines.append("Sections:")
        lines.append("  #  Name      VirtSize    RVA         VA          RawSize     RawOff      Flags")
        for i, sec in enumerate(self.sections):
            va = self.image_base + sec["virtual_address"]
            lines.append("  %-2d %-8s  %10s  %10s  %10s  %10s  %10s  %08X" % (
                i, sec["name"] or "<none>",
                fmt_hex(sec["virtual_size"]),
                fmt_hex(sec["virtual_address"]),
                fmt_hex(va),
                fmt_hex(sec["size_raw"]),
                fmt_hex(sec["ptr_raw"]),
                sec["characteristics"]))
        lines.append("")
        lines.append("Address map (RVA / VA / file offset):")
        for i, sec in enumerate(self.sections):
            start_rva = sec["virtual_address"]
            span = sec["size_raw"] if sec["size_raw"] else sec["virtual_size"]
            end_rva = start_rva + span
            lines.append("  [%s] RVA %s..%s  VA %s..%s  off %s..%s" % (
                sec["name"] or "<none>",
                fmt_hex(start_rva), fmt_hex(end_rva),
                fmt_hex(self.image_base + start_rva),
                fmt_hex(self.image_base + end_rva),
                fmt_hex(sec["ptr_raw"]),
                fmt_hex(sec["ptr_raw"] + span)))
        return "\n".join(lines)


def _fmt_time(ts):
    import datetime
    return datetime.datetime.utcfromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------- #
# File checks
# --------------------------------------------------------------------------- #
def compute_checks(data):
    return {
        "size": len(data),
        "crc32": "%08X" % (zlib.crc32(data) & 0xFFFFFFFF),
        "md5": hashlib.md5(data).hexdigest().upper(),
    }


def check_against(data, filecheck):
    """Return list of (name, expected, actual, ok)."""
    actual = compute_checks(data)
    results = []
    if not filecheck:
        return results
    for key in ("size", "crc32", "md5"):
        if key in filecheck and filecheck[key] is not None:
            exp = filecheck[key]
            if key == "size":
                exp_s, act_s = str(exp), str(actual["size"])
            else:
                exp_s, act_s = str(exp).upper(), actual[key]
            ok = (exp_s == act_s) or (key == "size" and int(exp) == actual["size"])
            results.append((key, exp_s, act_s, ok))
    return results


# --------------------------------------------------------------------------- #
# Project loading / registry placeholder resolution
# --------------------------------------------------------------------------- #
def load_project(path):
    with open(path, "r", encoding="utf-8") as fh:
        proj = json.load(fh)
    if not isinstance(proj, dict):
        raise ValueError("project root must be a JSON object")
    return proj


def resolve_registry(registry, metadata):
    """Resolve %macros% / placeholders in registry entries (report only)."""
    out = []
    for item in registry or []:
        entry = dict(item)
        data = entry.get("data", "")
        if isinstance(data, str):
            for key, val in (metadata or {}).items():
                data = data.replace("%%%s%%" % key, str(val))
            data = data.replace("%s", str(metadata.get("name", "")) if metadata else "")
            entry["data"] = data
        out.append(entry)
    return out


# ---------------------------------------------------------------------------
# apply
# --------------------------------------------------------------------------- #
def cmd_apply(args):
    with open(args.target, "rb") as fh:
        original = fh.read()

    proj = load_project(args.project)

    # 1) pre-patch file checks
    results = check_against(original, proj.get("filecheck"))
    if results:
        print("File checks (against original target):")
        all_ok = True
        for name, exp, act, ok in results:
            print("  [%s] %-5s expected=%s actual=%s" % (
                "OK" if ok else "FAIL", name, exp, act))
            all_ok = all_ok and ok
        if not all_ok:
            print("ERROR: target failed file check; aborting before any write.",
                  file=sys.stderr)
            return 2

    # 2) parse PE (needed for VA/RVA modes)
    pe = None
    entries = proj.get("entries") or []
    need_pe = any(e.get("mode") in ("va", "rva") for e in entries)
    if need_pe:
        try:
            pe = PEImage(args.target)
        except PEError as exc:
            print("ERROR: %s" % exc, file=sys.stderr)
            return 3

    data = bytearray(original)
    applied = 0
    errors = 0

    for idx, entry in enumerate(entries):
        mode = str(entry.get("mode", "offset")).lower()
        try:
            if mode in ("searchreplace", "search_replace", "sr", "sandr"):
                n = _apply_search_replace(data, entry)
                print("  entry[%d] searchreplace: %d occurrence(s) replaced" % (idx, n))
                applied += 1
            elif mode in ("offset", "file", "raw"):
                addr = parse_int(entry["addr"])
                patch = parse_hex_bytes(entry["bytes"])
                if addr < 0 or addr + len(patch) > len(data):
                    raise ValueError("offset 0x%X + %d bytes out of file range" % (addr, len(patch)))
                data[addr:addr + len(patch)] = patch
                print("  entry[%d] offset @0x%X <- %s (%d bytes)" % (
                    idx, addr, patch.hex().upper(), len(patch)))
                applied += 1
            elif mode == "va":
                addr = parse_int(entry["addr"])
                patch = parse_hex_bytes(entry["bytes"])
                off = pe.va_to_offset(addr)
                if off is None:
                    raise ValueError("VA 0x%X not backed by file data" % addr)
                data[off:off + len(patch)] = patch
                print("  entry[%d] va @0x%X -> off 0x%X <- %s" % (
                    idx, addr, off, patch.hex().upper()))
                applied += 1
            elif mode == "rva":
                addr = parse_int(entry["addr"])
                patch = parse_hex_bytes(entry["bytes"])
                off = pe.rva_to_offset(addr)
                if off is None:
                    raise ValueError("RVA 0x%X not backed by file data" % addr)
                data[off:off + len(patch)] = patch
                print("  entry[%d] rva @0x%X -> off 0x%X <- %s" % (
                    idx, addr, off, patch.hex().upper()))
                applied += 1
            else:
                raise ValueError("unknown patch mode %r" % mode)
        except (KeyError, ValueError, IndexError) as exc:
            errors += 1
            print("  entry[%d] ERROR: %s" % (idx, exc), file=sys.stderr)

    # 3) registry (record only)
    registry = resolve_registry(proj.get("registry"), proj.get("metadata"))
    if registry:
        print("Registry entries (recorded only, NOT written to live registry):")
        for item in registry:
            print("  [%s\\%s] %s = %r (type=%s, %s)" % (
                item.get("root", "HKLM"), item.get("path", ""),
                item.get("name", ""), item.get("data", ""),
                item.get("type", "REG_SZ"),
                ("%d-bit" % item["bitness"]) if item.get("bitness") else "native"))

    # 4) write output, preserving original mtime by default
    out_path = args.output or proj.get("output") or (args.target + ".patched")
    mtime = os.path.getmtime(args.target)
    with open(out_path, "wb") as fh:
        fh.write(data)
    if not args.no_preserve_time:
        os.utime(out_path, (mtime, mtime))

    print("")
    print("Applied %d patch entr%s, %d error(s)." % (
        applied, "y" if applied == 1 else "ies", errors))
    print("Output written : %s (%d bytes)" % (out_path, len(data)))
    if not args.no_preserve_time:
        print("Original date/time preserved from target.")
    return 1 if errors else 0


def _apply_search_replace(data, entry):
    pat = parse_pattern(entry["search"])
    rep = parse_hex_bytes(entry["replace"])
    if len(rep) != len(pat):
        raise ValueError("replace length (%d) != search length (%d)" % (len(rep), len(pat)))
    count = parse_int(entry.get("count", -1))
    if count is None or count < 0:
        count = -1  # all
    replaced = 0
    pos = 0
    while True:
        if count >= 0 and replaced >= count:
            break
        found = None
        for off in find_pattern(data, pat, pos):
            found = off
            break
        if found is None:
            break
        data[found:found + len(rep)] = rep
        replaced += 1
        pos = found + len(rep)
    return replaced


# ---------------------------------------------------------------------------
# info
# --------------------------------------------------------------------------- #
def cmd_info(args):
    pe = PEImage(args.pe)
    print(pe.describe())
    return 0


# ---------------------------------------------------------------------------
# verify
# --------------------------------------------------------------------------- #
def cmd_verify(args):
    with open(args.target, "rb") as fh:
        data = fh.read()
    proj = load_project(args.project)
    results = check_against(data, proj.get("filecheck"))
    if not results:
        print("No filecheck section in project; nothing to verify.")
        return 0
    print("File checks:")
    all_ok = True
    for name, exp, act, ok in results:
        print("  [%s] %-5s expected=%s actual=%s" % (
            "OK" if ok else "FAIL", name, exp, act))
        all_ok = all_ok and ok
    print("Result: %s" % ("PASS" if all_ok else "FAIL"))
    return 0 if all_ok else 2


# ---------------------------------------------------------------------------
# sniff  (serial sniffer heuristic)
# --------------------------------------------------------------------------- #
# Serial-like: groups of alnum blocks separated by - or space, e.g. XXXX-XXXX-XXXX-XXXX
_SERIAL_RE = re.compile(r"\b[A-Z0-9]{4}(?:[- ][A-Z0-9]{4}){2,5}\b")
# Generic key-ish: long alnum run with at least one separator group
_KEYISH_RE = re.compile(r"\b[A-Z0-9]{5,}(?:-[A-Z0-9]{5,}){1,}\b")
_CONTEXT_WORDS = re.compile(
    r"serial|cd.?key|product.?key|registration|activation|license|licence|"
    r"keygen|unlock|register.?number|\bkey\b", re.IGNORECASE)


def _extract_strings(data, min_len=4):
    """Yield (offset, text) for ASCII and UTF-16LE strings."""
    n = len(data)
    # ASCII strings
    i = 0
    while i < n:
        start = i
        while i < n and 0x20 <= data[i] < 0x7F:
            i += 1
        if i - start >= min_len:
            yield start, data[start:i].decode("latin-1")
        if i == start:
            i += 1
    # UTF-16LE strings
    i = 0
    while i + 1 < n:
        start = i
        chars = []
        while i + 1 < n and 0x20 <= data[i] < 0x7F and data[i + 1] == 0:
            chars.append(chr(data[i]))
            i += 2
        if len(chars) >= min_len:
            yield start, "".join(chars)
        if i == start:
            i += 1


def cmd_sniff(args):
    with open(args.exe, "rb") as fh:
        data = fh.read()
    print("Serial Sniffer (heuristic, best-effort) on %s" % args.exe)
    print("Size %d bytes, CRC32 %08X" % (len(data), zlib.crc32(data) & 0xFFFFFFFF))
    print("")

    serial_candidates = []
    key_candidates = []
    context_hits = []
    seen = set()

    for off, text in _extract_strings(data, 4):
        for m in _SERIAL_RE.finditer(text):
            s = m.group(0)
            key = (off + m.start(), s)
            if key in seen:
                continue
            seen.add(key)
            serial_candidates.append((off + m.start(), s))
        for m in _KEYISH_RE.finditer(text):
            s = m.group(0)
            key = ("k", off + m.start(), s)
            if key in seen:
                continue
            seen.add(key)
            key_candidates.append((off + m.start(), s))
        if _CONTEXT_WORDS.search(text):
            context_hits.append((off, text))

    print("== Serial-like strings (XXXX-XXXX-... pattern): %d ==" % len(serial_candidates))
    for off, s in serial_candidates[:40]:
        print("  @0x%08X  %s" % (off, s))
    if len(serial_candidates) > 40:
        print("  ... (%d more)" % (len(serial_candidates) - 40))

    print("")
    print("== Key-ish strings (multi-block alnum): %d ==" % len(key_candidates))
    for off, s in key_candidates[:40]:
        print("  @0x%08X  %s" % (off, s))
    if len(key_candidates) > 40:
        print("  ... (%d more)" % (len(key_candidates) - 40))

    print("")
    print("== Context strings (serial/key/license keywords): %d ==" % len(context_hits))
    for off, s in context_hits[:30]:
        snippet = s if len(s) <= 60 else s[:57] + "..."
        print("  @0x%08X  %s" % (off, snippet))
    if len(context_hits) > 30:
        print("  ... (%d more)" % (len(context_hits) - 30))

    print("")
    print("NOTE: heuristic only; results are candidates for manual review.")
    return 0


# ---------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------- #
def build_parser():
    p = argparse.ArgumentParser(
        prog="main.py",
        description="AT4RE Patcher v0.7.6 core engine re-implemented as a "
                    "static Python CLI (PE32/PE32+ patcher).")
    sub = p.add_subparsers(dest="command", metavar="<command>")
    sub.required = True

    pa = sub.add_parser("apply", help="apply a JSON project to a target file")
    pa.add_argument("target", help="file to patch")
    pa.add_argument("project", help="project JSON file")
    pa.add_argument("-o", "--output", help="output file (default: <target>.patched)")
    pa.add_argument("--no-preserve-time", action="store_true",
                    help="do not copy the target's mtime onto the output")
    pa.set_defaults(func=cmd_apply)

    pi = sub.add_parser("info", help="show PE32/PE32+ header, sections, address map, hashes")
    pi.add_argument("pe", help="PE file to inspect")
    pi.set_defaults(func=cmd_info)

    ps = sub.add_parser("sniff", help="serial sniffer heuristic (best-effort)")
    ps.add_argument("exe", help="file to scan")
    ps.set_defaults(func=cmd_sniff)

    pv = sub.add_parser("verify", help="run file checks from a project only")
    pv.add_argument("target", help="file to check")
    pv.add_argument("project", help="project JSON file")
    pv.set_defaults(func=cmd_verify)

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except (PEError, ValueError, OSError, json.JSONDecodeError) as exc:
        print("ERROR: %s" % exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())