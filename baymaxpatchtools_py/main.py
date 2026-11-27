#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
baymaxpatchtools_py -- a Python re-implementation of the core file/PE logic of
"Baymax Patch Tools v3.1.3" (x86, (c) Nisy/PYG, www.chinapyg.com).

WHAT THE ORIGINAL IS (evidence)
-------------------------------
Baymax Patch Tools is a "hijacking patch making tool": it generates a hijacking
DLL / loader that is injected into a target process and, at runtime, patches the
target's memory.  It does NOT normally rewrite the target EXE on disk.  Evidence:

  * Update.txt (shipped with the tool):
      - "Baymax Patch Tools is a hijacking patch making tool that releases a
         hijacking DLL for the target process to load the function module PYG.
         Two patching functions are supported. search and replace patch supports
         feature code search and replace memory data, exception breakpoint patch
         supports simulating the exception breakpoint function of debugger and
         modifying register, memory and other data after setting and triggering
         breakpoint ..."
      - Feature list: hijacking crack (no file modification), ASLR / dynamic
         base address, multiple DLL modules, multiple EXEs of the same patch,
         patch memory at a specified address, feature-code matching, API HOOK
         decoding for shelled programs, hardware/exception/conditional
         breakpoints, extract global variables from assembly, store data,
         read patch data from an ini file, memory keymaker, debug patches.
      - v3.1.3 (2023.01.30) changelog: XP compatibility, loader "When Running
         to Oep" hang fix, x64 QWORD condition-breakpoint display fix, old bpt
         project conditional-breakpoint parse fix.

  * Baymax.ini (shipped config):
      - [BAYMAX] VERSION=3.1.3 BUILD=0130 INTERRUPT=2 INJECT=1
      - [BREAKPOINTCODE] SHOWNOPINFO=1
      - [HOOKDLL] HookDllCount=7, SystemDllName0..6 = user32/kernel32/advapi32/
        wininet/ws2_32/wsock32/ntdll  (the DLLs the loader hooks to decode
        shelled code before patching)
      - [FILEHASH] base64-ish integrity hashes for Baymax.exe, Bella.dll,
        FeatureCode.dll, BreakPointCode.dll, SearchFeatureCode.dll, PatchUi.dat,
        PatchUid.dat, StringToHex.dll, ComparePeFile.dll, OffsetTransform.dll,
        Languages.dll  -> the tool verifies its own modules at startup.

  * Languages/en-US.ini (UI resource strings) map every tool/plugin to a
    resource block.  The "PlugIn Name" id 666 identifies each plugin:
      - [FeatureCodeUi]   666 = "Search and Replace Patch"
      - [BreakPointCodeUi]666 = "Exception Breakpoint Patch"
      - [ComparePeUi]     666 = "PE file comparison"
      - [OffsetTransformUi]666 = "Address format conversion"
      - [SearchFeatureUi] 666 = "Feature code search"
      - [StringToHexUi]   666 = "String to hexadecimal"
    These blocks also define the address model the tool uses everywhere:
    "Virtual Addr(VA)", "Offset Addr(RVA)", "Module Address", "File Offset
    Address", "Raw data"/"Patch data", feature code with '??' wildcards
    ("format: AA BB ?? ?? CC"), and the PE checks (2000..2007 "not a valid
    32/64-bit PE/DLL/EXE file").

  * PlugIn/ and Tools/ directories (PE DLLs):
      - PlugIn/FeatureCode.dll, PlugIn/BreakPointCode.dll export the "Angel/Ns"
        plugin SDK: NsCreateAngel / NsGetAngleName / NsGoodByeAngel.
      - Tools/ComparePeFile.dll, OffsetTransform.dll, SearchFeatureCode.dll,
        StringToHex.dll export the "Baymax" SDK:
        BaymaxCreateInstance / BaymaxPlugInName.
    PatchUi.dat / PatchUid.dat are actually PE files (MZ) -- renamed UI DLLs.

PROTECTION / METHOD (read this)
-------------------------------
The shipped Baymax.exe is protected with Themida/WinLicense (sections ".themida"
/ ".boot", VM-based).  The IDA disassembly (ida_out/t03.exe.asm) is therefore
NOT the program logic -- it is the Themida virtual-machine bytecode plus the PE
import table (kernel32/USER32/GDI32/COMDLG32/ADVAPI32/SHELL32/ole32/OLEAUT32/
SHLWAPI/COMCTL32) and a handful of stubs.  The VM itself was NOT disassembled.

Consequently the logic in this file was RECONSTRUCTED from:
  (a) the shipped documentation/config (Update.txt, Baymax.ini, Languages/*.ini),
  (b) the plugin/tool PE export tables and directory layout,
  (c) the publicly documented behaviour of Baymax Patch Tools (a memory patcher:
      search-and-replace + exception-breakpoint patch, with a VA/RVA/FOA address
      model and '??' feature-code wildcards).
It is a static, best-effort reconstruction -- not a byte-exact clone of the
protected binary, and it does not contain any of the runtime injection / loader /
breakpoint machinery (which only exists in the original VM-protected tool).

FEATURE -> SUBCOMMAND MAP
-------------------------
  info <pe>                 Address format conversion + PE checks
                            (OffsetTransform.dll / SearchFeatureCode.dll info;
                             ini blocks [OffsetTransformUi]/[SearchFeatureUi]).
  apply <target> <project>  Search-and-Replace patch + file compare
                            ([FeatureCodeUi] "Search and Replace Patch",
                             [ComparePeUi] "compare before adding", PE checks).
  compare <a> <b>           PE file comparison ([ComparePeUi] "PE file
                            comparison": RVA/VA/FOA, raw vs modify data).
  plugins [dir]             PlugIn/ + Tools/ descriptor inspection
                            (BaymaxCreateInstance / NsCreateAngel exports).

Only the Python standard library is used.  main.py is the single entry point.
"""

import argparse
import hashlib
import json
import os
import struct
import sys
import zlib

# --------------------------------------------------------------------------- #
# Constants
# --------------------------------------------------------------------------- #

IMAGE_NT_SIGNATURE = 0x00004550
PE32_MAGIC = 0x10B
PE32PLUS_MAGIC = 0x20B

# Machine / characteristics pretty names (subset).
MACHINE_NAMES = {
    0x014C: "x86 (i386)",
    0x8664: "x64 (AMD64)",
    0x01C0: "ARM",
    0xAA64: "ARM64",
    0x0200: "IA64",
}

SECTION_FLAG_NAMES = {
    0x00000020: "CODE",
    0x00000040: "INIT_DATA",
    0x00000080: "UNINIT_DATA",
    0x02000000: "DISCARDABLE",
    0x04000000: "NOT_CACHED",
    0x08000000: "NOT_PAGED",
    0x10000000: "SHARED",
    0x20000000: "EXECUTE",
    0x40000000: "READ",
    0x80000000: "WRITE",
}


# --------------------------------------------------------------------------- #
# Byte / pattern helpers
# --------------------------------------------------------------------------- #

def parse_hex_bytes(text):
    """Parse a hex byte string ("90 90 CC", "0x90,0xCC", "9090CC") into a list
    of ints, or None entries for '??' wildcards.  Raises ValueError on garbage."""
    if isinstance(text, (list, tuple)):
        out = []
        for v in text:
            if v is None or (isinstance(v, str) and v.strip() in ("??", "?")):
                out.append(None)
            else:
                out.append(int(v) & 0xFF)
        return out
    if not isinstance(text, str):
        raise ValueError("bytes must be a string or list, got %r" % (type(text),))
    s = text.strip().replace(",", " ").replace("0x", " ").replace("0X", " ")
    s = s.replace("\t", " ")
    tokens = s.split()
    if not tokens:
        return []
    # Allow a single contiguous blob like "9090CC" (even length).
    if len(tokens) == 1 and len(tokens[0]) % 2 == 0 and all(
        c in "0123456789abcdefABCDEF?" for c in tokens[0]
    ) and "?" not in tokens[0]:
        tokens = [tokens[0][i:i + 2] for i in range(0, len(tokens[0]), 2)]
    out = []
    for t in tokens:
        if t in ("??", "?"):
            out.append(None)
        else:
            if len(t) % 2:
                t = "0" + t
            for i in range(0, len(t), 2):
                out.append(int(t[i:i + 2], 16))
    return out


def pattern_to_bytes(pattern):
    """Concrete pattern -> bytes (wildcards not allowed)."""
    vals = parse_hex_bytes(pattern)
    if any(v is None for v in vals):
        raise ValueError("concrete bytes cannot contain '??' wildcards")
    return bytes(vals)


def find_pattern(haystack, pattern, start=0):
    """Find first index >= start where pattern (list of int|None) matches.
    Returns index or -1."""
    n = len(pattern)
    if n == 0:
        return -1
    end = len(haystack) - n
    i = start
    while i <= end:
        ok = True
        for j, p in enumerate(pattern):
            if p is not None and haystack[i + j] != p:
                ok = False
                break
        if ok:
            return i
        i += 1
    return -1


def find_all(haystack, pattern, limit=None):
    """Yield all match indices for a wildcard pattern."""
    idx = 0
    found = 0
    while True:
        i = find_pattern(haystack, pattern, idx)
        if i < 0:
            return
        yield i
        found += 1
        if limit is not None and found >= limit:
            return
        idx = i + 1


def hexdump_bytes(data, base=0):
    return " ".join("%02X" % b for b in data)


# --------------------------------------------------------------------------- #
# PE parser
# --------------------------------------------------------------------------- #

class Section(object):
    __slots__ = ("name", "virtual_size", "virtual_address", "size_raw",
                 "pointer_raw", "characteristics")

    def __init__(self, name, vs, va, rs, ro, ch):
        self.name = name
        self.virtual_size = vs
        self.virtual_address = va
        self.size_raw = rs
        self.pointer_raw = ro
        self.characteristics = ch

    @property
    def span(self):
        return max(self.virtual_size, self.size_raw)

    def flags_string(self):
        names = [n for bit, n in SECTION_FLAG_NAMES.items()
                 if self.characteristics & bit]
        return "|".join(names) if names else "0x%08X" % self.characteristics


class PEImage(object):
    """Minimal, dependency-free PE32/PE32+ reader with VA/RVA/FOA mapping."""

    def __init__(self, data, path=None):
        self.data = data
        self.path = path
        self._parse()

    def _u16(self, off):
        return struct.unpack_from("<H", self.data, off)[0]

    def _u32(self, off):
        return struct.unpack_from("<I", self.data, off)[0]

    def _parse(self):
        d = self.data
        if len(d) < 0x40 or d[:2] != b"MZ":
            raise ValueError("not a valid PE file (missing MZ)")
        e_lfanew = self._u32(0x3C)
        if e_lfanew + 24 > len(d) or d[e_lfanew:e_lfanew + 4] != b"PE\0\0":
            raise ValueError("not a valid PE file (missing PE signature)")
        self.e_lfanew = e_lfanew
        coff = e_lfanew + 4
        self.machine = self._u16(coff)
        self.number_of_sections = self._u16(coff + 2)
        self.timestamp = self._u32(coff + 4)
        size_opt = self._u16(coff + 16)
        self.characteristics = self._u16(coff + 18)
        opt = coff + 20
        self.magic = self._u16(opt)
        if self.magic == PE32_MAGIC:
            self.is_64 = False
            self.image_base = self._u32(opt + 28)
            self.size_of_image = self._u32(opt + 56)
            self.size_of_headers = self._u32(opt + 60)
            self.entry_rva = self._u32(opt + 16)
            num_dirs = self._u32(opt + 92)
            dirs_off = opt + 96
        elif self.magic == PE32PLUS_MAGIC:
            self.is_64 = True
            self.image_base = struct.unpack_from("<Q", d, opt + 24)[0]
            self.size_of_image = self._u32(opt + 56)
            self.size_of_headers = self._u32(opt + 60)
            self.entry_rva = self._u32(opt + 16)
            num_dirs = self._u32(opt + 108)
            dirs_off = opt + 112
        else:
            raise ValueError("not a valid PE file (bad optional magic 0x%X)"
                             % self.magic)
        self.data_directories = []
        for i in range(min(num_dirs, 16)):
            rva = self._u32(dirs_off + i * 8)
            sz = self._u32(dirs_off + i * 8 + 4)
            self.data_directories.append((rva, sz))
        sec_off = opt + size_opt
        self.sections = []
        for i in range(self.number_of_sections):
            o = sec_off + i * 40
            if o + 40 > len(d):
                break
            raw_name = d[o:o + 8]
            name = raw_name.rstrip(b"\0").decode("latin1", "replace")
            vs, va, rs, ro = struct.unpack_from("<IIII", d, o + 8)
            ch = self._u32(o + 36)
            self.sections.append(Section(name, vs, va, rs, ro, ch))

    # -- classification ---------------------------------------------------- #
    @property
    def is_dll(self):
        return bool(self.characteristics & 0x2000)

    @property
    def is_exe(self):
        return bool(self.characteristics & 0x0002)

    def kind(self):
        if self.is_dll:
            return "DLL"
        if self.is_exe:
            return "EXE"
        return "PE"

    def bits(self):
        return 64 if self.is_64 else 32

    # -- address conversion ------------------------------------------------ #
    def rva_to_offset(self, rva):
        if rva < self.size_of_headers:
            return rva if rva < len(self.data) else None
        for s in self.sections:
            if s.virtual_address <= rva < s.virtual_address + s.span:
                delta = rva - s.virtual_address
                if delta < s.size_raw:
                    off = s.pointer_raw + delta
                    return off if off < len(self.data) else None
                return None  # in virtual tail (BSS), not file-backed
        return None

    def offset_to_rva(self, off):
        if off < self.size_of_headers:
            return off
        for s in self.sections:
            if s.pointer_raw <= off < s.pointer_raw + s.size_raw:
                return s.virtual_address + (off - s.pointer_raw)
        return None

    def va_to_offset(self, va):
        return self.rva_to_offset(va - self.image_base)

    def rva_to_va(self, rva):
        return self.image_base + rva

    def offset_to_va(self, off):
        rva = self.offset_to_rva(off)
        return None if rva is None else self.rva_to_va(rva)

    def section_of_offset(self, off):
        for s in self.sections:
            if s.pointer_raw <= off < s.pointer_raw + s.size_raw:
                return s
        return None

    def section_of_rva(self, rva):
        for s in self.sections:
            if s.virtual_address <= rva < s.virtual_address + s.span:
                return s
        return None

    # -- exports (best effort, for module+export entries) ------------------ #
    def export_map(self):
        """Return {name: rva} from the export directory (best effort)."""
        if len(self.data_directories) < 1:
            return {}
        edir_rva = self.data_directories[0][0]
        if not edir_rva:
            return {}
        eo = self.rva_to_offset(edir_rva)
        if eo is None:
            return {}
        try:
            n_names = self._u32(eo + 24)
            names_rva = self._u32(eo + 32)
            funcs_rva = self._u32(eo + 28)
        except struct.error:
            return {}
        no = self.rva_to_offset(names_rva)
        fo = self.rva_to_offset(funcs_rva)
        if no is None or fo is None:
            return {}
        result = {}
        for i in range(n_names):
            try:
                nrva = self._u32(no + i * 4)
            except struct.error:
                break
            o = self.rva_to_offset(nrva)
            if o is None:
                continue
            end = self.data.find(b"\0", o)
            if end < 0:
                continue
            name = self.data[o:end].decode("latin1", "replace")
            try:
                frva = self._u32(fo + i * 4)
            except struct.error:
                break
            result[name] = frva
        return result


def load_pe(path):
    with open(path, "rb") as f:
        data = f.read()
    return PEImage(data, path), data


# --------------------------------------------------------------------------- #
# info
# --------------------------------------------------------------------------- #

def cmd_info(args):
    pe, data = load_pe(args.pe)
    print("File            : %s" % args.pe)
    print("Size            : %d bytes (0x%X)" % (len(data), len(data)))
    print("CRC32           : %08X" % (zlib.crc32(data) & 0xFFFFFFFF))
    print("MD5             : %s" % hashlib.md5(data).hexdigest())
    print("Type            : %s  (%d-bit)" % (pe.kind(), pe.bits()))
    print("Machine         : 0x%04X  %s"
          % (pe.machine, MACHINE_NAMES.get(pe.machine, "unknown")))
    print("Magic           : 0x%04X  %s"
          % (pe.magic, "PE32" if not pe.is_64 else "PE32+"))
    print("ImageBase       : 0x%016X" % pe.image_base)
    print("EntryPoint      : RVA 0x%08X  (VA 0x%016X)"
          % (pe.entry_rva, pe.rva_to_va(pe.entry_rva)))
    print("SizeOfImage     : 0x%X" % pe.size_of_image)
    print("SizeOfHeaders   : 0x%X" % pe.size_of_headers)
    print("Sections        : %d" % len(pe.sections))
    print()
    hdr = ("  %-10s %-12s %-10s %-10s %-10s %s"
           % ("Name", "VA(RVA)", "VSize", "RawOff", "RawSize", "Flags"))
    print(hdr)
    print("  " + "-" * (len(hdr) - 2))
    for s in pe.sections:
        print("  %-10s 0x%08X   0x%08X 0x%08X 0x%08X %s"
              % (s.name, s.virtual_address, s.virtual_size,
                 s.pointer_raw, s.size_raw, s.flags_string()))
    print()
    print("Address map (RVA -> VA -> file offset):")
    for s in pe.sections:
        lo = s.virtual_address
        hi = s.virtual_address + s.span
        fo = s.pointer_raw
        print("  %-10s RVA 0x%08X..0x%08X  VA 0x%016X..0x%016X  FOA 0x%08X..0x%08X"
              % (s.name, lo, hi, pe.rva_to_va(lo), pe.rva_to_va(hi),
                 fo, fo + s.size_raw))
    return 0


# --------------------------------------------------------------------------- #
# apply
# --------------------------------------------------------------------------- #

def _resolve_offset(pe, ent, target_is_pe):
    """Resolve an entry/check address to a file offset.  Returns (offset, desc)
    or raises ValueError."""
    if "offset" in ent and ent["offset"] is not None:
        off = int(str(ent["offset"]), 0) if isinstance(ent["offset"], str) \
            else int(ent["offset"])
        return off, "offset 0x%X" % off
    if not target_is_pe:
        raise ValueError("target is not a PE file; only 'offset' addresses work")
    if "va" in ent and ent["va"] is not None:
        va = int(str(ent["va"]), 0) if isinstance(ent["va"], str) else int(ent["va"])
        off = pe.va_to_offset(va)
        if off is None:
            raise ValueError("VA 0x%X is not file-backed" % va)
        return off, "VA 0x%X -> RVA 0x%X -> FOA 0x%X" % (
            va, va - pe.image_base, off)
    if "rva" in ent and ent["rva"] is not None:
        rva = int(str(ent["rva"]), 0) if isinstance(ent["rva"], str) else int(ent["rva"])
        off = pe.rva_to_offset(rva)
        if off is None:
            raise ValueError("RVA 0x%X is not file-backed" % rva)
        return off, "RVA 0x%X -> FOA 0x%X (VA 0x%X)" % (
            rva, off, pe.rva_to_va(rva))
    if "module" in ent and ent["module"] and "export" in ent and ent["export"]:
        mod = ent["module"]
        exp = ent["export"]
        exports = pe.export_map()
        if mod.lower() in (os.path.basename(pe.path or "").lower(), "", "."):
            if exp not in exports:
                raise ValueError("export %r not found in target" % exp)
            rva = exports[exp]
            off = pe.rva_to_offset(rva)
            if off is None:
                raise ValueError("export %r RVA not file-backed" % exp)
            return off, "export %s!%s -> RVA 0x%X -> FOA 0x%X" % (
                mod, exp, rva, off)
        raise ValueError(
            "module %r is a runtime module; static export resolution only "
            "supports the target file itself" % mod)
    raise ValueError("entry has no offset/va/rva/module+export address")


def _check_condition(buf, off, expected, label):
    """Verify expected (with '??' wildcards) at off.  Returns (ok, detail)."""
    if off < 0 or off + len(expected) > len(buf):
        return False, "%s: range 0x%X..0x%X out of file" % (
            label, off, off + len(expected))
    for j, p in enumerate(expected):
        if p is not None and buf[off + j] != p:
            return False, "%s: mismatch at 0x%X (got %02X expected %02X)" % (
                label, off + j, buf[off + j], p)
    return True, "%s: OK (%d bytes at 0x%X)" % (label, len(expected), off)


def cmd_apply(args):
    with open(args.project, "r", encoding="utf-8") as f:
        project = json.load(f)
    with open(args.target, "rb") as f:
        original = f.read()
    buf = bytearray(original)

    pe = None
    try:
        pe = PEImage(original, args.target)
    except ValueError as e:
        if args.verbose:
            print("[warn] %s (offset-only mode)" % e)

    entries = project.get("entries", []) or []
    checks = project.get("filecheck", []) or []
    searchrep = project.get("searchreplace", []) or []

    print("Target  : %s (%d bytes)" % (args.target, len(original)))
    print("Project : %s" % args.project)
    if pe is not None:
        print("PE      : %s %d-bit, ImageBase 0x%X"
              % (pe.kind(), pe.bits(), pe.image_base))
    print("Plan    : %d filecheck, %d entries, %d searchreplace"
          % (len(checks), len(entries), len(searchrep)))
    print()

    # 1) filecheck (compare-before-add, ini [ComparePeUi] 1039 / PE checks).
    ok_all = True
    for i, chk in enumerate(checks):
        expected = parse_hex_bytes(chk.get("expected", chk.get("raw", "")))
        off, desc = _resolve_offset(pe, chk, pe is not None)
        ok, detail = _check_condition(buf, off, expected, "check[%d]" % i)
        print("  " + ("[ok]  " if ok else "[FAIL]") + " " + desc + " :: " + detail)
        ok_all = ok_all and ok
    if not ok_all and not args.force:
        print("\nfilecheck failed; aborting (use --force to apply anyway).")
        return 2
    print()

    changes = 0

    # 2) direct entries (offset / va / rva / module+export).
    for i, ent in enumerate(entries):
        patch = parse_hex_bytes(ent.get("bytes", ent.get("data", "")))
        off, desc = _resolve_offset(pe, ent, pe is not None)
        # '??' in patch data means "leave original byte unchanged".
        concrete = [b for b in patch if b is not None]
        if off < 0 or off + len(patch) > len(buf):
            print("  [FAIL] entry[%d] %s :: range out of file" % (i, desc))
            if not args.force:
                return 3
            continue
        old = bytes(buf[off:off + len(patch)])
        new_list = [buf[off + j] if p is None else p for j, p in enumerate(patch)]
        new = bytes(new_list)
        buf[off:off + len(patch)] = new
        changes += 1
        print("  [ok] entry[%d] %s" % (i, desc))
        print("         old: %s" % hexdump_bytes(old))
        print("         new: %s%s"
              % (hexdump_bytes(new),
                 "" if len(concrete) == len(patch) else "  (?? = keep)"))
    print()

    # 3) search-and-replace (feature code with '??' wildcards).
    for i, sr in enumerate(searchrep):
        find = parse_hex_bytes(sr.get("find", sr.get("search", "")))
        repl = parse_hex_bytes(sr.get("replace", sr.get("patch", "")))
        if len(find) == 0:
            print("  [FAIL] searchreplace[%d] empty find" % i)
            if not args.force:
                return 4
            continue
        if any(p is None for p in repl):
            print("  [FAIL] searchreplace[%d] replace data has wildcards" % i)
            if not args.force:
                return 4
            continue
        if len(repl) != len(find):
            print("  [FAIL] searchreplace[%d] length %d != find %d "
                  "(Baymax requires equal length)" % (i, len(repl), len(find)))
            if not args.force:
                return 4
            continue
        do_all = bool(sr.get("all", True))
        matches = list(find_all(buf, find, limit=None if do_all else 1))
        if not matches:
            print("  [--] searchreplace[%d] pattern not found" % i)
            continue
        for m in matches:
            old = bytes(buf[m:m + len(find)])
            buf[m:m + len(find)] = bytes(repl)
            changes += 1
            rva = pe.offset_to_rva(m) if pe else None
            loc = "FOA 0x%X" % m
            if rva is not None:
                loc += " / RVA 0x%X / VA 0x%X" % (rva, pe.rva_to_va(rva))
            print("  [ok] searchreplace[%d] @ %s" % (i, loc))
            print("         old: %s" % hexdump_bytes(old))
            print("         new: %s" % hexdump_bytes(bytes(repl)))
        if not do_all:
            break
    print()

    if args.dry_run:
        print("Dry run: %d change(s) computed, nothing written." % changes)
        return 0

    out_path = args.out or args.target
    with open(out_path, "wb") as f:
        f.write(buf)
    print("Wrote %s (%d change(s))." % (out_path, changes))
    return 0


# --------------------------------------------------------------------------- #
# compare
# --------------------------------------------------------------------------- #

def cmd_compare(args):
    with open(args.a, "rb") as f:
        a = f.read()
    with open(args.b, "rb") as f:
        b = f.read()

    pea = peb = None
    try:
        pea = PEImage(a, args.a)
    except ValueError:
        pass
    try:
        peb = PEImage(b, args.b)
    except ValueError:
        pass

    print("A (original) : %s  (%d bytes)" % (args.a, len(a)))
    print("B (modify)   : %s  (%d bytes)" % (args.b, len(b)))
    if pea and peb:
        print("A PE         : %s %d-bit ImageBase 0x%X"
              % (pea.kind(), pea.bits(), pea.image_base))
        print("B PE         : %s %d-bit ImageBase 0x%X"
              % (peb.kind(), peb.bits(), peb.image_base))
        if pea.bits() != peb.bits():
            print("[warn] different PE bitness (ini ComparePeUi 1034)")
    elif pea or peb:
        print("[warn] only one file is a PE; VA mapping limited")
    if len(a) != len(b):
        print("[warn] size differs by %d bytes (ini ComparePeUi 1035)"
              % (len(b) - len(a)))
    print()

    base = None
    if args.base is not None:
        base = int(args.base, 0)
    elif pea is not None:
        base = pea.image_base

    # Group contiguous differing runs (merge runs separated by <= --gap bytes).
    n = min(len(a), len(b))
    diffs = [i for i in range(n) if a[i] != b[i]]
    if not diffs and len(a) == len(b):
        print("No differences found (0 bytes).")
        return 0

    runs = []
    for off in diffs:
        if runs and off - runs[-1][1] <= args.gap:
            runs[-1][1] = off
        else:
            runs.append([off, off])
    # include trailing length-mismatch region
    if len(a) != len(b):
        runs.append([n, max(len(a), len(b)) - 1])

    total_diff_bytes = 0
    print("  %-10s %-12s %-18s %-10s %-10s %s"
          % ("Offset", "RVA", "VA", "A(raw)", "B(mod)", "Section"))
    print("  " + "-" * 78)
    for lo, hi in runs:
        rva = pea.offset_to_rva(lo) if pea else None
        va = (base + rva) if (rva is not None and base is not None) else None
        sec = pea.section_of_offset(lo) if pea else None
        secname = sec.name if sec else "?"
        raw_a = a[lo:hi + 1] if lo < len(a) else b""
        raw_b = b[lo:hi + 1] if lo < len(b) else b""
        total_diff_bytes += max(len(raw_a), len(raw_b))
        loc_rva = "0x%08X" % rva if rva is not None else "-"
        loc_va = "0x%016X" % va if va is not None else "-"
        print("  0x%08X %s %s %-10s %-10s %s"
              % (lo, loc_rva, loc_va,
                 hexdump_bytes(raw_a) if raw_a else "-",
                 hexdump_bytes(raw_b) if raw_b else "-",
                 secname))
    print()
    print("%d difference run(s), %d differing byte(s)."
          % (len(runs), total_diff_bytes))
    return 0


# --------------------------------------------------------------------------- #
# plugins
# --------------------------------------------------------------------------- #

# Known plugin/tool descriptors (from Baymax.ini [FILEHASH] + en-US.ini id 666).
KNOWN_PLUGINS = {
    "featurecode.dll": ("PlugIn", "Search and Replace Patch", "Ns/Angel"),
    "breakpointcode.dll": ("PlugIn", "Exception Breakpoint Patch", "Ns/Angel"),
    "comparepefile.dll": ("Tools", "PE file comparison", "Baymax"),
    "offsettransform.dll": ("Tools", "Address format conversion", "Baymax"),
    "searchfeaturecode.dll": ("Tools", "Feature code search", "Baymax"),
    "stringtohex.dll": ("Tools", "String to hexadecimal", "Baymax"),
}


def _pe_exports(path):
    pe = PEImage(open(path, "rb").read(), path)
    return pe, pe.export_map()


def _sdk_kind(exports):
    names = set(exports)
    if "BaymaxCreateInstance" in names or "BaymaxPlugInName" in names:
        return "Baymax SDK (BaymaxCreateInstance/BaymaxPlugInName)"
    if "NsCreateAngel" in names or "NsGetAngleName" in names:
        return "Ns/Angel SDK (NsCreateAngel/NsGetAngleName/NsGoodByeAngel)"
    return "unknown SDK"


def cmd_plugins(args):
    dirs = []
    if args.dir:
        dirs = [args.dir]
    else:
        # Default: a "PlugIn" dir next to cwd, else the known install layout.
        candidates = [
            "PlugIn",
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "PlugIn"),
            r"D:/Program Files/crack-tool-patcher/BaymaxPatchTools_3.1.3/PlugIn",
        ]
        for c in candidates:
            if os.path.isdir(c):
                dirs = [c]
                break
        if not dirs:
            dirs = ["PlugIn"]
    if args.tools:
        if dirs:
            base = dirs[0]
            if os.path.isdir(base) and os.path.basename(base) == "PlugIn":
                t = os.path.join(os.path.dirname(base), "Tools")
            else:
                t = "Tools"
        else:
            t = "Tools"
        if os.path.isdir(t):
            dirs.append(t)

    print("Scanning plugin/tool directories:")
    for d in dirs:
        print("  %s" % d)
    print()

    found = 0
    for d in dirs:
        if not os.path.isdir(d):
            print("[--] %s (not found)" % d)
            continue
        for fn in sorted(os.listdir(d)):
            if not fn.lower().endswith(".dll"):
                continue
            path = os.path.join(d, fn)
            found += 1
            print("== %s ==" % fn)
            key = fn.lower()
            if key in KNOWN_PLUGINS:
                group, name, sdk = KNOWN_PLUGINS[key]
                print("   Role     : %s plugin -- %s" % (group, name))
                print("   Expected : %s" % sdk)
            try:
                pe, exports = _pe_exports(path)
                print("   PE       : %s %d-bit, ImageBase 0x%X"
                      % (pe.kind(), pe.bits(), pe.image_base))
                print("   SDK      : %s" % _sdk_kind(exports))
                print("   Exports  : %s"
                      % (", ".join(sorted(exports)) if exports else "(none)"))
            except Exception as e:
                print("   [warn] could not parse PE: %s" % e)
            print()
    if found == 0:
        print("No plugin DLLs found.")
    return 0


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser():
    p = argparse.ArgumentParser(
        prog="main.py",
        description="Baymax Patch Tools v3.1.3 core re-implementation "
                    "(PE info / apply / compare / plugins).",
        epilog="Reconstructed from Update.txt, Baymax.ini, Languages/*.ini and "
               "plugin PE exports; the original EXE is Themida VM-protected.")
    sub = p.add_subparsers(dest="cmd")

    pi = sub.add_parser("info", help="PE sections + CRC32/MD5/size + VA/RVA/FOA map")
    pi.add_argument("pe", help="PE file to inspect")
    pi.set_defaults(func=cmd_info)

    pa = sub.add_parser("apply", help="apply a JSON patch project to a target")
    pa.add_argument("target", help="target file to patch")
    pa.add_argument("project", help="JSON project file")
    pa.add_argument("--out", help="write result here instead of in-place")
    pa.add_argument("--dry-run", action="store_true",
                    help="compute but do not write")
    pa.add_argument("--force", action="store_true",
                    help="apply even if filecheck fails / ranges are bad")
    pa.add_argument("--verbose", action="store_true", help="extra diagnostics")
    pa.set_defaults(func=cmd_apply)

    pc = sub.add_parser("compare", help="byte diff of two files with VA mapping")
    pc.add_argument("a", help="original file")
    pc.add_argument("b", help="modified file")
    pc.add_argument("--base", help="override base VA for VA display (hex/dec)")
    pc.add_argument("--gap", type=int, default=0,
                    help="merge diff runs separated by <= N bytes (default 0)")
    pc.set_defaults(func=cmd_compare)

    pp = sub.add_parser("plugins", help="list/inspect PlugIn & Tools descriptors")
    pp.add_argument("dir", nargs="?", help="plugin directory (default: PlugIn)")
    pp.add_argument("--tools", action="store_true",
                    help="also scan the sibling Tools directory")
    pp.set_defaults(func=cmd_plugins)

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 1
    try:
        return args.func(args)
    except (ValueError, OSError, struct.error) as e:
        print("error: %s" % e, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())