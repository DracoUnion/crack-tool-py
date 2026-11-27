#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dup_py/main.py - dUP2 (diablo2oo2's Universal Patcher v2.26.1) rewritten as a
pure-Python 3 standard-library CLI.

ANALYSIS BASIS (static-only; no debugger used)
==============================================
Target : D:/Program Files/crack-tool-patcher/DUP_2.26.1_汉化版/dup2.exe
         x86 PE, NOT packed (clean .text / .rdata / .data sections)
Imagebase : 0x400000  (timestamp 50D4CE0C, Fri Dec 21 21:01:00 2012 UTC)
MD5          : 4AC92BDD98523AE864065C82FE6CAE7F
IDA disassembly: /d/temp/ida_out/t04.exe.asm

Key exported helpers recovered from the IDA listing (matching names/signatures):
  IsPEFile                   - "MZ" + "PE" signature check
  GetEntryPoint              - optional-header AddressOfEntryPoint (VA)
  GetFirstSectionOffset      - file offset of first section header
  RVAToOffset / OffsetToRVA  - RVA <-> raw file offset via section table
  OffsetToVA / VAToOffset    - VA <-> raw file offset (VA = RVA + ImageBase)
  CRC32OfFile / MD5OfFile    - file digest helpers
  LoadFileToMem / CloseLoadedFile - file mapping load/unload
  RegOpenKeyExA / RegCreateKeyExA / RegSetValueExA / RegQueryValueExA /
  RegCloseKey / Reg_Delete_Value - registry patching
  GetOpenFileNameA / ChooseFontA   - GUI file/font dialogs (not used here)
  CreateToolhelp32Snapshot / ShellExecuteA / WriteFile / ReadFile /
  CreateFileMappingA / MapViewOfFile / CreateProcessA / FindNextFileA

Section-table VA <-> raw offset mapping (recovered from IDA sub_402A5C /
sub_40297C / sub_402A8E / sub_402AD7):
  NT headers  at DOS e_lfanew ([pe+0x3C])
  NumberOfSections        = WORD at [NT + 0x06]
  SizeOfOptionalHeader    = WORD at [NT + 0x14]
  first section header    = [NT + 0x18] + SizeOfOptionalHeader
  each section header is 40 bytes:
      [+0x00] Name[8]      [+0x08] VirtualSize
      [+0x0C] VirtualAddress [+0x10] SizeOfRawData [+0x14] PointerToRawData
  RVA->raw : find section with VirtAddr <= rva < VirtAddr+SizeOfRawData
             raw = PointerToRawData + (rva - VirtualAddress)
  raw->VA  : find section with PtrToRaw <= off < PtrToRaw+SizeOfRawData
             VA = ImageBase + VirtualAddress + (off - PointerToRawData)
  VA->Offset: rva = VA - ImageBase; then RVA->raw

README feature -> subcommand mapping
------------------------------------
  * offset patcher            -> apply  (entry kind "offset", raw file offset)
  * VA patcher                -> apply  (entry kind "va", virtual address)
  * RVA patcher               -> apply  (entry kind "rva")
  * search and replace patcher-> apply  (entry kind "searchreplace")
  * text patcher (regex)      -> apply  (entry kind "text", regex on bytes)
  * registry patcher          -> apply  (entry kind "registry", emit .reg lines
                                       and/or write via winreg)
  * CRC32/MD5/filesize checks -> apply  (entry kind "verify", pre/post checks)
                                       and the standalone `verify` subcommand
  * file compare (RawOffset & VA) -> compare  (byte diff w/ raw-offset + VA map)
  * PE header/info + digests  -> info   (DOS/COFF/optional/sections summary)
  * save/load projects        -> project JSON read by `apply`/`verify`;
                                       `makeproject` builds a starter project
  * loader/packed-file patch  -> out of scope (static-only CLI; no unpacking)
SCOPE NOTE
----------
Static-analysis CLI only. No GUI, no skins, no music/tracker playback, no
plugin DLLs, no packer support, no in-memory/DLL patching. All logic is pure
Python 3 stdlib (struct, zlib, hashlib, re, argparse, json, os, sys, plus
winreg/ctypes on Windows for optional real registry writes).
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
# PE parsing (DOS header / COFF / optional header / section table)
# --------------------------------------------------------------------------- #

class PEError(Exception):
    pass


class Section:
    __slots__ = ("name", "virtual_size", "virtual_address",
                 "size_of_raw_data", "pointer_to_raw_data",
                 "characteristics")

    def __init__(self, name, virtual_size, virtual_address,
                 size_of_raw_data, pointer_to_raw_data, characteristics):
        self.name = name
        self.virtual_size = virtual_size
        self.virtual_address = virtual_address
        self.size_of_raw_data = size_of_raw_data
        self.pointer_to_raw_data = pointer_to_raw_data
        self.characteristics = characteristics

    def __repr__(self):
        return ("Section(name=%r, va=0x%X, vsize=0x%X, rawptr=0x%X, "
                "rawsize=0x%X, chars=0x%X)"
                % (self.name, self.virtual_address, self.virtual_size,
                   self.pointer_to_raw_data, self.size_of_raw_data,
                   self.characteristics))


class PE:
    """Minimal in-memory PE image (32-bit focus, tolerates PE32+ where fields
    overlap). Provides VA <-> raw file offset translation via the section
    table, mirroring dUP2's RVAToOffset/OffsetToVA/VAToOffset."""

    def __init__(self, data):
        self.data = data
        self._parse()

    def _parse(self):
        d = self.data
        if len(d) < 64:
            raise PEError("file too small to be a PE")
        if d[0:2] != b"MZ":
            raise PEError("not a PE file (no MZ signature)")
        e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
        if e_lfanew + 24 > len(d):
            raise PEError("e_lfanew points beyond EOF")
        if d[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
            raise PEError("not a PE file (no PE signature)")
        nt = e_lfanew
        self.e_lfanew = e_lfanew
        self.signature = nt
        self.coff = nt + 4
        machine, self.number_of_sections, timestamp, ptr_to_symtab, \
            num_symtab, sizeof_opt, characteristics = struct.unpack_from(
                "<HHIIIHH", d, self.coff)
        self.machine = machine
        self.timestamp = timestamp
        self.sizeof_optional_header = sizeof_opt
        self.characteristics = characteristics
        opt = self.coff + 20  # sizeof(IMAGE_FILE_HEADER)
        if opt + 96 > len(d):
            raise PEError("optional header truncated")
        self.opt = opt
        magic = struct.unpack_from("<H", d, opt)[0]
        self.magic = magic  # 0x10b PE32, 0x20b PE32+
        self.is_pe32 = (magic == 0x10B)
        # IMAGE_OPTIONAL_HEADER common fields
        self.address_of_entry_point = struct.unpack_from("<I", d, opt + 16)[0]
        self.image_base = struct.unpack_from("<I", d, opt + 28)[0]
        self.section_alignment = struct.unpack_from("<I", d, opt + 36)[0]
        self.file_alignment = struct.unpack_from("<I", d, opt + 40)[0]
        self.size_of_image = struct.unpack_from("<I", d, opt + 56)[0]
        self.size_of_headers = struct.unpack_from("<I", d, opt + 60)[0]
        self.checksum = struct.unpack_from("<I", d, opt + 64)[0]
        # section table
        sec_table = opt + sizeof_opt
        self.sections = []
        for i in range(self.number_of_sections):
            off = sec_table + i * 40
            if off + 40 > len(d):
                break
            name_raw = d[off:off + 8]
            name = name_raw.split(b"\x00")[0]
            try:
                name = name.decode("ascii", errors="replace")
            except Exception:
                name = name_raw.hex()
            vsize, vaddr, rawsize, rawptr = struct.unpack_from("<IIII", d,
                                                               off + 8)
            chars = struct.unpack_from("<I", d, off + 36)[0]
            self.sections.append(Section(name, vsize, vaddr, rawsize,
                                         rawptr, chars))

    def rva_to_offset(self, rva):
        """RVA -> raw file offset (dUP2 RVAToOffset)."""
        for s in self.sections:
            if s.size_of_raw_data == 0:
                continue
            if s.virtual_address <= rva < s.virtual_address + s.size_of_raw_data:
                return s.pointer_to_raw_data + (rva - s.virtual_address)
        # Fallback: not in any section with raw data (e.g. headers/resources).
        return None

    def offset_to_rva(self, off):
        """Raw file offset -> RVA."""
        for s in self.sections:
            if s.size_of_raw_data == 0:
                continue
            if s.pointer_to_raw_data <= off < s.pointer_to_raw_data + \
                    s.size_of_raw_data:
                return s.virtual_address + (off - s.pointer_to_raw_data)
        return None

    def va_to_offset(self, va):
        """Virtual Address -> raw offset (VA = RVA + ImageBase)."""
        return self.rva_to_offset(va - self.image_base)

    def offset_to_va(self, off):
        """Raw file offset -> Virtual Address."""
        rva = self.offset_to_rva(off)
        if rva is None:
            return None
        return self.image_base + rva

    def entry_point_va(self):
        return self.address_of_entry_point

    def entry_point_offset(self):
        return self.rva_to_offset(self.address_of_entry_point)

    def summary(self):
        lines = []
        lines.append("DOS e_lfanew        : 0x%X (%d)" % (self.e_lfanew,
                                                         self.e_lfanew))
        lines.append("Machine             : 0x%04X" % self.machine)
        lines.append("NumberOfSections    : %d" % self.number_of_sections)
        lines.append("SizeOfOptHeader     : 0x%X (%d)" % (self.sizeof_optional_header,
                                                          self.sizeof_optional_header))
        lines.append("Optional magic      : 0x%04X (%s)" % (self.magic,
                                                           "PE32" if self.is_pe32 else "PE32+/other"))
        lines.append("AddressOfEntryPoint : 0x%08X" % self.address_of_entry_point)
        lines.append("ImageBase           : 0x%08X" % self.image_base)
        lines.append("SizeOfImage         : 0x%X" % self.size_of_image)
        lines.append("SizeOfHeaders       : 0x%X" % self.size_of_headers)
        lines.append("CheckSum            : 0x%08X" % self.checksum)
        lines.append("")
        lines.append("Sections (%d):" % len(self.sections))
        lines.append("  %-10s %9s %9s %10s %10s  %s" % (
            "Name", "VirtAddr", "VirtSize", "RawPtr", "RawSize", "Chars"))
        for s in self.sections:
            lines.append("  %-10s 0x%08X 0x%08X 0x%08X 0x%08X  0x%08X" % (
                s.name, s.virtual_address, s.virtual_size,
                s.pointer_to_raw_data, s.size_of_raw_data,
                s.characteristics))
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# Hashing helpers
# --------------------------------------------------------------------------- #

def crc32_file(path):
    c = 0
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            c = zlib.crc32(chunk, c)
    return c & 0xFFFFFFFF


def crc32_bytes(data):
    return zlib.crc32(data) & 0xFFFFFFFF


def md5_file(path):
    m = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            m.update(chunk)
    return m.hexdigest()


def md5_bytes(data):
    return hashlib.md5(data).hexdigest()


def filesize(path):
    return os.path.getsize(path)


# --------------------------------------------------------------------------- #
# Hex / bytes parsing
# --------------------------------------------------------------------------- #

HEX_RE = re.compile(r"^[0-9A-Fa-f?\*\s]+$")


def parse_hex(text, allow_wildcard=False):
    """Parse a hex string like 'DE AD BE EF' or 'DEADBEEF'. '??' or '*'
    are wildcards (only meaningful for search/replace find patterns)."""
    s = text.strip()
    if s == "":
        return b""
    compact = re.sub(r"\s+", "", s)
    if not compact:
        return b""
    if allow_wildcard:
        tokens = compact.split()
        # tokens already whitespace-stripped; handle '**'/'??' wildcards
        out = bytearray()
        i = 0
        # Normalize '**' and '??' to a single wildcard marker '?', then walk.
        norm = compact.replace("**", "?").replace("??", "?")
        out = bytearray()
        j = 0
        while j < len(norm):
            c = norm[j]
            if c in "?*":
                out.append(None)  # wildcard byte
                j += 1
            elif j + 1 < len(norm) and norm[j + 1] in "0123456789ABCDEFabcdef":
                out.append(int(norm[j:j + 2], 16))
                j += 2
            else:
                raise ValueError("invalid hex token near %r" % norm[j:j + 4])
        return bytes(out)
    else:
        if not HEX_RE.match(compact.replace(" ", "")):
            raise ValueError("invalid hex data: %r" % text)
        if len(compact) % 2 != 0:
            raise ValueError("hex data must have an even number of digits: %r" % text)
        return bytes.fromhex(compact)


def parse_int(text):
    """Parse int allowing 0x/0X hex prefix or decimal; accepts int passthrough."""
    if isinstance(text, int):
        return text
    t = str(text).strip()
    if t.lower().startswith("0x"):
        return int(t, 16)
    return int(t, 10)


def find_bytes(data, pattern, start=0):
    """Find pattern (bytes; None == wildcard) in data from start. Returns index
    or -1."""
    pat = pattern
    if not pat:
        return -1
    idx = start
    plen = len(pat)
    dlen = len(data)
    while idx <= dlen - plen:
        match = True
        for k in range(plen):
            pb = pat[k]
            if pb is None:
                continue
            if data[idx + k] != pb:
                match = False
                break
        if match:
            return idx
        idx += 1
    return -1


# --------------------------------------------------------------------------- #
# Patch entry application
# --------------------------------------------------------------------------- #

REG_ROOTS = {
    "HKLM": "HKEY_LOCAL_MACHINE",
    "HKEY_LOCAL_MACHINE": "HKEY_LOCAL_MACHINE",
    "HKCU": "HKEY_CURRENT_USER",
    "HKEY_CURRENT_USER": "HKEY_CURRENT_USER",
    "HKCR": "HKEY_CLASSES_ROOT",
    "HKEY_CLASSES_ROOT": "HKEY_CLASSES_ROOT",
    "HKU": "HKEY_USERS",
    "HKEY_USERS": "HKEY_USERS",
    "HKCC": "HKEY_CURRENT_CONFIG",
    "HKEY_CURRENT_CONFIG": "HKEY_CURRENT_CONFIG",
}


def apply_offset(buf, pe, entry):
    offset = parse_int(entry["offset"])
    data = parse_hex(entry.get("data", ""))
    check = entry.get("check")
    check_bytes = parse_hex(check) if check else None
    if check_bytes is not None:
        actual = buf[offset:offset + len(check_bytes)]
        if actual != check_bytes:
            raise PatchError(
                "offset verify failed at 0x%X: expected %s, got %s"
                % (offset, check_bytes.hex(), actual.hex()))
    buf[offset:offset + len(data)] = data
    return offset, data


def apply_va(buf, pe, entry):
    va = parse_int(entry["va"])
    off = pe.va_to_offset(va)
    if off is None:
        raise PatchError("VA 0x%08X not mappable to a raw offset" % va)
    entry_apply = {"offset": off, "data": entry.get("data", ""),
                   "check": entry.get("check")}
    return apply_offset(buf, pe, entry_apply)


def apply_rva(buf, pe, entry):
    rva = parse_int(entry["rva"])
    off = pe.rva_to_offset(rva)
    if off is None:
        raise PatchError("RVA 0x%08X not mappable to a raw offset" % rva)
    entry_apply = {"offset": off, "data": entry.get("data", ""),
                   "check": entry.get("check")}
    return apply_offset(buf, pe, entry_apply)


def apply_searchreplace(buf, pe, entry):
    find = parse_hex(entry["find"], allow_wildcard=True)
    replace = parse_hex(entry.get("replace", ""))
    count_spec = entry.get("count", 1)
    occurrence = entry.get("occurrence", 1)  # 1-based occurrence to patch
    if len(find) == 0:
        raise PatchError("searchreplace: empty find pattern")
    # collect all matches
    matches = []
    idx = 0
    while True:
        idx = find_bytes(buf, find, idx)
        if idx < 0:
            break
        matches.append(idx)
        idx += 1
    if not matches:
        raise PatchError("searchreplace: pattern not found: %s" % find.hex())
    if count_spec == "all" or count_spec == 0:
        targets = matches
    else:
        try:
            n = int(count_spec)
        except ValueError:
            n = 1
        if occurrence and 1 <= occurrence <= len(matches):
            targets = [matches[occurrence - 1]]
        else:
            targets = matches[:n]
    applied = 0
    for m in targets:
        # replace must be same length as find for in-place; if different,
        # dUP2 "autocorrects" - here we require equal length for safety,
        # but allow shorter replace padded, or longer -> error.
        if len(replace) != len(find):
            raise PatchError(
                "searchreplace: replace length (%d) != find length (%d)"
                % (len(replace), len(find)))
        buf[m:m + len(replace)] = replace
        applied += 1
    return applied, matches


def apply_text(buf, pe, entry):
    """Regex text patch on raw bytes (true 'regex on bytes' like dUP2's
    text-patch module). pattern/replacement are str; encoding encodes them to
    bytes for matching/substitution. 'latin-1' is byte-safe (every byte maps
    1:1) and is the recommended encoding for binary executables."""
    pattern = entry["pattern"]
    replacement = entry.get("replacement", "")
    encoding = entry.get("encoding", "latin-1")
    count = entry.get("count", 0)  # 0 = all
    flags = 0
    if entry.get("case_insensitive"):
        flags |= re.IGNORECASE
    try:
        pat_b = pattern.encode(encoding)
        rep_b = replacement.encode(encoding)
    except (UnicodeEncodeError, LookupError) as e:
        raise PatchError("text: cannot encode pattern/replacement as %s: %s"
                         % (encoding, e))
    try:
        rx = re.compile(pat_b, flags)
    except re.error as e:
        raise PatchError("text: invalid regex %r: %s" % (pattern, e))
    new_buf, n = rx.subn(rep_b, bytes(buf), count=count)
    if n == 0:
        raise PatchError("text: pattern did not match: %r" % pattern)
    if len(new_buf) != len(buf):
        # dUP2 text patch is in-place same-length; changing size would shift
        # everything. We allow it but note it via return value (n == matches).
        pass
    buf[:] = new_buf
    return n


def apply_registry(entry):
    """Registry patch. Always emits .reg-style lines; if apply_registry_write
    is True and winreg is available, writes to the real registry."""
    root = entry.get("root", "HKLM")
    key = entry.get("key", "")
    name = entry.get("name", "")
    rtype = entry.get("type", "REG_SZ")
    data = entry.get("data", "")
    emit = entry.get("emit", True)
    lines = []
    root_full = REG_ROOTS.get(root, root)
    lines.append("Windows Registry Editor Version 5.00")
    lines.append("")
    lines.append("[%s\\%s]" % (root_full, key))
    # value line
    if rtype == "REG_DWORD":
        try:
            dw = int(data, 0) & 0xFFFFFFFF
        except ValueError:
            raise PatchError("registry REG_DWORD data must be a number: %r" % data)
        lines.append("\"%s\"=dword:%08X" % (name, dw))
    elif rtype == "REG_BINARY":
        b = parse_hex(data)
        lines.append("\"%s\"=hex:%s" % (name, b.hex()))
    elif rtype == "REG_EXPAND_SZ":
        lines.append("\"%s\"=hex(2):%s" % (name, data))
    elif rtype == "REG_MULTI_SZ":
        lines.append("\"%s\"=hex(7):%s" % (name, data))
    else:  # REG_SZ
        lines.append("\"%s\"=\"%s\"" % (name, data))
    if emit:
        print("\n".join(lines))
    wrote = False
    if entry.get("apply_registry_write"):
        try:
            import winreg  # stdlib on Windows
        except ImportError:
            raise PatchError("registry write requested but winreg unavailable "
                             "(not on Windows)")
        hkey_map = {
            "HKEY_LOCAL_MACHINE": winreg.HKEY_LOCAL_MACHINE,
            "HKEY_CURRENT_USER": winreg.HKEY_CURRENT_USER,
            "HKEY_CLASSES_ROOT": winreg.HKEY_CLASSES_ROOT,
            "HKEY_USERS": winreg.HKEY_USERS,
            "HKEY_CURRENT_CONFIG": winreg.HKEY_CURRENT_CONFIG,
        }
        hk = hkey_map.get(root_full)
        if hk is None:
            raise PatchError("unsupported registry root: %s" % root_full)
        try:
            keyh = winreg.CreateKeyEx(hk, key, 0,
                                      winreg.KEY_ALL_ACCESS)
            if rtype == "REG_DWORD":
                winreg.SetValueEx(keyh, name, 0, winreg.REG_DWORD, int(data, 0) & 0xFFFFFFFF)
            elif rtype == "REG_BINARY":
                winreg.SetValueEx(keyh, name, 0, winreg.REG_BINARY, parse_hex(data))
            elif rtype == "REG_MULTI_SZ":
                winreg.SetValueEx(keyh, name, 0, winreg.REG_MULTI_SZ, data.split("\x00"))
            else:
                winreg.SetValueEx(keyh, name, 0, winreg.REG_SZ, data)
            winreg.CloseKey(keyh)
            wrote = True
        except OSError as e:
            raise PatchError("registry write failed: %s" % e)
    return lines, wrote


class PatchError(Exception):
    pass


PATCH_KINDS = ("offset", "va", "rva", "searchreplace", "text",
               "registry", "verify")


def apply_entry(buf, pe, entry):
    kind = entry.get("kind")
    if kind not in PATCH_KINDS:
        raise PatchError("unknown patch kind: %r" % kind)
    if kind == "offset":
        return apply_offset(buf, pe, entry)
    if kind == "va":
        return apply_va(buf, pe, entry)
    if kind == "rva":
        return apply_rva(buf, pe, entry)
    if kind == "searchreplace":
        return apply_searchreplace(buf, pe, entry)
    if kind == "text":
        return apply_text(buf, pe, entry)
    if kind == "registry":
        return apply_registry(entry)
    if kind == "verify":
        return do_verify(buf, entry)
    raise PatchError("unsupported kind: %r" % kind)


def do_verify(buf, entry):
    """Verify CRC32/MD5/filesize of the current buffer. Used for both
    pre-checks (original file) and post-checks (patched buffer)."""
    vtype = entry.get("type", "crc32").lower()
    expected = entry.get("expected")
    if expected is None:
        raise PatchError("verify entry missing 'expected'")
    if vtype == "crc32":
        actual = crc32_bytes(buf)
        ok = (actual == parse_int(expected))
        label = "CRC32"
        aval = "0x%08X" % actual
    elif vtype == "md5":
        actual = md5_bytes(buf)
        ok = (actual.lower() == str(expected).lower())
        label = "MD5"
        aval = actual
    elif vtype == "filesize":
        actual = len(buf)
        ok = (actual == parse_int(expected))
        label = "filesize"
        aval = str(actual)
    else:
        raise PatchError("unknown verify type: %r" % vtype)
    desc = entry.get("description", "")
    status = "OK" if ok else "FAIL"
    print("[verify] %s %s: expected=%s actual=%s [%s] %s"
          % (label, status, expected, aval, desc,
             "" if ok else "<<< MISMATCH"))
    return ok


# --------------------------------------------------------------------------- #
# Project loading
# --------------------------------------------------------------------------- #

def load_project(path):
    with open(path, "r", encoding="utf-8") as f:
        proj = json.load(f)
    if not isinstance(proj, dict):
        raise PatchError("project JSON must be an object")
    return proj


# --------------------------------------------------------------------------- #
# Subcommands
# --------------------------------------------------------------------------- #

def cmd_info(args):
    with open(args.pe, "rb") as f:
        data = f.read()
    try:
        pe = PE(data)
    except PEError as e:
        print("error: %s" % e)
        return 1
    print(pe.summary())
    print("")
    print("File size        : %d bytes (0x%X)" % (len(data), len(data)))
    print("MD5              : %s" % md5_bytes(data))
    print("CRC32            : 0x%08X" % crc32_bytes(data))
    ep_off = pe.entry_point_offset()
    print("Entry point VA   : 0x%08X" % pe.entry_point_va())
    print("Entry point off  : %s"
          % ("0x%X" % ep_off if ep_off is not None else "n/a (not in a section)"))
    return 0


def _apply_project(proj, data):
    pe = PE(data)
    buf = bytearray(data)
    results = []
    # Pre-apply checks (against original file)
    for entry in proj.get("checks", []):
        if entry.get("kind") != "verify":
            entry = dict(entry, kind="verify")
        do_verify(bytes(buf), entry)
    # Apply patches in order
    for i, entry in enumerate(proj.get("patches", [])):
        desc = entry.get("description", "patch #%d" % (i + 1))
        print("[patch %d/%d] %s ..." % (i + 1, len(proj.get("patches", [])), desc))
        res = apply_entry(buf, pe, entry)
        results.append((desc, res))
    # Post-apply verify entries inside patches already printed; run any
    # top-level post-checks listed under 'post_checks' (alias of checks after
    # apply). Here we treat entries with kind verify inside patches as inline.
    return bytes(buf), pe, results


def cmd_apply(args):
    proj = load_project(args.project)
    with open(args.target, "rb") as f:
        data = f.read()
    out_buf, pe, results = _apply_project(proj, data)
    # Determine output path
    in_place = bool(proj.get("in_place", args.in_place))
    backup = bool(proj.get("backup", not args.no_backup))
    output = proj.get("output") or args.output
    if in_place:
        out_path = args.target
        if backup:
            bak = args.target + ".backup"
            if not os.path.exists(bak):
                with open(bak, "wb") as f:
                    f.write(data)
            print("[backup] wrote %s" % bak)
    else:
        if output:
            out_path = output
        else:
            base = args.target
            if base.lower().endswith(".exe"):
                base = base[:-4]
            out_path = base + ".patched"
    with open(out_path, "wb") as f:
        f.write(out_buf)
    print("[write] %s (%d bytes)" % (out_path, len(out_buf)))
    print("MD5  : %s" % md5_bytes(out_buf))
    print("CRC32: 0x%08X" % crc32_bytes(out_buf))
    # Post-apply verify entries (top-level)
    all_ok = True
    for entry in proj.get("post_checks", []):
        if entry.get("kind") != "verify":
            entry = dict(entry, kind="verify")
        ok = do_verify(out_buf, entry)
        all_ok = all_ok and ok
    if not all_ok:
        print("[result] VERIFY FAILED")
        return 1
    print("[result] applied %d patch entry/ies" % len(results))
    return 0


def cmd_verify(args):
    proj = load_project(args.project)
    with open(args.target, "rb") as f:
        data = f.read()
    all_ok = True
    for i, entry in enumerate(proj.get("checks", proj.get("patches", []))):
        if entry.get("kind") != "verify":
            entry = dict(entry, kind="verify")
        ok = do_verify(data, entry)
        all_ok = all_ok and ok
    print("[result] %s" % ("ALL CHECKS PASSED" if all_ok else "CHECK(S) FAILED"))
    return 0 if all_ok else 1


def cmd_compare(args):
    with open(args.a, "rb") as f:
        da = f.read()
    with open(args.b, "rb") as f:
        db = f.read()
    pa = None
    pb = None
    try:
        pa = PE(da)
    except PEError:
        pa = None
    try:
        pb = PE(db)
    except PEError:
        pb = None
    n = min(len(da), len(db))
    diffs = []
    for i in range(n):
        if da[i] != db[i]:
            diffs.append(i)
            if len(diffs) >= args.limit:
                break
    print("file A : %s (%d bytes)" % (args.a, len(da)))
    print("file B : %s (%d bytes)" % (args.b, len(db)))
    print("common length: %d bytes" % n)
    print("differing bytes: %d (showing first %d)" % (len(diffs),
                                                    min(len(diffs), args.limit)))
    if pa and pb:
        print("VA/raw mapping available for both files")
    for idx in diffs[:args.limit]:
        va_a = pa.offset_to_va(idx) if pa else None
        va_b = pb.offset_to_va(idx) if pb else None
        print("  raw 0x%08X (%d): A=0x%02X B=0x%02X"
              % (idx, idx, da[idx], db[idx]),
              (" VA_A=0x%08X" % va_a) if va_a is not None else "",
              (" VA_B=0x%08X" % va_b) if va_b is not None else "")
    if len(diffs) > args.limit:
        print("  ... %d more differing bytes not shown" % (len(diffs) - args.limit))
    # size delta note
    if len(da) != len(db):
        print("size delta: B - A = %d bytes" % (len(db) - len(da)))
    return 0


def cmd_makeproject(args):
    """Generate a starter project JSON for a single offset/VA patch."""
    offset = parse_int(args.offset)
    data = parse_hex(args.data)
    proj = {
        "name": args.name or "makeproject-generated",
        "description": "generated by dup_py makeproject",
        "backup": True,
        "in_place": False,
        "output": None,
        "checks": [],
        "patches": [
            {
                "kind": "offset",
                "offset": "0x%X" % offset,
                "data": data.hex(),
                "description": "offset patch 0x%X" % offset,
            }
        ],
        "post_checks": [],
    }
    out = args.output or "project.json"
    with open(out, "w", encoding="utf-8") as f:
        json.dump(proj, f, indent=2)
        f.write("\n")
    print("wrote project -> %s" % out)
    print("edit it, then: dup_py main.py apply <target.exe> %s" % out)
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="dup_py",
        description="dUP2-style universal patcher CLI (pure Python 3 stdlib).")
    sub = p.add_subparsers(dest="command", required=True)

    # info
    sp = sub.add_parser("info", help="PE header/sections summary + CRC32/MD5/filesize")
    sp.add_argument("pe", help="PE file to inspect")
    sp.set_defaults(func=cmd_info)

    # apply
    sp = sub.add_parser("apply", help="apply a JSON project to a target file")
    sp.add_argument("target", help="target file to patch")
    sp.add_argument("project", help="project JSON file")
    sp.add_argument("--output", help="output path (default <target>.patched)")
    sp.add_argument("--in-place", action="store_true",
                    help="write patched result back to target")
    sp.add_argument("--no-backup", action="store_true",
                    help="do not write a .backup file when in-place")
    sp.set_defaults(func=cmd_apply)

    # verify
    sp = sub.add_parser("verify", help="run CRC32/MD5/filesize checks from a project")
    sp.add_argument("target", help="target file to check")
    sp.add_argument("project", help="project JSON file")
    sp.set_defaults(func=cmd_verify)

    # compare
    sp = sub.add_parser("compare", help="byte-diff two files with raw-offset + VA mapping")
    sp.add_argument("a", help="first file")
    sp.add_argument("b", help="second file")
    sp.add_argument("--limit", type=int, default=50,
                    help="max differing bytes to show (default 50)")
    sp.set_defaults(func=cmd_compare)

    # makeproject
    sp = sub.add_parser("makeproject",
                        help="generate a starter single-offset project JSON")
    sp.add_argument("offset", help="raw file offset (hex 0x.. or dec)")
    sp.add_argument("data", help="hex bytes to write at offset")
    sp.add_argument("--name", help="project name")
    sp.add_argument("--output", default="project.json",
                    help="output project path (default project.json)")
    sp.set_defaults(func=cmd_makeproject)

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except PatchError as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    except FileNotFoundError as e:
        print("error: %s" % e, file=sys.stderr)
        return 1
    except Exception as e:  # noqa
        print("error: %s: %s" % (type(e).__name__, e), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
