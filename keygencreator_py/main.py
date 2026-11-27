#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
keygencreator_py -- a Python CLI reimplementation of "keygen creator" v2.1.0.0.

================================================================================
WHAT THE ORIGINAL IS
================================================================================
Target : "keygen creator.exe"  (x86 / 32-bit, PID 0x14c, imagebase 0x400000)
Vendor : "vison.v"  (version resource: ProductName "keygen creator",
         FileVersion / ProductVersion 2.1.0.0, InternalName "keygen creator.exe")
Manifest: embedded "dialogbox2.exe" / <description>Mx XP Program</description>
         (a common control v6 manifest, i.e. a themed GUI dialog app).
Plugin  : skin.ss / skin.ss1 are NOT text -- they are 32-bit PE *DLLs*
         (MZ/PE, .text/.rdata/.data/.rsrc, no exports) that the main EXE
         loads to draw its skinned UI.  Their imports give the game away:
             gdi32  : TextOutA, BitBlt, CreateCompatibleBitmap, CreatePen,
                      CreateSolidBrush, Rectangle, ...   (UI skin drawing)
             winmm  : waveOutOpen/Write/Pause/Close ...  (sound)
             kernel32: WriteProcessMemory, ReadProcessMemory, GetThreadContext,
                      SuspendThread/ResumeThread, CreateProcessA, CreateThread,
                      LoadResource/LockResource/FindResourceA (resource + injection)
         -> they are a theming/injection skin engine, not the keygen math.

================================================================================
ANTI-TAMPER / ENVIRONMENT FINGERPRINTING (cited from the .asm import table)
================================================================================
The static import table of the main EXE is deliberately tiny (the real imports
are resolved at run time by the protector).  The .asm (t05.exe.asm) shows:
    extrn GetInterfaceInfo:dword     ; IPHLPAPI  (network adapter enumeration)
    extrn GetMappedFileNameW:dword   ; PSAPI     (map the image, get its path)
    extrn RegDeleteKeyA:dword        ; ADVAPI32  (wipe trial/registration keys)
    extrn ShellExecuteA:dword        ; SHELL32   (open browser / "open file")
    extrn GetSaveFileNameA:dword     ; COMDLG32  ("save generated keygen" dialog)
    extrn GetTickCount / strncpy / GetStockObject / ReleaseDC / InitCommonControls
GetInterfaceInfo + GetMappedFileNameW + the SE* imports (below) are the classic
anti-debug / anti-VM / self-integrity fingerprint used by the protector; the
Reg* call clears registration data; GetSaveFileNameA + ShellExecuteA are the
"export the generated key / open the result" UI plumbing.

The protector is identified from cleartext strings:
    "Safengine Shielden v2.3.7.0"   "shielden_user@safengine.com"
plus the Safengine SDK exports it pulls in dynamically:
    SECheckProtection, SEGetLicenseUserInfoW, SEGetLicenseTrialInfo,
    SECheckHardwareID, SEGetHardwareIDW, SEGetLicenseHash,
    SENotifyLicenseBanned, SEResetTrial, SEAddMemoryGuard, ...
and the section layout (.text raw 0x2400 -> .vdata raw 0xc1800, entry RVA
0xd1014 redirected into .vdata) confirms the real code is virtualized.

================================================================================
HIGH-ENTROPY / .text LIMITATION  (why this is a reimplementation, not a copy)
================================================================================
Safengine Shielden *virtualizes* the original x86 into .vdata bytecode and
encrypts/packs the original .text (raw .text is only 0x2400 bytes for a
0x10000-byte virtual range; .vdata is ~0xc2000 bytes of high-entropy data).
Static disassembly therefore yields only the protector stub and the import
thunks -- the actual "name -> serial" algorithm, its template parser and its
hash/cipher helpers are *inside the VM* and cannot be read statically.
The .rsrc only carries an icon, the common-controls manifest and the version
string.  No md5/sha/base64/des literals survive in cleartext (.vdata only
leaks API names such as GetDesktopWindow / wsprintfW / OpenClipboard and the
Safengine SE* names).  Conclusion: the exact template grammar and the exact
serial algorithm are not statically recoverable from this sample.

This CLI therefore reimplements the *documented capability set* of a keygen
creator with a flexible template engine (INI key=value sections AND embedded
Python) and a real crypto/hash helper set (MD5/SHA-1/SHA-2/CRC32/hex/base64/
DES-ECB).  The DES S-boxes were recovered against a reference DES oracle and
verified with the classic FIPS vector (key 133457799BBCDFF1, PT
0123456789ABCDEF -> CT 85E813540F0AB405).

================================================================================
FEATURE -> SUBCOMMAND MAP
================================================================================
  hash <algo> <text>            the tool's crypto/hash helpers:
                                md5 sha1 sha256 sha512 crc32 hex base64 des
  gen <template> --name NAME    parse a keygen template (INI sections and/or
                                embedded python) and print the serial for NAME
  run <script.py> --name X      run a python algorithm template
                                [--count N]
  info <template>               dump the parsed template structure

Template format accepted by gen/info (flexible, auto-detected):
  1) INI / key=value sections:
         [Keygen]
         Name    = anything
         Key     = md5(name)[:12].upper()        # a python expression ...
         Serial  = {name}-{year}                 # ... or a placeholder string
     The serial is taken from the first of: Serial, Key, Code, Password,
     Token, Reg (case-insensitive); a value is eval'd as a Python expression
     when it references a helper (md5/sha1/...) or an operator, otherwise
     placeholders {name}/{NAME}/%name%/$NAME are substituted.
  2) Embedded Python: a fenced ```python ... ``` block, a <python>...</python>
     block, or a top-level `def generate(name):` / `def keygen(name):` /
     `def make_key(name):` function.  The function's return value is the key;
     failing that a variable named key/serial/result is used; failing that
     anything the block prints is used.

All subcommands are stdlib-only and never touch the network.
"""

import argparse
import base64
import binascii
import hashlib
import io
import os
import re
import sys
import zlib

# =============================================================================
# Pure-Python DES (ECB) -- used by `hash des` and by templates via des().
# S-boxes verified against a reference DES (FIPS 46-3 vector).
# =============================================================================
_IP = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7,
]
_FP = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25,
]
_E = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1,
]
_P = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25,
]
_PC1 = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4,
]
_PC2 = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32,
]
_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
_SBOX = [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7,
     0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8,
     4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0,
     15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10,
     3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5,
     0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15,
     13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8,
     13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1,
     13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7,
     1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15,
     13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9,
     10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4,
     3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9,
     14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6,
     4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14,
     11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11,
     10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8,
     9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6,
     4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1,
     13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6,
     1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2,
     6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7,
     1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2,
     7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8,
     2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
]


def _permute(value, table, width):
    out = 0
    for pos in table:
        out = (out << 1) | ((value >> (width - pos)) & 1)
    return out


def _des_subkeys(key8):
    k = _permute(int.from_bytes(key8, "big"), _PC1, 64)
    c = k >> 28
    d = k & 0xFFFFFFF
    keys = []
    for s in _SHIFTS:
        c = ((c << s) | (c >> (28 - s))) & 0xFFFFFFF
        d = ((d << s) | (d >> (28 - s))) & 0xFFFFFFF
        keys.append(_permute((c << 28) | d, _PC2, 56))
    return keys


def _des_feistel(r, subkey):
    x = _permute(r, _E, 32) ^ subkey
    out = 0
    for i in range(8):
        chunk = (x >> (42 - 6 * i)) & 0x3F
        row = ((chunk & 0x20) >> 4) | (chunk & 1)
        col = (chunk >> 1) & 0xF
        out = (out << 4) | _SBOX[i][row * 16 + col]
    return _permute(out, _P, 32)


def des_crypt_block(block8, key8, encrypt=True):
    """DES-ECB on a single 8-byte block."""
    subkeys = _des_subkeys(key8)
    if not encrypt:
        subkeys = subkeys[::-1]
    b = _permute(int.from_bytes(block8, "big"), _IP, 64)
    left, right = b >> 32, b & 0xFFFFFFFF
    for sk in subkeys:
        left, right = right, left ^ _des_feistel(right, sk)
    return _permute((right << 32) | left, _FP, 64).to_bytes(8, "big")


def des_ecb(data, key8, encrypt=True):
    """DES-ECB over arbitrary bytes (PKCS#7 padding on encrypt)."""
    if len(key8) != 8:
        key8 = (key8 + b"\x00" * 8)[:8]
    out = bytearray()
    if encrypt:
        pad = 8 - (len(data) % 8)
        data = data + bytes([pad]) * pad
        for i in range(0, len(data), 8):
            out += des_crypt_block(data[i:i + 8], key8, True)
    else:
        if len(data) % 8:
            data = data + bytes(8 - (len(data) % 8))
        for i in range(0, len(data), 8):
            out += des_crypt_block(data[i:i + 8], key8, False)
        # strip PKCS#7 padding if it is well-formed
        if out:
            p = out[-1]
            if 1 <= p <= 8 and len(out) >= p and all(b == p for b in out[-p:]):
                del out[-p:]
    return bytes(out)


# =============================================================================
# Hash / crypto helpers exposed to the CLI and to templates.
# =============================================================================
DEFAULT_DES_KEY = b"keygen12"  # 8 bytes


def _as_bytes(text):
    if isinstance(text, bytes):
        return text
    if isinstance(text, bytearray):
        return bytes(text)
    return str(text).encode("utf-8")


def _md5(text):
    return hashlib.md5(_as_bytes(text)).hexdigest()


def _sha1(text):
    return hashlib.sha1(_as_bytes(text)).hexdigest()


def _sha256(text):
    return hashlib.sha256(_as_bytes(text)).hexdigest()


def _sha512(text):
    return hashlib.sha512(_as_bytes(text)).hexdigest()


def _crc32(text):
    return format(zlib.crc32(_as_bytes(text)) & 0xFFFFFFFF, "08x")


def _hexenc(text):
    return _as_bytes(text).hex()


def _hexdec(text):
    try:
        return bytes.fromhex(text)
    except ValueError:
        return b""


def _b64enc(text):
    return base64.b64encode(_as_bytes(text)).decode("ascii")


def _b64dec(text):
    try:
        return base64.b64decode(text)
    except (binascii.Error, ValueError):
        return b""


def _des(text, key=DEFAULT_DES_KEY, encrypt=True):
    if isinstance(key, str):
        key = key.encode("latin1", "ignore")
    return des_ecb(_as_bytes(text), key, encrypt)


# =============================================================================
# Template engine
# =============================================================================
_HELPER_NAMES = {
    "md5": _md5, "sha1": _sha1, "sha256": _sha256, "sha512": _sha512,
    "crc32": _crc32, "hex": _hexenc, "unhex": _hexdec,
    "base64": _b64enc, "b64": _b64enc, "unbase64": _b64dec, "b64decode": _b64dec,
    "des": _des,
}

# A restricted builtins map for eval() of template expressions.
_SAFE_BUILTINS = {
    "len": len, "str": str, "int": int, "hex": _hexenc, "bin": bin,
    "upper": lambda s: str(s).upper(), "lower": lambda s: str(s).lower(),
    "abs": abs, "max": max, "min": min, "sum": sum, "round": round,
    "chr": chr, "ord": ord, "range": range, "enumerate": enumerate,
    "True": True, "False": False, "None": None,
}

_PLACEHOLDER_RE = re.compile(r"\{(\w+)\}|\$\{(\w+)\}|\$\w+|%(\w+)%")
_PY_BLOCK_RE = re.compile(r"```(?:python|py)?\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
_PY_TAG_RE = re.compile(r"<python>(.*?)</python>", re.DOTALL | re.IGNORECASE)
_FUNC_RE = re.compile(r"^\s*def\s+(generate|keygen|make_key|gen_key|serial)\s*\(", re.MULTILINE)


def _bind_name(text, name):
    """Substitute {name}/{NAME}/%name%/$NAME style placeholders."""
    def repl(m):
        token = m.group(1) or m.group(2) or m.group(3) or ""
        low = token.lower()
        if low in ("name", "user", "username"):
            return name.upper() if token.isupper() else name
        return m.group(0)
    # also handle bare $NAME
    text = re.sub(r"\$(NAME|NAME uppercase)", lambda m: name, text)
    text = _PLACEHOLDER_RE.sub(repl, text)
    return text


def _looks_like_expr(value):
    if not value:
        return False
    if re.search(r"\b(md5|sha1|sha256|sha512|crc32|hex|unhex|base64|b64|"
                 r"des)\s*\(", value):
        return True
    # placeholder markers mean this is a template string, not an expression
    if any(ch in value for ch in "{}%$"):
        return False
    # an expression if it has an operator and a name reference
    if re.search(r"[+\-*/]", value) and "name" in value.lower():
        return True
    return False


def _eval_expr(expr, name):
    env = dict(_SAFE_BUILTINS)
    env.update(_HELPER_NAMES)
    env["name"] = name
    env["NAME"] = name.upper()
    try:
        return str(eval(expr, {"__builtins__": _SAFE_BUILTINS}, env))
    except Exception:
        return _bind_name(expr, name)


def _extract_py_blocks(text):
    blocks = []
    for m in _PY_BLOCK_RE.finditer(text):
        blocks.append(m.group(1))
    for m in _PY_TAG_RE.finditer(text):
        blocks.append(m.group(1))
    return blocks


def _parse_ini(text):
    """Parse INI-ish [section] + key=value, tolerant of stray lines."""
    sections = {}
    current = "root"
    sections[current] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue
        if line.startswith("[") and line.endswith("]"):
            current = line[1:-1].strip()
            sections.setdefault(current, {})
            continue
        if "=" in line:
            key, _, val = line.partition("=")
            sections[current][key.strip()] = val.strip()
    return sections


def parse_template(text):
    """Auto-detect and parse a keygen template into a structure dict."""
    py_blocks = _extract_py_blocks(text)
    has_func = bool(_FUNC_RE.search(text))
    sections = _parse_ini(text)
    return {
        "raw": text,
        "sections": sections,
        "py_blocks": py_blocks,
        "has_function": has_func,
        "is_python": bool(py_blocks) or has_func,
    }


def _serial_from_sections(sections, name):
    priority = ["serial", "key", "code", "password", "passwd", "token", "reg",
                "registration", "license", "result"]
    flat = {}
    for sec in sections.values():
        for k, v in sec.items():
            flat.setdefault(k.lower(), v)
    for want in priority:
        if want in flat:
            val = flat[want]
            if _looks_like_expr(val):
                return _eval_expr(val, name)
            return _bind_name(val, name)
    # fall back: any value that mentions name
    for k, v in flat.items():
        if "name" in v.lower():
            return _bind_name(v, name)
    return ""


def _run_py_block(code, name, index=0):
    """Execute an embedded python block and return the produced key."""
    env = dict(_SAFE_BUILTINS)
    env.update(_HELPER_NAMES)
    env["name"] = name
    env["NAME"] = name.upper()
    env["index"] = index
    buf = io.StringIO()
    old = sys.stdout
    sys.stdout = buf
    try:
        exec(compile(code, "<template>", "exec"), env)
        result = None
        for fn in ("generate", "keygen", "make_key", "gen_key", "serial"):
            if callable(env.get(fn)):
                func = env[fn]
                try:
                    import inspect
                    nargs = len(inspect.signature(func).parameters)
                except (TypeError, ValueError):
                    nargs = 1
                result = func(name, index) if nargs >= 2 else func(name)
                break
        if result is None:
            for var in ("key", "serial", "result", "output"):
                if var in env and not callable(env[var]):
                    result = env[var]
                    break
    finally:
        sys.stdout = old
    printed = buf.getvalue().strip()
    if result is not None:
        return str(result).strip()
    return printed


def evaluate_template(parsed, name):
    """Produce the serial for `name` from a parsed template."""
    if parsed["is_python"]:
        code = "\n".join(parsed["py_blocks"]) if parsed["py_blocks"] else parsed["raw"]
        key = _run_py_block(code, name)
        if key:
            return key
        # fall through to INI if the python produced nothing
    return _serial_from_sections(parsed["sections"], name)


# =============================================================================
# Subcommands
# =============================================================================
def cmd_hash(args):
    algo = args.algo.lower()
    data = args.text.encode("utf-8")
    if algo == "md5":
        print(_md5(data))
    elif algo == "sha1":
        print(_sha1(data))
    elif algo == "sha256":
        print(_sha256(data))
    elif algo == "sha512":
        print(_sha512(data))
    elif algo == "crc32":
        print(_crc32(data))
    elif algo in ("hex", "hexenc", "tohex"):
        print(_hexenc(data))
    elif algo in ("unhex", "fromhex", "hexdec"):
        sys.stdout.write(_hexdec(args.text).decode("latin1"))
    elif algo in ("base64", "b64", "tobase64"):
        print(_b64enc(data))
    elif algo in ("unbase64", "b64decode", "frombase64"):
        sys.stdout.write(_b64dec(args.text).decode("latin1"))
    elif algo in ("des", "desecb"):
        key = args.key if args.key else DEFAULT_DES_KEY
        out = _des(data, key, encrypt=not args.decrypt)
        print(out.hex())
    else:
        sys.stderr.write("unknown algo: %s\n" % args.algo)
        sys.stderr.write("supported: md5 sha1 sha256 sha512 crc32 hex unhex "
                         "base64 unbase64 des\n")
        return 2
    return 0


def cmd_gen(args):
    try:
        with open(args.template, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        sys.stderr.write("cannot read template: %s\n" % exc)
        return 2
    parsed = parse_template(text)
    key = evaluate_template(parsed, args.name)
    print(key)
    return 0


def cmd_run(args):
    try:
        with open(args.script, "r", encoding="utf-8", errors="replace") as fh:
            code = fh.read()
    except OSError as exc:
        sys.stderr.write("cannot read script: %s\n" % exc)
        return 2
    count = max(1, args.count)
    blocks = _extract_py_blocks(code)
    if blocks:
        code = "\n".join(blocks)
    for i in range(count):
        name = args.name if (count == 1 or i == 0) else "%s%d" % (args.name, i)
        key = _run_py_block(code, name, i)
        print(key)
    return 0


def cmd_info(args):
    try:
        with open(args.template, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError as exc:
        sys.stderr.write("cannot read template: %s\n" % exc)
        return 2
    parsed = parse_template(text)
    print("== template: %s ==" % args.template)
    print("detected : %s" % ("embedded-python" if parsed["is_python"]
                             else "key=value sections"))
    if parsed["py_blocks"]:
        print("py blocks: %d" % len(parsed["py_blocks"]))
        for n, blk in enumerate(parsed["py_blocks"]):
            first = blk.strip().splitlines()[0] if blk.strip() else ""
            print("  [%d] %s" % (n, first[:70]))
    if parsed["has_function"]:
        print("function : yes (generate/keygen/make_key/...)")
    print("sections : %d" % len(parsed["sections"]))
    for sec, kv in parsed["sections"].items():
        print("  [%s]" % sec)
        for k, v in kv.items():
            print("    %s = %s" % (k, v))
    # show a sample evaluation
    sample = "DemoUser"
    print("sample gen --name %s -> %s" % (sample, evaluate_template(parsed, sample)))
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="keygencreator_py",
        description="Python CLI reimplementation of 'keygen creator' v2.1.0.0 "
                    "(Safengine Shielden virtualized original).",
        epilog="subcommands: hash, gen, run, info")
    sub = p.add_subparsers(dest="command")

    h = sub.add_parser("hash", help="hash / encode text with a helper")
    h.add_argument("algo", help="md5 sha1 sha256 sha512 crc32 hex unhex "
                                "base64 unbase64 des")
    h.add_argument("text", help="input text")
    h.add_argument("--key", default=None, help="DES key (default 'keygen12')")
    h.add_argument("--decrypt", action="store_true", help="DES decrypt instead")
    h.set_defaults(func=cmd_hash)

    g = sub.add_parser("gen", help="generate a key from a template + name")
    g.add_argument("template", help="template file (INI and/or embedded python)")
    g.add_argument("--name", required=True, help="user name to key")
    g.set_defaults(func=cmd_gen)

    r = sub.add_parser("run", help="run a python algorithm template")
    r.add_argument("script", help="python script defining generate(name)")
    r.add_argument("--name", required=True, help="user name to key")
    r.add_argument("--count", type=int, default=1, help="number of keys (default 1)")
    r.set_defaults(func=cmd_run)

    i = sub.add_parser("info", help="dump parsed template structure")
    i.add_argument("template", help="template file")
    i.set_defaults(func=cmd_info)
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "func", None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())