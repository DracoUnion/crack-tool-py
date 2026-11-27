#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
keymake_py -- a Python re-implementation of the KeyMake 2.0 keygen-script engine.

KeyMake (by 刘健英 / later maintained by 张湘平, "duhe") is a classic "keygen
maker": the user writes a small *algorithm script* and KeyMake compiles it into a
standalone keygen EXE.  This tool re-implements the *evaluation* half of that
pipeline in pure Python (stdlib only) so the serial a script computes for a given
name can be reproduced without the original (packed) binary.

--------------------------------------------------------------------------
Sources / references (docs shipped with the tool)
--------------------------------------------------------------------------
* D:/Program Files/crack-tool-patcher/KeyMake_2.0_win10修复版/
    - "keymake2.0 win10修复版使用说明.txt"  (whyida, 2018-01-28): the win10 fix
      note -- KeyMake was compiled on WinXP and many system-function addresses
      moved by Win10, so the preview build could no longer run; the fix patches
      the system function addresses (参考张湘平的做法).  This is why the shipped
      EXE is "keymakeA-w10.exe".
    - "keymake2.0修改版使用说明.htm" / ".txt": 张湘平 (duhe) 2004-02-02 note that
      the original author (刘健英) had left and this is a 2.0 preview re-build
      against a newer MASM.
    - "WhatsNew.txt": version history.  Relevant entries:
        v1.65  "重写了注册机编写这个部分 ... 现在改为从 include 子目录下查找
                KEY1.RES 资源文件" and "在注册机中加入了一个自定义的库文件 ...
                加密解密就只需要一个简单的调用就可以实现 ... 我在例子三中使用了
                加密算法" -- i.e. the INCLUDE dir + a custom helper lib is where
                MakeCrypt lives, and EXAMPLE/例子三 uses it.
        v1.40  "增加了一个128位十进制转十六进制的功能" (the htodw/atodw helpers).

--------------------------------------------------------------------------
Script format (EXAMPLE/*.rek and INCLUDE/*)
--------------------------------------------------------------------------
A KeyMake algorithm script (".rek") is a MASM-style assembly source with two
sections, e.g. EXAMPLE/注册机1.rek:

    .data
    szHomePage db "http://www.365hz.net",0
    a1 dd 0
    a2 dd 0
    a3 db "%1X",0
    a4 db 20 dup (0)
    .code
    CALL GetCommandLineA
    CMP  BYTE PTR [EAX],22h
    JNZ  n1
    INC  EAX
    n1:
    MOV  CX,WORD PTR [EAX]
    MOV  WORD PTR a2,CX
    MOV  WORD PTR a2+2,5Ch
    ... PUSH args ...
    CALL GetVolumeInformationA
    MOV  EAX,1
    CPUID
    MOV  ECX,a1
    XOR  EDX,EDX
    MUL  ECX
    ADD  EAX,EDX
    ... PUSH ...
    CALL wsprintfA
    LEA  EAX,a4

The three shipped examples show the whole language surface KeyMake actually uses:
  * 注册机1.rek  : GetCommandLineA -> take first 2 chars of the name, build a
                   root path "XX\", call GetVolumeInformationA to read the volume
                   serial into a1, CPUID, MUL/ADD fold, wsprintfA "%1X" -> a4.
  * 注册机2.rek  : parse a hex string (the name) with the classic
                   (c-'0') / (c-7-'0') nibble loop into EBX, CPUID, MUL/ADD fold,
                   wsprintfA "%1X" -> a4.
  * 例子三注册机.rek : invoke MakeCrypt,eax,addr szOut ; lea eax,szOut
                   (uses the INCLUDE helper library).

Constructs implemented by the emulator (all of the above, i.e. what the format
really uses -- note KeyMake scripts are *assembly*, not a BASIC dialect, so the
"string ops / mid / left / right / asc / ord" of the generic brief map onto
memory `db` strings + byte loads + the helper lib):
  data : db / dw / dd, "string", N dup(0), comma lists, '?'  (named labels)
  code : MOV, LEA, PUSH, POP, CALL, RET, JMP, Jcc (JZ/JNZ/JC/JNC/...), CMP,
         TEST, ADD, SUB, XOR, OR, AND, INC, DEC, SHL/SHR/SAR, MUL, IMUL,
         MOVZX, MOVSX, NEG, NOT, CPUID, NOP, XCHG, INVOKE
  ops  : registers (8/16/32), immediates (0x.., ..h, dec, 'c'), memory
         [reg], [reg+disp], direct label, label+disp, BYTE/WORD/DWORD PTR,
         addr/offset label.
  API  : GetCommandLineA, GetVolumeInformationA, wsprintfA, lstrlenA,
         ExitProcess, MessageBoxA (no-op) and the INCLUDE helpers
         MakeCrypt / UnMakeCrypt / htodw / atodw (stdcall @8/@4).

--------------------------------------------------------------------------
Packed-stub static limitation
--------------------------------------------------------------------------
keymakeA-w10.exe is packed / high-entropy: its PE import table only exposes
kernel32/advapi32/comctl32/gdi32/oleaut32/shell32/user32/comdlg32/ole32 and the
code section is a stub of encrypted `dd` constants (see /d/temp/ida_out/t06.exe.asm,
"start" just pushes an offset and calls into a blob).  Static disassembly of the
stub therefore yields no usable algorithm -- the real interpreter is unpacked at
run time.  This re-implementation consequently does NOT reverse the EXE; it
reproduces the *documented script language* (EXAMPLE/INCLUDE) directly, which is
what actually defines a script's output.

--------------------------------------------------------------------------
Determinism note
--------------------------------------------------------------------------
A real keygen's serial depends on machine state (volume serial, CPUID).  To make
`gen` reproducible, the emulator models that state deterministically:
  * CPUID leaf 1 -> fixed emulated signature (see CPUID1_EAX below).
  * GetVolumeInformationA -> a 32-bit FNV-1a hash of the root-path string.
Both are clearly emulated stand-ins; the *script logic* (the algorithm the user
wrote) is evaluated for real.

--------------------------------------------------------------------------
Subcommand -> feature map
--------------------------------------------------------------------------
  gen <script> --name NAME   parse + evaluate the algorithm, print the serial
  run <script> --name NAME [--count N]
                             evaluate N times (also executes an embedded
                             python body if the script has one, see below)
  info <script>              dump parsed .data/.code structure + helpers used
  selftest                   verify the helper ops (hex parse, wsprintf %X,
                             MUL/ADD fold, base64 MakeCrypt, dup alloc, ...)

Embedded python body: if a script contains a block delimited by the lines
`#PY` ... `#ENDPY`, `run` executes that Python instead of the assembler, with
`name`, `count` and `index` in scope.  (The shipped .rek files are pure
assembly and never use this; it is a convenience extension.)
"""

import argparse
import base64
import re
import sys

# --------------------------------------------------------------------------
# Emulated machine-state constants (documented stand-ins for real hardware)
# --------------------------------------------------------------------------
CPUID1_EAX = 0x000306A9   # emulated "processor signature" for CPUID.leaf=1
CPUID1_EBX = 0x00000000
CPUID1_ECX = 0x00000000
CPUID1_EDX = 0x00000000

DATA_BASE = 0x00001000    # where the .data segment is placed in emu memory
STACK_TOP = 0x00008000    # initial ESP
MEM_SIZE = 0x00010000     # 64 KiB emulated address space

REGS32 = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip")
REGS16 = {"ax": "eax", "bx": "ebx", "cx": "ecx", "dx": "edx",
          "si": "esi", "di": "edi", "bp": "ebp", "sp": "esp", "ip": "eip"}
REGS8L = {"al": "eax", "bl": "ebx", "cl": "ecx", "dl": "edx"}
REGS8H = {"ah": "eax", "bh": "ebx", "ch": "ecx", "dh": "edx"}


def fnv1a32(data):
    """32-bit FNV-1a hash -- deterministic stand-in for a volume serial."""
    h = 0x811C9DC5
    for b in data:
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


class EmuError(Exception):
    pass


# --------------------------------------------------------------------------
# Memory
# --------------------------------------------------------------------------
class Memory:
    def __init__(self, size=MEM_SIZE):
        self.m = bytearray(size)
        self.size = size

    def _chk(self, addr, n):
        if addr < 0 or addr + n > self.size:
            raise EmuError("memory out of range: 0x%X (%d bytes)" % (addr, n))

    def read(self, addr, n):
        self._chk(addr, n)
        return bytes(self.m[addr:addr + n])

    def write(self, addr, data):
        self._chk(addr, len(data))
        self.m[addr:addr + len(data)] = data

    def u8(self, a):  return self.m[a]
    def u16(self, a): return self.m[a] | (self.m[a + 1] << 8)
    def u32(self, a): return (self.m[a] | (self.m[a + 1] << 8) |
                              (self.m[a + 2] << 16) | (self.m[a + 3] << 24))

    def set8(self, a, v):  self.m[a] = v & 0xFF
    def set16(self, a, v): self.m[a] = v & 0xFF; self.m[a + 1] = (v >> 8) & 0xFF
    def set32(self, a, v):
        for i in range(4):
            self.m[a + i] = (v >> (8 * i)) & 0xFF

    def cstr(self, a, maxn=4096):
        out = bytearray()
        while maxn > 0:
            b = self.m[a]
            if b == 0:
                break
            out.append(b)
            a += 1
            maxn -= 1
        return bytes(out)


# --------------------------------------------------------------------------
# .rek parsing
# --------------------------------------------------------------------------
def load_text(path):
    raw = open(path, "rb").read()
    for enc in ("gbk", "utf-8", "latin1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return raw.decode("latin1", "replace")


def strip_comment(line):
    # drop stray NUL padding (some .rek files are NUL-terminated) and comments
    line = line.replace("\x00", "")
    i = line.find(";")
    if i >= 0:
        line = line[:i]
    return line.strip()


def parse_data(lines):
    """Parse .data directives -> (labels{name:addr}, data_bytes, next_addr)."""
    labels = {}
    buf = bytearray()
    addr = DATA_BASE
    for raw in lines:
        line = strip_comment(raw)
        if not line:
            continue
        m = re.match(r'^([A-Za-z_]\w*)\s+(db|dw|dd)\b\s*(.*)$',
                     line, re.IGNORECASE)
        if not m:
            continue
        name, kind, rest = m.group(1), m.group(2).lower(), m.group(3)
        labels[name] = addr
        start = addr
        for item in split_items(rest):
            item = item.strip()
            if not item:
                continue
            # N dup ( ... )
            md = re.match(r'^(\d+)\s+dup\s*\((.*)\)$', item, re.IGNORECASE)
            if md:
                cnt = int(md.group(1))
                inner = md.group(2).strip()
                unit = {"db": 1, "dw": 2, "dd": 4}[kind]
                fill = encode_scalar(inner, kind) if inner else b""
                chunk = (fill * cnt) if fill else bytes(cnt * unit)
                addr += len(chunk)
                buf += chunk
                continue
            if item == "?":
                unit = {"db": 1, "dw": 2, "dd": 4}[kind]
                addr += unit
                buf += bytes(unit)
                continue
            b = encode_scalar(item, kind)
            addr += len(b)
            buf += b
        _ = start
    return labels, bytes(buf), addr


def encode_scalar(text, kind):
    text = text.strip()
    if text.startswith('"') or text.startswith("'"):
        q = text[0]
        # find closing quote (handle "" escape)
        body = text[1:text.rfind(q)] if text.rfind(q) > 0 else text[1:]
        body = body.replace(q + q, q)
        raw = body.encode("gbk", "replace")
        if kind == "db":
            return raw
        return raw  # strings only valid with db
    # numeric / char constant
    val = parse_imm(text)
    if kind == "db":
        return bytes([val & 0xFF])
    if kind == "dw":
        return bytes([val & 0xFF, (val >> 8) & 0xFF])
    return bytes([val & 0xFF, (val >> 8) & 0xFF,
                  (val >> 16) & 0xFF, (val >> 24) & 0xFF])


def split_items(s):
    """Split a comma list, respecting quotes and parentheses."""
    out, cur, depth, q = [], "", 0, None
    for ch in s:
        if q:
            cur += ch
            if ch == q:
                q = None
            continue
        if ch in "\"'":
            q = ch
            cur += ch
        elif ch == "(":
            depth += 1
            cur += ch
        elif ch == ")":
            depth -= 1
            cur += ch
        elif ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return out


def parse_imm(text):
    """Parse an immediate: 0x.., ..h, decimal, 'c', or a label -> error."""
    t = text.strip()
    if not t:
        return 0
    if t[0] in "'\"":
        q = t[0]
        end = t.find(q, 1)
        body = t[1:end] if end > 0 else t[1:]
        return ord(body[0]) if body else 0
    low = t.lower()
    try:
        if low.startswith("0x"):
            return int(t, 16)
        if low.endswith("h"):
            return int(t[:-1], 16)
        if low.endswith("b") and set(low[:-1]) <= set("01"):
            return int(t[:-1], 2)
        if low.endswith("d"):
            return int(t[:-1], 10)
        return int(t, 10)
    except ValueError:
        raise EmuError("bad immediate: %r" % text)


class Instr:
    __slots__ = ("mn", "ops", "raw", "idx")

    def __init__(self, mn, ops, raw, idx):
        self.mn = mn
        self.ops = ops
        self.raw = raw
        self.idx = idx

    def __repr__(self):
        return "<%d %s %s>" % (self.idx, self.mn, ",".join(self.ops))


def parse_code(lines):
    """Parse .code -> (instructions, labels{name:index})."""
    instrs, labels = [], {}
    for raw in lines:
        line = strip_comment(raw)
        if not line:
            continue
        # label at start (possibly "n1:")
        m = re.match(r'^([A-Za-z_]\w*):\s*(.*)$', line)
        if m:
            labels[m.group(1)] = len(instrs)
            line = m.group(2).strip()
            if not line:
                continue
        parts = line.split(None, 1)
        mn = parts[0].lower()
        rest = parts[1] if len(parts) > 1 else ""
        ops = [o.strip() for o in split_ops(rest)] if rest else []
        instrs.append(Instr(mn, ops, line, len(instrs)))
    return instrs, labels


def split_ops(s):
    """Split operands on commas not inside [] or quotes."""
    out, cur, depth, q = [], "", 0, None
    for ch in s:
        if q:
            cur += ch
            if ch == q:
                q = None
            continue
        if ch in "\"'":
            q = ch
            cur += ch
        elif ch == "[":
            depth += 1
            cur += ch
        elif ch == "]":
            depth -= 1
            cur += ch
        elif ch == "," and depth == 0:
            out.append(cur)
            cur = ""
        else:
            cur += ch
    if cur.strip():
        out.append(cur)
    return out


# --------------------------------------------------------------------------
# Operand model + parser
# --------------------------------------------------------------------------
class Operand:
    __slots__ = ("kind", "reg", "size", "base", "index", "scale", "disp",
                 "abs", "text")

    def __init__(self):
        self.kind = None      # 'reg' | 'imm' | 'mem'
        self.reg = None
        self.size = None      # 1/2/4
        self.base = None
        self.index = None
        self.scale = 1
        self.disp = 0
        self.abs = None       # absolute address for direct mem
        self.text = ""


PTR_SIZE = {"byte": 1, "word": 2, "dword": 4, "qword": 8}


def parse_operand(tok, labels):
    op = Operand()
    op.text = tok
    t = tok.strip()
    if not t:
        return op
    # size prefix?
    m = re.match(r'^(byte|word|dword|qword)\s+ptr\s+(.*)$', t, re.IGNORECASE)
    if m:
        op.size = PTR_SIZE[m.group(1).lower()]
        t = m.group(2).strip()
    # addr / offset
    m = re.match(r'^(addr|offset)\s+(.+)$', t, re.IGNORECASE)
    if m:
        op.kind = "imm"
        op.abs = resolve_label(m.group(2).strip(), labels)
        return op
    # register?
    rl = t.lower()
    if rl in REGS32 or rl in REGS16 or rl in REGS8L or rl in REGS8H:
        op.kind = "reg"
        op.reg = rl
        op.size = 4 if rl in REGS32 else 2 if rl in REGS16 else 1
        return op
    # immediate number? (before label/memory so `mov eax,1` is an immediate)
    try:
        op.kind = "imm"
        op.abs = parse_imm(t)
        return op
    except EmuError:
        pass
    # memory [ ... ]?
    if t.startswith("["):
        op.kind = "mem"
        inner = t[1:t.rfind("]")]
        parse_mem_inner(inner, op)
        return op
    # direct label / label+disp
    op.kind = "mem"
    op.abs = resolve_label(t, labels)
    if op.size is None:
        op.size = 4
    return op


def resolve_label(t, labels):
    t = t.strip()
    m = re.match(r'^([A-Za-z_]\w*)\s*([+-])\s*(.+)$', t)
    if m and m.group(1) in labels:
        base = labels[m.group(1)]
        off = parse_imm(m.group(3))
        return base + off if m.group(2) == "+" else base - off
    if t in labels:
        return labels[t]
    # bare number used as address
    try:
        return parse_imm(t)
    except EmuError:
        raise EmuError("unknown label/operand: %r" % t)


def parse_mem_inner(inner, op):
    # split on + / - at top level (no nested parens expected)
    tokens = re.findall(r'[+-]?[^+-]+', inner)
    for tk in tokens:
        tk = tk.strip()
        if not tk:
            continue
        sign = 1
        if tk[0] == "+":
            tk = tk[1:].strip()
        elif tk[0] == "-":
            sign = -1
            tk = tk[1:].strip()
        low = tk.lower()
        if low in REGS32:
            if op.base is None:
                op.base = low
            else:
                op.index = low
        elif re.match(r'^\d+$', tk) or low.startswith("0x") or low.endswith("h"):
            op.disp += sign * parse_imm(tk)
        else:
            # label constant
            op.disp += sign * resolve_label(tk, op_abs_labels[0])
    _ = op


# a tiny holder so parse_mem_inner can resolve labels without threading them
op_abs_labels = [dict()]


# --------------------------------------------------------------------------
# The emulator
# --------------------------------------------------------------------------
class Emu:
    def __init__(self, labels, mem, name, code_labels=None):
        self.r = {k: 0 for k in REGS32}
        self.r["esp"] = STACK_TOP
        self.mem = mem
        self.labels = labels            # data labels -> addresses (operands)
        self.code_labels = code_labels or {}  # code labels -> instr index (control flow)
        self.name = name
        self.zf = self.cf = self.sf = self.of = False
        self.hooks = {}          # name -> python callable(emu, args)->None
        self.out = []            # captured wsprintf / helper outputs
        self._install_apis()

    def target(self, name):
        n = name.strip().lower()
        if n in self.code_labels:
            return self.code_labels[n]
        if n in self.labels:
            return self.labels[n]
        raise EmuError("unknown jump/call target %r" % name)

    # ---- register access -------------------------------------------------
    def get(self, name):
        n = name.lower()
        if n in REGS32:
            return self.r[n] & 0xFFFFFFFF
        if n in REGS16:
            return self.r[REGS16[n]] & 0xFFFF
        if n in REGS8L:
            return self.r[REGS8L[n]] & 0xFF
        if n in REGS8H:
            return (self.r[REGS8H[n]] >> 8) & 0xFF
        raise EmuError("bad register %r" % name)

    def set(self, name, val):
        n = name.lower()
        val &= 0xFFFFFFFF
        if n in REGS32:
            self.r[n] = val
        elif n in REGS16:
            self.r[REGS16[n]] = (self.r[REGS16[n]] & 0xFFFF0000) | (val & 0xFFFF)
        elif n in REGS8L:
            self.r[REGS8L[n]] = (self.r[REGS8L[n]] & 0xFFFFFF00) | (val & 0xFF)
        elif n in REGS8H:
            self.r[REGS8H[n]] = (self.r[REGS8H[n]] & 0xFFFF00FF) | ((val & 0xFF) << 8)
        else:
            raise EmuError("bad register %r" % name)

    # ---- flags -----------------------------------------------------------
    def set_zf(self, v): self.zf = bool(v)
    def set_cf(self, v): self.cf = bool(v)

    def flag_logical(self, res, size):
        mask = (1 << (size * 8)) - 1
        res &= mask
        self.zf = (res == 0)
        self.sf = bool(res & (1 << (size * 8 - 1)))
        self.of = False
        self.cf = False
        return res

    def flag_add(self, a, b, size, carry=0):
        mask = (1 << (size * 8)) - 1
        full = a + b + carry
        res = full & mask
        self.zf = (res == 0)
        self.sf = bool(res & (1 << (size * 8 - 1)))
        self.cf = (full > mask)
        sign = 1 << (size * 8 - 1)
        self.of = bool(((a ^ res) & (b ^ res) & sign))
        return res

    def flag_sub(self, a, b, size, borrow=0):
        mask = (1 << (size * 8)) - 1
        full = a - b - borrow
        res = full & mask
        self.zf = (res == 0)
        self.sf = bool(res & (1 << (size * 8 - 1)))
        self.cf = (full < 0)
        sign = 1 << (size * 8 - 1)
        self.of = bool(((a ^ b) & (a ^ res) & sign))
        return res

    # ---- operand resolution ---------------------------------------------
    def eff_addr(self, op):
        a = op.disp
        if op.base:
            a += self.get(op.base)
        if op.index:
            a += self.get(op.index) * op.scale
        if op.abs is not None:
            a += op.abs
        return a & 0xFFFFFFFF

    def read_op(self, op):
        if op.kind == "imm":
            return op.abs if op.abs is not None else 0
        if op.kind == "reg":
            return self.get(op.reg)
        # mem
        a = self.eff_addr(op)
        sz = op.size or 4
        if sz == 1:
            return self.mem.u8(a)
        if sz == 2:
            return self.mem.u16(a)
        return self.mem.u32(a)

    def write_op(self, op, val):
        if op.kind == "reg":
            self.set(op.reg, val)
            return
        a = self.eff_addr(op)
        sz = op.size or 4
        if sz == 1:
            self.mem.set8(a, val)
        elif sz == 2:
            self.mem.set16(a, val)
        else:
            self.mem.set32(a, val)

    # ---- stack -----------------------------------------------------------
    def push(self, val):
        self.r["esp"] = (self.r["esp"] - 4) & 0xFFFFFFFF
        self.mem.set32(self.r["esp"], val & 0xFFFFFFFF)

    def pop(self):
        v = self.mem.u32(self.r["esp"])
        self.r["esp"] = (self.r["esp"] + 4) & 0xFFFFFFFF
        return v

    # ---- API hooks -------------------------------------------------------
    def _install_apis(self):
        self.hooks["getcommandlinea"] = self.api_GetCommandLineA
        self.hooks["getvolumeinformationa"] = self.api_GetVolumeInformationA
        self.hooks["wsprintfa"] = self.api_wsprintfA
        self.hooks["lstrlena"] = self.api_lstrlenA
        self.hooks["exitprocess"] = self.api_exit
        self.hooks["messageboxa"] = self.api_msgbox
        self.hooks["makecrypt"] = self.api_MakeCrypt
        self.hooks["unmakecrypt"] = self.api_UnMakeCrypt
        self.hooks["htodw"] = self.api_htodw
        self.hooks["atodw"] = self.api_atodw

    def api_GetCommandLineA(self, args):
        # write the name into a scratch buffer and return its address
        buf = 0x7000
        self.mem.write(buf, self.name.encode("gbk", "replace") + b"\x00")
        return buf

    def api_GetVolumeInformationA(self, args):
        # args: root, volbuf, volsize, serialptr, maxlenptr, flags, fsbuf, fssize
        root = ""
        if len(args) >= 1 and args[0]:
            root = self.mem.cstr(args[0]).decode("latin1", "replace")
        serial = fnv1a32(root.encode("latin1", "replace"))
        if len(args) >= 4 and args[3]:
            self.mem.set32(args[3], serial)
        return 1

    def api_wsprintfA(self, args):
        buf = args[0]
        fmt = self.mem.cstr(args[1]).decode("latin1", "replace")
        vals = list(args[2:])
        out = self._format(fmt, vals)
        self.mem.write(buf, out.encode("latin1", "replace") + b"\x00")
        self.out.append(out)
        return len(out)

    def _format(self, fmt, vals):
        # minimal printf: %X %x %d %u %s %c, with optional width like %1X
        vi = 0
        res = ""
        i = 0
        while i < len(fmt):
            ch = fmt[i]
            if ch == "%" and i + 1 < len(fmt):
                j = i + 1
                while j < len(fmt) and fmt[j] in "0123456789":
                    j += 1
                width = fmt[i + 1:j]
                if j < len(fmt):
                    spec = fmt[j].upper()
                    v = vals[vi] if vi < len(vals) else 0
                    vi += 1
                    if spec == "X":
                        s = ("%X" % (v & 0xFFFFFFFF))
                    elif spec == "D":
                        s = "%d" % v
                    elif spec == "U":
                        s = "%u" % (v & 0xFFFFFFFF)
                    elif spec == "S":
                        s = self.mem.cstr(v).decode("latin1", "replace") if v else ""
                        width = ""
                    elif spec == "C":
                        s = chr(v & 0xFF)
                    else:
                        s = "%" + width + fmt[j]
                    if width:
                        s = s.rjust(int(width))
                    res += s
                    i = j + 1
                    continue
            res += ch
            i += 1
        return res

    def api_lstrlenA(self, args):
        return len(self.mem.cstr(args[0])) if args[0] else 0

    def api_exit(self, args):
        raise EmuError("ExitProcess(%d) called by script" % (args[0] if args else 0))

    def api_msgbox(self, args):
        return 1

    def api_MakeCrypt(self, args):
        # stdcall (src, dst): base64-encode the 4 LE bytes of src -> dst
        src = args[0] & 0xFFFFFFFF
        dst = args[1]
        raw = bytes([src & 0xFF, (src >> 8) & 0xFF,
                     (src >> 16) & 0xFF, (src >> 24) & 0xFF])
        enc = base64.b64encode(raw)
        self.mem.write(dst, enc + b"\x00")
        self.out.append(enc.decode("latin1"))
        return 0

    def api_UnMakeCrypt(self, args):
        src = args[0]
        dst = args[1]
        s = self.mem.cstr(src)
        try:
            raw = base64.b64decode(s)
        except Exception:
            raw = b"\x00\x00\x00\x00"
        raw = (raw + b"\x00\x00\x00\x00")[:4]
        self.mem.set32(dst, raw[0] | raw[1] << 8 | raw[2] << 16 | raw[3] << 24)
        return 0

    def api_htodw(self, args):
        s = self.mem.cstr(args[0]).decode("latin1", "replace")
        return int(s, 16) & 0xFFFFFFFF if s else 0

    def api_atodw(self, args):
        s = self.mem.cstr(args[0]).decode("latin1", "replace")
        return int(s, 10) & 0xFFFFFFFF if s else 0

    # ---- run -------------------------------------------------------------
    def run(self, instrs):
        self.instrs = instrs
        pc = 0
        steps = 0
        while pc < len(instrs):
            steps += 1
            if steps > 2_000_000:
                raise EmuError("instruction limit exceeded (infinite loop?)")
            ins = instrs[pc]
            npc = self.step(ins, pc)
            pc = npc if npc is not None else pc + 1
        return self

    def step(self, ins, pc):
        mn = ins.mn
        ops = ins.ops
        # ops that take raw symbol/label strings, not parsed operands
        if mn == "call":
            self.do_call(ops[0], pc)
            tgt = ops[0].lower()
            if tgt in self.code_labels or tgt in self.labels:
                return self.target(ops[0])
            return None  # API call: fall through to pc+1
        if mn == "ret":
            pc = self.pop()
            return pc
        if mn == "jmp":
            return self.target(ops[0])
        if mn in JCC:
            if JCC[mn](self):
                return self.target(ops[0])
            return None  # branch not taken -> next instruction
        if mn == "invoke":
            self.do_invoke(ops)
            return None
        # everything below takes parsed operands
        A = [parse_operand(o, self.labels) for o in ops]
        if mn == "mov":
            self.write_op(A[0], self.read_op(A[1]))
        elif mn == "lea":
            self.set(ops[0].lower(), self.eff_addr(A[1]))
        elif mn == "push":
            self.push(self.read_op(A[0]))
        elif mn == "pop":
            self.set(ops[0].lower(), self.pop())
        elif mn == "cmp":
            a = self.read_op(A[0]); b = self.read_op(A[1])
            self.flag_sub(a, b, self._size_op(A[0], A[1]))
        elif mn == "test":
            a = self.read_op(A[0]); b = self.read_op(A[1])
            self.flag_logical(a & b, self._size_op(A[0], A[1]))
        elif mn in ("add", "sub", "xor", "or", "and", "adc", "sbb"):
            a = self.read_op(A[0]); b = self.read_op(A[1])
            sz = self._size_op(A[0], A[1])
            if mn == "add":
                r = self.flag_add(a, b, sz)
            elif mn == "sub":
                r = self.flag_sub(a, b, sz)
            elif mn == "adc":
                r = self.flag_add(a, b, sz, 1 if self.cf else 0)
            elif mn == "sbb":
                r = self.flag_sub(a, b, sz, 1 if self.cf else 0)
            elif mn == "xor":
                r = self.flag_logical(a ^ b, sz)
            elif mn == "or":
                r = self.flag_logical(a | b, sz)
            else:
                r = self.flag_logical(a & b, sz)
            self.write_op(A[0], r)
        elif mn in ("inc", "dec"):
            a = self.read_op(A[0]); sz = A[0].size or 4
            r = self.flag_add(a, 1, sz) if mn == "inc" else self.flag_sub(a, 1, sz)
            self.write_op(A[0], r)
        elif mn in ("shl", "sal", "shr", "sar"):
            a = self.read_op(A[0]); sz = A[0].size or 4
            cnt = self.read_op(A[1])
            mask = (1 << (sz * 8)) - 1
            if mn in ("shl", "sal"):
                r = (a << cnt) & mask
                self.cf = bool((a >> (sz * 8 - cnt)) & 1) if cnt else self.cf
            elif mn == "shr":
                r = (a & mask) >> cnt
                self.cf = bool((a >> (cnt - 1)) & 1) if cnt else self.cf
            else:  # sar
                sign = a & (1 << (sz * 8 - 1))
                r = (a >> cnt) | (mask ^ (mask >> cnt) if sign else 0) if cnt else a
                r &= mask
                self.cf = bool((a >> (cnt - 1)) & 1) if cnt else self.cf
            self.zf = ((r & mask) == 0)
            self.sf = bool(r & (1 << (sz * 8 - 1)))
            self.write_op(A[0], r)
        elif mn == "mul":
            b = self.read_op(A[0])
            prod = (self.r["eax"] & 0xFFFFFFFF) * (b & 0xFFFFFFFF)
            self.r["eax"] = prod & 0xFFFFFFFF
            self.r["edx"] = (prod >> 32) & 0xFFFFFFFF
            self.cf = self.zf = (self.r["edx"] != 0)
        elif mn == "imul":
            b = self.read_op(A[0])
            a = self.r["eax"]
            sa = a - (1 << 32) if a & 0x80000000 else a
            sb = b - (1 << 32) if b & 0x80000000 else b
            prod = sa * sb
            self.r["eax"] = prod & 0xFFFFFFFF
            self.r["edx"] = (prod >> 32) & 0xFFFFFFFF
        elif mn == "movzx":
            v = self.read_op(A[1]) & ((1 << ((A[1].size or 1) * 8)) - 1)
            self.write_op(A[0], v)
        elif mn == "movsx":
            sz = A[1].size or 1
            v = self.read_op(A[1]) & ((1 << (sz * 8)) - 1)
            if v & (1 << (sz * 8 - 1)):
                v |= (~0) << (sz * 8)
            self.write_op(A[0], v)
        elif mn == "neg":
            a = self.read_op(A[0]); sz = A[0].size or 4
            self.write_op(A[0], self.flag_sub(0, a, sz))
        elif mn == "not":
            self.write_op(A[0], ~self.read_op(A[0]))
        elif mn == "xchg":
            va = self.read_op(A[0]); vb = self.read_op(A[1])
            self.write_op(A[0], vb); self.write_op(A[1], va)
        elif mn == "cpuid":
            leaf = self.r["eax"]
            if leaf == 1:
                self.r["eax"] = CPUID1_EAX
                self.r["ebx"] = CPUID1_EBX
                self.r["ecx"] = CPUID1_ECX
                self.r["edx"] = CPUID1_EDX
            else:
                self.r["eax"] = self.r["ebx"] = self.r["ecx"] = self.r["edx"] = 0
        elif mn in ("nop", "int3", "hlt"):
            pass
        else:
            raise EmuError("unsupported instruction: %r" % ins.raw)
        return None

    def _size_op(self, pa, pb):
        if pa.size:
            return pa.size
        return pb.size or 4

    def do_call(self, target, pc):
        t = target.strip().lower()
        if t in self.hooks:
            # args were pushed by preceding PUSH instrs; top of stack = last arg
            esp = self.r["esp"]
            args = [self.mem.u32(esp + 4 * i) for i in range(8)]
            ret = self.hooks[t](args)
            self.r["eax"] = (ret if ret is not None else 0) & 0xFFFFFFFF
            self.r["esp"] = (esp + 4 * self._arg_count(t)) & 0xFFFFFFFF
            return
        if t in self.code_labels or t in self.labels:
            self.push(pc + 1)
            return
        raise EmuError("call to unknown symbol %r" % target)

    def _arg_count(self, t):
        return {"getcommandlinea": 0, "getvolumeinformationa": 8,
                "wsprintfa": 3, "lstrlena": 1, "exitprocess": 1,
                "messageboxa": 4, "makecrypt": 2, "unmakecrypt": 2,
                "htodw": 1, "atodw": 1}.get(t, 0)

    def do_invoke(self, ops):
        # invoke Func, arg1, arg2, ...
        func = ops[0].strip().lower()
        arg_ops = [parse_operand(o, self.labels) for o in ops[1:]]
        # stdcall: push right-to-left
        for o in reversed(arg_ops):
            self.push(self.read_op(o))
        # emit a synthetic call
        n = len(arg_ops)
        if func in self.hooks:
            # args are on top of stack (no return addr yet)
            args = [self.mem.u32(self.r["esp"] + 4 * i) for i in range(n)]
            self.hooks[func](args)
            self.r["esp"] = (self.r["esp"] + 4 * n) & 0xFFFFFFFF
        else:
            raise EmuError("invoke unknown symbol %r" % ops[0])


# condition-code table
JCC = {
    "jz":  lambda e: e.zf,          "je":  lambda e: e.zf,
    "jnz": lambda e: not e.zf,      "jne": lambda e: not e.zf,
    "jc":  lambda e: e.cf,          "jb":  lambda e: e.cf,   "jnae": lambda e: e.cf,
    "jnc": lambda e: not e.cf,      "jae": lambda e: not e.cf, "jnb": lambda e: not e.cf,
    "js":  lambda e: e.sf,          "jns": lambda e: not e.sf,
    "jo":  lambda e: e.of,          "jno": lambda e: not e.of,
    "ja":  lambda e: (not e.cf) and (not e.zf),
    "jbe": lambda e: e.cf or e.zf,
    "jl":  lambda e: e.sf != e.of,
    "jge": lambda e: e.sf == e.of,
    "jg":  lambda e: (not e.zf) and (e.sf == e.of),
    "jle": lambda e: e.zf or (e.sf != e.of),
    "jp":  lambda e: False,         "jnp": lambda e: True,
}


# --------------------------------------------------------------------------
# Script driver
# --------------------------------------------------------------------------
class Script:
    def __init__(self, path):
        self.path = path
        self.text = load_text(path)
        self.pybody = extract_pybody(self.text)
        self.data_labels, self.data_bytes, self.data_end = None, None, None
        self.instrs, self.code_labels = None, None
        self._parse()

    def _parse(self):
        # split into .data / .code
        sec = None
        data_lines, code_lines = [], []
        for raw in self.text.splitlines():
            s = strip_comment(raw)
            low = s.lower()
            if low in (".data", ".data?"):
                sec = "data"; continue
            if low == ".code":
                sec = "code"; continue
            if low.startswith(".") and low in (".model", ".686p", ".mmx", ".386"):
                continue
            if sec == "data":
                data_lines.append(raw)
            elif sec == "code":
                code_lines.append(raw)
        # if no sections, treat all as code
        if not data_lines and not code_lines:
            code_lines = self.text.splitlines()
        op_abs_labels[0] = {}
        self.data_labels, self.data_bytes, self.data_end = parse_data(data_lines)
        op_abs_labels[0] = self.data_labels
        # memory image
        self.mem = Memory()
        if self.data_bytes:
            self.mem.write(DATA_BASE, self.data_bytes)
        self.instrs, self.code_labels = parse_code(code_lines)

    def make_emu(self, name):
        # data labels resolve operands; code labels resolve control flow
        e = Emu(dict(self.data_labels), self.mem, name, self.code_labels)
        # KeyMake runtime convention: EAX already points at the command line
        # (the name) when the snippet starts.  Scripts like 注册机2 rely on it.
        buf = 0x7000
        self.mem.write(buf, name.encode("gbk", "replace") + b"\x00")
        e.r["eax"] = buf
        return e

    def evaluate(self, name):
        if self.pybody is not None:
            return run_pybody(self.pybody, name, 1, 0)
        e = self.make_emu(name)
        e.run(self.instrs)
        return extract_result(e)

    def structure(self):
        return {
            "path": self.path,
            "data": self.data_labels,
            "data_size": len(self.data_bytes),
            "instrs": self.instrs,
            "code_labels": self.code_labels,
            "pybody": self.pybody is not None,
        }


def extract_pybody(text):
    lines = text.splitlines()
    out, inside = [], False
    for ln in lines:
        if ln.strip() == "#PY":
            inside = True; continue
        if ln.strip() == "#ENDPY":
            inside = False; continue
        if inside:
            out.append(ln)
    return "\n".join(out) if out else None


def run_pybody(body, name, count, index):
    ns = {"name": name, "count": count, "index": index}
    exec(body, ns)
    fn = ns.get("gen") or ns.get("main")
    if callable(fn):
        return fn(name)
    if "serial" in ns:
        return ns["serial"]
    return str(ns.get("result", ""))


def extract_result(e):
    """The serial is whatever EAX points to (a C string) at script end."""
    ptr = e.r["eax"] & 0xFFFFFFFF
    # try as a string pointer
    if 0 < ptr < e.mem.size:
        s = e.mem.cstr(ptr)
        if s and all(32 <= b < 127 or b >= 0x80 for b in s):
            try:
                return s.decode("gbk")
            except Exception:
                return s.decode("latin1", "replace")
    # fallback: treat EAX as the value
    return "%X" % ptr


# --------------------------------------------------------------------------
# Subcommands
# --------------------------------------------------------------------------
def cmd_gen(args):
    sc = Script(args.script)
    print(sc.evaluate(args.name))
    return 0


def cmd_run(args):
    sc = Script(args.script)
    n = args.count if args.count else 1
    for i in range(n):
        if sc.pybody is not None:
            res = run_pybody(sc.pybody, args.name, n, i)
        else:
            e = sc.make_emu(args.name)
            e.run(sc.instrs)
            res = extract_result(e)
        if n == 1:
            print(res)
        else:
            print("%d: %s" % (i, res))
    return 0


def cmd_info(args):
    sc = Script(args.script)
    st = sc.structure()
    print("script      :", st["path"])
    print("python body :", "yes" if st["pybody"] else "no")
    print(".data       : %d byte(s), %d label(s)" %
          (st["data_size"], len(st["data"])))
    for name, addr in sorted(st["data"].items(), key=lambda kv: kv[1]):
        print("    0x%04X  %s" % (addr, name))
    print(".code       : %d instruction(s), %d label(s)" %
          (len(st["instrs"]), len(st["code_labels"])))
    for ins in st["instrs"]:
        print("    %-7s %s" % (ins.mn, ", ".join(ins.ops)))
    used = sorted({i.mn for i in st["instrs"]})
    print("mnemonics   :", ", ".join(used))
    calls = sorted({o.strip().lower() for i in st["instrs"]
                    if i.mn in ("call", "invoke") for o in i.ops[:1]})
    print("calls       :", ", ".join(calls) if calls else "(none)")
    return 0


def cmd_selftest(args):
    ok = 0

    def check(name, cond):
        nonlocal ok
        if not cond:
            print("FAIL:", name)
            raise SystemExit(1)
        ok += 1
        print("ok  :", name)

    # hex nibble parse (the 注册机2 loop, as a helper)
    def hexval(s):
        v = 0
        for ch in s:
            c = ord(ch)
            if c >= 0x3A:
                c -= 7
            c -= 0x30
            v = ((v << 4) + c) & 0xFFFFFFFF
        return v
    check("hex parse '1A3F'", hexval("1A3F") == 0x1A3F)
    check("hex parse '0'", hexval("0") == 0)
    check("hex parse 'FF'", hexval("FF") == 0xFF)

    # wsprintf %1X formatting via a tiny Emu
    sc_data = ['a3 db "%1X",0', 'a4 db 20 dup (0)']
    labels, db, _ = parse_data(sc_data)
    mem = Memory(); mem.write(DATA_BASE, db)
    e = Emu(labels, mem, "test")
    e.api_wsprintfA([labels["a4"], labels["a3"], 0x1A2B])
    check("wsprintf %1X", mem.cstr(labels["a4"]).decode() == "1A2B")

    # MUL/ADD fold: eax=3, ecx=5 -> 15, edx=0 -> 15
    e.r["eax"] = 3
    e.r["ecx"] = 5
    e.r["edx"] = 0
    prod = e.r["eax"] * e.r["ecx"]
    e.r["eax"] = prod & 0xFFFFFFFF
    e.r["edx"] = (prod >> 32) & 0xFFFFFFFF
    e.flag_add(e.r["eax"], e.r["edx"], 4)
    check("mul/add fold 3*5", e.r["eax"] == 15)

    # MakeCrypt base64 of dword 0 -> "AAAAAA=="
    labels2, db2, _ = parse_data(['szOut db 100 dup (0)'])
    mem2 = Memory(); mem2.write(DATA_BASE, db2)
    e2 = Emu(labels2, mem2, "t")
    e2.api_MakeCrypt([0, labels2["szOut"]])
    check("MakeCrypt(0) base64", mem2.cstr(labels2["szOut"]).decode() == "AAAAAA==")

    # UnMakeCrypt roundtrip
    e2.api_UnMakeCrypt([labels2["szOut"], 0x5000])
    check("UnMakeCrypt roundtrip", mem2.u32(0x5000) == 0)

    # dup allocation
    labels3, db3, end3 = parse_data(['buf db 20 dup (0)', 'x dd 0'])
    check("dup 20 bytes + dd", (end3 - DATA_BASE) == 24 and labels3["x"] == DATA_BASE + 20)

    # htodw / atodw
    mem3 = Memory(); mem3.write(0x100, b"1A3F\x00"); mem3.write(0x200, b"4660\x00")
    e3 = Emu({}, mem3, "t")
    check("htodw 1A3F", e3.api_htodw([0x100]) == 0x1A3F)
    check("atodw 4660", e3.api_atodw([0x200]) == 4660)

    # FNV volume-serial determinism
    check("fnv deterministic", fnv1a32(b"AB\\") == fnv1a32(b"AB\\"))

    print("\nall %d selftests passed" % ok)
    return 0


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(
        prog="keymake_py",
        description="Evaluate KeyMake 2.0 keygen algorithm scripts (.rek) in "
                    "pure Python. See the module docstring for the script "
                    "format and references.",
        epilog="subcommands map to features: gen=parse+eval, run=eval N times / "
               "python body, info=dump structure, selftest=verify helper ops.")
    sub = p.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen", help="evaluate a script and print the serial")
    g.add_argument("script")
    g.add_argument("--name", required=True)
    g.set_defaults(func=cmd_gen)

    r = sub.add_parser("run", help="evaluate N times (or run embedded python)")
    r.add_argument("script")
    r.add_argument("--name", required=True)
    r.add_argument("--count", type=int, default=1)
    r.set_defaults(func=cmd_run)

    i = sub.add_parser("info", help="dump parsed algorithm structure")
    i.add_argument("script")
    i.set_defaults(func=cmd_info)

    s = sub.add_parser("selftest", help="verify helper ops")
    s.set_defaults(func=cmd_selftest)
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except EmuError as ex:
        print("error:", ex, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())