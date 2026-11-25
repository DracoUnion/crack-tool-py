#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
E-Code Explorer.exe  ->  Python CLI 重写版（真正逻辑：易语言程序分析器）

来源目录: D:\Program Files\crack-tool-dasm\ECodeExplorer_0.86_正式版
目标文件: E-Code Explorer.exe (32-bit PE, 易语言编译)
MD5: bd4dd82cd0c5708aba06b63eff9d4e33  (author: monkeycz, pediy.com)

======================== 逆向发现（真正的逻辑）========================

该程序不是普通 x86 应用，而是一款「易语言 (E-language) 程序分析/反汇编工具」。

1. .text 节 (0x401000-0x402000, 仅 4 KB) 只是一个原生加载桩：
   sub_40100B -> 获自身目录 -> 优先加载 krnln.fnr，失败则从注册表
   HKCU\Software\FlySky\E\Install 的 Path 读取并加载 krnln.fne ->
   GetProcAddress("GetNewSock") -> GetNewSock(1000) 返回函数指针 ->
   用 .ecode 节基址 0x403000(4206592) 调用该指针 -> ExitProcess(0)。
   加载桩里不包含任何业务逻辑。

2. .ecode 节 (0x403000-0x58f000, ~1.5 MB, rwx) 存放易语言字节码
   (E-code)。IDA 把它误当成 x86，产出 sub_53xxxx 等全是“假函数”。
   易语言字节码的 opcode 译码表在外部运行时 krnln.fnr 内，不在本 exe，
   无法纯静态还原完整的 E 字节码反汇编。

3. 可从字符串与结构确凿还原的“能做什么”（即本 CLI 真正实现的分析）：
   - 解析 PE 结构：DOS 头、PE 签名、COFF 头、可选头、节表、入口点、镜像基址
   - 导入表 / 导出表解析（字符串铁证：AddressOfFunctions、NumberOfFunctions、
     OriginalFirstThunk、DllName；原程序会加载 LoadDLL.exe / Symbol.dll /
     disasm.dll 等，并解析其导出）
   - 检测易语言头：36 字节签名 "WTNE / MADE BY E COMPILER - WUTAO " + 版本号
     (.ecode+0x24，本文件版本 0x4A1=1185)，并列出头部原始 DWORD 表及从字符串
     表回收的字段名词汇（m_nCodeSectionOffset、m_nStartCodeOffset、
     m_nConstSectionOffset、m_nExportSymbolCount、m_aryReLocationItem、...）
   - 字符串/常量提取：扫描 .ecode 中的 ASCII 与 GBK(中文) 字符串
   - 代码节字节级列表：用原程序的输出口吻 (@ BEGIN / Func_ / END) 打印

缺失说明：完整的 E 字节码 mnemonic 反汇编需要 krnln.fnr 运行时的 opcode 表，
          本 CLI 只做字节级列表与结构分析，明确标注，不编造伪码。

本程序为纯 Python CLI，无第三方依赖，直接 `python main.py [目标文件]` 运行。
不带参数时，复现原程序的加载桩行为（加载 krnln 运行时并跳转；缺少运行时时
弹出与原程序完全一致的错误 MessageBox，退出码 -1）。
"""

import ctypes
import ctypes.wintypes
import os
import struct
import sys

# ===================== 易语言加载桩（sub_40100B 原样复现）========================
kernel32 = ctypes.windll.kernel32
user32 = ctypes.windll.user32
advapi32 = ctypes.windll.advapi32

HKEY_CURRENT_USER = 0x80000001
REG_KEY = r"Software\FlySky\E\Install"
REG_VALUE = "Path"
REG_ACCESS = 0x20019

DLL_NAME1 = "krnln.fnr"      # 0x401019
DLL_NAME2 = "krnln.fne"      # 0x401023
PROC_NAME = "GetNewSock"     # 0x40102D
GETNEWSOCK_ARG = 1000        # 0x3E8
ECODE_BASE = 0x403000        # 4206592, .ecode 节基址 (原程序 push 4206592)

MB_TITLE = "Error"                                             # 0x401096
MB_MSG = ("Not found the kernel library or the kernel library is invalid!")  # 0x401057
MB_ICON = 0x10                                                 # MB_ICONEXCLAMATION

_GetModuleFileNameA = kernel32.GetModuleFileNameA
_GetModuleFileNameA.argtypes = [ctypes.wintypes.HANDLE,
                                ctypes.c_char_p,
                                ctypes.wintypes.DWORD]
_GetModuleFileNameA.restype = ctypes.wintypes.DWORD

_LoadLibraryA = kernel32.LoadLibraryA
_LoadLibraryA.argtypes = [ctypes.c_char_p]
_LoadLibraryA.restype = ctypes.wintypes.HMODULE

_GetProcAddress = kernel32.GetProcAddress
_GetProcAddress.argtypes = [ctypes.wintypes.HMODULE, ctypes.c_char_p]
_GetProcAddress.restype = ctypes.c_void_p

_FreeLibrary = kernel32.FreeLibrary
_FreeLibrary.argtypes = [ctypes.wintypes.HMODULE]
_FreeLibrary.restype = ctypes.wintypes.BOOL

_ExitProcess = kernel32.ExitProcess
_ExitProcess.argtypes = [ctypes.wintypes.UINT]
_ExitProcess.restype = None

_RegOpenKeyExA = advapi32.RegOpenKeyExA
_RegOpenKeyExA.argtypes = [ctypes.wintypes.HKEY, ctypes.c_char_p,
                           ctypes.wintypes.DWORD, ctypes.wintypes.DWORD,
                           ctypes.POINTER(ctypes.wintypes.HKEY)]
_RegOpenKeyExA.restype = ctypes.wintypes.LONG

_RegQueryValueExA = advapi32.RegQueryValueExA
_RegQueryValueExA.argtypes = [ctypes.wintypes.HKEY, ctypes.c_char_p,
                              ctypes.POINTER(ctypes.wintypes.DWORD),
                              ctypes.POINTER(ctypes.wintypes.DWORD),
                              ctypes.c_char_p,
                              ctypes.POINTER(ctypes.wintypes.DWORD)]
_RegQueryValueExA.restype = ctypes.wintypes.LONG

_RegCloseKey = advapi32.RegCloseKey
_RegCloseKey.argtypes = [ctypes.wintypes.HKEY]
_RegCloseKey.restype = ctypes.wintypes.LONG

_MessageBoxA = user32.MessageBoxA
_MessageBoxA.argtypes = [ctypes.wintypes.HWND, ctypes.c_char_p,
                         ctypes.c_char_p, ctypes.wintypes.UINT]
_MessageBoxA.restype = ctypes.c_int


def get_self_dir():
    buf = ctypes.create_string_buffer(260)
    n = _GetModuleFileNameA(None, buf, ctypes.sizeof(buf))
    if n == 0:
        return os.path.dirname(os.path.abspath(__file__)) + "\\"
    path = buf.value.decode("mbcs")
    idx = path.rfind("\\")
    if idx != -1:
        return path[:idx + 1]
    return path + "\\"


def ensure_trailing_backslash(path):
    if not path.endswith("\\"):
        path = path[:-1] + "\\" if path else "\\"
    return path


def load_library(path):
    handle = _LoadLibraryA(path.encode("mbcs"))
    return handle if handle else None


def get_proc_address(module, name):
    addr = _GetProcAddress(module, name.encode("mbcs"))
    return int(addr) if addr else None


def call_stdcall_int_int(addr, arg):
    func = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_int)(addr)
    return func(arg)


def call_cdecl_void_int(addr, arg):
    func = ctypes.CFUNCTYPE(None, ctypes.c_int)(addr)
    func(arg)


def show_error():
    _MessageBoxA(0, MB_MSG.encode("mbcs"), MB_TITLE.encode("mbcs"), MB_ICON)
    return -1


def bootstrap_loader():
    """复现原程序无参启动时的加载桩行为 (sub_40100B)."""
    base_dir = get_self_dir()

    path1 = base_dir + DLL_NAME1
    hmod = load_library(path1)

    if hmod is None:
        hkey = ctypes.wintypes.HKEY()
        rc = _RegOpenKeyExA(HKEY_CURRENT_USER,
                            REG_KEY.encode("mbcs"),
                            0,
                            REG_ACCESS,
                            ctypes.byref(hkey))
        if rc != 0:
            return show_error()
        try:
            buf = ctypes.create_string_buffer(260)
            buf_size = ctypes.wintypes.DWORD(ctypes.sizeof(buf))
            rc = _RegQueryValueExA(hkey,
                                   REG_VALUE.encode("mbcs"),
                                   None,
                                   None,
                                   buf,
                                   ctypes.byref(buf_size))
        finally:
            _RegCloseKey(hkey)
        if rc != 0:
            return show_error()

        reg_path = ensure_trailing_backslash(buf.value.decode("mbcs"))
        path2 = reg_path + DLL_NAME2
        hmod = load_library(path2)
        if hmod is None:
            return show_error()

    proc_addr = get_proc_address(hmod, PROC_NAME)
    if proc_addr is not None:
        v5 = call_stdcall_int_int(proc_addr, GETNEWSOCK_ARG)
        if v5 != 0:
            call_cdecl_void_int(v5, ECODE_BASE)
            _ExitProcess(0)
            return 0

    _FreeLibrary(hmod)
    return show_error()


# ===================== 易语言程序结构分析器（真正的业务逻辑）========================

# 从字符串表回收的易语言 APP_HEADER_INFO 字段名词汇（原样保留，供人工对照）
# 注意：IDA 无法给出每个字段的精确偏移，以下名词来自本程序自身的字符串引用，
#      与下方打印的头部原始 DWORD 表配合使用，不作为绝对偏移断言。
HEADER_FIELD_VOCAB = [
    "_nDllFileNameConstOffset",
    "m_nDllCmdNameConstOffset",
    "m_szLibString",
    "m_aryReLocationItem",
    "m_arySymbolDataOffset",
    "m_szarySymbolNameOffset",
    "_nSectionSize",
    "_nNextSectionOffset",
    "m_nRecordOffset",
    "m_nReLocationItemCount",
    "m_nExportSymbolCount",
    "m_nBeginSectionOffset",
    "_nVarSectionOffset",
    "m_nCodeSectionOffset",
    "m_nHelpFuncSectionOffset",
    "m_nWinFormSectionOffset",
    "_nConstSectionOffset",
    "m_nStartCodeOffset",
    "T_RELEASE_RUN_VER",
]

EC_CODE_SIG = b"WTNE / MADE BY E COMPILER - WUTAO "

# Windows PE 常量
IMAGE_DOS_SIGNATURE = 0x5A4D   # "MZ"
IMAGE_NT_SIGNATURE = 0x00004550  # "PE\0\0"
IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002
IMAGE_DIRECTORY_ENTRY_IMPORT = 1
IMAGE_DIRECTORY_ENTRY_EXPORT = 0


def read_bytes(data, off, size):
    return data[off:off + size]


def cstr_at(data, off, maxlen=256):
    """在 data 中按 C 字符串读取，优先 gbk，失败 latin1."""
    raw = data[off:off + maxlen]
    nul = raw.find(b"\x00")
    if nul != -1:
        raw = raw[:nul]
    if not raw:
        return None
    for enc in ("gbk", "latin1"):
        try:
            return raw.decode(enc)
        except UnicodeDecodeError:
            continue
    return None


def is_printable_bs(b):
    return 32 <= b < 127


def extract_strings(data, min_len=4):
    """提取 data 中的 ASCII 与 GBK 中文字符串，返回 (地址, 文本)."""
    out = []
    i = 0
    n = len(data)
    while i < n:
        b = data[i]
        # ASCII 串
        if is_printable_bs(b):
            j = i
            while j < n and is_printable_bs(data[j]):
                j += 1
            if j - i >= min_len:
                try:
                    s = data[i:j].decode("ascii")
                except UnicodeDecodeError:
                    s = None
                if s:
                    out.append((i, s))
            i = j
            continue
        # GBK 中文（首字节 0x81-0xFE）
        if 0x81 <= b <= 0xFE and i + 1 < n:
            j = i
            while j + 1 < n:
                b1, b2 = data[j], data[j + 1]
                if (0x81 <= b1 <= 0xFE) and ((0x40 <= b2 <= 0x7E) or (0x80 <= b2 <= 0xFE)):
                    if b2 == 0x7F:
                        break
                    j += 2
                else:
                    break
            if j - i >= min_len * 2:
                try:
                    s = data[i:j].decode("gbk")
                except UnicodeDecodeError:
                    s = None
                if s:
                    out.append((i, s))
            i = max(j, i + 1)
            continue
        i += 1
    return out


class PEParser:
    def __init__(self, path):
        self.path = path
        with open(path, "rb") as f:
            self.data = f.read()
        self.dos_e_lfanew = None
        self.nt_off = None
        self.coff = {}
        self.opt = {}
        self.sections = []
        self.image_base = 0
        self.entry_rva = 0
        self.size_of_image = 0
        self._parse()

    def _parse(self):
        d = self.data
        if len(d) < 64:
            return
        dos_sig = struct.unpack_from("<H", d, 0)[0]
        if dos_sig != IMAGE_DOS_SIGNATURE:
            return
        self.dos_e_lfanew = struct.unpack_from("<I", d, 0x3C)[0]
        nt_off = self.dos_e_lfanew
        if nt_off + 24 > len(d):
            return
        nt_sig = struct.unpack_from("<I", d, nt_off)[0]
        if nt_sig != IMAGE_NT_SIGNATURE:
            return
        self.nt_off = nt_off
        coff_off = nt_off + 4
        (machine, num_sec, timestamp, ptr_sym, num_sym, opt_size,
         characteristics) = struct.unpack_from("<HHIIIHH", d, coff_off)
        self.coff = dict(machine=machine, num_sec=num_sec,
                         opt_size=opt_size, characteristics=characteristics)
        opt_off = coff_off + 20
        opt_magic = struct.unpack_from("<H", d, opt_off)[0]
        is_pe32 = opt_magic == 0x10B
        if is_pe32:
            # PE32 可选头: HBB + 9I + 6H + 4I + 2H + 6I
            vals = struct.unpack_from("<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII", d, opt_off)
            entry_rva = vals[6]      # AddressOfEntryPoint
            base_of_code = vals[7]   # BaseOfCode
            base_of_data = vals[8]   # BaseOfData
            image_base = vals[9]     # ImageBase
            self.size_of_image = vals[19]  # SizeOfImage
            num_rva_and_sizes = vals[29]   # NumberOfRvaAndSizes
            self.dd_off = opt_off + 96     # 数据目录起始
        else:
            # PE32+ 简化处理（本程序为 PE32，此处留空）
            return
        self.opt = dict(magic=opt_magic, entry_rva=entry_rva,
                        base_of_code=base_of_code, base_of_data=base_of_data,
                        image_base=image_base)
        self.image_base = image_base
        self.entry_rva = entry_rva
        self.num_rva_and_sizes = num_rva_and_sizes
        # 节表紧随完整可选头之后
        sec_off = opt_off + opt_size
        for i in range(num_sec):
            soff = sec_off + i * 40
            if soff + 40 > len(d):
                break
            name = d[soff:soff + 8].rstrip(b"\x00").decode("ascii", "replace")
            vsize, vaddr, rawsize, rawptr, _, _, _, chars = struct.unpack_from(
                "<IIIIHHHH", d, soff + 8)
            self.sections.append(dict(name=name, vaddr=vaddr, vsize=vsize,
                                      rawptr=rawptr, rawsize=rawsize,
                                      chars=chars))

    def rva_to_raw(self, rva):
        for sec in self.sections:
            if sec["vaddr"] <= rva < sec["vaddr"] + sec["vsize"]:
                return sec["rawptr"] + (rva - sec["vaddr"])
        return None

    def section_containing_rva(self, rva):
        for sec in self.sections:
            if sec["vaddr"] <= rva < sec["vaddr"] + sec["vsize"]:
                return sec
        return None

    def find_section(self, name):
        for sec in self.sections:
            if sec["name"] == name:
                return sec
        return None

    def get_section_raw(self, name):
        sec = self.find_section(name)
        if not sec:
            return b"", 0
        return self.data[sec["rawptr"]:sec["rawptr"] + sec["rawsize"]], sec["vaddr"]

    def iter_imports(self):
        """遍历导入表，生成 (dll_name, [(func_name_or_ord, thunk_rva)])."""
        d = self.data
        dd_off = self.dd_off  # 数据目录起始
        import_dd_off = dd_off + IMAGE_DIRECTORY_ENTRY_IMPORT * 8
        if import_dd_off + 8 > len(d):
            return
        import_rva, import_size = struct.unpack_from("<II", d, import_dd_off)
        if import_rva == 0:
            return
        i = 0
        while True:
            entry_off = self.rva_to_raw(import_rva + i * 20)
            if entry_off is None or entry_off + 20 > len(d):
                break
            (ilt_rva, timestamp, fwd_chain, name_rva, iat_rva) = struct.unpack_from(
                "<IIIII", d, entry_off)
            if ilt_rva == 0 and name_rva == 0:
                break
            dll_raw = self.rva_to_raw(name_rva)
            dll_name = cstr_at(d, dll_raw, 128) if dll_raw else "(unknown)"
            funcs = []
            j = 0
            while True:
                thunk_raw = self.rva_to_raw(ilt_rva + j * 4)
                if thunk_raw is None or thunk_raw + 4 > len(d):
                    break
                thunk = struct.unpack_from("<I", d, thunk_raw)[0]
                if thunk == 0:
                    break
                if thunk & 0x80000000:
                    funcs.append((("ordinal", thunk & 0xFFFF), ilt_rva + j * 4))
                else:
                    hint_name_raw = self.rva_to_raw(thunk)
                    fname = cstr_at(d, hint_name_raw + 2, 128) if hint_name_raw else None
                    funcs.append((("name", fname or "(unnamed)"), ilt_rva + j * 4))
                j += 1
            yield (dll_name or "(unknown)", funcs)
            i += 1

    def iter_exports(self):
        """遍历导出表，生成 (dll_name, base, [(ordinal, name, func_rva)])."""
        d = self.data
        dd_off = self.dd_off
        export_dd_off = dd_off + IMAGE_DIRECTORY_ENTRY_EXPORT * 8
        if export_dd_off + 8 > len(d):
            return
        export_rva, export_size = struct.unpack_from("<II", d, export_dd_off)
        if export_rva == 0:
            return
        ed_raw = self.rva_to_raw(export_rva)
        if ed_raw is None or ed_raw + 40 > len(d):
            return
        (export_flags, timestamp, maj_ver, min_ver, name_rva, base,
         num_exp_names, num_exp_funcs, exp_func_rva, exp_name_rva,
         exp_ord_rva) = struct.unpack_from("<IIHHIIIIIII", d, ed_raw)
        dll_name_raw = self.rva_to_raw(name_rva)
        dll_name = cstr_at(d, dll_name_raw, 128) if dll_name_raw else "(unknown)"
        funcs = []
        name_raw_off = self.rva_to_raw(exp_name_rva)
        ord_raw_off = self.rva_to_raw(exp_ord_rva)
        func_raw_off = self.rva_to_raw(exp_func_rva)
        for k in range(num_exp_names):
            if name_raw_off is None:
                break
            name_rva_k = struct.unpack_from("<I", d, name_raw_off + k * 4)[0] \
                if name_raw_off + k * 4 + 4 <= len(d) else 0
            ord_k = struct.unpack_from("<H", d, ord_raw_off + k * 2)[0] \
                if ord_raw_off is not None and ord_raw_off + k * 2 + 2 <= len(d) \
                else 0
            func_rva_k = struct.unpack_from("<I", d, func_raw_off + ord_k * 4)[0] \
                if func_raw_off is not None and func_raw_off + ord_k * 4 + 4 <= len(d) \
                else 0
            name_raw = self.rva_to_raw(name_rva_k)
            fname = cstr_at(d, name_raw, 128) if name_raw else "(ordinal)"
            funcs.append((base + ord_k, fname, func_rva_k))
        yield (dll_name or "(unknown)", base, funcs)


class ECodeAnalyzer:
    def __init__(self, pe):
        self.pe = pe
        self.ecode_data = b""
        self.ecode_vaddr = 0
        self.ecode_off = 0
        self.sig = b""
        self.version = None
        self.header_dwords = []
        self._locate_ecode()

    def _locate_ecode(self):
        raw, vaddr = self.pe.get_section_raw(".ecode")
        if raw:
            self.ecode_data = raw
            self.ecode_vaddr = vaddr
            self.ecode_off = raw  # file offset handled via rva_to_raw when needed
            self._parse_header()

    def _parse_header(self):
        d = self.ecode_data
        if len(d) >= 36:
            self.sig = d[:36]
        if len(d) >= 40:
            self.version = struct.unpack_from("<I", d, 0x24)[0]
            # 头部 DWORD 表：从 0x28 开始，逐 4 字节打印（供配合字段名词汇人工对照）
            self.header_dwords = []
            for off in range(0x28, min(len(d), 0x58), 4):
                v = struct.unpack_from("<I", d, off)[0]
                self.header_dwords.append((off, v))

    def detect(self):
        return self.sig[:4] == b"WTNE" or EC_CODE_SIG[:4] in self.sig

    def format_header(self):
        lines = []
        lines.append("  签名:          %r" % self.sig)
        lines.append("  版本号 (0x24): 0x%08X (%d)" % (self.version or 0, self.version or 0))
        if self.header_dwords:
            lines.append("  头部 DWORD 表 (0x28-0x58，逐 4 字节，供配合字段名词汇对照):")
            for off, v in self.header_dwords:
                lines.append("    +0x%02X: 0x%08X (%d)" % (off, v, v))
        return lines

    def list_strings(self, min_len=4):
        return extract_strings(self.ecode_data, min_len)

    def list_code(self, width=16, max_rows=None):
        """代码节字节级列表，按原程序输出口吻包裹."""
        d = self.ecode_data
        rows = []
        rows.append("@ BEGIN =================")
        rows.append(";================= Func_<ecode>")
        total = len(d)
        limit = total if max_rows is None else min(total, max_rows * width)
        off = 0
        while off < limit:
            chunk = d[off:off + width]
            hex_part = " ".join("%02X" % b for b in chunk)
            asc_part = "".join(chr(b) if is_printable_bs(b) else "." for b in chunk)
            rows.append("  %08X  %-48s  %s" % (off, hex_part, asc_part))
            off += width
        rows.append(" END ===================")
        return rows


def print_pe_summary(pe):
    lines = []
    lines.append("=" * 72)
    lines.append("PE 结构分析: %s" % pe.path)
    lines.append("=" * 72)
    lines.append("DOS 头 e_lfanew:     0x%08X" % pe.dos_e_lfanew)
    lines.append("入口点 RVA:          0x%08X" % pe.entry_rva)
    lines.append("镜像基址:            0x%08X" % pe.image_base)
    lines.append("镜像大小:            0x%08X (%d)" % (pe.size_of_image, pe.size_of_image))
    lines.append("节数:                %d" % pe.coff.get("num_sec", 0))
    lines.append("COFF 特征:           0x%04X" % pe.coff.get("characteristics", 0))
    lines.append("")
    lines.append("节表:")
    lines.append("  %-10s %10s %10s %10s %10s  %-10s" %
                 ("名", "VAddr", "VSize", "RawPtr", "RawSize", "Characteristics"))
    for sec in pe.sections:
        lines.append("  %-10s 0x%08X 0x%08X 0x%08X 0x%08X  0x%08X" %
                     (sec["name"], sec["vaddr"], sec["vsize"],
                      sec["rawptr"], sec["rawsize"], sec["chars"]))
    lines.append("")
    return lines


def print_imports(pe):
    lines = ["-" * 72, "导入表:", "-" * 72]
    count = 0
    for dll_name, funcs in pe.iter_imports():
        count += 1
        lines.append("  [%s] (%d 个导入)" % (dll_name, len(funcs)))
        for sym, thunk in funcs[:12]:
            kind, val = sym
            if kind == "ordinal":
                lines.append("      ord:%d      (thunk RVA 0x%08X)" % (val, thunk))
            else:
                lines.append("      %-40s (thunk RVA 0x%08X)" % (val, thunk))
        if len(funcs) > 12:
            lines.append("      ... 还省略 %d 个" % (len(funcs) - 12))
    if count == 0:
        lines.append("  (无导入表)")
    lines.append("")
    return lines


def print_exports(pe):
    lines = ["-" * 72, "导出表:", "-" * 72]
    count = 0
    for dll_name, base, funcs in pe.iter_exports():
        count += 1
        lines.append("  [%s] 基序号=%d (%d 个导出名)" % (dll_name, base, len(funcs)))
        for ord_, fname, func_rva in funcs[:20]:
            lines.append("      ord=%-4d %-40s funcRVA=0x%08X" %
                         (ord_, fname, func_rva or 0))
        if len(funcs) > 20:
            lines.append("      ... 还省略 %d 个" % (len(funcs) - 20))
    if count == 0:
        lines.append("  (无导出表)")
    lines.append("")
    return lines


def print_ecode(analyzer):
    lines = ["-" * 72, "易语言 .ecode 分析:", "-" * 72]
    if not analyzer.ecode_data:
        lines.append("  未找到 .ecode 节。")
        lines.append("")
        return lines
    lines.append(".ecode 节大小:         0x%08X (%d 字节)" %
                 (len(analyzer.ecode_data), len(analyzer.ecode_data)))
    lines.append("易语言签名检测:        %s" % ("命中 (WTNE)" if analyzer.detect() else "未命中"))
    lines.append("")
    lines.extend(analyzer.format_header())
    lines.append("")
    lines.append("头部字段名词汇 (来自本程序自身字符串，供人工对照):")
    for name in HEADER_FIELD_VOCAB:
        lines.append("    %s" % name)
    lines.append("")
    # 字符串/常量
    strs = analyzer.list_strings()
    lines.append("字符串/常量 (共 %d 个，min_len=4):" % len(strs))
    shown = 0
    for off, s in strs:
        if shown >= 60:
            lines.append("  ... 还省略 %d 个字符串" % (len(strs) - shown))
            break
        esc = s.replace("\n", "\\n").replace("\r", "\\r").replace("\t", "\\t")
        lines.append("  +0x%06X  %s" % (off, esc[:120]))
        shown += 1
    lines.append("")
    return lines


def print_code_listing(analyzer):
    lines = ["-" * 72, "代码节字节级列表 (.ecode, 前 256 字节):", "-" * 72]
    if not analyzer.ecode_data:
        lines.append("  无 .ecode 数据。")
        lines.append("")
        return lines
    lines.extend(analyzer.list_code(width=16, max_rows=16))
    lines.append("")
    lines.append("说明：以上为字节级列表，非 mnemonic 反汇编。完整的易语言 E 字节码")
    lines.append("     opcode 译码需外部运行时 krnln.fnr 的 opcode 表（不在本 exe 内），")
    lines.append("     无法纯静态还原，故不编造伪码。")
    lines.append("")
    return lines


def analyze_file(path):
    if not os.path.isfile(path):
        print("错误: 找不到文件: %s" % path)
        return 1
    pe = PEParser(path)
    out = []
    out.extend(print_pe_summary(pe))
    out.extend(print_imports(pe))
    out.extend(print_exports(pe))
    analyzer = ECodeAnalyzer(pe)
    out.extend(print_ecode(analyzer))
    out.extend(print_code_listing(analyzer))
    print("\n".join(out))
    return 0


def main(argv):
    # 尽量以 UTF-8 输出，避免中文在控制台乱码/崩溃
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    if len(argv) >= 2:
        # 分析模式：真正的业务逻辑
        return analyze_file(argv[1])
    # 无参数：复现原程序的加载桩行为
    return bootstrap_loader()


if __name__ == "__main__":
    sys.exit(main(sys.argv))
