#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HzorInline v1.3 beta (build 20060824)  ->  Python CLI 重写版
================================================================

来源目录 : D:\\Program Files\\crack-tool-patcher\\HzorInline_1.3b20060824
目标文件 : HzorInline.exe (9,221 字节, 32-bit PE, 基址 0x400000, 已加壳/UPX 风格)
作者     : arnix  (arnix@freenet.am)   GNU GPL v2.1

逆向依据
--------
1) 完整主程序源码  source\\HzorInline.asm (Fasm 语法, 共 ~2600 行) —— 这是本重写的
   *真正* 依据: 它给出了脚本语言解析、两遍 (two-pass) 处理、自由空间搜索
   (seek_free_space)、VA<->RAW 换算、JMP 生成、APPEND 追加节、代码生成
   (idgencode) 的逐指令算法, 本程序逐条对照重写。
2) 加壳 stub 的 IDA 反汇编 (/d/temp/ida_out/HzorInline.exe.asm):
   - 仅导入  KERNEL32.dll 的 LoadLibraryA / GetProcAddress (壳解压后由它们重建 IAT);
   - 入口 start: `xchg esp, ds:off_40C1C8` / `popa` / `xchg eax,esp` / `push ebp`
     ... 是典型 UPX/自定义压缩引导 (decompression stub) 指令序列;
   - 两个区段: seg001 (VA 0x401000, VSize 0x9000, RawSize 0 —— 运行时解压目标),
     seg002 (VA 0x40A000, RawSize 0x2205 —— 压缩数据/资源);
   - 字符串: 'KERNEL32.dll' / 'LoadLibraryA' / 'GetProcAddress' / 'MNOAPCDQFGR67I9:J<=K"7'
     (压缩字典残留).
   => 【加壳 stub 静态限制】EXE 是加壳的, 静态反汇编只能看到解压引导, 看不到真正
      的界面/解析代码; 因此本重写以随附的 *完整源码* 为准, stub 仅用于印证身份
      (导入/入口/区段布局)。
3) 文档: doc\\readme.txt (命令集权威定义), doc\\help.txt, doc\\whatsnew.txt,
   doc\\todo.txt; 模块示例 modules\\*.asm (upx/aspack/nspack/pecompact 等) 与
   tutorial\\patch.asm 用于印证各命令的实际用法。

readme.txt 命令集 -> 本程序实现映射
----------------------------------
  OUT=XXXXXXXX        -> ScriptBuilder.out_va / out_raw; ENDP 时在该 VA 处写 5 字节 JMP
  OUT_CODE=XX,YY,..   -> out_code (逗号或 #XXYY# 两种写法); 覆盖默认 E9 跳转, 决定
  (或 #XXYYZZ#)         "偷字节数" stolen = len(out_code)
  REST                -> 在 inline 里生成 `BF <VA_OUT> (B0 <原字节> AA)*` 还原被偷字节
  FREE=AUTO           -> free_mode='auto'; ENDP 调 seek_free_space 自动找尾随 0 填充
  FREE=APPEND         -> free_mode='append'; inline 追加到文件尾并修正末节 SizeOfRawData
  FREE=XXXXXXXX       -> free_mode='fixed'; 直接用该 RAW 地址
  MAX_SIZE=XXXXXXXX   -> max_size; 仅与 FREE=AUTO 搭配, 空间不足则报 "patch too big"
  OEP=XXXXXXXX        -> oep_va; 供 PUSH OEP 使用
  PROC                -> proc=True; 之后 P/BIN/REST/PUSH... 走 inline 分支
  PUSH FREE           -> inline += 68 <VA(free)> (地址在 ENDP 定, 用 fixup 回填)
  PUSH OEP            -> inline += 68 <VA_OEP>
  PUSH OUT            -> inline += 68 <VA_OUT>   (源码实际指令名是 PUSH OUT)
  RETN                -> inline += C3
  PUSHAD / POPAD      -> inline += 60 / 61
  P,XXXXXXXX,YY,YY,.. -> PROC 前: simple patch (直接改文件 RAW); PROC 后: inline 代码
  BIN=XX,YY,..        -> inline += 原始字节 (需 PROC 之后)
  #XXYY# / XX,YY      -> parse_byte_list: 两种字节写法
  ENDP                -> 收尾: 定 free 空间 / 生成默认 JMP / 校验 MAX_SIZE / 回填 PUSH FREE
  ;注释                -> 跳过
  默认 OUT_CODE = E9 (JMP rel32) 当未用 OUT_CODE 覆盖时.

用法
----
  python main.py build  <target.exe> <module.script> [-o out.exe]
  python main.py free   <target.exe> [--min N]
  python main.py script <module.script> [target.exe]

依赖: 纯 Python 标准库 (无第三方依赖). main.py 为唯一入口.
"""

import argparse
import os
import struct
import sys


# ---------------------------------------------------------------------------
# 小工具: 定长小端读写 + 十六进制
# ---------------------------------------------------------------------------
def u16(b, o):
    return struct.unpack_from('<H', b, o)[0]


def u32(b, o):
    return struct.unpack_from('<I', b, o)[0]


def u64(b, o):
    return struct.unpack_from('<Q', b, o)[0]


def p16(v):
    return struct.pack('<H', v & 0xFFFF)


def p32(v):
    return struct.pack('<I', v & 0xFFFFFFFF)


def hx(bs):
    return ' '.join('%02X' % c for c in bs)


def hx_raw(bs):
    return ''.join('%02X' % c for c in bs)


# ---------------------------------------------------------------------------
# PE 解析
# ---------------------------------------------------------------------------
class Section(object):
    __slots__ = ('index', 'name', 'vsize', 'va', 'rawsize', 'rawptr', 'chars',
                 'name_off')

    def __init__(self, index, name_off, name, vsize, va, rawsize, rawptr, chars):
        self.index = index
        self.name_off = name_off          # 节头在文件中的偏移 (用于回写)
        self.name = name
        self.vsize = vsize
        self.va = va
        self.rawsize = rawsize
        self.rawptr = rawptr
        self.chars = chars

    @property
    def rawsize_field_off(self):
        return self.name_off + 0x10

    @property
    def vsize_field_off(self):
        return self.name_off + 0x08

    def __repr__(self):
        return '<Sec %d %r va=%08X vs=%X raw=%08X sz=%X>' % (
            self.index, self.name, self.va, self.vsize, self.rawptr, self.rawsize)


class PEFile(object):
    """最小 PE32/PE32+ 解析器, 只实现本工具需要的头字段与节表."""

    def __init__(self, data):
        self.data = data
        self._parse()

    def _parse(self):
        d = self.data
        if len(d) < 0x40 or d[0:2] != b'MZ':
            raise ValueError('not a PE file (no MZ)')
        e_lfanew = u32(d, 0x3C)
        if e_lfanew + 24 > len(d) or d[e_lfanew:e_lfanew + 4] != b'PE\x00\x00':
            raise ValueError('not a PE file (no PE signature)')
        self.e_lfanew = e_lfanew
        coff = e_lfanew + 4
        self.machine = u16(d, coff + 0)
        self.num_sections = u16(d, coff + 2)
        self.size_opt = u16(d, coff + 16)
        self.opt = coff + 20
        magic = u16(d, self.opt)
        if magic == 0x10B:               # PE32
            self.pe32plus = False
            self.imagebase = u32(d, self.opt + 28)
        elif magic == 0x20B:             # PE32+
            self.pe32plus = True
            self.imagebase = u64(d, self.opt + 24)
        else:
            raise ValueError('unsupported optional header magic %04X' % magic)
        self.section_align = u32(d, self.opt + 32)
        self.file_align = u32(d, self.opt + 36)
        self.size_headers = u32(d, self.opt + 60)
        self.sect_start = self.opt + self.size_opt
        self.sections = []
        off = self.sect_start
        for i in range(self.num_sections):
            if off + 40 > len(d):
                break
            raw_name = d[off:off + 8]
            name = raw_name.split(b'\x00')[0].decode('latin1') or ''
            vsize = u32(d, off + 0x08)
            va = u32(d, off + 0x0C)
            rawsize = u32(d, off + 0x10)
            rawptr = u32(d, off + 0x14)
            chars = u32(d, off + 0x24)
            self.sections.append(Section(i, off, name, vsize, va, rawsize,
                                         rawptr, chars))
            off += 40

    # -- VA <-> RAW ---------------------------------------------------------
    def va2raw(self, va):
        """Virtual Address -> 文件 RAW 偏移; 失败返回 0 (与原程序一致)."""
        if va < self.imagebase:
            return 0
        rva = va - self.imagebase
        # 头部分 (RVA 落在第一节之前)
        first_va = self.sections[0].va if self.sections else 0
        if rva < first_va:
            return rva if rva < self.size_headers else 0
        for s in self.sections:
            span = max(s.vsize, s.rawsize)
            if s.va <= rva < s.va + span:
                delta = rva - s.va
                if delta < s.rawsize:
                    return s.rawptr + delta
                return 0
        return 0

    def raw2va(self, raw):
        """文件 RAW 偏移 -> Virtual Address; 失败返回 0."""
        first_raw = self.sections[0].rawptr if self.sections else 0
        if raw < first_raw:
            return self.imagebase + raw
        for s in self.sections:
            if s.rawptr <= raw < s.rawptr + s.rawsize:
                return self.imagebase + s.va + (raw - s.rawptr)
        return 0

    def last_section(self):
        """文件末尾 (RAW 最靠后) 的有效节."""
        best = None
        for s in self.sections:
            if s.rawsize == 0:
                continue
            if best is None or (s.rawptr + s.rawsize) > (best.rawptr + best.rawsize):
                best = s
        return best

    # -- 自由空间 -----------------------------------------------------------
    def seek_free_space(self, size):
        """从最后一个节往前, 找节尾 (SizeOfRawData 内) 的 0 填充, 返回能放下
        `size` 字节的 RAW 偏移 (取该 0 区的 *末尾* size 字节); 找不到返回 0.
        算法对应源码 seek_free_space: 逆序遍历节表, 统计每节尾部连续 0 的个数."""
        d = self.data
        for s in reversed(self.sections):
            if s.rawsize == 0:
                continue
            start = s.rawptr
            end = s.rawptr + s.rawsize
            if end > len(d):
                end = len(d)
            i = end
            while i > start and d[i - 1] == 0:
                i -= 1
            zeros = end - i
            if zeros >= size:
                return end - size
        return 0

    def caves(self, min_len=1):
        """枚举候选代码洞 (全 0 区): 头部节表后到第一节之间的空隙 + 每节尾部 0 填充.
        返回 [(raw_off, length), ...]."""
        d = self.data
        out = []
        # 头部空隙
        if self.sections:
            head_end = self.sect_start + self.num_sections * 40
            first_raw = self.sections[0].rawptr
            if first_raw > head_end:
                seg = d[head_end:first_raw]
                if seg.count(0) == len(seg) and len(seg) >= min_len:
                    out.append((head_end, len(seg)))
        # 每节尾部 0 填充
        for s in self.sections:
            if s.rawsize == 0:
                continue
            end = min(s.rawptr + s.rawsize, len(d))
            i = end
            while i > s.rawptr and d[i - 1] == 0:
                i -= 1
            run = end - i
            if run >= min_len:
                out.append((i, run))
        return out


# ---------------------------------------------------------------------------
# 脚本解析
# ---------------------------------------------------------------------------
class ScriptError(Exception):
    pass


def parse_byte_list(s):
    """解析 OUT_CODE= / BIN= 的字节列表, 支持两种写法:
       'XX,YY,ZZ'  (逗号分隔, 每组 1-2 位十六进制)
       '#XXYYZZ#'  (# 包裹的连续十六进制, 位数必须为偶)."""
    s = s.strip()
    if not s:
        raise ScriptError('empty byte list')
    if s[0] == '#':
        inner = s[1:]
        h = inner.split('#', 1)[0]
        h = h.strip().replace(' ', '')
        if len(h) % 2 != 0:
            raise ScriptError('odd number of hex digits in #..# byte list: %r' % s)
        try:
            return bytes.fromhex(h)
        except ValueError:
            raise ScriptError('bad hex in #..# byte list: %r' % s)
    out = bytearray()
    for part in s.split(','):
        p = part.strip()
        if p == '':
            continue
        if len(p) > 2:
            raise ScriptError('bad byte %r in list %r' % (p, s))
        try:
            v = int(p, 16)
        except ValueError:
            raise ScriptError('bad hex byte %r in list %r' % (p, s))
        out.append(v & 0xFF)
    if not out:
        raise ScriptError('no bytes in list %r' % s)
    return bytes(out)


def _hexval(s):
    s = s.strip()
    if not s:
        raise ScriptError('empty hex value')
    for c in s:
        if c not in '0123456789abcdefABCDEF':
            raise ScriptError('invalid hex value %r' % s)
    return int(s, 16)


def encode_inline_patch(addr, bs):
    """把 PROC 之后的 P,addr,YY.. 编码为 inline 代码 (对应源码 _patch 的
    PROCHasBegun 分支). 注意: 原程序对 2/4 字节采用 *高位在前* 的字节序写入
    (即内存字节为脚本字节顺序的逆序), 这里为与原始工具输出逐字节一致而照做."""
    n = len(bs)
    if n == 1:
        return b'\xC6\x05' + p32(addr) + bytes([bs[0]])          # mov byte [addr],b0
    if n == 2:
        return b'\x66\xC7\x05' + p32(addr) + bytes([bs[1], bs[0]])  # mov word [addr],w
    if n == 4:
        return b'\xC7\x05' + p32(addr) + bytes([bs[3], bs[2], bs[1], bs[0]])  # mov dword
    # 其它长度: mov edi,addr ; (mov al,b ; stosb)*
    out = bytearray(b'\xBF' + p32(addr))
    for b in bs:
        out += b'\xB0' + bytes([b]) + b'\xAA'
    return bytes(out)


class ScriptBuilder(object):
    def __init__(self, pe=None, data=None):
        self.pe = pe
        self.data = data
        self.simple = []            # [(raw, bytes)]  PROC 前的简单补丁
        self.inline = bytearray()   # inline 代码
        self.push_free_fixups = []  # inline 中待回填的 dd 偏移 (PUSH FREE)
        self.out_va = 0
        self.out_raw = 0
        self.out_code = None        # 显式 OUT_CODE 字节; None 表示默认 E9
        self.stolen = 0
        self.free_mode = None       # 'auto' | 'append' | 'fixed' | None
        self.free_raw = 0
        self.oep = 0
        self.max_size = 0
        self.proc = False
        self.proc_patch_ok = False
        self.free_used = False
        self.ended = False
        self.events = []            # 供 script 子命令打印的计划
        self.errors = []

    # -- 错误 ---------------------------------------------------------------
    def err(self, msg):
        self.errors.append(msg)

    # -- 主解析 -------------------------------------------------------------
    def parse(self, text):
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if line == '' or line.startswith(';'):
                continue
            if self.ended:
                break
            self._dispatch(line)
        return self

    def _dispatch(self, line):
        low = line.lower()
        # 顺序敏感: OUT_CODE 先于 OUT; FREE/MAX/OEP 用 '=' 判定
        if low.startswith('free='):
            return self._set_free(line[5:])
        if low.startswith('max_size='):
            return self._set_max(line[9:])
        if low.startswith('oep='):
            return self._set_oep(line[4:])
        if low.startswith('out_code='):
            return self._set_out_code(line[9:])
        if low.startswith('out='):
            return self._set_out(line[4:])
        if low == 'rest':
            return self._rest()
        if low.startswith('bin='):
            return self._bin(line[4:])
        if low == 'proc':
            self.proc = True
            self.events.append(('PROC',))
            return
        if low.startswith('p,'):
            return self._patch(line)
        if low == 'pushad':
            return self._push('pushad')
        if low in ('push free', 'pushfree'):
            return self._push('free')
        if low in ('push oep', 'pushoep'):
            return self._push('oep')
        if low in ('push out', 'pushout'):
            return self._push('out')
        if low == 'popad':
            return self._popad()
        if low == 'retn':
            self.inline += b'\xC3'
            self.events.append(('RETN',))
            return
        if low == 'nop':
            self.inline += b'\x90'
            self.events.append(('NOP',))
            return
        if low == 'endp':
            return self._endp()
        self.err('unknown command: %r' % line)

    # -- 各命令 -------------------------------------------------------------
    def _set_free(self, val):
        v = val.strip()
        if not v:
            return self.err('bad FREE line')
        self.free_used = True
        if v.lower() == 'auto':
            self.free_mode = 'auto'
            self.free_raw = 0
            self.events.append(('FREE', 'AUTO'))
        elif v.lower() == 'append':
            self.free_mode = 'append'
            self.free_raw = len(self.data) if self.data else 0
            self.events.append(('FREE', 'APPEND'))
        else:
            self.free_mode = 'fixed'
            self.free_raw = _hexval(v)
            self.events.append(('FREE', 'fixed', self.free_raw))
        return

    def _set_max(self, val):
        self.max_size = _hexval(val)
        self.events.append(('MAX_SIZE', self.max_size))
        return

    def _set_oep(self, val):
        self.oep = _hexval(val)
        self.events.append(('OEP', self.oep))
        return

    def _set_out(self, val):
        if not self.free_used:
            return self.err('OUT= must come after FREE=')
        self.out_va = _hexval(val)
        if self.pe is not None:
            self.out_raw = self.pe.va2raw(self.out_va)
            if self.out_raw == 0:
                return self.err('OUT VA %08X can not map to RAW' % self.out_va)
        self.events.append(('OUT', self.out_va, self.out_raw))
        return

    def _set_out_code(self, val):
        bs = parse_byte_list(val)
        self.out_code = bs
        self.stolen = len(bs)
        self.events.append(('OUT_CODE', bs))
        return

    def _bin(self, val):
        if not self.proc:
            return self.err('BIN= must come after PROC')
        bs = parse_byte_list(val)
        self.inline += bs
        self.events.append(('BIN', bs))
        return

    def _rest(self):
        if self.out_va == 0:
            return self.err('REST must come after OUT=')
        if not self.proc:
            return self.err('REST must come after PROC')
        n = self.stolen if self.stolen > 0 else 5
        # 读取原始被偷字节 (从原文件 RAW 处); 无 target 时用 00 占位
        orig = bytearray(n)
        if self.data is not None and self.out_raw:
            for k in range(n):
                pos = self.out_raw + k
                orig[k] = self.data[pos] if 0 <= pos < len(self.data) else 0
        code = bytearray(b'\xBF' + p32(self.out_va))     # mov edi, VA_OUT
        for k in range(n):
            code += b'\xB0' + bytes([orig[k]]) + b'\xAA'  # mov al,orig ; stosb
        self.inline += code
        self.events.append(('REST', n, bytes(orig)))
        return

    def _push(self, which):
        if not self.proc:
            return self.err('PUSH must come after PROC')
        if which == 'pushad':
            self.inline += b'\x60'
            self.events.append(('PUSHAD',))
        elif which == 'oep':
            if self.oep == 0:
                return self.err('PUSH OEP before OEP=')
            self.inline += b'\x68' + p32(self.oep)
            self.events.append(('PUSH OEP', self.oep))
        elif which == 'out':
            if self.out_va == 0:
                return self.err('PUSH OUT before OUT=')
            self.inline += b'\x68' + p32(self.out_va)
            self.events.append(('PUSH OUT', self.out_va))
        elif which == 'free':
            self.inline += b'\x68' + p32(0)
            self.push_free_fixups.append(len(self.inline) - 4)
            self.events.append(('PUSH FREE',))
        return

    def _popad(self):
        if not self.proc:
            return self.err('POPAD must come after PROC')
        self.inline += b'\x61'
        self.events.append(('POPAD',))
        return

    def _patch(self, line):
        # P,XXXXXXXX,YY,YY,..
        body = line[2:]
        if ',' not in body:
            return self.err('bad patch line: %r' % line)
        addr_s, rest = body.split(',', 1)
        addr = _hexval(addr_s)
        if addr == 0:
            return self.err('bad patch line (zero address): %r' % line)
        bs = parse_byte_list(rest) if rest.strip() else b''
        if not bs:
            return self.err('patch line has no bytes: %r' % line)
        if not self.proc:
            # 简单补丁: 直接改文件 RAW
            if self.pe is not None:
                raw = self.pe.va2raw(addr)
                if raw == 0:
                    return self.err('P addr %08X can not map to RAW' % addr)
            else:
                raw = 0
            self.simple.append((raw, bs, addr))
            self.events.append(('P(simple)', addr, raw, bs))
        else:
            self.proc_patch_ok = True
            code = encode_inline_patch(addr, bs)
            self.inline += code
            self.events.append(('P(inline)', addr, bs, code))
        return

    def _endp(self):
        if not self.proc:
            return self.err('ENDP without PROC')
        if not self.proc_patch_ok:
            return self.err('ENDP: no P,... command inside PROC')
        self.ended = True
        self.events.append(('ENDP',))
        return

    # -- 收尾: 定 free 空间 / 生成 JMP / 校验 / 回填 ------------------------
    def resolve(self):
        """在解析完成后调用, 计算 free_raw、默认 JMP、PUSH FREE 回填、MAX_SIZE 校验.
        需要 self.pe (及 self.data, 用于 APPEND 的文件大小)."""
        if self.errors:
            raise ScriptError('; '.join(self.errors))
        if not self.ended:
            raise ScriptError('script has no ENDP')
        if self.max_size and self.free_mode not in (None, 'auto'):
            raise ScriptError('MAX_SIZE can only be used with FREE=AUTO')

        needed = len(self.inline) + 6      # +6: push xxxxxxxx / retn 余量 (同源码)

        # 1) 确定 free_raw
        append = False
        if self.free_mode == 'fixed':
            free_raw = self.free_raw
        elif self.free_mode == 'append':
            append = True
            free_raw = len(self.data) if self.data is not None else self.free_raw
        else:  # auto 或 未指定 (默认 AUTO)
            if self.pe is None:
                raise ScriptError('FREE=AUTO needs a target PE to search free space')
            free_raw = self.pe.seek_free_space(needed)
            if free_raw == 0:
                raise ScriptError('not enough free space for inline patch (%d bytes)'
                                  % needed)
        self.free_raw = free_raw

        # 2) free 空间 VA
        free_va = self._free_va(free_raw, append)

        # 3) 默认 JMP (未显式 OUT_CODE 时)
        if self.out_code is None:
            self.stolen = 5
            if self.out_va == 0:
                raise ScriptError('no OUT= address to write the jump to')
            rel = free_va - (self.out_va + 5)
            self.out_code = b'\xE9' + p32(rel)
        else:
            self.stolen = len(self.out_code)

        # 4) MAX_SIZE 校验
        if self.max_size and self.max_size < needed:
            raise ScriptError('patch too big: needs %d bytes, MAX_SIZE=%d'
                              % (needed, self.max_size))

        # 5) 回填 PUSH FREE
        for off in self.push_free_fixups:
            self.inline[off:off + 4] = p32(free_va)

        self.free_va = free_va
        self.append = append
        self.needed = needed
        return self

    def _free_va(self, free_raw, append):
        if self.pe is None:
            return 0
        if append:
            s = self.pe.last_section()
            if s is None:
                return 0
            return self.pe.imagebase + s.va + (free_raw - s.rawptr)
        return self.pe.raw2va(free_raw)


# ---------------------------------------------------------------------------
# 报告辅助
# ---------------------------------------------------------------------------
def hr(title=''):
    print('-' * 68)
    if title:
        print(title)
        print('-' * 68)


def dump_inline(events):
    """把 script 计划里 inline 相关事件以可读方式打印."""
    for ev in events:
        kind = ev[0]
        if kind == 'BIN':
            print('    BIN   -> %s' % hx(ev[1]))
        elif kind == 'P(inline)':
            print('    P     -> [%08X] = %s   ; %s' %
                  (ev[1], hx(ev[2]), hx(ev[3])))
        elif kind == 'REST':
            print('    REST  -> restore %d byte(s): %s' % (ev[1], hx(ev[2])))
        elif kind in ('PUSHAD', 'POPAD', 'RETN', 'NOP'):
            print('    %s' % kind)
        elif kind == 'PUSH OEP':
            print('    PUSH  -> OEP %08X' % ev[1])
        elif kind == 'PUSH OUT':
            print('    PUSH  -> OUT %08X' % ev[1])
        elif kind == 'PUSH FREE':
            print('    PUSH  -> FREE (addr fixed at ENDP)')


# ---------------------------------------------------------------------------
# 子命令: build
# ---------------------------------------------------------------------------
def cmd_build(args):
    if not os.path.isfile(args.target):
        print('error: target not found: %s' % args.target, file=sys.stderr)
        return 2
    if not os.path.isfile(args.module):
        print('error: module script not found: %s' % args.module, file=sys.stderr)
        return 2

    with open(args.target, 'rb') as f:
        raw = f.read()
    try:
        pe = PEFile(raw)
    except ValueError as e:
        print('error: %s' % e, file=sys.stderr)
        return 2

    with open(args.module, 'r', encoding='latin1') as f:
        text = f.read()

    data = bytearray(raw)
    sb = ScriptBuilder(pe, bytes(raw))
    try:
        sb.parse(text)
        sb.resolve()
    except ScriptError as e:
        print('script error: %s' % e, file=sys.stderr)
        for er in sb.errors:
            print('  - %s' % er, file=sys.stderr)
        return 1

    out_path = args.output or _default_out(args.target)

    hr('HzorInline build  -  %s' % os.path.basename(args.target))
    print('target      : %s' % args.target)
    print('script      : %s' % args.module)
    print('imagebase   : %08X   sections: %d' % (pe.imagebase, pe.num_sections))
    print('OUT site    : VA %08X  RAW %08X' % (sb.out_va, sb.out_raw))
    print('FREE mode   : %s  -> RAW %08X  VA %08X (%d bytes needed)'
          % (sb.free_mode or 'AUTO', sb.free_raw, sb.free_va, sb.needed))
    print('OEP         : %08X' % sb.oep)
    if sb.max_size:
        print('MAX_SIZE    : %X' % sb.max_size)
    print('jump (OUT)  : %s   (%d stolen byte(s))'
          % (hx(sb.out_code), sb.stolen))
    print('inline code : %d byte(s)' % len(sb.inline))
    print('             %s' % hx(sb.inline))

    # 1) 简单补丁
    if sb.simple:
        hr('simple patches (before PROC, direct file writes)')
        for (raw_off, bs, addr) in sb.simple:
            print('  RAW %08X  <- %s   (VA %08X, %d byte(s))'
                  % (raw_off, hx(bs), addr, len(bs)))
            data[raw_off:raw_off + len(bs)] = bs

    # 2) 写 OUT 处的跳转
    if sb.out_raw:
        hr('write jump at OUT site')
        print('  RAW %08X  <- %s' % (sb.out_raw, hx(sb.out_code)))
        data[sb.out_raw:sb.out_raw + sb.stolen] = sb.out_code

    # 3) 写 inline 代码
    if sb.append:
        hr('append inline code (FREE=APPEND)')
        last = pe.last_section()
        old_rawsize = last.rawsize
        data += sb.inline
        new_rawsize = len(data) - last.rawptr
        struct.pack_into('<I', data, last.rawsize_field_off, new_rawsize)
        # 若 VirtualSize 小于新 RAW 覆盖, 一并抬高, 保持可加载
        if last.vsize < new_rawsize:
            struct.pack_into('<I', data, last.vsize_field_off, new_rawsize)
        print('  section "%s": SizeOfRawData %X -> %X  (+%d bytes)'
              % (last.name, old_rawsize, new_rawsize, len(sb.inline)))
        print('  appended %d byte(s) at RAW %08X (VA %08X)'
              % (len(sb.inline), sb.free_raw, sb.free_va))
    else:
        hr('write inline code')
        fr = sb.free_raw
        if fr + len(sb.inline) > len(data):
            print('error: free RAW %08X + %d exceeds file size %X'
                  % (fr, len(sb.inline), len(data)), file=sys.stderr)
            return 1
        print('  RAW %08X  <- %d byte(s)' % (fr, len(sb.inline)))
        data[fr:fr + len(sb.inline)] = sb.inline

    with open(out_path, 'wb') as f:
        f.write(data)
    print()
    print('output      : %s  (%d bytes)' % (out_path, len(data)))
    return 0


def _default_out(target):
    base, ext = os.path.splitext(target)
    return base + '_hzinlined' + (ext or '.exe')


# ---------------------------------------------------------------------------
# 子命令: free
# ---------------------------------------------------------------------------
def cmd_free(args):
    if not os.path.isfile(args.target):
        print('error: target not found: %s' % args.target, file=sys.stderr)
        return 2
    with open(args.target, 'rb') as f:
        raw = f.read()
    try:
        pe = PEFile(raw)
    except ValueError as e:
        print('error: %s' % e, file=sys.stderr)
        return 2

    hr('HzorInline free-space scan  -  %s' % os.path.basename(args.target))
    print('imagebase %08X  filealign %X  sections %d'
          % (pe.imagebase, pe.file_align, pe.num_sections))
    print()
    print('sections:')
    for s in pe.sections:
        print('  #%d %-8s VA %08X  VSize %08X  RAW %08X  RawSize %08X'
              % (s.index, s.name, s.va, s.vsize, s.rawptr, s.rawsize))
    print()
    caves = pe.caves(args.min)
    hr('candidate code caves (all-zero runs, min length %d)' % args.min)
    if not caves:
        print('  (none found)')
    for (raw_off, length) in caves:
        va = pe.raw2va(raw_off)
        print('  RAW %08X  VA %08X  length %X (%d) bytes'
              % (raw_off, va, length, length))
    print()
    # 演示 seek_free_space 的取法
    for need in (16, 64, 256):
        fr = pe.seek_free_space(need)
        if fr:
            print('  seek_free_space(%d) -> RAW %08X  VA %08X'
                  % (need, fr, pe.raw2va(fr)))
        else:
            print('  seek_free_space(%d) -> not enough space' % need)
    return 0


# ---------------------------------------------------------------------------
# 子命令: script
# ---------------------------------------------------------------------------
def cmd_script(args):
    if not os.path.isfile(args.module):
        print('error: module script not found: %s' % args.module, file=sys.stderr)
        return 2
    with open(args.module, 'r', encoding='latin1') as f:
        text = f.read()

    pe = None
    raw = None
    if args.target:
        if not os.path.isfile(args.target):
            print('error: target not found: %s' % args.target, file=sys.stderr)
            return 2
        with open(args.target, 'rb') as f:
            raw = f.read()
        try:
            pe = PEFile(raw)
        except ValueError as e:
            print('error: %s' % e, file=sys.stderr)
            return 2

    sb = ScriptBuilder(pe, raw)
    sb.parse(text)

    hr('HzorInline script plan  -  %s' % os.path.basename(args.module))
    if sb.errors:
        print('PARSE ERRORS:')
        for er in sb.errors:
            print('  - %s' % er)
        return 1

    for ev in sb.events:
        k = ev[0]
        if k == 'FREE':
            print('FREE   = %s' % ev[1] if len(ev) == 2 else 'FREE   = %08X' % ev[2])
        elif k == 'MAX_SIZE':
            print('MAX_SIZE = %X' % ev[1])
        elif k == 'OEP':
            print('OEP    = %08X' % ev[1])
        elif k == 'OUT':
            extra = ('  (RAW %08X)' % ev[2]) if ev[2] else '  (RAW unresolved: no target)'
            print('OUT    = %08X%s' % (ev[1], extra))
        elif k == 'OUT_CODE':
            print('OUT_CODE = %s  (%d bytes)' % (hx(ev[1]), len(ev[1])))
        elif k == 'P(simple)':
            rawextra = ('RAW %08X' % ev[2]) if ev[2] else 'RAW unresolved'
            print('P      = [%08X] = %s   ; simple, %s'
                  % (ev[1], hx(ev[3]), rawextra))
        elif k == 'PROC':
            print('PROC   (main procedure begins)')
        elif k == 'ENDP':
            print('ENDP')
        else:
            dump_inline([ev])

    # 尝试解析 (需要 target 才能定 RAW / free)
    if pe is not None:
        try:
            sb.resolve()
        except ScriptError as e:
            print()
            print('RESOLVE ERROR: %s' % e)
            return 1
        hr('resolved')
        print('free      : %s RAW %08X  VA %08X  (%d bytes needed)'
              % (sb.free_mode or 'AUTO', sb.free_raw, sb.free_va, sb.needed))
        print('jump      : %s  (%d stolen byte(s)) at RAW %08X'
              % (hx(sb.out_code), sb.stolen, sb.out_raw))
        print('inline    : %d byte(s)' % len(sb.inline))
        print('            %s' % hx(sb.inline))
    else:
        print()
        print('(no target given: RAW addresses, free-space choice and the final')
        print(' jump/REST bytes are resolved only at build time)')
    return 0


# ---------------------------------------------------------------------------
# 入口
# ---------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(
        prog='main.py',
        description='HzorInline v1.3 beta (20060824) rewrite: two-pass inline '
                    'patch assembler for packed PE files (stdlib only).')
    sub = p.add_subparsers(dest='cmd')

    b = sub.add_parser('build', help='parse a module script and write a patched PE')
    b.add_argument('target', help='packed PE to patch')
    b.add_argument('module', help='module script (.asm/.script text)')
    b.add_argument('-o', '--output', default=None, help='output PE path')
    b.set_defaults(func=cmd_build)

    f = sub.add_parser('free', help='list candidate code caves / free space')
    f.add_argument('target', help='PE to scan')
    f.add_argument('--min', dest='min', type=int, default=16,
                   help='minimum cave length to report (default 16)')
    f.set_defaults(func=cmd_free)

    s = sub.add_parser('script', help='validate/parse a module script and print plan')
    s.add_argument('module', help='module script text')
    s.add_argument('target', nargs='?', default=None,
                   help='optional target PE (enables RAW/free resolution)')
    s.set_defaults(func=cmd_script)
    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, 'func', None):
        parser.print_help()
        return 0
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())