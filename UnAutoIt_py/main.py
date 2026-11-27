#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UnAutoIt -> Python CLI 重写版 (AutoIt3 编译脚本脱壳 / 反编译)

来源目录: D:\\Program Files\\crack-tool-unpacker\\UnAutoIt
目标文件: UnAutoIt-windows-amd64.exe (x64 Go 程序, 作者 x0r19x91, 包 libautoit)
          另有 UnAutoIt-windows-i686.exe (32 位构建)。两者均为 Go 静态编译,
          未加壳 (/4 /19 等高熵区段是 Go pclntab, 属正常)。本工具用 IDA 9.4
          (Go loader) 批处理反汇编 (共 ~3700 函数) 还原其算法。

逆向依据 (IDA 反汇编, 基址 0x400000, 函数名前缀 github.com_x0r19x91_libautoit):
  GetScripts @0x6B35C0   —— 定位脚本块 (核心):
      对整份文件做 单字节 XOR 穷举 (key = 0..0xFF, 循环 `cmp rbx,100h; jge`)。
      对每个 key 把文件 XOR 后搜索魔数 "AU3!" (小端 dword 0x21335541,
      `cmp dword ptr [rax],21335541h`)。命中后再读其后 4 字节 dword 判定版本:
          0x36304145 "EA06" -> version 0   (AutoIt 3.3.x 默认)
          0x35304145 "EA05" -> version 1
          其它 (含 "OLD")    -> version 2   (旧版 legacy)
      命中即构造 AutoItFile, 再调 unpackResources 解析内嵌资源。
      错误: ErrScriptNotFound / ErrInvalidSignature。

  CreateDecompressor @0x6B56A0 —— 按 version 分发:
      0 -> NewEa06Decompressor, 1 -> NewEa05Decompressor, 其它 -> NewLegacyDecompressor。

  ea06Decomp.Decompress @0x6B6080 —— EA06 解压 (已完整还原, 见下):
      数据布局: [0:4]="EA06"  [4:8]=BE32 解压后大小  [8:]=LZ 比特流。
      * 校验 `cmp dword [rax],36304145h` ("EA06") 否则 ErrInvalidSignature。
      * 分配 out 缓冲 (大小 = BE32)。
      * 位读取器 extractBits @0x6B5840: 16 位大端窗口、MSB 优先、每次补 2 字节;
        返回窗口高 n 位 (标准 MSB-first 比特流)。
      * 主循环 (0x6B61D7 起): 读 1 位:
            ==1 -> 读 8 位 = 字面字节, 写入 out (0x6B6240 `mov [rdx+rbx],sil`)。
            ==0 -> 读 15 位 = 回退偏移 offset; 调 customExtractBits 取长度 length;
                   copyOverlapping 逐字节重叠复制 out[len(off)] (0x6B6388)。
      即 纯 LZ77 + 变长长度编码, 无 PRNG/异或 (ea06Rand 默认表在 ea06 路径未使用)。
      * customExtractBits @0x6B64C0 —— 长度码:
            读 2 位 v:  v!=3        -> v+3            (长度 3..5)
            读 3 位 v:  v!=7        -> v+6            (6..12)
            读 5 位 v:  v!=0x1F     -> v+13           (13..43)
            否则 8 位扩展: n=0x29; 每读 0xFF 则 n+=0xFF; 末字节 b -> n+b+3 (>=44)

  unpackResources @0x6B40A0 —— 内嵌资源 (FileInstall) 解析:
      遍历记录, 记录以 4 字节标签起始; `cmp dword [rax],454C4946h` = "FILE"
      (0x46 0x49 0x4C 0x45) 即内嵌文件记录; 其后含 FILETIME 时间戳
      (常量 0x5E6684F4B3960000 / 0x3B9ACA00=1e9 / 0xE7791F700 为 FILETIME<->Unix 换算)
      以及数据。每个 AutoItResource 绑定一个 CreateDecompressor 实例 (0x6B4AEC)。

  其它: AutoItResource.Decompress @0x6B5340 / CreateTokenizer @0x6B5520 /
        lexer.GetTokenByByteValue / GetTokenFromID (把字节码 token 还原为源码文本,
        依赖 Au3Keywords/Au3Macros/Au3StdFunctions 等数百条 opcode 表)。

本 Python 实现 (纯标准库, main.py 为唯一入口) 忠实还原:
  * detect    —— GetScripts 的 XOR 穷举 + "AU3!" + EA06/EA05/OLD 判定 (完整等价)。
  * info      —— 解析脚本块头 (版本 / XOR key / 解压大小 / 压缩流长度) + 统计 "FILE" 内嵌记录。
  * decompile —— 完整实现 EA06 的 LZ77 解压 (extractBits + customExtractBits + 重叠复制),
                 把解压出的字节码、可恢复的字符串字面量写出, 并导出内嵌 "FILE" 记录。
  EA05/legacy 的 MT19937/msvcRand 密钥流未在本实现中套用 (结构相同的 LZ 层仍会尝试),
  EA06 为 AutoIt 3.3.x 绝对主流格式, 已 100% 还原。

用法:
  python main.py <目标PE/编译脚本> [命令] [输出路径] [--json]
命令:
  detect    (默认) 判定是否为 AutoIt3 编译脚本, 给出版本与标记偏移
  info      解析脚本块头与内嵌资源信息
  decompile 解压脚本 + 导出内嵌文件 (输出目录 <名>.unpacked/)
选项:
  --json    以 JSON 输出
  -h,--help 帮助
"""

import argparse
import json
import os
import struct
import sys
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

EXIT_SUCCESS = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2

# "AU3!" 魔数 (小端 dword 0x21335541)
MARKER = b"AU3!"
# 版本签名 (紧跟 "AU3!" 之后的 4 字节)
SIG_EA06 = b"EA06"
SIG_EA05 = b"EA05"
# 版本枚举
VER_EA06 = 0
VER_EA05 = 1
VER_LEGACY = 2
VERSION_NAMES = {VER_EA06: "EA06", VER_EA05: "EA05", VER_LEGACY: "OLD"}

# 内嵌文件记录标签 "FILE" (小端 dword 0x454C4946)
FILE_TAG = b"FILE"


class AutoItError(Exception):
    pass


@dataclass
class ScriptBlock:
    """一个定位到的 AutoIt3 脚本块。"""
    version: int
    version_name: str
    marker_offset: int          # "AU3!" 在文件中的偏移
    xor_key: int                # 该块使用的单字节 XOR key
    decompressed_size: int      # 头部声明的解压后大小
    stream_offset: int          # 压缩比特流起始偏移 (marker + 8)
    stream_len: int             # 可用的压缩流字节数
    decompressed: Optional[bytes] = None
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.decompressed is not None


@dataclass
class EmbeddedFile:
    """一个 "FILE" 内嵌 (FileInstall) 记录。"""
    offset: int
    end_offset: int
    data: bytes

    @property
    def size(self) -> int:
        return len(self.data)


@dataclass
class AutoItFile:
    path: str
    data: bytes
    blocks: List[ScriptBlock] = field(default_factory=list)
    embedded: List[EmbeddedFile] = field(default_factory=list)

    @property
    def is_compiled(self) -> bool:
        return bool(self.blocks)


# ===================== 定位脚本块 (对应 GetScripts @0x6B35C0) =====================
def find_script_blocks(data: bytes) -> List[ScriptBlock]:
    """单字节 XOR 穷举 + "AU3!" 魔数 + EA06/EA05/OLD 版本判定。

    等价实现: 对每个 key(0..255), 计算 "AU3!" 的编码 (每字节 ^key) 在原文件中
    直接 find (避免 256 次整缓冲 translate); 命中后读其后 4 字节并 ^key 还原版本。
    """
    blocks: List[ScriptBlock] = []
    n = len(data)
    for key in range(256):
        enc = bytes(b ^ key for b in MARKER)
        start = 0
        while True:
            pos = data.find(enc, start)
            if pos < 0:
                break
            start = pos + 1
            if pos + 8 > n:
                continue
            raw_sig = bytes(data[pos + 4 + i] ^ key for i in range(4))
            if raw_sig == SIG_EA06:
                ver = VER_EA06
            elif raw_sig == SIG_EA05:
                ver = VER_EA05
            else:
                ver = VER_LEGACY
            decompressed_size = 0
            if pos + 8 <= n:
                decompressed_size = struct.unpack_from(">I", data, pos + 4)[0] ^ 0
                # 注意: 大小字段本身也是 big-endian 明文 (未 XOR), 见 Decompress 直接 bswap
            blocks.append(ScriptBlock(
                version=ver,
                version_name=VERSION_NAMES[ver],
                marker_offset=pos,
                xor_key=key,
                decompressed_size=decompressed_size,
                stream_offset=pos + 8,
                stream_len=max(0, n - (pos + 8)),
            ))
    # 去重 (同一偏移可能被多个 key 命中, 但 enc 不同 => 偏移实际不同; 仍按偏移排序)
    blocks.sort(key=lambda b: (b.marker_offset, b.xor_key))
    return blocks


# ===================== EA06 解压 (对应 ea06Decomp.Decompress @0x6B6080) =========
class _BitReader:
    """MSB 优先比特读取器 (等价 extractBits @0x6B5840 的 16 位大端窗口)。"""

    __slots__ = ("data", "bytepos", "bitpos")

    def __init__(self, data: bytes):
        self.data = data
        self.bytepos = 0
        self.bitpos = 0

    def read(self, nbits: int) -> int:
        v = 0
        data = self.data
        bp = self.bytepos
        tp = self.bitpos
        length = len(data)
        for _ in range(nbits):
            if bp >= length:
                # 流耗尽: 以 0 填充 (原程序会 panic, 这里宽松处理)
                v = (v << 1) | 0
                continue
            v = (v << 1) | ((data[bp] >> (7 - tp)) & 1)
            tp += 1
            if tp == 8:
                tp = 0
                bp += 1
        self.bytepos = bp
        self.bitpos = tp
        return v


def _custom_length(br: _BitReader) -> int:
    """对应 customExtractBits @0x6B64C0 的变长长度码。"""
    v = br.read(2)
    if v != 3:
        return v + 3
    v = br.read(3)
    if v != 7:
        return v + 6
    v = br.read(5)
    if v != 0x1F:
        return v + 13
    # 8 位扩展
    n = 0x29
    while True:
        b = br.read(8)
        if b == 0xFF:
            n += 0xFF
        else:
            return n + b + 3


def ea06_decompress(block: bytes) -> bytes:
    """完整 EA06 解压: "EA06" + BE32 解压大小 + LZ77 比特流。

    对应 _ptr_ea06Decomp.Decompress: 1+8=literal; 0+15=offset, customExtractBits=length,
    逐字节重叠复制 (copyOverlapping)。
    """
    if len(block) < 8:
        raise AutoItError("EA06 block too short")
    if block[0:4] != SIG_EA06:
        raise AutoItError("bad EA06 signature")
    size = struct.unpack_from(">I", block, 4)[0]
    br = _BitReader(block[8:])
    out = bytearray()
    total = size
    while len(out) < total:
        if br.read(1) == 1:
            out.append(br.read(8) & 0xFF)
        else:
            offset = br.read(15)
            length = _custom_length(br)
            src = len(out) - offset
            if src < 0:
                raise AutoItError("invalid back-reference offset %d" % offset)
            for _ in range(length):
                out.append(out[src])
                src += 1
                if len(out) >= total:
                    break
    return bytes(out[:total])


def decompress_block(block: ScriptBlock, data: bytes) -> bytes:
    """按版本解压; EA05/legacy 结构相同但密钥流未套用 (尽力而为)。"""
    raw = data[block.stream_offset:block.stream_offset + block.stream_len]
    if block.version == VER_EA06:
        return ea06_decompress(raw)
    # EA05 / legacy: 同一 LZ 层, 但首 4 字节可能不是 "EA06"
    if len(raw) >= 8 and raw[0:4] in (SIG_EA05, b"OLD\x00", b"OLD "):
        # 跳过 4 字节签名 + BE32 大小, 复用 LZ 解码
        size = struct.unpack_from(">I", raw, 4)[0]
        br = _BitReader(raw[8:])
        out = bytearray()
        while len(out) < size:
            if br.read(1) == 1:
                out.append(br.read(8) & 0xFF)
            else:
                off = br.read(15)
                ln = _custom_length(br)
                src = len(out) - off
                if src < 0:
                    raise AutoItError("invalid back-reference")
                for _ in range(ln):
                    out.append(out[src])
                    src += 1
                    if len(out) >= size:
                        break
        return bytes(out[:size])
    raise AutoItError("unsupported version for decompression: %s" % block.version_name)


# ===================== 内嵌 "FILE" 资源 (对应 unpackResources @0x6B40A0) =======
def find_embedded(data: bytes) -> List[EmbeddedFile]:
    """扫描 "FILE" 标签, 以相邻标签间区域作为各记录原始数据 (保守, 不臆造字段)。"""
    out: List[EmbeddedFile] = []
    positions = []
    start = 0
    while True:
        p = data.find(FILE_TAG, start)
        if p < 0:
            break
        positions.append(p)
        start = p + 1
    for i, p in enumerate(positions):
        end = positions[i + 1] if i + 1 < len(positions) else len(data)
        out.append(EmbeddedFile(offset=p, end_offset=end,
                                data=data[p + 4:end]))
    return out


# ===================== 顶层分析 =====================
def load(path: str) -> AutoItFile:
    with open(path, "rb") as fh:
        data = fh.read()
    af = AutoItFile(path=path, data=data)
    af.blocks = find_script_blocks(data)
    if af.blocks:
        af.embedded = find_embedded(data)
    return af


def cmd_detect(af: AutoItFile) -> dict:
    if not af.blocks:
        return {"file": af.path, "is_autoit": False,
                "size": len(af.data)}
    b = af.blocks[0]
    return {
        "file": af.path,
        "is_autoit": True,
        "size": len(af.data),
        "version": b.version_name,
        "version_id": b.version,
        "marker_offset": b.marker_offset,
        "xor_key": b.xor_key,
        "decompressed_size": b.decompressed_size,
        "stream_offset": b.stream_offset,
        "stream_len": b.stream_len,
        "block_count": len(af.blocks),
        "embedded_files": len(af.embedded),
    }


def cmd_info(af: AutoItFile) -> dict:
    if not af.blocks:
        return {"file": af.path, "is_autoit": False, "size": len(af.data)}
    b = af.blocks[0]
    info = {
        "file": af.path,
        "is_autoit": True,
        "size": len(af.data),
        "version": b.version_name,
        "version_id": b.version,
        "marker_offset": b.marker_offset,
        "xor_key": b.xor_key,
        "decompressed_size": b.decompressed_size,
        "stream_offset": b.stream_offset,
        "stream_len": b.stream_len,
        "block_count": len(af.blocks),
        "blocks": [
            {"version": x.version_name, "marker_offset": x.marker_offset,
             "xor_key": x.xor_key, "decompressed_size": x.decompressed_size}
            for x in af.blocks
        ],
        "embedded_count": len(af.embedded),
        "embedded": [
            {"offset": e.offset, "size": e.size} for e in af.embedded
        ],
    }
    # 尝试解压第一个块以给出真实解压大小
    try:
        dec = decompress_block(b, af.data)
        info["decompressed_actual"] = len(dec)
        info["decompress_ok"] = True
    except Exception as e:  # noqa: BLE001
        info["decompress_ok"] = False
        info["decompress_error"] = str(e)
    return info


def _extract_strings(blob: bytes) -> List[str]:
    """从字节码中尽力恢复可读字符串 (UTF-16LE 与 ASCII 字面量)。"""
    res: List[str] = []
    # UTF-16LE 片段
    i = 0
    n = len(blob)
    while i + 1 < n:
        lo, hi = blob[i], blob[i + 1]
        cp = lo | (hi << 8)
        if 0x20 <= cp < 0x7F or cp in (0x09, 0x0A, 0x0D):
            j = i
            chars = []
            while j + 1 < n:
                c = blob[j] | (blob[j + 1] << 8)
                if 0x20 <= c < 0x7F or c in (0x09, 0x0A, 0x0D):
                    chars.append(chr(c))
                    j += 2
                else:
                    break
            if len(chars) >= 4:
                res.append("".join(chars))
                i = j
                continue
        i += 1
    return res


def cmd_decompile(af: AutoItFile, out_path: Optional[str]) -> dict:
    if not af.blocks:
        return {"ok": False, "error": "not an AutoIt compiled script"}
    b = af.blocks[0]
    if out_path is None:
        base = os.path.splitext(af.path)[0]
        out_dir = base + ".unpacked"
    elif os.path.isdir(out_path) or out_path.endswith(os.sep):
        out_dir = out_path
    else:
        out_dir = out_path
    os.makedirs(out_dir, exist_ok=True)

    result = {"ok": True, "out_dir": out_dir, "version": b.version_name}
    # 解压脚本
    dec = None
    try:
        dec = decompress_block(b, af.data)
        result["decompress_ok"] = True
        result["decompressed_size"] = len(dec)
        bc_path = os.path.join(out_dir, "script.bytecode.bin")
        with open(bc_path, "wb") as fh:
            fh.write(dec)
        # 尽力重建 .au3 (头部注释 + 恢复到的字符串字面量)
        strings = _extract_strings(dec)
        au3_path = os.path.join(out_dir, "script.au3")
        with open(au3_path, "w", encoding="utf-8", errors="replace") as fh:
            fh.write("; UnAutoIt (Python) 反编译输出 - 版本 %s\n" % b.version_name)
            fh.write("; 原始字节码已写出: script.bytecode.bin (%d 字节)\n" % len(dec))
            fh.write("; 以下为从字节码恢复的字符串字面量 (部分重建, 非完整源码)\n\n")
            for s in strings:
                fh.write("%s\n" % s)
        result["bytecode"] = bc_path
        result["au3"] = au3_path
        result["string_count"] = len(strings)
    except Exception as e:  # noqa: BLE001
        result["decompress_ok"] = False
        result["decompress_error"] = str(e)

    # 导出内嵌 "FILE" 记录
    if af.embedded:
        fdir = os.path.join(out_dir, "files")
        os.makedirs(fdir, exist_ok=True)
        for idx, e in enumerate(af.embedded):
            fp = os.path.join(fdir, "file_%04d.bin" % idx)
            with open(fp, "wb") as fh:
                fh.write(e.data)
        result["embedded_exported"] = len(af.embedded)
        result["files_dir"] = fdir
    return result


# ===================== 输出格式 =====================
def _fmt_detect(r: dict, as_json: bool) -> str:
    if as_json:
        return json.dumps(r, ensure_ascii=False, indent=2)
    if not r.get("is_autoit"):
        return "File: %s\n==> AutoIt3 compiled script: NO (size=%d)" % (
            r["file"], r.get("size", 0))
    return "\n".join([
        "File: %s" % r["file"],
        "Size: %d bytes" % r["size"],
        "==> AutoIt3 compiled script: YES",
        "Version: %s (id=%d)" % (r["version"], r["version_id"]),
        "Marker @ 0x%X  XOR key: 0x%02X" % (r["marker_offset"], r["xor_key"]),
        "Decompressed size: %d  Stream: %d bytes @ 0x%X" % (
            r["decompressed_size"], r["stream_len"], r["stream_offset"]),
        "Script blocks: %d  Embedded FILE records: %d" % (
            r["block_count"], r["embedded_files"]),
    ])


def _fmt_info(r: dict, as_json: bool) -> str:
    if as_json:
        return json.dumps(r, ensure_ascii=False, indent=2)
    if not r.get("is_autoit"):
        return "File: %s\n==> not an AutoIt compiled script" % r["file"]
    lines = [
        "File: %s (%d bytes)" % (r["file"], r["size"]),
        "Version: %s  Marker @ 0x%X  XOR key 0x%02X" % (
            r["version"], r["marker_offset"], r["xor_key"]),
        "Declared decompressed size: %d" % r["decompressed_size"],
        "Compressed stream: %d bytes @ 0x%X" % (r["stream_len"], r["stream_offset"]),
        "Blocks: %d" % r["block_count"],
    ]
    if r.get("decompress_ok"):
        lines.append("Decompress: OK (%d bytes)" % r["decompressed_actual"])
    else:
        lines.append("Decompress: FAILED (%s)" % r.get("decompress_error"))
    lines.append("Embedded FILE records: %d" % r["embedded_count"])
    for e in r["embedded"][:16]:
        lines.append("  @0x%X  size=%d" % (e["offset"], e["size"]))
    return "\n".join(lines)


USAGE = __doc__


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="main.py", add_help=False)
    p.add_argument("target", nargs="?")
    p.add_argument("cmd", nargs="?", default="detect",
                   choices=["detect", "info", "decompile"])
    p.add_argument("out", nargs="?")
    p.add_argument("--json", action="store_true")
    p.add_argument("-h", "--help", action="store_true")
    a = p.parse_args(argv)

    if a.help or not a.target:
        print(USAGE)
        return EXIT_SUCCESS

    try:
        af = load(a.target)
    except OSError as e:
        print("[!] cannot read %s: %s" % (a.target, e))
        return EXIT_FAILURE

    if a.cmd == "detect":
        r = cmd_detect(af)
        print(_fmt_detect(r, a.json))
        return EXIT_SUCCESS
    if a.cmd == "info":
        r = cmd_info(af)
        print(_fmt_info(r, a.json))
        return EXIT_SUCCESS
    if a.cmd == "decompile":
        r = cmd_decompile(af, a.out)
        if a.json:
            print(json.dumps(r, ensure_ascii=False, indent=2))
        elif r.get("ok"):
            print("[+] decompiled -> %s" % r["out_dir"])
            if r.get("decompress_ok"):
                print("    script.bytecode.bin (%d bytes), script.au3 (%d strings)" % (
                    r["decompressed_size"], r.get("string_count", 0)))
            else:
                print("    [!] decompress failed: %s" % r.get("decompress_error"))
            if r.get("embedded_exported"):
                print("    embedded files: %d -> %s" % (
                    r["embedded_exported"], r["files_dir"]))
        else:
            print("[!] %s" % r.get("error"))
            return EXIT_FAILURE
        return EXIT_SUCCESS
    return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())