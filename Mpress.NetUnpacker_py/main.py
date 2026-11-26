#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Mpress .Net Unpacker (by COB - cob_rce@hotmail.com) — Python CLI rewrite
=======================================================================

原程序：Mpress.NetUnpacker/Mpress .net unpacker.exe
        + Mpress.NetUnpacker/MpressClass.dll  (核心解压逻辑 mpress.Unpack)

原程序是一个 WinForms 拖放工具：把 MPress 加壳的 .NET 程序集拖进去，它会：
  1. 解析 PE，定位 MPress 压缩数据块；
  2. 用 LZMAT 算法解压，还原出原始 .NET 程序集字节；
  3. MPress 会把资源(Resource)段剥离到壳里，这里把原资源段回填并修正 RVA；
  4. 输出 "<文件名>.unpacked<扩展名>"。

本程序把上述逻辑重写为纯 Python 命令行工具，无第三方依赖：
    python main.py <file1> [file2 ...]

每个输入文件解包成功后写出 <name>.unpacked<ext>；失败打印错误。

算法来源：MpressClass.dll 反编译（ICSharpCode.Decompiler）逐行移植，保持
与原始 unsafe 指针代码完全一致的位级行为（半字节 nibble 状态机）。
"""

import argparse
import os
import struct
import sys

# ---------------------------------------------------------------------------
# 小端读取辅助（对应 C# 的 *(int*)(ptr+off) / *(ushort*)(ptr+off)）
# 越界读取时以 0 填充，避免崩溃；合法 MPress 数据自带足够填充，不会触发。
# ---------------------------------------------------------------------------
def rd(buf, off, n):
    if off < 0:
        off = 0
    chunk = buf[off:off + n]
    if len(chunk) < n:
        chunk = bytes(chunk) + b"\x00" * (n - len(chunk))
    return int.from_bytes(chunk, "little")


def rd_u16(buf, off):
    return rd(buf, off, 2)


def rd_u32(buf, off):
    return rd(buf, off, 4)


def w32(out, off, value):
    """向 out 写入 4 字节小端，越界自动忽略（保持与定长输出缓冲一致）。"""
    if off < 0 or off + 4 > len(out):
        return
    out[off:off + 4] = (value & 0xFFFFFFFF).to_bytes(4, "little")


# ---------------------------------------------------------------------------
# LZMAT 解压（mpress.Unpack.lzmat 的精确移植）
#   pOs : 输出缓冲（bytearray，长度 = 解压后大小）
#   pIs : 压缩输入（bytes）
#   cI  : 压缩输入有效长度
# 返回写入输出缓冲的字节数；0 表示失败。
# ---------------------------------------------------------------------------
def lzmat(pOs, pIs, cI):
    out = pOs
    inp = pIs
    out[0] = inp[4] & 0xFF
    num = 5          # 输入游标
    num2 = 1         # 输出游标
    b = 0            # 半字节(nibble)状态：0=高半字节优先, 1=已用低半字节

    while num < cI - b:
        b2 = inp[num] & 0xFF
        num += 1
        if b != 0:
            b2 = (b2 >> 4) & 0xFF
            b2 = (b2 + ((inp[num] << 4) & 0xFF)) & 0xFF

        num3 = 0
        while num3 < 8 and num < cI - b:
            if (b2 & 0x80) == 0x80:
                # ---- 匹配(压缩)块 ----
                num4 = rd_u32(inp, num)
                if b != 0:
                    num4 >>= 4
                num += 1
                num4 &= 0xFFFFF
                if num2 < 2177:
                    num5 = num4 >> 1
                    if (num4 & 1) == 1:
                        num += b
                        num5 = (num5 & 0x7FF) + 129
                        b = (b ^ 1) & 0xFF
                    else:
                        num5 = (num5 & 0x7F) + 1
                else:
                    num5 = num4 >> 2
                    low = num4 & 3
                    if low == 0:
                        num5 = (num5 & 0x3F) + 1
                    elif low == 1:
                        num += b
                        num5 = (num5 & 0x3FF) + 65
                        b = (b ^ 1) & 0xFF
                    elif low == 2:
                        num5 = (num5 & 0x3FFF) + 1089
                        num += 1
                    else:  # low == 3
                        num += 1 + b
                        num5 = (num5 & 0x3FFFF) + 17473
                        b = (b ^ 1) & 0xFF

                num6 = rd_u16(inp, num)
                if b != 0:
                    num6 >>= 4
                    b = 0
                    num += 1
                else:
                    num6 &= 0xFFF
                    b = 1

                if (num6 & 0xF) != 15:
                    num6 = (num6 & 0xF) + 3
                else:
                    num += 1
                    if num6 != 4095:
                        num6 = (num6 >> 4) + 18
                    else:
                        num6 = rd_u32(inp, num)
                        if b != 0:
                            num6 >>= 4
                        num6 &= 0xFFFF
                        num += 2
                        if num6 == 65535:
                            # 大块原始拷贝
                            if b != 0:
                                num6 = (rd_u32(inp, num - 4) & 0xFC) << 5
                                num += 1
                                b = 0
                            else:
                                num6 = (rd_u32(inp, num - 5) & 0xFC0) << 1
                            num6 += (b2 & 0x7F) + 4
                            num6 <<= 1
                            while num6 != 0:
                                w32(out, num2, rd_u32(inp, num))
                                num += 4
                                num2 += 4
                                num6 -= 1
                            break  # 跳出内层 8 次循环
                        num6 += 273

                num7 = num2 - num5          # 回溯复制起点
                while num6 != 0:
                    if 0 <= num7 < len(out):
                        out[num2] = out[num7]
                    num2 += 1
                    num7 += 1
                    num6 -= 1
            else:
                # ---- 字面量(未压缩)块 ----
                if num2 < len(out):
                    out[num2] = inp[num] & 0xFF
                if b != 0:
                    if 0 <= num2 < len(out):
                        out[num2] = (out[num2] >> 4) & 0xFF
                        out[num2] = (out[num2] + ((inp[num + 1] << 4) & 0xFF)) & 0xFF
                num2 += 1
                num += 1

            num3 += 1
            b2 = (b2 << 1) & 0xFF

    return num2


# ---------------------------------------------------------------------------
# lz：校验压缩流头并调用 lzmat（mpress.Unpack.lz）
#   c : 压缩数据；l : 有效长度
# 成功返回 (True, 解压字节)；失败返回 (False, None)
# ---------------------------------------------------------------------------
def lz(c, l):
    if c[4] != 77 or c[6] != 90:   # 'M' ... 'Z'
        return False, None
    size = 8 + c[0] + (c[1] << 8) + (c[2] << 16) + (c[3] << 24)
    out = bytearray(size)
    written = lzmat(out, c, l)
    if written != 0:
        return True, bytes(out)
    return False, None


# ---------------------------------------------------------------------------
# lf：打开文件，定位并解压 MPress 数据（mpress.Unpack.lf）
# 成功返回 (True, 解压字节)；失败返回 (False, None)
# ---------------------------------------------------------------------------
def lf(fn):
    with open(fn, "rb") as f:
        data = f.read()
    total = len(data)
    if total < 0x40:
        return False, None
    num2 = rd_u32(data, 60)            # e_lfanew
    if 2 <= num2 <= total - 512:
        num3 = rd_u32(data, num2)      # PE 签名
        if num3 == 17744:              # 0x4550 "PE\0\0"
            num2 += 348
            num4 = rd_u32(data, num2)  # 压缩数据块偏移
            if num4 < total and num4 >= 768:
                num4 += 16
                length = total - num4
                if length > 0:
                    comp = data[num4:num4 + length]
                    ok, out = lz(comp, length)
                    return ok, out
    return False, None


# ---------------------------------------------------------------------------
# ConvertRVA2OFFSET：RVA -> 文件偏移（mpress 原版 ConvertRVA2OFFSET）
# 注意：原程序只读 PE[60] / PE[6] 单字节，这里保持同样行为。
# ---------------------------------------------------------------------------
def convert_rva_to_offset(rva, pe):
    num = pe[60]                       # e_lfanew 低字节
    # 第一个节表项 VirtualAddress 位于 num+248+12
    if rva < rd_u32(pe, num + 248 + 12):
        return rva
    num_sections = rd_u16(pe, num + 6)  # NumberOfSections 位于 e_lfanew+6
    for i in range(1, num_sections):
        va = rd_u32(pe, num + 248 + i * 40 + 12)
        if rva < va:
            prev_va = rd_u32(pe, num + 248 + i * 40 + 12 - 40)
            raw_ptr = rd_u32(pe, num + 248 + i * 40 + 12 - 40 + 8)
            return (rva - prev_va) + raw_ptr
    return 0


# ---------------------------------------------------------------------------
# FixResource：把资源目录里的数据 RVA 从“壳内基址”改写到“解包后基址”
# （mpress 原版 FixResource）
#   ResourceSection : 资源段字节(bytearray，会被就地修改)
#   PackedResDir    : 壳文件资源目录 RVA
#   UnpackedResDir  : 解包文件资源目录 RVA
# ---------------------------------------------------------------------------
def fix_resource(resource_section, packed_res_dir, unpacked_res_dir):
    ms = resource_section
    num = rd_u16(ms, 14)               # NumberOfIdEntries
    num += rd_u16(ms, 12)              # + NumberOfNamedEntries
    for i in range(num):
        num2 = rd_u32(ms, 16 + i * 8 + 4) & 0x7FFFFFFF
        num3 = rd_u16(ms, num2 + 12)
        num3 += rd_u16(ms, num2 + 14)
        for j in range(num3):
            num4 = rd_u32(ms, num2 + 16 + j * 8 + 4) & 0x7FFFFFFF
            num5 = rd_u16(ms, num4 + 12)
            num5 += rd_u16(ms, num4 + 14)
            for k in range(num5):
                num6 = rd_u32(ms, num4 + 16 + k * 8 + 4) & 0x7FFFFFFF
                value = rd_u32(ms, num6) - packed_res_dir + unpacked_res_dir
                w32(ms, num6, value)


# ---------------------------------------------------------------------------
# 单文件解包（对应 Form1_DragDrop 对每个文件的处理）
# 成功返回 True，失败返回 False。
# ---------------------------------------------------------------------------
def unpack_one(path):
    base = os.path.basename(path)
    ok, a = lf(path)
    if not ok:
        print("[Error] Not .net mpress: %s" % base, file=sys.stderr)
        return False

    print("[Info] Mpressed file unpacked: %s" % base)

    # ---- 从壳文件中提取原始资源段 ----
    with open(path, "rb") as f:
        packed = f.read()
    res_bytes = None
    packed_res_dir = 0
    packed_res_off = 0
    packed_res_size = 0
    flag = False

    e_lfanew = rd_u32(packed, 60)
    packed_res_dir = rd_u32(packed, e_lfanew + 136)
    if packed_res_dir != 0:
        packed_res_size = rd_u32(packed, e_lfanew + 140)
        if packed_res_size != 0:
            packed_res_off = convert_rva_to_offset(packed_res_dir, packed)
            res_bytes = bytearray(packed[packed_res_off:packed_res_off + packed_res_size])
            flag = True
            print("[Info] (Packed File) Resource RVA : 0x%X" % packed_res_dir)
            print("[Info] (Packed File) Resource Size: 0x%X" % packed_res_size)
            print("[Info] (Packed File) Resource Offset: 0x%X" % packed_res_off)
        else:
            print("[Info] (Packed file) Ressource is null")
    else:
        print("[Info] (Packed File) Ressource not found")

    # ---- 在解包数据里定位资源目录并回填 ----
    unpacked = bytearray(a)
    unpacked_res_off = 0
    if flag:
        u_e_lfanew = rd_u32(unpacked, 60)
        unpacked_res_dir = rd_u32(unpacked, u_e_lfanew + 136)
        if unpacked_res_dir != 0:
            unpacked_res_off = convert_rva_to_offset(unpacked_res_dir, unpacked)
            print("[Info] (UnPacked File) Resource RVA : 0x%X" % unpacked_res_dir)
            print("[Info] (UnPacked File) Resource Offset: 0x%X" % unpacked_res_off)
            try:
                print("[Info] (Resource) Fixing resource directory")
                fix_resource(res_bytes, packed_res_dir, unpacked_res_dir)
            except Exception:
                print("[Error] Can't fix resource", file=sys.stderr)
                flag = False
        else:
            print("[Info] (Unpacked File) Ressource not found")
            flag = False

    if flag:
        # 把资源段写入解包数据对应偏移
        for idx in range(len(res_bytes)):
            pos = unpacked_res_off + idx
            if 0 <= pos < len(unpacked):
                unpacked[pos] = res_bytes[idx]
        print("[Info] (Unpacked file) Resource copied")
    else:
        print("[Info] (Unpacked file) Resource not copied")

    # ---- 写出结果 ----
    root, ext = os.path.splitext(path)
    out_path = root + ".unpacked" + ext
    with open(out_path, "wb") as f:
        f.write(unpacked)
    print("[Success] %s -> %s" % (base, os.path.basename(out_path)))
    return True


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Mpress .Net Unpacker (by COB) — Python CLI rewrite. "
                    "Unpack MPress-packed .NET assemblies.")
    parser.add_argument("files", nargs="+", metavar="FILE",
                        help="MPress 加壳的 .NET 文件（可多个）")
    args = parser.parse_args(argv)

    ok_count = 0
    for path in args.files:
        if not os.path.isfile(path):
            print("[Error] File not found: %s" % path, file=sys.stderr)
            continue
        try:
            if unpack_one(path):
                ok_count += 1
        except Exception as e:
            print("[Error] %s: %s" % (path, e), file=sys.stderr)

    print("\nDone. %d/%d file(s) unpacked." % (ok_count, len(args.files)))
    return 0 if ok_count == len(args.files) else 1


if __name__ == "__main__":
    sys.exit(main())