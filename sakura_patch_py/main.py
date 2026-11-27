#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sakura_patch — 樱花补丁制作工具 正式版 2.74 的 Python CLI 重写
================================================================

原程序: 樱花补丁制作工具_2.74_正式版/樱花补丁制作工具 正式版 2.74.exe
        (x86, 1,265,664 bytes, 2011-02-17)

关于原始程序的逆向说明 (IMPORTANT / 逆向依据)
--------------------------------------------
原 EXE 为 **自定义加壳 (custom-packed)** 程序:
  * 节区名称被随机化 (randomized section names)，各节呈高熵 (high entropy)，
    静态反汇编只能看到解包 stub / 壳代码，看不到真正的业务逻辑。
  * 因此本重写 **没有** 依赖对真实代码的逐指令还原，而是依据:
      - 程序目录内的配置/皮肤/数据文件 (本目录仅含主 EXE，无额外资源);
      - 程序可见字符串与窗口/按钮文本 (汉化界面: 选择原始文件 / 选择修改后文件 /
        生成补丁 / CRC 校验 等);
      - "樱花补丁制作工具" 这一类工具广为人知的公开行为约定。
    壳 **未被脱壳**，逻辑为静态推断 + 行为重建，非逐字节等价。
  * 真实的樱花补丁工具做的工作: 用户选择「原始文件」与「修改后文件」，工具对两者
    做字节级差分，生成一个 **独立的补丁 EXE (loader stub + 差分数据)**；该补丁 EXE
    在目标机器上运行时，读取目标文件、按差分把原始字节替换为新的字节，从而把原始
    文件还原成修改后的文件。通常会带 **文件大小 / CRC32 校验**，校验失败则拒绝打补丁。

差分 + loader-stub 算法 (本 CLI 的实现)
---------------------------------------
  * 差分 (diff): 先求两文件的最长公共前缀 (common prefix) 与最长公共后缀
    (common suffix)，把中间不同的区域按 **连续不同的字节段 (runs)** 切分，每段记录
    {offset, original_bytes, new_bytes}。这样绝大多数未改动区域被前缀/后缀吸收，
    差分数据极小 —— 与原工具"小补丁"的思路一致。
  * 补丁脚本 (loader stub): `make` 会 **额外生成一个自包含的 Python 补丁脚本**
    (默认 <patch>.py)，它内嵌差分数据 (META + PATCHES)，运行时:
      1) 读取目标文件;
      2) (可选) 校验目标文件大小与 CRC32 是否等于原始文件 —— 对应原工具的 CRC 校验;
      3) 按 offset 顺序把 original_bytes 校验并替换为 new_bytes (支持长度变化，
         用 delta 累加偏移);
      4) 写出结果 (默认原地覆盖，可用 -o 指定输出)。
    这相当于原工具生成的"独立补丁 EXE"，只是用纯 Python 脚本代替原生 stub。
  * 同时写出一份 JSON 差分 (`<patch>.json`)，供 `apply` / `verify` 子命令复用。

特性 -> 子命令 映射
-------------------
  | 原工具 GUI 功能                         | 本 CLI 子命令                  |
  |----------------------------------------|-------------------------------|
  | 选择原始文件 + 修改后文件，生成补丁      | `make <orig> <mod> -o p.py`   |
  | 生成的独立补丁 EXE (loader stub)        | `make` 同时产出的 p.py         |
  | 在目标机上应用补丁                      | `apply <target> <diff.json>`  |
  | CRC/大小校验 (打补丁前)                 | `verify <target> <diff.json>` |
  | 查看文件信息 (PE 节区/哈希)             | `info <pe>`                   |

约束: 单文件 main.py，仅用标准库 (stdlib)，无第三方依赖，无 git 操作。
"""

import argparse
import hashlib
import json
import os
import struct
import sys
import zlib

TOOL_NAME = "sakura_patch"
TOOL_VERSION = "1.0"
DIFF_MAGIC = "sakura-patch-diff"
DIFF_VERSION = 1


# ===========================================================================
# 基础工具: 文件读取 / 哈希
# ===========================================================================
def read_file(path):
    """读取整个文件为 bytes。"""
    with open(path, "rb") as f:
        return f.read()


def crc32_bytes(data):
    """CRC-32 (与 zlib 一致)。"""
    return zlib.crc32(data) & 0xFFFFFFFF


def md5_bytes(data):
    return hashlib.md5(data).hexdigest()


def file_meta(path, data):
    """构造文件元信息 (路径 + 大小 + CRC32 + MD5)。"""
    return {
        "path": os.path.abspath(path),
        "size": len(data),
        "crc32": "%08X" % crc32_bytes(data),
        "md5": md5_bytes(data),
    }


# ===========================================================================
# 差分算法: 公共前缀/后缀 + 连续不同字节段 (runs)
# ===========================================================================
def compute_diff(orig, mod):
    """
    计算 orig -> mod 的字节级差分。

    返回 patches 列表，每项为:
        {"offset": <原始文件中的偏移>, "original": <hex>, "new": <hex>}
    其中 original 段在目标文件该偏移处应逐字节匹配 (用于校验)，new 段用于替换。
    支持长度变化 (插入/删除): 应用时按 delta 累加偏移。
    """
    n = min(len(orig), len(mod))

    # 1) 最长公共前缀
    pre = 0
    while pre < n and orig[pre] == mod[pre]:
        pre += 1

    # 2) 最长公共后缀 (不与前缀重叠)
    suf = 0
    while pre + suf < n and orig[len(orig) - 1 - suf] == mod[len(mod) - 1 - suf]:
        suf += 1

    o_start, o_end = pre, len(orig) - suf
    m_start, m_end = pre, len(mod) - suf
    o_len = o_end - o_start
    m_len = m_end - m_start

    patches = []
    i = 0
    while i < o_len or i < m_len:
        ob = orig[o_start + i] if i < o_len else None
        mb = mod[m_start + i] if i < m_len else None
        if ob == mb and ob is not None:
            # 该字节未改动，跳过 (作为 run 之间的上下文)
            i += 1
            continue

        # 开始一个连续不同段
        run_off = pre + i
        obuf = bytearray()
        nbuf = bytearray()
        while i < o_len or i < m_len:
            ob = orig[o_start + i] if i < o_len else None
            mb = mod[m_start + i] if i < m_len else None
            if ob == mb and ob is not None:
                break
            if ob is not None:
                obuf.append(ob)
            if mb is not None:
                nbuf.append(mb)
            i += 1

        patches.append({
            "offset": run_off,
            "original": bytes(obuf).hex(),
            "new": bytes(nbuf).hex(),
        })

    return patches


def build_diff_doc(orig_path, mod_path, orig, mod):
    """构造完整的差分文档 (dict)，可序列化为 JSON。"""
    patches = compute_diff(orig, mod)
    return {
        "magic": DIFF_MAGIC,
        "version": DIFF_VERSION,
        "tool": TOOL_NAME,
        "original": file_meta(orig_path, orig),
        "modified": file_meta(mod_path, mod),
        "patch_count": len(patches),
        "patches": patches,
    }


# ===========================================================================
# 应用差分 (核心，被 apply 子命令与生成的补丁脚本共用同一逻辑)
# ===========================================================================
def apply_diff_bytes(buf, patches, verify=True):
    """
    在 bytearray buf (原始文件内容) 上就地应用 patches。
    成功返回 True，校验失败返回 False (并打印错误)。
    """
    delta = 0
    for idx, p in enumerate(patches):
        off = p["offset"] + delta
        ob = bytes.fromhex(p["original"]) if p.get("original") else b""
        nb = bytes.fromhex(p["new"]) if p.get("new") else b""

        if ob:
            cur = bytes(buf[off:off + len(ob)])
            if verify and cur != ob:
                sys.stderr.write(
                    "Error: run #%d @0x%X 原始字节不匹配 (期望 %s, 实际 %s)\n"
                    % (idx, off, ob.hex(), cur.hex())
                )
                return False
        # 替换 (长度可不同)
        buf[off:off + len(ob)] = nb
        delta += len(nb) - len(ob)
    return True


def cmd_apply_main(target, diff_path, output, verify):
    """apply 子命令: 读取 diff.json，应用到 target。"""
    try:
        doc = json.loads(read_file(diff_path).decode("utf-8"))
    except (OSError, ValueError) as e:
        sys.stderr.write("Error: 无法读取差分文件: %s\n" % e)
        return 1

    if doc.get("magic") != DIFF_MAGIC:
        sys.stderr.write("Error: 不是有效的樱花差分文件 (magic 不符)\n")
        return 1

    try:
        buf = bytearray(read_file(target))
    except OSError as e:
        sys.stderr.write("Error: 无法读取目标文件: %s\n" % e)
        return 1

    # 整文件 CRC/大小校验 (对应原工具打补丁前的校验)
    if verify:
        exp = doc.get("original", {})
        if "size" in exp and len(buf) != exp["size"]:
            sys.stderr.write(
                "Error: 目标文件大小 %d != 期望原始大小 %d\n"
                % (len(buf), exp["size"])
            )
            return 1
        if "crc32" in exp and crc32_bytes(bytes(buf)) != int(exp["crc32"], 16):
            sys.stderr.write("Error: 目标文件 CRC32 与期望原始 CRC32 不符\n")
            return 1

    patches = doc.get("patches", [])
    if not apply_diff_bytes(buf, patches, verify=verify):
        return 1

    out = output if output else target
    try:
        with open(out, "wb") as f:
            f.write(bytes(buf))
    except OSError as e:
        sys.stderr.write("Error: 无法写出: %s\n" % e)
        return 1

    print("已应用 %d 个差分段 -> %s" % (len(patches), out))
    return 0


# ===========================================================================
# 生成自包含补丁脚本 (loader stub)
# ===========================================================================
PATCH_SCRIPT_TEMPLATE = r'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Self-contained patcher — 由 sakura_patch make 自动生成 (樱花补丁 loader stub 等价物)。
把差分应用到目标文件，还原为修改后的文件。仅用标准库。

用法:
    python <this>.py <target> [-o out] [--no-verify]
"""
import argparse
import sys
import zlib

META = __META__
PATCHES = __PATCHES__


def _crc32(data):
    return zlib.crc32(data) & 0xFFFFFFFF


def apply(target, output=None, verify=True):
    with open(target, "rb") as f:
        buf = bytearray(f.read())

    if verify:
        exp_size = META["original"]["size"]
        exp_crc = int(META["original"]["crc32"], 16)
        if len(buf) != exp_size:
            sys.stderr.write("Error: size %d != expected %d\n" % (len(buf), exp_size))
            return 1
        if _crc32(bytes(buf)) != exp_crc:
            sys.stderr.write("Error: CRC32 mismatch (target is not the expected original)\n")
            return 1

    delta = 0
    for idx, p in enumerate(PATCHES):
        off = p["offset"] + delta
        ob = bytes.fromhex(p["original"]) if p.get("original") else b""
        nb = bytes.fromhex(p["new"]) if p.get("new") else b""
        if ob:
            cur = bytes(buf[off:off + len(ob)])
            if verify and cur != ob:
                sys.stderr.write("Error: run #%d @0x%X original bytes mismatch\n" % (idx, off))
                return 1
        buf[off:off + len(ob)] = nb
        delta += len(nb) - len(ob)

    out = output if output else target
    with open(out, "wb") as f:
        f.write(bytes(buf))
    print("Patched %d run(s) -> %s" % (len(PATCHES), out))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(prog="patch", description="Apply a sakura_patch diff to a target file.")
    ap.add_argument("target", help="要修补的目标文件 (原始文件)")
    ap.add_argument("-o", "--output", default=None, help="输出路径 (默认原地覆盖 target)")
    ap.add_argument("--no-verify", action="store_true", help="跳过 大小/CRC 与逐段原始字节校验")
    args = ap.parse_args(argv)
    return apply(args.target, args.output, verify=not args.no_verify)


if __name__ == "__main__":
    sys.exit(main())
'''


def emit_patch_script(doc):
    """把差分文档渲染成自包含补丁脚本源码 (字符串)。"""
    meta = {
        "original": doc["original"],
        "modified": doc["modified"],
    }
    src = PATCH_SCRIPT_TEMPLATE
    src = src.replace("__META__", repr(meta))
    src = src.replace("__PATCHES__", repr(doc["patches"]))
    return src


# ===========================================================================
# make 子命令
# ===========================================================================
def cmd_make(args):
    try:
        orig = read_file(args.original)
    except OSError as e:
        sys.stderr.write("Error: 无法读取原始文件: %s\n" % e)
        return 1
    try:
        mod = read_file(args.modified)
    except OSError as e:
        sys.stderr.write("Error: 无法读取修改后文件: %s\n" % e)
        return 1

    doc = build_diff_doc(args.original, args.modified, orig, mod)

    # 写出 JSON 差分 (与补丁脚本同名的 .json)
    out_py = args.output
    base, _ext = os.path.splitext(out_py)
    json_path = base + ".json"

    # 写出自包含补丁脚本
    try:
        with open(out_py, "w", encoding="utf-8") as f:
            f.write(emit_patch_script(doc))
    except OSError as e:
        sys.stderr.write("Error: 无法写出补丁脚本: %s\n" % e)
        return 1

    # 写出 JSON 差分
    try:
        with open(json_path, "w", encoding="utf-8") as f:
            json.dump(doc, f, ensure_ascii=False, indent=2)
    except OSError as e:
        sys.stderr.write("Error: 无法写出 JSON 差分: %s\n" % e)
        return 1

    print("原始文件 : %s (%d bytes, CRC32 %s)"
          % (doc["original"]["path"], doc["original"]["size"], doc["original"]["crc32"]))
    print("修改文件 : %s (%d bytes, CRC32 %s)"
          % (doc["modified"]["path"], doc["modified"]["size"], doc["modified"]["crc32"]))
    print("差分段数 : %d" % doc["patch_count"])
    print("补丁脚本 : %s" % out_py)
    print("JSON 差分: %s" % json_path)
    return 0


# ===========================================================================
# verify 子命令
# ===========================================================================
def cmd_verify(args):
    try:
        doc = json.loads(read_file(args.diff).decode("utf-8"))
    except (OSError, ValueError) as e:
        sys.stderr.write("Error: 无法读取差分文件: %s\n" % e)
        return 1
    if doc.get("magic") != DIFF_MAGIC:
        sys.stderr.write("Error: 不是有效的樱花差分文件\n")
        return 1

    try:
        data = read_file(args.target)
    except OSError as e:
        sys.stderr.write("Error: 无法读取目标文件: %s\n" % e)
        return 1

    exp = doc.get("original", {})
    ok = True
    if "size" in exp:
        if len(data) == exp["size"]:
            print("size  : OK (%d)" % len(data))
        else:
            print("size  : FAIL (got %d, expected %d)" % (len(data), exp["size"]))
            ok = False
    if "crc32" in exp:
        got = "%08X" % crc32_bytes(data)
        if got == exp["crc32"]:
            print("crc32 : OK (%s)" % got)
        else:
            print("crc32 : FAIL (got %s, expected %s)" % (got, exp["crc32"]))
            ok = False
    if "md5" in exp:
        got = md5_bytes(data)
        if got == exp["md5"]:
            print("md5   : OK (%s)" % got)
        else:
            print("md5   : FAIL (got %s, expected %s)" % (got, exp["md5"]))
            ok = False

    if ok:
        print("结果  : 目标文件与差分原始文件一致，可以应用补丁。")
        return 0
    print("结果  : 目标文件与差分原始文件不一致 (可能已打过补丁或文件错误)。")
    return 1


# ===========================================================================
# info 子命令: 纯 stdlib PE 解析
# ===========================================================================
MACHINE_NAMES = {
    0x014C: "x86 (i386)",
    0x0162: "R3000",
    0x0166: "R4000",
    0x0168: "R10000",
    0x01A2: "SH3",
    0x01C0: "ARM",
    0x01C4: "ARMNT",
    0x0200: "IA64",
    0x8664: "x64 (AMD64)",
    0xAA64: "ARM64",
}

SUBSYSTEM_NAMES = {
    1: "Native",
    2: "Windows GUI",
    3: "Windows CUI (console)",
    5: "OS/2 CUI",
    7: "POSIX CUI",
    9: "Windows CE GUI",
    10: "EFI Application",
    11: "EFI Boot Service Driver",
    12: "EFI Runtime Driver",
    13: "EFI ROM",
    14: "XBOX",
}

# 节区 Characteristics 标志位
SCN_FLAGS = [
    (0x00000020, "CNT_CODE"),
    (0x00000040, "CNT_INITIALIZED_DATA"),
    (0x00000080, "CNT_UNINITIALIZED_DATA"),
    (0x02000000, "MEM_DISCARDABLE"),
    (0x04000000, "MEM_NOT_CACHED"),
    (0x08000000, "MEM_NOT_PAGED"),
    (0x10000000, "MEM_SHARED"),
    (0x20000000, "MEM_EXECUTE"),
    (0x40000000, "MEM_READ"),
    (0x80000000, "MEM_WRITE"),
]


def section_entropy(raw):
    """对一段原始数据计算香农熵 (bit/byte)，用于识别加壳/高熵节区。"""
    if not raw:
        return 0.0
    total = len(raw)
    counts = [0] * 256
    for b in raw:
        counts[b] += 1
    ent = 0.0
    for c in counts:
        if c:
            p = c / total
            ent -= p * _log2(p)
    return ent


def _log2(x):
    import math
    return math.log2(x)


def parse_pe(data):
    """解析 PE，返回 dict；解析失败抛 ValueError。"""
    if len(data) < 0x40 or data[0:2] != b"MZ":
        raise ValueError("不是 PE 文件 (缺少 MZ 头)")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 24 > len(data) or data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("不是 PE 文件 (缺少 PE 签名)")

    coff = e_lfanew + 4
    (machine, num_sections, timestamp, _symtab, _nsyms,
     size_opt, characteristics) = struct.unpack_from("<HHIIIHH", data, coff)

    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0] if opt + 2 <= len(data) else 0
    pe32plus = (magic == 0x20B)

    entry = struct.unpack_from("<I", data, opt + 16)[0]
    if pe32plus:
        image_base = struct.unpack_from("<Q", data, opt + 24)[0]
        size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
        subsystem = struct.unpack_from("<H", data, opt + 68)[0]
    else:
        image_base = struct.unpack_from("<I", data, opt + 28)[0]
        size_of_image = struct.unpack_from("<I", data, opt + 56)[0]
        subsystem = struct.unpack_from("<H", data, opt + 68)[0]

    section_align = struct.unpack_from("<I", data, opt + 32)[0]
    file_align = struct.unpack_from("<I", data, opt + 36)[0]

    sec_table = opt + size_opt
    sections = []
    for k in range(num_sections):
        off = sec_table + k * 40
        if off + 40 > len(data):
            break
        name_raw = data[off:off + 8]
        name = name_raw.split(b"\x00", 1)[0].decode("latin-1", "replace")
        vsize, vaddr, rsize, raddr = struct.unpack_from("<IIII", data, off + 8)
        chars = struct.unpack_from("<I", data, off + 36)[0]
        raw = data[raddr:raddr + rsize] if rsize and raddr + rsize <= len(data) else b""
        flags = [nm for bit, nm in SCN_FLAGS if chars & bit]
        sections.append({
            "name": name,
            "virtual_size": vsize,
            "virtual_address": vaddr,
            "raw_size": rsize,
            "raw_address": raddr,
            "characteristics": chars,
            "flags": flags,
            "entropy": section_entropy(raw),
        })

    return {
        "machine": machine,
        "machine_name": MACHINE_NAMES.get(machine, "unknown(0x%04X)" % machine),
        "num_sections": num_sections,
        "timestamp": timestamp,
        "size_opt": size_opt,
        "characteristics": characteristics,
        "magic": magic,
        "pe32plus": pe32plus,
        "entry": entry,
        "image_base": image_base,
        "size_of_image": size_of_image,
        "subsystem": subsystem,
        "subsystem_name": SUBSYSTEM_NAMES.get(subsystem, "unknown(%d)" % subsystem),
        "section_align": section_align,
        "file_align": file_align,
        "sections": sections,
    }


def cmd_info(args):
    try:
        data = read_file(args.pe)
    except OSError as e:
        sys.stderr.write("Error: 无法读取文件: %s\n" % e)
        return 1

    print("文件    : %s" % os.path.abspath(args.pe))
    print("大小    : %d bytes" % len(data))
    print("CRC32   : %08X" % crc32_bytes(data))
    print("MD5     : %s" % md5_bytes(data))
    print("-" * 60)

    try:
        pe = parse_pe(data)
    except ValueError as e:
        sys.stderr.write("Error: %s\n" % e)
        return 1

    print("PE 类型 : %s" % ("PE32+ (64-bit)" if pe["pe32plus"] else "PE32 (32-bit)"))
    print("Machine : %s" % pe["machine_name"])
    print("时间戳  : 0x%08X" % pe["timestamp"])
    print("入口点  : 0x%08X" % pe["entry"])
    print("镜像基址: 0x%X" % pe["image_base"])
    print("镜像大小: 0x%X" % pe["size_of_image"])
    print("节对齐  : 0x%X   文件对齐: 0x%X" % (pe["section_align"], pe["file_align"]))
    print("子系统  : %s" % pe["subsystem_name"])
    print("节区数  : %d" % pe["num_sections"])
    print("-" * 60)
    print("%-10s %10s %10s %10s %10s  %s"
          % ("Name", "VirtAddr", "VirtSize", "RawAddr", "RawSize", "Entropy/Flags"))
    for s in pe["sections"]:
        print("%-10s 0x%8X 0x%8X 0x%8X 0x%8X  %.3f  %s"
              % (s["name"], s["virtual_address"], s["virtual_size"],
                 s["raw_address"], s["raw_size"], s["entropy"],
                 ",".join(s["flags"])))
    return 0


# ===========================================================================
# 参数解析 / 入口
# ===========================================================================
def build_parser():
    ap = argparse.ArgumentParser(
        prog="sakura_patch",
        description="樱花补丁制作工具 2.74 的 Python CLI 重写 —— 文件差分并生成/应用补丁。",
    )
    ap.add_argument("--version", action="version",
                    version="%s %s" % (TOOL_NAME, TOOL_VERSION))
    sub = ap.add_subparsers(dest="command", metavar="<command>")

    # make
    p_make = sub.add_parser("make", help="对原始/修改后文件做差分，生成补丁脚本 + JSON 差分")
    p_make.add_argument("original", help="原始文件路径")
    p_make.add_argument("modified", help="修改后文件路径")
    p_make.add_argument("-o", "--output", default="patch.py",
                        help="输出补丁脚本路径 (默认 patch.py；同时写同名 .json)")
    p_make.set_defaults(func=cmd_make)

    # apply
    p_apply = sub.add_parser("apply", help="把 JSON 差分应用到目标文件")
    p_apply.add_argument("target", help="要修补的目标文件 (原始文件)")
    p_apply.add_argument("diff", help="JSON 差分文件 (make 生成)")
    p_apply.add_argument("-o", "--output", default=None,
                         help="输出路径 (默认原地覆盖 target)")
    p_apply.add_argument("--no-verify", action="store_true",
                         help="跳过 大小/CRC 与逐段原始字节校验")
    p_apply.set_defaults(func=lambda a: cmd_apply_main(
        a.target, a.diff, a.output, verify=not a.no_verify))

    # info
    p_info = sub.add_parser("info", help="显示 PE 节区 + CRC32/MD5/大小")
    p_info.add_argument("pe", help="要分析的 PE 文件")
    p_info.set_defaults(func=cmd_info)

    # verify
    p_verify = sub.add_parser("verify", help="校验目标文件是否匹配差分的原始文件")
    p_verify.add_argument("target", help="目标文件")
    p_verify.add_argument("diff", help="JSON 差分文件")
    p_verify.set_defaults(func=cmd_verify)

    return ap


def main(argv=None):
    ap = build_parser()
    args = ap.parse_args(argv)
    if not getattr(args, "command", None):
        ap.print_help()
        return 0
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())