#!/usr/bin/env python3
"""
Keygener Assistant — Python CLI rewrite

原程序：KeygenerAssistant/keyAssistant Remixed.exe (Mr Paradox, AT4RE, v2.1.2, 2016)
综合密码学/密钥生成辅助工具。

本 CLI 把原程序中核心、可独立复现的算法重写为 Python 命令行工具：
编码转换、哈希校验、经典对称加密、大数模幂(RSA 数学基础)，以及 AES
(借助 cryptography 库)。标准库部分无第三方依赖。

字符串按 UTF-8 字节处理；文件路径以 `@` 前缀表示从文件读取。
"""

import argparse
import base64
import binascii
import hashlib
import os
import sys
import zlib

try:
    from cryptography.hazmat.primitives.ciphers import Cipher
    from cryptography.hazmat.primitives.ciphers.algorithms import AES
    from cryptography.hazmat.primitives.ciphers.modes import CBC, CFB, CTR, ECB, OFB
    CRYPTOGRAPHY = True
except Exception:  # pragma: no cover - 依赖环境问题
    CRYPTOGRAPHY = False


# ---------------------------------------------------------------------------
# 辅助：读取输入（字符串或 @file）
# ---------------------------------------------------------------------------
def read_input(spec):
    """如果 spec 以 '@' 开头，则读取该文件的字节；否则按 UTF-8 编码。"""
    if spec.startswith("@"):
        path = spec[1:]
        if not os.path.isfile(path):
            print("Error: file not found: %s" % path, file=sys.stderr)
            sys.exit(1)
        with open(path, "rb") as f:
            return f.read()
    return spec.encode("utf-8")


def out_bytes(data, as_hex=False):
    if as_hex:
        sys.stdout.write(data.hex())
        sys.stdout.write("\n")
    else:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.write(b"\n")


# ---------------------------------------------------------------------------
# 编码转换
# ---------------------------------------------------------------------------
_DIGITS = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/="


def cmd_base64(args):
    data = read_input(args.text)
    if args.mode == "enc":
        sys.stdout.write(base64.b64encode(data).decode("ascii"))
        sys.stdout.write("\n")
    else:
        try:
            raw = base64.b64decode(data)
        except Exception as e:
            print("Error: invalid base64: %s" % e, file=sys.stderr)
            return 1
        out_bytes(raw, as_hex=False)
    return 0


def cmd_hex(args):
    data = read_input(args.text)
    if args.mode == "enc":
        sys.stdout.write(data.hex().upper())
        sys.stdout.write("\n")
    else:
        h = data.decode("ascii").strip().replace(" ", "")
        try:
            raw = binascii.unhexlify(h)
        except Exception as e:
            print("Error: invalid hex: %s" % e, file=sys.stderr)
            return 1
        out_bytes(raw, as_hex=False)
    return 0


def _to_int(s, base):
    """用自定义 digit 把字符串 s (base 进制) 转成整数。支持 2-62 及 base64 字符集。"""
    if base <= 36:
        return int(s, base)
    if base == 62:
        digs = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    elif base == 64:
        digs = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    else:
        print("Error: unsupported base %d (use 2-36, 62, or 64)" % base, file=sys.stderr)
        sys.exit(1)
    val = 0
    for ch in s:
        val = val * base + digs.index(ch)
    return val


def _from_int(val, base):
    if base <= 36:
        if val == 0:
            return "0"
        digs = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        out = []
        while val > 0:
            out.append(digs[val % base])
            val //= base
        return "".join(reversed(out))
    if base == 62:
        digs = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    elif base == 64:
        digs = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    else:
        print("Error: unsupported base %d" % base, file=sys.stderr)
        sys.exit(1)
    if val == 0:
        return digs[0]
    out = []
    while val > 0:
        out.append(digs[val % base])
        val //= base
    return "".join(reversed(out))


def cmd_base(args):
    try:
        val = _to_int(args.number, args.src_base)
    except Exception as e:
        print("Error: invalid number for base %d: %s" % (args.src_base, e), file=sys.stderr)
        return 1
    sys.stdout.write(_from_int(val, args.dst_base))
    sys.stdout.write("\n")
    return 0


# ---------------------------------------------------------------------------
# 哈希
# ---------------------------------------------------------------------------
def cmd_hash(args):
    algo = args.algo.lower()
    data = read_input(args.text)
    if algo == "md5":
        print(hashlib.md5(data).hexdigest())
    elif algo == "sha1":
        print(hashlib.sha1(data).hexdigest())
    elif algo == "crc32":
        print("%08X" % (zlib.crc32(data) & 0xFFFFFFFF))
    else:
        print("Error: unknown algo %s" % algo, file=sys.stderr)
        return 1
    return 0


# ---------------------------------------------------------------------------
# 经典对称加密
# ---------------------------------------------------------------------------
def _shift_char(ch, n, alphabet):
    if ch not in alphabet:
        return ch
    idx = alphabet.index(ch)
    return alphabet[(idx + n) % len(alphabet)]


def cmd_caesar(args):
    text = read_input(args.text).decode("utf-8", errors="replace")
    n = args.shift % 26
    upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    lower = "abcdefghijklmnopqrstuvwxyz"
    out = []
    for ch in text:
        if ch in upper:
            out.append(_shift_char(ch, n, upper))
        elif ch in lower:
            out.append(_shift_char(ch, n, lower))
        else:
            out.append(ch)
    sys.stdout.write("".join(out))
    sys.stdout.write("\n")
    return 0


def cmd_rot(args):
    # ROT-n 等同于 caesar shift n
    args.shift = args.n
    return cmd_caesar(args)


def cmd_vigenere(args):
    mode = args.mode.lower()
    key = args.key
    text = read_input(args.text).decode("utf-8", errors="replace")
    upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    lower = "abcdefghijklmnopqrstuvwxyz"
    ki = 0
    out = []
    for ch in text:
        if ch in upper:
            kch = key[ki % len(key)].upper()
            shift = upper.index(kch) if kch in upper else 0
            if mode == "dec":
                shift = -shift
            out.append(_shift_char(ch, shift, upper))
            ki += 1
        elif ch in lower:
            kch = key[ki % len(key)].lower()
            shift = lower.index(kch) if kch in lower else 0
            if mode == "dec":
                shift = -shift
            out.append(_shift_char(ch, shift, lower))
            ki += 1
        else:
            out.append(ch)
    sys.stdout.write("".join(out))
    sys.stdout.write("\n")
    return 0


def _xor_crypt(data, key):
    kb = key.encode("utf-8")
    return bytes(b ^ kb[i % len(kb)] for i, b in enumerate(data))


def cmd_xor(args):
    data = read_input(args.text)
    res = _xor_crypt(data, args.key)
    out_bytes(res, as_hex=True)
    return 0


def cmd_not(args):
    data = read_input(args.text)
    res = bytes((~b) & 0xFF for b in data)
    out_bytes(res, as_hex=True)
    return 0


def cmd_add(args):
    data = read_input(args.text)
    k = int(args.key) & 0xFF
    res = bytes((b + k) & 0xFF for b in data)
    out_bytes(res, as_hex=True)
    return 0


# ---------------------------------------------------------------------------
# AES（需 cryptography 库；对应原程序对称加密模块）
# ---------------------------------------------------------------------------
def _parse_key(s, fmt):
    if fmt == "hex":
        return binascii.unhexlify(s.strip().replace(" ", ""))
    return s.encode("utf-8")


def _pad_pkcs7(data, block=16):
    n = block - (len(data) % block)
    return data + bytes([n]) * n


def _unpad_pkcs7(data, block=16):
    if not data:
        raise ValueError("empty data")
    n = data[-1]
    if n < 1 or n > block or data[-n:] != bytes([n]) * n:
        raise ValueError("invalid PKCS7 padding")
    return data[:-n]


_AES_MODES = {
    "ecb": ECB,
    "cbc": CBC,
    "cfb": CFB,
    "ofb": OFB,
    "ctr": CTR,
}


def cmd_aes(args):
    if not CRYPTOGRAPHY:
        print("Error: cryptography 库未安装，请先执行: pip install cryptography", file=sys.stderr)
        return 1

    key = _parse_key(args.key, args.key_format)
    if len(key) not in (16, 24, 32):
        print("Error: AES key must be 16/24/32 bytes (%d given)" % len(key), file=sys.stderr)
        return 1

    mode = args.mode.lower()
    ModeCls = _AES_MODES.get(mode)
    if ModeCls is None:
        print("Error: unknown mode %s (valid: ecb/cbc/cfb/ofb/ctr)" % mode, file=sys.stderr)
        return 1

    if mode == "ecb":
        cipher_mode = ModeCls()
    else:
        iv = _parse_key(args.iv, args.iv_format)
        if len(iv) != 16:
            print("Error: IV must be 16 bytes (%d given)" % len(iv), file=sys.stderr)
            return 1
        cipher_mode = ModeCls(iv)

    if args.action == "enc":
        data = read_input(args.text)  # 纯文本按 UTF-8，@file 读原始字节
        need_pad = mode in ("ecb", "cbc") and args.pad == "pkcs7"
        if need_pad:
            data = _pad_pkcs7(data)
        enc = Cipher(AES(key), cipher_mode).encryptor()
        out = enc.update(data) + enc.finalize()
        sys.stdout.write(out.hex())
        sys.stdout.write("\n")
    else:
        if args.text.startswith("@"):
            data = read_input(args.text)  # @file 读原始密文字节
        else:
            try:
                data = binascii.unhexlify(args.text.strip().replace(" ", ""))
            except Exception as e:
                print("Error: invalid hex ciphertext: %s" % e, file=sys.stderr)
                return 1
        need_pad = mode in ("ecb", "cbc") and args.pad == "pkcs7"
        dec = Cipher(AES(key), cipher_mode).decryptor()
        out = dec.update(data) + dec.finalize()
        if need_pad:
            try:
                out = _unpad_pkcs7(out)
            except ValueError as e:
                print("Error: %s" % e, file=sys.stderr)
                return 1
        out_bytes(out, as_hex=False)
    return 0


# ---------------------------------------------------------------------------
# 大数 / RSA 基础
# ---------------------------------------------------------------------------
def cmd_modpow(args):
    b = int(args.base)
    e = int(args.exp)
    m = int(args.mod)
    if m == 0:
        print("Error: modulus must be non-zero", file=sys.stderr)
        return 1
    print(pow(b, e, m))
    return 0


def cmd_rsa(args):
    n = int(args.n)
    exp = int(args.exp)
    mode = args.mode.lower()
    data = read_input(args.text)
    # 将字节串视为一个大整数做模幂（RSA 数学基础，不填充，仅供教学/分析）
    val = int.from_bytes(data, "big")
    res = pow(val, exp, n)
    # 输出与输入等长的字节（不足补零）
    width = (n.bit_length() + 7) // 8
    out_bytes(res.to_bytes(width, "big"), as_hex=True)
    return 0


# ---------------------------------------------------------------------------
# 参数解析
# ---------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(
        prog="main.py",
        description="Keygener Assistant — Python CLI (纯 Python 重写，标准库实现)。",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("base64", help="Base64 (MIME64) 编码/解码")
    sp.add_argument("mode", choices=["enc", "dec"])
    sp.add_argument("text", help="文本或 @file")
    sp.set_defaults(func=cmd_base64)

    sp = sub.add_parser("hex", help="十六进制编码/解码")
    sp.add_argument("mode", choices=["enc", "dec"])
    sp.add_argument("text", help="文本或 @file")
    sp.set_defaults(func=cmd_hex)

    sp = sub.add_parser("base", help="进制转换 (2-36, 62, 64)")
    sp.add_argument("src_base", type=int)
    sp.add_argument("dst_base", type=int)
    sp.add_argument("number", help="源进制数字串")
    sp.set_defaults(func=cmd_base)

    for algo in ("md5", "sha1", "crc32"):
        sp = sub.add_parser(algo, help="计算 %s 哈希" % algo.upper())
        sp.add_argument("text", help="文本或 @file")
        sp.set_defaults(func=cmd_hash, algo=algo)

    sp = sub.add_parser("caesar", help="凯撒密码 E(x)=(x+shift) mod 26")
    sp.add_argument("text", help="文本或 @file")
    sp.add_argument("shift", type=int)
    sp.set_defaults(func=cmd_caesar)

    sp = sub.add_parser("rot", help="ROT-n 旋转字母")
    sp.add_argument("n", type=int)
    sp.add_argument("text", help="文本或 @file")
    sp.set_defaults(func=cmd_rot)

    sp = sub.add_parser("vigenere", help="维吉尼亚多表替换加/解密")
    sp.add_argument("mode", choices=["enc", "dec"])
    sp.add_argument("key", help="密钥")
    sp.add_argument("text", help="文本或 @file")
    sp.set_defaults(func=cmd_vigenere)

    sp = sub.add_parser("xor", help="与密钥循环异或 (输出 hex)")
    sp.add_argument("key", help="密钥")
    sp.add_argument("text", help="文本或 @file")
    sp.set_defaults(func=cmd_xor)

    sp = sub.add_parser("not", help="按位取反 (输出 hex)")
    sp.add_argument("text", help="文本或 @file")
    sp.set_defaults(func=cmd_not)

    sp = sub.add_parser("add", help="每字节 + key (mod 256)，输出 hex")
    sp.add_argument("key", help="加数 (0-255)")
    sp.add_argument("text", help="文本或 @file")
    sp.set_defaults(func=cmd_add)

    sp = sub.add_parser("modpow", help="大数模幂 base^exp mod mod")
    sp.add_argument("base", help="底数")
    sp.add_argument("exp", help="指数")
    sp.add_argument("mod", help="模数")
    sp.set_defaults(func=cmd_modpow)

    sp = sub.add_parser("rsa", help="RSA 基础加/解密(模幂，无填充，教学用)")
    sp.add_argument("mode", choices=["enc", "dec"])
    sp.add_argument("n", help="模数")
    sp.add_argument("exp", help="公钥指数 e 或 私钥指数 d")
    sp.add_argument("text", help="文本或 @file")
    sp.set_defaults(func=cmd_rsa)

    sp = sub.add_parser("aes", help="AES 加解密（需 cryptography 库）")
    aes_sub = sp.add_subparsers(dest="aes_cmd", required=True)
    sp_enc = aes_sub.add_parser("enc", help="AES 加密（输出十六进制；@file 读原始明文）")
    sp_enc.add_argument("key", help="密钥 (16/24/32 字节)")
    sp_enc.add_argument("text", help="明文 (UTF-8) 或 @file")
    sp_enc.set_defaults(func=cmd_aes, action="enc")
    sp_dec = aes_sub.add_parser("dec", help="AES 解密（输入十六进制密文，或 @file 读原始密文）")
    sp_dec.add_argument("key", help="密钥 (16/24/32 字节)")
    sp_dec.add_argument("text", help="十六进制密文，或 @file")
    sp_dec.set_defaults(func=cmd_aes, action="dec")
    for sp_aes in (sp_enc, sp_dec):
        sp_aes.add_argument("--mode", choices=["ecb", "cbc", "cfb", "ofb", "ctr"], default="cbc")
        sp_aes.add_argument("--iv", default="00000000000000000000000000000000",
                            help="初始向量 (十六进制或 UTF-8，默认全零)")
        sp_aes.add_argument("--key-format", choices=["utf8", "hex"], default="utf8")
        sp_aes.add_argument("--iv-format", choices=["utf8", "hex"], default="hex")
        sp_aes.add_argument("--pad", choices=["pkcs7", "none"], default="pkcs7")

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
