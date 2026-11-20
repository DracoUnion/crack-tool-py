#!/usr/bin/env python3
"""
ToolsFx 1.15.0 — Python CLI rewrite

原程序：ToolsFx_1.15.0_WithJRE_Windows (Leon406, Java/Kotlin + BouncyCastle)
综合密码学/编码工具箱。

本 CLI 把可用 Python 标准库独立复现的部分重写为命令行工具：
编码转换、哈希、HMAC、PBKDF2、RSA 基础模幂、MD5 字典破解，以及 AES
(借助 cryptography 库)。标准库部分无第三方依赖。
"""

import argparse
import base64
import binascii
import hashlib
import hmac
import os
import sys
import urllib.parse

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
    if spec.startswith("@"):
        path = spec[1:]
        if not os.path.isfile(path):
            print("Error: file not found: %s" % path, file=sys.stderr)
            sys.exit(1)
        with open(path, "rb") as f:
            return f.read()
    return spec.encode("utf-8")


def out_text(s):
    sys.stdout.write(s)
    sys.stdout.write("\n")


def out_bytes(data, as_hex=False):
    if as_hex:
        sys.stdout.write(data.hex())
        sys.stdout.write("\n")
    else:
        sys.stdout.buffer.write(data)
        sys.stdout.buffer.write(b"\n")


# ---------------------------------------------------------------------------
# 编码转换（Classical）
# ---------------------------------------------------------------------------
def cmd_base64(args):
    data = read_input(args.text)
    if args.mode == "enc":
        out_text(base64.b64encode(data).decode("ascii"))
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
        out_text(data.hex().upper())
    else:
        h = data.decode("ascii").strip().replace(" ", "")
        try:
            raw = binascii.unhexlify(h)
        except Exception as e:
            print("Error: invalid hex: %s" % e, file=sys.stderr)
            return 1
        out_bytes(raw, as_hex=False)
    return 0


def cmd_url(args):
    data = read_input(args.text)
    if args.mode == "enc":
        out_text(urllib.parse.quote(data.decode("utf-8", errors="replace"), safe=""))
    else:
        s = data.decode("utf-8", errors="replace")
        out_text(urllib.parse.unquote(s))
    return 0


# ---------------------------------------------------------------------------
# 哈希
# ---------------------------------------------------------------------------
_HASH_ALGO = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
}


def cmd_hash(args):
    algo = args.algo.lower()
    if algo not in _HASH_ALGO:
        print("Error: unknown algo %s" % algo, file=sys.stderr)
        return 1
    data = read_input(args.text)
    out_text(_HASH_ALGO[algo](data).hexdigest())
    return 0


# ---------------------------------------------------------------------------
# HMAC（MAC）
# ---------------------------------------------------------------------------
def cmd_hmac(args):
    algo = args.algo.lower()
    if algo not in _HASH_ALGO:
        print("Error: unknown algo %s" % algo, file=sys.stderr)
        return 1
    key = read_input(args.key)
    data = read_input(args.text)
    out_text(hmac.new(key, data, _HASH_ALGO[algo]).hexdigest())
    return 0


# ---------------------------------------------------------------------------
# PBKDF2（PBE）
# ---------------------------------------------------------------------------
def cmd_pbkdf2(args):
    password = read_input(args.password)
    salt = read_input(args.salt)
    dk = hashlib.pbkdf2_hmac("sha256", password, salt, args.iterations, dklen=args.klen)
    out_bytes(dk, as_hex=True)
    return 0


# ---------------------------------------------------------------------------
# RSA 基础模幂（BigInt / Signature 数学基础）
# ---------------------------------------------------------------------------
def cmd_rsa_modpow(args):
    b = int(args.base)
    e = int(args.exp)
    m = int(args.mod)
    if m == 0:
        print("Error: modulus must be non-zero", file=sys.stderr)
        return 1
    out_text(str(pow(b, e, m)))
    return 0


# ---------------------------------------------------------------------------
# AES（需 cryptography 库；对应原程序 Symmetric Stream 模块）
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
        if mode in ("ecb", "cbc") and args.pad == "pkcs7":
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
        dec = Cipher(AES(key), cipher_mode).decryptor()
        out = dec.update(data) + dec.finalize()
        if mode in ("ecb", "cbc") and args.pad == "pkcs7":
            try:
                out = _unpad_pkcs7(out)
            except ValueError as e:
                print("Error: %s" % e, file=sys.stderr)
                return 1
        out_bytes(out, as_hex=False)
    return 0


# ---------------------------------------------------------------------------
# MD5 字典破解（crack）
# ---------------------------------------------------------------------------
def cmd_crack_md5(args):
    target = args.hash.strip().lower()
    if not os.path.isfile(args.dictfile):
        print("Error: dictionary file not found: %s" % args.dictfile, file=sys.stderr)
        return 1
    found = None
    count = 0
    with open(args.dictfile, "rb") as f:
        for line in f:
            count += 1
            # 去掉行尾换行，尝试原样与 utf-8 解码后两种
            raw = line.rstrip(b"\r\n")
            candidates = [raw, raw.decode("utf-8", errors="replace").encode("utf-8")]
            for cand in candidates:
                if hashlib.md5(cand).hexdigest() == target:
                    found = cand
                    break
            if found is not None:
                break
    if found is not None:
        try:
            out_text(found.decode("utf-8"))
        except UnicodeDecodeError:
            out_bytes(found, as_hex=True)
        print("Found after %d lines." % count, file=sys.stderr)
        return 0
    print("Not found in %d lines." % count, file=sys.stderr)
    return 1


# ---------------------------------------------------------------------------
# 参数解析
# ---------------------------------------------------------------------------
def build_parser():
    p = argparse.ArgumentParser(
        prog="main.py",
        description="ToolsFx 1.15.0 — Python CLI (纯 Python 重写，标准库实现)。",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("base64", help="Base64 编码/解码")
    sp.add_argument("mode", choices=["enc", "dec"])
    sp.add_argument("text", help="文本或 @file")
    sp.set_defaults(func=cmd_base64)

    sp = sub.add_parser("hex", help="十六进制编码/解码")
    sp.add_argument("mode", choices=["enc", "dec"])
    sp.add_argument("text", help="文本或 @file")
    sp.set_defaults(func=cmd_hex)

    sp = sub.add_parser("url", help="URL 编码/解码")
    sp.add_argument("mode", choices=["enc", "dec"])
    sp.add_argument("text", help="文本或 @file")
    sp.set_defaults(func=cmd_url)

    for algo in ("md5", "sha1", "sha256", "sha512"):
        sp = sub.add_parser(algo, help="计算 %s 哈希" % algo.upper())
        sp.add_argument("text", help="文本或 @file")
        sp.set_defaults(func=cmd_hash, algo=algo)

    sp = sub.add_parser("hmac", help="HMAC 消息认证码")
    sp.add_argument("algo", choices=["md5", "sha1", "sha256", "sha512"])
    sp.add_argument("key", help="密钥")
    sp.add_argument("text", help="文本或 @file")
    sp.set_defaults(func=cmd_hmac)

    sp = sub.add_parser("pbkdf2", help="PBKDF2 派生密钥 (输出 hex)")
    sp.add_argument("password", help="口令")
    sp.add_argument("salt", help="盐")
    sp.add_argument("iterations", type=int, nargs="?", default=10000)
    sp.add_argument("klen", type=int, nargs="?", default=32)
    sp.set_defaults(func=cmd_pbkdf2)

    sp = sub.add_parser("rsa", help="RSA 基础数学（模幂）")
    rsa_sub = sp.add_subparsers(dest="rsa_cmd", required=True)
    sp_mp = rsa_sub.add_parser("modpow", help="大数模幂 base^exp mod mod")
    sp_mp.add_argument("base")
    sp_mp.add_argument("exp")
    sp_mp.add_argument("mod")
    sp_mp.set_defaults(func=cmd_rsa_modpow)

    sp = sub.add_parser("crack-md5", help="MD5 字典破解")
    sp.add_argument("hash", help="目标 MD5 哈希")
    sp.add_argument("dictfile", help="字典文件路径")
    sp.set_defaults(func=cmd_crack_md5)

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
