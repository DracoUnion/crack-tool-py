#!/usr/bin/env python3
"""
PYG 密码学综合工具 5.0.0.5 — Python CLI rewrite

原程序：PYG_TOOLS_VER5.exe + PYG.dll (www.chinapyg.com)
PYG.dll 暴露 AES/DES/3DES/Blowfish/CAST/Camellia/GOST/IDEA/MARS/RC2/5/6/Tiger/BTEA/Adler32/CRC32/Base64/MD2/4/5/SHA1/224/256/384/512/SHA3/RSA/TLS/SSL 等算法，并提供 *_FileHash 文件哈希。

本 CLI 实现 Python 标准库可独立完成的部分：多种哈希、Adler32、CRC32、Base64、文件哈希、RSA 基础模幂，以及 AES（借助 cryptography 库）加解密。
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

_HASH_ALGO = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha224": hashlib.sha224,
    "sha256": hashlib.sha256,
    "sha384": hashlib.sha384,
    "sha512": hashlib.sha512,
    "sha3_224": hashlib.sha3_224,
    "sha3_256": hashlib.sha3_256,
    "sha3_384": hashlib.sha3_384,
    "sha3_512": hashlib.sha3_512,
    "blake2b": hashlib.blake2b,
    "blake2s": hashlib.blake2s,
}


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


def cmd_hash(args):
    algo = args.algo.lower()
    if algo not in _HASH_ALGO:
        print("Error: unknown algo %s" % algo, file=sys.stderr)
        return 1
    data = read_input(args.text)
    out_text(_HASH_ALGO[algo](data).hexdigest())
    return 0


def cmd_adler32(args):
    data = read_input(args.text)
    out_text("%08X" % (zlib.adler32(data) & 0xFFFFFFFF))
    return 0


def cmd_crc32(args):
    data = read_input(args.text)
    out_text("%08X" % (zlib.crc32(data) & 0xFFFFFFFF))
    return 0


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
        sys.stdout.buffer.write(raw)
        sys.stdout.buffer.write(b"\n")
    return 0


def cmd_filehash(args):
    algo = args.algo.lower()
    if algo not in _HASH_ALGO:
        print("Error: unknown algo %s" % algo, file=sys.stderr)
        return 1
    path = args.file
    if not os.path.isfile(path):
        print("Error: file not found: %s" % path, file=sys.stderr)
        return 1
    h = _HASH_ALGO[algo]()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            h.update(chunk)
    out_text(h.hexdigest())
    return 0


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
# AES（需 cryptography 库；对应 PYG.dll 的 AES_Encrypt / AES_Decrypt）
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


_MODES = {
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
    ModeCls = _MODES.get(mode)
    if ModeCls is None:
        print("Error: unknown mode %s (valid: ecb/cbc/cfb/ofb/ctr)" % mode, file=sys.stderr)
        return 1

    # 构造模式对象（ECB 不需要 IV）
    if mode == "ecb":
        cipher_mode = ModeCls()
    else:
        iv = _parse_key(args.iv, args.iv_format)
        if len(iv) != 16:
            print("Error: IV must be 16 bytes (%d given)" % len(iv), file=sys.stderr)
            return 1
        cipher_mode = ModeCls(iv)

    # 读取输入：enc 按 UTF-8 字节；dec 按十六进制（或 @file 原始字节）
    if args.action == "enc":
        data = args.text.encode("utf-8")
    else:
        if args.text.startswith("@"):
            path = args.text[1:]
            if not os.path.isfile(path):
                print("Error: file not found: %s" % path, file=sys.stderr)
                return 1
            with open(path, "r", encoding="utf-8") as f:
                hextext = f.read()
        else:
            hextext = args.text
        try:
            data = binascii.unhexlify(hextext.strip().replace(" ", ""))
        except Exception as e:
            print("Error: invalid hex ciphertext: %s" % e, file=sys.stderr)
            return 1

    # Padding：仅 ECB/CBC 且要求 pkcs7 时使用
    need_pad = mode in ("ecb", "cbc") and args.pad == "pkcs7"

    cipher = Cipher(AES(key), cipher_mode)
    if args.action == "enc":
        if need_pad:
            data = _pad_pkcs7(data)
        enc = cipher.encryptor()
        out = enc.update(data) + enc.finalize()
        sys.stdout.write(out.hex())
        sys.stdout.write("\n")
    else:
        dec = cipher.decryptor()
        out = dec.update(data) + dec.finalize()
        if need_pad:
            try:
                out = _unpad_pkcs7(out)
            except ValueError as e:
                print("Error: %s" % e, file=sys.stderr)
                return 1
        # 优先按 UTF-8 输出明文；失败则输出十六进制
        try:
            sys.stdout.buffer.write(out)
            sys.stdout.buffer.write(b"\n")
        except Exception:
            sys.stdout.write(out.hex())
            sys.stdout.write("\n")
    return 0


def build_parser():
    p = argparse.ArgumentParser(
        prog="main.py",
        description="PYG 密码学综合工具 5.0.0.5 — Python CLI (纯 Python 重写，标准库实现)。",
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    for algo in sorted(_HASH_ALGO):
        sp = sub.add_parser(algo, help="计算 %s 哈希" % algo.upper())
        sp.add_argument("text", help="文本或 @file")
        sp.set_defaults(func=cmd_hash, algo=algo)

    sp = sub.add_parser("adler32", help="Adler32 校验")
    sp.add_argument("text", help="文本或 @file")
    sp.set_defaults(func=cmd_adler32)

    sp = sub.add_parser("crc32", help="CRC32 校验")
    sp.add_argument("text", help="文本或 @file")
    sp.set_defaults(func=cmd_crc32)

    sp = sub.add_parser("base64", help="Base64 编码/解码")
    sp.add_argument("mode", choices=["enc", "dec"])
    sp.add_argument("text", help="文本")
    sp.set_defaults(func=cmd_base64)

    sp = sub.add_parser("filehash", help="计算文件哈希（对应原程序 *_FileHash）")
    sp.add_argument("algo", help="哈希算法 (md5/sha1/sha256/...)")
    sp.add_argument("file", help="文件路径")
    sp.set_defaults(func=cmd_filehash)

    sp = sub.add_parser("aes", help="AES 加解密（需 cryptography 库）")
    aes_sub = sp.add_subparsers(dest="aes_cmd", required=True)

    sp_enc = aes_sub.add_parser("enc", help="AES 加密（输出十六进制）")
    sp_enc.add_argument("key", help="密钥 (16/24/32 字节)")
    sp_enc.add_argument("text", help="明文 (UTF-8)")
    sp_enc.set_defaults(func=cmd_aes, action="enc")

    sp_dec = aes_sub.add_parser("dec", help="AES 解密（输入十六进制密文，或 @file 读原始字节）")
    sp_dec.add_argument("key", help="密钥 (16/24/32 字节)")
    sp_dec.add_argument("text", help="十六进制密文，或 @file")
    sp_dec.set_defaults(func=cmd_aes, action="dec")

    for sp_aes in (sp_enc, sp_dec):
        sp_aes.add_argument("--mode", choices=["ecb", "cbc", "cfb", "ofb", "ctr"], default="cbc",
                            help="工作模式 (默认 cbc)")
        sp_aes.add_argument("--iv", default="00000000000000000000000000000000",
                            help="初始向量 (十六进制或 UTF-8，默认全零)")
        sp_aes.add_argument("--key-format", choices=["utf8", "hex"], default="utf8",
                            help="密钥输入格式 (默认 utf8)")
        sp_aes.add_argument("--iv-format", choices=["utf8", "hex"], default="hex",
                            help="IV 输入格式 (默认 hex)")
        sp_aes.add_argument("--pad", choices=["pkcs7", "none"], default="pkcs7",
                            help="填充方式 (ecb/cbc 默认 pkcs7；流模式建议 none)")

    sp = sub.add_parser("rsa", help="RSA 基础数学（模幂，无填充）")
    rsa_sub = sp.add_subparsers(dest="rsa_cmd", required=True)
    sp_mp = rsa_sub.add_parser("modpow", help="大数模幂 base^exp mod mod")
    sp_mp.add_argument("base")
    sp_mp.add_argument("exp")
    sp_mp.add_argument("mod")
    sp_mp.set_defaults(func=cmd_rsa_modpow)

    return p


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
