# PYG 密码学综合工具 5.0.0.5 — Python CLI rewrite

原程序：`PYG密码学综合工具_5.0.0.5/PYG_TOOLS_VER5.exe` + `PYG.dll`（www.chinapyg.com）。

PYG 是一个密码学综合工具箱，其 `PYG.dll` 暴露了大量加密算法，包括：
AES, DES, 3DES, Blowfish, CAST128/256, Camellia, GOST, IDEA, MARS, RC2/5/6, Tiger, BTEA, Adler32, CRC32, Base64, MD2/4/5, SHA1/224/256/384/512, SHA3, RSA, TLS/SSL 等，并提供文件哈希（*_FileHash）功能。

`PYG_TOOLS_VER5.exe` 和 `PYG.dll` 均被 PECompact2 壳保护，完整的对称加密算法实现无法直接从标准库复现。本 CLI 按 PYG 的功能描述重写，实现 Python 标准库可独立完成的部分：**多种哈希（MD/SHA/SHA3/Blake2/Adler32/CRC32）、Base64、文件哈希、RSA 基础模幂（无填充）**。AES/DES/Blowfish 等对称加密需第三方库（如 cryptography），故不在本 CLI 中实现。

## 用法

```
python main.py <子命令> [参数] [选项]
```

## 子命令

| 子命令 | 说明 |
|--------|------|
| `md5\|sha1\|sha224\|sha256\|sha384\|sha512 <text\|@file>` | 哈希校验 |
| `sha3_224\|sha3_256\|sha3_384\|sha3_512 <text\|@file>` | SHA-3 哈希 |
| `blake2b\|blake2s <text\|@file>` | BLAKE2 哈希 |
| `adler32 <text\|@file>` | Adler32 校验 |
| `crc32 <text\|@file>` | CRC32 校验 |
| `base64 enc\|dec <text>` | Base64 编码/解码 |
| `filehash <algo> <file>` | 计算文件哈希（对应 *_FileHash） |
| `aes enc\|dec <key> <text>` | AES 加/解密（需 `cryptography` 库；`--mode ecb/cbc/cfb/ofb/ctr`，`--key-format utf8\|hex`，`--iv ...`） |
| `rsa modpow <base> <exp> <mod>` | RSA 基础模幂 base^exp mod mod（无填充） |

### 示例

```
python main.py md5 "hello"
python main.py sha256 @setup.exe
python main.py filehash md5 setup.exe
python main.py base64 enc "Hello"
python main.py rsa modpow 5 13 23
python main.py aes enc 0123456789abcdef0123456789abcdef "Hello World" --key-format hex --mode cbc --iv 00000000000000000000000000000000 --iv-format hex
python main.py aes dec 0123456789abcdef0123456789abcdef <密文hex> --key-format hex --mode cbc --iv 00000000000000000000000000000000 --iv-format hex
python main.py crc32 "data"
```

所有字符串按 UTF-8 字节处理；`@file` 表示从文件读取。
