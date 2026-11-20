# Keygener Assistant — Python CLI rewrite

原程序：`KeygenerAssistant/keyAssistant Remixed.exe`（Coded By Mr Paradox, TEAM AT4RE, v2.1.2, 2016）。

这是一个综合密码学 / 密钥生成辅助工具，用于算法分析，功能包括：
- BigNumbers 计算器（大数运算、模幂、素性测试）
- Conversion & Encoding（Base91/MIME32/MIME64/PGP/UUCODE/XXCODE/RFC1760，2/8/10/16/32/64/256 进制转换）
- Hashing & CheckSum（MD5, SHA1, CRC 等）
- Cryptography Operations（RSA, DSA, ElGamal, ECC/ECDSA, AES, DES, Cesare, Vigenere, ROT-n, PC1, XOR, ADD, NOT）
- Hash & Crypto detector
- 系统信息与工具

本 CLI 把原程序中最核心、可独立复现的算法重写为纯 Python 命令行工具（标准库实现，无第三方依赖），涵盖编码转换、哈希校验、经典对称加密与大数模幂（RSA 基础加解密）。

## 用法

```
python main.py <子命令> [参数] [选项]
```

## 子命令

| 子命令 | 说明 |
|--------|------|
| `base64 enc\|dec <text>` | Base64 (MIME64) 编码/解码 |
| `hex enc\|dec <text>` | 十六进制编码/解码 |
| `base <src_base> <dst_base> <number>` | 进制转换 (2-256 进制) |
| `md5\|sha1\|crc32 <text\|@file>` | 计算字符串或文件哈希（`@file` 表示读文件） |
| `caesar <text> <shift>` | 凯撒密码 E(x)=(x+shift) mod 26 |
| `rot <n> <text>` | ROT-n 旋转 |
| `vigenere <enc\|dec> <key> <text>` | 维吉尼亚多表替换加/解密 |
| `xor <key> <text>` | 与密钥异或（密钥会循环） |
| `not <text>` | 按位取反（加解密对称） |
| `add <key> <text>` | 与密钥相加（模 256） |
| `modpow <base> <exp> <mod>` | 大数模幂 base^exp mod mod（RSA 数学基础） |
| `rsa enc\|dec <n> <e\|d> <text>` | RSA 基础加/解密（给定模数 n 与指数 e/d，对数值做模幂） |
| `aes enc\|dec <key> <text>` | AES 加解密（需 cryptography 库；`--mode ecb/cbc/cfb/ofb/ctr`，`--key-format utf8\|hex`，`--iv ...`） |

### 示例

```
python main.py base64 enc "Hello"
python main.py base64 dec "SGVsbG8="
python main.py base 16 2 "48656C6C6F"
python main.py md5 @setup.exe
python main.py sha1 "password"
python main.py crc32 "data"
python main.py caesar "Hello" 3
python main.py rot 13 "Hello"
python main.py vigenere enc KEY "HELLO"
python main.py xor key "Hello"
python main.py not "Hello"
python main.py modpow 5 13 23
python main.py rsa enc <n> <e> "42"
python main.py aes enc 0123456789abcdef0123456789abcdef "Hello Keygen AES" --key-format hex --mode cbc --iv 00000000000000000000000000000000 --iv-format hex
python main.py aes dec 0123456789abcdef0123456789abcdef <密文hex> --key-format hex --mode cbc --iv 00000000000000000000000000000000 --iv-format hex
```

所有字符串按 UTF-8 字节处理；文件路径以 `@` 前缀表示从文件读取。
