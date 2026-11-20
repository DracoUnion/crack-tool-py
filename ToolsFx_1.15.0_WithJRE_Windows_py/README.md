# ToolsFx 1.15.0 — Python CLI rewrite

原程序：`ToolsFx_1.15.0_WithJRE_Windows/`（Leon406, https://github.com/Leon406/ToolsFx，Java/Kotlin + JavaFX + BouncyCastle）。

这是一个综合密码学 / 编码工具箱，属性文件声明了这些模块：
- Classical（经典编码/转换）
- PBE（基于口令的密码派生）
- Signature（数字签名）
- MAC（消息认证码）
- Symmetric Stream（对称流加密）
- Qrcode（二维码）
- BigInt（大整数）
- 内置 Webview（调用 hiencode/tool.lu/sojson 等在线工具）

并随带 `dict/top1000.txt` 与 `自定义字典.txt`，用于 MD5 字典破解（crack）。

本 CLI 把原程序中可用 Python 标准库独立复现的部分重写为命令行工具：**编码转换、哈希、HMAC、PBKDF2、RSA 基础模幂、MD5 字典破解**。对称加密 (AES/DES)、二维码需第三方库，故不在本 CLI 中实现。

## 用法

```
python main.py <子命令> [参数] [选项]
```

## 子命令

| 子命令 | 说明 |
|--------|------|
| `base64 enc\|dec <text>` | Base64 编码/解码 |
| `hex enc\|dec <text>` | 十六进制编码/解码 |
| `url enc\|dec <text>` | URL 编码/解码 |
| `md5\|sha1\|sha256\|sha512 <text\|@file>` | 哈希校验（`@file` 读文件） |
| `hmac <algo> <key> <text\|@file>` | HMAC（algo: md5/sha1/sha256/sha512） |
| `pbkdf2 <password> <salt> [iterations] [klen]` | PBKDF2 派生密钥（输出 hex） |
| `rsa modpow <base> <exp> <mod>` | 大数模幂（RSA 数学基础） |
| `aes enc\|dec <key> <text>` | AES 加解密（需 cryptography 库；`--mode ecb/cbc/cfb/ofb/ctr`，`--key-format utf8\|hex`，`--iv ...`） |
| `crack-md5 <hash> <dictfile>` | MD5 字典破解（逐行比对字典） |

### 示例

```
python main.py base64 enc "Hello"
python main.py hex dec "48656C6C6F"
python main.py url enc "a=b&c=d"
python main.py sha256 @setup.exe
python main.py hmac sha256 mykey "message"
python main.py pbkdf2 password salt 10000 32
python main.py rsa modpow 5 13 23
python main.py aes enc 0123456789abcdef0123456789abcdef "Hello ToolsFx AES" --key-format hex --mode cbc --iv 00000000000000000000000000000000 --iv-format hex
python main.py aes dec 0123456789abcdef0123456789abcdef <密文hex> --key-format hex --mode cbc --iv 00000000000000000000000000000000 --iv-format hex
python main.py crack-md5 5d41402abc4b2a76b9719d911017c592 dict/top1000.txt
```

字符串按 UTF-8 字节处理；`@file` 表示从文件读取。
