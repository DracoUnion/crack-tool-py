# PasswareKit Forensic 32+64 便携版 — Python CLI rewrite

原程序：`PasswareKitForensic_32_64_便携版/PasswareKitForensic 32+64便携版/PasswareKitForensic.exe`（及 x64 版，约 112 MB 商业密码恢复/取证软件）。

PasswareKit 是面向取证与密码恢复的商业工具，支持对多种文件格式（PDF、Office、ZIP、RAR 等）的密码恢复。随附材料包括：
- `kEy.txt`：PasswareKit 注册密钥与使用说明（断网、禁用自动更新、防火墙阻止）。
- `网络流行资源字典.txt`：常见弱密码字典（用于字典攻击）。

完整逆向 112 MB 商业程序不现实。本 CLI 按 PasswareKit 的核心用途（基于字典的密码恢复/破解）重写：给定目标哈希与字典文件，逐行尝试多种哈希算法，找出匹配明文。

## 用法

```
python main.py crack <hash> <dictfile> [--algo md5|sha1|sha256|sha512|all]
python main.py key
```

| 子命令 | 说明 |
|--------|------|
| `crack <hash> <dictfile>` | 字典攻击：在字典中查找与目标哈希匹配的明文 |
| `--algo` | 指定哈希算法：md5 / sha1 / sha256 / sha512 / all（默认 md5） |
| `key` | 显示随附 kEy.txt 中的注册密钥信息（参考） |

### 示例

```
python main.py crack 5d41402abc4b2a76b9719d911017c592 字典.txt
python main.py crack aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d 字典.txt --algo sha1
python main.py crack 827ccb0eea8a706c4c34a16891f84e7b dict.txt --algo all
python main.py key
```

字典文件每行一个候选密码；空行自动跳过。
