# Hash文件校验器 1.04 — Python CLI rewrite

原程序：`Hash文件校验器_1.04/Hash文件校验器_1.04.exe`（by Robin Keir, keir.net, 2013）。

这是一个文件哈希校验工具，支持 CRC32、MD5、SHA1 三种哈希算法，可将计算结果保存为文本列表，并支持拖拽文件与剪贴板复制。

本 CLI 把原 GUI 功能重写为纯 Python 命令行工具，无第三方依赖，标准库自带 `hashlib`/`zlib` 即可实现全部算法，输出格式与原程序一致（`CRC32: %08X`、`MD5:`、`SHA1:`）。

## 用法

```
python main.py <file> [file ...] [--algo crc32|md5|sha1|all] [--output file]
```

| 选项 | 说明 |
|------|------|
| `<file>` | 要计算哈希的文件路径（可多个） |
| `--algo` | 指定算法：crc32 / md5 / sha1 / all（默认 all） |
| `--output` | 将结果写入文本文件（每行一个文件） |

### 示例

```
# 计算一个文件的全部哈希（CRC32/MD5/SHA1）
python main.py setup.exe

# 只计算 MD5
python main.py setup.exe --algo md5

# 多文件，全部算法
python main.py a.exe b.dll c.zip --algo all

# 保存结果到文件
python main.py *.exe --algo all --output hashes.txt
```

输出示例（与原程序格式一致）：
```
setup.exe
  Size : 123456 bytes
  CRC32: 3610A686
  MD5  : 5d41402abc4b2a76b9719d911017c592
  SHA1 : aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d
```
