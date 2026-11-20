# FFV v1.0 — Python CLI rewrite

原程序：`FFV_1.0/FFV v1.0.exe`（VB6 编写，by yuanfang235，2013）。

这是一个文件头查看 / 文件类型识别工具：打开一个文件，显示文件名、大小、创建时间、修改时间，以及文件头的十六进制与字符串表示，并根据内置文件头签名库识别文件类型（如 zip/pdf/png/jpeg/rar/avi 等）。

本 CLI 把原 GUI 功能重写为纯 Python 命令行工具，无第三方依赖，内置原程序随附的文件头签名库。

## 用法

```
python main.py <file> [--hex-len N]
python main.py --list
```

| 参数 | 说明 |
|------|------|
| `<file>` | 要查看的文件路径 |
| `--hex-len N` | 显示文件头的十六进制字节数（默认 32） |
| `--list` | 列出内置的所有文件头签名 |

### 示例

```
python main.py setup.zip
python main.py image.png --hex-len 64
python main.py --list
```

输出示例：
```
File     : setup.zip
Size     : 123456 bytes
Created  : 2023-01-15 08:30:00
Modified : 2023-01-15 09:15:00
Head hex : 50 4B 03 04 14 00 01 00 08 00 ...
Head str : PK....... (PK)
Type     : zip
```
