# EasyRecovery 12 — Python CLI rewrite

原程序：`EasyRecovery_12/EasyRecovery12.exe`（EasyRecovery 12 的 NSIS 安装程序，Nullsoft Install System v3.0b1，UPX 压缩）。

注意：该二进制本身只是 EasyRecovery 的安装程序，而非数据恢复引擎，且已被 UPX 壳压缩，完整逆向其恢复引擎不现实。本 CLI 按 EasyRecovery 的"数据恢复/undelete"定位重写：对给定二进制文件（如磁盘镜像、删除文件的 raw 镜像）做文件头签名扫描与文件雕刻（carve），把识别出的文件片段提取出来。

## 用法

```
python main.py scan <file> [--json]
python main.py carve <file> <outdir> [--chunk N]
```

| 子命令 | 说明 |
|--------|------|
| `scan <file>` | 扫描二进制文件，列出所有已知文件头签名的偏移与类型 |
| `--json` | 以 JSON 输出 |
| `carve <file> <outdir>` | 扫描并把每个签名处开始的 N 字节提取为独立文件到 outdir |
| `--chunk N` | 每个片段提取的字节数（默认 4096） |

已知签名包括：JPEG, PNG, GIF, BMP, PDF, ZIP, GZIP, RAR, 7Z, EXE/DLL (MZ), PNG, ICO, WMF, MIDI 等。

### 示例

```
python main.py scan disk.img
python main.py scan disk.img --json
python main.py carve disk.img ./recovered --chunk 8192
```

输出示例（scan）：
```
0x00001000  JPEG image
0x00005000  PNG image
0x0000A000  PDF document
0x00012000  ZIP archive
```
