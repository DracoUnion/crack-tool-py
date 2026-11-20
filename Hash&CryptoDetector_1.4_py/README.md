# Hash & Crypto Detector 1.4 — Python CLI rewrite

原程序：`Hash&CryptoDetector_1.4/Hash & Crypto Detector v1.4/HCD.exe`（Mr. Paradox, AT4RE, 2009）。

HCD 是一个 PE 文件签名扫描器，用于检测 PE 文件中嵌入的常见哈希/加密算法实现、编译器及壳/保护标识（声称 120+ 个签名），支持命令行扫描、拖拽与 Shell 集成。

HCD.exe 本身被 PECompact2 壳保护，其内置签名库无法直接通过静态字符串提取。本 CLI 按 HCD 的功能描述重写：对给定 PE 文件做结构解析、字符串扫描（编译器/壳/保护标识）及常见哈希/加密算法特征字节扫描，输出检测结果。

## 用法

```
python main.py <pefile> [--deep]
python main.py <pefile> --json
```

| 选项 | 说明 |
|------|------|
| `<pefile>` | 要扫描的 PE 文件路径 |
| `--deep` | 深度扫描：扫描所有节区并尝试定位特征字节偏移（对应 "Total Scan / Deep Methode Scan"） |
| `--json` | 以 JSON 形式输出结果 |

### 示例

```
python main.py setup.exe
python main.py malware.bin --deep
python main.py app.dll --json
```

输出示例（文本）：
```
File    : setup.exe
Size    : 123456 bytes
Machine : x86 (0x14c)
Entry   : 0x00401000
Sections: .text .rdata .data .rsrc

[Compiler] Microsoft Visual C++ (MSVC) detected
[Crypto]   MD5 constant detected at VA 0x004055A0
[Packer]   None detected
```
