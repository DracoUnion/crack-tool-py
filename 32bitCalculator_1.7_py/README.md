# 32bitCalculator v1.7 — Python CLI rewrite

原程序：`32bitCalculator_1.7/32bitCalculator_1.7.exe`（Win32 汇编编写，by cybult，2006）。

这是一个 32 位寄存器计算器，不使用 MMX/FPU/SSE，提供常用位运算与进制转换。本 CLI 按子命令形式把原 GUI 功能重写出来，全部为纯 Python 实现，无第三方依赖。

## 用法

```
python main.py <子命令> [参数] [选项]
```

## 子命令

| 子命令 | 说明 |
|--------|------|
| `crc32 <file>` | 计算文件的 CRC-32 校验值 |
| `str2hex <text>` | 字符串转十六进制（对应 String2Hex Converter） |
| `hex2str <hex>` | 十六进制转字符串（对应 Hex2String Converter） |
| `hex2bin <hex>` | 十六进制转二进制（对应 Hex2Bin Converter） |
| `bin2hex <bin>` | 二进制转十六进制（对应 Bin2Hex Converter） |
| `dec2hex <n>` | 十进制转十六进制（32 位无符号） |
| `hex2dec <hex>` | 十六进制转十进制（32 位无符号） |
| `jmpcalc <from> <to>` | 计算相对跳转偏移并给出条件跳转 opcode（对应 JMP Calc / Jump-Call Calculator） |
| `op <and\|or\|xor\|not\|neg\|rol\|ror\|shl\|shr\|imul\|idiv\|bswap> <a> [b]` | 32 位位运算（对应 and/or/xor/neg/rol/IMUL/IDIV/BSWAP 等） |

### 示例

```
# CRC-32 文件校验
python main.py crc32 setup.exe

# 字符串 <-> 十六进制
python main.py str2hex "Hello"
python main.py hex2str 48656c6c6f

# 二进制 <-> 十六进制
python main.py hex2bin 4865
python main.py bin2hex 01001000

# 十进制 <-> 十六进制（32 位）
python main.py dec2hex 12345
python main.py hex2dec 0x3039

# 相对跳转偏移（如 jmp 0x401000 -> 0x402000）
python main.py jmpcalc 0x401000 0x402000

# 32 位位运算
python main.py op xor 0xDEADBEEF 0x12345678
python main.py op rol 0x87654321 4
python main.py op not 0x0000000F
python main.py op bswap 0x12345678
```

所有数值均视为 32 位无符号整数，运算结果截断到 32 位（`& 0xFFFFFFFF`），与原汇编程序的 32 位寄存器行为一致。