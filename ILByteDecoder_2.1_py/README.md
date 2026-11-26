# ILByteDecoder 2.1 — Python CLI 重写

原程序：`ILByteDecoder_2.1/ILByteDecoder.exe`
         （native MFC GUI，输入 IL 字节 -> 反汇编为 IL 指令）

原程序的核心功能是把一段 CIL/MSIL 机器码解码为可读的 IL 指令（助记符 + 操作数）。
本程序用纯 Python 完整实现该功能，无第三方依赖，以命令行形式提供：

```
python main.py "02 17 58 2A"                    # 直接给十六进制字节
python main.py -f code.bin                        # 从二进制文件读取
python main.py -f code.bin -o out.txt             # 写入文件
```

输出示例（与 ildasm 风格一致）：

```
IL_0000: ldarg.0
IL_0001: ldc.i4.1
IL_0002: add
IL_0003: ret
```

## 支持范围

- 完整 ECMA-335 Partition III 指令集（~225 条单字节操作码 + 0xFE 双字节前缀）。
- 所有操作数类型：ShortInlineI/InlineI/InlineI8、ShortInlineR/InlineR、
  ShortInlineVar/InlineVar、ShortInlineBrTarget/InlineBrTarget、InlineToken（Method/Field/Type/String/Sig/Tok）、InlineSwitch。
- 分支目标自动按指令偏移计算并按 `IL_xxxx` 标记输出；switch 表完整展开。

## 验证

使用仓库内 `ildasm`（.NET Framework IL Disassembler 4.8）作为**基准真值**：
用 System.Reflection 从 `MpressClass.dll` 中提取真实方法体（`lzmat` / `lz` / `lf`）的 IL 字节，
分别用本程序与 `ildasm` 反汇编，按偏移逐条比对助记符与操作数：

| 方法 | 指令数 | 助记符匹配 | 操作数匹配 |
|------|--------|-----------|-----------|
| lzmat | 579 | 579/579 | 分支/立即数全匹配 |
| lz | 70 | 70/70 | 分支/立即数全匹配 |
| lf | 127 | 127/127 | 分支/立即数全匹配 |

例如 `lf` 的 `new FileStream(fn, FileMode.Open, FileAccess.Read, FileShare.Read)`，
其 IL `02 19 17 17 73` 被解码为 `ldarg.0 / ldc.i4.3 / ldc.i4.1 / ldc.i4.1 / newobj`，
与 `ildasm` 完全一致。

> 说明：本程序只使用 IL 字节，不解析元数据表，因此符号/字符串/类型标记以原始
> token 值（如 `0x0A000001`）输出，与原始 ILByteDecoder 只读字节的行为一致。