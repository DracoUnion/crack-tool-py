# DNiD 2.0.6.0 — Python CLI 重写

原程序：`DNiD_2.0.6.0/DNiD2.exe`
（"DNiD is a PE Identifier specifically targeting .NET compiled binaries.
  It has basically the same features as PEiD, only written in .NET"）

## 功能

识别 .NET 程序集被加壳/混淆的保护厂商与名称（类 PEiD 的签名扫描）。
核心逻辑 `clsScanner.Scan`：读取文件字节，把每条保护签名（字节模式，`-1`
为通配符）从文件偏移 0 处顺序匹配，命中第一条即返回对应名称，否则返回
`Unknown or no protection!`。

## 用法

扫描（默认子命令）：

```
python main.py scan <file1> [file2 ...]
python main.py <file1> [file2 ...]          # 省略 scan 亦可
```

示例：

```
python main.py some_app.exe
some_app.exe: ConfuserEx -> Ki
```

右键菜单（mU.DCMA，对应 `mU.DCMA.exe`）：

```
python main.py menu <DNiD目录> [--remove] [--dry-run] [--root hkcr|hkcu]
```

- 默认写入 `HKCR\*\shell\Scan with DNiD 2\command` = `<目录>\DNiD2.exe %1`
  （与原 mU.DCMA 的 `Environment.CurrentDirectory + "\DNiD2.exe %1"` 一致）。
- `--dry-run` 只打印不写入；`--root hkcu` 改写到 `HKCU\Software\Classes`
  （当前用户，便于安全测试）；`--remove` 删除菜单项。

## 结构

- `main.py` — CLI 入口与扫描算法（`search_bytes` / `scan`）。
- `signatures.py` — 77 条签名（显示名、模式字节、是否从入口点开始）。
  自动从 `DNiD2.exe` 反编译的 `Signatures.SignaturesList` 与
  `SignatureList.Add` 调用顺序提取，逐字节保真，避免手工转录错误。

## 与源代码的对应

| 原 (DNiD2.exe) | Python |
|---|---|
| `clsScanner.Scan(byte[])` | `scan(data)` |
| `clsScanner.SearchBytes` / `FindPattern` | `search_bytes(data, pattern, start)` |
| `Signatures.SignaturesList.*` + `SignatureList.Add` | `signatures.SIGNATURES` |

> 说明：原程序用 `Parallel.ForEach` 并返回“最后匹配项”（并发顺序不确定）；
> 本 CLI 改为确定性的“按声明顺序返回首匹配”。所有内部签名 `item2` 均为
> `false`，即一律从偏移 0 开始匹配。

## 验证

用特征字节注入到测试文件，验证识别结果（含通配符、多厂商、默认值）：

| 注入内容 | 期望识别 |
|---|---|
| `ConfuserEx v` | ConfuserEx -> Ki |
| `\0Macrobject.Obfuscator\0` | Obfuscator.NET 2009 -> Macrobject Software |
| `_mpress` | MPRESS v1.0 - v2.X -> MATCODE Software |
| `\0BabelAttribute\0` | Babel Obfuscator v3.X -> Alberto Ferrazzoli |
| `Powered by SmartAssembly 6.X.Y` | SmartAssembly v5.X -> RedGate（v5 子串先命中）|
| 随机字节 | Unknown or no protection! |

全部通过。