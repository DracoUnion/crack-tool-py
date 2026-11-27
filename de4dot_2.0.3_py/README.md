# de4dot 2.0.3 — Python CLI rewrite

原程序：`de4dot_2.0.3/de4dot.exe`（x86 启动器）+ `bin/de4dot.cui.dll`（命令行前端）
`de4dot.exe` 只是薄启动器，把 `args` 交给 `de4dot.cui.Program.main`；真正的去混淆
由 `de4dot.code.dll` 引擎（基于 Mono.Cecil、数 MB、数百条去混淆器规则）完成。

## 复刻范围（如实说明）

- **完整复刻** 原命令行契约：`-d`、`-r/-ro/-ru`、`--dont-rename`、`--keep-names`、
  `--default-strtyp/--default-strtok`、`--no-cflow-deob`、`--keep-types`、
  `--preserve-tokens/--preserve-table`、`-o`、`-f`（追加文件）、`--strtyp/--strtok`、
  `-h/--help`，以及 `file1 file2 ...` / `file1 -f file2 -o ...` 的用法。
- **真正可测试的 Python 逻辑**：PE/CLR 头解析（识别 .NET 程序集、读取 CLR 版本），
  以及轻量级混淆启发式检测（读元数据 `#Strings` 流，统计可疑重命名占比）。
- **未移植**：`de4dot.code` 去混淆引擎（不现实逐行重写）。因此本 CLI 对“疑似混淆”
  的文件只报告、不去混淆；对“未混淆”的文件按原命名习惯写出 `<名>.cleared.<扩展名>`。

> 这是“命令行契约 + 轻量检测”的忠实复刻，**不是**完整去混淆引擎的移植。README 与
> `--help` 均明确标注，避免误导。

## 逐函数端口（de4dot.code.Utils）

`de4dot_utils.py` 逐函数移植了 `de4dot.code.dll` 反编译（ICSharpCode.Decompiler）
中的 `de4dot.Utils` 静态类纯函数（与 IL 操作无关、可忠实移植）：

`unique` / `toCsharpString` / `shellEscape` / `removeNewlines` / `getFullPath` /
`randomName` / `getBaseName` / `getDirName` / `StartsWith` /
`getAssemblySimpleName` / `pathExists` / `fileExists`。

自测：`python de4dot_utils.py` → `ALL OK`。`toCsharpString` 已与 C# 源码逐字符核对一致。

## 用法

```
python main.py [-d] [-r <dir>] [-o <out>] [-f <file> ...] <file...>
python main.py --help
```

示例：

```
python main.py obfuscated.dll
python main.py -d file1.exe -f file2.dll
python main.py -r c:\my\files -ro c:\my\output
```

## 验证

- `--help` 输出与原 de4dot 选项一致；
- 对 `dnSpy.exe` / `DNiD2.exe` / `DePhe.exe` 等真实 .NET 程序集均正确识别为
  `dotnet=True, CLR v2`；
- 未混淆文件生成 `<名>.cleared.<扩展名>`；
- 非 .NET 文件被跳过。

无第三方依赖，纯标准库。
## 去混淆分析核心（deobfuscate_core.py）

基于同仓 `dnlib_py` 元数据引擎，解析元数据 + 方法体 IL，识别常见混淆特征：

- **字符串加密**：返回 `string` 且带 `int/token` 参数、被多处用常量整数调用的
  方法（经典 `string Decrypt(int id)` 模式）；
- **代理/转发方法**：方法体仅 `ldarg.0; call Target; ret`；
- **控制流平坦化**：含 ≥5 目标 `switch` 且存在回边跳转；
- **标识符重命名**：全符号 / 极短随机名 的类型/方法/字段统计；
- **P/Invoke**：`pinvokeimpl` 方法计数。

`-d` 检测模式即调用此核心输出带证据的报告。这是 de4dot.code 的**分析核心**
忠实子集；字节级改写需完整元数据写入器，超出本核心范围。

```
python deobfuscate_core.py <assembly>
python main.py -d <assembly>
```
