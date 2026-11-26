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