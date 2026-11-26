# dnSpy — Python CLI rewrite

原程序：`dnSpy/dnSpy.Console.exe`（dnSpy 套件命令行版）+ `dnSpy/dnSpy.exe`（图形版）

`dnSpy.Console.exe` 解析 21 条选项后调用 `DnSpyDecompiler.Run(args)`，由
dnlib + dnSpy.Decompiler 引擎把 .NET 程序集反编译为 C#。

## 复刻范围（如实说明）

- **完整复刻** `dnSpy.Console.exe` 的命令行契约（21 条选项，与 `usageInfos` 一致）：
  `--asm-path`、`--user-gac`、`--no-gac`、`--no-stdlib`、`--no-sln`、`--sln-name`、
  `--threads`、`--no-resources`、`--no-resx`、`--no-baml`、`--no-color`、`--spaces`、
  `--vs`、`--project-guid`、`-t/--type`、`--md`、`--gac-file`、`-r`、`-o`、`-l`。
- **真正可测试的 Python 逻辑**：PE/CLR 头解析（识别 .NET 程序集、读取 CLR 版本），
  `-o` 时写出元数据摘要。
- **未移植**：dnlib + dnSpy 去编译引擎（数十 MB、多程序集强依赖，不现实逐行重写）。
  本 CLI 不做 C# 去编译，只识别与报告。

> 这是“命令行契约 + .NET 识别”的忠实复刻，**不是**完整反编译引擎的移植；
> `--help` 与 README 均明确标注，避免误导。

## 用法

```
python main.py [options] <file>
python main.py --help
```

示例：

```
python main.py file.dll -o out/
python main.py -r c:\my\files -o c:\my\output
```

## 验证

- `--help` 输出 21 条选项与原 dnSpy.Console 一致；
- 对真实 .NET 程序集（如 `MpressClass.dll`）正确识别 `CLR v2.5`；
- `-o` 写出 `.info.txt` 元数据摘要；
- 非 .NET 文件被跳过。

无第三方依赖，纯标准库。