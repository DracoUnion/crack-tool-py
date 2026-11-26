# .NET Reflector 7.3 (ReflectorCmd) — Python CLI rewrite

原程序：`Reflector_7.3/ReflectorCmd.exe（Red Gate .NET Reflector 命令行启动器）`

ReflectorCmd 是 .NET Reflector 的命令行启动器，把参数转交 Reflector GUI。

## 复刻范围（如实说明）

- **完整复刻** 原程序命令行契约（选项/参数/用法，见 `--help`）。
- **真正可测试的 Python 逻辑**：PE/CLR 头解析（识别 .NET 程序集、读取 CLR 版本）。
- **未移植**：.NET Reflector 反编译引擎（GUI 内嵌）（不现实逐行重写）。本 CLI 不做该转换，只识别与报告。

> 这是“命令行契约 + .NET 识别”的忠实复刻，**不是**核心引擎的移植；`--help` 与
> 本 README 均明确标注，避免误导。

## 用法

```
python main.py [options] <file...>
python main.py --help
```

## 验证

- `--help` 输出选项与原程序一致；
- 对真实 .NET 程序集正确识别 CLR 版本；非 .NET 文件被跳过。

无第三方依赖，纯标准库。


## 逐函数逆向分析（深入）

原程序：`Reflector_7.3/ReflectorCmd.exe`

反编译确认 ReflectorCmd 是 .NET Reflector 的**命令行启动器**（仅打印 banner 并把参数转交 Reflector GUI），无独立逆向逻辑可移植。
