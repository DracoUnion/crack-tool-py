# GrayWolf 1.88 — Python CLI rewrite

原程序：`GrayWolf_1.88/GrayWolf.exe（GUI .NET 去混淆/解包器）`

GrayWolf 是 .NET 去混淆/解包工具（GUI）。

## 复刻范围（如实说明）

- **完整复刻** 原程序命令行契约（选项/参数/用法，见 `--help`）。
- **真正可测试的 Python 逻辑**：PE/CLR 头解析（识别 .NET 程序集、读取 CLR 版本）。
- **未移植**：GrayWolf 去混淆引擎（不现实逐行重写）。本 CLI 不做该转换，只识别与报告。

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

原程序：`GrayWolf_1.88/GrayWolf.exe`

可反编译（真实名，非混淆），核心为 Mono.Cecil 去混淆/解包（SaveSupport/MethodEditorIL 等，数十 MB）。已移植 CLI 契约与 .NET 识别；去混淆引擎未逐行移植。
