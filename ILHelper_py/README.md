# ILHelper — Python CLI rewrite

原程序：`ILHelper/ILHelper.exe（原生 PE，IL 编辑器）`

ILHelper 是原生 (C++) IL 字节编辑器（无托管元数据）。

## 复刻范围（如实说明）

- **完整复刻** 原程序命令行契约（选项/参数/用法，见 `--help`）。
- **真正可测试的 Python 逻辑**：PE/CLR 头解析（识别 .NET 程序集、读取 CLR 版本）。
- **未移植**：ILHelper 原生 IL 编辑逻辑（不现实逐行重写）。本 CLI 不做该转换，只识别与报告。

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

原程序：`ILHelper/ILHelper.exe`

x32dbg 反汇编：导入表仅 `lstrcpy`/`InitCommonControls`（其余 API 均动态 GetProcAddress 解析），二进制内无任何 IL 助记符/元数据字符串——典型的**加壳/保护**原生程序。逐函数逆向被壳阻断，无可读 IL 逻辑可移植；需先脱壳（x32dbg 运行到 OEP dump）后再分析。
