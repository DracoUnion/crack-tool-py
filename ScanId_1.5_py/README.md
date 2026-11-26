# ScanId 1.5 — Python CLI rewrite

原程序：`ScanId_1.5/ScanId.exe（GUI，de4dot 前端，识别 .NET 混淆器）`

ScanId 是 de4dot 的图形前端，扫描文件并报告所用混淆器。

## 复刻范围（如实说明）

- **完整复刻** 原程序命令行契约（选项/参数/用法，见 `--help`）。
- **真正可测试的 Python 逻辑**：PE/CLR 头解析（识别 .NET 程序集、读取 CLR 版本）。
- **未移植**：de4dot 检测库（内嵌于 ScanId）（不现实逐行重写）。本 CLI 不做该转换，只识别与报告。

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

原程序：`ScanId_1.5/ScanId.exe`

反编译显示类名为 `ykSTlfndjcWO4c8Wm7` 等（**被混淆**），且核心检测在 de4dot 库内。逐函数逆向被混淆阻断；已移植 CLI 契约与 .NET 识别。
