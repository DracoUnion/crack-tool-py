# NETReactorSlayer 6.4 — Python CLI rewrite

原程序：`NETReactorSlayer_6.4/NETReactorSlayer.CLI.exe（CLI 前端，转交核心）`

NETReactorSlayer.CLI.exe 是 7KB 薄包装，把 args 转交 NETReactorSlayer 核心。

## 复刻范围（如实说明）

- **完整复刻** 原程序命令行契约（选项/参数/用法，见 `--help`）。
- **真正可测试的 Python 逻辑**：PE/CLR 头解析（识别 .NET 程序集、读取 CLR 版本）。
- **未移植**：NETReactorSlayer 去混淆引擎（.NET Reactor 专用）（不现实逐行重写）。本 CLI 不做该转换，只识别与报告。

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

原程序：`NETReactorSlayer_6.4/NETReactorSlayer.exe`

NETReactorSlayer.CLI.exe 为 7KB 薄包装转交核心；核心程序反编译报错（**被混淆**），逐函数逆向被混淆阻断。已移植 CLI 契约。


## x32dbg 脱壳尝试结果（CTF）

对 `ScanId.exe` 做 x32dbg 脱壳尝试（.NET 程序在 CLR 下运行）：
1. LoadBinary 后运行，CLR 启动，`scanid.exe` 模块映射到 `0xAE0000`（2.5MB）；
2. `DumpModule scanid.exe` 导出内存镜像到 `scanid_dumped.exe`；
3. 反编译内存镜像报 `Missing data directory`（内存镜像 PE 数据目录被清零，需重建）；
4. **关键结论**：ScanId 的混淆是**元数据符号重命名**（`ykSTlfndjcWO4c8Wm7` 等），
   非压缩壳；从内存 DUMP 得到的仍是同一套混淆程序集，且核心检测逻辑在 de4dot 库内。
   因此“脱壳”不改变混淆本质，无法据此产出忠实的 Python 引擎。
