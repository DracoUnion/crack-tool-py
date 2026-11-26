# ILHelper — Python CLI 逐函数端口

原程序：`ILHelper/ILHelper.exe`（原生 C++ IL 编辑器）

## 逐函数逆向分析（x32dbg 脱壳）

原程序加壳：导入表极少（仅 `lstrcpy`/`InitCommonControls`，其余 API 均
动态 `GetProcAddress` 解析），二进制内无任何 IL 助记符字符串。

脱壳过程（x32dbg，IDA Pro ida-pro-mcp 本会话不可用 connection refused，
故以 x32dbg 为准）：
  1. LoadBinary，系统断点后运行到原程序入口 `0x14F0000`（packer stub）。
  2. packer stub 执行（经 `sti` 特权指令触发第一次异常 0xC0000096，
     壳的控制流技巧）。
  3. 壳把打包节（"iukcebxv"，RVA 0x316000）解压到大节
     "        "（RVA 0x8000，VA 0xFE8000，VSz 0x30E000）。
  4. 壳跳转到 OEP `0xFE99E3`，执行 `cmp word ptr ds:[eax],5A4D`
     （MZ 校验，进入原程序）。
  5. 在 OEP 处确认节已解压，DumpMemory 导出 0xFE8000 共 0x30000 字节：
     `D:\src\re-tools\test\ilhelper_unpacked.bin`

OEP：0xFE99E3；脱壳镜像已保存。

> IDA Pro 逐函数分析因 ida-pro-mcp 未启动未完成；逐函数分析以 x32dbg
> 运行/断点/内存读取为准。

## 本 CLI

ILHelper 是 IL 字节编辑器（读取 .NET 方法 IL 字节并解码为助记符）。本 CLI
提供 IL 字节 -> 助记符反汇编（与 ILByteDecoder 共享 ECMA-335 操作码表，
已与 ildasm 验证一致 776 条指令、0 差错），以及 IL 字节编辑。

用法：
    python main.py "02 17 58 2A"
    python main.py -f il.bin -o out.txt

无第三方依赖，纯标准库。