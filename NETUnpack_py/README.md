# NETUnpack — Python CLI 逐函数端口（.NET 元数据解析）

原程序：`NETUnpack/NETUnpack.exe`（原生 MFC，.NET 元数据解包/重建器）

## 逆向方法

x32dbg 加载 `NETUnpack.exe`（429 函数的 MFC 程序），结合导入表与字符串
（`.NET MetaData Directory RVA`、`MetaData RVA`、`MethodBody`、`NumberOfStreams` 等）
确认其核心是 **PE/CLR 头解析 + .NET 元数据流（#~）解析 + 元数据表（TypeDef/
MethodDef/Field）重建**。

## 逐函数端口（main.py）

纯 Python 复刻了核心算法链：

1. `is_dotnet_clr` — PE/CLR 头定位（读取 CLI 头 RVA、CLR 版本）；
2. `rva_to_offset` — RVA→文件偏移（节表遍历）；
3. `parse_dotnet_metadata` — 定位元数据根（BSJB）与 #~ 表头（major=2、valid 位图）；
4. `parse_tables` — 读取 64 位 valid 位图、各表行数、按行大小跳过前置表，
   定位 TypeDef/MethodDef/Field 表数据；
5. `read_string` — #Strings 堆字符串解码。

## 验证

对 `Mpress.NetUnpacker/MpressClass.dll`：
- 正确识别 `CLR v2.5`；
- 定位 #~ 表头 `t_off=0x880`（= md_off+0x74，与流表项一致）；
- 读取行数 Module=1、TypeRef=21、TypeDef=2（与真实元数据一致）。

> 说明：PE/CLR 头、元数据根、#~ 表头、行数位图与行数解析已验证正确；
> TypeDef/MethodDef 的逐行字段解码（名称/签名索引）为尽力而为，个别偏移
> 在复杂程序集上可能不准（已在输出中以原始索引标注）。

无第三方依赖，纯标准库。