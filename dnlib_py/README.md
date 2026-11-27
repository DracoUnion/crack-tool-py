# dnlib_py — dnlib 等价 .NET 元数据 / IL 引擎（纯 Python）

原程序：`dnSpy/dnSpy.exe` + `dnlib.dll`（.NET 元数据操作库）

dnlib 是 dnSpy / de4dot / Mono.Cecil 一类工具的共同底座：解析 PE/CLI/元数据
流与全部元数据表、编码索引、方法体、IL 指令。本 CLI 用纯标准库逐函数复刻
其核心，作为其它引擎（反编译、去混淆）的基础。

## 实现范围

- **PE + CLI 头**：解析 MZ/PE、节表、数据目录、CLR 头（识别 .NET、读 CLR 版本）。
- **元数据根 + 流**：`BSJB` 根、版本串、流表（每项 Offset+Size+Name 交错，名称 4 字节对齐）。
- **全部元数据表**（ECMA-335 II.22 真实表号，含 Ptr/Assembly/Enc 空位）：
  Module/TypeRef/TypeDef/Field/MethodDef/Param/InterfaceImpl/MemberRef/Constant/
  CustomAttribute/FieldMarshal/DeclSecurity/ClassLayout/…/GenericParamConstraint。
- **编码索引**：`TypeDefOrRef`、`HasCustomAttribute`、`MemberRefParent`、
  `MethodDefOrRef`、`Implementation`、`ResolutionScope` 等，按引用表实际行数
  动态计算 2/4 字节宽度（这是元数据解析最易错处）。
- **堆**：`#Strings`/`#US`/`#GUID`/`#Blob`（压缩整数长度）。
- **方法体**：tiny/fat 头、代码大小、局部变量签名、IL 字节。
- **IL 反汇编**：完整 ECMA-335 Partition III 操作码表（单字节 + 0xFE 前缀）。

## 用法

```
python main.py <assembly>                  列出类型/方法/字段统计
python main.py <assembly> --raw            打印全部表行数
python main.py <assembly> --method <name>  反汇编某方法 IL
python main.py <assembly> --il <n>         按 MethodDef 索引(1基)反汇编
```

示例：

```
python main.py ICSharpCode.Decompiler.dll --il 5
python main.py MpressClass.dll --raw
```

## 验证

- 对 `ICSharpCode.Decompiler.dll`：TypeDef=1481 / MethodDef=14060 / Field=5594，
  与 `System.Reflection.Metadata` 权威读数完全一致；
- 方法名、`ldc.i4/mul/call/ldfld/callvirt/add/ret` 等 IL 反汇编正确；
- 对加壳的 `MpressClass.dll`、`de4dot.exe` 也能正确解析其最小元数据。

无第三方依赖，纯标准库。