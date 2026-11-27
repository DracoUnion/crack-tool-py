# Mono.Cecil_py — Mono.Cecil 等价引擎（.NET 程序集对象模型，读取侧）

原程序：被 de4dot / 众多混淆器与反射工具引用的 `Mono.Cecil.dll`

Mono.Cecil 是 .NET 程序集读写对象模型库：`ModuleDefinition.ReadModule(path)`
读入模块，暴露 `Types / Methods / Fields / Body.Instructions` 等对象。de4dot
及 Cecil 生态的几乎所有工具都构建于其上。本 CLI 用纯标准库（复用同仓
`dnlib_py` 元数据引擎）复刻其**读取侧对象模型**：

- `ModuleDefinition.ReadModule(path)`
- `ModuleDefinition.Types` -> `TypeDefinition`（Name/Namespace/FullName/
  Methods/Fields/NestedTypes）
- `TypeDefinition.Methods` -> `MethodDefinition`（Name/DeclaringType/Body）
- `MethodDefinition.Body` -> `MethodBody.Instructions` -> `Instruction`
  （OpCode / Operand / Offset，操作数已符号化）
- `ILProcessor` 占位（读取侧只读）

## 诚实说明

Cecil 的**写入**（`ILProcessor.Emit` / `WriteModule` 重写程序集）需要完整
元数据写入器，超出本核心范围；本 CLI 是其读取侧对象模型的忠实子集。

## 用法

```
python main.py <assembly>                         列出类型/方法（Cecil 风格）
python main.py <assembly> --type <t> --method <m> 导出方法 IL
python main.py <assembly> --il <n>                按 MethodDef 索引导出 IL
```

示例：

```
python main.py ICSharpCode.Decompiler.dll --il 2
python main.py MpressClass.dll
```

## 验证

- `ICSharpCode.Decompiler.dll`：正确列出 1481 类型及其方法/字段计数；
  `--il 2` 输出 `ldfld 0x0A000094 (<m>i__Field)` 等符号化 IL。
- 无第三方依赖，纯标准库（导入同仓 `dnlib_py` 引擎）。