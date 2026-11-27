# ILSpy_7.2.1.6856_py — ILSpy / ICSharpCode.Decompiler 等价引擎（IL -> C# 核心）

原程序：`ILSpy_7.2.1.6856_bin/ILSpy.exe`（前端）+ `ICSharpCode.Decompiler.dll`（引擎）

ILSpy 的 `ILSpy.exe` 本身只是图形化前端，真正的反编译由 `ICSharpCode.Decompiler.dll`
完成：读程序集元数据 + 方法体 IL，重建表达式树、推断类型、结构化控制流，输出 C#。
本 CLI 用纯标准库逐函数复刻其**表达式反编译核心**（复用同仓 `dnlib_py` 元数据引擎）：

## 实现范围

- 基于 IL 求值栈的表达式树重建：`ldc.i4/ldc.i8/ldc.r4/ldc.r8`、`ldstr`、`ldnull`、
  `ldarg`/`ldloc`、`ldfld`/`ldsfld`、`call`/`callvirt`/`newobj`、`castclass`/`box`/`unbox`、
  算术与比较（`add/sub/mul/div/rem/and/or/xor/shl/shr/ceq/cgt/clt`/`beq/bne/bge/…`）、
  `conv.*`、`neg`/`not`、`ret`、`br`/`brtrue`/`brfalse`/`switch`、`leave`/`endfinally`。
- 运算符优先级与最小括号输出。
- 记号解析（成员/类型/字符串）复用 `dnlib_py`，并做属性 getter 折叠（`get_X()` → `.X`）。
- 方法签名解析（`this` 指针与参数个数）用于调用展开。

## 诚实说明

完整 `ICSharpCode.Decompiler`（数十万行、完整类型系统、泛型、LINQ、async/await、
控制流结构化、资源与 WinForms 反编译）无法逐行移植。本 CLI 是其**表达式反编译核心**
的忠实子集：对简单方法产出真实可读的 C#；对复杂控制流/泛型方法产出近似结果。

## 用法

```
python main.py <assembly> --list            列出全部方法
python main.py <assembly> --method <name>   反编译某方法为 C#
python main.py <assembly> --il <n>          按 MethodDef 索引(1基)反编译
python main.py <assembly> --all -o out.cs   反编译全部有方法体的方法
```

示例：

```
python main.py ICSharpCode.Decompiler.dll --il 5
python main.py MpressClass.dll --all -o out.cs
```

## 验证

- `ICSharpCode.Decompiler.dll`：`get_c` → `return this.<c>i__Field;`；
  `.ctor` → 字段赋值 + 基类构造调用；`Equals`（无方法体）正确报告。
- 无第三方依赖，纯标准库（导入同仓 `dnlib_py` 引擎）。
