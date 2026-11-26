# Mpress .Net Unpacker — Python CLI 重写

原程序：**Mpress .Net unpacker by COB** (`cob_rce@hotmail.com`, 2012)
- `Mpress.NetUnpacker/Mpress .net unpacker.exe` — WinForms 拖放界面
- `Mpress.NetUnpacker/MpressClass.dll` — 核心解压逻辑 `mpress.Unpack`

本项目把该工具重写为纯 Python 命令行程序，无第三方依赖。

## 功能

MPress 加壳的 .NET 程序集，原始元数据/方法体被 LZMAT 压缩，资源段被剥离。
本工具：

1. 解析 PE，读取 `e_lfanew`，定位 MPress 压缩数据块（偏移 = `u32(e_lfanew+348) + 16`）；
2. 用 **LZMAT** 算法解压，还原原始 .NET 程序集字节；
3. 从壳文件提取被剥离的 **资源段**，按解包后的基址修正资源目录中的 RVA，回填到解包数据；
4. 写出 `<文件名>.unpacked<扩展名>`。

## 用法

```
python main.py <file1> [file2 ...]
```

例：

```
python main.py packed.exe
# 成功 -> packed.unpacked.exe
```

## 算法映射（C# -> Python）

| 原函数 (MpressClass.dll) | Python |
|---|---|
| `Unpack.lzmat(byte[] pOs, byte[] pIs, int cI)` | `lzmat(out, inp, cI)` |
| `Unpack.lz(byte[] c, out byte[] a, int l)` | `lz(c, l)` |
| `Unpack.lf(string fn, out byte[] a)` | `lf(fn)` |
| `Form1.ConvertRVA2OFFSET(int RVA, byte[] PE)` | `convert_rva_to_offset(rva, pe)` |
| `Form1.FixResource(...)` | `fix_resource(...)` |
| `Form1.Form1_DragDrop(...)` | `unpack_one(path)` |

`lzmat` 是 MPress 的 LZMAT 解压（半字节 nibble 状态机 + 回溯复制），按原始
`unsafe` 指针代码逐行移植，保持位级一致。

## 验证

使用仓库内 ILSpy 的 `ICSharpCode.Decompiler.dll` 反编译 `MpressClass.dll` 得到
C# 源码，并编译一个调用原始 `mpress.Unpack.lf/lz/lzmat` 的 C# 参考程序做差分：

- `lzmat` 字面量路径：Python 与 C# 输出**逐字节一致**；
- `lzmat` 匹配路径（距离/长度/复制/nibble 切换）：**逐字节一致**；
- 完整 `lf`（PE 解析 + 解压）：**逐字节一致**；
- `fix_resource`：RVA 偏移改写正确；
- `convert_rva_to_offset`：与原始行为一致（含“最后一个节返回 0”的原版 quirk）；
- CLI 端到端（合成加壳文件）+ 非加壳文件负例：均正确。

> 说明：原始 `ConvertRVA2OFFSET` 的循环 `for i in 1..NumberOfSections-1` 不会
> 命中最后一个节，故落在最后节的 RVA 会返回 0；本移植忠实保留该行为。