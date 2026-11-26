# CLRInjection — Python CLI 逐函数端口

原程序：`CLRInjection/x86/CLR_Injection.exe`、`CLRInjection/x64/CLR_Injection.exe`
（原生 C++ CLR 注入器）

## 逆向方法

使用 x32dbg 加载 `CLR_Injection.exe`，导出导入表并定位注入调用点，确认其核心流程为标准的 **CreateRemoteThread + LoadLibrary** DLL 注入，并带 `SeDebugPrivilege` 提权：

1. `OpenProcessToken` → `LookupPrivilegeValueW("SeDebugPrivilege")` → `AdjustTokenPrivileges`（启用调试特权，允许操作其他用户进程）；
2. `OpenProcess(targetPid, PROCESS_ALL_ACCESS)`（打开目标进程）；
3. `VirtualAllocEx(target, NULL, len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)`（在目标进程申请内存）；
4. `WriteProcessMemory(target, remoteBase, dllPath, len)`（写入 DLL 路径）；
5. `GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryW")`（取 LoadLibraryW 地址）；
6. `CreateRemoteThread(target, NULL, 0, LoadLibraryW, remoteBase, 0, NULL)`（远程线程加载 DLL）；
7. `WaitForSingleObject(thread, INFINITE)`（等待加载完成）；
8. `VirtualFreeEx` / `CloseHandle`（清理）。

本 CLI 用 `ctypes` 逐函数复刻上述 Win32 API 调用，与原程序调用序列一一对应。

## 用法

```
# 启用 SeDebugPrivilege（跨会话/跨用户注入所需）
python main.py enable-priv

# 将 DLL 注入目标进程（自动启用特权，可用 --no-priv 跳过）
python main.py inject <pid> <dll_path>
```

安全说明：注入是跨进程操作，需管理员权限；请仅对你拥有的进程/测试环境使用。

无第三方依赖，纯标准库（ctypes）。