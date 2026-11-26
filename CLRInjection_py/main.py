#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CLRInjection — Python CLI rewrite (逐函数端口)
=============================================

原程序：`CLRInjection/x86/CLR_Injection.exe`（原生 C++ CLR 注入器）
        `CLRInjection/x64/CLR_Injection.exe`

原程序通过 x64dbg 逐函数反汇编，确认其注入流程为标准的
**CreateRemoteThread + LoadLibrary** DLL 注入，并带 `SeDebugPrivilege`
提权：

1. `OpenProcessToken` + `LookupPrivilegeValueW` + `AdjustTokenPrivileges`
   → 启用 SeDebugPrivilege（允许操作其他用户进程）；
2. `OpenProcess(targetPid, PROCESS_ALL_ACCESS)` → 打开目标进程；
3. `VirtualAllocEx(target, NULL, len, MEM_COMMIT|MEM_RESERVE, PAGE_READWRITE)`
   → 在目标进程申请执行/读写内存；
4. `WriteProcessMemory(target, remoteBase, dllPath, len)` → 写入 DLL 路径；
5. `GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryW")`
   → 取 LoadLibraryW 地址；
6. `CreateRemoteThread(target, NULL, 0, LoadLibraryW, remoteBase, 0, NULL)`
   → 远程线程加载 DLL；
7. `WaitForSingleObject(thread, INFINITE)` → 等待加载完成；
8. `VirtualFreeEx` / `CloseHandle` 清理。

本 CLI 以 `ctypes` 忠实复刻上述每个 Win32 API 调用，提供：

```
python main.py inject <pid> <dll_path>          注入 DLL 到目标进程
python main.py enable-priv                      启用 SeDebugPrivilege
python main.py --help
```

安全说明：
- 注入是跨进程操作，需管理员/提权；请仅对你拥有的进程/测试环境使用。
- 默认测试时注入的是系统已载入的 `user32.dll`（无害，LoadLibrary 仅增加引用计数）。

无第三方依赖，纯标准库。
"""

import argparse
import ctypes
import ctypes.wintypes as w
import os
import sys

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)

# ---------------- 常量 ----------------
PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_READWRITE = 0x04
INFINITE = 0xFFFFFFFF
SE_DEBUG_NAME = "SeDebugPrivilege"
TOKEN_ADJUST_PRIVILEGES = 0x0020
TOKEN_QUERY = 0x0008
SE_PRIVILEGE_ENABLED = 0x00000002


class LUID(ctypes.Structure):
    _fields_ = [("LowPart", w.DWORD), ("HighPart", w.LONG)]


class LUID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [("Luid", LUID), ("Attributes", w.DWORD)]


class TOKEN_PRIVILEGES(ctypes.Structure):
    _fields_ = [("PrivilegeCount", w.DWORD),
                ("Privileges", LUID_AND_ATTRIBUTES * 1)]


# ---------------- 原函数等价实现 ----------------

def enable_debug_privilege():
    """
    对应原程序：OpenProcessToken(GetCurrentProcess) ->
               LookupPrivilegeValueW(NULL, "SeDebugPrivilege", &luid) ->
               AdjustTokenPrivileges(token, FALSE, &tp, 0, NULL, NULL)
    启用 SeDebugPrivilege，使注入跨会话/跨用户进程成为可能。
    """
    h_token = w.HANDLE()
    if not advapi32.OpenProcessToken(
            kernel32.GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            ctypes.byref(h_token)):
        raise ctypes.WinError(ctypes.get_last_error())

    luid = LUID()
    if not advapi32.LookupPrivilegeValueW(None, SE_DEBUG_NAME, ctypes.byref(luid)):
        kernel32.CloseHandle(h_token)
        raise ctypes.WinError(ctypes.get_last_error())

    tp = TOKEN_PRIVILEGES()
    tp.PrivilegeCount = 1
    tp.Privileges[0].Luid = luid
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED

    if not advapi32.AdjustTokenPrivileges(
            h_token, False, ctypes.byref(tp), ctypes.sizeof(tp), None, None):
        kernel32.CloseHandle(h_token)
        raise ctypes.WinError(ctypes.get_last_error())

    kernel32.CloseHandle(h_token)
    return True


def inject_dll(pid, dll_path):
    """
    对应原程序注入主流程（CreateRemoteThread + LoadLibrary）。
    逐函数映射：
      OpenProcess -> VirtualAllocEx -> WriteProcessMemory ->
      GetProcAddress(LoadLibraryW) -> CreateRemoteThread -> WaitForSingleObject
    """
    dll_path = os.path.abspath(dll_path)
    if not os.path.isfile(dll_path):
        print("Error: DLL not found: %s" % dll_path, file=sys.stderr)
        return 1

    # 1. OpenProcess(targetPid, PROCESS_ALL_ACCESS)
    h_proc = kernel32.OpenProcess(PROCESS_ALL_ACCESS, False, pid)
    if not h_proc:
        print("Error: OpenProcess(%d) failed: %s" % (pid, ctypes.WinError(ctypes.get_last_error())), file=sys.stderr)
        return 1
    print("[Info] Opened target process PID=%d" % pid)

    try:
        # 2. VirtualAllocEx
        path_bytes = (dll_path + "\x00").encode("utf-16-le")
        buf_len = len(path_bytes)
        remote = kernel32.VirtualAllocEx(h_proc, None, buf_len,
                                         MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
        if not remote:
            print("Error: VirtualAllocEx failed: %s" % ctypes.WinError(ctypes.get_last_error()), file=sys.stderr)
            return 1
        print("[Info] Allocated %d bytes at 0x%08X in target" % (buf_len, remote))

        # 3. WriteProcessMemory
        written = w.SIZE_T(0)
        if not kernel32.WriteProcessMemory(h_proc, remote, path_bytes, buf_len, ctypes.byref(written)):
            print("Error: WriteProcessMemory failed: %s" % ctypes.WinError(ctypes.get_last_error()), file=sys.stderr)
            return 1
        print("[Info] Wrote DLL path (%d bytes)" % written.value)

        # 4. GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryW")
        h_kernel32 = kernel32.GetModuleHandleW("kernel32.dll")
        if not h_kernel32:
            print("Error: GetModuleHandle(kernel32) failed: %s" % ctypes.WinError(ctypes.get_last_error()), file=sys.stderr)
            return 1
        load_lib = kernel32.GetProcAddress(h_kernel32, "LoadLibraryW")
        if not load_lib:
            print("Error: GetProcAddress(LoadLibraryW) failed: %s" % ctypes.WinError(ctypes.get_last_error()), file=sys.stderr)
            return 1
        print("[Info] LoadLibraryW at 0x%08X" % load_lib)

        # 5. CreateRemoteThread(target, NULL, 0, LoadLibraryW, remote, 0, NULL)
        h_thread = kernel32.CreateRemoteThread(h_proc, None, 0, load_lib, remote, 0, None)
        if not h_thread:
            print("Error: CreateRemoteThread failed: %s" % ctypes.WinError(ctypes.get_last_error()), file=sys.stderr)
            return 1
        print("[Info] Created remote thread (LoadLibraryW)")

        # 6. WaitForSingleObject(thread, INFINITE)
        rc = kernel32.WaitForSingleObject(h_thread, INFINITE)
        print("[Info] Remote thread finished (rc=%d)" % rc)
        kernel32.CloseHandle(h_thread)
    finally:
        kernel32.CloseHandle(h_proc)

    print("[Success] DLL injected: %s -> PID %d" % (dll_path, pid))
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="CLR_Injection",
        description="CLRInjection — Python CLI rewrite (CreateRemoteThread + LoadLibrary 注入，逐函数端口).")
    sub = parser.add_subparsers(dest="cmd")

    p_inj = sub.add_parser("inject", help="将 DLL 注入目标进程")
    p_inj.add_argument("pid", type=int, help="目标进程 PID")
    p_inj.add_argument("dll", help="要注入的 DLL 路径")
    p_inj.add_argument("--no-priv", action="store_true",
                       help="不启用 SeDebugPrivilege（已有权限时可用）")

    p_priv = sub.add_parser("enable-priv", help="启用 SeDebugPrivilege")

    args = parser.parse_args(argv)

    if args.cmd == "inject":
        if not args.no_priv:
            try:
                enable_debug_privilege()
                print("[Info] SeDebugPrivilege enabled")
            except Exception as e:
                print("Warning: enable privilege failed: %s (continuing anyway)" % e, file=sys.stderr)
        return inject_dll(args.pid, args.dll)
    if args.cmd == "enable-priv":
        try:
            enable_debug_privilege()
            print("[Success] SeDebugPrivilege enabled")
            return 0
        except Exception as e:
            print("Error: %s" % e, file=sys.stderr)
            return 1
    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())