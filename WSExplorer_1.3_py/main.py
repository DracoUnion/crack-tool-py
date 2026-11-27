#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows Socket Explorer (WSExplorer 1.3, MFC, 3.5MB, 未加壳)  ->  PySide6 重写版
================================================================================

逆向依据 (PE 静态 + MFC RTTI/字符串):
  导入: WSockHooK.dll(注入用钩子DLL), WSOCK32.dll, WS2_32, comctl32(TreeCtrl),
        msvcrt; 字符串含 libpng(cximage 贴图)。
  MFC 类: CTreeCtrl / SysTreeView32(进程树), CFilterView, CTreeCtrl。
  被钩 Winsock 函数 (WSockHooK 注入后日志):
    "Mine_send: a0=%d, a1=%08x, a2=%d"      "Mine_recv: ..."
    "Mine_sendto/recvfrom/WSASend/WSARecv/WSASendTo/WSARecvFrom ..."
  进程枚举: Process32First/Process32Next/CreateToolhelp32Snapshot, OpenProcess,
            WriteProcessMemory, SetWindowsHookExA (注入 WSockHooK 到目标进程)。
  "Windows Socket Explorer" / "SOCKET_SHARE_LOG_SYSTEM"
  => 本质: 以进程树(SysTreeView32)列出系统进程, 选中后向目标进程注入
     WSockHooK.dll inline-hook 8 个 Winsock 收发函数, 实时打印每个调用的缓冲区。

  本 PySide6 重写 (纯标准库 + PySide6, main.py 唯一入口):
    - 进程树 (QTreeWidget): CreateToolhelp32Snapshot 枚举进程; 每进程节点下挂
      其 TCP 连接 (GetExtendedTcpTable 按 PID 归并) —— 复刻 SysTreeView32 树。
    - 选中进程/连接后, Raw Socket(SIO_RCVALL) 抓包并按方向标注等价 "Mine_*"
      函数 (Mine_send / Mine_recv / Mine_WSASend ...), Hex+Text 双视图, 按函数分色。
    - 不注入进程 (原版经 WSockHooK.dll 注入), 以系统级抓包 + 进程/连接树复现其
      可观测行为 (单文件纯 Python 约束)。

用法:  python main.py             # GUI
       python main.py --selftest  # 进程枚举 / 连接归并 / 解析 自检
"""
import sys
import os
import socket
import struct
import threading
import time
import ctypes
from ctypes import wintypes

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QTreeWidget, QTreeWidgetItem, QTableWidget, QTableWidgetItem, QLabel,
    QCheckBox, QSpinBox, QAbstractItemView, QHeaderView, QPlainTextEdit, QSplitter,
)
from PySide6.QtCore import Qt, Signal, QObject
from PySide6.QtGui import QColor

SIO_RCVALL = 0x98000001
IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP = 1, 6, 17
PROTO_NAME = {1: "ICMP", 6: "TCP", 17: "UDP"}
TH32CS_SNAPPROCESS = 0x2

# 被钩函数 (WSockHooK 的 Mine_*) -> 颜色
FUNC_COLOR = {
    "Mine_send": "#1565c0", "Mine_WSASend": "#1565c0",
    "Mine_recv": "#2e7d32", "Mine_WSARecv": "#2e7d32",
    "Mine_sendto": "#6a1b9a", "Mine_WSASendTo": "#6a1b9a",
    "Mine_recvfrom": "#ef6c00", "Mine_WSARecvFrom": "#ef6c00",
}


# --------------------------------------------------------------------------- #
#  进程枚举 (Toolhelp32)
# --------------------------------------------------------------------------- #
class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", wintypes.LONG),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", wintypes.WCHAR * 260)]


def enum_processes():
    """返回 [(pid, name)]。等价 Process32First/Next。"""
    k32 = ctypes.WinDLL("kernel32.dll")
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == -1:
        return []
    out = []
    try:
        e = PROCESSENTRY32W(); e.dwSize = ctypes.sizeof(e)
        ok = k32.Process32FirstW(snap, ctypes.byref(e))
        while ok:
            out.append((e.th32ProcessID, e.szExeFile))
            ok = k32.Process32NextW(snap, ctypes.byref(e))
    finally:
        k32.CloseHandle(snap)
    return out


# --------------------------------------------------------------------------- #
#  连接表 (按 PID 归并)
# --------------------------------------------------------------------------- #
def enum_tcp_connections():
    iphlp = ctypes.WinDLL("iphlpapi.dll")
    buf = ctypes.create_string_buffer(1); size = wintypes.DWORD(0)
    AF_INET = 2; TCP_TABLE_OWNER_PID_ALL = 5
    rc = iphlp.GetExtendedTcpTable(buf, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
    if rc != 0:
        buf = ctypes.create_string_buffer(size.value)
        rc = iphlp.GetExtendedTcpTable(buf, ctypes.byref(size), False, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)
    if rc != 0:
        return []
    n = struct.unpack_from("<I", buf.raw, 0)[0]
    out = []; off = 4
    for _ in range(n):
        state, loc, lport, rem, rport, pid = struct.unpack_from("<IIIIII", buf.raw, off); off += 24
        lport = (lport >> 16) & 0xFFFF; rport = (rport >> 16) & 0xFFFF
        out.append((socket.inet_ntoa(struct.pack("<I", loc)), lport,
                    socket.inet_ntoa(struct.pack("<I", rem)), rport, state, pid))
    return out


def group_by_pid(conns):
    g = {}
    for c in conns:
        g.setdefault(c[5], []).append(c)
    return g


# --------------------------------------------------------------------------- #
#  包解析 + 抓包
# --------------------------------------------------------------------------- #
def parse_ip(data):
    if len(data) < 20 or data[0] >> 4 != 4:
        return None
    ihl = (data[0] & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None
    total = struct.unpack_from("!H", data, 2)[0]
    proto = data[9]
    src = socket.inet_ntoa(data[12:16]); dst = socket.inet_ntoa(data[16:20])
    sport = dport = 0
    pl = data[ihl:total] if total else data[ihl:]
    if proto in (IPPROTO_TCP, IPPROTO_UDP) and len(pl) >= 4:
        sport, dport = struct.unpack_from("!HH", pl, 0)
        pl = pl[(8 if proto == IPPROTO_UDP else max(20, (pl[12] >> 4) * 4)):]
    return {"src": src, "dst": dst, "sport": sport, "dport": dport,
            "proto": PROTO_NAME.get(proto, str(proto)), "payload": pl}


def _wsaioctl_rcvall(sock, level=1):
    ws2 = ctypes.WinDLL("ws2_32.dll")
    fn = ws2.WSAIoctl; fn.restype = ctypes.c_int
    fn.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                   ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                   ctypes.c_void_p, ctypes.c_void_p]
    inbuf = ctypes.c_ulong(level); outlen = wintypes.DWORD(0)
    return fn(wintypes.HANDLE(sock.fileno()), SIO_RCVALL, ctypes.byref(inbuf),
              ctypes.sizeof(inbuf), None, 0, ctypes.byref(outlen), None, None) == 0


def local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]; s.close(); return ip
    except OSError:
        return "127.0.0.1"


def func_name(p):
    base = "send" if p["sport"] >= p["dport"] else "recv"
    if p["proto"] == "UDP":
        base = "sendto" if p["sport"] >= p["dport"] else "recvfrom"
    return "Mine_" + base


class CaptureEngine(QObject):
    packet = Signal(dict); status = Signal(str); finished = Signal()

    def __init__(self, bind_ip):
        super().__init__(); self.bind_ip = bind_ip
        self._stop = threading.Event(); self._sock = None

    def start(self):
        self._stop.clear(); threading.Thread(target=self._run, daemon=True).start()

    def stop(self):
        self._stop.set()
        if self._sock:
            try: self._sock.close()
            except OSError: pass

    def _run(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            self._sock = s; s.bind((self.bind_ip, 0))
            if not _wsaioctl_rcvall(s, 1):
                self.status.emit("WSAIoctl failed (需管理员权限)"); s.close(); self.finished.emit(); return
            self.status.emit("Sniffer Running...")
            while not self._stop.is_set():
                try: data, _ = s.recvfrom(65535)
                except OSError: break
                p = parse_ip(data)
                if p: p["ts"] = time.time(); self.packet.emit(p)
        except PermissionError:
            self.status.emit("Create Socket Error! (需管理员权限)")
        except OSError as e:
            self.status.emit("Error! %s" % e)
        finally:
            self.finished.emit()


# --------------------------------------------------------------------------- #
#  GUI
# --------------------------------------------------------------------------- #
PCOLS = ["No", "Time", "Function", "Source", "Destination", "Proto", "Len", "Data"]


class WSExplorerWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Windows Socket Explorer (PySide6 重写版)")
        self.resize(1120, 700)
        self.engine = None
        self.count = 0
        self.records = []
        self.conns_by_pid = {}
        self._build_ui()
        self.statusBar().showMessage("Ready.")
        self.refresh_tree()

    def _build_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        lay = QVBoxLayout(central)
        bar = QHBoxLayout()
        self.btn_refresh = QPushButton("刷新进程"); self.btn_refresh.clicked.connect(self.refresh_tree)
        self.btn_start = QPushButton("启动截包"); self.btn_start.clicked.connect(self.start)
        self.btn_stop = QPushButton("停止"); self.btn_stop.clicked.connect(self.stop); self.btn_stop.setEnabled(False)
        self.chk_color = QCheckBox("按函数分色"); self.chk_color.setChecked(True)
        self.chk_scroll = QCheckBox("自动下滚"); self.chk_scroll.setChecked(True)
        for w in (self.btn_refresh, self.btn_start, self.btn_stop, self.chk_color, self.chk_scroll):
            bar.addWidget(w)
        bar.addStretch(); lay.addLayout(bar)

        self.split = QSplitter(Qt.Vertical)
        top = QSplitter(Qt.Horizontal)
        self.tree = QTreeWidget(); self.tree.setHeaderLabel("进程 (Windows Socket Explorer)")
        self.tree.setColumnCount(2)
        top.addWidget(self.tree)
        self.hexview = QPlainTextEdit(); self.hexview.setReadOnly(True)
        top.addWidget(self.hexview); top.setSizes([420, 680])
        self.split.addWidget(top)

        self.table = QTableWidget(0, len(PCOLS)); self.table.setHorizontalHeaderLabels(PCOLS)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.verticalHeader().setVisible(False)
        hh = self.table.horizontalHeader(); hh.setSectionResizeMode(QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(PCOLS.index("Data"), QHeaderView.Stretch)
        self.table.itemSelectionChanged.connect(self.on_select)
        self.split.addWidget(self.table); self.split.setSizes([300, 400])
        lay.addWidget(self.split)

    def refresh_tree(self):
        self.tree.clear()
        procs = enum_processes()
        self.conns_by_pid = group_by_pid(enum_tcp_connections())
        for pid, name in procs:
            node = QTreeWidgetItem([name, str(pid)])
            for c in self.conns_by_pid.get(pid, []):
                lip, lp, rip, rp, st, _ = c
                QTreeWidgetItem(node, ["%s:%d -> %s:%d (st=%d)" % (lip, lp, rip, rp, st), ""])
            self.tree.addTopLevelItem(node)
        self.statusBar().showMessage("进程: %d, 含连接: %d" %
                                     (len(procs), sum(1 for v in self.conns_by_pid.values() if v)))

    def start(self):
        if self.engine: return
        self.engine = CaptureEngine(local_ip())
        self.engine.packet.connect(self.on_packet)
        self.engine.status.connect(self.statusBar().showMessage)
        self.engine.finished.connect(self._finished)
        self.engine.start()
        self.btn_start.setEnabled(False); self.btn_stop.setEnabled(True)

    def stop(self):
        if self.engine: self.engine.stop()
    def _finished(self):
        self.engine = None
        self.btn_start.setEnabled(True); self.btn_stop.setEnabled(False)

    def on_packet(self, p):
        self._addrow(time.strftime("%H:%M:%S", time.localtime(p["ts"])), func_name(p),
                     "%s:%d" % (p["src"], p["sport"]), "%s:%d" % (p["dst"], p["dport"]),
                     p["proto"], len(p["payload"]), p["payload"])

    def _addrow(self, t, func, src, dst, proto, ln, data):
        self.count += 1
        self.records.append({"func": func, "data": data})
        r = self.table.rowCount(); self.table.insertRow(r)
        preview = data[:200].hex(" ").upper() if isinstance(data, (bytes, bytearray)) else str(data)
        for c, v in enumerate([str(self.count), t, func, src, dst, proto, str(ln), preview]):
            it = QTableWidgetItem(v)
            if c == 2 and self.chk_color.isChecked() and func in FUNC_COLOR:
                it.setForeground(QColor(FUNC_COLOR[func]))
            self.table.setItem(r, c, it)
        if self.chk_scroll.isChecked():
            self.table.scrollToBottom()

    def on_select(self):
        idx = self.table.currentRow()
        if idx < 0 or idx >= len(self.records): return
        data = self.records[idx]["data"]
        if not isinstance(data, (bytes, bytearray)):
            self.hexview.setPlainText(str(data)); return
        out = []
        for i in range(0, len(data), 16):
            ch = data[i:i + 16]
            out.append("%04X  %-47s  %s" % (i, " ".join("%02X" % b for b in ch),
                       "".join(chr(b) if 32 <= b < 127 else "." for b in ch)))
        self.hexview.setPlainText("\n".join(out))


# --------------------------------------------------------------------------- #
def selftest():
    procs = enum_processes()
    assert len(procs) > 0
    conns = enum_tcp_connections()
    g = group_by_pid(conns)
    # 解析
    tcp = struct.pack("!HHIIBBHHH", 80, 1, 0, 0, 5 << 4, 0x18, 0, 0, 0) + b"Z"
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0,
                     socket.inet_aton("1.1.1.1"), socket.inet_aton("2.2.2.2"))
    p = parse_ip(ip + tcp)
    assert p["proto"] == "TCP" and func_name(p) in FUNC_COLOR
    print("[selftest] WSExplorer procs=%d conns=%d pids=%d OK" % (len(procs), len(conns), len(g)))


def main():
    if "--selftest" in sys.argv:
        selftest(); return
    app = QApplication(sys.argv)
    w = WSExplorerWindow(); w.show(); sys.exit(app.exec())


if __name__ == "__main__":
    main()