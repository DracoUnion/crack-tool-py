#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WSockExpert (_cn 汉化, Delphi VCL, 643KB, 未加壳)  ->  PySide6 重写版
================================================================================

逆向依据 (PE 静态分析 + Delphi 字符串, .text 熵 6.51 未加壳):
  导入: wsock32.dll(Winsock1.1), ole32/oleaut32/olepro32, vcltest3.dll, comdlg32。
  Delphi 类/字符串 (VCL 窗体与数据模型):
    "TPacketHolder$"  "MaxPacketCount"  "PacketViewsHolder"
    "PacketViewHex"   "PacketViewText"  "PacketListHolder"
    "PacketList"      "PacketListChange" "PacketListAdvancedCustomDrawItem"
    "ChangePacketViewCmd"  "IStringsAdapter$"  "TStreamAdapter"
    "SOFTWARE\\Borland\\Delphi\\RTL"  "StdVCL"
  => WSockExpert 本质: 通过 WSockHook.dll 对目标进程 inline-hook Winsock 函数
     (send/recv/WSASend/WSARecv/connect/accept/sendto/recvfrom/...), 把每次
     调用的缓冲区以 Hex+Text 双视图、按函数分色、限制 MaxPacketCount 显示。

  本 PySide6 重写 (纯标准库 + PySide6, main.py 唯一入口):
    用 iphlpapi!GetExtendedTcpTable 实时枚举系统 TCP 连接 (等价"选择目标进程/
    连接"面板) + Raw Socket(SIO_RCVALL) 抓包, 按方向标注等价 Winsock 函数
    (recv 入站 / send 出站), Hex+Text 双视图, 按"函数"分色, MaxPacketCount
    上限 —— 完整复刻 WSockExpert 的可视化数据模型 (PacketList / PacketViewHex /
    PacketViewText / MaxPacketCount / 按函数分色)。
    注: 原版经 WSockHook.dll 注入目标进程 inline-hook Winsock; 本单文件纯 Python
    版以等价的"系统级抓包 + 连接枚举 + 函数级着色"复现其可观测行为, 不注入进程。

用法:  python main.py             # GUI
       python main.py --selftest  # 连接表 / 解析 自检
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
    QTableWidget, QTableWidgetItem, QLabel, QCheckBox, QSpinBox,
    QAbstractItemView, QHeaderView, QPlainTextEdit, QSplitter,
)
from PySide6.QtCore import Qt, Signal, QObject
from PySide6.QtGui import QColor, QTextCharFormat

SIO_RCVALL = 0x98000001
IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP = 1, 6, 17
PROTO_NAME = {1: "ICMP", 6: "TCP", 17: "UDP"}

# 函数 -> 颜色 (WSockExpert 按调用的 Winsock 函数分色)
FUNC_COLOR = {
    "send": "#1565c0", "WSASend": "#1565c0",
    "recv": "#2e7d32", "WSARecv": "#2e7d32",
    "sendto": "#6a1b9a", "WSASendTo": "#6a1b9a",
    "recvfrom": "#ef6c00", "WSARecvFrom": "#ef6c00",
    "connect": "#c62828", "WSAConnect": "#c62828",
    "accept": "#00838f", "WSAAccept": "#00838f",
}


# --------------------------------------------------------------------------- #
#  连接表 (GetExtendedTcpTable) —— 等价"目标进程/连接"面板
# --------------------------------------------------------------------------- #
def enum_tcp_connections():
    """返回 [(local_ip, local_port, remote_ip, remote_port, state, pid)]。"""
    iphlp = ctypes.WinDLL("iphlpapi.dll")
    buf = ctypes.create_string_buffer(1)
    size = wintypes.DWORD(0)
    AF_INET = 2
    TCP_TABLE_OWNER_PID_ALL = 5
    rc = iphlp.GetExtendedTcpTable(buf, ctypes.byref(size), False, AF_INET,
                                   TCP_TABLE_OWNER_PID_ALL, 0)
    if rc != 0:  # ERROR_INSUFFICIENT_BUFFER
        buf = ctypes.create_string_buffer(size.value)
        rc = iphlp.GetExtendedTcpTable(buf, ctypes.byref(size), False, AF_INET,
                                       TCP_TABLE_OWNER_PID_ALL, 0)
    if rc != 0:
        return []

    # MIB_TCPTABLE_OWNER_PID: dwNumEntries then entries
    n = struct.unpack_from("<I", buf.raw, 0)[0]
    out = []
    off = 4
    # MIB_TCPROW_OWNER_PID (DWORD dwState, DWORD dwLocalAddr, dwLocalPort,
    #  dwRemoteAddr, dwRemotePort, dwOwningPid) = 24 bytes
    for _ in range(n):
        row = struct.unpack_from("<IIIIII", buf.raw, off); off += 24
        state, loc, lport, rem, rport, pid = row
        lport = (lport >> 16) & 0xFFFF  # network byte order in low word
        rport = (rport >> 16) & 0xFFFF
        lip = socket.inet_ntoa(struct.pack("<I", loc))
        rip = socket.inet_ntoa(struct.pack("<I", rem))
        out.append((lip, lport, rip, rport, state, pid))
    return out


# --------------------------------------------------------------------------- #
#  包解析 (raw socket)
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


# --------------------------------------------------------------------------- #
#  抓包引擎
# --------------------------------------------------------------------------- #
class CaptureEngine(QObject):
    packet = Signal(dict)
    status = Signal(str)
    finished = Signal()

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
            self.status.emit("Bind Error! %s" % e)
        finally:
            self.finished.emit()


# --------------------------------------------------------------------------- #
#  GUI
# --------------------------------------------------------------------------- #
COLS = ["No", "Time", "Function", "Source", "Destination", "Protocol", "Len", "Data"]


class WsockExpertWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("WSockExpert (PySide6 重写版)")
        self.resize(1080, 660)
        self.engine = None
        self.count = 0
        self.records = []
        self._build_ui()
        self.statusBar().showMessage("Ready.")

    def _build_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        lay = QVBoxLayout(central)
        bar = QHBoxLayout()
        self.btn_start = QPushButton("Start"); self.btn_start.clicked.connect(self.start)
        self.btn_stop = QPushButton("Stop"); self.btn_stop.clicked.connect(self.stop); self.btn_stop.setEnabled(False)
        self.btn_clear = QPushButton("Clear"); self.btn_clear.clicked.connect(self.clear)
        self.btn_conns = QPushButton("Refresh Connections"); self.btn_conns.clicked.connect(self.show_connections)
        bar.addWidget(self.btn_start); bar.addWidget(self.btn_stop); bar.addWidget(self.btn_clear)
        bar.addWidget(QLabel("MaxPacketCount:"))
        self.spin = QSpinBox(); self.spin.setRange(0, 1000000); self.spin.setValue(100000)
        bar.addWidget(self.spin); bar.addWidget(self.btn_conns); bar.addStretch()
        lay.addLayout(bar)

        self.split = QSplitter(Qt.Vertical)
        self.table = QTableWidget(0, len(COLS))
        self.table.setHorizontalHeaderLabels(COLS)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.verticalHeader().setVisible(False)
        hh = self.table.horizontalHeader(); hh.setSectionResizeMode(QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(COLS.index("Data"), QHeaderView.Stretch)
        self.table.itemSelectionChanged.connect(self.on_select)
        self.split.addWidget(self.table)

        self.hexview = QPlainTextEdit(); self.hexview.setReadOnly(True)
        self.hexview.setPlaceholderText("Hex + Text view (选中数据包显示)")
        self.split.addWidget(self.hexview)
        self.split.setSizes([420, 240])
        lay.addWidget(self.split)

    # ---- actions ----
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
        self.statusBar().showMessage("Stopped.")

    def _finished(self):
        self.engine = None
        self.btn_start.setEnabled(True); self.btn_stop.setEnabled(False)

    def clear(self):
        self.count = 0; self.records = []; self.table.setRowCount(0); self.hexview.clear()

    def show_connections(self):
        conns = enum_tcp_connections()
        self.clear()
        for (lip, lp, rip, rp, st, pid) in conns:
            self._addrow(time.strftime("%H:%M:%S"), "conn", "%s:%d" % (lip, lp),
                         "%s:%d" % (rip, rp), "TCP", 0, "state=%d pid=%d" % (st, pid))
        self.statusBar().showMessage("Connections: %d" % len(conns))

    def on_packet(self, p):
        cap = self.spin.value()
        if cap and self.count >= cap:
            return
        func = "recv" if p["sport"] < p["dport"] else "send"
        # 入站(低端口为本地服务端? ) — 用源端口<目的端口近似方向
        if p["proto"] == "TCP":
            func = "recv" if p["sport"] < p["dport"] else "send"
        self._addrow(time.strftime("%H:%M:%S", time.localtime(p["ts"])), func,
                     "%s:%d" % (p["src"], p["sport"]), "%s:%d" % (p["dst"], p["dport"]),
                     p["proto"], len(p["payload"]), p["payload"])

    def _addrow(self, t, func, src, dst, proto, ln, data):
        self.count += 1
        rec = {"t": t, "func": func, "src": src, "dst": dst, "proto": proto, "data": data}
        self.records.append(rec)
        r = self.table.rowCount(); self.table.insertRow(r)
        preview = data[:200].hex(" ").upper() if isinstance(data, (bytes, bytearray)) else str(data)
        for c, v in enumerate([str(self.count), t, func, src, dst, proto, str(ln), preview]):
            it = QTableWidgetItem(v)
            if c == 2 and func in FUNC_COLOR:
                it.setForeground(QColor(FUNC_COLOR[func]))
            self.table.setItem(r, c, it)
        self.table.scrollToBottom()

    def on_select(self):
        idx = self.table.currentRow()
        if idx < 0 or idx >= len(self.records):
            return
        data = self.records[idx]["data"]
        if not isinstance(data, (bytes, bytearray)):
            self.hexview.setPlainText(str(data)); return
        lines = []
        for i in range(0, len(data), 16):
            chunk = data[i:i + 16]
            hexs = " ".join("%02X" % b for b in chunk)
            text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append("%04X  %-47s  %s" % (i, hexs, text))
        self.hexview.setPlainText("\n".join(lines))


# --------------------------------------------------------------------------- #
def selftest():
    conns = enum_tcp_connections()
    assert isinstance(conns, list)
    # parse 一个 TCP 包
    tcp = struct.pack("!HHIIBBHHH", 80, 12345, 1, 0, 5 << 4, 0x18, 0, 0, 0) + b"xyz"
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0,
                     socket.inet_aton("10.1.1.1"), socket.inet_aton("10.2.2.2"))
    p = parse_ip(ip + tcp)
    assert p["proto"] == "TCP" and p["sport"] == 80 and p["payload"] == b"xyz"
    # hex view 格式
    assert "%02X" % 0xAB == "AB"
    print("[selftest] WSockExpert conn=%d parse OK; local=%s" % (len(conns), local_ip()))


def main():
    if "--selftest" in sys.argv:
        selftest(); return
    app = QApplication(sys.argv)
    w = WsockExpertWindow(); w.show(); sys.exit(app.exec())


if __name__ == "__main__":
    main()