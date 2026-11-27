#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Microsoft Network Monitor 3.4 (NM34)  ->  PySide6 重写版
================================================================================

逆向依据 (PE 静态分析):
  目录主程序 NM34_x64.exe / NM34_x86.exe 是 Microsoft 安装引导程序 (导入
  advpack/setupx/setupapi/msvcrt, 资源串 "This will install Microsoft Network
  Monitor Capture and Parser engine followed by the ... Parsers. Do you wish to
  continue?"), 真正的 nm.exe 抓包引擎 + NetworkMonitor_Parsers MSI 在其内部。
  Microsoft Network Monitor 3.4 核心行为 (公开):
    - 选择网卡捕获"帧"(Frame), 列表列: Frame#/Time/源/目的/协议/说明;
    - 帧详情按协议分层解码 (Ethernet → IPv4/IPv6 → TCP/UDP/ICMP → 应用层);
    - 显示过滤器 (NPL 风格, 如 tcp / http / ip.addr==x.x.x.x);
    - 协议分布统计。

  本 PySide6 重写 (纯标准库 + PySide6, main.py 唯一入口):
    - Raw Socket(SIO_RCVALL) 捕获 IP 帧; 逐帧分层解码 (IPv4/TCP/UDP/ICMP,
      TCP 载荷识别 HTTP/DNS 等) 生成 Frame 列表 (编号/时间/源/目的/协议/说明);
    - 帧详情 = 可展开协议树 (逐层字段), 等价 NetMon 的 frame detail 解码;
    - 显示过滤器 (tcp/udp/http/dns/icmp/ip.addr==A 等), 协议分布统计;
    - 适配器选择 (本机 IPv4), 启动/停止/清除。

用法:  python main.py             # GUI
       python main.py --selftest  # 解码 / 过滤 自检
"""
import sys
import os
import socket
import struct
import threading
import time
import ctypes
from ctypes import wintypes
from collections import defaultdict

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QTreeWidget, QTreeWidgetItem, QTableWidget, QTableWidgetItem, QLabel,
    QLineEdit, QComboBox, QAbstractItemView, QHeaderView, QSplitter,
)
from PySide6.QtCore import Qt, Signal, QObject
from PySide6.QtGui import QColor

SIO_RCVALL = 0x98000001
IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP = 1, 6, 17
PROTO_NAME = {1: "ICMP", 6: "TCP", 17: "UDP"}


# --------------------------------------------------------------------------- #
#  分层解码
# --------------------------------------------------------------------------- #
def decode_dns(payload):
    """极简 DNS 名解析 (仅用于说明), 失败返回空串。"""
    try:
        tid, flags, qd, an, ns, ar = struct.unpack_from("!HHHHHH", payload, 0)
        if qd < 1:
            return ""
        off = 12; labels = []
        while off < len(payload) and payload[off] != 0:
            ln = payload[off]; off += 1
            labels.append(payload[off:off + ln].decode("latin1", "replace")); off += ln
        return ".".join(labels)
    except Exception:
        return ""


def decode_frame(data):
    """返回 (proto, summary, layers) ; layers = [(name, [(field, value), ...]), ...]。"""
    if len(data) < 20 or data[0] >> 4 != 4:
        return None
    ihl = (data[0] & 0x0F) * 4
    total = struct.unpack_from("!H", data, 2)[0]
    proto = data[9]
    src = socket.inet_ntoa(data[12:16]); dst = socket.inet_ntoa(data[16:20])
    ttl = data[8]
    layers = [("IPv4", [("Version", "4"), ("IHL", "%d*4=%d" % (ihl // 4, ihl)),
                        ("Total Length", str(total)), ("TTL", str(ttl)),
                        ("Protocol", PROTO_NAME.get(proto, str(proto))),
                        ("Source", src), ("Destination", dst)])]
    pl = data[ihl:total] if total else data[ihl:]
    proto_label = PROTO_NAME.get(proto, "IP-%d" % proto)
    summary = "%s %s -> %s" % (proto_label, src, dst)

    if proto == IPPROTO_TCP and len(pl) >= 20:
        sp, dp, seq, ack = struct.unpack_from("!HHII", pl, 0)
        doff = (pl[12] >> 4) * 4; flags = pl[13]
        payload = pl[doff:]
        layers.append(("TCP", [("Src Port", str(sp)), ("Dst Port", str(dp)),
                               ("Seq", str(seq)), ("Ack", str(ack)),
                               ("Flags", "0x%02X" % flags)]))
        summary = "TCP %s:%d -> %s:%d" % (src, sp, dst, dp)
        proto_label = "TCP"
        if payload:
            app = detect_app(payload)
            if app:
                proto_label = app
                summary = "%s %s:%d -> %s:%d" % (app, src, sp, dst, dp)
                layers.append((app, [("Payload", payload[:120].decode("latin1", "replace"))]))
    elif proto == IPPROTO_UDP and len(pl) >= 8:
        sp, dp, ln = struct.unpack_from("!HHH", pl, 0)
        payload = pl[8:]
        layers.append(("UDP", [("Src Port", str(sp)), ("Dst Port", str(dp)), ("Length", str(ln))]))
        summary = "UDP %s:%d -> %s:%d" % (src, sp, dst, dp)
        proto_label = "UDP"
        if sp == 53 or dp == 53:
            name = decode_dns(payload)
            proto_label = "DNS"
            summary = "DNS %s -> %s %s" % (src, dst, name)
            layers.append(("DNS", [("Query", name)]))
    elif proto == IPPROTO_ICMP and len(pl) >= 4:
        t, code = pl[0], pl[1]
        layers.append(("ICMP", [("Type", str(t)), ("Code", str(code))]))
        summary = "ICMP %s -> %s type=%d" % (src, dst, t)
    return proto_label, summary, layers


def detect_app(payload):
    if payload[:4] in (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"OPTI"):
        return "HTTP"
    if payload[:5] == b"HTTP/":
        return "HTTP"
    return ""


# --------------------------------------------------------------------------- #
#  抓包
# --------------------------------------------------------------------------- #
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


class CaptureEngine(QObject):
    frame = Signal(dict); status = Signal(str); finished = Signal()

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
            self.status.emit("Capturing on %s..." % self.bind_ip)
            while not self._stop.is_set():
                try: data, _ = s.recvfrom(65535)
                except OSError: break
                d = decode_frame(data)
                if d:
                    self.frame.emit({"ts": time.time(), "proto": d[0],
                                     "summary": d[1], "layers": d[2]})
        except PermissionError:
            self.status.emit("Create Socket Error! (需管理员权限)")
        except OSError as e:
            self.status.emit("Bind Error! %s" % e)
        finally:
            self.finished.emit()


# --------------------------------------------------------------------------- #
#  过滤器 (NPL 风格子集)
# --------------------------------------------------------------------------- #
def match_filter(proto, summary, expr):
    expr = expr.strip().lower()
    if not expr:
        return True
    # ip.addr==x
    if expr.startswith("ip.addr=="):
        want = expr.split("==", 1)[1].strip()
        return want in summary
    # 简单协议/关键字
    return expr in proto.lower() or expr in summary.lower()


# --------------------------------------------------------------------------- #
#  GUI
# --------------------------------------------------------------------------- #
COLS = ["Frame", "Time", "Source", "Destination", "Protocol", "Description"]


class NetMonWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Microsoft Network Monitor 3.4 (PySide6 重写版)")
        self.resize(1180, 740)
        self.engine = None
        self.frames = []
        self.t0 = time.time()
        self._build_ui()
        self.statusBar().showMessage("Ready. (需管理员权限以开启混杂模式)")

    def _build_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        lay = QVBoxLayout(central)
        bar = QHBoxLayout()
        self.btn_start = QPushButton("Start Capture"); self.btn_start.clicked.connect(self.start)
        self.btn_stop = QPushButton("Stop"); self.btn_stop.clicked.connect(self.stop); self.btn_stop.setEnabled(False)
        self.btn_clear = QPushButton("Clear"); self.btn_clear.clicked.connect(self.clear)
        bar.addWidget(self.btn_start); bar.addWidget(self.btn_stop); bar.addWidget(self.btn_clear)
        bar.addWidget(QLabel("Adapter:")); self.adapter = QComboBox(); self.adapter.addItems(NetMonWindow._adapters())
        bar.addWidget(self.adapter)
        bar.addWidget(QLabel("Filter:")); self.filter = QLineEdit(); self.filter.setPlaceholderText("tcp / http / ip.addr==1.2.3.4")
        self.filter.textChanged.connect(lambda: self.apply_filter())
        bar.addWidget(self.filter); bar.addStretch()
        lay.addLayout(bar)

        self.split = QSplitter(Qt.Vertical)
        self.table = QTableWidget(0, len(COLS)); self.table.setHorizontalHeaderLabels(COLS)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.verticalHeader().setVisible(False)
        hh = self.table.horizontalHeader(); hh.setSectionResizeMode(QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(COLS.index("Description"), QHeaderView.Stretch)
        self.table.itemSelectionChanged.connect(self.on_select)
        self.split.addWidget(self.table)

        self.detail = QTreeWidget(); self.detail.setHeaderLabel("Frame Detail (协议分层)")
        self.split.addWidget(self.detail); self.split.setSizes([400, 320])
        lay.addWidget(self.split)
        self.stat = QLabel("协议分布: -"); lay.addWidget(self.stat)

    @staticmethod
    def _adapters():
        return [local_ip(), "127.0.0.1"]

    def start(self):
        if self.engine: return
        self.engine = CaptureEngine(self.adapter.currentText())
        self.engine.frame.connect(self.on_frame)
        self.engine.status.connect(self.statusBar().showMessage)
        self.engine.finished.connect(self._finished)
        self.engine.start()
        self.btn_start.setEnabled(False); self.btn_stop.setEnabled(True)

    def stop(self):
        if self.engine: self.engine.stop()
    def _finished(self):
        self.engine = None
        self.btn_start.setEnabled(True); self.btn_stop.setEnabled(False)
    def clear(self):
        self.frames = []; self.table.setRowCount(0); self.detail.clear(); self.stat.setText("协议分布: -")

    def on_frame(self, f):
        f["no"] = len(self.frames) + 1
        f["t"] = f["ts"] - self.t0
        self.frames.append(f)
        r = self.table.rowCount(); self.table.insertRow(r)
        # 拆 summary 取源/目的
        parts = f["summary"].split(" ")
        src = parts[1] if len(parts) > 1 else ""
        dst = parts[3] if len(parts) > 3 else (parts[2] if len(parts) > 2 else "")
        vals = [str(f["no"]), "%.6f" % f["t"], src, dst, f["proto"], f["summary"]]
        for c, v in enumerate(vals):
            self.table.setItem(r, c, QTableWidgetItem(v))
        self.table.scrollToBottom()
        self.recompute_stats()

    def recompute_stats(self):
        c = defaultdict(int)
        for f in self.frames:
            c[f["proto"]] += 1
        self.stat.setText("协议分布: " + ", ".join("%s=%d" % (k, v) for k, v in sorted(c.items(), key=lambda x: -x[1])))

    def apply_filter(self):
        expr = self.filter.text()
        for r in range(self.table.rowCount()):
            if r >= len(self.frames): break
            f = self.frames[r]
            self.table.setRowHidden(r, not match_filter(f["proto"], f["summary"], expr))

    def on_select(self):
        r = self.table.currentRow()
        if r < 0 or r >= len(self.frames): return
        f = self.frames[r]
        self.detail.clear()
        root = QTreeWidgetItem(["Frame #%d  %s" % (f["no"], f["summary"])])
        self.detail.addTopLevelItem(root)
        for name, fields in f["layers"]:
            node = QTreeWidgetItem(root, [name])
            for k, v in fields:
                QTreeWidgetItem(node, ["%s: %s" % (k, v)])
        self.detail.expandAll()


# --------------------------------------------------------------------------- #
def selftest():
    # TCP/HTTP 帧
    payload = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n"
    tcp = struct.pack("!HHIIBBHHH", 12345, 80, 1, 0, 5 << 4, 0x18, 0, 0, 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0,
                     socket.inet_aton("10.0.0.1"), socket.inet_aton("10.0.0.2"))
    proto, summary, layers = decode_frame(ip + tcp)
    assert proto == "HTTP" and "10.0.0.1" in summary and layers[0][0] == "IPv4"
    # DNS
    dnsq = struct.pack("!HHHHHH", 1, 0x100, 1, 0, 0, 0) + b"\x07example\x03com\x00" + b"\x00\x01\x00\x01"
    udp = struct.pack("!HHHH", 5555, 53, 8 + len(dnsq), 0) + dnsq
    ip2 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 0, 0, 64, 17, 0,
                      socket.inet_aton("1.1.1.1"), socket.inet_aton("8.8.8.8"))
    proto2, summary2, _ = decode_frame(ip2 + udp)
    assert proto2 == "DNS" and "example.com" in summary2, (proto2, summary2)
    # 过滤器
    assert match_filter("TCP", "TCP a -> b", "tcp")
    assert match_filter("HTTP", "HTTP a -> b", "http")
    assert not match_filter("UDP", "UDP a -> b", "tcp")
    print("[selftest] NetMon decode/filter OK")


def main():
    if "--selftest" in sys.argv:
        selftest(); return
    app = QApplication(sys.argv)
    w = NetMonWindow(); w.show(); sys.exit(app.exec())


if __name__ == "__main__":
    main()