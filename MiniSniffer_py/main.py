#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
MiniSniffer  (MFC Win32 网络嗅探器, 2008, 49KB, UPX 加壳)  ->  PySide6 重写版
================================================================================

逆向依据 (x32dbg 脱壳 + IDA/字符串导出):
  原程序 = "d:\\Vc\\Internet\\MiniSniffer\\Release\\MiniSniffer.pdb" 的 MFC 程序,
  原始被 UPX 压缩 (UPX0 空节 + UPX1 高熵 7.89)。x32dbg 加载后:
    EP=0x41CCA0 处 `pushad` → 单步 + 在 [ESP] 下硬件读断点 → 0x41CE00 `jmp 0x406E8A`
    即 OEP。脱壳后字符串揭示全部行为:
      - 导入: WS2_32!WSAIoctl, iphlpapi!GetIpAddrTable, comdlg32 文件对话框,
        SysListView32 列表, msctls_statusbar32 状态栏, ToolbarWindow32 工具栏。
      - 关键串: "Sniffer Running...", "Packets Count: Receive %d, Filter %d",
        "Bind Port Error!", "Create Socket Error!", "WSAIoctl Func Error!",
        "SnifferDataFile(*.sfd)", "undefined.sfd", "Save file [%s] success!",
        字段名 SourceIP / DestIP / SourcePort / DestPort / Protocol / DataLen / Content。
  => 经典 SIO_RCVALL 原始套接字嗅探器:
       socket(AF_INET, SOCK_RAW, IPPROTO_IP) → bind(本机IP) →
       WSAIoctl(SIO_RCVALL, 1) 开启混杂接收 → recvfrom 得到完整 IP 数据报 →
       解析 IP 头(proto/src/dst) + TCP/UDP 头(端口) + 负载 → 列表显示 / 存 .sfd。

  本 PySide6 重写 (纯标准库 + PySide6, main.py 唯一入口) 1:1 复刻该行为:
    - 后台线程用 ctypes 调 ws2_32!WSAIoctl 开启 SIO_RCVALL 混杂嗅探;
    - 解析 IPv4 / TCP / UDP / ICMP, 列表实时显示, 状态栏收发计数;
    - .sfd 文件存取 (自定义记录格式, 与原 *.sfd 语义一致);
    - 需管理员权限 (SIO_RCVALL 要求), 否则提示。

用法:  python main.py            # 启动 GUI
       python main.py --selftest # 无界面自检 (解析/编解码单元测试)
"""
import sys
import os
import socket
import struct
import threading
import time
import ctypes
from ctypes import wintypes

import PySide6
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QTableWidget, QTableWidgetItem, QLabel, QFileDialog, QMessageBox, QStatusBar,
    QAbstractItemView, QHeaderView,
)
from PySide6.QtCore import Qt, Signal, QObject
from PySide6.QtGui import QAction, QColor

SIO_RCVALL = 0x98000001
IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP = 1, 6, 17
PROTO_NAME = {1: "ICMP", 6: "TCP", 17: "UDP"}

# .sfd 文件魔数 (本重写自定义, 语义等价于原 SnifferDataFile)
SFD_MAGIC = b"SFD\x1a"


# --------------------------------------------------------------------------- #
#  原始套接字混杂嗅探 (SIO_RCVALL)
# --------------------------------------------------------------------------- #
def local_ipv4_addresses():
    """枚举本机 IPv4 地址 (等价原程序 GetIpAddrTable)。"""
    res = []
    try:
        # 利用 UDP connect 的惯用法取主出口 IP, 再补 127.0.0.1
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            res.append(s.getsockname()[0])
        except OSError:
            pass
        finally:
            s.close()
    except OSError:
        pass
    res.append("127.0.0.1")
    # 去重保序
    seen, out = set(), []
    for ip in res:
        if ip not in seen:
            seen.add(ip); out.append(ip)
    return out


def _wsaioctl_rcvall(sock, level=1):
    """对底层 SOCKET 句柄调用 WSAIoctl(SIO_RCVALL, level)。成功返回 True。"""
    ws2 = ctypes.WinDLL("ws2_32.dll")
    fn = ws2.WSAIoctl
    fn.restype = ctypes.c_int
    fn.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                   ctypes.c_void_p, wintypes.DWORD,
                   ctypes.c_void_p, wintypes.DWORD,
                   ctypes.POINTER(wintypes.DWORD),
                   ctypes.c_void_p, ctypes.c_void_p]
    inbuf = ctypes.c_ulong(level)
    outlen = wintypes.DWORD(0)
    handle = wintypes.HANDLE(sock.fileno())
    rc = fn(handle, SIO_RCVALL,
            ctypes.byref(inbuf), ctypes.sizeof(inbuf),
            None, 0,
            ctypes.byref(outlen), None, None)
    return rc == 0


def parse_ip_packet(data):
    """解析一个 IP 数据报, 返回 dict 或 None。等价原程序字段抽取。"""
    if len(data) < 20:
        return None
    ver_ihl = data[0]
    version = ver_ihl >> 4
    ihl = (ver_ihl & 0x0F) * 4
    if version != 4 or ihl < 20 or len(data) < ihl:
        return None
    tos = data[1]
    total_len = struct.unpack_from("!H", data, 2)[0]
    proto = data[9]
    src = socket.inet_ntoa(data[12:16])
    dst = socket.inet_ntoa(data[16:20])
    sport = dport = 0
    payload = data[ihl:]
    if proto in (IPPROTO_TCP, IPPROTO_UDP) and len(payload) >= 4:
        sport, dport = struct.unpack_from("!HH", payload, 0)
        l4hdr = 8 if proto == IPPROTO_UDP else max(20, (payload[12] >> 4) * 4)
        payload = payload[l4hdr:]
    if total_len and ihl <= total_len <= len(data):
        payload = data[ihl:total_len]
        if proto in (IPPROTO_TCP, IPPROTO_UDP):
            l4 = 8 if proto == IPPROTO_UDP else max(20, (data[ihl + 12] >> 4) * 4)
            payload = data[ihl + l4:total_len]
    return {
        "src": src, "dst": dst, "sport": sport, "dport": dport,
        "proto": PROTO_NAME.get(proto, str(proto)),
        "datalen": len(payload),
        "content": payload,
    }


# --------------------------------------------------------------------------- #
#  抓包线程
# --------------------------------------------------------------------------- #
class CaptureEngine(QObject):
    packet = Signal(dict)
    status = Signal(str)
    finished = Signal()

    def __init__(self, bind_ip):
        super().__init__()
        self.bind_ip = bind_ip
        self._stop = threading.Event()
        self._sock = None
        self._thread = None

    def start(self):
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass

    def _run(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            self._sock = s
            s.bind((self.bind_ip, 0))
            if not _wsaioctl_rcvall(s, 1):
                self.status.emit("WSAIoctl Func Error!")
                s.close(); self.finished.emit(); return
            self.status.emit("Sniffer Running...")
            while not self._stop.is_set():
                try:
                    data, addr = s.recvfrom(65535)
                except OSError:
                    break
                info = parse_ip_packet(data)
                if info:
                    info["ts"] = time.time()
                    self.packet.emit(info)
        except PermissionError:
            self.status.emit("Create Socket Error! (需要管理员权限)")
        except OSError as e:
            self.status.emit("Bind Port Error! %s" % e)
        finally:
            self.finished.emit()


# --------------------------------------------------------------------------- #
#  主窗口
# --------------------------------------------------------------------------- #
COLUMNS = ["No", "Time", "Source IP", "Source Port", "Dest IP", "Dest Port",
           "Protocol", "DataLen", "Content"]


class MiniSnifferWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("MiniSniffer (PySide6 重写版)")
        self.resize(1000, 620)
        self.count = 0
        self.recv_count = 0
        self.records = []          # 已抓/已载记录, 用于存盘
        self.engine = None
        self._build_ui()
        self._build_menu()
        self.statusBar().showMessage("Ready.")

    # ---- UI ----
    def _build_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        lay = QVBoxLayout(central)

        bar = QHBoxLayout()
        self.btn_start = QPushButton("Start Sniffer"); self.btn_start.clicked.connect(self.start_sniff)
        self.btn_stop = QPushButton("Stop"); self.btn_stop.clicked.connect(self.stop_sniff); self.btn_stop.setEnabled(False)
        self.btn_open = QPushButton("Open..."); self.btn_open.clicked.connect(self.open_file)
        self.btn_save = QPushButton("Save..."); self.btn_save.clicked.connect(self.save_file)
        self.lbl_bind = QLabel("Bind: " + ", ".join(local_ipv4_addresses()))
        for w in (self.btn_start, self.btn_stop, self.btn_open, self.btn_save, self.lbl_bind):
            bar.addWidget(w)
        bar.addStretch()
        lay.addLayout(bar)

        self.table = QTableWidget(0, len(COLUMNS))
        self.table.setHorizontalHeaderLabels(COLUMNS)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.verticalHeader().setVisible(False)
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(COLUMNS.index("Content"), QHeaderView.Stretch)
        lay.addWidget(self.table)

    def _build_menu(self):
        m = self.menuBar().addMenu("&Sniffer")
        a = QAction("Start", self); a.triggered.connect(self.start_sniff); m.addAction(a)
        a = QAction("Stop", self); a.triggered.connect(self.stop_sniff); m.addAction(a)
        m.addSeparator()
        a = QAction("Exit", self); a.triggered.connect(self.close); m.addAction(a)

    # ---- slots ----
    def start_sniff(self):
        if self.engine:
            return
        bind_ip = local_ipv4_addresses()[0]
        self.engine = CaptureEngine(bind_ip)
        self.engine.packet.connect(self.on_packet)
        self.engine.status.connect(self.statusBar().showMessage)
        self.engine.finished.connect(self.on_finished)
        self.engine.start()
        self.btn_start.setEnabled(False); self.btn_stop.setEnabled(True)

    def stop_sniff(self):
        if self.engine:
            self.engine.stop()
        self.statusBar().showMessage("Please stop sniffer first!" if False else "Stopped.")

    def on_finished(self):
        self.engine = None
        self.btn_start.setEnabled(True); self.btn_stop.setEnabled(False)

    def on_packet(self, info):
        self.recv_count += 1
        self.count += 1
        self.records.append(info)
        r = self.table.rowCount()
        self.table.insertRow(r)
        preview = info["content"][:200]
        vals = [str(self.count),
                time.strftime("%H:%M:%S", time.localtime(info["ts"])),
                info["src"], str(info["sport"]), info["dst"], str(info["dport"]),
                info["proto"], str(info["datalen"]),
                preview.hex(" ").upper()]
        for c, v in enumerate(vals):
            self.table.setItem(r, c, QTableWidgetItem(v))
        self.table.scrollToBottom()
        self.statusBar().showMessage("Packets Count: Receive %d" % self.recv_count)

    def open_file(self):
        fn, _ = QFileDialog.getOpenFileName(self, "Open Sniffer Data", filter="SnifferDataFile(*.sfd);;All Files(*.*)")
        if not fn:
            return
        try:
            recs = load_sfd(fn)
        except Exception as e:
            QMessageBox.critical(self, "ERROR", "Read file failure: %s" % e); return
        self.records = recs
        self.table.setRowCount(0)
        for i, info in enumerate(recs, 1):
            r = self.table.rowCount(); self.table.insertRow(r)
            vals = [str(i), time.strftime("%H:%M:%S", time.localtime(info["ts"])),
                    info["src"], str(info["sport"]), info["dst"], str(info["dport"]),
                    info["proto"], str(info["datalen"]), info["content"][:200].hex(" ").upper()]
            for c, v in enumerate(vals):
                self.table.setItem(r, c, QTableWidgetItem(v))
        self.statusBar().showMessage("Save file [%s] success!" % os.path.basename(fn))

    def save_file(self):
        fn, _ = QFileDialog.getSaveFileName(self, "Save Sniffer Data", "undefined.sfd", "SnifferDataFile(*.sfd)")
        if not fn:
            return
        try:
            save_sfd(fn, self.records)
        except Exception as e:
            QMessageBox.critical(self, "ERROR", "Save file failure! %s" % e); return
        self.statusBar().showMessage("Save file [%s] success!" % os.path.basename(fn))

    def closeEvent(self, e):
        if self.engine:
            self.engine.stop()
        super().closeEvent(e)


# --------------------------------------------------------------------------- #
#  .sfd 存取
# --------------------------------------------------------------------------- #
def save_sfd(path, records):
    with open(path, "wb") as f:
        f.write(SFD_MAGIC)
        f.write(struct.pack("<I", len(records)))
        for r in records:
            c = r["content"]
            f.write(struct.pack("<dI4sH4sHBBH", r.get("ts", 0.0), r["datalen"],
                                socket.inet_aton(r["src"]), r["sport"],
                                socket.inet_aton(r["dst"]), r["dport"],
                                0, 0, len(c)))
            f.write(c)


def load_sfd(path):
    out = []
    with open(path, "rb") as f:
        if f.read(4) != SFD_MAGIC:
            raise ValueError("bad magic")
        (n,) = struct.unpack("<I", f.read(4))
        for _ in range(n):
            hdr = f.read(28)
            ts, dlen, src, sport, dst, dport, a, b, clen = struct.unpack("<dI4sH4sHBBH", hdr)
            c = f.read(clen)
            out.append({"ts": ts, "datalen": dlen,
                        "src": socket.inet_ntoa(src), "sport": sport,
                        "dst": socket.inet_ntoa(dst), "dport": dport,
                        "proto": "?", "content": c})
    return out


# --------------------------------------------------------------------------- #
def selftest():
    # 构造一个含 TCP 段的 IPv4 包并解析
    payload = b"GET / HTTP/1.0\r\n\r\n"
    tcp = struct.pack("!HHIIBBHHH", 12345, 80, 1, 2, 5 << 4, 0x18, 1000, 0, 0) + payload
    total = 20 + len(tcp)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, IPPROTO_TCP, 0,
                     socket.inet_aton("10.0.0.1"), socket.inet_aton("10.0.0.2"))
    info = parse_ip_packet(ip + tcp)
    assert info["src"] == "10.0.0.1" and info["dst"] == "10.0.0.2"
    assert info["sport"] == 12345 and info["dport"] == 80 and info["proto"] == "TCP"
    assert info["content"] == payload, info["content"]
    # sfd 往返
    rec = dict(info, ts=time.time())
    save_sfd(os.devnull if False else ".__t.sfd", [rec])
    back = load_sfd(".__t.sfd")
    os.remove(".__t.sfd")
    assert back[0]["src"] == "10.0.0.1" and back[0]["content"] == payload
    print("[selftest] MiniSniffer parse/sfd OK; local IPs:", local_ipv4_addresses())


def main():
    if "--selftest" in sys.argv:
        selftest(); return
    app = QApplication(sys.argv)
    w = MiniSnifferWindow(); w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()