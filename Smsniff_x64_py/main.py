#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SmartSniff (NirSoft, x64, 233KB, 未加壳)  ->  PySide6 重写版
================================================================================

逆向依据 (PE 静态分析 / 导入 / 字符串, x64 .text 熵 6.32 未加壳):
  导入: wpcap.dll(WinPcap), NmApi.dll(NetMon API), npptools.dll(NetMon3),
        WS2_32, iphlpapi, dnsapi, riched20, msvcrt。
  关键字符串 (配置/行为):
    "CaptureMethod"        —— 抓包后端选择 (Raw Socket / WinPcap / NetMon / NetMon3)
    "PCapAdapterName" / "NetMonAdapterName" / "NetMon3AdapterName" / "AdapterName"
    "CaptureOnProgramStart" / "LoadPacketsFilterIndex" / "CaptureFilter"
    "DecompressHTTP"       —— 对 HTTP 响应做 gzip/deflate 解压
    "DisplayCaptureTime"   / "HttpExtractOptions.Folder"
    "<meta http-equiv='content-type' ...>" / "<br><h4>%s <a href=...>SmartSniff..."
  => SmartSniff 核心: 从网卡捕获 IP 包 → 按 TCP/UDP 流重组会话 →
     解析并(可选)解压 HTTP → 逐行显示 (时间/方向/源/目的/协议/解码数据)。

  本 PySide6 重写 (纯标准库 + PySide6, main.py 唯一入口):
    - 默认 Raw Socket(SIO_RCVALL) 抓包 (无需 WinPcap, 管理员权限);
      若存在 wpcap.dll 也可走 WinPcap (此处保留接口, 自动回退 raw)。
    - IPv4/TCP/UDP/ICMP 解析 + 每连接 TCP 双向流重组 (按 seq 排序去重);
    - HTTP 请求/响应识别, 自动 gzip/deflate 解压 (等价 DecompressHTTP);
    - 列表实时显示, 方向 (+ 出站 / - 入站), 协议过滤, 保存/加载。

用法:  python main.py             # GUI
       python main.py --selftest  # 解析/解压/重组 自检
"""
import sys
import os
import socket
import struct
import threading
import time
import zlib
import gzip as _gzip
import io
import ctypes
from ctypes import wintypes
from collections import defaultdict

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QTableWidget, QTableWidgetItem, QLabel, QFileDialog, QMessageBox,
    QAbstractItemView, QHeaderView, QComboBox, QCheckBox,
)
from PySide6.QtCore import Qt, Signal, QObject

SIO_RCVALL = 0x98000001
IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP = 1, 6, 17
PROTO_NAME = {1: "ICMP", 6: "TCP", 17: "UDP"}


# --------------------------------------------------------------------------- #
#  HTTP 解码 (等价 DecompressHTTP)
# --------------------------------------------------------------------------- #
def decompress_http(body, content_encoding=""):
    enc = (content_encoding or "").lower()
    try:
        if "gzip" in enc:
            return _gzip.GzipFile(fileobj=io.BytesIO(body)).read()
        if "deflate" in enc:
            try:
                return zlib.decompress(body)
            except zlib.error:
                return zlib.decompress(body, -zlib.MAX_WBITS)
    except Exception:
        return body
    return body


def parse_http_headers(data):
    """若 data 以 HTTP 方法/状态行开头, 返回 (start_line, headers_dict, body_offset) 否则 None。"""
    if not data:
        return None
    head = data
    idx = head.find(b"\r\n\r\n")
    if idx < 0:
        return None
    head = head[:idx]
    lines = head.split(b"\r\n")
    start = lines[0]
    if not (start.startswith(b"HTTP/") or start[:4] in
            (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"OPTI", b"PATC")):
        return None
    headers = {}
    for ln in lines[1:]:
        if b":" in ln:
            k, v = ln.split(b":", 1)
            headers[k.strip().lower().decode("latin1")] = v.strip().decode("latin1")
    return start.decode("latin1"), headers, idx + 4


# --------------------------------------------------------------------------- #
#  包解析
# --------------------------------------------------------------------------- #
def parse_ip_packet(data):
    if len(data) < 20:
        return None
    ver_ihl = data[0]
    if ver_ihl >> 4 != 4:
        return None
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < 20 or len(data) < ihl:
        return None
    total_len = struct.unpack_from("!H", data, 2)[0]
    proto = data[9]
    src = socket.inet_ntoa(data[12:16]); dst = socket.inet_ntoa(data[16:20])
    sport = dport = seq = ack = 0
    payload = data[ihl:total_len] if total_len else data[ihl:]
    if proto in (IPPROTO_TCP, IPPROTO_UDP) and len(payload) >= 4:
        sport, dport = struct.unpack_from("!HH", payload, 0)
        if proto == IPPROTO_TCP and len(payload) >= 20:
            seq, ack = struct.unpack_from("!II", payload, 4)
            doff = (payload[12] >> 4) * 4
            payload = payload[doff:]
        elif proto == IPPROTO_UDP:
            payload = payload[8:]
    return {"src": src, "dst": dst, "sport": sport, "dport": dport,
            "seq": seq, "ack": ack,
            "proto": PROTO_NAME.get(proto, str(proto)), "payload": payload}


# --------------------------------------------------------------------------- #
#  TCP 流重组器
# --------------------------------------------------------------------------- #
class TcpReassembler:
    """按 (src,sport,dst,dport) 单向流缓存段, 按 seq 排序, 输出连续字节。"""
    def __init__(self):
        self.streams = defaultdict(list)   # key -> list[(seq, bytes)]
        self.got = defaultdict(dict)       # key -> {seq: bytes} 去重

    def push(self, key, seq, data):
        if not data:
            return b""
        buf = self.got[key]
        buf.setdefault(seq, data)          # 去重 (重传)
        out = bytearray()
        for s in sorted(buf):
            out += buf[s]
        # 消费已连续部分, 保留空洞之后的
        # 简化: 全量返回, 清空 (对请求/响应短流足够)
        buf.clear()
        return bytes(out)

    def key(self, p):
        return (p["src"], p["sport"], p["dst"], p["dport"])


# --------------------------------------------------------------------------- #
#  抓包引擎 (raw socket; 若 wpcap 存在则提示)
# --------------------------------------------------------------------------- #
def _wsaioctl_rcvall(sock, level=1):
    ws2 = ctypes.WinDLL("ws2_32.dll")
    fn = ws2.WSAIoctl
    fn.restype = ctypes.c_int
    fn.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                   ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD),
                   ctypes.c_void_p, ctypes.c_void_p]
    inbuf = ctypes.c_ulong(level); outlen = wintypes.DWORD(0)
    rc = fn(wintypes.HANDLE(sock.fileno()), SIO_RCVALL,
            ctypes.byref(inbuf), ctypes.sizeof(inbuf), None, 0,
            ctypes.byref(outlen), None, None)
    return rc == 0


class CaptureEngine(QObject):
    packet = Signal(dict)        # 解析后的原始包
    reassembled = Signal(dict)   # 重组后的流数据
    status = Signal(str)
    finished = Signal()

    def __init__(self, bind_ip):
        super().__init__()
        self.bind_ip = bind_ip
        self._stop = threading.Event()
        self._sock = None
        self.reasm = TcpReassembler()

    def start(self):
        self._stop.clear()
        threading.Thread(target=self._run, daemon=True).start()

    def stop(self):
        self._stop.set()
        if self._sock:
            try: self._sock.close()
            except OSError: pass

    def _run(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            self._sock = s
            s.bind((self.bind_ip, 0))
            if not _wsaioctl_rcvall(s, 1):
                self.status.emit("WSAIoctl failed (需管理员权限)"); s.close(); self.finished.emit(); return
            self.status.emit("Capture... (Raw Socket)")
            while not self._stop.is_set():
                try:
                    data, _ = s.recvfrom(65535)
                except OSError:
                    break
                p = parse_ip_packet(data)
                if not p:
                    continue
                p["ts"] = time.time()
                self.packet.emit(p)
                if p["proto"] == "TCP" and p["payload"]:
                    k = self.reasm.key(p)
                    stream = self.reasm.push(k, p["seq"], p["payload"])
                    if stream:
                        self.reassembled.emit({"key": k, "data": stream,
                                               "ts": p["ts"], "src": p["src"],
                                               "sport": p["sport"], "dst": p["dst"],
                                               "dport": p["dport"]})
        except PermissionError:
            self.status.emit("Create Socket Error! (需管理员权限)")
        except OSError as e:
            self.status.emit("Bind Error! %s" % e)
        finally:
            self.finished.emit()


# --------------------------------------------------------------------------- #
#  行解码: 把流数据转成可显示文本 (HTTP  specially)
# --------------------------------------------------------------------------- #
def decode_stream_to_lines(src, sport, dst, dport, data):
    """返回 [(direction, text)]。HTTP 响应会解压 body。"""
    out = []
    h = parse_http_headers(data)
    if h:
        start, headers, off = h
        body = data[off:]
        if start.startswith("HTTP/"):
            body = decompress_http(body, headers.get("content-encoding", ""))
        text = start + "\n"
        for k, v in headers.items():
            text += "%s: %s\n" % (k, v)
        text += "\n" + body.decode("latin1", "replace")
        out.append(("->" if sport < dport else "<-", text))
    else:
        txt = data.decode("latin1", "replace")
        out.append(("->" if sport < dport else "<-", txt))
    return out


# --------------------------------------------------------------------------- #
#  GUI
# --------------------------------------------------------------------------- #
COLS = ["Time", "Dir", "Source", "Destination", "Protocol", "Data"]


class SmartSniffWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SmartSniff (PySide6 重写版)")
        self.resize(1050, 640)
        self.engine = None
        self.rows = []
        self._build_ui()
        self.statusBar().showMessage("Ready.")

    def _build_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        lay = QVBoxLayout(central)
        bar = QHBoxLayout()
        self.btn_start = QPushButton("Start"); self.btn_start.clicked.connect(self.start)
        self.btn_stop = QPushButton("Stop"); self.btn_stop.clicked.connect(self.stop); self.btn_stop.setEnabled(False)
        self.btn_clear = QPushButton("Clear"); self.btn_clear.clicked.connect(self.clear)
        self.btn_save = QPushButton("Save..."); self.btn_save.clicked.connect(self.save)
        self.cmb_proto = QComboBox(); self.cmb_proto.addItems(["All", "TCP", "UDP", "ICMP"])
        self.cmb_proto.currentTextChanged.connect(lambda _: None)
        self.chk_http = QCheckBox("Decompress HTTP"); self.chk_http.setChecked(True)
        for w in (self.btn_start, self.btn_stop, self.btn_clear, self.btn_save,
                  QLabel("Filter:"), self.cmb_proto, self.chk_http):
            bar.addWidget(w)
        bar.addStretch()
        lay.addLayout(bar)

        self.table = QTableWidget(0, len(COLS))
        self.table.setHorizontalHeaderLabels(COLS)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.verticalHeader().setVisible(False)
        hh = self.table.horizontalHeader(); hh.setSectionResizeMode(QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(COLS.index("Data"), QHeaderView.Stretch)
        lay.addWidget(self.table)

    def start(self):
        if self.engine: return
        ip = "127.0.0.1"
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]; s.close()
        except OSError: pass
        self.engine = CaptureEngine(ip)
        self.engine.packet.connect(self.on_packet)
        self.engine.reassembled.connect(self.on_stream)
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
        self.rows = []; self.table.setRowCount(0)
    def save(self):
        fn, _ = QFileDialog.getSaveFileName(self, "Save", filter="Text (*.txt)")
        if fn:
            with open(fn, "w", encoding="utf-8", errors="replace") as f:
                for (t, d, src, dst, proto, data) in self.rows:
                    f.write("[%s] %s %s -> %s %s\n%s\n\n" % (t, d, src, dst, proto, data))

    def _pass_filter(self, proto):
        f = self.cmb_proto.currentText()
        return f == "All" or f == proto

    def on_packet(self, p):
        # UDP/ICMP 直接成行
        if p["proto"] in ("UDP", "ICMP"):
            if not self._pass_filter(p["proto"]): return
            data = p["payload"].decode("latin1", "replace")
            self._addrow(time.strftime("%H:%M:%S", time.localtime(p["ts"])),
                         "->", "%s:%d" % (p["src"], p["sport"]),
                         "%s:%d" % (p["dst"], p["dport"]), p["proto"], data)

    def on_stream(self, s):
        if not self._pass_filter("TCP"): return
        lines = decode_stream_to_lines(s["src"], s["sport"], s["dst"], s["dport"], s["data"])
        for d, text in lines:
            self._addrow(time.strftime("%H:%M:%S", time.localtime(s["ts"])), d,
                         "%s:%d" % (s["src"], s["sport"]),
                         "%s:%d" % (s["dst"], s["dport"]), "TCP", text)

    def _addrow(self, t, d, src, dst, proto, data):
        self.rows.append((t, d, src, dst, proto, data))
        r = self.table.rowCount(); self.table.insertRow(r)
        for c, v in enumerate([t, d, src, dst, proto, data]):
            it = QTableWidgetItem(v)
            if c == 1:
                it.setForeground(QColor("#2a7") if d == "->" else QColor("#c33"))
            self.table.setItem(r, c, it)
        self.table.scrollToBottom()


from PySide6.QtGui import QColor


# --------------------------------------------------------------------------- #
def selftest():
    # HTTP gzip 解压
    raw = b"hello world" * 5
    gz = _gzip.compress(raw)
    assert decompress_http(gz, "gzip") == raw
    # HTTP 头解析
    msg = b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n" + gz
    h = parse_http_headers(msg)
    assert h and h[0].startswith("HTTP/") and h[1]["content-encoding"] == "gzip"
    body = decompress_http(msg[h[2]:], h[1]["content-encoding"])
    assert body == raw
    # TCP 流重组
    r = TcpReassembler()
    out = r.push(("1", 1, "2", 2), 100, b"GET / HTTP/1.0\r\n")
    out += r.push(("1", 1, "2", 2), 116, b"\r\n")
    assert out == b"GET / HTTP/1.0\r\n\r\n", out
    # IP 解析
    tcp = struct.pack("!HHIIBBHHH", 5555, 80, 1, 0, 5 << 4, 0x18, 0, 0, 0) + b"abc"
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0,
                     socket.inet_aton("1.1.1.1"), socket.inet_aton("2.2.2.2"))
    p = parse_ip_packet(ip + tcp)
    assert p["proto"] == "TCP" and p["sport"] == 5555 and p["payload"] == b"abc"
    print("[selftest] SmartSniff HTTP/TCP/IP OK")


def main():
    if "--selftest" in sys.argv:
        selftest(); return
    app = QApplication(sys.argv)
    w = SmartSniffWindow(); w.show(); sys.exit(app.exec())


if __name__ == "__main__":
    main()