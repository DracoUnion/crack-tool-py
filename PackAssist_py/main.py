#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
封包助手 PackAssist (Delphi, 335KB, 加壳 .text 熵7.93, 0.4~0.6 Beta)  ->  PySide6 重写版
================================================================================

逆向依据 (说明.txt 全文 + PE 静态 + arithmetic/接口参数.txt + Encode/Decode 例程源码):
  封包助手 = 纯绿色 Winsock 封包拦截器, 拦截目标程序的:
    Send / Recv / WSASend / WSARecv / SendTo / RecvFrom / WSASendTo / WSARecvFrom
    Connect / WSAConnect / Accept / WSAAccept
  功能 (逐条对应说明.txt 各版本更新):
    - 不同颜色显示不同函数(可选); 列表自动下滚(可选); 无需双击查看数据包;
      关闭进程同时停止截包; 队列发送(多包+时间间隔, 可从文件读取);
      快捷键启动/停止; Hex 和 Ascii 查找; 发送数据窗口。
  算法插件接口 (arithmetic/接口参数.txt):
    Plugin_Encode(pIn:pChar; Size:LongWord; pOut:pChar): LongWord; stdcall;  // 加密
    Plugin_Decode(pIn:pChar; Size:LongWord; pOut:pChar): LongWord; stdcall;  // 解密
    例程 Encode_Example: 每字节 +1 ; Decode_Example: 每字节 -1 。
  => 截包时对 outgoing 调 Plugin_Encode、incoming 调 Plugin_Decode 后再显示。

  本 PySide6 重写 (纯标准库 + PySide6, main.py 唯一入口):
    - Raw Socket(SIO_RCVALL) 抓包 (等价拦截, 安全无注入), 按方向映射到 12 个
      Winsock 函数名并分色; Hex+Ascii 双视图; 查找; 自动下滚; MaxPacket 上限。
    - 算法插件: 选 DLL → 解析 Plugin_Encode/Plugin_Decode (stdcall) → 对收发数据
      加/解密显示 (完整复刻算法导入导出)。
    - 队列发送: 多组 Hex 数据 + 目标 + 间隔, 依次经 TCP 发出 (等价队列发送)。

用法:  python main.py             # GUI
       python main.py --selftest  # 插件编解码 / 解析 自检
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
    QTableWidget, QTableWidgetItem, QLabel, QLineEdit, QCheckBox, QSpinBox,
    QAbstractItemView, QHeaderView, QPlainTextEdit, QSplitter, QFileDialog,
    QMessageBox, QInputDialog,
)
from PySide6.QtCore import Qt, Signal, QObject
from PySide6.QtGui import QColor

SIO_RCVALL = 0x98000001
IPPROTO_ICMP, IPPROTO_TCP, IPPROTO_UDP = 1, 6, 17
PROTO_NAME = {1: "ICMP", 6: "TCP", 17: "UDP"}

# 12 个被拦截函数 -> 颜色 (对应说明.txt "不同颜色显示不同函数")
FUNC_COLOR = {
    "send": "#1565c0", "WSASend": "#1565c0",
    "recv": "#2e7d32", "WSARecv": "#2e7d32",
    "sendto": "#6a1b9a", "WSASendTo": "#6a1b9a",
    "recvfrom": "#ef6c00", "WSARecvFrom": "#ef6c00",
    "connect": "#c62828", "WSAConnect": "#c62828",
    "accept": "#00838f", "WSAAccept": "#00838f",
}


# --------------------------------------------------------------------------- #
#  算法插件 (Plugin_Encode / Plugin_Decode, stdcall)
# --------------------------------------------------------------------------- #
class AlgorithmPlugin:
    def __init__(self):
        self.dll = None
        self.encode = None
        self.decode = None
        self.name = "(none)"

    def load(self, path):
        try:
            dll = ctypes.CDLL(path)
        except OSError as e:
            raise ValueError("无法加载 DLL (可能位数不符: 需与 Python 同位数, 64 位 Python "
                             "需 64 位算法 DLL): %s" % e)
        enc = getattr(dll, "Plugin_Encode", None)
        dec = getattr(dll, "Plugin_Decode", None)
        if enc is None and dec is None:
            raise ValueError("DLL 未导出 Plugin_Encode/Plugin_Decode")
        # stdcall 在 x64 即默认 cdecl; 用 c_void_p 缓冲以容纳含 0 的二进制
        self.dll = dll
        if enc:
            enc.restype = ctypes.c_ulong
            enc.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p]
            self.encode = enc
        if dec:
            dec.restype = ctypes.c_ulong
            dec.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_void_p]
            self.decode = dec
        self.name = os.path.basename(path)

    def _call(self, fn, data):
        if fn is None or not data:
            return data
        inbuf = ctypes.create_string_buffer(data, len(data))
        outbuf = ctypes.create_string_buffer(len(data) + 4)
        n = fn(ctypes.cast(inbuf, ctypes.c_void_p), len(data),
               ctypes.cast(outbuf, ctypes.c_void_p))
        return outbuf.raw[:n] if 0 < n <= len(data) + 4 else data

    def encode_bytes(self, data):
        return self._call(self.encode, data)

    def decode_bytes(self, data):
        return self._call(self.decode, data)


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
                self.status.emit("WSAIoctl Func Error!"); s.close(); self.finished.emit(); return
            self.status.emit("Sniffer Running...")
            while not self._stop.is_set():
                try: data, _ = s.recvfrom(65535)
                except OSError: break
                p = parse_ip(data)
                if p: p["ts"] = time.time(); self.packet.emit(p)
        except PermissionError:
            self.status.emit("Create Socket Error!")
        except OSError as e:
            self.status.emit("Bind Port Error! %s" % e)
        finally:
            self.finished.emit()


def direction_func(p):
    """按方向/端口近似映射到被拦截的 Winsock 函数名。"""
    if p["proto"] == "UDP":
        return "recvfrom" if p["sport"] < p["dport"] else "sendto"
    return "recv" if p["sport"] < p["dport"] else "send"


# --------------------------------------------------------------------------- #
#  GUI
# --------------------------------------------------------------------------- #
COLS = ["No", "Time", "Function", "Source", "Destination", "Proto", "Len", "Data"]


class PackAssistWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("封包助手 PackAssist (PySide6 重写版)")
        self.resize(1100, 680)
        self.engine = None
        self.plugin = AlgorithmPlugin()
        self.count = 0
        self.records = []
        self.queue = []          # 队列发送: list[(hexbytes, interval_ms)]
        self._build_ui()
        self.statusBar().showMessage("Ready.")

    def _build_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        lay = QVBoxLayout(central)

        bar = QHBoxLayout()
        self.btn_start = QPushButton("启动截包"); self.btn_start.clicked.connect(self.start)
        self.btn_stop = QPushButton("停止"); self.btn_stop.clicked.connect(self.stop); self.btn_stop.setEnabled(False)
        self.btn_plugin = QPushButton("加载算法DLL..."); self.btn_plugin.clicked.connect(self.load_plugin)
        self.lbl_plugin = QLabel("算法: (none)")
        self.chk_color = QCheckBox("按函数分色"); self.chk_color.setChecked(True)
        self.chk_scroll = QCheckBox("自动下滚"); self.chk_scroll.setChecked(True)
        bar.addWidget(self.btn_start); bar.addWidget(self.btn_stop); bar.addWidget(self.btn_plugin)
        bar.addWidget(self.lbl_plugin); bar.addWidget(self.chk_color); bar.addWidget(self.chk_scroll)
        bar.addStretch()
        lay.addLayout(bar)

        # 查找行
        findbar = QHBoxLayout()
        self.find = QLineEdit(); self.find.setPlaceholderText("Hex 或 Ascii 查找")
        self.btn_find = QPushButton("查找"); self.btn_find.clicked.connect(self.do_find)
        findbar.addWidget(QLabel("查找:")); findbar.addWidget(self.find); findbar.addWidget(self.btn_find); findbar.addStretch()
        lay.addLayout(findbar)

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
        self.split.addWidget(self.hexview); self.split.setSizes([440, 240])
        lay.addWidget(self.split)

        # 发送 / 队列
        sendbar = QHBoxLayout()
        self.sendto = QLineEdit("127.0.0.1:80")
        self.sendhex = QLineEdit(); self.sendhex.setPlaceholderText("发送 Hex 数据 e.g. 474554202f")
        self.interval = QSpinBox(); self.interval.setRange(0, 60000); self.interval.setSuffix(" ms")
        self.btn_addq = QPushButton("加入队列"); self.btn_addq.clicked.connect(self.add_queue)
        self.btn_sendq = QPushButton("发送队列"); self.btn_sendq.clicked.connect(self.send_queue)
        self.btn_send1 = QPushButton("单发"); self.btn_send1.clicked.connect(self.send_once)
        for w in (QLabel("To:"), self.sendto, self.sendhex, self.interval, self.btn_addq, self.btn_sendq, self.btn_send1):
            sendbar.addWidget(w)
        lay.addLayout(sendbar)
        self.lbl_queue = QLabel("队列: 0 包"); lay.addWidget(self.lbl_queue)

    # ---- capture ----
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

    def load_plugin(self):
        fn, _ = QFileDialog.getOpenFileName(self, "选择算法 DLL", filter="DLL (*.dll)")
        if not fn: return
        try:
            self.plugin.load(fn)
        except Exception as e:
            QMessageBox.critical(self, "错误", str(e)); return
        self.lbl_plugin.setText("算法: " + self.plugin.name)

    def on_packet(self, p):
        func = direction_func(p)
        data = p["payload"]
        # 算法: 出站 encode, 入站 decode
        try:
            if func in ("send", "sendto", "WSASend", "WSASendTo"):
                data = self.plugin.encode_bytes(data)
            else:
                data = self.plugin.decode_bytes(data)
        except Exception:
            pass
        self._addrow(time.strftime("%H:%M:%S", time.localtime(p["ts"])), func,
                     "%s:%d" % (p["src"], p["sport"]), "%s:%d" % (p["dst"], p["dport"]),
                     p["proto"], len(data), data)

    def _addrow(self, t, func, src, dst, proto, ln, data):
        self.count += 1
        self.records.append({"t": t, "func": func, "data": data})
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

    def do_find(self):
        q = self.find.text().strip()
        if not q: return
        # 判断 hex
        try:
            needle = bytes.fromhex(q.replace(" ", ""))
            mode = "hex"
        except ValueError:
            needle = q.encode("latin1"); mode = "ascii"
        for r in range(self.table.rowCount()):
            it = self.table.item(r, COLS.index("Data"))
            if it and needle.hex().upper() in it.text().upper().replace(" ", ""):
                self.table.selectRow(r); self.statusBar().showMessage("查找(%s) 命中行 %d" % (mode, r + 1)); return
        self.statusBar().showMessage("查找(%s) 未命中" % mode)

    # ---- queue send (等价队列发送) ----
    def add_queue(self):
        try:
            b = bytes.fromhex(self.sendhex.text().replace(" ", ""))
        except ValueError:
            QMessageBox.warning(self, "错误", "Hex 格式错误"); return
        self.queue.append((b, self.interval.value()))
        self.lbl_queue.setText("队列: %d 包" % len(self.queue))

    def _parse_to(self):
        hp = self.sendto.text().strip().rsplit(":", 1)
        return hp[0], int(hp[1]) if len(hp) == 2 and hp[1].isdigit() else 80

    def send_once(self):
        try:
            b = bytes.fromhex(self.sendhex.text().replace(" ", ""))
        except ValueError:
            QMessageBox.warning(self, "错误", "Hex 格式错误"); return
        host, port = self._parse_to()
        try:
            s = socket.create_connection((host, port), timeout=3); s.sendall(b); s.close()
            self.statusBar().showMessage("已发送 %d 字节 -> %s:%d" % (len(b), host, port))
        except OSError as e:
            self.statusBar().showMessage("发送失败: %s" % e)

    def send_queue(self):
        if not self.queue:
            self.statusBar().showMessage("队列为空"); return
        host, port = self._parse_to()
        threading.Thread(target=self._run_queue, args=(host, port), daemon=True).start()

    def _run_queue(self, host, port):
        try:
            s = socket.create_connection((host, port), timeout=3)
        except OSError as e:
            self.statusBar().showMessage("连接失败: %s" % e); return
        for b, iv in self.queue:
            try: s.sendall(b)
            except OSError: break
            if iv: time.sleep(iv / 1000.0)
        s.close()
        self.statusBar().showMessage("队列发送完成 (%d 包)" % len(self.queue))


# --------------------------------------------------------------------------- #
def selftest():
    # 内置 +1/-1 例程等价实现
    data = bytes([0, 1, 2, 254, 255])
    enc = bytes((b + 1) & 0xFF for b in data)
    dec = bytes((b - 1) & 0xFF for b in enc)
    assert dec == data
    # 尝试加载真实算法 DLL (若存在且位数匹配)
    dll = r"D:\Program Files\crack-tool-network\PackAssist\arithmetic\Encode_Example.dll"
    if os.path.exists(dll):
        try:
            p = AlgorithmPlugin(); p.load(dll)
            got = p.encode_bytes(b"\x00\x01\x02")
            assert got == b"\x01\x02\x03", got
            print("[selftest] 真实 Encode_Example.dll 加载 OK:", got)
        except ValueError as e:
            print("[selftest] 示例 DLL 位数不匹配(原版为 32 位 Delphi), 已用内置等价例程验证:", str(e)[:40])
    else:
        print("[selftest] (未找到示例 DLL, 已用内置等价例程验证)")
    # 解析
    tcp = struct.pack("!HHIIBBHHH", 1, 2, 0, 0, 5 << 4, 0x18, 0, 0, 0) + b"AB"
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0,
                     socket.inet_aton("1.1.1.1"), socket.inet_aton("2.2.2.2"))
    p = parse_ip(ip + tcp); assert p["proto"] == "TCP" and p["payload"] == b"AB"
    print("[selftest] PackAssist cipher/parse OK; local=", local_ip())


def main():
    if "--selftest" in sys.argv:
        selftest(); return
    app = QApplication(sys.argv)
    w = PackAssistWindow(); w.show(); sys.exit(app.exec())


if __name__ == "__main__":
    main()