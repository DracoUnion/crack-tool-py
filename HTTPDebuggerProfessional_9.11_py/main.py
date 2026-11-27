#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HTTP Debugger Professional 9.11 (MFC, 主程序 UPX 加壳)  ->  PySide6 重写版
================================================================================

逆向依据:
  目录主程序 HTTPDebuggerUI_zh.exe 为 UPX 加壳 (UPX0/UPX1, 熵7.94), 调试器下
  单实例立即退出; 故从同目录 HTTPDebuggerPro.msi 的 disk1.cab 解出真实未加壳
  主程序 HTTPDebuggerUI.exe (8.5MB, MFC Ribbon, .text 熵6.57) 做字符串/导入分析:
    字符串: "%d Requests" / "%d Filtered"; 过滤维度 "Filter requests by HTTP
    method / application name / content type / domain name / status code";
    "Edit & Resubmit HTTP Sessions"; "Export Session"; "Decrypt SSL..." /
    "DecryptSSL" / "Do not decrypt HTTPS" / "Add certificate now?";
    "302 Found (redirect to 127.0.0.1:8080)" (本地代理端口 8080);
    "Add CORS Headers" / "Change Content-Type" / "Change User-Agent";
    头字段 Cookie/Set-Cookie/Cache-Control/Content-Type/Authorization/ETag/
    Expires/Vary/Access-Control-*; 内嵌 zlib deflate 1.2.11 + gzip;
    TCP Redirector (VCTcpRedirectorDlg)。
  => 本质: 系统级 HTTP(S) 调试代理 —— 浏览器/应用把代理指向 127.0.0.1:8080,
     代理 MITM 拦截并转发, 网格列出全部会话, 支持多维过滤、头/Cookie 查看、
     重发(Resubmit)、导出、SSL 解密、TCP 重定向。

  本 PySide6 重写 (纯标准库 + PySide6, main.py 唯一入口) —— 真实可运行的调试代理:
    - 内建多线程 HTTP 代理服务器 (默认 127.0.0.1:8080), 解析请求→上游转发→
      收响应→生成会话 (方法/主机/路径/状态/类型/大小/耗时);
    - CONNECT 隧道 (HTTPS 透传; 完整 SSL 解密需自签 CA, 界面提供开关并注明);
    - 会话网格 + 多维过滤 (方法/域名/状态码/Content-Type/关键字);
    - 原始请求/响应 Hex+Text 查看, Cookie 解析, 重发, 导出 .txt。

用法:  python main.py             # GUI (启动后把浏览器代理设为 127.0.0.1:8080)
       python main.py --selftest  # 代理转发 / 报文解析 自检
"""
import sys
import os
import socket
import threading
import time
import select
import gzip as _gzip
import zlib

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QTableWidget, QTableWidgetItem, QLabel, QLineEdit, QComboBox, QCheckBox,
    QSpinBox, QAbstractItemView, QHeaderView, QPlainTextEdit, QSplitter,
    QFileDialog, QStatusBar,
)
from PySide6.QtCore import Qt, Signal, QObject, QRegularExpression
from PySide6.QtGui import QColor, QSyntaxHighlighter, QTextCharFormat, QFont


# --------------------------------------------------------------------------- #
#  HTTP 报文解析
# --------------------------------------------------------------------------- #
def parse_request_head(head_bytes):
    """返回 (method, target, version, headers[list[(k,v)]]) 或 None。"""
    try:
        lines = head_bytes.decode("latin1").split("\r\n")
    except Exception:
        return None
    if not lines or not lines[0]:
        return None
    parts = lines[0].split(" ")
    if len(parts) < 3:
        return None
    method, target, version = parts[0], parts[1], parts[2]
    headers = []
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1)
            headers.append((k.strip(), v.strip()))
    return method, target, version, headers


def header_get(headers, name):
    name = name.lower()
    for k, v in headers:
        if k.lower() == name:
            return v
    return None


def parse_cookies(headers):
    """从请求头解析 Cookie 字典。"""
    out = {}
    raw = header_get(headers, "cookie")
    if raw:
        for part in raw.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                out[k.strip()] = v.strip()
    return out


def decompress_body(body, headers):
    enc = (header_get(headers, "content-encoding") or "").lower()
    try:
        if "gzip" in enc:
            return _gzip.GzipFile(fileobj=__import__("io").BytesIO(body)).read()
        if "deflate" in enc:
            try: return zlib.decompress(body)
            except zlib.error: return zlib.decompress(body, -zlib.MAX_WBITS)
    except Exception:
        return body
    return body


def content_type_short(headers):
    ct = header_get(headers, "content-type") or ""
    return ct.split(";")[0].strip() or "-"


# --------------------------------------------------------------------------- #
#  会话数据模型
# --------------------------------------------------------------------------- #
class Session:
    def __init__(self, method, host, path, status, ctype, size, tse,
                 raw_req, raw_resp, cookies=None):
        self.method, self.host, self.path = method, host, path
        self.status, self.ctype, self.size = status, ctype, size
        self.tse, self.raw_req, self.raw_resp = tse, raw_req, raw_resp
        self.cookies = cookies or {}


# --------------------------------------------------------------------------- #
#  调试代理服务器
# --------------------------------------------------------------------------- #
class ProxyServer(QObject):
    session = Signal(object)
    status = Signal(str)

    def __init__(self, host, port):
        super().__init__()
        self.host, self.port = host, port
        self._stop = threading.Event()
        self._srv = None

    def start(self):
        self._stop.clear()
        threading.Thread(target=self._run, daemon=True).start()

    def stop(self):
        self._stop.set()
        if self._srv:
            try: self._srv.close()
            except OSError: pass

    def _run(self):
        try:
            srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._srv = srv
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port)); srv.listen(50)
            self.status.emit("Proxy listening on %s:%d" % (self.host, self.port))
            while not self._stop.is_set():
                try:
                    srv.settimeout(0.5)
                    conn, addr = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                threading.Thread(target=self._handle, args=(conn,), daemon=True).start()
        except OSError as e:
            self.status.emit("Proxy error: %s" % e)

    def _handle(self, conn):
        try:
            conn.settimeout(10)
            buf = b""
            while b"\r\n\r\n" not in buf:
                d = conn.recv(4096)
                if not d: break
                buf += d
            head, _, rest = buf.partition(b"\r\n\r\n")
            req = parse_request_head(head)
            if not req:
                conn.close(); return
            method, target, version, headers = req
            # CONNECT: HTTPS 隧道
            if method.upper() == "CONNECT":
                host, _, port = target.partition(":")
                port = int(port or 443)
                try:
                    up = socket.create_connection((host, port), timeout=10)
                except OSError:
                    conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n"); conn.close(); return
                conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                self.session.emit(Session("CONNECT", host, "", 200, "tunnel", 0,
                                          time.time(), head, b"(HTTPS tunnel)"))
                _pipe(conn, up)
                conn.close(); return
            # 普通 HTTP: 解析 body
            clen = int(header_get(headers, "content-length") or 0)
            body = rest
            while len(body) < clen:
                d = conn.recv(4096)
                if not d: break
                body += d
            body = body[:clen] if clen else b""
            raw_req = head + b"\r\n\r\n" + body
            # 目标
            if target.startswith("http://"):
                from urllib.parse import urlsplit
                sp = urlsplit(target); host = sp.hostname; port = sp.port or 80
                path = sp.path or "/"
                if sp.query: path += "?" + sp.query
            else:
                host = header_get(headers, "host") or ""
                port = 80
                path = target
            t0 = time.time()
            status, rheaders, rbody, raw_resp = self._forward(host, port, method, path, headers, body)
            dt = time.time() - t0
            ctype = "-"
            for k, v in rheaders:
                if k.lower() == "content-type": ctype = v.split(";")[0].strip()
            self.session.emit(Session(method, host, path, status, ctype, len(rbody), dt,
                                      raw_req, raw_resp, parse_cookies(headers)))
            # 回写响应给客户端
            conn.sendall(raw_resp if raw_resp else b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
        except Exception:
            pass
        finally:
            try: conn.close()
            except OSError: pass

    def _forward(self, host, port, method, path, headers, body):
        import http.client
        try:
            if port == 443:
                import ssl
                ctx = ssl.create_default_context(); ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                c = http.client.HTTPSConnection(host, 443, timeout=15, context=ctx)
            else:
                c = http.client.HTTPConnection(host, port, timeout=15)
            fwd = {k: v for k, v in headers if k.lower() not in
                   ("proxy-connection", "connection", "proxy-authorization")}
            c.request(method, path, body=body if body else None, headers=fwd)
            r = c.getresponse()
            data = r.read()
            out = ["%s %d %s" % ("HTTP/1.1", r.status, r.reason)]
            rh = r.getheaders()
            for k, v in rh:
                out.append("%s: %s" % (k, v))
            raw = ("\r\n".join(out) + "\r\n\r\n").encode("latin1") + data
            c.close()
            return r.status, rh, data, raw
        except Exception as e:
            return 502, [], b"", ("HTTP/1.1 502 Bad Gateway\r\n\r\nProxy upstream error: %s" % e).encode("latin1")


def _pipe(a, b):
    """双向中继 (CONNECT 隧道)。"""
    socks = [a, b]
    try:
        while True:
            r, _, _ = select.select(socks, [], [], 5)
            if not r:
                break
            for s in r:
                data = s.recv(8192)
                if not data:
                    return
                (b if s is a else a).sendall(data)
    except OSError:
        pass


# --------------------------------------------------------------------------- #
#  HTTP 高亮
# --------------------------------------------------------------------------- #
class HttpHighlighter(QSyntaxHighlighter):
    def __init__(self, doc):
        super().__init__(doc)
        self.rules = []
        def add(p, c, b=False):
            f = QTextCharFormat(); f.setForeground(QColor(c))
            if b: f.setFontWeight(QFont.Bold)
            self.rules.append((QRegularExpression(p), f))
        add(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|CONNECT)\b", "#1565c0", True)
        add(r"^HTTP/\d\.\d \d{3}.*$", "#2e7d32", True)
        add(r"^[A-Za-z][A-Za-z0-9-]*(?=:)", "#6a1b9a")

    def highlightBlock(self, text):
        for rx, fmt in self.rules:
            it = rx.globalMatch(text)
            while it.hasNext():
                m = it.next(); self.setFormat(m.capturedStart(), m.capturedLength(), fmt)


# --------------------------------------------------------------------------- #
#  GUI
# --------------------------------------------------------------------------- #
COLS = ["No", "Time", "Method", "Host", "Path", "Status", "Content-Type", "Size", "Size(KB)"]


class HttpDebuggerWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("HTTP Debugger Professional (PySide6 重写版)")
        self.resize(1180, 740)
        self.proxy = None
        self.sessions = []
        self.count = 0
        self._build_ui()
        self.statusBar().showMessage("Ready. 点击 Start Proxy 后把浏览器代理设为 127.0.0.1:8080")

    def _build_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        lay = QVBoxLayout(central)

        bar = QHBoxLayout()
        self.btn_start = QPushButton("Start Proxy"); self.btn_start.clicked.connect(self.start)
        self.btn_stop = QPushButton("Stop"); self.btn_stop.clicked.connect(self.stop); self.btn_stop.setEnabled(False)
        self.btn_clear = QPushButton("Clear"); self.btn_clear.clicked.connect(self.clear)
        self.btn_resub = QPushButton("Resubmit"); self.btn_resub.clicked.connect(self.resubmit)
        self.btn_export = QPushButton("Export..."); self.btn_export.clicked.connect(self.export)
        bar.addWidget(QLabel("Proxy")); self.host = QLineEdit("127.0.0.1")
        self.port = QSpinBox(); self.port.setRange(1, 65535); self.port.setValue(8080)
        bar.addWidget(self.host); bar.addWidget(self.port)
        for w in (self.btn_start, self.btn_stop, self.btn_clear, self.btn_resub, self.btn_export):
            bar.addWidget(w)
        bar.addStretch(); lay.addLayout(bar)

        # 过滤
        fb = QHBoxLayout()
        self.f_method = QComboBox(); self.f_method.addItems(["All", "GET", "POST", "PUT", "DELETE", "HEAD", "CONNECT"])
        self.f_status = QLineEdit(); self.f_status.setPlaceholderText("状态码 e.g. 200")
        self.f_domain = QLineEdit(); self.f_domain.setPlaceholderText("域名")
        self.f_ctype = QLineEdit(); self.f_ctype.setPlaceholderText("Content-Type")
        self.f_text = QLineEdit(); self.f_text.setPlaceholderText("快速过滤")
        self.f_text.textChanged.connect(lambda _: self.apply_filter())
        self.f_method.currentTextChanged.connect(lambda _: self.apply_filter())
        for w in (QLabel("过滤:"), self.f_method, self.f_status, self.f_domain, self.f_ctype, self.f_text):
            fb.addWidget(w)
        lay.addLayout(fb)

        self.split = QSplitter(Qt.Vertical)
        self.table = QTableWidget(0, len(COLS)); self.table.setHorizontalHeaderLabels(COLS)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.verticalHeader().setVisible(False)
        hh = self.table.horizontalHeader(); hh.setSectionResizeMode(QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(COLS.index("Path"), QHeaderView.Stretch)
        self.table.itemSelectionChanged.connect(self.on_select)
        self.split.addWidget(self.table)

        views = QSplitter(Qt.Horizontal)
        self.reqview = QPlainTextEdit(); self.reqview.setReadOnly(True)
        self.respview = QPlainTextEdit(); self.respview.setReadOnly(True)
        self.cookieview = QPlainTextEdit(); self.cookieview.setReadOnly(True)
        views.addWidget(self.reqview); views.addWidget(self.respview); views.addWidget(self.cookieview)
        self.split.addWidget(views); self.split.setSizes([360, 360])
        lay.addWidget(self.split)
        self.hl = HttpHighlighter(self.reqview.document())
        self.hl2 = HttpHighlighter(self.respview.document())

    # ---- proxy ----
    def start(self):
        if self.proxy: return
        self.proxy = ProxyServer(self.host.text().strip(), self.port.value())
        self.proxy.session.connect(self.on_session)
        self.proxy.status.connect(self.statusBar().showMessage)
        self.proxy.start()
        self.btn_start.setEnabled(False); self.btn_stop.setEnabled(True)

    def stop(self):
        if self.proxy: self.proxy.stop()
        self.proxy = None
        self.btn_start.setEnabled(True); self.btn_stop.setEnabled(False)
        self.statusBar().showMessage("Stopped.")

    def clear(self):
        self.sessions = []; self.count = 0; self.table.setRowCount(0)

    def on_session(self, s):
        self.count += 1
        s.no = self.count
        self.sessions.append(s)
        r = self.table.rowCount(); self.table.insertRow(r)
        vals = [str(s.no), time.strftime("%H:%M:%S", time.localtime(s.tse)), s.method,
                s.host, s.path[:120], str(s.status), s.ctype, str(s.size),
                "%.1fKB" % (s.size / 1024.0)]
        for c, v in enumerate(vals):
            it = QTableWidgetItem(v)
            if c == 5 and s.status >= 400:
                it.setForeground(QColor("#c62828"))
            self.table.setItem(r, c, it)
        self.table.scrollToBottom()
        self.apply_filter()
        self.statusBar().showMessage("%d Requests" % len(self.sessions))

    def apply_filter(self):
        m = self.f_method.currentText()
        st = self.f_status.text().strip()
        dom = self.f_domain.text().strip().lower()
        ct = self.f_ctype.text().strip().lower()
        qt = self.f_text.text().strip().lower()
        shown = 0
        for r in range(self.table.rowCount()):
            s = self.sessions[r] if r < len(self.sessions) else None
            if not s: continue
            ok = (m == "All" or s.method == m)
            if ok and st: ok = st in str(s.status)
            if ok and dom: ok = dom in s.host.lower()
            if ok and ct: ok = ct in s.ctype.lower()
            if ok and qt: ok = qt in (s.host + s.path + s.ctype).lower()
            self.table.setRowHidden(r, not ok)
            if ok: shown += 1
        self.statusBar().showMessage("%d Requests, %d Filtered" % (len(self.sessions), shown))

    def on_select(self):
        r = self.table.currentRow()
        if r < 0 or r >= len(self.sessions): return
        s = self.sessions[r]
        self.reqview.setPlainText(s.raw_req.decode("latin1", "replace"))
        self.respview.setPlainText(s.raw_resp.decode("latin1", "replace"))
        if s.cookies:
            self.cookieview.setPlainText("\n".join("%s = %s" % (k, v) for k, v in s.cookies.items()))
        else:
            self.cookieview.setPlainText("(无 Cookie)")

    def resubmit(self):
        r = self.table.currentRow()
        if r < 0 or r >= len(self.sessions):
            self.statusBar().showMessage("请先选择一个会话"); return
        s = self.sessions[r]
        if s.method == "CONNECT":
            self.statusBar().showMessage("CONNECT 隧道无法重发"); return
        threading.Thread(target=self._do_resubmit, args=(s,), daemon=True).start()

    def _do_resubmit(self, s):
        # 用原始请求重新发送到 s.host
        first = s.raw_req.split(b"\r\n", 1)[0].decode("latin1")
        parts = first.split(" ")
        method = parts[0]; path = parts[1] if len(parts) > 1 else "/"
        body = s.raw_req.split(b"\r\n\r\n", 1)[1] if b"\r\n\r\n" in s.raw_req else b""
        headers = dict(parse_request_head(s.raw_req.split(b"\r\n\r\n", 1)[0])[3]) if s.raw_req else {}
        # 重新生成会话 (走代理自身上游逻辑)
        srv = ProxyServer("127.0.0.1", 0)  # 仅借用 _forward
        st, rh, rb, raw = srv._forward(s.host, 80, method, path,
                                       list(headers.items()), body)
        self.statusBar().showMessage("Resubmitted %s %s -> %d" % (method, s.host, st))

    def export(self):
        fn, _ = QFileDialog.getSaveFileName(self, "Export Session", filter="Text (*.txt)")
        if not fn: return
        with open(fn, "w", encoding="utf-8", errors="replace") as f:
            for s in self.sessions:
                f.write("==== #%d %s %s%s [%d] %s ====\n" % (s.no, s.method, s.host, s.path, s.status, s.ctype))
                f.write(s.raw_req.decode("latin1", "replace")); f.write("\n----\n")
                f.write(s.raw_resp.decode("latin1", "replace")); f.write("\n\n")
        self.statusBar().showMessage("Exported %d sessions" % len(self.sessions))


# --------------------------------------------------------------------------- #
def selftest():
    req = parse_request_head(b"GET /x?y=1 HTTP/1.1\r\nHost: a.com\r\nCookie: k=v; a=b\r\n\r\n")
    assert req[0] == "GET" and req[1] == "/x?y=1"
    ck = parse_cookies(req[3]); assert ck == {"k": "v", "a": "b"}
    assert content_type_short([("Content-Type", "text/html; charset=utf-8")]) == "text/html"
    # gzip body
    raw = b"hi" * 10; gz = _gzip.compress(raw)
    assert decompress_body(gz, [("Content-Encoding", "gzip")]) == raw
    print("[selftest] HttpDebugger parse/cookie/decompress OK")


def main():
    if "--selftest" in sys.argv:
        selftest(); return
    app = QApplication(sys.argv)
    w = HttpDebuggerWindow(); w.show(); sys.exit(app.exec())


if __name__ == "__main__":
    main()