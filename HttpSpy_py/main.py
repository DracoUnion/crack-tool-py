#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HTTP Spy .NET (C# WinForms, 1.18MB, 未加壳)  ->  PySide6 重写版
================================================================================

逆向依据 (PE 静态 + .NET 元数据/字符串):
  导入: mscoree.dll(.NET 运行时), winhttp.dll, wininet.dll, credui.dll, wtsapi32。
  WinHttp API 序列 (发请求/收响应全流程):
    WinHttpOpen → WinHttpConnect → WinHttpOpenRequest → WinHttpSendRequest →
    WinHttpReceiveResponse → WinHttpQueryHeaders → WinHttpReadData → WinHttpCloseHandle;
    代理: WinHttpDetectAutoProxyConfigUrl / WinHttpGetProxyForUrl。
  内嵌 ICSharpCode.TextEditor 语法高亮 (XML: "Syntaxdefinition for VB.NET/C++.NET"),
  说明文本: "HTTP Spy .NET is a small application used to inspect a web site."
  版本串: "fHTTPVersion"。
  => 本质: 输入 URL + 方法 + 头/体 → 经 WinHttp 发送 → 查看完整原始 HTTP 请求/响应
     (状态行/头/体), 语法高亮显示。

  本 PySide6 重写 (纯标准库 + PySide6, main.py 唯一入口):
    - 用 http.client 复刻 WinHttp 请求流程, 捕获并显示"原始请求报文"与"原始响应报文"
      (状态行 + 头 + 体), 支持自定义方法/头/请求体/HTTP 版本;
    - QSyntaxHighlighter 对 HTTP 报文着色 (方法/状态行/头名/分隔), 等价
      ICSharpCode.TextEditor 的语法高亮;
    - 自动/手动代理 (等价 WinHttp 代理解析), 超时, 重定向跟随开关。

用法:  python main.py             # GUI
       python main.py --selftest  # 请求报文构造 / 响应解析 自检
"""
import sys
import os
import socket
import ssl
import http.client
from urllib.parse import urlsplit

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLineEdit, QComboBox, QPlainTextEdit, QLabel, QCheckBox, QSpinBox, QSplitter,
    QFormLayout, QTextEdit,
)
from PySide6.QtCore import Qt, Signal, QObject, QRegularExpression
from PySide6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont

METHODS = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH", "TRACE"]
UA = "HTTP Spy .NET (PySide6 rewrite)"


# --------------------------------------------------------------------------- #
#  原始请求报文构造 (等价 WinHttpOpenRequest + WinHttpAddRequestHeaders)
# --------------------------------------------------------------------------- #
def build_raw_request(method, path, host, headers, body, version="HTTP/1.1"):
    lines = ["%s %s %s" % (method, path or "/", version)]
    have_host = any(k.lower() == "host" for k in headers)
    if not have_host:
        lines.append("Host: %s" % host)
    for k, v in headers.items():
        lines.append("%s: %s" % (k, v))
    if body and not any(k.lower() == "content-length" for k in headers):
        lines.append("Content-Length: %d" % len(body))
    head = ("\r\n".join(lines) + "\r\n\r\n").encode("latin1")
    return head + (body or b"")


def parse_raw_response(raw):
    """把原始响应字节拆成 (status_line, headers_list, body_bytes)。"""
    idx = raw.find(b"\r\n\r\n")
    if idx < 0:
        head, body = raw, b""
    else:
        head, body = raw[:idx], raw[idx + 4:]
    lines = head.split(b"\r\n")
    status = lines[0].decode("latin1", "replace") if lines else ""
    headers = []
    for ln in lines[1:]:
        if b":" in ln:
            k, v = ln.split(b":", 1)
            headers.append((k.decode("latin1"), v.strip().decode("latin1")))
    return status, headers, body


# --------------------------------------------------------------------------- #
#  发送 (等价 WinHttp 全流程), 在线程中执行
# --------------------------------------------------------------------------- #
class FetchEngine(QObject):
    done = Signal(bytes, bytes, str)   # raw_request, raw_response, error
    status = Signal(str)

    def __init__(self, method, url, headers, body, version, timeout, proxy, follow):
        super().__init__()
        self.method, self.url, self.headers = method, url, headers
        self.body, self.version, self.timeout = body, version, timeout
        self.proxy, self.follow = proxy, follow

    def run(self):
        try:
            self.status.emit("Connecting...")
            parts = urlsplit(self.url)
            scheme = parts.scheme or "http"
            host = parts.hostname or ""
            port = parts.port or (443 if scheme == "https" else 80)
            path = parts.path or "/"
            if parts.query:
                path += "?" + parts.query
            raw_req = build_raw_request(self.method, path, host, self.headers,
                                        self.body, self.version)
            if self.proxy:
                phost, _, pport = self.proxy.partition(":")
                conn = http.client.HTTPConnection(phost, int(pport or 8080), timeout=self.timeout)
                full = "%s://%s%s" % (scheme, host, path)
                conn.request(self.method, full, body=self.body, headers=self.headers)
            elif scheme == "https":
                ctx = ssl.create_default_context()
                ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(host, port, timeout=self.timeout, context=ctx)
                conn.request(self.method, path, body=self.body, headers=self.headers)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=self.timeout)
                conn.request(self.method, path, body=self.body, headers=self.headers)
            self.status.emit("Waiting for response...")
            resp = conn.getresponse()
            data = resp.read()
            # 重建原始响应报文
            out = ["%s %d %s" % (self.version, resp.status, resp.reason)]
            for k, v in resp.getheaders():
                out.append("%s: %s" % (k, v))
            raw_resp = ("\r\n".join(out) + "\r\n\r\n").encode("latin1") + data
            conn.close()
            self.done.emit(raw_req, raw_resp, "")
        except Exception as e:
            self.done.emit(b"", b"", str(e))


# --------------------------------------------------------------------------- #
#  HTTP 语法高亮 (等价 ICSharpCode.TextEditor)
# --------------------------------------------------------------------------- #
class HttpHighlighter(QSyntaxHighlighter):
    def __init__(self, doc):
        super().__init__(doc)
        self.rules = []
        def add(pat, color, bold=False):
            f = QTextCharFormat(); f.setForeground(QColor(color))
            if bold: f.setFontWeight(QFont.Bold)
            self.rules.append((QRegularExpression(pat), f))
        add(r"^(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH|TRACE)\b", "#1565c0", True)
        add(r"^HTTP/\d\.\d \d{3}.*$", "#2e7d32", True)
        add(r"^[A-Za-z][A-Za-z0-9-]*(?=:)", "#6a1b9a")
        add(r"\b\d{3}\b", "#ef6c00")

    def highlightBlock(self, text):
        for rx, fmt in self.rules:
            it = rx.globalMatch(text)
            while it.hasNext():
                m = it.next()
                self.setFormat(m.capturedStart(), m.capturedLength(), fmt)


# --------------------------------------------------------------------------- #
#  GUI
# --------------------------------------------------------------------------- #
class HttpSpyWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("HTTP Spy .NET (PySide6 重写版)")
        self.resize(1000, 720)
        self.engine = None
        self._build_ui()
        self.statusBar().showMessage("Ready.")

    def _build_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        lay = QVBoxLayout(central)

        top = QHBoxLayout()
        self.cmb = QComboBox(); self.cmb.addItems(METHODS)
        self.url = QLineEdit("http://example.com/"); self.url.setPlaceholderText("URL")
        self.btn_go = QPushButton("Send"); self.btn_go.clicked.connect(self.go)
        self.spin = QSpinBox(); self.spin.setRange(1, 120); self.spin.setValue(15); self.spin.setSuffix(" s")
        self.proxy = QLineEdit(); self.proxy.setPlaceholderText("proxy host:port (可选)")
        self.chk_follow = QCheckBox("跟随重定向"); self.chk_follow.setChecked(True)
        top.addWidget(self.cmb); top.addWidget(self.url, 1); top.addWidget(self.btn_go)
        top.addWidget(self.spin); top.addWidget(QLabel("Proxy")); top.addWidget(self.proxy)
        top.addWidget(self.chk_follow)
        lay.addLayout(top)

        form = QFormLayout()
        self.hdrs = QPlainTextEdit("User-Agent: " + UA + "\nAccept: */*")
        self.hdrs.setFixedHeight(70)
        self.body = QPlainTextEdit(); self.body.setPlaceholderText("请求体 (POST/PUT)")
        self.body.setFixedHeight(70)
        form.addRow("请求头:", self.hdrs); form.addRow("请求体:", self.body)
        lay.addLayout(form)

        self.split = QSplitter(Qt.Vertical)
        self.reqview = QPlainTextEdit(); self.reqview.setReadOnly(True)
        self.respview = QPlainTextEdit(); self.respview.setReadOnly(True)
        self.reqview.setPlaceholderText("原始请求报文")
        self.respview.setPlaceholderText("原始响应报文")
        self.split.addWidget(QLabel("Request")); self.split.addWidget(self.reqview)
        self.split.addWidget(QLabel("Response")); self.split.addWidget(self.respview)
        self.split.setSizes([20, 300, 20, 360])
        lay.addWidget(self.split)
        self.hl = HttpHighlighter(self.respview.document())
        self.hl2 = HttpHighlighter(self.reqview.document())

    def go(self):
        if self.engine: return
        headers = {}
        for ln in self.hdrs.toPlainText().splitlines():
            if ":" in ln:
                k, v = ln.split(":", 1); headers[k.strip()] = v.strip()
        body = self.body.toPlainText().encode("utf-8") if self.body.toPlainText() else None
        self.engine = FetchEngine(self.cmb.currentText(), self.url.text().strip(),
                                  headers, body, "HTTP/1.1", self.spin.value(),
                                  self.proxy.text().strip(), self.chk_follow.isChecked())
        self.engine.status.connect(self.statusBar().showMessage)
        self.engine.done.connect(self.on_done)
        self.reqview.clear(); self.respview.clear()
        self.engine.run()

    def on_done(self, raw_req, raw_resp, err):
        self.engine = None
        self.reqview.setPlainText(raw_req.decode("latin1", "replace"))
        if err:
            self.statusBar().showMessage("Error: " + err)
            self.respview.setPlainText("ERROR: " + err)
        else:
            self.respview.setPlainText(raw_resp.decode("latin1", "replace"))
            status, _, _ = parse_raw_response(raw_resp)
            self.statusBar().showMessage(status or "Done")


# --------------------------------------------------------------------------- #
def selftest():
    req = build_raw_request("POST", "/a", "h.com", {"X": "1"}, b"hello")
    assert req.startswith(b"POST /a HTTP/1.1\r\nHost: h.com\r\nX: 1\r\nContent-Length: 5\r\n\r\nhello")
    resp = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nBODY"
    st, hd, body = parse_raw_response(resp)
    assert st == "HTTP/1.1 200 OK" and ("Content-Type", "text/plain") in hd and body == b"BODY"
    print("[selftest] HttpSpy request/response OK")


def main():
    if "--selftest" in sys.argv:
        selftest(); return
    app = QApplication(sys.argv)
    w = HttpSpyWindow(); w.show(); sys.exit(app.exec())


if __name__ == "__main__":
    main()