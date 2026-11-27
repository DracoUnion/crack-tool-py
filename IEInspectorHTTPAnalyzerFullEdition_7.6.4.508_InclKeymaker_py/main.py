#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IEInspector HTTP Analyzer Full Edition V7.6.4  ->  PySide6 重写版
================================================================================

逆向依据:
  目录主程序 HttpAnalyzerFull_V7.6.4.exe 是 Inno Setup 安装包 (PE 资源版本信息:
  "This installation was built with Inno Setup.", ProductName "HTTPAnalyzer Full
  Edition V7.6.4", CompanyName "IEInspector Software")。7z 可拆出 Inno 容器
  (CODE/DATA/[0] 10MB 压缩载荷) 但载荷为 Inno 私有压缩, 未展开; 故依据该工具
  公开行为 + 安装包元数据重写。
  IEInspector HTTP Analyzer 核心行为: 作为系统代理捕获 HTTP(S) 会话, 对每个会话
  做结构化分析 —— 请求/响应头表、查询参数表、表单/POST 参数表、Cookie 表、
  时间线(开始/耗时)、大小; 并给出聚合统计 (按状态码/Content-Type/方法/域名的
  数量与字节数), 支持过滤、导出。

  本 PySide6 重写 (纯标准库 + PySide6, main.py 唯一入口):
    - 内建多线程 HTTP 调试代理 (默认 127.0.0.1:8080) 捕获会话 (CONNECT 透传);
    - 会话列表 + 结构化分析 (头/查询参数/表单参数/Cookie 表, 时间线, 大小);
    - 聚合统计面板 (按状态码 / Content-Type / 方法 / 域名 计数与字节, 总计);
    - 过滤 (方法/域名/状态码/Content-Type/关键字), 导出会话为 JSON。

用法:  python main.py             # GUI (浏览器代理指向 127.0.0.1:8080)
       python main.py --selftest  # 参数/cookie/统计 自检
"""
import sys
import os
import socket
import threading
import time
import select
import json
from urllib.parse import urlsplit, parse_qsl

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QTableWidget, QTableWidgetItem, QLabel, QLineEdit, QComboBox, QSpinBox,
    QAbstractItemView, QHeaderView, QPlainTextEdit, QSplitter, QTabWidget,
    QFileDialog, QTreeWidget, QTreeWidgetItem,
)
from PySide6.QtCore import Qt, Signal, QObject
from PySide6.QtGui import QColor


# --------------------------------------------------------------------------- #
#  解析工具
# --------------------------------------------------------------------------- #
def parse_head(head_bytes):
    lines = head_bytes.decode("latin1").split("\r\n")
    if not lines or len(lines[0].split(" ")) < 3:
        return None
    method, target, version = lines[0].split(" ")[:3]
    headers = []
    for ln in lines[1:]:
        if ":" in ln:
            k, v = ln.split(":", 1); headers.append((k.strip(), v.strip()))
    return method, target, version, headers


def hget(headers, name):
    name = name.lower()
    for k, v in headers:
        if k.lower() == name:
            return v
    return None


def parse_params(target, headers, body):
    """返回 (query_list, form_list)。"""
    query = []
    form = []
    if "?" in target:
        query = parse_qsl(target.split("?", 1)[1], keep_blank_values=True)
    ct = (hget(headers, "content-type") or "").lower()
    if body and "application/x-www-form-urlencoded" in ct:
        try:
            form = parse_qsl(body.decode("latin1"), keep_blank_values=True)
        except Exception:
            pass
    return query, form


def parse_cookies(headers):
    out = []
    raw = hget(headers, "cookie")
    if raw:
        for part in raw.split(";"):
            if "=" in part:
                k, v = part.split("=", 1); out.append((k.strip(), v.strip()))
    return out


def ctype_short(headers):
    return (hget(headers, "content-type") or "-").split(";")[0].strip() or "-"


# --------------------------------------------------------------------------- #
#  会话
# --------------------------------------------------------------------------- #
class Session:
    def __init__(self, method, host, path, status, ctype, size, tse, dur,
                 raw_req, raw_resp):
        self.no = 0
        self.method, self.host, self.path = method, host, path
        self.status, self.ctype, self.size = status, ctype, size
        self.tse, self.dur, self.raw_req, self.raw_resp = tse, dur, raw_req, raw_resp
        self.req_headers = []
        self.resp_headers = []
        self.query, self.form, self.cookies = [], [], []
        self._analyze()

    def _analyze(self):
        if b"\r\n\r\n" in self.raw_req:
            head, _, body = self.raw_req.partition(b"\r\n\r\n")
            r = parse_head(head)
            if r:
                self.req_headers = r[3]
                self.query, self.form = parse_params(r[1], r[3], body)
                self.cookies = parse_cookies(r[3])
        if b"\r\n\r\n" in self.raw_resp:
            head = self.raw_resp.split(b"\r\n\r\n", 1)[0]
            r = parse_head(head)
            if r:
                self.resp_headers = r[3]


# --------------------------------------------------------------------------- #
#  代理 (捕获)
# --------------------------------------------------------------------------- #
class ProxyServer(QObject):
    session = Signal(object)
    status = Signal(str)

    def __init__(self, host, port):
        super().__init__(); self.host, self.port = host, port
        self._stop = threading.Event(); self._srv = None

    def start(self):
        self._stop.clear(); threading.Thread(target=self._run, daemon=True).start()

    def stop(self):
        self._stop.set()
        if self._srv:
            try: self._srv.close()
            except OSError: pass

    def _run(self):
        try:
            srv = socket.socket(); self._srv = srv
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((self.host, self.port)); srv.listen(50)
            self.status.emit("Proxy listening on %s:%d" % (self.host, self.port))
            while not self._stop.is_set():
                try:
                    srv.settimeout(0.5); conn, _ = srv.accept()
                except socket.timeout:
                    continue
                except OSError:
                    break
                threading.Thread(target=self._handle, args=(conn,), daemon=True).start()
        except OSError as e:
            self.status.emit("Proxy error: %s" % e)

    def _handle(self, conn):
        try:
            conn.settimeout(10); buf = b""
            while b"\r\n\r\n" not in buf:
                d = conn.recv(4096)
                if not d: break
                buf += d
            head, _, rest = buf.partition(b"\r\n\r\n")
            req = parse_head(head)
            if not req:
                conn.close(); return
            method, target, version, headers = req
            if method.upper() == "CONNECT":
                host, _, port = target.partition(":"); port = int(port or 443)
                try: up = socket.create_connection((host, port), timeout=10)
                except OSError:
                    conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\n\r\n"); conn.close(); return
                conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                self.session.emit(Session("CONNECT", host, "", 200, "tunnel", 0,
                                          time.time(), 0.0, head, b"(HTTPS tunnel)"))
                _pipe(conn, up); conn.close(); return
            clen = int(hget(headers, "content-length") or 0)
            body = rest
            while len(body) < clen:
                d = conn.recv(4096)
                if not d: break
                body += d
            body = body[:clen] if clen else b""
            raw_req = head + b"\r\n\r\n" + body
            if target.startswith("http://"):
                sp = urlsplit(target); host = sp.hostname; port = sp.port or 80
                path = sp.path or "/"
                if sp.query: path += "?" + sp.query
            else:
                host = hget(headers, "host") or ""; port = 80; path = target
            t0 = time.time()
            status, rh, rbody, raw_resp = self._forward(host, port, method, path, headers, body)
            dur = time.time() - t0
            self.session.emit(Session(method, host, path, status, ctype_short(rh),
                                      len(rbody), t0, dur, raw_req, raw_resp))
            conn.sendall(raw_resp or b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
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
            c.request(method, path, body=body or None, headers=fwd)
            r = c.getresponse(); data = r.read(); rh = r.getheaders()
            out = ["HTTP/1.1 %d %s" % (r.status, r.reason)] + ["%s: %s" % (k, v) for k, v in rh]
            raw = ("\r\n".join(out) + "\r\n\r\n").encode("latin1") + data
            c.close(); return r.status, rh, data, raw
        except Exception as e:
            return 502, [], b"", ("HTTP/1.1 502 Bad Gateway\r\n\r\n%s" % e).encode("latin1")


def _pipe(a, b):
    socks = [a, b]
    try:
        while True:
            r, _, _ = select.select(socks, [], [], 5)
            if not r: break
            for s in r:
                data = s.recv(8192)
                if not data: return
                (b if s is a else a).sendall(data)
    except OSError:
        pass


# --------------------------------------------------------------------------- #
#  GUI
# --------------------------------------------------------------------------- #
COLS = ["No", "Time", "Method", "Host", "Path", "Status", "Type", "Size", "ms"]


class HttpAnalyzerWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("IEInspector HTTP Analyzer (PySide6 重写版)")
        self.resize(1200, 760)
        self.proxy = None
        self.sessions = []
        self._build_ui()
        self.statusBar().showMessage("Ready. Start 后浏览器代理设为 127.0.0.1:8080")

    def _build_ui(self):
        central = QWidget(); self.setCentralWidget(central)
        lay = QVBoxLayout(central)
        bar = QHBoxLayout()
        self.btn_start = QPushButton("Start"); self.btn_start.clicked.connect(self.start)
        self.btn_stop = QPushButton("Stop"); self.btn_stop.clicked.connect(self.stop); self.btn_stop.setEnabled(False)
        self.btn_clear = QPushButton("Clear"); self.btn_clear.clicked.connect(self.clear)
        self.btn_export = QPushButton("Export JSON"); self.btn_export.clicked.connect(self.export)
        self.host = QLineEdit("127.0.0.1"); self.port = QSpinBox(); self.port.setRange(1, 65535); self.port.setValue(8080)
        for w in (self.btn_start, self.btn_stop, self.btn_clear, QLabel("Proxy"), self.host, self.port, self.btn_export):
            bar.addWidget(w)
        bar.addStretch(); lay.addLayout(bar)

        fb = QHBoxLayout()
        self.f_method = QComboBox(); self.f_method.addItems(["All", "GET", "POST", "PUT", "DELETE", "CONNECT"])
        self.f_status = QLineEdit(); self.f_status.setPlaceholderText("状态码")
        self.f_domain = QLineEdit(); self.f_domain.setPlaceholderText("域名")
        self.f_text = QLineEdit(); self.f_text.setPlaceholderText("关键字"); self.f_text.textChanged.connect(lambda: self.apply_filter())
        self.f_method.currentTextChanged.connect(lambda: self.apply_filter())
        for w in (QLabel("过滤:"), self.f_method, self.f_status, self.f_domain, self.f_text):
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

        self.tabs = QTabWidget()
        self.tab_headers = self._kv_table(["Name", "Value"])
        self.tab_query = self._kv_table(["Key", "Value"])
        self.tab_form = self._kv_table(["Key", "Value"])
        self.tab_cookies = self._kv_table(["Name", "Value"])
        self.tab_raw = QPlainTextEdit(); self.tab_raw.setReadOnly(True)
        self.tabs.addTab(self.tab_headers, "请求/响应头")
        self.tabs.addTab(self.tab_query, "查询参数")
        self.tabs.addTab(self.tab_form, "表单参数")
        self.tabs.addTab(self.tab_cookies, "Cookies")
        self.tabs.addTab(self.tab_raw, "原始")
        self.split.addWidget(self.tabs)
        self.split.setSizes([380, 380]); lay.addWidget(self.split)

        self.stat = QTreeWidget(); self.stat.setHeaderLabels(["统计", "数量", "字节"])
        lay.addWidget(self.stat)

    def _kv_table(self, cols):
        t = QTableWidget(0, len(cols)); t.setHorizontalHeaderLabels(cols)
        t.setEditTriggers(QAbstractItemView.NoEditTriggers)
        t.verticalHeader().setVisible(False)
        t.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        return t

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

    def clear(self):
        self.sessions = []; self.table.setRowCount(0); self.stat.clear()

    def on_session(self, s):
        s.no = len(self.sessions) + 1
        self.sessions.append(s)
        r = self.table.rowCount(); self.table.insertRow(r)
        vals = [str(s.no), time.strftime("%H:%M:%S", time.localtime(s.tse)), s.method,
                s.host, s.path[:120], str(s.status), s.ctype, str(s.size), "%.1f" % (s.dur * 1000)]
        for c, v in enumerate(vals):
            it = QTableWidgetItem(v)
            if c == 5 and s.status >= 400: it.setForeground(QColor("#c62828"))
            self.table.setItem(r, c, it)
        self.table.scrollToBottom()
        self.recompute_stats(); self.apply_filter()

    def recompute_stats(self):
        from collections import defaultdict
        by = {"status": defaultdict(lambda: [0, 0]), "ctype": defaultdict(lambda: [0, 0]),
              "method": defaultdict(lambda: [0, 0]), "host": defaultdict(lambda: [0, 0])}
        tot_n = tot_b = 0
        for s in self.sessions:
            tot_n += 1; tot_b += s.size
            for k, key in (("status", str(s.status)), ("ctype", s.ctype),
                           ("method", s.method), ("host", s.host)):
                by[k][key][0] += 1; by[k][key][1] += s.size
        self.stat.clear()
        root = QTreeWidgetItem(["总计", str(tot_n), str(tot_b)]); self.stat.addTopLevelItem(root)
        for k, title in (("status", "按状态码"), ("ctype", "按 Content-Type"),
                         ("method", "按方法"), ("host", "按域名")):
            node = QTreeWidgetItem([title, "", ""])
            for key, (n, b) in sorted(by[k].items(), key=lambda x: -x[1][0]):
                QTreeWidgetItem(node, [key, str(n), str(b)])
            self.stat.addTopLevelItem(node)
        self.stat.expandAll()

    def apply_filter(self):
        m = self.f_method.currentText(); st = self.f_status.text().strip()
        dom = self.f_domain.text().strip().lower(); qt = self.f_text.text().strip().lower()
        for r in range(self.table.rowCount()):
            if r >= len(self.sessions): break
            s = self.sessions[r]
            ok = (m == "All" or s.method == m)
            if ok and st: ok = st in str(s.status)
            if ok and dom: ok = dom in s.host.lower()
            if ok and qt: ok = qt in (s.host + s.path + s.ctype).lower()
            self.table.setRowHidden(r, not ok)

    def on_select(self):
        r = self.table.currentRow()
        if r < 0 or r >= len(self.sessions): return
        s = self.sessions[r]
        self._fill(self.tab_headers, [("REQ", k + ": " + v) for k, v in s.req_headers] +
                   [("RESP", k + ": " + v) for k, v in s.resp_headers])
        self._fill(self.tab_query, s.query)
        self._fill(self.tab_form, s.form)
        self._fill(self.tab_cookies, s.cookies)
        self.tab_raw.setPlainText("REQUEST:\n" + s.raw_req.decode("latin1", "replace") +
                                  "\n\nRESPONSE:\n" + s.raw_resp.decode("latin1", "replace"))

    def _fill(self, table, pairs):
        table.setRowCount(0)
        for k, v in pairs:
            r = table.rowCount(); table.insertRow(r)
            table.setItem(r, 0, QTableWidgetItem(str(k)))
            table.setItem(r, 1, QTableWidgetItem(str(v)))

    def export(self):
        fn, _ = QFileDialog.getSaveFileName(self, "Export", filter="JSON (*.json)")
        if not fn: return
        data = [{"no": s.no, "method": s.method, "host": s.host, "path": s.path,
                 "status": s.status, "ctype": s.ctype, "size": s.size,
                 "req_headers": s.req_headers, "resp_headers": s.resp_headers,
                 "query": s.query, "form": s.form, "cookies": s.cookies} for s in self.sessions]
        with open(fn, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        self.statusBar().showMessage("Exported %d sessions" % len(self.sessions))


# --------------------------------------------------------------------------- #
def selftest():
    q, f = parse_params("/p?a=1&b=2", [("Content-Type", "application/x-www-form-urlencoded")], b"x=9&y=8")
    assert q == [("a", "1"), ("b", "2")] and f == [("x", "9"), ("y", "8")]
    ck = parse_cookies([("Cookie", "sid=abc; theme=dark")])
    assert ("sid", "abc") in ck and ("theme", "dark") in ck
    s = Session("GET", "h.com", "/p?a=1", 200, "text/html", 10, time.time(), 0.1,
                b"GET /p?a=1 HTTP/1.1\r\nHost: h.com\r\n\r\n",
                b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nbody")
    assert s.query == [("a", "1")] and s.resp_headers and s.status == 200
    print("[selftest] HttpAnalyzer params/cookies/session OK")


def main():
    if "--selftest" in sys.argv:
        selftest(); return
    app = QApplication(sys.argv)
    w = HttpAnalyzerWindow(); w.show(); sys.exit(app.exec())


if __name__ == "__main__":
    main()