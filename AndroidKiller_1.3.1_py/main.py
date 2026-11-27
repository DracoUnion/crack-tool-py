#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Android Killer 1.3.1  ->  Python 重写版 (PySide6 GUI)
================================================================================
逆向依据 (目录 AndroidKiller_1.3.1, 主程序 AndroidKiller.exe, PE32 GUI,
  Delphi XE (rtl230.bpl/vcl230.bpl/AKCommon.bpl), 配置 configs.ini):
  Android Killer 是 Android 逆向助手 GUI, 集成 apktool 反编译/回编译,
  jadx 反编译, 签名, 日志, 工程管理等, 界面为多标签 + 工具按钮 + 输出面板.
  本重写复刻其核心 (main.py 唯一入口, 纯标准库 + PySide6):
    打开 APK -> 反编译(apktool) / 反编译为 Java(jadx) / 回编译 / 签名,
    按钮调用同项目内已重写的 Python 工具 (兄弟目录 *_py/main.py),
    并显示输出日志与工程文件树.

用法:
  python main.py --selftest
  python main.py gui [app.apk]
"""

import sys
import os
import subprocess

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

TOOLS = {
    "apktool": os.path.join(BASE, "APKTool_2.7.0_py", "main.py"),
    "jadx": os.path.join(BASE, "JADX_1.4.5_py", "main.py"),
    "multitool": os.path.join(BASE, "APKMultiTool_py", "main.py"),
}


def run_tool(key, args, cwd=None):
    """调用兄弟 Python 工具, 返回 (returncode, output)。"""
    script = TOOLS.get(key)
    if not script or not os.path.exists(script):
        return 127, "工具不可用: %s (%s)" % (key, script)
    cmd = [sys.executable, script] + args
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd,
                           encoding="utf-8", errors="replace")
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except Exception as ex:
        return 1, "调用失败: %s" % ex


def run_gui(argv):
    from PySide6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
        QLabel, QFileDialog, QPlainTextEdit, QTreeWidget, QSplitter, QMessageBox)
    from PySide6.QtCore import Qt
    app = QApplication(sys.argv)
    win = QMainWindow(); win.setWindowTitle("Android Killer 1.3.1 (Android 逆向助手)  PySide6")
    win.resize(1100, 740)
    cw = QWidget(); win.setCentralWidget(cw); lay = QVBoxLayout(cw)

    top = QHBoxLayout()
    b_open = QPushButton("打开 APK"); b_dec = QPushButton("反编译 (apktool)")
    b_jadx = QPushButton("反编译为 Java (jadx)"); b_build = QPushButton("回编译")
    b_sign = QPushButton("签名")
    for b in (b_open, b_dec, b_jadx, b_build, b_sign):
        top.addWidget(b)
    top.addStretch(); lay.addLayout(top)

    path_lbl = QLabel("未打开工程"); lay.addWidget(path_lbl)

    sp = QSplitter()
    tree = QTreeWidget(); tree.setHeaderLabels(["工程文件"])
    console = QPlainTextEdit(); console.setReadOnly(True)
    sp.addWidget(tree); sp.addWidget(console); lay.addWidget(sp)

    st = {"apk": None, "outdir": None}

    def log(s):
        console.appendPlainText(s)

    def do_open():
        p, _ = QFileDialog.getOpenFileName(win, "打开 APK", "", "APK (*.apk);;All (*.*)")
        if p:
            st["apk"] = p
            st["outdir"] = os.path.splitext(p)[0] + "_out"
            path_lbl.setText(p)
            tree.clear()
            it = QTreeWidgetItem(tree, [os.path.basename(p)])
            for sub in ("smali", "res", "AndroidManifest.xml", "lib", "assets"):
                QTreeWidgetItem(it, [sub])
            tree.addTopLevelItem(it)
            log("已打开: %s" % p)

    def do_dec():
        if not st["apk"]:
            QMessageBox.warning(win, "提示", "请先打开 APK"); return
        rc, out = run_tool("apktool", ["d", st["apk"], "-o", st["outdir"]])
        log("$ apktool d ...\n" + out + "\n[rc=%d]" % rc)

    def do_jadx():
        if not st["apk"]:
            QMessageBox.warning(win, "提示", "请先打开 APK"); return
        jout = os.path.splitext(st["apk"])[0] + "_java"
        rc, out = run_tool("jadx", ["decompile", st["apk"], "-o", jout])
        log("$ jadx decompile ...\n" + out + "\n[rc=%d]" % rc)

    def do_build():
        if not st["outdir"] or not os.path.isdir(st["outdir"]):
            QMessageBox.warning(win, "提示", "请先反编译"); return
        out = os.path.splitext(st["apk"])[0] + "_built.apk"
        rc, o = run_tool("apktool", ["b", st["outdir"], "-o", out])
        log("$ apktool b ...\n" + o + "\n[rc=%d]" % rc)

    def do_sign():
        if not st["apk"]:
            QMessageBox.warning(win, "提示", "请先打开 APK"); return
        out = os.path.splitext(st["apk"])[0] + "_signed.apk"
        rc, o = run_tool("multitool", ["sign", st["apk"], out])
        log("$ sign ...\n" + o + "\n[rc=%d]" % rc)

    b_open.clicked.connect(do_open)
    b_dec.clicked.connect(do_dec)
    b_jadx.clicked.connect(do_jadx)
    b_build.clicked.connect(do_build)
    b_sign.clicked.connect(do_sign)

    if len(argv) > 1 and os.path.exists(argv[1]):
        st["apk"] = argv[1]; path_lbl.setText(argv[1])
    win.statusBar().showMessage("就绪"); win.show(); sys.exit(app.exec())


def selftest():
    ok = 0; fail = 0
    def check(n, c):
        nonlocal ok, fail
        print("  [%s] %s" % ("OK " if c else "ERR", n)); ok += 1 if c else 0; fail += 0 if c else 1
    check("BASE 存在", os.path.isdir(BASE))
    check("apktool 工具存在", os.path.exists(TOOLS["apktool"]))
    check("jadx 工具存在", os.path.exists(TOOLS["jadx"]))
    rc, out = run_tool("apktool", ["--selftest"])
    check("apktool --selftest rc=0", rc == 0)
    print("结果: %d 通过, %d 失败" % (ok, fail))
    return 0 if fail == 0 else 1


def main():
    a = sys.argv[1:]
    if "--selftest" in a:
        return selftest()
    run_gui(a)


if __name__ == "__main__":
    sys.exit(main() or 0)