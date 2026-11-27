#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ApkIDE 3.3  ->  Python 重写版 (PySide6 GUI)
================================================================================
逆向依据 (目录 ApkIDE_3.3/ApkIDE, 主程序 ApkIDE.exe, PE32 .NET 程序集,
  Appres/Start.java, 内置 apktool.jar / dex2jar / aapt / test.keystore):
  ApkIDE 是面向 APK 的集成编辑环境: 解包 APK, 浏览/编辑 smali 与资源,
  回编译并签名 (内置 test.keystore). 界面为文件树 + 代码编辑器 + 输出面板.
  本重写复刻其核心 (main.py 唯一入口, 纯标准库 + PySide6):
    打开/反编译 APK -> 文件树浏览 -> 编辑器查看/修改 smali -> 回编译 -> 签名,
    调用同项目兄弟 Python 工具 (apktool / multitool).

用法:
  python main.py --selftest
  python main.py gui [app.apk]
"""

import sys
import os
import subprocess

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APKTOOL = os.path.join(BASE, "APKTool_2.7.0_py", "main.py")
MULTITOOL = os.path.join(BASE, "APKMultiTool_py", "main.py")


def run_tool(script, args):
    if not os.path.exists(script):
        return 127, "工具不可用: %s" % script
    p = subprocess.run([sys.executable, script] + args, capture_output=True, text=True,
                       encoding="utf-8", errors="replace")
    return p.returncode, (p.stdout or "") + (p.stderr or "")


def run_gui(argv):
    from PySide6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
        QFileDialog, QPlainTextEdit, QTreeWidget, QSplitter, QMessageBox, QLabel)
    app = QApplication(sys.argv)
    win = QMainWindow(); win.setWindowTitle("ApkIDE 3.3 (APK 集成编辑)  PySide6"); win.resize(1100, 760)
    cw = QWidget(); win.setCentralWidget(cw); lay = QVBoxLayout(cw)

    top = QHBoxLayout()
    b_open = QPushButton("打开/反编译 APK"); b_build = QPushButton("回编译"); b_sign = QPushButton("签名")
    for b in (b_open, b_build, b_sign):
        top.addWidget(b)
    top.addStretch(); lay.addLayout(top)
    path_lbl = QLabel("未打开"); lay.addWidget(path_lbl)

    sp = QSplitter()
    tree = QTreeWidget(); tree.setHeaderLabels(["工程"])
    editor = QPlainTextEdit()
    sp.addWidget(tree); sp.addWidget(editor); lay.addWidget(sp)
    console = QPlainTextEdit(); console.setReadOnly(True); console.setMaximumHeight(160); lay.addWidget(console)

    st = {"apk": None, "outdir": None}

    def log(s): console.appendPlainText(s)

    def populate_tree():
        tree.clear()
        if not st["outdir"] or not os.path.isdir(st["outdir"]):
            return
        root = QTreeWidgetItem(tree, [os.path.basename(st["outdir"])])
        tree.addTopLevelItem(root)
        def add(parent, path):
            for n in sorted(os.listdir(path)):
                full = os.path.join(path, n)
                if os.path.isdir(full):
                    it = QTreeWidgetItem(parent, [n]); it.setData(0, 1, full); add(it, full)
                else:
                    it = QTreeWidgetItem(parent, [n]); it.setData(0, 1, full)
        add(root, st["outdir"])

    def do_open():
        p, _ = QFileDialog.getOpenFileName(win, "打开 APK", "", "APK (*.apk);;All (*.*)")
        if not p:
            return
        st["apk"] = p; st["outdir"] = os.path.splitext(p)[0] + "_out"
        path_lbl.setText(p)
        rc, out = run_tool(APKTOOL, ["d", p, "-o", st["outdir"]])
        log("$ apktool d\n" + out + "\n[rc=%d]" % rc)
        populate_tree()

    def on_tree():
        it = tree.currentItem()
        if not it:
            return
        path = it.data(0, 1)
        if path and os.path.isfile(path):
            try:
                editor.setPlainText(open(path, encoding="utf-8", errors="replace").read())
            except Exception as ex:
                editor.setPlainText("// 无法打开: %s" % ex)

    def do_build():
        if not st["outdir"]:
            QMessageBox.warning(win, "提示", "请先反编译"); return
        out = os.path.splitext(st["apk"])[0] + "_built.apk"
        rc, o = run_tool(APKTOOL, ["b", st["outdir"], "-o", out])
        log("$ apktool b\n" + o + "\n[rc=%d]" % rc)

    def do_sign():
        if not st["apk"]:
            QMessageBox.warning(win, "提示", "请先打开"); return
        built = os.path.splitext(st["apk"])[0] + "_built.apk"
        src = built if os.path.exists(built) else st["apk"]
        out = os.path.splitext(st["apk"])[0] + "_signed.apk"
        rc, o = run_tool(MULTITOOL, ["sign", src, out])
        log("$ sign\n" + o + "\n[rc=%d]" % rc)

    tree.itemSelectionChanged.connect(on_tree)
    b_open.clicked.connect(do_open); b_build.clicked.connect(do_build); b_sign.clicked.connect(do_sign)

    if len(argv) > 1 and os.path.exists(argv[1]):
        st["apk"] = argv[1]; path_lbl.setText(argv[1])
    win.statusBar().showMessage("就绪"); win.show(); sys.exit(app.exec())


def selftest():
    ok = 0; fail = 0
    def check(n, c):
        nonlocal ok, fail
        print("  [%s] %s" % ("OK " if c else "ERR", n)); ok += 1 if c else 0; fail += 0 if c else 1
    check("BASE 存在", os.path.isdir(BASE))
    check("apktool 存在", os.path.exists(APKTOOL))
    check("multitool 存在", os.path.exists(MULTITOOL))
    rc, _ = run_tool(APKTOOL, ["--selftest"])
    check("apktool selftest rc=0", rc == 0)
    print("结果: %d 通过, %d 失败" % (ok, fail))
    return 0 if fail == 0 else 1


def main():
    a = sys.argv[1:]
    if "--selftest" in a:
        return selftest()
    run_gui(a)


if __name__ == "__main__":
    sys.exit(main() or 0)