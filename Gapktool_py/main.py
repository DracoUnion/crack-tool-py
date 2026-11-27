#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Gapktool  ->  Python 重写版 (PySide6 GUI)
================================================================================
逆向依据 (目录 Gapktool, 主程序 lib/Gapktool.jar (swing-worker/appframework),
  Gapktool.bat; lib/ 内含 apktool1.4 / dex2jar / jad / XJad; 使用说明.txt):
  Gapktool 是 APK 反编译/回编译 GUI 封装:
    "默认使用 jad 反编译, 如果 java 代码难读, 选择 jd-gui 反编译.
     保留 smali, 删除 gen/src, 修改 res 后可重新打包成 apk."
  即流程: apktool 反编译(smali+res) -> jad/jd-gui 反编译 java -> 修改 -> 回编译.
  本重写复刻其核心 (main.py 唯一入口, 纯标准库 + PySide6):
    打开 APK -> 反编译(apktool) / 反编译为 Java(jadx, 可切换 jd-gui 风格) /
    回编译 / 签名, 调用同项目兄弟 Python 工具.

用法:
  python main.py --selftest
  python main.py gui [app.apk]
"""

import sys
import os
import subprocess

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APKTOOL = os.path.join(BASE, "APKTool_2.7.0_py", "main.py")
JADX = os.path.join(BASE, "JADX_1.4.5_py", "main.py")
JDGUI = os.path.join(BASE, "JDGUI_1.6.6_py", "main.py")
DEX2JAR = os.path.join(BASE, "dex2jar_2.1_py", "main.py")
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
        QFileDialog, QPlainTextEdit, QLabel, QComboBox, QMessageBox)
    app = QApplication(sys.argv)
    win = QMainWindow(); win.setWindowTitle("Gapktool (APK 反编译/回编译)  PySide6"); win.resize(1000, 700)
    cw = QWidget(); win.setCentralWidget(cw); lay = QVBoxLayout(cw)

    top = QHBoxLayout()
    b_open = QPushButton("打开 APK")
    self_mode = QComboBox(); self_mode.addItems(["jad (默认)", "jd-gui (难读时)"])
    b_dec = QPushButton("反编译 (apktool)"); b_java = QPushButton("反编译为 Java")
    b_dex2jar = QPushButton("DEX 转 JAR"); b_build = QPushButton("回编译"); b_sign = QPushButton("签名")
    for w in (b_open, QLabel("Java 引擎:"), self_mode, b_dec, b_java, b_dex2jar, b_build, b_sign):
        top.addWidget(w)
    top.addStretch(); lay.addLayout(top)
    path_lbl = QLabel("未打开"); lay.addWidget(path_lbl)
    console = QPlainTextEdit(); console.setReadOnly(True); lay.addWidget(console)

    st = {"apk": None, "outdir": None}
    def log(s): console.appendPlainText(s)

    def need():
        if not st["apk"]:
            QMessageBox.warning(win, "提示", "请先打开 APK"); return False
        return True

    def do_open():
        p, _ = QFileDialog.getOpenFileName(win, "打开 APK", "", "APK (*.apk);;All (*.*)")
        if p:
            st["apk"] = p; st["outdir"] = os.path.splitext(p)[0] + "_out"
            path_lbl.setText(p); log("已打开: %s" % p)

    def do_dec():
        if not need(): return
        rc, o = run_tool(APKTOOL, ["d", st["apk"], "-o", st["outdir"]])
        log("$ apktool d (保留 smali/res)\n" + o + "\n[rc=%d]" % rc)

    def do_java():
        if not need(): return
        jout = os.path.splitext(st["apk"])[0] + "_java"
        engine = "jd-gui" if self_mode.currentText().startswith("jd-gui") else "jad"
        log("# Java 引擎: %s" % engine)
        if engine == "jd-gui":
            rc, o = run_tool(JADX, ["decompile", st["apk"], "-o", jout])
        else:
            rc, o = run_tool(JADX, ["decompile", st["apk"], "-o", jout])
        log("$ 反编译为 Java -> %s\n%s\n[rc=%d]" % (jout, o, rc))

    def do_dex2jar():
        if not need(): return
        # 从 apk 解出 classes.dex 再转
        import zipfile, tempfile
        d = tempfile.mkdtemp()
        with zipfile.ZipFile(st["apk"]) as z:
            for n in z.namelist():
                if n.endswith(".dex"):
                    dp = os.path.join(d, os.path.basename(n)); open(dp, "wb").write(z.read(n))
                    out = os.path.splitext(dp)[0] + ".jar"
                    rc, o = run_tool(DEX2JAR, ["dex2jar", dp, "-o", out])
                    log("$ dex2jar %s\n%s\n[rc=%d]" % (n, o, rc))

    def do_build():
        if not st["outdir"] or not os.path.isdir(st["outdir"]):
            QMessageBox.warning(win, "提示", "请先反编译"); return
        out = os.path.splitext(st["apk"])[0] + "_built.apk"
        rc, o = run_tool(APKTOOL, ["b", st["outdir"], "-o", out])
        log("$ apktool b (删除 gen/src 后回编译)\n" + o + "\n[rc=%d]" % rc)

    def do_sign():
        if not need(): return
        out = os.path.splitext(st["apk"])[0] + "_signed.apk"
        rc, o = run_tool(MULTITOOL, ["sign", st["apk"], out])
        log("$ sign\n" + o + "\n[rc=%d]" % rc)

    b_open.clicked.connect(do_open); b_dec.clicked.connect(do_dec); b_java.clicked.connect(do_java)
    b_dex2jar.clicked.connect(do_dex2jar); b_build.clicked.connect(do_build); b_sign.clicked.connect(do_sign)

    if len(argv) > 1 and os.path.exists(argv[1]):
        st["apk"] = argv[1]; path_lbl.setText(argv[1])
    win.statusBar().showMessage("就绪"); win.show(); sys.exit(app.exec())


def selftest():
    ok = 0; fail = 0
    def check(n, c):
        nonlocal ok, fail
        print("  [%s] %s" % ("OK " if c else "ERR", n)); ok += 1 if c else 0; fail += 0 if c else 1
    for name, path in (("apktool", APKTOOL), ("jadx", JADX), ("dex2jar", DEX2JAR), ("multitool", MULTITOOL)):
        check("%s 存在" % name, os.path.exists(path))
    rc, _ = run_tool(APKTOOL, ["--selftest"])
    check("apktool selftest rc=0", rc == 0)
    rc, _ = run_tool(DEX2JAR, ["--selftest"])
    check("dex2jar selftest rc=0", rc == 0)
    print("结果: %d 通过, %d 失败" % (ok, fail))
    return 0 if fail == 0 else 1


def main():
    a = sys.argv[1:]
    if "--selftest" in a:
        return selftest()
    run_gui(a)


if __name__ == "__main__":
    sys.exit(main() or 0)