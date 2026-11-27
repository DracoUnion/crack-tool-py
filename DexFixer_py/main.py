#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DexFixer  ->  Python 重写版 (CLI + PySide6 GUI)
================================================================================
逆向依据 (目录主程序 DexFixer.exe, PE32 GUI, 34 KB, VC++2008 MFC):
  ASCII 字符串确认身份:
    ".?AVCDexFixerApp@@" / ".?AVCDexFixerDlg@@"   (MFC 对话框应用类)
    "Dex Files(*.dex)|*.dex|All Files(*.*)|*.*||"
    "checksum" , "DragAcceptFiles" , "DexFixer"
    "e:\\VCProject\\DexFixer\\Release\\DexFixer.pdb"
  -> 一个 MFC 对话框工具: 选择/拖入 .dex, 修复其头部校验 (checksum) 等字段.

DEX 文件头 (little-endian, 0x70 字节) 关键字段:
  0x00  magic[8]        "dex\n035\0" (旧版 009/0A 等)
  0x08  checksum        u32  Adler32 覆盖 [12, file_size)
  0x0C  signature[20]   SHA-1   覆盖 [32, file_size)
  0x20  file_size       u32
  0x24  header_size     u32 (=0x70)
  0x28  endian_tag      u32 (=0x12345678)
  0x2C  link_size/off
  0x34  map_off
  0x38  string_ids_size/off ... data_size/off
本工具复刻其修复核心 (main.py 唯一入口, 纯标准库):
  - 修正 magic
  - 修正 header_size / endian_tag
  - 用实际文件长度修正 file_size
  - 重算 SHA-1 signature (覆盖 [32, file_size))
  - 重算 Adler32 checksum (覆盖 [12, file_size))

用法:
  python main.py                 # 启动 GUI
  python main.py --selftest
  python main.py fix <in.dex> [out.dex]      # 修复 (默认覆盖/另存)
  python main.py info <file.dex>             # 显示头部信息
"""

import sys
import os
import zlib
import struct
import hashlib

DEX_MAGIC = b"dex\n035\0"
HEADER_SIZE = 0x70
ENDIAN_TAG = 0x12345678


class DexError(Exception):
    pass


def adler32(data):
    return zlib.adler32(data) & 0xFFFFFFFF


def sha1(data):
    return hashlib.sha1(data).digest()


def parse_header(data):
    if len(data) < HEADER_SIZE:
        raise DexError("文件太小, 不足 0x70 字节头部")
    h = {}
    h["magic"] = data[0:8]
    (h["checksum"],) = struct.unpack_from("<I", data, 0x08)
    h["signature"] = data[0x0C:0x20]
    (h["file_size"], h["header_size"], h["endian_tag"]) = struct.unpack_from("<III", data, 0x20)
    (h["link_size"], h["link_off"]) = struct.unpack_from("<II", data, 0x2C)
    (h["map_off"],) = struct.unpack_from("<I", data, 0x34)
    (h["string_ids_size"], h["string_ids_off"]) = struct.unpack_from("<II", data, 0x38)
    (h["data_size"], h["data_off"]) = struct.unpack_from("<II", data, 0x68)
    return h


def fix_data(data, fix_magic=True, fix_checksum=True, fix_signature=True,
             fix_size=True, fix_header=True):
    """返回 (fixed_bytes, report_lines)。不修改入参。"""
    if len(data) < HEADER_SIZE:
        raise DexError("文件太小, 不足 0x70 字节头部")
    buf = bytearray(data)
    report = []

    # 1. magic
    if fix_magic and bytes(buf[0:8]) != DEX_MAGIC:
        # 保留版本号 (035/037/038/039), 仅修正 "dex\n" 前缀与结尾 NUL
        ver = bytes(buf[4:7]) if buf[4:7].isdigit() else b"035"
        new_magic = b"dex\n" + ver + b"\0"
        report.append("magic: %r -> %r" % (bytes(buf[0:8]), new_magic))
        buf[0:8] = new_magic

    # 2. file_size 先修正 (后续 checksum/signature 覆盖范围依赖它)
    actual = len(buf)
    (old_fsize,) = struct.unpack_from("<I", buf, 0x20)
    if fix_size and old_fsize != actual:
        struct.pack_into("<I", buf, 0x20, actual)
        report.append("file_size: 0x%x -> 0x%x" % (old_fsize, actual))
    file_size = struct.unpack_from("<I", buf, 0x20)[0]
    if file_size > len(buf):
        # 头部声明的 size 超过实际, 用实际长度兜底以便继续修复
        struct.pack_into("<I", buf, 0x20, len(buf))
        file_size = len(buf)
        report.append("file_size 超出实际, 强制为 0x%x" % file_size)

    # 3. header_size / endian_tag
    if fix_header:
        (old_hs,) = struct.unpack_from("<I", buf, 0x24)
        if old_hs != HEADER_SIZE:
            struct.pack_into("<I", buf, 0x24, HEADER_SIZE)
            report.append("header_size: 0x%x -> 0x%x" % (old_hs, HEADER_SIZE))
        (old_et,) = struct.unpack_from("<I", buf, 0x28)
        if old_et != ENDIAN_TAG:
            struct.pack_into("<I", buf, 0x28, ENDIAN_TAG)
            report.append("endian_tag: 0x%x -> 0x12345678" % old_et)

    # 4. SHA-1 signature 覆盖 [32, file_size)
    if fix_signature:
        new_sig = sha1(bytes(buf[32:file_size]))
        old_sig = bytes(buf[0x0C:0x20])
        if old_sig != new_sig:
            buf[0x0C:0x20] = new_sig
            report.append("signature: %s -> %s" % (old_sig.hex(), new_sig.hex()))

    # 5. Adler32 checksum 覆盖 [12, file_size)
    if fix_checksum:
        new_ck = adler32(bytes(buf[12:file_size]))
        (old_ck,) = struct.unpack_from("<I", buf, 0x08)
        struct.pack_into("<I", buf, 0x08, new_ck)
        if old_ck != new_ck:
            report.append("checksum: 0x%08x -> 0x%08x" % (old_ck, new_ck))

    if not report:
        report.append("无需修复 (头部校验已正确)")
    return bytes(buf), report


def info_text(data):
    h = parse_header(data)
    lines = []
    lines.append("magic        : %r" % h["magic"])
    lines.append("checksum     : 0x%08x" % h["checksum"])
    lines.append("signature    : %s" % h["signature"].hex())
    lines.append("file_size    : 0x%x (%d)  实际: %d" % (h["file_size"], h["file_size"], len(data)))
    lines.append("header_size  : 0x%x" % h["header_size"])
    lines.append("endian_tag   : 0x%08x" % h["endian_tag"])
    lines.append("map_off      : 0x%x" % h["map_off"])
    lines.append("string_ids   : size=%d off=0x%x" % (h["string_ids_size"], h["string_ids_off"]))
    lines.append("data         : size=0x%x off=0x%x" % (h["data_size"], h["data_off"]))
    # 校验当前实际值
    actual_sig = sha1(data[32:h["file_size"]]) if h["file_size"] <= len(data) else b""
    actual_ck = adler32(data[12:h["file_size"]]) if h["file_size"] <= len(data) else 0
    lines.append("期望 signature: %s  %s" % (actual_sig.hex(), "(匹配)" if actual_sig == h["signature"] else "(不匹配)"))
    lines.append("期望 checksum : 0x%08x  %s" % (actual_ck, "(匹配)" if actual_ck == h["checksum"] else "(不匹配)"))
    return "\n".join(lines)


# ============================================================ GUI
def run_gui():
    from PySide6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
        QLabel, QPlainTextEdit, QFileDialog, QMessageBox,
    )
    app = QApplication(sys.argv)
    win = QMainWindow(); win.setWindowTitle("DexFixer (DEX 头部校验修复)  PySide6")
    win.resize(820, 560)
    cw = QWidget(); win.setCentralWidget(cw); lay = QVBoxLayout(cw)

    path_lbl = QLabel("未选择文件"); lay.addWidget(path_lbl)
    row = QHBoxLayout()
    b_open = QPushButton("打开 DEX"); b_fix = QPushButton("修复"); b_save = QPushButton("另存为")
    b_info = QPushButton("查看头部")
    for b in (b_open, b_fix, b_info, b_save):
        row.addWidget(b)
    row.addStretch(); lay.addLayout(row)

    out = QPlainTextEdit(); out.setReadOnly(True); lay.addWidget(out)

    state = {"path": None, "data": None, "fixed": None}

    def load(path):
        state["path"] = path
        state["data"] = open(path, "rb").read()
        state["fixed"] = None
        path_lbl.setText(path)
        out.setPlainText(info_text(state["data"]))

    def do_open():
        p, _ = QFileDialog.getOpenFileName(win, "选择 DEX", "", "Dex Files(*.dex);;All Files(*.*)")
        if p:
            try:
                load(p)
            except Exception as e:
                QMessageBox.critical(win, "错误", str(e))

    def do_fix():
        if not state["data"]:
            QMessageBox.warning(win, "提示", "请先打开 DEX"); return
        try:
            fixed, report = fix_data(state["data"])
            state["fixed"] = fixed
            out.setPlainText("修复报告:\n" + "\n".join(report) +
                             "\n\n修复后头部:\n" + info_text(fixed))
        except Exception as e:
            QMessageBox.critical(win, "错误", str(e))

    def do_save():
        data = state["fixed"] or state["data"]
        if not data:
            QMessageBox.warning(win, "提示", "无数据"); return
        p, _ = QFileDialog.getSaveFileName(win, "保存 DEX", "", "Dex Files(*.dex)")
        if p:
            open(p, "wb").write(data)
            win.statusBar().showMessage("已保存: %s" % p)

    b_open.clicked.connect(do_open)
    b_fix.clicked.connect(do_fix)
    b_save.clicked.connect(do_save)
    b_info.clicked.connect(lambda: state["data"] and out.setPlainText(info_text(state["data"])))
    win.statusBar().showMessage("就绪")
    win.show(); sys.exit(app.exec())


# ============================================================ CLI / 自检
def selftest():
    # 构造一个最小合法 dex 头 + 数据, 破坏校验后修复
    buf = bytearray(HEADER_SIZE + 16)
    buf[0:8] = DEX_MAGIC
    struct.pack_into("<I", buf, 0x20, len(buf))      # file_size
    struct.pack_into("<I", buf, 0x24, HEADER_SIZE)   # header_size
    struct.pack_into("<I", buf, 0x28, ENDIAN_TAG)    # endian_tag
    struct.pack_into("<I", buf, 0x68, 16)            # data_size
    struct.pack_into("<I", buf, 0x6C, HEADER_SIZE)   # data_off
    for i in range(HEADER_SIZE, len(buf)):
        buf[i] = i & 0xFF
    # 正确签名/校验
    buf[0x0C:0x20] = sha1(bytes(buf[32:]))
    struct.pack_into("<I", buf, 0x08, adler32(bytes(buf[12:])))
    good = bytes(buf)

    ok = 0; fail = 0
    def check(name, cond):
        nonlocal ok, fail
        print("  [%s] %s" % ("OK " if cond else "ERR", name))
        if cond: ok += 1
        else: fail += 1

    # 破坏后再修复
    broken = bytearray(good)
    broken[0:4] = b"XXXX"                       # 坏 magic
    struct.pack_into("<I", broken, 0x08, 0)     # 坏 checksum
    broken[0x0C:0x20] = b"\x00" * 20            # 坏 signature
    struct.pack_into("<I", broken, 0x20, 999)   # 坏 file_size
    fixed, report = fix_data(bytes(broken))
    check("修复后等于原始", fixed == good)
    check("magic 恢复", fixed[0:8] == DEX_MAGIC)
    check("checksum 正确", struct.unpack_from("<I", fixed, 0x08)[0] == adler32(fixed[12:]))
    check("signature 正确", fixed[0x0C:0x20] == sha1(fixed[32:]))
    check("file_size 正确", struct.unpack_from("<I", fixed, 0x20)[0] == len(fixed))
    print("结果: %d 通过, %d 失败" % (ok, fail))
    return 0 if fail == 0 else 1


def main():
    args = sys.argv[1:]
    if "--selftest" in args:
        return selftest()
    if not args or args[0] in ("-h", "--help"):
        print(__doc__); return 0
    cmd = args[0]
    if cmd == "fix":
        if len(args) < 2:
            print("用法: python main.py fix <in.dex> [out.dex]"); return 2
        inp = args[1]
        outp = args[2] if len(args) > 2 else inp
        data = open(inp, "rb").read()
        fixed, report = fix_data(data)
        open(outp, "wb").write(fixed)
        print("\n".join(report))
        print("已写入: %s" % outp)
        return 0
    if cmd == "info":
        print(info_text(open(args[1], "rb").read())); return 0
    run_gui()


if __name__ == "__main__":
    sys.exit(main() or 0)