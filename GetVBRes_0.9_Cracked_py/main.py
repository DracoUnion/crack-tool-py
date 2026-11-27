#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GetVBRes 0.8.2 (ResTools - GetVBRes, Rainbow Workshop, 2001-2003)  ->  PySide6 重写版
================================================================================
逆向依据 (ASPack + .wynney 双层压缩, x32dbg 脱壳 + 字符串导出):
  原 32位 Delphi 程序被 ASPack 压缩, 且 .wynney 节为第二层壳; x32dbg 加载
  EP `push OEP; call` 解压, 跑到消息循环后 DUMP 取得脱壳镜像, 字符串:
    - 身份: ProductName "ResTools - GetVBRes", InternalName "GetVBRes",
      FileVersion 0.8.2.0, LegalCopyright "2001-2003", FileDescription "VB ";
    - Delphi 窗体类: TMAINFORM / TIMGFORM / TFINDFORM / TADVFILTERFORM /
      TREGFORM / TSETFORM / TSTRFORM (MDI 多窗体);
    - 批处理: OPENFOLDER / CURRENTFOLDER / CLOSEDFOLDER, KNOWNFILE/UNKNOWNFILE,
      DXTOOL_SAVE, MAINICON.
  => 结论: 从 Visual Basic 6 生成的 EXE/DLL 中提取内嵌资源 (窗体/图片/字符串/
     清单) 的工具, 支持单文件与文件夹批处理.

  本 PySide6 重写 (纯标准库 + PySide6, main.py 唯一入口) 复刻核心:
    - 解析 PE 资源目录, 识别 VB6 程序 (VB5!/VB6! 头 / VBHeader);
    - 抽取 RT_RCDATA / 图片 / 字符串 / 版本 / manifest 等资源到输出目录;
    - 扫描内嵌 JPEG/PNG/GIF 图片并落盘 (VB 常把图片存为 RCDATA);
    - 文件夹批处理 (等价 OPENFOLDER/CURRENTFOLDER), 进度与日志.

用法:  python main.py            # GUI
       python main.py --selftest # 自检
       python main.py file.exe   # 提取
"""
import sys
import os
import struct

import PySide6
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QFileDialog, QMessageBox, QPlainTextEdit, QProgressBar, QCheckBox,
    QStatusBar,
)
from PySide6.QtCore import Qt


def u16(b, o): return struct.unpack_from("<H", b, o)[0]
def u32(b, o): return struct.unpack_from("<I", b, o)[0]
def u64(b, o): return struct.unpack_from("<Q", b, o)[0]

RT_NAMES = {1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG",
            6: "STRING", 9: "ACCELERATOR", 10: "RCDATA", 12: "GROUP_CURSOR",
            14: "GROUP_ICON", 16: "VERSION", 24: "MANIFEST"}

IMG_SIGS = [(b"\xFF\xD8\xFF", "jpg"), (b"\x89PNG\r\n\x1a\n", "png"),
            (b"GIF8", "gif"), (b"BM", "bmp")]


def detect_image(blob):
    for sig, ext in IMG_SIGS:
        if blob.startswith(sig):
            return ext
    return None


class PE:
    def __init__(self, data):
        self.d = data
        self.valid = False
        self.is_vb = False
        self.bits = 32
        if data[:2] != b"MZ":
            return
        e = u32(data, 0x3c)
        if data[e:e + 4] != b"PE\x00\x00":
            return
        opt = e + 24
        self.bits = 64 if u16(data, opt) == 0x20b else 32
        ndd = u32(data, opt + (108 if self.bits == 64 else 92))
        dd = opt + (112 if self.bits == 64 else 96)
        self.res_rva = u32(data, dd + 16) if ndd >= 3 else 0
        nsec = u16(data, e + 6); optsz = u16(data, e + 20)
        secoff = opt + optsz
        self.sections = []
        for i in range(nsec):
            o = secoff + i * 40
            self.sections.append((u32(data, o + 12), u32(data, o + 8), u32(data, o + 20), u32(data, o + 16)))
        # VB6 detection
        self.is_vb = (b"VB5!" in data[:0x400] or b"VB6!" in data[:0x400] or
                      b"VBHeader" in data or b"MSVBVM60" in data or b"MSVBVM50" in data)
        self.valid = True

    def rva2off(self, rva):
        for va, vsz, raw, rsz in self.sections:
            if va <= rva < va + max(vsz, rsz):
                return raw + (rva - va)
        return None

    def resources(self):
        out = []
        if not self.res_rva:
            return out
        base = self.rva2off(self.res_rva)
        if base is None:
            return out
        d = self.d
        for tname_id, tsub in self._dir(base):
            tname = RT_NAMES.get(tname_id, str(tname_id)) if isinstance(tname_id, int) else tname_id
            for n_id, nsub in self._dir(base + (tsub & 0x7fffffff)):
                for lang, dataent in self._dir(base + (nsub & 0x7fffffff)):
                    doff = base + dataent
                    if doff + 8 > len(d):
                        continue
                    rva = u32(d, doff); size = u32(d, doff + 4)
                    off = self.rva2off(rva)
                    blob = d[off:off + size] if off is not None else b""
                    out.append((tname, n_id, lang, blob))
        return out

    def _dir(self, base):
        d = self.d
        if base < 0 or base + 16 > len(d):
            return []
        nnamed = u16(d, base + 12); nid = u16(d, base + 14)
        res = []
        for i in range(nnamed + nid):
            o = base + 16 + i * 8
            if o + 8 > len(d):
                break
            name = u32(d, o); off = u32(d, o + 4)
            if name & 0x80000000:
                no = base + (name & 0x7fffffff)
                if no + 2 > len(d):
                    continue
                ln = u16(d, no)
                nm = d[no + 2:no + 2 + ln * 2].decode("utf-16le", "ignore")
            else:
                nm = name
            res.append((nm, off))
        return res


def extract_exe(path, outdir, log):
    data = open(path, "rb").read()
    pe = PE(data)
    if not pe.valid:
        log.append("  not a PE: %s" % path); return 0
    base = os.path.join(outdir, os.path.splitext(os.path.basename(path))[0])
    os.makedirs(base, exist_ok=True)
    cnt = 0
    log.append("  %s  VB6=%s  resources..." % (os.path.basename(path), pe.is_vb))
    for tname, name, lang, blob in pe.resources():
        if not blob:
            continue
        ext = detect_image(blob)
        if ext:
            fn = "%s_%s.%s" % (tname, name, ext)
            open(os.path.join(base, fn), "wb").write(blob); cnt += 1
        elif tname in ("RCDATA", "VERSION", "MANIFEST", "STRING", "BITMAP", "ICON"):
            fn = "%s_%s_%s.bin" % (tname, name, lang)
            open(os.path.join(base, fn), "wb").write(blob); cnt += 1
    # 扫描内嵌图片 (不在资源目录里的)
    for sig, ext in IMG_SIGS:
        i = data.find(sig)
        while i >= 0:
            end = data.find(b"\x00", i)
            open(os.path.join(base, "scan_%08X.%s" % (i, ext)), "wb").write(data[i:i + 4096])
            i = data.find(sig, i + 1)
            cnt += 1
            if cnt > 2000:
                break
    log.append("  -> %d files to %s" % (cnt, base))
    return cnt


class GetVBResWindow(QMainWindow):
    def __init__(self, path=None):
        super().__init__()
        self.setWindowTitle("GetVBRes 0.8 (PySide6 重写版) — ResTools")
        self.resize(820, 560)
        self._build_ui()
        self.statusBar().showMessage("GetVBRes ready.")
        if path:
            self.do_file(path)

    def _build_ui(self):
        c = QWidget(); self.setCentralWidget(c); lay = QVBoxLayout(c)
        bar = QHBoxLayout()
        self.btn_file = QPushButton("提取单文件..."); self.btn_file.clicked.connect(lambda: self.do_file(None))
        self.btn_dir = QPushButton("文件夹批处理..."); self.btn_dir.clicked.connect(self.do_dir)
        self.btn_out = QPushButton("输出目录..."); self.btn_out.clicked.connect(self.pick_out)
        for w in (self.btn_file, self.btn_dir, self.btn_out):
            bar.addWidget(w)
        bar.addStretch(); lay.addLayout(bar)
        self.pb = QProgressBar(); lay.addWidget(self.pb)
        self.log = QPlainTextEdit(); self.log.setReadOnly(True); lay.addWidget(self.log, 1)
        self.outdir = os.path.join(os.getcwd(), "_getvbres_out")

    def pick_out(self):
        d = QFileDialog.getExistingDirectory(self, "Output")
        if d:
            self.outdir = d

    def do_file(self, path):
        if not path:
            fn, _ = QFileDialog.getOpenFileName(self, "Open VB exe", "PE (*.exe *.dll)")
            if not fn:
                return
            path = fn
        self.log.clear()
        lines = []
        n = extract_exe(path, self.outdir, lines)
        self.log.setPlainText("\n".join(lines))
        self.statusBar().showMessage("Extracted %d from %s" % (n, os.path.basename(path)))

    def do_dir(self):
        d = QFileDialog.getExistingDirectory(self, "Folder with VB exes")
        if not d:
            return
        self.log.clear(); lines = []
        exes = [os.path.join(d, f) for f in os.listdir(d) if f.lower().endswith((".exe", ".dll"))]
        total = 0
        for i, f in enumerate(exes, 1):
            total += extract_exe(f, self.outdir, lines)
            self.pb.setMaximum(len(exes)); self.pb.setValue(i)
        self.log.setPlainText("\n".join(lines))
        self.statusBar().showMessage("Batch done: %d files from %d exes" % (total, len(exes)))


def selftest():
    # 构造含 VB6 标识 + 一个 PNG 资源的 PE
    d = bytearray(0x600)
    d[0:2] = b"MZ"; struct.pack_into("<I", d, 0x3c, 0x80)
    d[0x80:0x84] = b"PE\x00\x00"; struct.pack_into("<H", d, 0x84, 0x14c)
    struct.pack_into("<H", d, 0x86, 1); struct.pack_into("<H", d, 0x94, 0xE0)
    opt = 0x98; struct.pack_into("<H", d, opt, 0x10b)
    struct.pack_into("<I", d, opt + 28, 0x400000); struct.pack_into("<I", d, opt + 92, 16)
    secoff = opt + 0xE0
    struct.pack_into("<8s", d, secoff, b".rsrc\x00\x00\x00")
    struct.pack_into("<I", d, secoff + 8, 0x1000); struct.pack_into("<I", d, secoff + 12, 0x1000)
    struct.pack_into("<I", d, secoff + 16, 0x200); struct.pack_into("<I", d, secoff + 20, 0x400)
    struct.pack_into("<I", d, opt + 96 + 16, 0x1000)
    d[0x300:0x305] = b"VB6!"; d[0x305:0x309] = b"VB6!"
    r = 0x400
    struct.pack_into("<H", d, r + 14, 1)
    struct.pack_into("<I", d, r + 16, 10); struct.pack_into("<I", d, r + 20, 0x80000000 | 0x20)
    struct.pack_into("<H", d, r + 0x20 + 14, 1)
    struct.pack_into("<I", d, r + 0x20 + 16, 1); struct.pack_into("<I", d, r + 0x20 + 20, 0x80000000 | 0x40)
    struct.pack_into("<H", d, r + 0x40 + 14, 1)
    struct.pack_into("<I", d, r + 0x40 + 16, 0x409); struct.pack_into("<I", d, r + 0x40 + 20, 0x60)
    png = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
    struct.pack_into("<I", d, r + 0x60, 0x1100); struct.pack_into("<I", d, r + 0x64, len(png))
    d[r + 0x100:r + 0x100 + len(png)] = png
    pe = PE(bytes(d))
    assert pe.valid and pe.is_vb
    res = pe.resources()
    assert any(t == "RCDATA" and detect_image(b) == "png" for t, n, l, b in res)
    print("[selftest] GetVBRes VB detect + resource/image scan OK; is_vb=%s res=%d" % (pe.is_vb, len(res)))


def main():
    if "--selftest" in sys.argv:
        selftest(); return
    files = [a for a in sys.argv[1:] if not a.startswith("-")]
    app = QApplication(sys.argv)
    w = GetVBResWindow(files[0] if files else None); w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()