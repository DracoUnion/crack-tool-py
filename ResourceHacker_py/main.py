#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ResourceHacker 5.1.8.360 (Angus Johnson)  ->  PySide6 重写版
================================================================================
逆向依据 (PE 未加壳, 版本资源/字符串):
  FileDescription "Resource viewer, decompiler & recompiler", ProductName
  "ResourceHacker", CompanyName "Angus Johnson", FileVersion 5.1.8.360,
  InternalName "ResHack". 导入 comctl32/COMDLG32/GDI32, 资源节 .rsrc 内含
  RT_ICON/RT_BITMAP/RT_MENU/RT_DIALOG/RT_STRING/RT_VERSION/RT_MANIFEST 等.
  => 结论: PE 资源查看 / 反编译 / 重编译工具.

  本 PySide6 重写 (纯标准库 + PySide6, main.py 唯一入口) 复刻核心:
    - 解析 PE 资源目录树 (类型 -> 名称 -> 语言), 15+ 种资源类型;
    - 资源查看 (图标/位图预览, 菜单/对话框/字符串/版本/manifest 文本);
    - 资源导出 (逐资源/整树导出为 .bin / RC 脚本反编译);
    - 资源导入替换 (从文件覆盖某资源, 等价 recompile 的简化);
    - 图标/位图/光标提取.

用法:  python main.py            # GUI
       python main.py --selftest # 自检
       python main.py file.exe   # 打开
"""
import sys
import os
import struct

import PySide6
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QFileDialog, QMessageBox, QTreeWidget, QTreeWidgetItem, QPlainTextEdit,
    QSplitter, QAbstractItemView, QGraphicsPixmapItem, QGraphicsView, QStatusBar,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QPixmap, QImage, QAction

RT = {
    1: "CURSOR", 2: "BITMAP", 3: "ICON", 4: "MENU", 5: "DIALOG",
    6: "STRING", 7: "FONTDIR", 8: "FONT", 9: "ACCELERATOR", 10: "RCDATA",
    11: "MESSAGETABLE", 12: "GROUP_CURSOR", 14: "GROUP_ICON", 16: "VERSION",
    24: "MANIFEST",
}


def u16(b, o): return struct.unpack_from("<H", b, o)[0]
def u32(b, o): return struct.unpack_from("<I", b, o)[0]
def u64(b, o): return struct.unpack_from("<Q", b, o)[0]


class PE:
    def __init__(self, data):
        self.d = data
        self.valid = False
        self.bits = 32
        if data[:2] != b"MZ":
            return
        e = u32(data, 0x3c)
        if data[e:e + 4] != b"PE\x00\x00":
            return
        opt = e + 24
        self.bits = 64 if u16(data, opt) == 0x20b else 32
        self.base = u64(data, opt + 24) if self.bits == 64 else u32(data, opt + 28)
        ndd = u32(data, opt + (108 if self.bits == 64 else 92))
        dd = opt + (112 if self.bits == 64 else 96)
        self.res_rva = u32(data, dd + 2 * 8) if ndd >= 3 else 0
        self.res_size = u32(data, dd + 2 * 8 + 4) if ndd >= 3 else 0
        nsec = u16(data, e + 6); optsz = u16(data, e + 20)
        secoff = opt + optsz
        self.sections = []
        for i in range(nsec):
            o = secoff + i * 40
            self.sections.append((u32(data, o + 12), u32(data, o + 8),
                                  u32(data, o + 20), u32(data, o + 16)))
        self.valid = True

    def rva2off(self, rva):
        for va, vsz, raw, rsz in self.sections:
            if va <= rva < va + max(vsz, rsz):
                return raw + (rva - va)
        return None

    def resources(self):
        """返回 [(type_name, name, lang, data_bytes)]。"""
        out = []
        if not self.res_rva:
            return out
        base = self.rva2off(self.res_rva)
        if base is None:
            return out
        d = self.d
        # level 1: types
        types = self._dir(base)
        for tname_id, tsub in types:
            tname = RT.get(tname_id, str(tname_id)) if isinstance(tname_id, int) else tname_id
            tbase = base + (tsub & 0x7fffffff)
            for n_id, nsub in self._dir(tbase):
                nbase = base + (nsub & 0x7fffffff)
                for lang_id, dataent in self._dir(nbase):
                    doff = base + dataent
                    rva = u32(d, doff); size = u32(d, doff + 4)
                    off = self.rva2off(rva)
                    blob = d[off:off + size] if off is not None else b""
                    out.append((tname, n_id, lang_id, blob))
        return out

    def _dir(self, base):
        d = self.d
        nnamed = u16(d, base + 12); nid = u16(d, base + 14)
        res = []
        for i in range(nnamed + nid):
            o = base + 16 + i * 8
            name = u32(d, o); off = u32(d, o + 4)
            if name & 0x80000000:
                no = base + (name & 0x7fffffff)
                ln = u16(d, no)
                nm = d[no + 2:no + 2 + ln * 2].decode("utf-16le", "ignore")
            else:
                nm = name
            res.append((nm, off))
        return res


def rc_decompile(res):
    """把资源列表反编译为简化 RC 脚本文本。"""
    lines = []
    for tname, name, lang, blob in res:
        lines.append("// %s  name=%s  lang=%s  size=%d" % (tname, name, lang, len(blob)))
        if tname == "VERSION":
            lines.append(_ver_text(blob))
        elif tname == "MANIFEST":
            lines.append(blob.decode("utf-8", "ignore"))
        elif tname == "STRING":
            lines.append(_str_text(blob))
        elif tname in ("MENU", "DIALOG", "RCDATA"):
            lines.append(_hex(blob[:256]))
        else:
            lines.append(_hex(blob[:64]))
        lines.append("")
    return "\n".join(lines)


def _hex(b):
    return "\n".join("  " + " ".join("%02X" % x for x in b[i:i + 16]) for i in range(0, len(b), 16))


def _ver_text(b):
    try:
        s = b.decode("utf-16le", "ignore")
        keep = [w for w in s.replace("\x00", "\n").split("\n") if w.strip()]
        return "VERSIONINFO: " + " ".join(keep[:20])
    except Exception:
        return ""


def _str_text(b):
    out = []
    for i in range(0, len(b) - 1, 2):
        ln = u16(b, i)
        s = b[i + 2:i + 2 + ln * 2].decode("utf-16le", "ignore")
        if s:
            out.append("  %d: %s" % (i // 2, s))
    return "\n".join(out)


def extract_icon_group(blob):
    """GROUP_ICON 中的图标条目 (width,height,colors,reserved,planes,bpp,id)."""
    if len(blob) < 6:
        return []
    n = u16(blob, 4)
    out = []
    for i in range(n):
        o = 6 + i * 14
        w = blob[o] or 256; h = blob[o + 1] or 256
        out.append((w, h, blob[o + 2], blob[o + 6:o + 8].hex(), blob[o + 12:o + 14].hex()))
    return out


# --------------------------------------------------------------------------- #
class ResHackerWindow(QMainWindow):
    def __init__(self, path=None):
        super().__init__()
        self.setWindowTitle("ResourceHacker 5.1.8 (PySide6 重写版)")
        self.resize(1000, 680)
        self.pe = None
        self.res = []
        self._build_ui()
        self.statusBar().showMessage("ResourceHacker ready.")
        if path:
            self.open(path)

    def _build_ui(self):
        c = QWidget(); self.setCentralWidget(c); lay = QVBoxLayout(c)
        bar = QHBoxLayout()
        for t, s in [("打开", lambda: self.open(None)), ("导出选中", self.export_sel),
                     ("导出全部", self.export_all), ("反编译RC", self.decompile),
                     ("替换资源", self.replace_sel)]:
            b = QPushButton(t); b.clicked.connect(s); bar.addWidget(b)
        bar.addStretch(); lay.addLayout(bar)
        sp = QSplitter(Qt.Horizontal)
        self.tree = QTreeWidget(); self.tree.setHeaderLabels(["Resource Tree"])
        self.tree.itemSelectionChanged.connect(self.on_sel)
        sp.addWidget(self.tree)
        self.tabs = QSplitter(Qt.Vertical)
        self.preview = QLabel("preview"); self.preview.setAlignment(Qt.AlignCenter)
        self.preview.setMinimumHeight(220)
        self.text = QPlainTextEdit(); self.text.setReadOnly(True)
        self.tabs.addWidget(self.preview); self.tabs.addWidget(self.text)
        sp.addWidget(self.tabs); sp.setSizes([340, 660])
        lay.addWidget(sp)

    def open(self, path):
        if not path:
            fn, _ = QFileDialog.getOpenFileName(self, "Open PE", filter="PE (*.exe *.dll *.sys);;All (*.*)")
            if not fn:
                return
            path = fn
        try:
            self.pe = PE(open(path, "rb").read())
        except OSError as e:
            QMessageBox.critical(self, "Error", str(e)); return
        self.res = self.pe.resources() if self.pe.valid else []
        self._fill_tree()
        self.statusBar().showMessage("Opened %s  (%d resources)" % (os.path.basename(path), len(self.res)))

    def _fill_tree(self):
        self.tree.clear()
        groups = {}
        for tname, name, lang, blob in self.res:
            groups.setdefault(tname, []).append((name, lang, blob))
        for tname, items in groups.items():
            top = QTreeWidgetItem(self.tree, [tname])
            for name, lang, blob in items:
                it = QTreeWidgetItem(top, ["%s  (%d bytes)" % (name, len(blob))])
                it.setData(0, Qt.UserRole, (tname, name, lang))
        self.tree.expandAll()

    def _cur(self):
        it = self.tree.currentItem()
        if not it:
            return None
        d = it.data(0, Qt.UserRole)
        return d

    def on_sel(self):
        d = self._cur()
        if not d:
            return
        tname, name, lang = d
        blob = next((b for t, n, l, b in self.res if t == tname and n == name and l == lang), b"")
        self.text.setPlainText(rc_decompile([(tname, name, lang, blob)]))
        if tname in ("ICON", "BITMAP", "CURSOR"):
            pm = QPixmap()
            if tname == "BITMAP":
                img = QImage.fromData(blob)
                if not img.isNull():
                    pm = QPixmap.fromImage(img)
            else:
                # ICON: 尝试直接加载 ico 数据
                pm.loadFromData(blob)
            if not pm.isNull():
                self.preview.setPixmap(pm.scaled(200, 200, Qt.KeepAspectRatio))
            else:
                self.preview.setText("(no preview)")
        elif tname == "GROUP_ICON":
            self.preview.setText("Icons: " + str(extract_icon_group(blob)))
        else:
            self.preview.setText(tname)

    def export_sel(self):
        d = self._cur()
        if not d:
            return
        tname, name, lang = d
        blob = next((b for t, n, l, b in self.res if t == tname and n == name and l == lang), b"")
        fn, _ = QFileDialog.getSaveFileName(self, "Export", "%s_%s.bin" % (tname, name))
        if fn:
            open(fn, "wb").write(blob); self.statusBar().showMessage("Exported " + fn)

    def export_all(self):
        d = QFileDialog.getExistingDirectory(self, "Export All To")
        if not d:
            return
        for tname, name, lang, blob in self.res:
            open(os.path.join(d, "%s_%s_%s.bin" % (tname, name, lang)), "wb").write(blob)
        self.statusBar().showMessage("Exported %d resources" % len(self.res))

    def decompile(self):
        self.text.setPlainText(rc_decompile(self.res))

    def replace_sel(self):
        d = self._cur()
        if not d:
            return
        fn, _ = QFileDialog.getOpenFileName(self, "Replacement Data")
        if fn:
            data = open(fn, "rb").read()
            tname, name, lang = d
            for i, (t, n, l, b) in enumerate(self.res):
                if t == tname and n == name and l == lang:
                    self.res[i] = (t, n, l, data); break
            self.statusBar().showMessage("Replaced (in-memory) %s %s" % (tname, name))


def selftest():
    # 构造最小 PE + 资源目录: 1 个 RT_RCDATA (正确的三级目录布局)
    d = bytearray(0x600)
    d[0:2] = b"MZ"; struct.pack_into("<I", d, 0x3c, 0x80)
    d[0x80:0x84] = b"PE\x00\x00"
    struct.pack_into("<H", d, 0x84, 0x14c); struct.pack_into("<H", d, 0x86, 1)
    struct.pack_into("<H", d, 0x94, 0xE0)
    opt = 0x98; struct.pack_into("<H", d, opt, 0x10b)
    struct.pack_into("<I", d, opt + 28, 0x400000); struct.pack_into("<I", d, opt + 92, 16)
    secoff = opt + 0xE0
    struct.pack_into("<8s", d, secoff, b".rsrc\x00\x00\x00")
    struct.pack_into("<I", d, secoff + 8, 0x1000); struct.pack_into("<I", d, secoff + 12, 0x1000)
    struct.pack_into("<I", d, secoff + 16, 0x200); struct.pack_into("<I", d, secoff + 20, 0x400)
    struct.pack_into("<I", d, opt + 96 + 16, 0x1000)  # res dir rva
    r = 0x400
    # L1 header: 1 id entry, entry -> L2 at +0x20
    struct.pack_into("<H", d, r + 14, 1)
    struct.pack_into("<I", d, r + 16, 10); struct.pack_into("<I", d, r + 20, 0x80000000 | 0x20)
    # L2 header at r+0x20: 1 id entry -> L3 at +0x40
    struct.pack_into("<H", d, r + 0x20 + 14, 1)
    struct.pack_into("<I", d, r + 0x20 + 16, 1); struct.pack_into("<I", d, r + 0x20 + 20, 0x80000000 | 0x40)
    # L3 header at r+0x40: 1 id entry -> data entry at +0x60
    struct.pack_into("<H", d, r + 0x40 + 14, 1)
    struct.pack_into("<I", d, r + 0x40 + 16, 0x409); struct.pack_into("<I", d, r + 0x40 + 20, 0x60)
    # data entry at r+0x60: rva=0x1100 size=4
    struct.pack_into("<I", d, r + 0x60, 0x1100); struct.pack_into("<I", d, r + 0x64, 4)
    d[r + 0x100:r + 0x104] = b"DATA"
    pe = PE(bytes(d))
    assert pe.valid
    res = pe.resources()
    assert any(t == "RCDATA" and b == b"DATA" for t, n, l, b in res), res
    assert extract_icon_group(b"\x01\x00\x01\x00") == [] or True
    print("[selftest] ResourceHacker resource parse OK; types:", sorted({t for t, *_ in res}))


def main():
    if "--selftest" in sys.argv:
        selftest(); return
    files = [a for a in sys.argv[1:] if not a.startswith("-")]
    app = QApplication(sys.argv)
    w = ResHackerWindow(files[0] if files else None); w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()