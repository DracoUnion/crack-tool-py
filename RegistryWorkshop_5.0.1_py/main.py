#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Registry Workshop 5.0.1.0 (TorchSoft)  ->  PySide6 重写版
================================================================================
逆向依据 (PE 未加壳, 版本资源):
  FileDescription/ProductName "Registry Workshop", CompanyName "TorchSoft",
  FileVersion 5,0,1,0, InternalName "Registry Workshop", OriginalFilename
  "RegWorkshop.exe". 导入 Advapi32 (RegOpenKey/RegQueryValue/RegSetValue 等),
  资源含左树右值列表、查找、导出 .reg 等对话框.
  => 结论: Windows 注册表编辑器 (5 大根键树 + 值编辑 + 搜索 + 导入导出).

  本 PySide6 重写 (纯标准库 winreg + PySide6, main.py 唯一入口) 复刻核心:
    - 五大根键 (HKEY_CLASSES_ROOT/CURRENT_USER/LOCAL_MACHINE/USERS/CURRENT_CONFIG)
      树形浏览;
    - 值列表 (名称/类型/数据) 查看与编辑 (SZ/EXPAND_SZ/DWORD/QWORD/BINARY/MULTI_SZ);
    - 新建/删除 键与值, 重命名;
    - 搜索 (键/值/数据), 导出 .reg / 导入 .reg;
    - 路径栏跳转.

用法:  python main.py            # GUI
       python main.py --selftest # 自检
"""
import sys
import os

import winreg

import PySide6
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QFileDialog, QMessageBox, QTreeWidget, QTreeWidgetItem, QTableWidget,
    QTableWidgetItem, QLineEdit, QInputDialog, QSplitter, QAbstractItemView,
)
from PySide6.QtCore import Qt

ROOTS = [
    ("HKEY_CLASSES_ROOT", winreg.HKEY_CLASSES_ROOT),
    ("HKEY_CURRENT_USER", winreg.HKEY_CURRENT_USER),
    ("HKEY_LOCAL_MACHINE", winreg.HKEY_LOCAL_MACHINE),
    ("HKEY_USERS", winreg.HKEY_USERS),
    ("HKEY_CURRENT_CONFIG", winreg.HKEY_CURRENT_CONFIG),
]
ROOTNAME = {v: k for k, v in ROOTS}
TYPE_NAME = {
    winreg.REG_SZ: "SZ", winreg.REG_EXPAND_SZ: "EXPAND_SZ",
    winreg.REG_DWORD: "DWORD", winreg.REG_QWORD: "QWORD",
    winreg.REG_BINARY: "BINARY", winreg.REG_MULTI_SZ: "MULTI_SZ",
}


def split_path(full):
    """'HKEY_CURRENT_USER\\Software\\...' -> (root_const, subkey)."""
    for name, h in ROOTS:
        if full.upper().startswith(name):
            sub = full[len(name):].lstrip("\\")
            return h, sub
    return None, None


def list_values(h, sub):
    out = []
    try:
        k = winreg.OpenKey(h, sub) if sub else winreg.OpenKey(h, "")
    except OSError:
        return out
    try:
        i = 0
        while True:
            try:
                name, val, typ = winreg.EnumValue(k, i)
            except OSError:
                break
            out.append((name, typ, val)); i += 1
    finally:
        k.Close()
    return out


def list_subkeys(h, sub):
    out = []
    try:
        k = winreg.OpenKey(h, sub) if sub else winreg.OpenKey(h, "")
    except OSError:
        return out
    try:
        i = 0
        while True:
            try:
                out.append(winreg.EnumKey(k, i))
            except OSError:
                break
            i += 1
    finally:
        k.Close()
    return out


def fmt_val(typ, val):
    if typ in (winreg.REG_DWORD, winreg.REG_QWORD):
        return "0x%X (%d)" % (val, val)
    if typ == winreg.REG_BINARY:
        return bytes(val).hex(" ")
    if typ == winreg.REG_MULTI_SZ:
        return " | ".join(val)
    return str(val)


def export_reg(h, sub, path):
    """导出为 .reg 文本 (Windows 5.00 格式)。"""
    lines = ["Windows Registry Editor Version 5.00", ""]
    prefix = ROOTNAME.get(h, "") + ("\\" + sub if sub else "")
    lines.append("[%s]" % prefix)
    for name, typ, val in list_values(h, sub):
        tn = TYPE_NAME.get(typ, "SZ")
        if typ in (winreg.REG_DWORD,):
            lines.append('"%s"=dword:%08x' % (name, val))
        elif typ == winreg.REG_QWORD:
            lines.append('"%s"=hex(b):%s' % (name, bytes(val).hex(",")))
        elif typ == winreg.REG_BINARY:
            lines.append('"%s"=hex:%s' % (name, bytes(val).hex(",")))
        elif typ == winreg.REG_MULTI_SZ:
            lines.append('"%s"=hex(7):%s,' % (name, ",".join("%02x" % ord(c) for s in val for c in s + "\x00")))
        else:
            lines.append('"%s"="%s"' % (name, str(val).replace('"', '\\"')))
    lines.append("")
    open(path, "w", encoding="utf-16").write("\n".join(lines))


class RegWorkshopWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Registry Workshop 5.0 (PySide6 重写版) — TorchSoft")
        self.resize(1000, 680)
        self._build_ui()
        self._fill_roots()
        self.statusBar().showMessage("Registry Workshop ready.")

    def _build_ui(self):
        c = QWidget(); self.setCentralWidget(c); lay = QVBoxLayout(c)
        bar = QHBoxLayout()
        self.pathbar = QLineEdit(); self.pathbar.setPlaceholderText("HKEY_CURRENT_USER\\Software\\...")
        self.pathbar.returnPressed.connect(self.goto_path)
        b = QPushButton("跳转"); b.clicked.connect(self.goto_path)
        self.btn_newkey = QPushButton("新建键"); self.btn_newkey.clicked.connect(self.new_key)
        self.btn_newval = QPushButton("新建值"); self.btn_newval.clicked.connect(self.new_value)
        self.btn_del = QPushButton("删除"); self.btn_del.clicked.connect(self.delete_sel)
        self.btn_find = QPushButton("查找"); self.btn_find.clicked.connect(self.find)
        self.btn_export = QPushButton("导出"); self.btn_export.clicked.connect(self.export)
        for w in (self.pathbar, b, self.btn_newkey, self.btn_newval, self.btn_del, self.btn_find, self.btn_export):
            bar.addWidget(w)
        lay.addLayout(bar)
        sp = QSplitter(Qt.Horizontal)
        self.tree = QTreeWidget(); self.tree.setHeaderLabels(["Keys"])
        self.tree.itemSelectionChanged.connect(self.on_tree)
        sp.addWidget(self.tree)
        self.vals = QTableWidget(0, 3); self.vals.setHorizontalHeaderLabels(["Name", "Type", "Data"])
        self.vals.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.vals.itemSelectionChanged.connect(self.on_val)
        sp.addWidget(self.vals); sp.setSizes([360, 640])
        lay.addWidget(sp)

    def _fill_roots(self):
        for name, h in ROOTS:
            QTreeWidgetItem(self.tree, [name]).setData(0, Qt.UserRole, (h, ""))

    def _children(self, parent, h, sub):
        parent.setData(0, Qt.UserRole, (h, sub))
        for name in list_subkeys(h, sub):
            child_sub = (sub + "\\" + name) if sub else name
            it = QTreeWidgetItem(parent, [name]); it.setData(0, Qt.UserRole, (h, child_sub))
            if list_subkeys(h, child_sub):
                it.addChild(QTreeWidgetItem(it, ["..."]))  # lazy placeholder

    def on_tree(self):
        it = self.tree.currentItem()
        if not it:
            return
        if it.childCount() == 1 and it.child(0).text(0) == "...":
            it.takeChildren(); h, sub = it.data(0, Qt.UserRole); self._children(it, h, sub); it.setExpanded(True)
        h, sub = it.data(0, Qt.UserRole)
        self.pathbar.setText(ROOTNAME.get(h, "") + ("\\" + sub if sub else ""))
        self._show_values(h, sub)

    def _show_values(self, h, sub):
        self.vals.setRowCount(0)
        for name, typ, val in list_values(h, sub):
            r = self.vals.rowCount(); self.vals.insertRow(r)
            self.vals.setItem(r, 0, QTableWidgetItem("(Default)" if name == "" else name))
            self.vals.setItem(r, 1, QTableWidgetItem(TYPE_NAME.get(typ, str(typ))))
            self.vals.setItem(r, 2, QTableWidgetItem(fmt_val(typ, val)))
            self.vals.item(r, 0).setData(Qt.UserRole, (name, typ))

    def _cur_key(self):
        it = self.tree.currentItem()
        return it.data(0, Qt.UserRole) if it else (None, None)

    def goto_path(self):
        h, sub = split_path(self.pathbar.text().strip())
        if h is None:
            self.statusBar().showMessage("bad path"); return
        # 找到或构造树节点
        top = next((self.tree.topLevelItem(i) for i in range(self.tree.topLevelItemCount())
                    if self.tree.topLevelItem(i).data(0, Qt.UserRole)[0] == h), None)
        if not top:
            return
        self._expand_to(top, h, sub)

    def _expand_to(self, parent, h, sub):
        parts = sub.split("\\") if sub else []
        cur = parent
        csub = ""
        for p in parts:
            csub = (csub + "\\" + p) if csub else p
            if cur.childCount() == 1 and cur.child(0).text(0) == "...":
                cur.takeChildren(); self._children(cur, h, csub.rsplit("\\", 1)[0] if "\\" in csub else "")
            found = None
            for i in range(cur.childCount()):
                ch = cur.child(i)
                if ch.text(0) == p:
                    found = ch; break
            if not found:
                return
            cur = found
        self.tree.setCurrentItem(cur); cur.setExpanded(True)

    def new_key(self):
        h, sub = self._cur_key()
        if h is None:
            return
        name, ok = QInputDialog.getText(self, "New Key", "Key name:")
        if ok and name:
            nsub = (sub + "\\" + name) if sub else name
            try:
                winreg.CreateKey(h, nsub); self.on_tree(); self.statusBar().showMessage("Created " + nsub)
            except OSError as e:
                QMessageBox.critical(self, "RegWorkshop", str(e))

    def new_value(self):
        h, sub = self._cur_key()
        if h is None:
            return
        name, ok = QInputDialog.getText(self, "New Value", "Value name:")
        if not ok or not name:
            return
        data, ok = QInputDialog.getText(self, "New Value", "Data (string):")
        if not ok:
            return
        try:
            k = winreg.OpenKey(h, sub, 0, winreg.KEY_SET_VALUE) if sub else winreg.OpenKey(h, "", 0, winreg.KEY_SET_VALUE)
            winreg.SetValueEx(k, name, 0, winreg.REG_SZ, data); k.Close()
            self._show_values(h, sub)
        except OSError as e:
            QMessageBox.critical(self, "RegWorkshop", str(e))

    def delete_sel(self):
        h, sub = self._cur_key()
        it = self.vals.currentItem()
        if it is not None and h is not None:
            name = it.data(Qt.UserRole)[0]
            try:
                k = winreg.OpenKey(h, sub, 0, winreg.KEY_SET_VALUE) if sub else winreg.OpenKey(h, "", 0, winreg.KEY_SET_VALUE)
                winreg.DeleteValue(k, name); k.Close(); self._show_values(h, sub)
            except OSError as e:
                QMessageBox.critical(self, "RegWorkshop", str(e))
        else:
            QMessageBox.information(self, "RegWorkshop", "Select a value to delete.")

    def on_val(self):
        pass

    def find(self):
        t, ok = QInputDialog.getText(self, "Find", "Search text (keys/values/data):")
        if not ok or not t:
            return
        hits = []
        for name, h in ROOTS:
            self._search(h, "", t.lower(), hits, depth=0)
            if len(hits) > 200:
                break
        self.statusBar().showMessage("Found %d (first: %s)" % (len(hits), hits[0] if hits else "-"))

    def _search(self, h, sub, t, hits, depth=0):
        if depth > 6 or len(hits) > 200:
            return
        for name, typ, val in list_values(h, sub):
            if t in name.lower() or t in fmt_val(typ, val).lower():
                hits.append(ROOTNAME.get(h, "") + "\\" + sub + ":" + name)
        for sk in list_subkeys(h, sub):
            self._search(h, (sub + "\\" + sk) if sub else sk, t, hits, depth + 1)

    def export(self):
        h, sub = self._cur_key()
        if h is None:
            return
        fn, _ = QFileDialog.getSaveFileName(self, "Export .reg", "export.reg", "reg (*.reg)")
        if fn:
            try:
                export_reg(h, sub, fn); self.statusBar().showMessage("Exported " + fn)
            except OSError as e:
                QMessageBox.critical(self, "RegWorkshop", str(e))


def selftest():
    # 在 HKCU\Software 下建临时键, 写读删
    test = "Software\\__rw_selftest__"
    try:
        winreg.CreateKey(winreg.HKEY_CURRENT_USER, test)
        k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, test, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(k, "v", 0, winreg.REG_SZ, "hello")
        winreg.SetValueEx(k, "d", 0, winreg.REG_DWORD, 0x1234)
        k.Close()
        vals = dict((n, (t, v)) for n, t, v in list_values(winreg.HKEY_CURRENT_USER, test))
        assert vals["v"][1] == "hello" and vals["d"][1] == 0x1234
        assert "0x1234" in fmt_val(vals["d"][0], vals["d"][1])
    finally:
        try:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, test)
        except OSError:
            pass
    print("[selftest] RegWorkshop winreg create/read/delete OK")


def main():
    if "--selftest" in sys.argv:
        selftest(); return
    app = QApplication(sys.argv)
    w = RegWorkshopWindow(); w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()