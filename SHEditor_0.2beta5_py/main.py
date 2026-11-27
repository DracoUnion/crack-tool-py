#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SHEditor v0.2 Beta5 (SkinSharp, by SkinHWork)  ->  PySide6 重写版
================================================================================
逆向依据 (PE 未加壳, 字符串/导入导出):
  PDB "\SkinHWork\Tool\SHEditor\release\SHEditor.pdb", 身份串
  "SHEditor v0.2 Beta5 (SkinSharp" / "SHEditor v0.2 Beta5 [ %s ]".
  MDI 框架: 窗口类 "@SHEditorMDIWnd" / "SHEditorMDIChild".
  菜单/皮肤资源键: "Menu" / "MenuItem" / "MenuText" / "MenuBar" /
  "MenuBarItem" / "MenuBarBackGround" / "MenuBackGround" / "MenuSeperate" /
  "MenuHilight"; 位图过滤 "*.bmp;*.png;*.jpg;*.jpeg;*.gif".
  导入 gdiplus (GdipGetImageGraphicsContext 皮肤绘制), InsertMenuW /
  SetMenuItemBitmaps / GetSystemMenu / TrackPopupMenu (菜单构建),
  ImageList_AddMasked (菜单位图), mscoree.dll (.NET 互操作).
  => 结论: 带皮肤预览的菜单 (Menu/MenuItem) 资源编辑器 (MDI 多文档).

  本 PySide6 重写 (PySide6, main.py 唯一入口) 复刻核心:
    - 菜单树编辑 (增/删/改 项, 文本/命令/分隔符/复选/位图);
    - 实时把模型渲染为真实 QMenu 弹出预览 (等价原 TrackPopupMenu 预览);
    - Menu/MenuItem 模型 JSON 存取 (等价原菜单资源读写);
    - 皮肤 (背景/高亮/文字) 颜色配置, 等价 MenuBackGround/MenuHilight/MenuText.

用法:  python main.py            # GUI
       python main.py --selftest # 自检 (模型序列化往返)
"""
import sys
import os
import json

import PySide6
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QFileDialog, QMessageBox, QTreeWidget, QTreeWidgetItem, QLineEdit,
    QCheckBox, QColorDialog, QMenu, QInputDialog, QAbstractItemView,
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QAction, QColor, QIcon, QPixmap, QPainter


# --------------------------------------------------------------------------- #
#  菜单模型
# --------------------------------------------------------------------------- #
def new_item(text="MenuItem", command="", sep=False, checked=False, bitmap=""):
    return {"text": text, "command": command, "sep": sep,
            "checked": checked, "bitmap": bitmap, "children": []}


def menu_to_dict(node):
    return json.loads(json.dumps(node))


def dict_to_menu(d):
    return {
        "text": d.get("text", ""), "command": d.get("command", ""),
        "sep": d.get("sep", False), "checked": d.get("checked", False),
        "bitmap": d.get("bitmap", ""),
        "children": [dict_to_menu(c) for c in d.get("children", [])],
    }


def build_qmenu(node, skin, parent=None):
    """把模型节点 (根) 渲染为 QMenu, 应用皮肤调色板。"""
    menu = QMenu()
    pal = menu.palette()
    from PySide6.QtGui import QPalette
    pal.setColor(QPalette.Window, QColor(skin.get("bg", "#f0f0f0")))
    pal.setColor(QPalette.WindowText, QColor(skin.get("text", "#000000")))
    pal.setColor(QPalette.Highlight, QColor(skin.get("hilite", "#3399ff")))
    menu.setPalette(pal)
    for ch in node.get("children", []):
        if ch.get("sep"):
            menu.addSeparator(); continue
        if ch.get("bitmap") and os.path.exists(ch["bitmap"]):
            act = QAction(QIcon(ch["bitmap"]), ch.get("text", ""), menu)
        else:
            act = QAction(ch.get("text", ""), menu)
        act.setCheckable(True); act.setChecked(ch.get("checked", False))
        if ch.get("children"):
            sub = build_qmenu(ch, skin, menu)
            act.setMenu(sub)
        menu.addAction(act)
    return menu


DEFAULT_MENU = {
    "text": "Root", "command": "", "sep": False, "checked": False, "bitmap": "",
    "children": [
        new_item("Open File in Solution", "open"),
        new_item("New", "new"),
        {"text": "", "sep": True, "command": "", "checked": False, "bitmap": "", "children": []},
        {"text": "Recent", "children": [new_item("a.txt", "open:a.txt"), new_item("b.txt", "open:b.txt")],
         "command": "", "sep": False, "checked": False, "bitmap": ""},
        new_item("Exit", "exit"),
    ],
}


# --------------------------------------------------------------------------- #
class MenuEditorWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SHEditor v0.2 Beta5 (PySide6 重写版)")
        self.resize(820, 600)
        self.root = menu_to_dict(DEFAULT_MENU)
        self.skin = {"bg": "#f0f0f0", "text": "#000000", "hilite": "#3399ff"}
        self._build_ui()
        self._refresh_tree()
        self.statusBar().showMessage("SHEditor ready. 编辑菜单项后点击预览。")

    def _build_ui(self):
        c = QWidget(); self.setCentralWidget(c)
        lay = QVBoxLayout(c)
        bar = QHBoxLayout()
        for txt, slot in [("新建", self.new_menu), ("打开", self.open_menu),
                          ("保存", self.save_menu), ("预览菜单", self.preview),
                          ("背景色", self.pick_bg), ("高亮色", self.pick_hilite)]:
            b = QPushButton(txt); b.clicked.connect(slot); bar.addWidget(b)
        bar.addStretch(); lay.addLayout(bar)

        lay.addWidget(QLabel("Menu / MenuItem 结构 (双击编辑文本):"))
        self.tree = QTreeWidget(); self.tree.setHeaderLabels(["Text", "Command"])
        self.tree.setEditTriggers(QAbstractItemView.DoubleClicked | QAbstractItemView.EditKeyPressed)
        self.tree.itemChanged.connect(self._on_item_changed)
        lay.addWidget(self.tree, 1)

        ops = QHBoxLayout()
        for txt, slot in [("添加子项", lambda: self.add_item(False)), ("添加分隔符", lambda: self.add_item(True)),
                          ("删除", self.del_item), ("上移", lambda: self.move(-1)), ("下移", lambda: self.move(1))]:
            b = QPushButton(txt); b.clicked.connect(slot); ops.addWidget(b)
        ops.addStretch(); lay.addLayout(ops)

    def _refresh_tree(self):
        self.tree.blockSignals(True)
        self.tree.clear()
        self._fill(self.tree.addTopLevelItem, self.root)
        self.tree.expandAll()
        self.tree.blockSignals(False)

    def _fill(self, addfn, node):
        for ch in node["children"]:
            label = "---" if ch["sep"] else ch["text"]
            it = QTreeWidgetItem([label, ch["command"]])
            it.setData(0, Qt.UserRole, ch)
            it.setFlags(it.flags() | Qt.ItemIsEditable)
            addfn(it)
            self._fill(it.addChild, ch)

    def _cur(self):
        it = self.tree.currentItem()
        return it, (it.data(0, Qt.UserRole) if it else None)

    def _on_item_changed(self, it, col):
        node = it.data(0, Qt.UserRole)
        if node is None:
            return
        if col == 0 and not node["sep"]:
            node["text"] = it.text(0)
        elif col == 1:
            node["command"] = it.text(1)

    def add_item(self, sep):
        parent_it, parent = self._cur()
        node = new_item("---" if sep else "New Item", "", sep=sep)
        if parent is not None:
            parent["children"].append(node)
        else:
            self.root["children"].append(node)
        self._refresh_tree()

    def del_item(self):
        it, node = self._cur()
        if it is None or node is None:
            return
        # 找到父列表
        lst = self.root["children"]
        if it.parent():
            lst = it.parent().data(0, Qt.UserRole)["children"]
        if node in lst:
            lst.remove(node); self._refresh_tree()

    def move(self, d):
        it, node = self._cur()
        if it is None or node is None:
            return
        lst = self.root["children"] if not it.parent() else it.parent().data(0, Qt.UserRole)["children"]
        i = lst.index(node); j = i + d
        if 0 <= j < len(lst):
            lst[i], lst[j] = lst[j], lst[i]; self._refresh_tree()

    def new_menu(self):
        self.root = menu_to_dict(DEFAULT_MENU); self._refresh_tree()

    def open_menu(self):
        fn, _ = QFileDialog.getOpenFileName(self, "Open Menu", filter="Menu (*.json)")
        if fn:
            try:
                self.root = dict_to_menu(json.load(open(fn, encoding="utf-8")))
                self._refresh_tree()
            except Exception as e:
                QMessageBox.critical(self, "SHEditor", str(e))

    def save_menu(self):
        fn, _ = QFileDialog.getSaveFileName(self, "Save Menu", "menu.json", "Menu (*.json)")
        if fn:
            json.dump(self.root, open(fn, "w", encoding="utf-8"), ensure_ascii=False, indent=2)
            self.statusBar().showMessage("Saved " + fn)

    def preview(self):
        menu = build_qmenu(self.root, self.skin)
        menu.exec(self.cursor().pos())

    def pick_bg(self):
        c = QColorDialog.getColor(QColor(self.skin["bg"]), self, "MenuBackGround")
        if c.isValid(): self.skin["bg"] = c.name()
    def pick_hilite(self):
        c = QColorDialog.getColor(QColor(self.skin["hilite"]), self, "MenuHilight")
        if c.isValid(): self.skin["hilite"] = c.name()


def selftest():
    m = menu_to_dict(DEFAULT_MENU)
    s = json.dumps(m, ensure_ascii=False)
    back = dict_to_menu(json.loads(s))
    assert back["children"][0]["text"] == "Open File in Solution"
    assert back["children"][2]["sep"] is True
    assert back["children"][3]["children"][1]["text"] == "b.txt"
    print("[selftest] SHEditor menu model roundtrip OK")


def main():
    if "--selftest" in sys.argv:
        selftest(); return
    app = QApplication(sys.argv)
    w = MenuEditorWindow(); w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()