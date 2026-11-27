#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JD-GUI 1.6.6  ->  Python 重写版 (CLI + PySide6 GUI)
================================================================================
逆向依据 (目录 JDGUI_1.6.6/JDGUI-1.6.6.jar, 主类 JD-GUI):
  JD-GUI 是基于 JD 反编译引擎的 Java 反编译器 GUI, 打开 .jar/.class, 左侧
  包/类树, 右侧显示反编译的 Java 源码.
  本重写复刻其核心 (main.py 唯一入口, 纯标准库 + PySide6):
    - 解析 .class (常量池/this/super/interfaces/fields/methods/Code)
    - 把 JVM 字节码近似反编译为 Java 源码 (字段/方法签名/方法体)
    - 打开 .jar (ZIP) 列出所有类; GUI 类树 + 源码
  实现: 内置 JVM class 解析器 + JVM->Java 反编译 (常用子集).

用法:
  python main.py --selftest
  python main.py decompile <File.class>      # 输出 Java
  python main.py list <app.jar>
  python main.py gui [file.jar]
"""

import sys
import os
import struct
import zipfile

JVM_OP = {
    0x00:("nop",0),0x01:("aconst_null",0),0x02:("iconst_m1",0),0x03:("iconst_0",0),
    0x04:("iconst_1",0),0x05:("iconst_2",0),0x06:("iconst_3",0),0x07:("iconst_4",0),
    0x08:("iconst_5",0),0x09:("lconst_0",0),0x0a:("lconst_1",0),0x0b:("fconst_0",0),
    0x0c:("fconst_1",0),0x0d:("fconst_2",0),0x0e:("dconst_0",0),0x0f:("dconst_1",0),
    0x10:("bipush",1),0x11:("sipush",2),0x12:("ldc",1),0x13:("ldc_w",2),0x14:("ldc2_w",2),
    0x15:("iload",1),0x16:("lload",1),0x17:("fload",1),0x18:("dload",1),0x19:("aload",1),
    0x1a:("iload_0",0),0x1b:("iload_1",0),0x1c:("iload_2",0),0x1d:("iload_3",0),
    0x2a:("aload_0",0),0x2b:("aload_1",0),0x2c:("aload_2",0),0x2d:("aload_3",0),
    0x2e:("iaload",0),0x32:("aaload",0),
    0x36:("istore",1),0x3a:("astore",1),0x3b:("istore_0",0),0x3c:("istore_1",0),
    0x3d:("istore_2",0),0x3e:("istore_3",0),0x4b:("astore_0",0),0x4c:("astore_1",0),
    0x4d:("astore_2",0),0x4e:("astore_3",0),
    0x57:("pop",0),0x59:("dup",0),
    0x60:("iadd",0),0x64:("isub",0),0x68:("imul",0),0x6c:("idiv",0),0x70:("irem",0),
    0x74:("ineg",0),0x78:("ishl",0),0x7a:("ishr",0),0x7e:("iand",0),0x80:("ior",0),0x82:("ixor",0),
    0x84:("iinc",2),0x85:("i2l",0),0x86:("i2f",0),0x87:("i2d",0),0x91:("i2b",0),0x92:("i2c",0),0x93:("i2s",0),
    0x99:("ifeq",2),0x9a:("ifne",2),0x9b:("iflt",2),0x9c:("ifge",2),0x9d:("ifgt",2),0x9e:("ifle",2),
    0x9f:("if_icmpeq",2),0xa0:("if_icmpne",2),0xa1:("if_icmplt",2),0xa2:("if_icmpge",2),
    0xa3:("if_icmpgt",2),0xa4:("if_icmple",2),0xa7:("goto",2),0xa8:("jsr",2),0xa9:("ret",1),
    0xac:("ireturn",0),0xad:("lreturn",0),0xae:("freturn",0),0xaf:("dreturn",0),0xb0:("areturn",0),0xb1:("return",0),
    0xb2:("getstatic",2),0xb3:("putstatic",2),0xb4:("getfield",2),0xb5:("putfield",2),
    0xb6:("invokevirtual",2),0xb7:("invokespecial",2),0xb8:("invokestatic",2),
    0xb9:("invokeinterface",4),0xba:("invokedynamic",4),0xbb:("new",2),0xbc:("newarray",1),
    0xbd:("anewarray",2),0xbe:("arraylength",0),0xbf:("athrow",0),0xc0:("checkcast",2),
    0xc1:("instanceof",2),0xc2:("monitorenter",0),0xc3:("monitorexit",0),0xc4:("wide",-1),
    0xc5:("multianewarray",3),0xc6:("ifnull",2),0xc7:("ifnonnull",2),
}


class ClassError(Exception):
    pass


class ClassFile:
    def __init__(self, data):
        self.d = data
        if data[:4] != b"\xca\xfe\xba\xbe":
            raise ClassError("非 .class")
        self.minor, self.major = struct.unpack_from(">HH", data, 4)
        self.cp_count = struct.unpack_from(">H", data, 8)[0]
        self.cp = [None] * self.cp_count
        self._parse_cp(10)
        p = self._cp_end
        self.access, self.this_class, self.super_class = struct.unpack_from(">HHH", data, p); p += 6
        ic = struct.unpack_from(">H", data, p)[0]; p += 2
        self.interfaces = [struct.unpack_from(">H", data, p + i * 2)[0] for i in range(ic)]; p += ic * 2
        self.fields, p = self._parse_members(p)
        self.methods, p = self._parse_members(p)
        self.attrs, p = self._parse_attrs(p)

    def _parse_cp(self, o):
        i = 1
        while i < self.cp_count:
            tag = self.d[o]; o += 1
            if tag == 1:
                ln = struct.unpack_from(">H", self.d, o)[0]; o += 2
                self.cp[i] = (1, self.d[o:o + ln].decode("utf-8", "replace")); o += ln
            elif tag in (7, 8, 16, 19, 20):
                self.cp[i] = (tag, struct.unpack_from(">H", self.d, o)[0]); o += 2
            elif tag == 15:
                self.cp[i] = (tag, struct.unpack_from(">BH", self.d, o)); o += 3
            elif tag in (3, 4, 9, 10, 11, 12, 17, 18):
                self.cp[i] = (tag, struct.unpack_from(">HH", self.d, o)); o += 4
            elif tag in (5, 6):
                v = struct.unpack_from(">I", self.d, o)[0] | (struct.unpack_from(">I", self.d, o + 4)[0] << 32)
                o += 8; self.cp[i] = (tag, v); i += 1
            else:
                raise ClassError("未知 tag %d" % tag)
            i += 1
        self._cp_end = o

    def utf8(self, i):
        e = self.cp[i]
        return e[1] if e and e[0] == 1 else ""

    def cp_str(self, i):
        e = self.cp[i]
        if not e: return "?"
        t = e[0]
        if t == 1: return e[1]
        if t == 7: return self.utf8(e[1])
        if t == 8: return '"%s"' % self.utf8(e[1])
        if t in (9, 10, 11):
            cls = self.utf8(self.cp[e[1][0]][1]); nt = e[1][1]
            n = self.utf8(self.cp[nt][1][0]); desc = self.utf8(self.cp[nt][1][1])
            return "%s.%s:%s" % (cls, n, desc)
        if t == 12: return "%s:%s" % (self.utf8(e[1][0]), self.utf8(e[1][1]))
        return str(e[1] if len(e) > 1 else e)

    def _parse_members(self, o):
        cnt = struct.unpack_from(">H", self.d, o)[0]; o += 2
        out = []
        for _ in range(cnt):
            acc, ni, di, ac = struct.unpack_from(">HHHH", self.d, o); o += 8
            attrs = []
            for _ in range(ac):
                an, ln = struct.unpack_from(">HI", self.d, o); o += 6
                attrs.append((self.utf8(an), self.d[o:o + ln])); o += ln
            out.append((acc, self.utf8(ni), self.utf8(di), attrs))
        return out, o

    def _parse_attrs(self, o):
        cnt = struct.unpack_from(">H", self.d, o)[0]; o += 2
        out = []
        for _ in range(cnt):
            an, ln = struct.unpack_from(">HI", self.d, o); o += 6
            out.append((self.utf8(an), self.d[o:o + ln])); o += ln
        return out, o


def desc_to_java(t):
    prim = {"V":"void","Z":"boolean","B":"byte","S":"short","C":"char","I":"int","J":"long","F":"float","D":"double"}
    if t in prim: return prim[t]
    if t.startswith("L") and t.endswith(";"): return t[1:-1].replace("/", ".")
    if t.startswith("["): return desc_to_java(t[1:]) + "[]"
    return t


def access_str(a):
    s = []
    for bit, n in [(1,"public"),(2,"private"),(4,"protected"),(8,"static"),(0x10,"final"),
                   (0x100,"native"),(0x400,"abstract"),(0x1000,"synthetic")]:
        if a & bit: s.append(n)
    return " ".join(s)


def disasm_to_java(cw, code):
    """把 Code 字节码近似翻译为 Java 语句 (常用子集)。"""
    out = []
    o = 0
    while o < len(code):
        op = code[o]
        if op not in JVM_OP:
            o += 1; continue
        name, n = JVM_OP[op]
        if n == 0:
            if name.startswith("iconst"):
                v = int(name[-1]) if name[-1].isdigit() else -1
                out.append("    // push %d" % v)
            elif name in ("ireturn","return"): out.append("    return;")
            elif name == "areturn": out.append("    return null;")
            o += 1
        elif n == 1 and name in ("bipush","ldc","iload","aload","istore","astore","newarray"):
            v = code[o+1]
            if name == "bipush": out.append("    // push %d" % v)
            o += 2
        elif n == 2:
            idx = struct.unpack_from(">H", code, o+1)[0]
            if name in ("getstatic","getfield"): out.append("    // %s %s" % (name, cw.cp_str(idx)))
            elif name in ("putstatic","putfield"): out.append("    // %s %s" % (name, cw.cp_str(idx)))
            elif name.startswith("invoke"): out.append("    // %s %s" % (name, cw.cp_str(idx)))
            elif name == "new": out.append("    // new %s" % cw.cp_str(idx))
            elif name in ("ifeq","ifne","iflt","ifge","ifgt","ifle","ifnull","ifnonnull","goto"):
                out.append("    // %s -> %d" % (name, o + struct.unpack_from(">h", code, o+1)[0]))
            o += 3
        else:
            o += (n + 1) if n > 0 else 1
    if not out:
        out.append("    // (empty body)")
    return out


def class_to_java(data):
    cw = ClassFile(data)
    name = cw.cp_str(cw.this_class).replace("/", ".")
    L = ["// JD-GUI (Python) 反编译结果", "package %s;" % (name.rsplit(".",1)[0] if "." in name else ""),
         "", "%s class %s%s {" % (access_str(cw.access) or "public", name.rsplit(".",1)[-1],
         " extends " + desc_to_java(cw.cp_str(cw.super_class)) if cw.super_class else "")]
    for acc, fn, fd, attrs in cw.fields:
        L.append("    %s %s %s;" % (access_str(acc), desc_to_java(fd), fn))
    for acc, mn, md, attrs in cw.methods:
        m = md[1:md.index(")")]; ret = md[md.index(")")+1:]
        params = []
        i = 0
        while i < len(m):
            j = i
            while m[j] == "[": j += 1
            if m[j] == "L": j = m.index(";", j)+1
            else: j += 1
            params.append(desc_to_java(m[i:j])); i = j
        ps = ", ".join("%s p%d" % (t, k) for k, t in enumerate(params))
        L.append("    %s %s %s(%s) {" % (access_str(acc), desc_to_java(ret), mn, ps))
        for an, ab in attrs:
            if an == "Code":
                clen = struct.unpack_from(">I", ab, 4)[0]
                L += disasm_to_java(cw, ab[8:8+clen])
        L.append("    }")
    L.append("}")
    return "\n".join(L)


def run_gui(argv):
    from PySide6.QtWidgets import (
        QApplication,QMainWindow,QWidget,QVBoxLayout,QHBoxLayout,QPushButton,
        QFileDialog,QTreeWidget,QTreeWidgetItem,QPlainTextEdit,QSplitter,QMessageBox)
    app = QApplication(sys.argv)
    win = QMainWindow(); win.setWindowTitle("JD-GUI 1.6.6 (Java 反编译)  PySide6"); win.resize(1000,700)
    cw = QWidget(); win.setCentralWidget(cw); lay = QVBoxLayout(cw)
    row = QHBoxLayout(); b_open = QPushButton("打开 jar/class"); row.addWidget(b_open); row.addStretch(); lay.addLayout(row)
    sp = QSplitter(); tree = QTreeWidget(); tree.setHeaderLabels(["类"])
    src = QPlainTextEdit(); src.setReadOnly(True); sp.addWidget(tree); sp.addWidget(src); lay.addWidget(sp)
    def load(p):
        tree.clear()
        if p.lower().endswith((".jar",".zip")):
            with zipfile.ZipFile(p) as z:
                for n in z.namelist():
                    if n.endswith(".class"):
                        it = QTreeWidgetItem(tree,[n]); it.setData(0,1,("c",z.read(n)));
                        if not it.parent(): tree.addTopLevelItem(it)
        elif p.lower().endswith(".class"):
            it = QTreeWidgetItem(tree,[os.path.basename(p)]); it.setData(0,1,("c",open(p,"rb").read())); tree.addTopLevelItem(it)
    def onsel():
        it = tree.currentItem()
        if not it: return
        kind, data = it.data(0,1)
        try: src.setPlainText(class_to_java(data))
        except Exception as ex: src.setPlainText("// 错误: %s" % ex)
    tree.itemSelectionChanged.connect(onsel)
    def do_open():
        p,_ = QFileDialog.getOpenFileName(win,"打开","","Java (*.jar *.class *.zip);;All (*.*)")
        if p:
            try: load(p)
            except Exception as ex: QMessageBox.critical(win,"错误",str(ex))
    b_open.clicked.connect(do_open)
    if len(argv)>1 and os.path.exists(argv[1]): load(argv[1])
    win.statusBar().showMessage("就绪"); win.show(); sys.exit(app.exec())


def selftest():
    ok=0;fail=0
    def check(n,c):
        nonlocal ok,fail
        print("  [%s] %s"%("OK " if c else "ERR",n));ok+=1 if c else 0;fail+=0 if c else 1
    check("JVM 操作码 >= 100",len(JVM_OP)>=100)
    check("desc int",desc_to_java("I")=="int")
    check("desc obj",desc_to_java("Ljava/lang/String;")=="java.lang.String")
    # 用 javap 风格最小 class
    cp=bytearray()
    cp+=struct.pack('>BH',1,5)+b'Hello';cp+=struct.pack('>BH',7,1)
    cp+=struct.pack('>BH',1,16)+b'java/lang/Object';cp+=struct.pack('>BH',7,3)
    cp+=struct.pack('>BH',1,4)+b'main';cp+=struct.pack('>BH',1,5)+b'(II)V';cp+=struct.pack('>BH',1,4)+b'Code'
    code=b'\x04\x3b\xb1';cab=struct.pack('>HHI',8,2,len(code))+code+struct.pack('>HH',0,0)
    ca=struct.pack('>HI',7,len(cab))+cab;m=struct.pack('>HHHH',9,5,6,1)+ca
    body=struct.pack('>IHHH',0xCAFEBABE,0,52,8)+cp+struct.pack('>HHHH',0x21,2,4,0)+struct.pack('>H',0)+struct.pack('>H',1)+m+struct.pack('>H',0)
    try:
        j=class_to_java(body)
        check("反编译含 class Hello","class Hello" in j)
        check("反编译含 main","main" in j)
    except Exception as ex: check("反编译 (%s)"%ex,False)
    print("结果: %d 通过, %d 失败"%(ok,fail))
    return 0 if fail==0 else 1


def main():
    a=sys.argv[1:]
    if "--selftest" in a:return selftest()
    if not a or a[0] in ("-h","--help"):print(__doc__);return 0
    if a[0]=="decompile":print(class_to_java(open(a[1],"rb").read()));return 0
    if a[0]=="list":
        with zipfile.ZipFile(a[1]) as z:
            for n in z.namelist():
                if n.endswith(".class"):print(n)
        return 0
    run_gui(a);return 0


if __name__=="__main__":
    sys.exit(main() or 0)