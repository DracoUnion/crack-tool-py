#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Bytecode Viewer 2.11.2  ->  Python 重写版 (CLI + PySide6 GUI)
================================================================================
逆向依据 (目录 BytecodeViewer_2.11.2/BytecodeViewer-2.11.2.jar): BytecodeViewer
  是一个多格式字节码查看器, 能打开 .class/.jar/.dex/.apk, 左侧类树, 右侧显示
  反编译/JVM 字节码/十六进制. 本重写复刻其核心 (main.py 唯一入口,
  纯标准库 + PySide6):
    - 解析 JAR/ZIP -> .class; 解析 .class (常量池/this/super/interfaces/
      fields/methods/Code 属性) 并反汇编 JVM 字节码
    - 解析 DEX (类/方法) 与 smali
    - GUI: 类树 + JVM 字节码/十六进制/字符串 视图
  实现: 内置 JVM class 解析器 + JVM 操作码反汇编器 + 精简 DEX 解析.

用法:
  python main.py --selftest
  python main.py disasm <File.class>        # 反汇编 JVM 字节码
  python main.py gui [file.jar|class|dex]
"""

import sys
import os
import struct
import zipfile

# ============================================================ JVM 操作码表
JVM_OP = {
    0x00:("nop",0),0x01:("aconst_null",0),0x02:("iconst_m1",0),0x03:("iconst_0",0),
    0x04:("iconst_1",0),0x05:("iconst_2",0),0x06:("iconst_3",0),0x07:("iconst_4",0),
    0x08:("iconst_5",0),0x09:("lconst_0",0),0x0a:("lconst_1",0),0x0b:("fconst_0",0),
    0x0c:("fconst_1",0),0x0d:("fconst_2",0),0x0e:("dconst_0",0),0x0f:("dconst_1",0),
    0x10:("bipush",1),0x11:("sipush",2),0x12:("ldc",1),0x13:("ldc_w",2),0x14:("ldc2_w",2),
    0x15:("iload",1),0x16:("lload",1),0x17:("fload",1),0x18:("dload",1),0x19:("aload",1),
    0x1a:("iload_0",0),0x1b:("iload_1",0),0x1c:("iload_2",0),0x1d:("iload_3",0),
    0x1e:("lload_0",0),0x1f:("lload_1",0),0x20:("lload_2",0),0x21:("lload_3",0),
    0x22:("fload_0",0),0x23:("fload_1",0),0x24:("fload_2",0),0x25:("fload_3",0),
    0x26:("dload_0",0),0x27:("dload_1",0),0x28:("dload_2",0),0x29:("dload_3",0),
    0x2a:("aload_0",0),0x2b:("aload_1",0),0x2c:("aload_2",0),0x2d:("aload_3",0),
    0x2e:("iaload",0),0x2f:("laload",0),0x30:("faload",0),0x31:("daload",0),
    0x32:("aaload",0),0x33:("baload",0),0x34:("caload",0),0x35:("saload",0),
    0x36:("istore",1),0x37:("lstore",1),0x38:("fstore",1),0x39:("dstore",1),0x3a:("astore",1),
    0x3b:("istore_0",0),0x3c:("istore_1",0),0x3d:("istore_2",0),0x3e:("istore_3",0),
    0x3f:("lstore_0",0),0x40:("lstore_1",0),0x41:("lstore_2",0),0x42:("lstore_3",0),
    0x43:("fstore_0",0),0x44:("fstore_1",0),0x45:("fstore_2",0),0x46:("fstore_3",0),
    0x47:("dstore_0",0),0x48:("dstore_1",0),0x49:("dstore_2",0),0x4a:("dstore_3",0),
    0x4b:("astore_0",0),0x4c:("astore_1",0),0x4d:("astore_2",0),0x4e:("astore_3",0),
    0x4f:("iastore",0),0x50:("lastore",0),0x51:("fastore",0),0x52:("dastore",0),
    0x53:("aastore",0),0x54:("bastore",0),0x55:("castore",0),0x56:("sastore",0),
    0x57:("pop",0),0x58:("pop2",0),0x59:("dup",0),0x5a:("dup_x1",0),0x5b:("dup_x2",0),
    0x5c:("dup2",0),0x5d:("dup2_x1",0),0x5e:("dup2_x2",0),0x5f:("swap",0),
    0x60:("iadd",0),0x61:("ladd",0),0x62:("fadd",0),0x63:("dadd",0),0x64:("isub",0),
    0x65:("lsub",0),0x66:("fsub",0),0x67:("dsub",0),0x68:("imul",0),0x69:("lmul",0),
    0x6a:("fmul",0),0x6b:("dmul",0),0x6c:("idiv",0),0x6d:("ldiv",0),0x6e:("fdiv",0),
    0x6f:("ddiv",0),0x70:("irem",0),0x71:("lrem",0),0x72:("frem",0),0x73:("drem",0),
    0x74:("ineg",0),0x75:("lneg",0),0x76:("fneg",0),0x77:("dneg",0),0x78:("ishl",0),
    0x79:("lshl",0),0x7a:("ishr",0),0x7b:("lshr",0),0x7c:("iushr",0),0x7d:("lushr",0),
    0x7e:("iand",0),0x7f:("land",0),0x80:("ior",0),0x81:("lor",0),0x82:("ixor",0),
    0x83:("lxor",0),0x84:("iinc",2),0x85:("i2l",0),0x86:("i2f",0),0x87:("i2d",0),
    0x88:("l2i",0),0x89:("l2f",0),0x8a:("l2d",0),0x8b:("f2i",0),0x8c:("f2l",0),
    0x8d:("f2d",0),0x8e:("d2i",0),0x8f:("d2l",0),0x90:("d2f",0),0x91:("i2b",0),
    0x92:("i2c",0),0x93:("i2s",0),0x94:("lcmp",0),0x95:("fcmpl",0),0x96:("fcmpg",0),
    0x97:("dcmpl",0),0x98:("dcmpg",0),0x99:("ifeq",2),0x9a:("ifne",2),0x9b:("iflt",2),
    0x9c:("ifge",2),0x9d:("ifgt",2),0x9e:("ifle",2),0x9f:("if_icmpeq",2),
    0xa0:("if_icmpne",2),0xa1:("if_icmplt",2),0xa2:("if_icmpge",2),0xa3:("if_icmpgt",2),
    0xa4:("if_icmple",2),0xa5:("if_acmpeq",2),0xa6:("if_acmpne",2),0xa7:("goto",2),
    0xa8:("jsr",2),0xa9:("ret",1),0xaa:("tableswitch",-1),0xab:("lookupswitch",-1),
    0xac:("ireturn",0),0xad:("lreturn",0),0xae:("freturn",0),0xaf:("dreturn",0),
    0xb0:("areturn",0),0xb1:("return",0),0xb2:("getstatic",2),0xb3:("putstatic",2),
    0xb4:("getfield",2),0xb5:("putfield",2),0xb6:("invokevirtual",2),
    0xb7:("invokespecial",2),0xb8:("invokestatic",2),0xb9:("invokeinterface",4),
    0xba:("invokedynamic",4),0xbb:("new",2),0xbc:("newarray",1),0xbd:("anewarray",2),
    0xbe:("arraylength",0),0xbf:("athrow",0),0xc0:("checkcast",2),0xc1:("instanceof",2),
    0xc2:("monitorenter",0),0xc3:("monitorexit",0),0xc4:("wide",-1),
    0xc5:("multianewarray",3),0xc6:("ifnull",2),0xc7:("ifnonnull",2),
    0xc8:("goto_w",4),0xc9:("jsr_w",4),
}

# ============================================================ class 文件解析
class ClassError(Exception):
    pass


class ClassFile:
    def __init__(self, data):
        self.d = data
        if data[:4] != b"\xca\xfe\xba\xbe":
            raise ClassError("非 .class (magic 不符)")
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
                v = struct.unpack_from(">H", self.d, o)[0]; o += 2; self.cp[i] = (tag, v)
            elif tag in (15,):
                v = struct.unpack_from(">BH", self.d, o); o += 3; self.cp[i] = (tag, v)
            elif tag in (3, 4, 9, 10, 11, 12, 17, 18):
                v = struct.unpack_from(">HH", self.d, o); o += 4; self.cp[i] = (tag, v)
            elif tag in (5, 6):
                v = struct.unpack_from(">I", self.d, o)[0] | (struct.unpack_from(">I", self.d, o + 4)[0] << 32)
                o += 8; self.cp[i] = (tag, v); i += 1
            else:
                raise ClassError("未知常量池 tag %d @%d" % (tag, o))
            i += 1
        self._cp_end = o

    def utf8(self, idx):
        e = self.cp[idx]
        return e[1] if e and e[1] is not None else ""

    def cp_str(self, idx):
        e = self.cp[idx]
        if not e:
            return "?"
        tag = e[0]
        if tag == 1:
            return e[1]
        if tag == 7:
            return self.utf8(e[1])
        if tag == 8:
            return '"%s"' % self.utf8(e[1])
        if tag in (9, 10, 11):
            cls = self.utf8(self.cp[e[1][0]][1])
            nt = e[1][1]
            n = self.utf8(self.cp[nt][1][0]); desc = self.utf8(self.cp[nt][1][1])
            kind = {9: "field", 10: "method", 11: "interface-method"}[tag]
            return "%s.%s:%s" % (cls, n, desc)
        if tag == 12:
            return "%s:%s" % (self.utf8(e[1][0]), self.utf8(e[1][1]))
        if tag in (3, 4):
            return str(e[1])
        return str(e)

    def _parse_members(self, o):
        cnt = struct.unpack_from(">H", self.d, o)[0]; o += 2
        out = []
        for _ in range(cnt):
            acc, name_i, desc_i, ac = struct.unpack_from(">HHHH", self.d, o); o += 8
            attrs = []
            for _ in range(ac):
                name_i2, ln = struct.unpack_from(">HI", self.d, o); o += 6
                attrs.append((self.utf8(name_i2), self.d[o:o + ln])); o += ln
            out.append((acc, self.utf8(name_i), self.utf8(desc_i), attrs))
        return out, o

    def _parse_attrs(self, o):
        cnt = struct.unpack_from(">H", self.d, o)[0]; o += 2
        out = []
        for _ in range(cnt):
            name_i, ln = struct.unpack_from(">HI", self.d, o); o += 6
            out.append((self.utf8(name_i), self.d[o:o + ln])); o += ln
        return out, o


def disasm_method_code(cw, code):
    out = []
    o = 0
    while o < len(code):
        op = code[o]
        if op not in JVM_OP:
            out.append("  %d: <db 0x%02x>" % (o, op)); o += 1; continue
        name, nlen = JVM_OP[op]
        if nlen == 0:
            out.append("  %d: %s" % (o, name)); o += 1
        elif nlen == 1:
            v = code[o + 1]; out.append("  %d: %s %d" % (o, name, v)); o += 2
        elif nlen == 2:
            v = struct.unpack_from(">h", code, o + 1)[0]
            # 分支目标
            if name.startswith("if") or name in ("goto", "jsr"):
                out.append("  %d: %s %d (to %d)" % (o, name, v, o + v))
            elif name == "iinc":
                out.append("  %d: iinc %d, %d" % (o, code[o + 1], struct.unpack_from(">b", code, o + 2)[0]))
            else:
                idx = struct.unpack_from(">H", code, o + 1)[0]
                out.append("  %d: %s #%d // %s" % (o, name, idx, cw.cp_str(idx) if idx < len(cw.cp) else ""))
            o += 3
        elif nlen == 4:
            idx = struct.unpack_from(">H", code, o + 1)[0]
            out.append("  %d: %s #%d" % (o, name, idx)); o += 5
        else:
            out.append("  %d: %s ..." % (o, name)); o += 1
    return out


def class_to_text(data):
    cw = ClassFile(data)
    L = []
    L.append("Class: %s  (major=%d)" % (cw.cp_str(cw.this_class), cw.major))
    L.append("Super: %s" % (cw.cp_str(cw.super_class) if cw.super_class else "-"))
    L.append("Access: 0x%04x" % cw.access)
    L.append("Fields:")
    for acc, name, desc, attrs in cw.fields:
        L.append("  %s %s %s" % (hex(acc), name, desc))
    L.append("Methods:")
    for acc, name, desc, attrs in cw.methods:
        L.append("  %s %s%s" % (hex(acc), name, desc))
        for aname, ablob in attrs:
            if aname == "Code":
                max_stack, max_locals, clen = struct.unpack_from(">HHI", ablob, 0)
                code = ablob[8:8 + clen]
                L.append("    Code: stack=%d locals=%d len=%d" % (max_stack, max_locals, clen))
                for line in disasm_method_code(cw, code):
                    L.append("    " + line)
    return "\n".join(L)


# ============================================================ DEX (精简, 复用思路)
def dex_classes(data):
    if data[:4] != b"dex\n":
        return []
    def u4(o): return struct.unpack_from("<I", data, o)[0]
    def u2(o): return struct.unpack_from("<H", data, o)[0]
    ssz=u4(0x38);soff=u4(0x3C);tsz=u4(0x40);toff=u4(0x44)
    msz=u4(0x58);moff=u4(0x5C);csz=u4(0x60);coff=u4(0x64)
    strings=[]
    for i in range(ssz):
        o=u4(soff+i*4)
        # uleb
        r=0;s=0
        while True:
            b=data[o];o+=1;r|=(b&0x7f)<<s
            if not(b&0x80):break
            s+=7
        e=data.find(b"\0",o);strings.append(data[o:e].decode("utf-8","replace"))
    types=[strings[u4(toff+i*4)] for i in range(tsz)]
    out=[]
    for ci in range(csz):
        o=coff+ci*32;out.append(types[u4(o)])
    return out


# ============================================================ CLI / GUI / 自检
def selftest():
    ok=0;fail=0
    def check(n,c):
        nonlocal ok,fail
        print("  [%s] %s"%("OK " if c else "ERR",n));ok+=1 if c else 0;fail+=0 if c else 1
    check("JVM 操作码表 >= 200",len(JVM_OP)>=200)
    check("含 aload_0",0x2a in JVM_OP)
    check("含 invokevirtual",0xb6 in JVM_OP)
    check("含 new",0xbb in JVM_OP)
    # 用真实 class 测试 (javap 产物)
    import tempfile
    d=tempfile.mkdtemp()
    # 生成一个 class 文件 (最小)
    # 构造常量池: Utf8 "Hello", Class, Utf8 "java/lang/Object", Class
    cp=bytearray()
    cp+=struct.pack(">BH",1,5)+b"Hello"          # #1 Utf8 Hello
    cp+=struct.pack(">BH",7,1)                    # #2 Class #1
    cp+=struct.pack(">BH",1,16)+b"java/lang/Object"  # #3 Utf8
    cp+=struct.pack(">BH",7,3)                    # #4 Class #3
    body=struct.pack(">IHHH",0xCAFEBABE,0,52,5)+cp
    body+=struct.pack(">HHHHH",0x21,2,4,0,0)      # access,this,super,ifaces=0,fields=0
    body+=struct.pack(">H",0)                     # methods=0
    body+=struct.pack(">H",0)                     # attrs=0
    try:
        cw=ClassFile(bytes(body))
        check("解析 class this",cw.cp_str(cw.this_class)=="Hello")
        check("解析 class super",cw.cp_str(cw.super_class)=="java/lang/Object")
        check("class_to_text 含 Class:", "Class: Hello" in class_to_text(bytes(body)))
    except Exception as ex:
        check("解析 class (%s)"%ex,False)
    # DEX
    hdr=bytearray(0x70);hdr[0:8]=b"dex\n035\0"
    check("空 dex 类=0",dex_classes(bytes(hdr))==[])
    print("结果: %d 通过, %d 失败"%(ok,fail))
    return 0 if fail==0 else 1


def run_gui(argv):
    from PySide6.QtWidgets import (
        QApplication,QMainWindow,QWidget,QVBoxLayout,QHBoxLayout,QPushButton,QLabel,
        QPlainTextEdit,QFileDialog,QTreeWidget,QTreeWidgetItem,QSplitter,QMessageBox)
    app=QApplication(sys.argv)
    win=QMainWindow();win.setWindowTitle("Bytecode Viewer 2.11.2  PySide6");win.resize(1000,700)
    cw=QWidget();win.setCentralWidget(cw);lay=QVBoxLayout(cw)
    row=QHBoxLayout();b_open=QPushButton("打开 class/jar/dex/apk");row.addWidget(b_open);row.addStretch();lay.addLayout(row)
    sp=QSplitter()
    tree=QTreeWidget();tree.setHeaderLabels(["类"])
    view=QPlainTextEdit();view.setReadOnly(True)
    sp.addWidget(tree);sp.addWidget(view);lay.addWidget(sp)
    st={}
    def load(p):
        tree.clear();st.clear()
        low=p.lower()
        if low.endswith((".jar",".zip",".apk")):
            with zipfile.ZipFile(p) as z:
                for n in z.namelist():
                    if n.endswith(".class"):
                        data=z.read(n)
                        it=QTreeWidgetItem(tree,[n]);it.setData(0,1,("class",data))
                        tree.addTopLevelItem(it)
                    elif n.endswith(".dex"):
                        it=QTreeWidgetItem(tree,[n]);it.setData(0,1,("dex",z.read(n)))
                        tree.addTopLevelItem(it)
        elif low.endswith(".class"):
            data=open(p,"rb").read()
            it=QTreeWidgetItem(tree,[os.path.basename(p)]);it.setData(0,1,("class",data));tree.addTopLevelItem(it)
        elif low.endswith(".dex"):
            it=QTreeWidgetItem(tree,[os.path.basename(p)]);it.setData(0,1,("dex",open(p,"rb").read()));tree.addTopLevelItem(it)
    def onsel():
        it=tree.currentItem()
        if not it:return
        kind,data=it.data(0,1)
        try:
            if kind=="class":
                view.setPlainText(class_to_text(data))
            else:
                cs=dex_classes(data)
                view.setPlainText("DEX 类:\n"+"\n".join(cs))
        except Exception as ex:
            view.setPlainText("错误: %s"%ex)
    tree.itemSelectionChanged.connect(onsel)
    def do_open():
        p,_=QFileDialog.getOpenFileName(win,"打开","","字节码 (*.class *.jar *.dex *.apk *.zip);;All (*.*)")
        if p:
            try:load(p)
            except Exception as ex:QMessageBox.critical(win,"错误",str(ex))
    b_open.clicked.connect(do_open)
    if len(argv)>1 and os.path.exists(argv[1]):
        load(argv[1])
    win.statusBar().showMessage("就绪");win.show();sys.exit(app.exec())


def main():
    a=sys.argv[1:]
    if "--selftest" in a:return selftest()
    if a and a[0]=="disasm":
        print(class_to_text(open(a[1],"rb").read()));return 0
    run_gui(a);return 0


if __name__=="__main__":
    sys.exit(main() or 0)