#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JADX 1.4.5  ->  Python 重写版 (CLI + PySide6 GUI)
================================================================================
逆向依据 (目录 JADX_1.4.5, 主入口 jadx/bin/jadx (jadx-cli) 与 jadx-gui):
  jadx 是 dex/apk -> Java 反编译工具. CLI: jadx -d outdir <input> 输出 .java.
  GUI: 左侧类树, 右侧反编译源码.
  本重写复刻其核心 (main.py 唯一入口, 纯标准库 + PySide6):
    - 解析 DEX (header/string/type/proto/field/method/class/code)
    - 为每个类生成可读 Java 源码 (package/import/class/super/fields/methods,
      常用 Dalvik 指令翻译为近似 Java 语句, 复杂方法回退为 smali 注释)
    - CLI 输出 .java 文件; GUI 类树 + 源码浏览.

用法:
  python main.py --selftest
  python main.py decompile <classes.dex|apk> [-o outdir]
  python main.py gui            # 启动 GUI
"""

import sys
import os
import struct
import zipfile

# ============================================================ DEX 解析
class DexError(Exception):
    pass


def _uleb(d, o):
    r = 0; s = 0
    while True:
        b = d[o]; o += 1
        r |= (b & 0x7F) << s
        if not (b & 0x80):
            break
        s += 7
    return r, o


_OPW = {}
for _b in range(256):
    _OPW[_b] = 1
for _b in list(range(0x02, 0x04)) + [0x1f, 0x20, 0x22, 0x23, 0x26, 0x29, 0x2b, 0x2c,
        0x2d, 0x2e, 0x2f, 0x30, 0x31] + list(range(0x32, 0x3e)) + \
        list(range(0x44, 0x52)) + list(range(0x52, 0x6e)) + [0x6e, 0x6f, 0x70, 0x71, 0x72] + \
        list(range(0x74, 0x79)) + list(range(0x90, 0xe3)) + [0x13, 0x15, 0x16, 0x19, 0x1a, 0x1c]:
    _OPW[_b] = 2
for _b in [0x03, 0x06, 0x09, 0x14, 0x17, 0x1b, 0x24, 0x25, 0x2a, 0x74, 0x75, 0x76, 0x77, 0x78]:
    _OPW[_b] = 3
_OPW[0x18] = 5
for _b in range(0xb0, 0xd0):
    _OPW[_b] = 1
for _b in range(0xd0, 0xe3):
    _OPW[_b] = 2

_MN = {
    0x00:"nop",0x01:"move",0x02:"move/from16",0x03:"move/16",0x04:"move-wide",
    0x07:"move-object",0x0a:"move-result",0x0b:"move-result-wide",0x0c:"move-result-object",
    0x0d:"move-exception",0x0e:"return-void",0x0f:"return",0x10:"return-wide",0x11:"return-object",
    0x12:"const/4",0x13:"const/16",0x14:"const",0x15:"const/high16",0x16:"const-wide/16",
    0x17:"const-wide/32",0x18:"const-wide",0x1a:"const-string",0x1b:"const-string/jumbo",
    0x1c:"const-class",0x1d:"monitor-enter",0x1e:"monitor-exit",0x1f:"check-cast",
    0x20:"instance-of",0x21:"array-length",0x22:"new-instance",0x23:"new-array",
    0x24:"filled-new-array",0x27:"throw",0x28:"goto",0x29:"goto/16",0x2a:"goto/32",
    0x32:"if-eq",0x33:"if-ne",0x34:"if-lt",0x35:"if-ge",0x36:"if-gt",0x37:"if-le",
    0x38:"if-eqz",0x39:"if-nez",0x3a:"if-ltz",0x3b:"if-gez",0x3c:"if-gtz",0x3d:"if-lez",
    0x6e:"invoke-virtual",0x6f:"invoke-super",0x70:"invoke-direct",0x71:"invoke-static",
    0x72:"invoke-interface",0x74:"invoke-virtual/range",0x90:"add-int",0x91:"sub-int",
    0x92:"mul-int",0x93:"div-int",0x94:"rem-int",0xb0:"add-int/2addr",0xd8:"add-int/lit8",
}


class Dex:
    def __init__(self, d):
        self.d = d
        if d[:4] != b"dex\n":
            raise DexError("非 DEX")
        def u4(o): return struct.unpack_from("<I", d, o)[0]
        def u2(o): return struct.unpack_from("<H", d, o)[0]
        self.ssz=u4(0x38);self.soff=u4(0x3C);self.tsz=u4(0x40);self.toff=u4(0x44)
        self.psz=u4(0x48);self.poff=u4(0x4C);self.fsz=u4(0x50);self.foff=u4(0x54)
        self.msz=u4(0x58);self.moff=u4(0x5C);self.csz=u4(0x60);self.coff=u4(0x64)
        self.strings=[]
        for i in range(self.ssz):
            o=u4(self.soff+i*4);n,o=_uleb(d,o);e=d.find(b"\0",o)
            self.strings.append(d[o:e].decode("utf-8","replace"))
        self.types=[self.strings[u4(self.toff+i*4)] for i in range(self.tsz)]
        self.protos=[]
        for i in range(self.psz):
            o=self.poff+i*12;ret=self.types[u4(o+4)];po=u4(o+8);params=[]
            if po:
                sz=u4(po);params=[self.types[u2(po+4+j*2)] for j in range(sz)]
            self.protos.append((ret,params))
        self.fields=[(self.types[u2(self.foff+i*8)],self.strings[u4(self.foff+i*8+4)],
                      self.types[u2(self.foff+i*8+2)]) for i in range(self.fsz)]
        self.methods=[(self.types[u2(self.moff+i*8)],self.strings[u4(self.moff+i*8+4)],
                      self.protos[u2(self.moff+i*8+2)]) for i in range(self.msz)]

    def classes(self):
        d=self.d
        def u4(o): return struct.unpack_from("<I",d,o)[0]
        out=[]
        for ci in range(self.csz):
            o=self.coff+ci*32
            cls=self.types[u4(o)];sup=u4(o+8);cdo=u4(o+24)
            fields=[];methods=[]
            if cdo:
                p=cdo;sf,p=_uleb(d,p);inf,p=_uleb(d,p);dm,p=_uleb(d,p);vm,p=_uleb(d,p)
                idx=0
                for _ in range(sf):
                    diff,p=_uleb(d,p);idx+=diff;acc,p=_uleb(d,p);fields.append((idx,acc,False))
                for _ in range(inf):
                    diff,p=_uleb(d,p);idx+=diff;acc,p=_uleb(d,p);fields.append((idx,acc,True))
                idx=0;ml=[]
                for _ in range(dm):
                    diff,p=_uleb(d,p);idx+=diff;acc,p=_uleb(d,p);co,p=_uleb(d,p);ml.append((idx,acc,co))
                idx=0
                for _ in range(vm):
                    diff,p=_uleb(d,p);idx+=diff;acc,p=_uleb(d,p);co,p=_uleb(d,p);ml.append((idx,acc,co))
                for mi,acc,co in ml: methods.append((mi,acc,co))
            out.append((cls,self.types[sup] if sup!=0xFFFFFFFF else None,fields,methods))
        return out

    def code(self, coff):
        d=self.d
        regs=struct.unpack_from("<H",d,coff)[0];isz=struct.unpack_from("<I",d,coff+12)[0]
        io=coff+16;out=[];i=0
        while i<isz:
            cu=struct.unpack_from("<H",d,io)[0];out.append((cu,io));w=_OPW.get(cu&0xFF,1)
            io+=w*2;i+=w
        return regs,out


# ============================================================ Java 生成
def desc_to_java(t):
    prim={"V":"void","Z":"boolean","B":"byte","S":"short","C":"char","I":"int",
          "J":"long","F":"float","D":"double"}
    if t in prim: return prim[t]
    if t.startswith("L") and t.endswith(";"):
        return t[1:-1].replace("/", ".")
    if t.startswith("["):
        return desc_to_java(t[1:]) + "[]"
    return t


def access_str(a):
    s=[]
    for bit,n in [(1,"public"),(2,"private"),(4,"protected"),(8,"static"),(0x10,"final"),
                  (0x100,"native"),(0x400,"abstract"),(0x1000,"synthetic"),(0x10000,"")]:
        if a&bit and n: s.append(n)
    return " ".join(s)


def gen_java(dex, cls, sup, fields, methods):
    L=[]
    pkg=""
    name=cls[1:-1] if cls.startswith("L") else cls
    if "/" in name:
        pkg,simple=name.rsplit("/",1)
        L.append("package %s;"%pkg.replace("/", "."));L.append("")
    else:
        simple=name
    L.append("%s class %s%s {"%(access_str(0x1) or "public", simple,
             " extends "+desc_to_java(sup) if sup else ""))
    # 字段
    for fi,acc,inst in fields:
        fc,fname,ftype=dex.fields[fi]
        L.append("    %s %s %s;"%(access_str(acc),desc_to_java(ftype),fname))
    # 方法
    for mi,acc,coff in methods:
        mname,proto=dex.methods[mi][1],dex.methods[mi][2]
        ret,params=proto
        ps=", ".join("%s p%d"%(desc_to_java(pt),i) for i,pt in enumerate(params))
        L.append("    %s %s %s(%s) {"%(access_str(acc),desc_to_java(ret),mname,ps))
        if coff:
            regs,insns=dex.code(coff)
            body=_translate_body(dex,insns,regs)
            for bl in body:
                L.append("        "+bl)
        else:
            L.append("        // native / no code")
        L.append("    }")
    L.append("}")
    return "\n".join(L)


def _translate_body(dex, insns, regs):
    out=[]
    for cu,io in insns:
        op=cu&0xFF;A=(cu>>8)&0xF;B=(cu>>12)&0xF;C=cu&0xFF
        mn=_MN.get(op)
        if mn is None:
            out.append(".word 0x%04x // 0x%02x"%(cu,op));continue
        if op==0x0e: out.append("return;")
        elif op==0x0f: out.append("return v%d;"%A)
        elif op==0x11: out.append("return v%d;"%A)
        elif op==0x12:
            lit=B if B<8 else B-16;out.append("v%d = %d; // const/4"%(A,lit))
        elif op in (0x01,0x07): out.append("v%d = v%d;"%(A,B))
        elif op==0x1a:
            sidx=struct.unpack_from("<H",dex.d,io+2)[0]
            out.append('v%d = "%s";'%(A,dex.strings[sidx]))
        elif op in (0x90,0x91,0x92,0x93,0x94):
            opc={0x90:"+",0x91:"-",0x92:"*",0x93:"/",0x94:"%"}[op]
            out.append("v%d = v%d %s v%d;"%(A,B,opc,C))
        elif op in (0x6e,0x6f,0x70,0x71,0x72,0x74):
            out.append("// %s (invoke)"%mn)
        elif op in (0x28,0x29,0x2a): out.append("// goto")
        elif 0x32<=op<=0x3d: out.append("// %s"%mn)
        else: out.append("%s v%d"%(mn,A))
    if not out: out.append("// (empty)")
    return out


def decompile_to_dir(data, outdir):
    dex=Dex(data)
    os.makedirs(outdir,exist_ok=True)
    count=0
    for cls,sup,fields,methods in dex.classes():
        src=gen_java(dex,cls,sup,fields,methods)
        name=cls[1:-1] if cls.startswith("L") else cls
        path=os.path.join(outdir,name+".java")
        os.makedirs(os.path.dirname(path) or ".",exist_ok=True)
        open(path,"w",encoding="utf-8").write(src)
        count+=1
    return count


def load_dex_from_input(path):
    if path.lower().endswith(".apk") or path.lower().endswith(".zip"):
        with zipfile.ZipFile(path) as z:
            for n in z.namelist():
                if n.lower().endswith(".dex"):
                    return z.read(n)
        raise DexError("APK 内无 dex")
    return open(path,"rb").read()


# ============================================================ GUI
def run_gui():
    from PySide6.QtWidgets import (
        QApplication,QMainWindow,QWidget,QVBoxLayout,QHBoxLayout,QPushButton,QLabel,
        QPlainTextEdit,QFileDialog,QTreeWidget,QTreeWidgetItem,QSplitter,QMessageBox)
    app=QApplication(sys.argv)
    win=QMainWindow();win.setWindowTitle("JADX (dex -> Java 反编译)  PySide6");win.resize(1000,680)
    cw=QWidget();win.setCentralWidget(cw);lay=QVBoxLayout(cw)
    row=QHBoxLayout();b_open=QPushButton("打开 dex/apk");row.addWidget(b_open);row.addStretch();lay.addLayout(row)
    sp=QSplitter()
    tree=QTreeWidget();tree.setHeaderLabels(["类 / 方法"])
    src=QPlainTextEdit();src.setReadOnly(True)
    sp.addWidget(tree);sp.addWidget(src);lay.addWidget(sp)
    st={"dex":None}
    def load(p):
        try:
            dex=Dex(load_dex_from_input(p))
        except Exception as ex:
            QMessageBox.critical(win,"错误",str(ex));return
        st["dex"]=dex;tree.clear()
        for cls,sup,fields,methods in dex.classes():
            name=cls[1:-1] if cls.startswith("L") else cls
            it=QTreeWidgetItem(tree,[name])
            it.setData(0,1,cls)
            for mi,acc,coff in methods:
                mn=dex.methods[mi][1]
                child=QTreeWidgetItem(it,[mn]);child.setData(0,1,(cls,mi))
            tree.addTopLevelItem(it)
    def onsel():
        it=tree.currentItem()
        if not it:return
        data=it.data(0,1)
        if isinstance(data,tuple) and len(data)==2 and isinstance(data[1],int):
            cls,mi=data;dex=st["dex"]
            mname,proto=dex.methods[mi][1],dex.methods[mi][2]
            ret,params=proto
            ps=", ".join(desc_to_java(pt) for pt in params)
            lines=["%s %s(%s) {"%(desc_to_java(ret),mname,ps)]
            coff=None
            # 找 code
            for c,sup,fields,methods in dex.classes():
                if c==cls:
                    for m,acc,co in methods:
                        if m==mi: coff=co
            if coff:
                regs,insns=dex.code(coff)
                for bl in _translate_body(dex,insns,regs): lines.append("    "+bl)
            lines.append("}")
            src.setPlainText("\n".join(lines))
        elif isinstance(data,str):
            dex=st["dex"]
            for cls,sup,fields,methods in dex.classes():
                if cls==data:
                    src.setPlainText(gen_java(dex,cls,sup,fields,methods));break
    tree.itemSelectionChanged.connect(onsel)
    def do_open():
        p,_=QFileDialog.getOpenFileName(win,"打开","",  "Dex/APK (*.dex *.apk *.zip);;All (*.*)")
        if p: load(p)
    b_open.clicked.connect(do_open)
    win.statusBar().showMessage("就绪");win.show();sys.exit(app.exec())


# ============================================================ CLI / 自检
def selftest():
    ok=0;fail=0
    def check(n,c):
        nonlocal ok,fail
        print("  [%s] %s"%("OK " if c else "ERR",n));ok+=1 if c else 0;fail+=0 if c else 1
    hdr=bytearray(0x70);hdr[0:8]=b"dex\n035\0"
    struct.pack_into("<I",hdr,0x20,0x70);struct.pack_into("<I",hdr,0x24,0x70)
    struct.pack_into("<I",hdr,0x28,0x12345678)
    try:
        dex=Dex(bytes(hdr));check("解析空 DEX",dex.csz==0)
    except Exception as ex: check("解析空 DEX (%s)"%ex,False)
    check("desc_to_java int",desc_to_java("I")=="int")
    check("desc_to_java String",desc_to_java("Ljava/lang/String;")=="java.lang.String")
    check("desc_to_java 数组",desc_to_java("[I")=="int[]")
    check("操作码表非空",len(_MN)>20)
    print("结果: %d 通过, %d 失败"%(ok,fail))
    return 0 if fail==0 else 1


def main():
    a=sys.argv[1:]
    if "--selftest" in a: return selftest()
    if not a or a[0] in ("-h","--help"): print(__doc__);return 0
    if a[0]=="gui": run_gui();return 0
    if a[0]=="decompile":
        inp=a[1];out="out"
        if "-o" in a: out=a[a.index("-o")+1]
        n=decompile_to_dir(load_dex_from_input(inp),out)
        print("已反编译 %d 个类 -> %s"%(n,out));return 0
    print(__doc__);return 0


if __name__=="__main__":
    sys.exit(main() or 0)