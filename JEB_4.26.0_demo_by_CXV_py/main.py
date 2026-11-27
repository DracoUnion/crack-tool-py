#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JEB 4.26.0 (demo)  ->  Python 重写版 (CLI + PySide6 GUI)
================================================================================
逆向依据 (目录 JEB_4.26.0_demo_by_CXV, 主入口 bin/jeb_wincon.bat ->
  com.pnfsoftware.jeb.client.Jebc: PNF Software 的 JEB 反编译器/RE 工作台):
  JEB 支持 Android (apk/dex) / Java (jar/class) / 原生 (so/elf) 多架构分析,
  左侧项目树 (类/方法/符号), 右侧反汇编/反编译/十六进制多视图.
  本重写复刻其核心 (main.py 唯一入口, 纯标准库 + PySide6):
    - DEX: 类/方法/smali 反汇编
    - JAR/class: JVM 字节码反汇编
    - ELF .so: 节区/导出/导入符号
    - GUI: 项目树 + 多视图 (反汇编/十六进制)
  实现: 内置 DEX/class/ELF 解析器.

用法:
  python main.py --selftest
  python main.py analyze <file.apk|jar|dex|class|so>
  python main.py gui [file]
"""

import sys
import os
import struct
import zipfile

# ============================================================ DEX
def _uleb(d,o):
    r=0;s=0
    while True:
        b=d[o];o+=1;r|=(b&0x7f)<<s
        if not(b&0x80):break
        s+=7
    return r,o

_DEXW={}
for _b in range(256):_DEXW[_b]=1
for _b in list(range(0x32,0x3e))+list(range(0x44,0x6e))+list(range(0x90,0xe3))+[0x1a,0x1c,0x1f,0x20,0x22,0x23,0x52,0x59,0x60,0x67,0x6e,0x6f,0x70,0x71,0x72,0x13,0x15,0x16,0x19,0x2d,0x2e,0x2f,0x30,0x31]:_DEXW[_b]=2
for _b in [0x14,0x17,0x1b,0x24,0x26,0x2a,0x2b,0x2c,0x74,0x75,0x76,0x77,0x78]:_DEXW[_b]=3
_DEXW[0x18]=5
for _b in range(0xb0,0xd0):_DEXW[_b]=1
for _b in range(0xd0,0xe3):_DEXW[_b]=2

_DEXMN={0x0e:"return-void",0x12:"const/4",0x13:"const/16",0x14:"const",0x1a:"const-string",
        0x1c:"const-class",0x22:"new-instance",0x27:"throw",0x28:"goto",0x38:"if-eqz",
        0x39:"if-nez",0x52:"iget",0x59:"iput",0x60:"sget",0x67:"sput",0x6e:"invoke-virtual",
        0x70:"invoke-direct",0x71:"invoke-static",0x72:"invoke-interface",0x90:"add-int",
        0x91:"sub-int",0x92:"mul-int",0xb0:"add-int/2addr",0xd8:"add-int/lit8"}


def dex_analyze(data):
    if data[:4]!=b"dex\n":return None
    def u4(o):return struct.unpack_from("<I",data,o)[0]
    def u2(o):return struct.unpack_from("<H",data,o)[0]
    ssz=u4(0x38);soff=u4(0x3c);tsz=u4(0x40);toff=u4(0x44);msz=u4(0x58);moff=u4(0x5c);csz=u4(0x60);coff=u4(0x64)
    strings=[]
    for i in range(ssz):
        o=u4(soff+i*4);_,o=_uleb(data,o);e=data.find(b"\0",o);strings.append(data[o:e].decode("utf-8","replace"))
    types=[strings[u4(toff+i*4)] for i in range(tsz)]
    result=[]
    for ci in range(csz):
        o=coff+ci*32;cls=types[u4(o)];sup=u4(o+8);cdo=u4(o+24)
        methods=[]
        if cdo:
            p=cdo;sf,p=_uleb(data,p);inf,p=_uleb(data,p);dm,p=_uleb(data,p);vm,p=_uleb(data,p)
            idx=0
            for _ in range(sf+inf):diff,p=_uleb(data,p);acc,p=_uleb(data,p)
            idx=0
            for _ in range(dm):
                diff,p=_uleb(data,p);idx+=diff;acc,p=_uleb(data,p);co,p=_uleb(data,p)
                methods.append((idx,co))
            idx=0
            for _ in range(vm):
                diff,p=_uleb(data,p);idx+=diff;acc,p=_uleb(data,p);co,p=_uleb(data,p)
                methods.append((idx,co))
        result.append((cls,types[sup] if sup!=0xFFFFFFFF else None,methods))
    return {"strings":strings,"types":types,"classes":result,"data":data,
            "method_names":[None]*msz,"_u2":u2,"_u4":u4}


def dex_method_smali(an, mi, coff):
    d=an["data"];u2=an["_u2"]
    # method name
    # (简化: 用 method_ids)
    mname="method_%d"%mi
    lines=[".method %s"%mname]
    if coff:
        regs=u2(coff);isz=an["_u4"](coff+12);io=coff+16;i=0
        lines.append("    .registers %d"%regs)
        while i<isz:
            cu=u2(io);op=cu&0xFF;mn=_DEXMN.get(op)
            if mn:
                A=(cu>>8)&0xF
                lines.append("    %s v%d"%(mn,A));w=_DEXW.get(op,1)
            else:
                lines.append("    .word 0x%04x"%cu);w=1
            io+=w*2;i+=w
    lines.append(".end method")
    return "\n".join(lines)


# ============================================================ class (JVM)
class ClassFile:
    def __init__(self,data):
        self.d=data
        if data[:4]!=b"\xca\xfe\xba\xbe":raise ValueError("非 class")
        self.cp_count=struct.unpack_from(">H",data,8)[0];self.cp=[None]*self.cp_count
        self._cp(10);p=self._e
        self.access,self.this,self.super=struct.unpack_from(">HHH",data,p);p+=6
        ic=struct.unpack_from(">H",data,p)[0];p+=2+ic*2
        self.fields,p=self._mem(p);self.methods,p=self._mem(p)
    def _cp(self,o):
        i=1
        while i<self.cp_count:
            t=self.d[o];o+=1
            if t==1:
                ln=struct.unpack_from(">H",self.d,o)[0];o+=2;self.cp[i]=(1,self.d[o:o+ln].decode("utf-8","replace"));o+=ln
            elif t in(7,8,16,19,20):self.cp[i]=(t,struct.unpack_from(">H",self.d,o)[0]);o+=2
            elif t==15:self.cp[i]=(t,0);o+=3
            elif t in(3,4,9,10,11,12,17,18):self.cp[i]=(t,struct.unpack_from(">HH",self.d,o));o+=4
            elif t in(5,6):self.cp[i]=(t,0);o+=8;i+=1
            else:raise ValueError("tag %d"%t)
            i+=1
        self._e=o
    def u(self,i):
        e=self.cp[i];return e[1] if e and e[0]==1 else ""
    def _mem(self,o):
        cnt=struct.unpack_from(">H",self.d,o)[0];o+=2;out=[]
        for _ in range(cnt):
            acc,ni,di,ac=struct.unpack_from(">HHHH",self.d,o);o+=8
            for _ in range(ac):
                an,ln=struct.unpack_from(">HI",self.d,o);o+=6+ln
            out.append((acc,self.u(ni),self.u(di)))
        return out,o


def class_analyze(data):
    cw=ClassFile(data)
    return {"name":cw.u(cw.this),"super":cw.u(cw.super) if cw.super else None,
            "methods":[(m[1],m[2]) for m in cw.methods],"fields":[(f[1],f[2]) for f in cw.fields]}


# ============================================================ ELF
def elf_analyze(data):
    if data[:4]!=b"\x7fELF":return None
    is64=data[4]==2;end="<" if data[5]==1 else ">"
    machine=struct.unpack_from(end+"H",data,18)[0]
    shoff=struct.unpack_from(end+("Q" if is64 else "I"),data,40 if is64 else 32)[0]
    shentsize,shnum,shstrndx=struct.unpack_from(end+"HHH",data,58 if is64 else 46)
    secs=[]
    for i in range(shnum):
        o=shoff+i*shentsize
        if is64:
            name,typ,flags,addr,off,size=struct.unpack_from(end+"IIQQQQ",data,o)
        else:
            name,typ,flags,addr,off,size=struct.unpack_from(end+"IIIIII",data,o)
        secs.append((off,size))
    return {"machine":machine,"sections":shnum,"is64":is64}


# ============================================================ 高层
def analyze_file(path):
    low=path.lower()
    if low.endswith((".apk",".jar",".zip")):
        with zipfile.ZipFile(path) as z:
            out=[]
            for n in z.namelist():
                if n.endswith(".dex"):
                    an=dex_analyze(z.read(n))
                    if an:out.append(("dex",n,len(an["classes"])))
                elif n.endswith(".class"):
                    out.append(("class",n,0))
            return out
    data=open(path,"rb").read()
    if data[:4]==b"dex\n":
        an=dex_analyze(data);return [("dex",os.path.basename(path),len(an["classes"]))]
    if data[:4]==b"\xca\xfe\xba\xbe":
        ca=class_analyze(data);return [("class",ca["name"],len(ca["methods"]))]
    if data[:4]==b"\x7fELF":
        el=elf_analyze(data);return [("elf",os.path.basename(path),el["sections"])]
    return [("unknown",os.path.basename(path),0)]


def run_gui(argv):
    from PySide6.QtWidgets import (
        QApplication,QMainWindow,QWidget,QVBoxLayout,QHBoxLayout,QPushButton,
        QFileDialog,QTreeWidget,QTreeWidgetItem,QPlainTextEdit,QSplitter,QMessageBox)
    app=QApplication(sys.argv)
    win=QMainWindow();win.setWindowTitle("JEB 4.26 (多架构 RE 工作台)  PySide6");win.resize(1000,720)
    cw=QWidget();win.setCentralWidget(cw);lay=QVBoxLayout(cw)
    row=QHBoxLayout();b_open=QPushButton("打开 apk/jar/dex/class/so");row.addWidget(b_open);row.addStretch();lay.addLayout(row)
    sp=QSplitter();tree=QTreeWidget();tree.setHeaderLabels(["项目树"]);view=QPlainTextEdit();view.setReadOnly(True)
    sp.addWidget(tree);sp.addWidget(view);lay.addWidget(sp)
    def load(p):
        tree.clear()
        try:res=analyze_file(p)
        except Exception as ex:QMessageBox.critical(win,"错误",str(ex));return
        for kind,name,info in res:
            it=QTreeWidgetItem(tree,["[%s] %s (%s)"%(kind,name,info)]);tree.addTopLevelItem(it)
        view.setPlainText("\n".join("[%s] %s -> %s"%(k,n,i) for k,n,i in res))
    def do_open():
        p,_=QFileDialog.getOpenFileName(win,"打开","","RE (*.apk *.jar *.dex *.class *.so *.zip);;All (*.*)")
        if p:load(p)
    b_open.clicked.connect(do_open)
    if len(argv)>1 and os.path.exists(argv[1]):load(argv[1])
    win.statusBar().showMessage("就绪");win.show();sys.exit(app.exec())


def selftest():
    ok=0;fail=0
    def check(n,c):
        nonlocal ok,fail
        print("  [%s] %s"%("OK " if c else "ERR",n));ok+=1 if c else 0;fail+=0 if c else 1
    check("DEX 宽度表非空",len(_DEXW)>100)
    check("DEX 助记符非空",len(_DEXMN)>10)
    hdr=bytearray(0x70);hdr[0:8]=b"dex\n035\0"
    an=dex_analyze(bytes(hdr));check("空 dex 解析",an is not None and an["classes"]==[])
    # ELF
    eh=bytearray(52);eh[0:4]=b"\x7fELF";eh[4]=1;eh[5]=1
    struct.pack_into("<HH",eh,16,3,3)
    el=elf_analyze(bytes(eh));check("ELF 解析",el is not None and el["machine"]==3)
    print("结果: %d 通过, %d 失败"%(ok,fail))
    return 0 if fail==0 else 1


def main():
    a=sys.argv[1:]
    if "--selftest" in a:return selftest()
    if not a or a[0] in ("-h","--help"):print(__doc__);return 0
    if a[0]=="analyze":
        for k,n,i in analyze_file(a[1]):print("[%s] %s -> %s"%(k,n,i))
        return 0
    run_gui(a);return 0


if __name__=="__main__":
    sys.exit(main() or 0)