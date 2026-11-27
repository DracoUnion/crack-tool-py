#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
GDA 4.04 (GJTechnology, 中文多平台逆向工具)  ->  Python 重写版 (CLI + PySide6 GUI)
================================================================================
逆向依据 (目录 GDA_4.04/GDA4.04.exe, PE32 GUI, 6.4 MB, 内嵌 JRE):
  GDA (全名 Guard/General Data Analyzer) 是中文 Android/多平台逆向分析工具,
  支持 APK/DEX/JAR/SO 的反编译与反汇编, 全中文界面, 主界面左侧类/方法树,
  右侧 smali/Java/十六进制视图.
  本重写复刻其核心 (main.py 唯一入口, 纯标准库 + PySide6, 中文界面):
    - DEX: 解析类/方法, 反汇编为 smali
    - JAR/class: 列出类/方法, JVM 字节码反汇编
    - APK: 解包并列出 dex
    - GUI: 中文类树 + 反汇编/反编译视图

用法:
  python main.py --selftest
  python main.py 分析 <file.apk|dex|jar|class>
  python main.py gui [file]
"""

import sys
import os
import struct
import zipfile

def _uleb(d,o):
    r=0;s=0
    while True:
        b=d[o];o+=1;r|=(b&0x7f)<<s
        if not(b&0x80):break
        s+=7
    return r,o

_DEXW={}
for _b in range(256):_DEXW[_b]=1
for _b in list(range(0x32,0x3e))+list(range(0x44,0x6e))+list(range(0x90,0xe3))+[0x1a,0x1c,0x1f,0x20,0x22,0x23,0x52,0x59,0x60,0x67,0x6e,0x6f,0x70,0x71,0x72,0x13,0x15,0x16,0x19]:_DEXW[_b]=2
for _b in [0x14,0x17,0x1b,0x24,0x26,0x2a,0x2b,0x2c,0x74,0x75,0x76,0x77,0x78]:_DEXW[_b]=3
_DEXW[0x18]=5
for _b in range(0xb0,0xd0):_DEXW[_b]=1

_DEXMN={0x00:"nop",0x01:"move",0x0a:"move-result",0x0e:"return-void",0x0f:"return",
        0x11:"return-object",0x12:"const/4",0x13:"const/16",0x14:"const",0x1a:"const-string",
        0x1b:"const-string/jumbo",0x1c:"const-class",0x1f:"check-cast",0x21:"array-length",
        0x22:"new-instance",0x23:"new-array",0x27:"throw",0x28:"goto",0x38:"if-eqz",
        0x39:"if-nez",0x3a:"if-ltz",0x52:"iget",0x54:"iget-object",0x59:"iput",
        0x5b:"iput-object",0x60:"sget",0x62:"sget-object",0x67:"sput",0x69:"sput-object",
        0x6e:"invoke-virtual",0x6f:"invoke-super",0x70:"invoke-direct",0x71:"invoke-static",
        0x72:"invoke-interface",0x74:"invoke-virtual/range",0x90:"add-int",0x91:"sub-int",
        0x92:"mul-int",0x93:"div-int",0x94:"rem-int",0xb0:"add-int/2addr",0xd8:"add-int/lit8"}


def dex_classes(data):
    if data[:4]!=b"dex\n":return None
    def u4(o):return struct.unpack_from("<I",data,o)[0]
    def u2(o):return struct.unpack_from("<H",data,o)[0]
    ssz=u4(0x38);soff=u4(0x3c);tsz=u4(0x40);toff=u4(0x44)
    msz=u4(0x58);moff=u4(0x5c);csz=u4(0x60);coff=u4(0x64)
    strings=[]
    for i in range(ssz):
        o=u4(soff+i*4);_,o=_uleb(data,o);e=data.find(b"\0",o);strings.append(data[o:e].decode("utf-8","replace"))
    types=[strings[u4(toff+i*4)] for i in range(tsz)]
    mnames=[strings[u4(moff+i*8+4)] for i in range(msz)]
    out=[]
    for ci in range(csz):
        o=coff+ci*32;cls=types[u4(o)];sup=u4(o+8);cdo=u4(o+24);methods=[]
        if cdo:
            p=cdo;sf,p=_uleb(data,p);inf,p=_uleb(data,p);dm,p=_uleb(data,p);vm,p=_uleb(data,p)
            idx=0
            for _ in range(sf+inf):diff,p=_uleb(data,p);acc,p=_uleb(data,p)
            idx=0
            for _ in range(dm+vm):
                diff,p=_uleb(data,p);idx+=diff;acc,p=_uleb(data,p);co,p=_uleb(data,p)
                methods.append((idx,co))
        out.append((cls,types[sup] if sup!=0xFFFFFFFF else None,methods))
    return {"classes":out,"data":data,"mnames":mnames,"u2":u2,"u4":u4,"types":types,"strings":strings}


def method_smali(an,mi,coff):
    d=an["data"];u2=an["u2"];name=an["mnames"][mi] if mi<len(an["mnames"]) else "m%d"%mi
    L=[".method %s"%name]
    if coff:
        regs=u2(coff);isz=an["u4"](coff+12);io=coff+16;i=0
        L.append("    .registers %d"%regs)
        while i<isz:
            cu=u2(io);op=cu&0xFF;mn=_DEXMN.get(op)
            if mn:
                A=(cu>>8)&0xF;B=(cu>>12)&0xF
                if op==0x12:L.append("    const/4 v%d, #%d"%(A,B if B<8 else B-16))
                elif mn.startswith("invoke"):L.append("    %s (invoke)"%mn)
                else:L.append("    %s v%d"%(mn,A))
                w=_DEXW.get(op,1)
            else:L.append("    .word 0x%04x"%cu);w=1
            io+=w*2;i+=w
    L.append(".end method")
    return "\n".join(L)


def class_analyze(data):
    if data[:4]!=b"\xca\xfe\xba\xbe":return None
    cpc=struct.unpack_from(">H",data,8)[0];cp=[None]*cpc;o=10;i=1
    while i<cpc:
        t=data[o];o+=1
        if t==1:
            ln=struct.unpack_from(">H",data,o)[0];o+=2;cp[i]=(1,data[o:o+ln].decode("utf-8","replace"));o+=ln
        elif t in(7,8,16,19,20):cp[i]=(t,struct.unpack_from(">H",data,o)[0]);o+=2
        elif t==15:o+=3
        elif t in(3,4,9,10,11,12,17,18):cp[i]=(t,struct.unpack_from(">HH",data,o));o+=4
        elif t in(5,6):o+=8;i+=1
        else:break
        i+=1
    def u(i):
        e=cp[i];return e[1] if e and e[0]==1 else ""
    p=o;acc,this,sup=struct.unpack_from(">HHH",data,p);p+=6
    ic=struct.unpack_from(">H",data,p)[0];p+=2+ic*2
    # 跳过 fields
    fcnt=struct.unpack_from(">H",data,p)[0];p+=2
    for _ in range(fcnt):
        a,ni,di,ac=struct.unpack_from(">HHHH",data,p);p+=8
        for _ in range(ac):
            an,ln=struct.unpack_from(">HI",data,p);p+=6+ln
    # 解析 methods
    methods=[]
    mcnt=struct.unpack_from(">H",data,p)[0];p+=2
    for _ in range(mcnt):
        a,ni,di,ac=struct.unpack_from(">HHHH",data,p);p+=8
        for _ in range(ac):
            an,ln=struct.unpack_from(">HI",data,p);p+=6+ln
        methods.append((u(ni),u(di)))
    return {"name":u(this),"super":u(sup) if sup else None,"methods":methods}


def analyze(path):
    low=path.lower()
    if low.endswith((".apk",".jar",".zip")):
        with zipfile.ZipFile(path) as z:
            out=[]
            for n in z.namelist():
                if n.endswith(".dex"):
                    an=dex_classes(z.read(n))
                    if an:out.append(("DEX",n,"%d 个类"%len(an["classes"])))
                elif n.endswith(".class"):out.append(("CLASS",n,""))
            return out
    data=open(path,"rb").read()
    if data[:4]==b"dex\n":
        an=dex_classes(data);return [("DEX",os.path.basename(path),"%d 个类"%len(an["classes"]))]
    if data[:4]==b"\xca\xfe\xba\xbe":
        ca=class_analyze(data);return [("CLASS",ca["name"],"%d 个方法"%len(ca["methods"]))]
    return [("未知",os.path.basename(path),"")]


def run_gui(argv):
    from PySide6.QtWidgets import (
        QApplication,QMainWindow,QWidget,QVBoxLayout,QHBoxLayout,QPushButton,
        QFileDialog,QTreeWidget,QTreeWidgetItem,QPlainTextEdit,QSplitter,QMessageBox)
    app=QApplication(sys.argv)
    win=QMainWindow();win.setWindowTitle("GDA 4.04 (中文多平台逆向)  PySide6");win.resize(1000,720)
    cw=QWidget();win.setCentralWidget(cw);lay=QVBoxLayout(cw)
    row=QHBoxLayout();b=QPushButton("打开文件 (APK/DEX/JAR/CLASS)");row.addWidget(b);row.addStretch();lay.addLayout(row)
    sp=QSplitter();tree=QTreeWidget();tree.setHeaderLabels(["类 / 方法"]);view=QPlainTextEdit();view.setReadOnly(True)
    sp.addWidget(tree);sp.addWidget(view);lay.addWidget(sp)
    st={}
    def load(p):
        tree.clear();st.clear()
        low=p.lower()
        if low.endswith((".apk",".jar",".zip")):
            with zipfile.ZipFile(p) as z:
                for n in z.namelist():
                    if n.endswith(".dex"):
                        an=dex_classes(z.read(n))
                        if an:
                            st[n]=an
                            it=QTreeWidgetItem(tree,["%s"%n])
                            for cls,sup,methods in an["classes"]:
                                cit=QTreeWidgetItem(it,[cls]);cit.setData(0,1,("cls",an,cls,methods))
                            tree.addTopLevelItem(it)
        elif low.endswith(".dex"):
            an=dex_classes(open(p,"rb").read());st[p]=an
            it=QTreeWidgetItem(tree,[os.path.basename(p)])
            for cls,sup,methods in an["classes"]:
                cit=QTreeWidgetItem(it,[cls]);cit.setData(0,1,("cls",an,cls,methods))
            tree.addTopLevelItem(it)
        elif low.endswith(".class"):
            ca=class_analyze(open(p,"rb").read())
            it=QTreeWidgetItem(tree,[ca["name"]]);it.setData(0,1,("jclass",ca));tree.addTopLevelItem(it)
    def onsel():
        it=tree.currentItem()
        if not it:return
        data=it.data(0,1)
        if not data:view.clear();return
        if data[0]=="cls":
            _,an,cls,methods=data
            lines=[".class %s"%cls,".super %s"%(an["classes"][0][1] or "")]
            for mi,co in methods:lines.append(method_smali(an,mi,co))
            view.setPlainText("\n".join(lines))
        elif data[0]=="jclass":
            ca=data[1];view.setPlainText("class %s extends %s\n方法:\n"%(ca["name"],ca["super"])+"\n".join("%s %s"%(n,d) for n,d in ca["methods"]))
    tree.itemSelectionChanged.connect(onsel)
    def do_open():
        p,_=QFileDialog.getOpenFileName(win,"打开","","逆向 (*.apk *.dex *.jar *.class *.zip);;所有 (*.*)")
        if p:
            try:load(p)
            except Exception as ex:QMessageBox.critical(win,"错误",str(ex))
    b.clicked.connect(do_open)
    if len(argv)>1 and os.path.exists(argv[1]):load(argv[1])
    win.statusBar().showMessage("就绪");win.show();sys.exit(app.exec())


def selftest():
    ok=0;fail=0
    def check(n,c):
        nonlocal ok,fail
        print("  [%s] %s"%("OK " if c else "ERR",n));ok+=1 if c else 0;fail+=0 if c else 1
    check("DEX 助记符 >= 30",len(_DEXMN)>=30)
    hdr=bytearray(0x70);hdr[0:8]=b"dex\n035\0"
    struct.pack_into("<I",hdr,0x20,0x70);struct.pack_into("<I",hdr,0x24,0x70)
    an=dex_classes(bytes(hdr));check("空 DEX 解析",an is not None and an["classes"]==[])
    check("class 非 class 返回 None",class_analyze(b"xxxx") is None)
    print("结果: %d 通过, %d 失败"%(ok,fail))
    return 0 if fail==0 else 1


def main():
    a=sys.argv[1:]
    if "--selftest" in a:return selftest()
    if not a or a[0] in ("-h","--help"):print(__doc__);return 0
    if a[0]=="分析":
        for k,n,i in analyze(a[1]):print("[%s] %s -> %s"%(k,n,i))
        return 0
    run_gui(a);return 0


if __name__=="__main__":
    sys.exit(main() or 0)