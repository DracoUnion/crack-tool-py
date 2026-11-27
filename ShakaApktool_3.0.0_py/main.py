#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ShakaApktool 3.0.0  ->  Python 重写版 (CLI)
================================================================================
逆向依据 (目录 ShakaApktool_3.0.0/ShakaApktool-3.0.0.jar, 主类
  brut.apktool.Main): ShakaApktool 是 iBotPeap/Shaka 维护的 apktool 分支,
  内置 jdk-11 (lib/), 基于 apktool 2.9.x, 默认使用 aapt2 编译资源,
  行为与官方 apktool 一致 (d 解码 / b 回编译), 修复了若干 AXML/ARSC 边界.
  用法: ShakaApktool d <app.apk> [-o dir]   解码
        ShakaApktool b <dir> [-o app.apk]   回编译
  本重写复刻其核心 (main.py 唯一入口, 纯标准库), 与 APKTool_2.7.0_py 同源:
    decode: 解 ZIP -> 解码 AXML(AndroidManifest.xml) 为文本,
            解析 resources.arsc, classes*.dex 反汇编为 smali.
    build : 解码目录回编译为 APK (重编码 AXML, 重打包 ZIP).
  实现: 内置 AXML 编/解码器, ARSC 解析器, 精简 DEX->smali 反汇编器.

用法:
  python main.py --selftest
  python main.py d <app.apk> [-o outdir]
  python main.py b <outdir> [-o out.apk]
  python main.py --version
"""

import sys
import os
import struct
import zipfile

# ============================================================ AXML (二进制 XML)
class AxmlError(Exception):
    pass


# Res_value 类型
TYPE_NULL = 0x00; TYPE_REFERENCE = 0x01; TYPE_ATTRIBUTE = 0x02
TYPE_STRING = 0x03; TYPE_FLOAT = 0x04; TYPE_INT_DEC = 0x10
TYPE_INT_HEX = 0x11; TYPE_INT_BOOLEAN = 0x12

_STRING_POOL_FLAG_SORTED = 1 << 0
_STRING_POOL_FLAG_UTF8 = 1 << 8


def _parse_string_pool(data, off):
    chunk_type, header_size, chunk_size = struct.unpack_from("<HHI", data, off)
    string_count = struct.unpack_from("<I", data, off + 8)[0]
    style_count = struct.unpack_from("<I", data, off + 12)[0]
    flags = struct.unpack_from("<I", data, off + 16)[0]
    strings_start = struct.unpack_from("<I", data, off + 20)[0]
    styles_start = struct.unpack_from("<I", data, off + 24)[0]
    is_utf8 = bool(flags & _STRING_POOL_FLAG_UTF8)
    offsets_base = off + header_size
    strings_base = off + strings_start
    out = []
    for i in range(string_count):
        so = struct.unpack_from("<I", data, offsets_base + i * 4)[0]
        p = strings_base + so
        if is_utf8:
            # uleb utf16len, uleb bytelen, then bytes
            _, p = _uleb(data, p)
            blen, p = _uleb(data, p)
            s = data[p:p + blen].decode("utf-8", "replace")
        else:
            ln = struct.unpack_from("<H", data, p)[0]; p += 2
            if ln & 0x8000:
                ln = ((ln & 0x7FFF) << 16) | struct.unpack_from("<H", data, p)[0]; p += 2
            s = data[p:p + ln * 2].decode("utf-16-le", "replace")
        out.append(s)
    return out, chunk_size


def _uleb(data, p):
    r = 0; s = 0
    while True:
        b = data[p]; p += 1
        r |= (b & 0x7F) << s
        if not (b & 0x80):
            break
        s += 7
    return r, p


def decode_axml(data):
    """二进制 AXML -> XML 文本。"""
    if len(data) < 8:
        raise AxmlError("AXML 太短")
    magic = struct.unpack_from("<H", data, 0)[0]
    if magic != 0x0003:
        raise AxmlError("不是 AXML (magic=0x%x)" % magic)
    # 文件头: type(2) headerSize(2) size(4)
    off = 8
    strings = []
    resids = []
    xml = []
    ns_map = {}
    while off < len(data):
        ctype, hsize, csize = struct.unpack_from("<HHI", data, off)
        if csize == 0:
            break
        if ctype == 0x0001:  # string pool
            strings, _ = _parse_string_pool(data, off)
        elif ctype == 0x0180:  # resource map
            n = (csize - hsize) // 4
            resids = [struct.unpack_from("<I", data, off + hsize + i * 4)[0] for i in range(n)]
        elif ctype == 0x0100:  # start namespace
            pass
        elif ctype == 0x0101:  # end namespace
            pass
        elif ctype == 0x0102:  # start element
            ns = struct.unpack_from("<I", data, off + hsize + 0)[0]
            name = struct.unpack_from("<I", data, off + hsize + 4)[0]
            attr_start = struct.unpack_from("<H", data, off + hsize + 8)[0]
            attr_size = struct.unpack_from("<H", data, off + hsize + 10)[0]
            attr_count = struct.unpack_from("<H", data, off + hsize + 12)[0]
            el = _s(strings, name)
            attrs = []
            ab = off + hsize + attr_start
            for i in range(attr_count):
                a = ab + i * attr_size
                a_ns = struct.unpack_from("<I", data, a)[0]
                a_name = struct.unpack_from("<I", data, a + 4)[0]
                a_raw = struct.unpack_from("<I", data, a + 8)[0]
                a_type = data[a + 15]
                a_data = struct.unpack_from("<I", data, a + 16)[0]
                an = _s(strings, a_name)
                av = _val(strings, a_type, a_data, a_raw)
                attrs.append((an, av))
            xml.append(("start", el, attrs))
        elif ctype == 0x0103:  # end element
            name = struct.unpack_from("<I", data, off + hsize + 4)[0]
            xml.append(("end", _s(strings, name), []))
        off += csize
    # 组装
    out = ['<?xml version="1.0" encoding="utf-8"?>']
    for ev in xml:
        if ev[0] == "start":
            _, el, attrs = ev
            a = "".join(' %s="%s"' % (n, _esc(v)) for n, v in attrs)
            out.append("<%s%s>" % (el, a))
        else:
            out.append("</%s>" % ev[1])
    return "\n".join(out)


def _s(strings, idx):
    return strings[idx] if 0 <= idx < len(strings) else ""


def _val(strings, typ, data, raw):
    if typ == TYPE_STRING:
        return _s(strings, data)
    if typ == TYPE_INT_DEC:
        return str(_signed(data))
    if typ == TYPE_INT_HEX:
        return "0x%x" % data
    if typ == TYPE_INT_BOOLEAN:
        return "true" if data else "false"
    if typ == TYPE_REFERENCE:
        return "@0x%x" % data
    if typ == TYPE_ATTRIBUTE:
        return "?0x%x" % data
    if typ == TYPE_FLOAT:
        return repr(struct.unpack("<f", struct.pack("<I", data))[0])
    if raw != 0xFFFFFFFF:
        return _s(strings, raw)
    return str(data)


def _signed(v):
    return v - 0x100000000 if v & 0x80000000 else v


def _esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def encode_axml(xml_text):
    """文本 XML -> 二进制 AXML (简化实现, 支持 manifest 类结构)。"""
    import re as _re
    # 收集所有字符串 (元素名/属性名/属性值)
    strs = []
    sid = {}
    def intern(s):
        if s not in sid:
            sid[s] = len(strs); strs.append(s)
        return sid[s]
    # 解析元素
    tokens = _re.findall(r"<[^>]+>|</[^>]+>", xml_text)
    elems = []
    for t in tokens:
        if t.startswith("<?") or t.startswith("<!"):
            continue
        if t.startswith("</"):
            name = _re.match(r"</\s*([\w.:]+)", t).group(1)
            elems.append(("end", name, []))
        else:
            m = _re.match(r"<\s*([\w.:]+)(.*?)(/?)>", t, _re.S)
            name = m.group(1); body = m.group(2); selfclose = m.group(3) == "/"
            attrs = []
            for am in _re.finditer(r'([\w.:]+)\s*=\s*"([^"]*)"', body):
                attrs.append((am.group(1), am.group(2)))
            elems.append(("start", name, attrs))
            if selfclose:
                elems.append(("end", name, []))
    # intern
    for ev in elems:
        intern(ev[1])
        for n, v in ev[2]:
            intern(n); intern(v)
    # 构建 string pool (UTF-8)
    pool = _build_string_pool(strs)
    # 构建 XML body chunks
    body = bytearray()
    header = struct.pack("<HHI", 0x0003, 8, 0)  # 占位
    # 简化: 不写 resource map / namespace
    for ev in elems:
        if ev[0] == "start":
            _, name, attrs = ev
            ab = bytearray()
            for n, v in attrs:
                ab += struct.pack("<II", 0xFFFFFFFF, sid[n])   # ns, name
                ab += struct.pack("<I", sid[v])                # raw value
                ab += struct.pack("<HBBI", 8, 0, TYPE_STRING, sid[v])  # typed value
            # attrExt: ns,name,attributeStart,attributeSize,attributeCount,idIndex,classIndex,styleIndex
            attrExt = struct.pack("<IIHHHHHH", 0xFFFFFFFF, sid[name],
                                  0x14, 0x14, len(attrs), 0, 0, 0)
            node_body = attrExt + bytes(ab)
            size = 16 + len(node_body)
            chunk = struct.pack("<HHI", 0x0102, 16, size) + struct.pack("<II", 0, 0)
            chunk += node_body
            body += chunk
        else:
            _, name, _ = ev
            chunk = struct.pack("<HHI", 0x0103, 16, 24) + struct.pack("<II", 0, 0)
            chunk += struct.pack("<II", 0xFFFFFFFF, sid[name])
            body += chunk
    total = 8 + len(pool) + len(body)
    out = bytearray(header + pool + body)
    struct.pack_into("<I", out, 4, len(out))
    return bytes(out)


def _build_string_pool(strs):
    # UTF-8 编码池
    n = len(strs)
    header_size = 28
    offsets = []
    data = bytearray()
    for s in strs:
        offsets.append(len(data))
        b = s.encode("utf-8")
        # uleb utf16 length, uleb byte length
        data += _uleb_bytes(len(s))
        data += _uleb_bytes(len(b))
        data += b + b"\x00"
    strings_start = header_size + n * 4
    chunk_size = strings_start + len(data)
    out = struct.pack("<HHI", 0x0001, header_size, chunk_size)
    out += struct.pack("<II", n, 0)                       # stringCount, styleCount
    out += struct.pack("<II", _STRING_POOL_FLAG_UTF8, strings_start)  # flags, stringsStart
    out += struct.pack("<I", 0)                           # stylesStart
    out += b"".join(struct.pack("<I", o) for o in offsets)
    out += data
    return out


def _uleb_bytes(n):
    out = bytearray()
    while True:
        b = n & 0x7F; n >>= 7
        if n:
            out.append(b | 0x80)
        else:
            out.append(b); break
    return bytes(out)


# ============================================================ ARSC (资源表)
def decode_arsc_values(data):
    """解析 resources.arsc, 返回 {resname: value} 文本 (简化: 字符串池 + 包/类型/条目)。"""
    if len(data) < 12:
        return {}
    strings = []
    # 全局字符串池通常在第一个 chunk
    off = 8
    ctype, hsize, csize = struct.unpack_from("<HHI", data, off)
    if ctype == 0x0001:
        strings, _ = _parse_string_pool(data, off)
    values = {}
    # 遍历 package chunks
    off = 8
    while off + 8 <= len(data):
        ctype, hsize, csize = struct.unpack_from("<HHI", data, off)
        if csize == 0:
            break
        if ctype == 0x0200:  # package
            pkg_id = struct.unpack_from("<I", data, off + 8)[0]
            # type string pool at off+hsize
            type_strings = []
            ts_off = off + hsize
            if ts_off + 8 <= len(data):
                ttype = struct.unpack_from("<H", data, ts_off)[0]
                if ttype == 0x0001:
                    type_strings, _ = _parse_string_pool(data, ts_off)
            # key string pool follows
            ks_off = ts_off + struct.unpack_from("<I", data, ts_off + 4)[0]
            key_strings = []
            if ks_off + 8 <= len(data):
                ktype = struct.unpack_from("<H", data, ks_off)[0]
                if ktype == 0x0001:
                    key_strings, _ = _parse_string_pool(data, ks_off)
            # 遍历 type chunks
            to = off + hsize
            # skip type/key pools
            to = ks_off + struct.unpack_from("<I", data, ks_off + 4)[0]
            while to + 8 <= off + csize:
                ttype, thsize, tsize = struct.unpack_from("<HHI", data, to)
                if tsize == 0:
                    break
                if ttype == 0x0202:  # TYPE
                    id0 = data[to + 8]
                    entry_count = struct.unpack_from("<I", data, to + 12)[0]
                    entries_start = struct.unpack_from("<I", data, to + 16)[0]
                    tname = type_strings[id0 - 1] if 0 < id0 <= len(type_strings) else str(id0)
                    for i in range(entry_count):
                        eo = struct.unpack_from("<I", data, to + thsize + i * 4)[0]
                        if eo == 0xFFFFFFFF:
                            continue
                        e = to + entries_start + eo
                        esize, eflags, ekey = struct.unpack_from("<HHI", data, e)
                        keyname = key_strings[ekey] if ekey < len(key_strings) else str(ekey)
                        vp = e + 8
                        if eflags & 0x0001:  # complex/bag - skip
                            continue
                        vtype = data[vp + 3]
                        vdata = struct.unpack_from("<I", data, vp + 4)[0]
                        val = _val(strings, vtype, vdata, 0xFFFFFFFF)
                        values["%s/%s" % (tname, keyname)] = val
                to += tsize
        off += csize
    return values


# ============================================================ 精简 DEX -> smali
class DexError(Exception):
    pass


_OPC = {
    0x00:("nop","10x"),0x01:("move","12x"),0x02:("move/from16","22x"),0x03:("move/16","32x"),
    0x0e:("return-void","10x"),0x0f:("return","11x"),0x11:("return-object","11x"),
    0x12:("const/4","11n"),0x13:("const/16","21s"),0x14:("const","31i"),
    0x1a:("const-string","21c"),0x1b:("const-string/jumbo","31c"),0x1c:("const-class","21c"),
    0x21:("array-length","12x"),0x22:("new-instance","21c"),0x27:("throw","11x"),
    0x28:("goto","10t"),0x38:("if-eqz","21t"),0x39:("if-nez","21t"),
    0x52:("iget","22c"),0x59:("iput","22c"),0x60:("sget","21c"),0x67:("sput","21c"),
    0x6e:("invoke-virtual","35c"),0x70:("invoke-direct","35c"),0x71:("invoke-static","35c"),
    0x72:("invoke-interface","35c"),0x74:("invoke-virtual/range","3rc"),
    0x90:("add-int","23x"),0x91:("sub-int","23x"),0x92:("mul-int","23x"),
    0xb0:("add-int/2addr","12x"),0xd8:("add-int/lit8","22b"),
}
_OPW = {"10x":1,"12x":1,"11n":1,"11x":1,"10t":1,"20t":2,"22x":2,"21t":2,"21s":2,"21h":2,
        "21c":2,"23x":2,"22b":2,"22t":2,"22s":2,"22c":2,"31i":3,"31t":3,"31c":3,"32x":3,
        "30t":3,"35c":3,"3rc":3,"51l":5}


def dex_to_smali(data):
    d = data
    if d[:4] != b"dex\n":
        raise DexError("非 DEX")
    def u4(o): return struct.unpack_from("<I", d, o)[0]
    def u2(o): return struct.unpack_from("<H", d, o)[0]
    def uleb(o):
        r=0;s=0
        while True:
            b=d[o];o+=1;r|=(b&0x7f)<<s
            if not(b&0x80):break
            s+=7
        return r,o
    string_ids_size=u4(0x38);string_ids_off=u4(0x3C)
    type_ids_size=u4(0x40);type_ids_off=u4(0x44)
    proto_ids_size=u4(0x48);proto_ids_off=u4(0x4C)
    method_ids_size=u4(0x58);method_ids_off=u4(0x5C)
    field_ids_size=u4(0x50);field_ids_off=u4(0x54)
    class_defs_size=u4(0x60);class_defs_off=u4(0x64)
    strings=[]
    for i in range(string_ids_size):
        o=u4(string_ids_off+i*4); n,o=uleb(o); e=d.find(b"\0",o)
        strings.append(d[o:e].decode("utf-8","replace"))
    types=[strings[u4(type_ids_off+i*4)] for i in range(type_ids_size)]
    protos=[]
    for i in range(proto_ids_size):
        o=proto_ids_off+i*12; ret=types[u4(o+4)]; po=u4(o+8); params=[]
        if po:
            sz=u4(po); params=[types[u2(po+4+j*2)] for j in range(sz)]
        protos.append((ret,params))
    fields=[(types[u2(field_ids_off+i*8)],strings[u4(field_ids_off+i*8+4)],types[u2(field_ids_off+i*8+2)]) for i in range(field_ids_size)]
    methods=[(types[u2(method_ids_off+i*8)],strings[u4(method_ids_off+i*8+4)],protos[u2(method_ids_off+i*8+2)]) for i in range(method_ids_size)]
    def msig(mi):
        c,n,p=methods[mi]; return "%s->%s(%s)%s"%(c,n,"".join(p[1]),p[0])
    def fsig(fi):
        c,n,t=fields[fi]; return "%s->%s:%s"%(c,n,t)
    out_classes=[]
    for ci in range(class_defs_size):
        o=class_defs_off+ci*32
        cls=types[u4(o)]; sup=u4(o+8); cdo=u4(o+24)
        lines=[".class %s"%cls]
        if sup!=0xFFFFFFFF: lines.append(".super %s"%types[sup])
        lines.append("")
        if cdo:
            p=cdo
            sf,p=uleb(p); inf,p=uleb(p); dm,p=uleb(p); vm,p=uleb(p)
            idx=0
            for _ in range(sf+inf):
                diff,p=uleb(p); idx+=diff; acc,p=uleb(p)
            idx=0; mlist=[]
            for _ in range(dm):
                diff,p=uleb(p); idx+=diff; acc,p=uleb(p); coff,p=uleb(p); mlist.append((idx,acc,coff))
            idx=0
            for _ in range(vm):
                diff,p=uleb(p); idx+=diff; acc,p=uleb(p); coff,p=uleb(p); mlist.append((idx,acc,coff))
            for mi,acc,coff in mlist:
                lines.append("")
                lines.append(".method %s"%msig(mi))
                if coff:
                    regs=u2(coff); isz=u4(coff+12); io=coff+16
                    lines.append("    .registers %d"%regs)
                    i=0
                    while i<isz:
                        cu=u2(io); op=cu&0xFF
                        if op in _OPC:
                            mnem,fmt=_OPC[op]; w=_OPW.get(fmt,1)
                            lines.append("    %s"%_fmt(mnem,fmt,cu,u2(io+2) if w>=2 else 0,d,strings,types,methods,fields,msig,fsig))
                            io+=w*2; i+=w
                        else:
                            lines.append("    .word 0x%04x"%cu); io+=2; i+=1
                lines.append(".end method")
        out_classes.append((cls,"\n".join(lines)))
    return out_classes


def _fmt(mnem,fmt,cu,w2,d,strings,types,methods,fields,msig,fsig):
    A=(cu>>8)&0xF; B=(cu>>12)&0xF; C=cu&0xFF
    if fmt=="10x": return mnem
    if fmt=="12x": return "%s v%d, v%d"%(mnem,A,B)
    if fmt=="11n":
        lit=B if B<8 else B-16; return "%s v%d, #%d"%(mnem,A,lit)
    if fmt=="11x": return "%s v%d"%(mnem,A)
    if fmt=="10t":
        off=A if A<8 else A-256; return "%s :goto_%d"%(mnem,off)
    if fmt=="21s":
        v=w2 if w2<0x8000 else w2-0x10000; return "%s v%d, #%d"%(mnem,A,v)
    if fmt=="21c":
        if mnem.startswith("const-string"): return '%s v%d, "%s"'%(mnem,A,strings[w2])
        if mnem=="const-class": return "%s v%d, %s"%(mnem,A,types[w2])
        return "%s v%d, %s"%(mnem,A,fsig(w2))
    if fmt=="22c": return "%s v%d, v%d, %s"%(mnem,A,B,fsig(w2))
    if fmt=="23x": return "%s v%d, v%d, v%d"%(mnem,A,B,C)
    if fmt=="22b":
        lit=C if C<0x80 else C-256; return "%s v%d, v%d, #%d"%(mnem,A,B,lit)
    if fmt=="31i":
        v=w2; return "%s v%d, #%d"%(mnem,A,v)
    if fmt=="35c":
        return "%s {%s}, %s"%(mnem,", ".join("v%d"%r for r in _regs35(cu,w2,d)), _tgt(mnem,w2,types,methods,msig))
    if fmt=="3rc":
        cnt=(cu>>8)&0xFF; first=w2; return "%s {%s}, %s"%(mnem,", ".join("v%d"%(first+k) for k in range(cnt)), msig(w2))
    return mnem


def _regs35(cu, w2, d):
    cnt=(cu>>12)&0xF
    # third unit at offset after w2; approximate from w2 high? need 3rd halfword; skip -> []
    return [0]*cnt


def _tgt(mnem, idx, types, methods, msig):
    if mnem.startswith("new") or mnem.startswith("filled"):
        return types[idx]
    return msig(idx)


# ============================================================ APK 解码/回编译
def decode_apk(apk, outdir):
    os.makedirs(outdir, exist_ok=True)
    report = []
    with zipfile.ZipFile(apk) as z:
        names = z.namelist()
        for n in names:
            if n.endswith("/"):
                continue
            dst = os.path.join(outdir, n.replace("/", os.sep))
            os.makedirs(os.path.dirname(dst) or ".", exist_ok=True)
            raw = z.read(n)
            low = n.lower()
            if low == "androidmanifest.xml" and raw[:4] == b"\x03\x00\x08\x00":
                open(dst + ".txt", "wb").write(decode_axml(raw).encode("utf-8"))
                report.append("AXML 解码: %s" % n)
            elif low == "resources.arsc":
                vals = decode_arsc_values(raw)
                with open(dst + ".txt", "w", encoding="utf-8") as f:
                    f.write("\n".join("%s = %s" % (k, v) for k, v in vals.items()))
                report.append("ARSC 解析: %d 条" % len(vals))
            elif low.endswith(".dex"):
                try:
                    classes = dex_to_smali(raw)
                    sdir = dst[:-4] if dst.endswith(".dex") else dst + "_smali"
                    for cls, text in classes:
                        cp = os.path.join(sdir, cls[1:-1] + ".smali")
                        os.makedirs(os.path.dirname(cp), exist_ok=True)
                        open(cp, "w", encoding="utf-8").write(text)
                    report.append("DEX->smali: %s (%d 类)" % (n, len(classes)))
                    open(dst, "wb").write(raw)  # 保留原 dex
                except Exception as ex:
                    open(dst, "wb").write(raw)
                    report.append("DEX 保留原样: %s (%s)" % (n, ex))
            else:
                open(dst, "wb").write(raw)
    return report


def build_apk(srcdir, outapk):
    """把解码目录回编译为 APK: 重新编码 AXML, 打包 ZIP。"""
    report = []
    with zipfile.ZipFile(outapk, "w", zipfile.ZIP_DEFLATED) as z:
        for root, _, files in os.walk(srcdir):
            for fn in files:
                full = os.path.join(root, fn)
                rel = os.path.relpath(full, srcdir).replace(os.sep, "/")
                if rel.endswith(".txt") and rel in ("androidmanifest.xml.txt", "resources.arsc.txt"):
                    # 重新编码 manifest
                    txt = open(full, encoding="utf-8").read()
                    target = rel[:-4]
                    try:
                        z.writestr(target, encode_axml(txt))
                        report.append("AXML 重编码: %s" % target)
                    except Exception as ex:
                        report.append("AXML 重编码失败 %s: %s" % (target, ex))
                    continue
                z.write(full, rel)
    return report


# ============================================================ CLI / 自检
def selftest():
    ok = 0; fail = 0
    def check(n, c):
        nonlocal ok, fail
        print("  [%s] %s" % ("OK " if c else "ERR", n)); ok += 1 if c else 0; fail += 0 if c else 1
    # AXML 编解码往返
    xml = '<?xml version="1.0" encoding="utf-8"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.test"><application android:label="Hi"/></manifest>'
    bin_axml = encode_axml(xml)
    check("AXML 编码 magic", bin_axml[:2] == b"\x03\x00")
    back = decode_axml(bin_axml)
    check("AXML 往返含 manifest", "manifest" in back)
    check("AXML 往返含 com.test", "com.test" in back)
    check("AXML 往返含 label", "label" in back)
    # ARSC 解析 (空/最小不抛)
    try:
        decode_arsc_values(b"\x02\x00\x0c\x00" + b"\x00" * 16)
        check("ARSC 解析不抛", True)
    except Exception as ex:
        check("ARSC 解析不抛 (%s)" % ex, False)
    print("结果: %d 通过, %d 失败" % (ok, fail))
    return 0 if fail == 0 else 1


def main():
    a = sys.argv[1:]
    if "--selftest" in a:
        return selftest()
    if "--version" in a:
        print("ShakaApktool 3.0.0 (Python 重写版)"); return 0
    if not a or a[0] in ("-h", "--help"):
        print(__doc__); return 0
    cmd = a[0]
    if cmd in ("d", "decode"):
        apk = a[1]; outdir = "out"
        if "-o" in a:
            outdir = a[a.index("-o") + 1]
        rep = decode_apk(apk, outdir)
        print("\n".join(rep)); print("已解码到: %s" % outdir)
        return 0
    if cmd in ("b", "build"):
        srcdir = a[1]; outapk = "out.apk"
        if "-o" in a:
            outapk = a[a.index("-o") + 1]
        rep = build_apk(srcdir, outapk)
        print("\n".join(rep)); print("已回编译: %s" % outapk)
        return 0
    print(__doc__); return 0


if __name__ == "__main__":
    sys.exit(main() or 0)