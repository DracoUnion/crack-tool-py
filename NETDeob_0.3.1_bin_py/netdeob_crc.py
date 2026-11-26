#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NETDeob.Core — CRC (SevenZip.CRC) 逐函数 Python 端口
====================================================

来源：`NETDeob_0.3.1_bin/NETDeob.Core.dll` 反编译中的 `SevenZip.CRC` 类。

C# 核心（逐行对应）：
  static ctor: Table[256] 由多项式 0xEDB88320 反射生成；
  _value 初值 uint.MaxValue；
  UpdateByte(b): _value = Table[(byte)_value ^ b] ^ (_value >> 8)；
  Update(data, offset, size): 逐字节调用 UpdateByte；
  GetDigest(): _value ^ 0xFFFFFFFFu；
  CalculateDigest / VerifyDigest: 封装。

本端口保留相同的类/方法名与算法，可直接与原 DLL 交叉验证。
"""

import struct
from typing import List


class CRC:
    Table: List[int]

    def __init__(self):
        self._value = 0xFFFFFFFF

    def update_byte(self, b: int):
        self._value = self.Table[(self._value ^ b) & 0xFF] ^ (self._value >> 8)

    def update(self, data: bytes, offset: int, size: int):
        for num in range(size):
            self._value = self.Table[(self._value ^ data[offset + num]) & 0xFF] ^ (self._value >> 8)

    def get_digest(self) -> int:
        return self._value ^ 0xFFFFFFFF


# 生成 Table（与 C# 静态构造函数一致）
_TABLE = [0] * 256
for _num in range(256):
    _num2 = _num
    for _ in range(8):
        if (_num2 & 1) == 0:
            _num2 >>= 1
        else:
            _num2 = (_num2 >> 1) ^ 0xEDB88320
    _TABLE[_num] = _num2 & 0xFFFFFFFF

CRC.Table = _TABLE


def calculate_digest(data: bytes, offset: int, size: int) -> int:
    crc = CRC()
    crc.update(data, offset, size)
    return crc.get_digest()


def verify_digest(digest: int, data: bytes, offset: int, size: int) -> bool:
    return calculate_digest(data, offset, size) == digest


if __name__ == "__main__":
    import zlib
    # 自测：与 zlib.crc32（标准 CRC32）交叉验证
    tests = [b"", b"a", b"abc", b"The quick brown fox jumps over the lazy dog",
             bytes(range(256)), os.urandom(1000) if False else b"x" * 1000]
    ok = True
    for t in tests:
        mine = calculate_digest(t, 0, len(t))
        ref = zlib.crc32(t) & 0xFFFFFFFF
        if mine != ref:
            ok = False
            print("MISMATCH len=%d: mine=0x%08X ref=0x%08X" % (len(t), mine, ref))
    # VerifyDigest 路径
    d = calculate_digest(b"NETDeob.Core", 0, len(b"NETDeob.Core"))
    assert verify_digest(d, b"NETDeob.Core", 0, len(b"NETDeob.Core"))
    assert not verify_digest(d ^ 1, b"NETDeob.Core", 0, len(b"NETDeob.Core"))
    # 单字节 UpdateByte 路径与 Update 一致
    c1 = CRC()
    for b in b"NETDeob.Core":
        c1.update_byte(b)
    c2 = CRC()
    c2.update(b"NETDeob.Core", 0, len(b"NETDeob.Core"))
    assert c1.get_digest() == c2.get_digest()
    print("NETDeob.Core CRC port self-test: %s" % ("ALL OK" if ok else "FAILED"))
    print("Table[0]=0x%08X  Table[1]=0x%08X" % (CRC.Table[0], CRC.Table[1]))