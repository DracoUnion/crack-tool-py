# -*- coding: utf-8 -*-
"""
de4dot.code.Utils — 逐函数 Python 端口
=====================================

来源：de4dot_2.0.3/bin/de4dot.code.dll 反编译（ICSharpCode.Decompiler）中的
`de4dot.Utils` 静态类。这些是纯函数（字符串/路径/集合工具），与 IL 操作无关，
可逐函数忠实移植，作为对 de4dot 引擎“逐函数逆向”的可测试部分。

移植函数（与 C# 一一对应）：
  unique<T> / toCsharpString / shellEscape / removeNewlines / getFullPath /
  randomName / getBaseName / getDirName / StartsWith / getAssemblySimpleName /
  pathExists / fileExists
"""

import os
import random
import string


def unique(values):
    """对应 Utils.unique<T>：去重并保持首次出现顺序（C# 用 Dictionary 键）。"""
    seen = {}
    for v in values:
        seen[v] = True
    return list(seen.keys())


def to_csharp_string(s):
    """对应 Utils.toCsharpString(string)：转成 C# 字符串字面量（带引号与转义）。"""
    out = ['"']
    for c in s:
        if c < ' ':
            if c == '\a':
                out.append('\\a')
            elif c == '\b':
                out.append('\\b')
            elif c == '\f':
                out.append('\\f')
            elif c == '\n':
                out.append('\\n')
            elif c == '\r':
                out.append('\\r')
            elif c == '\t':
                out.append('\\t')
            elif c == '\v':
                out.append('\\v')
            else:
                out.append('\\u%04X' % ord(c))
        elif c == '\\' or c == '"':
            out.append('\\' + c)
        else:
            out.append(c)
    out.append('"')
    return ''.join(out)


def shell_escape(s):
    """对应 Utils.shellEscape：仅转义双引号，整体加引号。"""
    out = ['"']
    for c in s:
        if c == '"':
            out.append('\\"' )
        else:
            out.append(c)
    out.append('"')
    return ''.join(out)


def remove_newlines(s):
    """对应 Utils.removeNewlines：\\n 与 \\r 替换为空格。"""
    return s.replace('\n', ' ').replace('\r', ' ')


def get_full_path(path):
    """对应 Utils.getFullPath：Path.GetFullPath 的等价（失败返回原串）。"""
    try:
        return os.path.abspath(path)
    except Exception:
        return path


def random_name(rng, mn, mx):
    """对应 Utils.randomName(min,max)：首字符大写，其余小写，按 1..4 段切换。"""
    num = rng.randint(mn, mx)
    sb = []
    num2 = 0
    for _ in range(num):
        if num2 == 0:
            sb.append(chr(65 + rng.randint(0, 25)))   # A-Z
        else:
            sb.append(chr(97 + rng.randint(0, 25)))   # a-z
        num2 = (num2 - 1) if num2 != 0 else rng.randint(1, 4)
    return ''.join(sb)


def get_base_name(name):
    """对应 Utils.getBaseName：取最后一个目录分隔符之后的部分。"""
    num = max(name.rfind('\\'), name.rfind('/'))
    if num < 0:
        return name
    return name[num + 1:]


def get_dir_name(name):
    """对应 Utils.getDirName：Path.GetDirectoryName。"""
    d = os.path.dirname(name)
    return d if d else None


def starts_with(left, right):
    """对应 Utils.StartsWith（序数比较）。"""
    if len(left) < len(right):
        return False
    return left[:len(right)] == right


def get_assembly_simple_name(name):
    """对应 Utils.getAssemblySimpleName：取第一个逗号之前的部分。"""
    num = name.find(',')
    if num < 0:
        return name
    return name[:num]


def path_exists(path):
    """对应 Utils.pathExists。"""
    try:
        return os.path.isdir(path)
    except Exception:
        return False


def file_exists(path):
    """对应 Utils.fileExists。"""
    try:
        return os.path.isfile(path)
    except Exception:
        return False


if __name__ == "__main__":
    # 简单自测
    assert unique([1, 2, 2, 3, 1]) == [1, 2, 3]
    assert to_csharp_string('a"b\\c\n') == '"a\\"b\\\\c\\n"'
    assert shell_escape('a"b') == '"a\\"b"'
    assert remove_newlines('a\r\nb') == 'a  b'
    assert get_base_name('C:\\x\\y.dll') == 'y.dll'
    assert get_assembly_simple_name('Foo, Version=1.0') == 'Foo'
    assert starts_with('hello', 'he') and not starts_with('hi', 'he')
    r = random.Random(1234)
    n = random_name(r, 5, 8)
    assert 5 <= len(n) <= 8 and n[0].isupper()
    print("de4dot.code.Utils port self-test: ALL OK")
    print("toCsharpString demo:", to_csharp_string('hi\t"there"'))