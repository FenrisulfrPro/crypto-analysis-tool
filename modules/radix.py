# -*- coding: utf-8 -*-
"""进制转换核心逻辑：二进制 / 八进制 / 十进制 / 十六进制 互转。

纯标准库实现，不依赖 GUI；仅支持整数（Python int 任意精度，大数天然支持）。
默认 十进制 → 十六进制；统一入口 convert(text, src, dst)。

输出规则（固化约定）：
- 负号直传：符号前置 + 绝对值按各进制排版（不做补码、不做位宽选择）；
- hex：大写、字节对齐（补齐偶数长度，不足补前导 0）；
- bin：补齐到 8 的倍数位，按 8 位一组空格分隔；
- oct / dec：最短表示。

输入容错：去空格 / 下划线 / 千分位逗号；接受与所选进制一致的
0b / 0o / 0x 前缀；非法字符抛 ValueError（中文消息）。
"""

# 进制注册表：key -> (基数, 中文标签, 前缀)
_BASES = {
    "bin": (2, "二进制", "0b"),
    "oct": (8, "八进制", "0o"),
    "dec": (10, "十进制", ""),
    "hex": (16, "十六进制", "0x"),
}

# 各进制允许的数字字符（小写归一后比对）
_ALLOWED_DIGITS = {
    "bin": set("01"),
    "oct": set("01234567"),
    "dec": set("0123456789"),
    "hex": set("0123456789abcdef"),
}

_OUT_LABELS = {k: v[1] for k, v in _BASES.items()}


def parse_int(text, base):
    """容错解析输入文本为整数，非法输入抛 ValueError（中文消息）。"""
    if base not in _BASES:
        raise ValueError("不支持的进制：%s" % base)
    radix, label, prefix = _BASES[base]
    s = (text or "").strip()
    if not s:
        raise ValueError("输入为空")
    for sep in (" ", "_", ",", "，"):
        s = s.replace(sep, "")
    negative = s.startswith("-")
    if negative:
        s = s[1:]
    low = s.lower()
    if prefix and low.startswith(prefix):
        s = s[2:]
    elif low[:2] in ("0b", "0o", "0x") and low[:2] != prefix:
        raise ValueError("%s 输入不应带 %s 前缀" % (label, low[:2]))
    if not s:
        raise ValueError("%s 输入为空" % label)
    bad = set(s.lower()) - _ALLOWED_DIGITS[base]
    if bad:
        raise ValueError("%s 含非法字符：%s" % (label, "、".join(sorted(bad))))
    try:
        n = int(s, radix)
    except ValueError:
        raise ValueError("%s 数值格式错误：%s" % (label, text.strip()[:32]))
    return -n if negative else n


def _fmt_bin(n):
    """二进制：补齐到 8 的倍数位，按 8 位一组空格分隔（入参非负）。"""
    s = format(n, "b")
    s = "0" * ((-len(s)) % 8) + s
    return " ".join(s[i:i + 8] for i in range(0, len(s), 8))


def _fmt_oct(n):
    """八进制：最短表示（入参非负）。"""
    return format(n, "o")


def _fmt_dec(n):
    """十进制：最短表示（入参非负）。"""
    return str(n)


def _fmt_hex(n):
    """十六进制：大写、字节对齐（补齐偶数长度，不足补前导 0，入参非负）。"""
    s = format(n, "X")
    return s if len(s) % 2 == 0 else "0" + s


_FORMATTERS = {"bin": _fmt_bin, "oct": _fmt_oct, "dec": _fmt_dec, "hex": _fmt_hex}


def format_in(n, base):
    """把整数格式化为指定进制字符串：负号直传 + 绝对值按输出规则排版。"""
    if base not in _FORMATTERS:
        raise ValueError("不支持的进制：%s" % base)
    body = _FORMATTERS[base](abs(n))
    return ("-" + body) if n < 0 else body


def all_bases(n):
    """返回 [(进制 key, 中文标签, 字符串)] 四进制全景（置顶顺序由 GUI 决定）。"""
    return [(k, _OUT_LABELS[k], format_in(n, k)) for k in ("bin", "oct", "dec", "hex")]


def out_label(base):
    """进制的中文标签。"""
    return _OUT_LABELS.get(base, base)


def convert(text, src, dst):
    """统一转换入口：src/dst ∈ {bin, oct, dec, hex}，非法输入抛 ValueError。"""
    return format_in(parse_int(text, src), dst)
