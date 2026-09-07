# -*- coding: utf-8 -*-
"""常用编码转换核心逻辑"""
import base64
import binascii
import urllib.parse


def to_hex(data: bytes) -> str:
    return data.hex().upper()


def from_hex(s: str) -> bytes:
    """HEX 字符串转字节，容忍空格/0x 前缀/奇数位自动补零"""
    s = s.strip().replace(' ', '').replace('\n', '').replace('\r', '')
    if s.lower().startswith('0x'):
        s = s[2:]
    if len(s) % 2 == 1:
        s = '0' + s
    return bytes.fromhex(s)


def to_base64(data: bytes) -> str:
    return base64.b64encode(data).decode('ascii')


def from_base64(s: str) -> bytes:
    s = ''.join(s.split())
    # 补全 padding
    pad = len(s) % 4
    if pad:
        s += '=' * (4 - pad)
    return base64.b64decode(s, validate=False)


def url_encode(data: bytes) -> str:
    return urllib.parse.quote_from_bytes(data, safe='')


def url_decode(s: str) -> bytes:
    return urllib.parse.unquote_to_bytes(s)


def unicode_escape(data: bytes) -> str:
    """UTF-8 字节转 \\uXXXX / 可打印原样展示的转义形式"""
    out = []
    for b in data:
        if 0x20 <= b < 0x7f:
            out.append(chr(b))
        elif b < 0x80:
            out.append('\\x%02x' % b)
        else:
            out.append('\\u%04x' % b)
    return ''.join(out)


def utf8_view(data: bytes) -> str:
    """逐字节 UTF-8 视图：如 E4 B8 AD (文)"""
    try:
        text = data.decode('utf-8')
    except UnicodeDecodeError:
        return "（无法按 UTF-8 解码，可能是其它编码或二进制数据）"
    parts = []
    i = 0
    while i < len(data):
        ch = text[i]
        ch_len = len(ch.encode('utf-8'))
        parts.append('%s (%s)' % (' '.join('%02X' % b for b in data[i:i + ch_len]), ch))
        i += ch_len
    return ' '.join(parts)


# ---------------- 多编码形式互转（Base64 / Base64URL / HEX / UTF-8 / URL） ----------------

def to_base64url(data: bytes) -> str:
    """Base64 URL 安全编码（std 字符集：- 与 _）"""
    return base64.urlsafe_b64encode(data).decode('ascii')


def from_base64url(s: str) -> bytes:
    """Base64 URL 安全解码（容忍空格/换行，自动补全 padding）"""
    s = ''.join(s.split())
    pad = len(s) % 4
    if pad:
        s += '=' * (4 - pad)
    return base64.urlsafe_b64decode(s)


def to_hex_lower(data: bytes) -> str:
    return data.hex().lower()


# 支持的输入格式名 -> (描述, 解析函数)
_INPUT_DECODERS = {
    "base64":    ("Base64",              from_base64),
    "base64url": ("Base64URL（URL 安全）", from_base64url),
    "hex":       ("HEX（十六进制）",       from_hex),
    "utf8":      ("UTF-8 文本",           lambda s: s.encode('utf-8')),
    "url":       ("URL 编码",             url_decode),
}

_OUTPUT_ENCODERS = {
    "base64":    ("Base64",              to_base64),
    "base64url": ("Base64URL（URL 安全）", to_base64url),
    "hex_upper": ("HEX 大写",            to_hex),
    "hex_lower": ("HEX 小写",            to_hex_lower),
    "utf8":      ("UTF-8 文本",          lambda b: b.decode('utf-8', 'replace')),
    "url":       ("URL 编码",            lambda b: url_encode(b)),
}

# 输入格式自动识别
_HEX_CHARS = set("0123456789abcdefABCDEF ")
_B64_CHARS = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/= \n\r\t")


def sniff_input(text: str) -> str:
    """自动识别输入格式：hex / base64 / base64url / utf8"""
    s = text.strip()
    if not s:
        return "utf8"
    t = s.replace('0x', '').replace('0X', '') if s.lower().startswith('0x') else s
    if t and set(t) <= _HEX_CHARS and len(t.replace(' ', '')) % 2 == 0 and any(c in "abcdefABCDEF" for c in t):
        return "hex"
    if set(s) <= _B64_CHARS:
        if '-' in s or '_' in s:
            return "base64url"
        return "base64"
    return "utf8"


def convert(src: str, dst: str, text: str) -> str:
    """统一编码转换入口。

    src: base64 / base64url / hex / utf8 / url / auto
    dst: base64 / base64url / hex_upper / hex_lower / utf8 / url
    返回转换后字符串。
    """
    src = src if src != "auto" else sniff_input(text)
    if src not in _INPUT_DECODERS:
        raise ValueError("不支持的输入格式：%s" % src)
    if dst not in _OUTPUT_ENCODERS:
        raise ValueError("不支持的输出格式：%s" % dst)
    raw = _INPUT_DECODERS[src][1](text)
    return _OUTPUT_ENCODERS[dst][1](raw)
