# -*- coding: utf-8 -*-
"""摘要与 HMAC 核心逻辑：SM3 / MD5 / SHA-1 / SHA-224 / SHA-256 / SHA-384 / SHA-512。
不依赖 GUI，便于复用与测试。
"""
import base64
import hashlib
import hmac

from cryptography.hazmat.primitives import hashes


HASH_ALGOS = {
    "SM3":      (hashes.SM3,      32),
    "MD5":      (hashes.MD5,      16),
    "SHA-1":    (hashes.SHA1,     20),
    "SHA-224":  (hashes.SHA224,   28),
    "SHA-256":  (hashes.SHA256,   32),
    "SHA-384":  (hashes.SHA384,   48),
    "SHA-512":  (hashes.SHA512,   64),
}

# 用于 HMAC 的算法（比纯摘要少 MD5，避免弱 Hash 场景误用）
HMAC_ALGOS = {
    "SM3":      hashes.SM3,
    "SHA-1":    hashes.SHA1,
    "SHA-224":  hashes.SHA224,
    "SHA-256":  hashes.SHA256,
    "SHA-384":  hashes.SHA384,
    "SHA-512":  hashes.SHA512,
}


# ---------------------------------------------------------------- 输入解析
def _strip_ws(s: str) -> str:
    return ''.join(s.split())


def _is_hex(s: str) -> bool:
    if not s or len(s) % 2 != 0:
        return False
    return all(c in '0123456789abcdefABCDEF' for c in s)


def _b64_try_decode(s: str):
    t = s.replace('-', '+').replace('_', '/')
    t += '=' * (-len(t) % 4)
    try:
        raw = base64.b64decode(t, validate=True)
    except Exception:
        return None
    return raw


def parse_bytes(text: str) -> bytes:
    """智能解析输入为字节：优先 hex，其次 base64/URL-safe base64，最后按 UTF-8。"""
    t = (text or '').strip()
    if not t:
        raise ValueError("输入为空")
    s = _strip_ws(t)
    if s.lower().startswith('0x'):
        s = s[2:]
    if _is_hex(s):
        return bytes.fromhex(s)
    if len(s) >= 4:  # 过短（<4 字符）不按 base64 猜测，避免 'abc' 这类文本被误判
        raw = _b64_try_decode(t)
        if raw is not None and len(raw) > 0:
            return raw
    return t.encode('utf-8')


# ---------------------------------------------------------------- 摘要
def hash_bytes(algo: str, data: bytes) -> str:
    """计算单个算法的摘要，返回小写 hex。"""
    algo = algo.upper()
    if algo not in HASH_ALGOS:
        raise ValueError("不支持的摘要算法：%s" % algo)
    cls, _size = HASH_ALGOS[algo]
    d = hashes.Hash(cls())
    d.update(data)
    return d.finalize().hex()


def hash_all(data: bytes) -> dict:
    """一次计算全部支持的摘要算法，返回 {算法名: hex}。"""
    out = {}
    for name in HASH_ALGOS:
        out[name] = hash_bytes(name, data)
    return out


def hash_from_text(algo: str, text: str) -> str:
    """从文本/hex/base64 智能解析数据并计算摘要。"""
    return hash_bytes(algo, parse_bytes(text))


# ---------------------------------------------------------------- HMAC
def hmac_bytes(algo: str, key: bytes, data: bytes) -> str:
    """计算 HMAC(Hash=algo, key, data)，返回小写 hex。"""
    algo = algo.upper()
    if algo not in HMAC_ALGOS:
        raise ValueError("HMAC 不支持该摘要算法：%s" % algo)
    if not key:
        raise ValueError("密钥为空")
    return hmac.new(key, data, _hashlib_name(algo)).hexdigest()


def _hashlib_name(algo: str) -> str:
    """把算法名映射为 hashlib 支持的名字；SM3 在 OpenSSL 后端可用。"""
    m = {
        "SM3": "sm3", "MD5": "md5", "SHA-1": "sha1", "SHA-224": "sha224",
        "SHA-256": "sha256", "SHA-384": "sha384", "SHA-512": "sha512",
    }
    return m[algo]


def hmac_from_text(algo: str, key_text: str, data_text: str) -> str:
    """从文本智能解析密钥与数据，计算 HMAC。"""
    return hmac_bytes(algo, parse_bytes(key_text), parse_bytes(data_text))
