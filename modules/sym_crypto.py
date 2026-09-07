# -*- coding: utf-8 -*-
"""对称加解密核心逻辑：SM4 / AES，支持 ECB / CBC / CFB / OFB / CTR / GCM。
不依赖 GUI，便于复用与测试。
"""
import base64
import secrets

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# CFB/OFB 自 cryptography 44+ 起移入“弃用区”，此处兼容新旧版本导入路径
try:  # pragma: no cover
    from cryptography.hazmat.decrepit.ciphers.modes import CFB as _CFB
    from cryptography.hazmat.decrepit.ciphers.modes import OFB as _OFB
except Exception:  # pragma: no cover
    from cryptography.hazmat.primitives.ciphers.modes import CFB as _CFB
    from cryptography.hazmat.primitives.ciphers.modes import OFB as _OFB

# 支持的算法：名称 -> (键长列表)
ALGORITHMS = {
    "SM4": (16,),            # 国密 SM4，128 位分组 / 16 字节密钥
    "AES": (16, 24, 32),     # AES-128/192/256
}

# 各模式是否要求输入长度是分组倍数（ECB/CBC 需要填充，其余为流式）
_BLOCK_MODES = ("ECB", "CBC")
# 需要额外认证标签的模式
_TAG_MODES = ("GCM",)
# 需要 IV / Nonce 的模式（ECB 不需要）
_IV_MODES = ("CBC", "CFB", "OFB", "CTR", "GCM")

_BLOCK_SIZE = 16


# ---------------------------------------------------------------- 工具
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
    """智能解析输入为字节：优先 hex，其次 base64/URL-safe base64，最后按 UTF-8 处理。"""
    t = (text or '').strip()
    if not t:
        raise ValueError("输入为空")
    s = _strip_ws(t)
    if s.lower().startswith('0x'):
        s = s[2:]
    if _is_hex(s):
        return bytes.fromhex(s)
    if '-----BEGIN' in t:
        # PEM 文本：去头尾取 base64
        body = ''.join(line for line in t.splitlines()
                       if line and not line.startswith('-----'))
        raw = base64.b64decode(body)
        if raw:
            return raw
    if len(s) >= 4:  # 过短（<4 字符）不按 base64 猜测
        raw = _b64_try_decode(t)
        if raw is not None and len(raw) > 0:
            return raw
    return t.encode('utf-8')


def to_hex(data: bytes) -> str:
    return data.hex()


def secure_random_hex(nbytes: int) -> str:
    """生成 nbytes 字节的密码学安全随机数，返回 hex。"""
    return secrets.token_hex(nbytes)


def normalize_key(alg: str, size_bits: int, key_text: str) -> bytes:
    """把用户输入的密钥文本规整为合法密钥字节。"""
    if alg not in ALGORITHMS:
        raise ValueError("不支持的算法：%s" % alg)
    allowed = ALGORITHMS[alg]
    if size_bits is not None and (size_bits // 8) not in allowed:
        raise ValueError("%s 不支持 %d 位密钥" % (alg, size_bits))
    b = parse_bytes(key_text)
    if len(b) not in allowed:
        raise ValueError("%s 密钥长度应为 %s 字节，实际 %d 字节"
                         % (alg, "/".join(str(x) for x in allowed), len(b)))
    return b


def normalize_iv(mode: str, iv_text: str, block_size: int = _BLOCK_SIZE) -> bytes:
    """规整 IV / Nonce。GCM 建议 12 字节；CBC/CFB/OFB/CTR 要求分组大小。"""
    b = parse_bytes(iv_text)
    if mode == "GCM":
        if len(b) < 8:
            raise ValueError("GCM 的 Nonce 至少 8 字节，建议 12 字节")
    elif len(b) != block_size:
        raise ValueError("%s 模式 IV 需 %d 字节，实际 %d 字节"
                         % (mode, block_size, len(b)))
    return b


# ---------------------------------------------------------------- 填充
def pkcs7_pad(data: bytes, block_size: int = _BLOCK_SIZE) -> bytes:
    n = block_size - (len(data) % block_size)
    return data + bytes([n]) * n


def pkcs7_unpad(data: bytes, block_size: int = _BLOCK_SIZE) -> bytes:
    if not data:
        raise ValueError("空数据无法去填充")
    n = data[-1]
    if n < 1 or n > block_size or n > len(data):
        raise ValueError("PKCS7 填充无效")
    if data[-n:] != bytes([n]) * n:
        raise ValueError("PKCS7 填充校验失败")
    return data[:-n]


# ---------------------------------------------------------------- 核心加解密
def _cipher(alg: str, key: bytes):
    if alg == "SM4":
        return Cipher(algorithms.SM4(key), None)
    return Cipher(algorithms.AES(key), None)


def encrypt(alg: str, mode: str, key: bytes, iv: bytes = None,
            plaintext: bytes = b"", associated_data: bytes = b""
            ) -> dict:
    """对称加密。

    返回 dict：
      cipher_hex  密文（hex）
      tag_hex     GCM 认证标签（hex，仅 GCM 模式）
      mode / alg  回显
    """
    mode = mode.upper()
    if mode not in ("ECB", "CBC", "CFB", "OFB", "CTR", "GCM"):
        raise ValueError("不支持的加密模式：%s" % mode)
    if mode in _BLOCK_MODES:
        data = pkcs7_pad(plaintext)
    else:
        data = plaintext

    if mode == "ECB":
        ctx = Cipher(algorithms_for(alg, key), modes.ECB())
    elif mode == "CBC":
        ctx = Cipher(algorithms_for(alg, key), modes.CBC(iv))
    elif mode == "CFB":
        ctx = Cipher(algorithms_for(alg, key), _CFB(iv))
    elif mode == "OFB":
        ctx = Cipher(algorithms_for(alg, key), _OFB(iv))
    elif mode == "CTR":
        ctx = Cipher(algorithms_for(alg, key), modes.CTR(iv))
    else:
        ctx = Cipher(algorithms_for(alg, key), modes.GCM(iv))
        enc = ctx.encryptor()
        if associated_data:
            enc.authenticate_additional_data(associated_data)
        ct = enc.update(data) + enc.finalize()
        out = {"cipher_hex": ct.hex(), "text_len": len(plaintext), "mode": mode, "alg": alg,
               "tag_hex": enc.tag.hex()}
        return out
    enc = ctx.encryptor()
    ct = enc.update(data) + enc.finalize()
    return {"cipher_hex": ct.hex(), "text_len": len(plaintext), "mode": mode, "alg": alg}


def algorithms_for(alg, key):
    if alg == "SM4":
        return algorithms.SM4(key)
    return algorithms.AES(key)


def decrypt(alg: str, mode: str, key: bytes, iv: bytes = None,
            ciphertext: bytes = b"", tag: bytes = None,
            associated_data: bytes = b"") -> bytes:
    """对称解密，返回明文 bytes。"""
    mode = mode.upper()
    if mode not in ("ECB", "CBC", "CFB", "OFB", "CTR", "GCM"):
        raise ValueError("不支持的解密模式：%s" % mode)
    if mode in _TAG_MODES:
        if not tag:
            raise ValueError("GCM 模式需要认证标签")
        ctx = Cipher(algorithms_for(alg, key), modes.GCM(iv, tag))
        dec = ctx.decryptor()
        if associated_data:
            dec.authenticate_additional_data(associated_data)
        return dec.update(ciphertext) + dec.finalize()
    if mode == "ECB":
        ctx = Cipher(algorithms_for(alg, key), modes.ECB())
    elif mode == "CBC":
        ctx = Cipher(algorithms_for(alg, key), modes.CBC(iv))
    elif mode == "CFB":
        ctx = Cipher(algorithms_for(alg, key), _CFB(iv))
    elif mode == "OFB":
        ctx = Cipher(algorithms_for(alg, key), _OFB(iv))
    else:
        ctx = Cipher(algorithms_for(alg, key), modes.CTR(iv))
    dec = ctx.decryptor()
    plain = dec.update(ciphertext) + dec.finalize()
    if mode in _BLOCK_MODES:
        plain = pkcs7_unpad(plain)
    return plain
