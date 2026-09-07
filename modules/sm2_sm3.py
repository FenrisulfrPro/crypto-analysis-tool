# -*- coding: utf-8 -*-
"""国密 SM2 / SM3 核心逻辑（无 GUI 依赖，便于复用与测试）"""
import base64
import binascii
import secrets

from gmssl import sm2, sm3, func
from gmssl.sm2 import default_ecc_table

# GM/T 0003 规定的默认用户标识
DEFAULT_ID = "1234567812345678"


def sm3_hex(data: bytes) -> str:
    """计算 SM3 摘要，返回 64 位小写 hex"""
    return sm3.sm3_hash(func.bytes_to_list(data))


def generate_sm2_keypair():
    """生成 SM2 密钥对，返回 (私钥hex, 公钥hex)，公钥为 x||y 拼接（无 04 前缀）"""
    n = int(default_ecc_table['n'], 16)
    priv = format(secrets.randbelow(n - 1) + 1, '064x')
    c = sm2.CryptSM2(private_key='', public_key='', ecc_table=default_ecc_table)
    pub = c._kg(int(priv, 16), default_ecc_table['g'])
    return priv, pub


def sm2_sign(data: bytes, priv_hex: str, pub_hex: str, k_hex: str = None) -> str:
    """SM2-with-SM3 签名，返回 r||s 拼接的 128 位 hex"""
    if not priv_hex or not pub_hex:
        raise ValueError("请先填写或生成私钥与公钥")
    c = sm2.CryptSM2(private_key=priv_hex.strip(), public_key=pub_hex.strip(), asn1=False)
    sig = c.sign_with_sm3(data, k_hex.strip() if k_hex and k_hex.strip() else None)
    if not sig:
        raise ValueError("签名失败，请尝试更换随机数 K")
    return sig


def sm2_verify(data: bytes, sig_hex: str, pub_hex: str) -> bool:
    """SM2-with-SM3 验签（兼容旧接口：data=bytes，sig=r||s 128 hex，pub=x||y 128 hex）"""
    if not pub_hex:
        raise ValueError("请填写公钥")
    c = sm2.CryptSM2(private_key='', public_key=pub_hex.strip(), asn1=False)
    try:
        return bool(c.verify_with_sm3(sig_hex.strip(), data))
    except Exception:
        return False


def sm2_encrypt(data: bytes, pub_hex: str) -> str:
    """SM2 公钥加密（GM/T 0003.4，C1C3C2 密文格式），返回密文 hex。"""
    pub_xy = parse_pubkey(pub_hex)
    c = sm2.CryptSM2(private_key='', public_key=pub_xy, ecc_table=default_ecc_table)
    return c.encrypt(data).hex()


def sm2_decrypt(cipher_hex: str, priv_hex: str) -> bytes:
    """SM2 私钥解密（GM/T 0003.4，C1C3C2 密文格式），返回明文 bytes。"""
    if not priv_hex:
        raise ValueError("请填写私钥")
    clean = ''.join(ch for ch in cipher_hex if not ch.isspace())
    try:
        ct = bytes.fromhex(clean)
    except Exception:
        raise ValueError("密文不是合法的十六进制")
    # C1(1+64) + C3(32) + C2(n)：最短 97 字节明文为空时也至少 97 字节
    if len(ct) < 97:
        raise ValueError("SM2 密文(C1C3C2)长度至少 97 字节，实际 %d 字节——请确认输入的是密文而非明文"
                         % len(ct))
    c = sm2.CryptSM2(private_key=priv_hex.strip(), public_key='', ecc_table=default_ecc_table)
    raw = c.decrypt(ct)
    if not raw:
        raise ValueError("SM2 解密失败：私钥与密文不匹配，或密文被篡改")
    return raw


# ============================================================ 智能输入解析（新增）
def _strip_s(text: str) -> str:
    """删除所有空白字符"""
    return ''.join(ch for ch in text if not ch.isspace())


def _check_hex(s: str) -> bool:
    if not s or len(s) % 2 != 0:
        return False
    return all(ch in '0123456789abcdefABCDEF' for ch in s)


def _b64_try_decode(s: str) -> bytes | None:
    """尝试 base64 / base64url 解码，成功且字节数合理则返回 bytes，否则 None"""
    t = s.replace('-', '+').replace('_', '/')
    t += '=' * (-len(t) % 4)
    try:
        raw = base64.b64decode(t, validate=True)
    except Exception:
        return None
    return raw if raw else None


def parse_message(text: str) -> bytes:
    """智能识别消息：优先 hex，其次 base64，最后按 UTF-8 文本处理；无法解析时抛错"""
    t = _strip_s(text or '')
    if not t:
        raise ValueError("消息为空")
    if _check_hex(t):
        return bytes.fromhex(t)
    raw = _b64_try_decode(t)
    if raw is not None and len(raw) and len(raw) * 4 // 3 >= len(t) - 4:
        return raw
    return t.encode('utf-8')


def parse_signature(text: str) -> str:
    """将签名输入归一化为 r||s 128 位 hex（小写）。
    支持：r||s hex / DER hex / base64(DER 或原生 r||s 码流)。"""
    t = _strip_s(text or '')
    if not t:
        raise ValueError("签名值为空")
    data = None
    if _check_hex(t):
        raw = bytes.fromhex(t)
        data = raw
    else:
        data = _b64_try_decode(t)
        if data is None:
            raise ValueError("无法识别签名格式（需 r||s hex / DER hex / base64）")
    # DER 解码
    try:
        rs = _der_to_rs(data)
        return rs
    except Exception:
        pass
    # 原生 r||s 码流（64 字节）
    if len(data) == 64:
        return data.hex()
    raise ValueError("签名长度异常：%d 字节" % len(data))


def rs_to_der(rs_hex: str) -> bytes:
    """r||s(128 hex) → ASN.1 DER 签名 (SEQUENCE{INTEGER r, INTEGER s})，高位补 0x00 保证正确编码。"""
    if len(rs_hex) != 128:
        raise ValueError("r||s 应为 128 位十六进制")
    r, s = bytes.fromhex(rs_hex[:64]), bytes.fromhex(rs_hex[64:])
    aus = []
    for b in (r, s):
        if b[0] & 0x80:
            aus.append(b'\x02\x21\x00' + b)
        else:
            aus.append(b'\x02\x20' + b)
    body = aus[0] + aus[1]
    return b'\x30' + bytes([len(body)]) + body


def _der_to_rs(der: bytes) -> str:
    """DER 签名 (SEQUENCE{INTEGER r, INTEGER s}) -> r||s 128 hex"""
    i = 0
    if der[i] != 0x30:
        raise ValueError("非 DER 序列")
    i += 1
    ln = der[i]
    if ln & 0x80:
        nlen = ln & 0x7F
        ln = int.from_bytes(der[i + 1:i + 1 + nlen], 'big')
        i += 1 + nlen
    else:
        i += 1
    end = i + ln
    parts = []
    while i < end:
        if der[i] != 0x02:
            raise ValueError("DER 整数标记错误")
        i += 1
        l = der[i]
        i += 1
        # 长格式长度（少见）
        if l & 0x80:
            ll = l & 0x7F
            parts.append(der[i + ll:i + ll + int.from_bytes(der[i:i + ll], 'big')])
            i += ll + int.from_bytes(der[i:i + ll], 'big')
        else:
            parts.append(der[i:i + l])
            i += l
    if len(parts) != 2:
        raise ValueError("DER 签名应含 r、s 两个整数")
    out = []
    for p in parts:
        p = bytes(p)
        if len(p) > 32:
            if p[0] == 0:
                p = p[1:]
            else:
                raise ValueError("整数超长")
        if len(p) < 32:
            p = b'\x00' * (32 - len(p)) + p
        out.append(p)
    return out[0].hex() + out[1].hex()


def parse_pubkey(text: str) -> str:
    """将公钥输入归一化为 x||y 128 位 hex。
    支持：x||y hex(128) / 04||X||Y hex(130) / base64 码流(64B 或证书 DER) / PEM 证书。"""
    t = text.strip()
    if not t:
        raise ValueError("公钥为空")
    # 1) hex
    s = _strip_s(t)
    if _check_hex(s):
        raw = bytes.fromhex(s)
        return _point_to_xy(raw)
    # 2) PEM 证书
    if '-----BEGIN' in t:
        return _extract_from_cert(t.encode('utf-8'))
    # 3) base64
    data = _b64_try_decode(t)
    if data is None:
        raise ValueError("无法识别公钥格式（需 x||y hex / 04||X||Y hex / base64 / PEM 证书）")
    # 4) base64 证书体（DER）或 64B 点
    try:
        return _extract_from_cert(data)
    except Exception:
        pass
    try:
        return _point_to_xy(data)
    except Exception:
        pass
    raise ValueError("无法从输入中解析出 SM2 公钥")


def _point_to_xy(raw: bytes) -> str:
    """未压缩点 (04||X||Y, 65B) 或 x||y (64B) -> x||y 128 hex"""
    if len(raw) == 65 and raw[0] == 4:
        return raw[1:].hex()
    if len(raw) == 64:
        return raw.hex()
    raise ValueError("公钥点长度异常：%d 字节" % len(raw))


def _extract_from_cert(pem_or_der) -> str:
    """从 PEM / DER 证书提取 SM2 未压缩公钥点 -> x||y 128 hex"""
    from cryptography import x509
    try:
        cert = x509.load_pem_x509_certificate(pem_or_der)
    except Exception:
        cert = x509.load_der_x509_certificate(pem_or_der)
    # SM2 公钥：cryptography 可能不支持 SM2 曲线(OID 1.2.156.10197.1.301)，
    # 因此先尝试 public_numbers，失败则直接从 DER 抠 SPKI BIT STRING 中的未压缩点。
    try:
        spki = cert.public_key()
        nums = spki.public_numbers()
        return format(nums.x, '064x') + format(nums.y, '064x')
    except Exception:
        pass
    # 兜底：在 TBS 的 SPKI 中定位 03 <len> 00 04（未压缩点 04||X||Y）
    from cryptography.hazmat.primitives import serialization
    raw = cert.public_bytes(serialization.Encoding.DER)
    i = 0
    n = len(raw)
    while i + 2 < n:
        if raw[i] == 0x03 and i + 3 < n and raw[i + 1] < 0x80 \
                and raw[i + 2] == 0x00 and raw[i + 3] == 0x04:
            plen = raw[i + 1] - 1  # 去掉 unused-bits 字节 00
            if plen == 65:
                pt = raw[i + 3:i + 3 + 65]
                if pt[0] == 4:
                    return pt[1:].hex()
        i += 1
    raise ValueError("证书中未找到 SM2 未压缩公钥点")


def _sm2_z(pub_xy: str, id_bytes: bytes) -> str:
    """计算 SM2 用户 Z 值（hex）"""
    ec = default_ecc_table
    entl = (len(id_bytes) * 8).to_bytes(2, 'big')
    pre = entl + id_bytes
    za_in = pre + bytes.fromhex(ec['a']) + bytes.fromhex(ec['b']) \
        + bytes.fromhex(ec['g']) + bytes.fromhex(pub_xy)
    return sm3_hex(za_in)


def sm2_verify_auto(msg_text: str, sig_text: str, pub_text: str,
                    sm2_id: str = None) -> tuple:
    """全自动 SM2-with-SM3 验签。

    参数均可使用常见外部格式：
    - msg_text：原始 UTF-8 文本 / base64 / hex
    - sig_text：r||s(128 hex) / DER(hex 或 base64)
    - pub_text：x||y(128 hex) / 04||X||Y(130 hex) / base64(点或证书) / PEM 证书
    - sm2_id：签名者用户标识（默认 None → 标准默认 1234567812345678）

    返回 (通过:bool, 日志:str)
    """
    log = []
    try:
        msg = parse_message(msg_text)
        sig_rs = parse_signature(sig_text)
        pub_xy = parse_pubkey(pub_text)
    except ValueError as e:
        return False, "输入解析失败：%s" % e

    log.append("消息字节数: %d  开头的 hex: %s" % (len(msg), msg[:16].hex()))
    log.append("公钥 X||Y (128 hex):\n%s" % pub_xy)
    r, s = sig_rs[:64], sig_rs[64:]
    log.append("签名 r: %s\n签名 s: %s" % (r, s))

    id_bytes = (sm2_id if sm2_id is not None and sm2_id.strip()
                else DEFAULT_ID).encode('utf-8')
    log.append("签名者 ID: %s" % id_bytes.decode())

    try:
        za = _sm2_z(pub_xy, id_bytes)
        e = sm3_hex(bytes.fromhex(za) + msg)
        c = sm2.CryptSM2(private_key='', public_key=pub_xy, asn1=False)
        ok = bool(c.verify(sig_rs, bytes.fromhex(e)))
    except Exception as ex:
        return False, "验签执行异常：%s" % ex
    log.append("Z 值: %s\ne 值: %s" % (za, e))
    log.append("验签结果: %s" % ("通过 ✓" if ok else "不通过 ✗"))
    return ok, "\n".join(log)


def sm2_verify_ex(msg: bytes, sig_text: str, pub_text: str,
                  sm2_id: str = None, msg_is_za_m: bool = False) -> tuple:
    """SM2-with-SM3 验签（底层版，支持显式字节消息或直接给定 e 值）。

    支持两种消息输入形态：
    - 消息M：msg_is_za_m=False（默认），msg 为消息原文/HEX/文件字节，内部计算 e=Hash(Za||M)
    - Hash(Za||M)：msg_is_za_m=True，msg 直接作为 e 值（32 字节）参与验签，跳过 Hash 计算

    返回 (通过:bool, 日志:str)
    """
    log = []
    try:
        sig_rs = parse_signature(sig_text)
        pub_xy = parse_pubkey(pub_text)
    except ValueError as e:
        return False, "输入解析失败：%s" % e

    r, s = sig_rs[:64], sig_rs[64:]
    log.append("公钥 X||Y (128 hex):\n%s" % pub_xy)
    log.append("签名 r: %s\n签名 s: %s" % (r, s))

    id_bytes = (sm2_id if sm2_id is not None and sm2_id.strip()
                else DEFAULT_ID).encode('utf-8')
    log.append("签名者 ID: %s" % id_bytes.decode('utf-8'))

    try:
        if msg_is_za_m:
            e = msg.hex()
            log.append("消息模式: Hash(Za||M)（直接使用 e 值，%d 字节）" % len(msg))
        else:
            log.append("消息字节数: %d  开头的 hex: %s" % (len(msg), msg[:16].hex()))
            za = _sm2_z(pub_xy, id_bytes)
            e = sm3_hex(bytes.fromhex(za) + msg)
            log.append("Z 值: %s" % za)
        c = sm2.CryptSM2(private_key='', public_key=pub_xy, asn1=False)
        ok = bool(c.verify(sig_rs, bytes.fromhex(e)))
    except Exception as ex:
        return False, "验签执行异常：%s" % ex
    log.append("e 值 (Hash(Za||M)): %s" % e)
    log.append("验签结果: %s" % ("通过 ✓" if ok else "不通过 ✗"))
    return ok, "\n".join(log)
