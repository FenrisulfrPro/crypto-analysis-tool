# -*- coding: utf-8 -*-
"""TLS 通信协议逐包深度解析（Wireshark 式）
依据 TLS 1.0 / 1.1 / 1.2 / 1.3 RFC 与 IANA 参数表，
对 pcap/pcapng 中的 TLS 记录按 TCP 流重组后：
  - 拆分 Record → Handshake 消息链
  - 解出 ClientHello / ServerHello 的加密套件、SNI、ALPN、签名算法、密钥共享组
  - 解出 Certificate 证书链（主体 / 签发者 / 有效期 / 公钥 / 签名算法 / 指纹 / 签名值）
  - 解出 CertificateVerify / ServerKeyExchange / Finished 等签名与校验数据
"""
import struct
import re
from collections import Counter, OrderedDict, defaultdict

from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ARP

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
except Exception:  # pragma: no cover
    x509 = None

# ---------------------------------------------------------------- 常量映射

TLS_RECORD_TYPE = {
    20: "ChangeCipherSpec",
    21: "Alert",
    22: "Handshake",
    23: "ApplicationData",
    24: "Heartbeat",
}

# ---- TLCP（GB/T 38636-2020 传输层密码协议，国密 SSL）----
# TLCP 记录头结构与 TLS 相同：type(1) + version(2) + length(2)，但版本号用 0x0101。
# 记录类型在 TLS 基础上多用 0x18（EOF，数据结束）。
TLCP_RECORD_TYPE = {
    0x14: "ChangeCipherSpec",
    0x15: "Alert",
    0x16: "Handshake",
    0x17: "ApplicationData",
    0x18: "EOF (TLCP 数据结束)",
}

# TLCP 版本号（区别于标准 TLS 的 0x0301~0x0304）
TLCP_VERSION = {
    0x0001: "TLCP (0x0001)",
    0x0002: "TLCP (0x0002)",
    0x0101: "TLCP 1.0 (0x0101)",
}

# TLCP 国密加密套件（GB/T 38636，以 0xE0xx 为主；个别实现值可能不同，未命中显示 hex）
TLCP_CIPHER_SUITES = {
    0xE011: "ECC_SM4_CBC_SM3 (GB/T 38636)",
    0xE013: "ECC_SM4_CBC_SM3 (GB/T 38636)",
    0xE015: "ECC_SM4_CBC_SM4 (GB/T 38636)",
    0xE017: "ECC_SM4_GCM_SM3 (GB/T 38636)",
    0xE019: "ECDHE_SM4_CBC_SM3 (GB/T 38636)",
    0xE01B: "ECDHE_SM4_GCM_SM3 (GB/T 38636)",
    0xE023: "SM4_CBC_SM3 (GB/T 38636)",
    0xE025: "SM4_GCM_SM3 (GB/T 38636)",
    0xE053: "ECDHE_SM4_GCM_SM3 (GB/T 38636)",
    0xE055: "ECDHE_SM4_GCM_SM4 (GB/T 38636)",
}

HANDSHAKE_TYPE = {
    0: "HelloRequest",
    1: "ClientHello",
    2: "ServerHello",
    4: "NewSessionTicket",
    8: "EncryptedExtensions",
    11: "Certificate",
    12: "ServerKeyExchange",
    13: "CertificateRequest",
    14: "ServerHelloDone",
    15: "CertificateVerify",
    16: "ClientKeyExchange",
    20: "Finished",
    24: "KeyUpdate",
    254: "MessageHash",
}

# ---- TLS 版本号
TLS_VERSION = {
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
}

# ---- 常用加密套件（IANA TLS Cipher Suites 摘录）
CIPHER_SUITES = {
    0x0004: "TLS_RSA_WITH_RC4_128_MD5", 0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA", 0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA", 0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256", 0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x003E: "TLS_DH_RSA_WITH_AES_128_CBC_SHA",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256", 0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", 0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
    0x1301: "TLS_AES_128_GCM_SHA256", 0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256", 0x1304: "TLS_AES_128_CCM_SHA256",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA", 0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256", 0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", 0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xC2F9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0xC2FB: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
}

# ---- 签名算法 SignatureScheme
SIG_SCHEMES = {
    0x0201: "rsa_pkcs1_sha1", 0x0203: "ecdsa_sha1",
    0x0401: "rsa_pkcs1_sha256", 0x0402: "rsa_pkcs1_sha384", 0x0403: "rsa_pkcs1_sha512",
    0x0405: "ecdsa_sha256", 0x0406: "ecdsa_sha384", 0x0407: "ecdsa_sha512",
    0x0501: "rsa_pss_rsae_sha256", 0x0502: "rsa_pss_rsae_sha384", 0x0503: "rsa_pss_rsae_sha512",
    0x0804: "rsa_pss_pss_sha256", 0x0805: "rsa_pss_pss_sha384", 0x0806: "rsa_pss_pss_sha512",
    0x0807: "ed25519", 0x0808: "ed448",
}

# ---- 命名曲线 / 密钥共享组
NAMED_GROUPS = {
    0x0017: "secp256r1 (P-256)", 0x0018: "secp384r1 (P-384)",
    0x0019: "secp521r1 (P-521)", 0x001D: "x25519", 0x001E: "x448",
    0x0100: "ffdhe2048", 0x0101: "ffdhe3072", 0x0102: "ffdhe4096",
}

# ---- 扩展类型
EXT_TYPE = {
    0: "server_name (SNI)", 5: "status_request", 10: "supported_groups",
    11: "EC_Point_Formats", 13: "signature_algorithms", 14: "use_srtp",
    15: "heartbeat", 16: "application_layer_protocol_negotiation (ALPN)",
    18: "signed_certificate_timestamp", 21: "padding", 23: "extended_master_secret",
    27: "compress_certificate", 28: "record_size_limit", 35: "session_ticket",
    41: "pre_shared_key", 42: "early_data", 43: "supported_versions",
    44: "cookie", 45: "psk_key_exchange_modes", 51: "key_share", 54: "encrypted_client_hello",
}


def _cipher_name(code: int) -> str:
    return CIPHER_SUITES.get(code, "UNKNOWN(0x%04X)" % code)


def _cipher_name_for(code: int, proto: str = "TLS") -> str:
    """按协议选择套件表：TLCP（国密）用 GB/T 38636 表，否则用 IANA TLS 表。"""
    if proto == "TLCP":
        return TLCP_CIPHER_SUITES.get(code, "UNKNOWN(0x%04X)" % code)
    return CIPHER_SUITES.get(code, "UNKNOWN(0x%04X)" % code)


def _sig_name(code: int) -> str:
    return SIG_SCHEMES.get(code, "UNKNOWN(0x%04X)" % code)


def _group_name(code: int) -> str:
    return NAMED_GROUPS.get(code, "UNKNOWN(0x%04X)" % code)


def _ext_name(code: int) -> str:
    return EXT_TYPE.get(code, "ext_type(%d)" % code)


def _ver_name(code: int, proto: str = "TLS") -> str:
    if proto == "TLCP":
        return TLCP_VERSION.get(code, "TLCP(0x%04X)" % code)
    return TLS_VERSION.get(code, "0x%04X" % code)


def _fmt_hex(data: bytes, limit: int = 64) -> str:
    h = data.hex()
    if len(h) > limit * 2:
        h = h[:limit * 2] + "…"
    return h


# ---------------------------------------------------------------- 字节拆分器

def split_tls_records(data: bytes):
    """把连续字节流按 TLS Record 头部拆分成列表 [(type, version, payload, record_offset)]。"""
    recs, off = [], 0
    while off + 5 <= len(data):
        typ = data[off]
        ver = struct.unpack(">H", data[off + 1:off + 3])[0]
        ln = struct.unpack(">H", data[off + 3:off + 5])[0]
        if off + 5 + ln > len(data):
            break
        recs.append((typ, ver, data[off + 5:off + 5 + ln], off))
        off += 5 + ln
    return recs


def split_proto_records(data: bytes, default: str = "TLS"):
    """对字节流判定是 TLS 还是 TLCP（国密），再拆分记录。

    判定规则：记录头 5 字节中 version == 0x0101 / 0x0001 / 0x0002 判为 TLCP，
    其余标准 TLS 版本（0x0301~0x0304）判为 TLS。返回 (proto, records)。
    """
    proto = default
    if len(data) >= 3:
        ver = struct.unpack(">H", data[1:3])[0]
        if ver in (0x0001, 0x0002, 0x0101):
            proto = "TLCP"
    return proto, split_tls_records(data)


def split_handshake_messages(payload: bytes):
    """把握手记录内容拆成 [(msgtype, body, msg_offset)] 消息列表。"""
    msgs, off = [], 0
    while off + 4 <= len(payload):
        mt = payload[off]
        ln = int.from_bytes(payload[off + 1:off + 4], "big")
        if off + 4 + ln > len(payload):
            break
        msgs.append((mt, payload[off + 4:off + 4 + ln], off))
        off += 4 + ln
    return msgs


# ---------------------------------------------------------------- 各握手消息字段

def parse_client_hello(body: bytes, proto: str = "TLS"):
    """ClientHello：版本 / 随机数 / 会话ID / 套件 / 压缩 / 扩展。"""
    d = OrderedDict()
    if len(body) < 34:
        return d
    d["legacy_version"] = _ver_name(struct.unpack(">H", body[0:2])[0], proto)
    random = body[2:34]
    d["random"] = _fmt_hex(random, 48)
    off = 34
    sid_len = body[off]; off += 1
    d["session_id"] = _fmt_hex(body[off:off + sid_len], 32)
    off += sid_len
    if off + 2 > len(body):
        return d
    cs_len = struct.unpack(">H", body[off:off + 2])[0]; off += 2
    ciphers = []
    for i in range(0, cs_len, 2):
        c = struct.unpack(">H", body[off + i:off + i + 2])[0]
        ciphers.append("%s" % _cipher_name_for(c, proto))
    d["cipher_suites"] = " | ".join(ciphers[:16]) + (" …（共%d 个）" % (cs_len // 2) if cs_len // 2 > 16 else "")
    d["cipher_suites_full"] = " | ".join(ciphers)
    off += cs_len
    if off >= len(body):
        return d
    comp_len = body[off]; off += 1
    d["compression_methods"] = "0x%02X" % body[off] if comp_len else "(无)"
    off += comp_len
    exts = _parse_extensions(body, off)
    for k, v in exts.items():
        d[k] = v
    return d


def parse_server_hello(body: bytes, proto: str = "TLS"):
    """ServerHello：版本 / 随机数 / 会话ID / 选套件 / 压缩 / 扩展。"""
    d = OrderedDict()
    if len(body) < 38:
        return d
    d["legacy_version"] = _ver_name(struct.unpack(">H", body[0:2])[0], proto)
    d["random"] = _fmt_hex(body[2:34], 48)
    sid_len = body[34]
    d["session_id"] = _fmt_hex(body[35:35 + sid_len], 32)
    off = 35 + sid_len
    d["selected_cipher_suite"] = "%s" % _cipher_name_for(struct.unpack(">H", body[off:off + 2])[0], proto) \
        if off + 2 <= len(body) else "(截断)"
    off += 2
    if off + 1 > len(body):
        return d
    d["compression_method"] = "null" if body[off] == 0 else "0x%02X" % body[off]
    off += 1
    exts = _parse_extensions(body, off)
    for k, v in exts.items():
        d[k] = v
    return d


def _parse_extensions(body: bytes, off: int):
    """解析扩展区，返回 OrderedDict（键为可读名称）。"""
    out = OrderedDict()
    if off + 2 > len(body):
        return out
    ext_len = struct.unpack(">H", body[off:off + 2])[0]
    end = off + 2 + ext_len
    off += 2
    while off + 4 <= end:
        etype = struct.unpack(">H", body[off:off + 2])[0]
        elen = struct.unpack(">H", body[off + 2:off + 4])[0]
        ev = body[off + 4:off + 4 + elen]
        out["ext_" + _ext_name(etype)] = _parse_ext_value(etype, ev, out)
        off += 4 + elen
    return out


def _parse_ext_value(etype: int, ev: bytes, acc: dict):
    try:
        if etype == 0:  # SNI
            off = 2
            while off + 3 <= len(ev):
                nt = ev[off]
                nl = struct.unpack(">H", ev[off + 1:off + 3])[0]
                name = ev[off + 3:off + 3 + nl].decode('utf-8', 'replace')
                acc["SNI"] = name
                off += 3 + nl
            return acc.get("SNI", ev.hex()[:32])
        if etype == 10:  # supported_groups
            glen = struct.unpack(">H", ev[0:2])[0]
            groups = [NAMED_GROUPS.get(g, "0x%04X" % g) for g in
                      struct.unpack(">%dH" % (glen // 2), ev[2:2 + glen])]
            return ", ".join(groups)
        if etype == 13:  # signature_algorithms
            slen = struct.unpack(">H", ev[0:2])[0]
            schemes = [SIG_SCHEMES.get(s, "0x%04X" % s) for s in
                       struct.unpack(">%dH" % (slen // 2), ev[2:2 + slen])]
            return ", ".join(schemes)
        if etype == 16:  # ALPN
            plen = struct.unpack(">H", ev[0:2])[0]
            off2, protos = 2, []
            while off2 + 1 <= 2 + plen:
                pl = ev[off2]
                protos.append(ev[off2 + 1:off2 + 1 + pl].decode('utf-8', 'replace'))
                off2 += 1 + pl
            return ", ".join(protos)
        if etype == 43:  # supported_versions
            if ev and len(ev) > 1 and ev[0] == len(ev) - 1:
                vers = [_ver_name(struct.unpack(">H", ev[1 + i:3 + i])[0])
                        for i in range(0, len(ev) - 1, 2)]
            else:
                vers = [_ver_name(struct.unpack(">H", ev[i:i + 2])[0]) for i in range(0, len(ev), 2)]
            return ", ".join(vers)
        if etype == 51:  # key_share
            kl = struct.unpack(">H", ev[0:2])[0]
            off2, parts = 2, []
            while off2 + 4 <= 2 + kl:
                g = struct.unpack(">H", ev[off2:off2 + 2])[0]
                klen = struct.unpack(">H", ev[off2 + 2:off2 + 4])[0]
                parts.append("%s pubkey=%s…" % (_group_name(g), _fmt_hex(ev[off2 + 4:off2 + 4 + klen], 16)))
                off2 += 4 + klen
            return " | ".join(parts)
        if etype == 35:  # session_ticket
            return "ticket_len=%d" % len(ev)
        if etype == 45:  # psk_key_exchange_modes
            return ", ".join("0x%02X" % b for b in ev[1:1 + ev[0]]) if ev else ""
        if etype == 44:  # cookie
            return "len=%d" % len(ev)
        if etype == 21:  # padding
            return "len=%d" % len(ev)
        if etype == 18:  # SCT
            return "len=%d" % len(ev)
        if etype == 5:   # status_request
            return "len=%d" % len(ev)
        return _fmt_hex(ev, 24)
    except Exception:
        return _fmt_hex(ev, 24)


def parse_certificate(body: bytes, is_tls13=False):
    """Certificate 消息：证书链（列表）。每张证书用 cryptography 解析。"""
    certs = []
    if is_tls13:
        # 签名算法(2) + certificate_list(3)
        context = body[0]
        off = 1 + context
        list_len = int.from_bytes(body[off:off + 3], "big"); off += 3
        end = off + list_len
    else:
        off = 0
        end = min(len(body), 3 + int.from_bytes(body[0:3], "big"))
        off = 3
    while off + 3 <= end:
        clen = int.from_bytes(body[off:off + 3], "big"); off += 3
        der = body[off:off + clen]; off += clen
        info = _parse_der_cert(der)
        certs.append(info)
        # TLS1.3 可有 extensions（跳过）
        if is_tls13 and off + 2 <= end:
            xlen = struct.unpack(">H", body[off:off + 2])[0]
            off += 2 + xlen
    return certs


_EKU_NAME = {
    "1.3.6.1.5.5.7.3.1": "serverAuth 服务器认证",
    "1.3.6.1.5.5.7.3.2": "clientAuth 客户端认证",
    "1.3.6.1.5.5.7.3.3": "codeSigning 代码签名",
    "1.3.6.1.5.5.7.3.4": "emailProtection 电子邮件保护",
    "1.3.6.1.5.5.7.3.8": "ocspSigning / OCSP 签名",
    "1.3.6.1.5.5.7.3.9": "timeStamping 时间戳",
}

_KEY_USAGE_FLAGS = (
    ("digital_signature", "digitalSignature 数字签名"),
    ("content_commitment", "nonRepudiation 不可否认性"),
    ("key_encipherment", "keyEncipherment 密钥加密"),
    ("data_encipherment", "dataEncipherment 数据加密"),
    ("key_agreement", "keyAgreement 密钥协商"),
    ("key_cert_sign", "keyCertSign 证书签发"),
    ("crl_sign", "cRLSign CRL 签发"),
    ("encipher_only", "encipherOnly"),
    ("decipher_only", "decipherOnly"),
)


def _eku_text(eku) -> str:
    oids = getattr(eku, "extended_key_usage", None) or getattr(eku, "_usages", None) or []
    return ", ".join(_EKU_NAME.get(o.dotted_string, o.dotted_string) for o in oids)


def _key_usage_text(ku) -> str:
    parts = []
    for attr, name in _KEY_USAGE_FLAGS:
        try:
            flag = bool(getattr(ku, attr, False))
        except ValueError:  # encipher_only/decipher_only 在 key_agreement=False 时未定义
            flag = False
        if flag:
            parts.append(name)
    return ", ".join(parts) or "（未声明）"


def _parse_der_cert(der: bytes):
    """用 cryptography 解析单张 DER 证书；失败（如国密 SM2 曲线）时降级到 ASN.1 松散解析。
    若输入为 PEM 文本（-----BEGIN CERTIFICATE-----），自动解码为 DER。"""
    if der.startswith(b"-----BEGIN"):
        try:
            import base64
            body = b"".join(line for line in der.split(b"\n")
                            if line and not line.startswith(b"-----"))
            der = base64.b64decode(body)
        except Exception:
            pass
    info = OrderedDict()
    if x509 is None:
        info["error"] = "未安装 cryptography"
        return info
    try:
        c = x509.load_der_x509_certificate(der)
        info["subject"] = _dn_attr_first_4514(c.subject.rfc4514_string())
        info["issuer"] = _dn_attr_first_4514(c.issuer.rfc4514_string())
        info["not_before"] = _fmt_cert_time(c.not_valid_before_utc)
        info["not_after"] = _fmt_cert_time(c.not_valid_after_utc)
        info["version"] = _cert_version_text(c.version)
        info["serial"] = "%X" % c.serial_number
        info["sig_algorithm"] = _alg_label(c.signature_algorithm_oid.dotted_string)
        info["pubkey"] = _fmt_pubkey(c.public_key())
        info["sha256_thumb"] = _sha256(der)
        info["sig_value"] = c.signature.hex()
        info["sig_sha256"] = _sha256(c.signature)
        info["der_hex"] = der.hex()
        # 证书用途（EKU）/ 密钥用途（KeyUsage）/ CA 约束：区分加密证书与签名证书
        exts = c.extensions
        try:
            eku = exts.get_extension_for_class(x509.ExtendedKeyUsage).value
            info["ext_key_usage"] = _eku_text(eku)
        except x509.ExtensionNotFound:
            pass
        try:
            ku = exts.get_extension_for_class(x509.KeyUsage).value
            info["key_usage"] = _key_usage_text(ku)
        except x509.ExtensionNotFound:
            pass
        try:
            bc = exts.get_extension_for_class(x509.BasicConstraints).value
            info["basic_constraints"] = "is_ca=%s" % bc.ca
        except x509.ExtensionNotFound:
            pass
        return info
    except Exception:
        info = _parse_der_loose(der)
        info.setdefault("sha256_thumb", _sha256(der))
        info.setdefault("sig_sha256", _sha256(der))
        return info


# ---------------------------------------------------------- ASN.1 松散解析（兼容国密证书）

_SM2_OID = "1.2.156.10197.1.301"
_OID_SHORT = {
    "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST",
    "2.5.4.9": "STREET", "2.5.4.10": "O", "2.5.4.11": "OU",
    "1.2.840.113549.1.9.1": "emailAddress",
    "1.2.840.113549.1.1.1": "rsaEncryption",
    "1.2.840.10045.2.1": "id-ecPublicKey",
    "1.2.156.10197.1.301": "SM2", "1.2.156.10197.1.104": "SM3",
    "1.2.840.113549.1.1.11": "sha256WithRSA", "1.2.840.113549.1.1.5": "sha1WithRSA",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
}

# 签名算法 OID → 标准名字（固密签名见 GB/T 32918.3 / GM/T 0003.2，命名与 Bouncy Castle GMObjectIdentifiers 一致）
_SIG_OID_NAMES = {
    "1.2.156.10197.1.501": "SM3withSM2",
    "1.2.156.10197.1.502": "SHA1withSM2",
    "1.2.156.10197.1.503": "SHA256withSM2",
    "1.2.156.10197.1.504": "SHA512withSM2",
    "1.2.156.10197.1.505": "SHA224withSM2",
    "1.2.156.10197.1.506": "SHA384withSM2",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.113549.1.1.14": "sha224WithRSAEncryption",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
    "1.2.840.10045.4.3.4": "ecdsa-with-SHA512",
}


def _alg_label(oid) -> str:
    """签名/算法 OID → '名字（OID …）'；未收录的 OID 退化为原样。"""
    oid = oid or ""
    name = _SIG_OID_NAMES.get(oid) or _OID_SHORT.get(oid)
    if name:
        return "%s（OID %s）" % (name, oid)
    return oid


def _fmt_cert_time(dt) -> str:
    """datetime → 'YYYY/M/D H:M:S'（本地时区；无前导零的月/日，参考工具表达）。"""
    try:
        local = dt.astimezone()
        return "%d/%d/%d %02d:%02d:%02d" % (local.year, local.month, local.day,
                                            local.hour, local.minute, local.second)
    except Exception:
        return str(dt)


def _asn1_time_str(raw: bytes) -> str:
    """X.509 UTCTime(YYMMDDHHMMSSZ) / GeneralizedTime(YYYYMMDDHHMMSSZ) → 本地 'YYYY/M/D H:M:S'。"""
    s = raw.decode('ascii', 'replace').strip()
    try:
        from datetime import datetime, timezone
        body = s.rstrip("Z")
        if len(body) == 12:
            dt = datetime.strptime(body, "%y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        elif len(body) == 14:
            dt = datetime.strptime(body, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        else:
            return s
        return _fmt_cert_time(dt)
    except Exception:
        return s


def _cert_version_text(ver) -> str:
    """x509.Version / int → 'V1'/'V2'/'V3'。"""
    try:
        n = int(ver.value)
    except Exception:
        try:
            n = int(ver)
        except Exception:
            return str(ver)
    return {0: "V1", 1: "V2", 2: "V3"}.get(n, "V%d" % (n + 1))


def _ber_tlv(data: bytes, off: int):
    """读取一个 BER/DER TLV，返回 (tag, value_bytes, next_off)。"""
    tag = data[off]; off += 1
    lb = data[off]; off += 1
    if lb & 0x80:
        n = lb & 0x7F
        ln = int.from_bytes(data[off:off + n], "big"); off += n
    else:
        ln = lb
    return tag, data[off:off + ln], off + ln


def _ber_oid_str(oid_bytes: bytes) -> str:
    parts = []
    first = True
    x = 0
    for b in oid_bytes:
        x = (x << 7) | (b & 0x7F)
        if not (b & 0x80):
            if first:
                parts.append(str(x // 40))
                parts.append(str(x % 40))
                first = False
            else:
                parts.append(str(x))
            x = 0
    return ".".join(parts)


def _val_to_str(tag: int, val: bytes) -> str:
    if tag in (0x0C, 0x13, 0x16, 0x1E, 0x14):  # UTF8/Printable/IA5/T61/Teletex
        return val.decode('utf-8', 'replace').strip()
    return val.hex()


_DN_PRIORITY = {"CN": 0, "OU": 1, "O": 2, "L": 3, "ST": 4, "STREET": 5,
                "C": 6, "emailAddress": 7}


def _dn_attr_first(pairs):
    """按展示优先级稳定排序 RDN（CN → OU → O → L → ST → C），
    各 CA 的 DER 顺序（有的 CN 在前、有的 C 在前）统一成「CN 在前的常见展示顺序」。"""
    pairs.sort(key=lambda x: _DN_PRIORITY.get(x[0], 9))
    return ",".join(v for _, v in pairs)


def _name_to_str(name_val: bytes) -> str:
    """Name ::= SEQUENCE OF RDN（RDN ::= SET OF AttributeTypeAndValue）→ rfc4514 样式。"""
    parts = []
    off = 0
    while off < len(name_val):
        _, rdn_set, off = _ber_tlv(name_val, off)  # SET
        off3 = 0
        while off3 < len(rdn_set):
            _, atv, off3 = _ber_tlv(rdn_set, off3)  # ATV ::= SEQ{oid, value}
            _, oid_b, o4 = _ber_tlv(atv, 0)
            oid = _ber_oid_str(oid_b)
            v_tag, v_bytes, _ = _ber_tlv(atv, o4)
            label = _OID_SHORT.get(oid, oid)
            parts.append((label, "%s=%s" % (label, _val_to_str(v_tag, v_bytes))))
    return _dn_attr_first(parts)


def _dn_attr_first_4514(s: str) -> str:
    """把 RFC4514 DN 字符串重排为 CN 在前的展示顺序。
    按 rfc4514 转义规则切分：前有反斜杠的逗号属于值内，不切断。"""
    if not s:
        return s
    toks = re.split(r"(?<!\\),", s)
    pairs = []
    for t in toks:
        if "=" in t:
            lbl, val = t.split("=", 1)
            pairs.append((lbl, t))
        else:
            pairs.append(("", t))
    pairs.sort(key=lambda x: _DN_PRIORITY.get(x[0], 9))
    return ",".join(v for _, v in pairs)


def _alg_oid_of(alg_seq: bytes):
    """algorithm SEQUENCE { oid, params? } → (oid_str, params_bytes)。"""
    try:
        _, oid_b, off = _ber_tlv(alg_seq, 0)
        oid = _ber_oid_str(oid_b)
        params = b""
        if off < len(alg_seq):
            _, params, _ = _ber_tlv(alg_seq, off)
        return oid, params
    except Exception:
        return "", b""


def _parse_der_loose(der: bytes) -> OrderedDict:
    """纯 ASN.1 方式提取证书关键字段，兼容 SM2 国密曲线。"""
    d = OrderedDict()
    try:
        _, body, _ = _ber_tlv(der, 0)
        # body: [tbs, sig_alg, sig]
        _, tbs, off = _ber_tlv(body, 0)
        _, sig_alg_seq, off = _ber_tlv(body, off)
        _, sig_bit, _ = _ber_tlv(body, off)

        # TBS：version [0] IMPLICIT（可选，V2/V3 才有）→ serial INTEGER → 其余 SEQUENCE
        tbs_o = 0
        d["version"] = "V1"
        tg0, v0, tbs_o = _ber_tlv(tbs, tbs_o)
        if tg0 == 0xA0:  # [0] version
            try:
                _, iv, _ = _ber_tlv(v0, 0)
                n = int.from_bytes(iv, "big")
                d["version"] = {0: "V1", 1: "V2", 2: "V3"}.get(n, "V%d" % (n + 1))
            except Exception:
                pass
            tg0, v0, tbs_o = _ber_tlv(tbs, tbs_o)  # 随后的 serial
        if tg0 == 0x02:
            d["serial"] = "%X" % int.from_bytes(v0, "big")

        # 其余按序收集 SEQUENCE：signature, issuer, validity, subject, spki；同时捕获 [3] extensions
        seqs = []
        ext_val = b""
        o = tbs_o
        while o < len(tbs):
            tag, val, o = _ber_tlv(tbs, o)
            if tag == 0x30:
                seqs.append(val)
            elif tag == 0xA3:
                ext_val = val
        sig_seq = seqs[0] if len(seqs) > 0 else b""
        issuer = seqs[1] if len(seqs) > 1 else b""
        validity = seqs[2] if len(seqs) > 2 else b""
        subject = seqs[3] if len(seqs) > 3 else b""
        spki = seqs[4] if len(seqs) > 4 else b""

        d["subject"] = _name_to_str(subject) if subject else "(空)"
        d["issuer"] = _name_to_str(issuer) if issuer else "(空)"
        # validity
        if validity:
            try:
                _, nb, o2 = _ber_tlv(validity, 0)
                _, na, _ = _ber_tlv(validity, o2)
                d["not_before"] = _asn1_time_str(nb)
                d["not_after"] = _asn1_time_str(na)
            except Exception:
                pass
        # 证书整体签名算法（TBS.sig 与 outer sig_alg 一般一致）
        sig_oid, _ = _alg_oid_of(sig_seq)
        outer_oid, _ = _alg_oid_of(sig_alg_seq)
        d["sig_algorithm"] = _alg_label(outer_oid or sig_oid)
        # 公钥
        if spki:
            try:
                # spki 的 SEQUENCE value 内第一个 TLV 即 AlgorithmIdentifier（含算法与曲线参数）
                _, spki_inner, _ = _ber_tlv(spki, 0)
                alg_oid, params = _alg_oid_of(spki_inner)
                curve = ""
                if params:
                    try:
                        # params 已是曲线 OID 的内容体（去掉 0x06 标签）
                        curve = _ber_oid_str(params)
                    except Exception:
                        pass
                if alg_oid == "1.2.156.10197.1.301":
                    d["pubkey"] = "SM2（椭圆曲线公钥密码算法）"
                    d["pubkey_curve"] = "SM2（OID 1.2.156.10197.1.301，256 位）"
                elif alg_oid == "1.2.840.10045.2.1":
                    if curve == "1.2.156.10197.1.301" or curve == "1.3.132.0.38":
                        d["pubkey"] = "SM2（椭圆曲线公钥密码算法）"
                        d["pubkey_curve"] = "SM2（OID %s，256 位）" % curve
                    else:
                        d["pubkey"] = "ECC（椭圆曲线公钥算法 id-ecPublicKey）"
                        d["pubkey_curve"] = "%s（OID %s）" % (_OID_SHORT.get(curve, curve or "未知曲线"), curve)
                else:
                    d["pubkey"] = "%s（OID %s）" % (_OID_SHORT.get(alg_oid, "未知算法"), alg_oid)
            except Exception:
                pass
        # 签名值
        if sig_bit:
            d["sig_value"] = sig_bit[1:].hex() if len(sig_bit) > 1 else ""
        if ext_val:
            _parse_cert_extensions(ext_val, d)
        d["note"] = "（cryptography 不支持该曲线，已用 ASN.1 松散解析）" if "SM2" in d.get("pubkey", "") else "（ASN.1 松散解析）"
        d["der_hex"] = der.hex()
        return d
    except Exception as e:
        return {"error": "证书解析失败: %r" % e, "der_hex": _fmt_hex(der, 48)}


_KEY_USAGE_BITS = (
    (0, "digitalSignature 数字签名"), (1, "nonRepudiation 不可否认性"),
    (2, "keyEncipherment 密钥加密"), (3, "dataEncipherment 数据加密"),
    (4, "keyAgreement 密钥协商"), (5, "keyCertSign 证书签发"),
    (6, "cRLSign CRL 签发"), (7, "encipherOnly"), (8, "decipherOnly"),
)


def _key_usage_text_raw(bitstr: bytes) -> str:
    """KeyUsage ::= BIT STRING（首字节为未用位数，其余字节 MSB 优先）→ 用法文本。"""
    if not bitstr:
        return "（未声明）"
    unused = bitstr[0]
    total = len(bitstr[1:]) * 8 - min(unused, 7)
    names = []
    for i, b in enumerate(bitstr[1:]):
        for j in range(8):
            idx = i * 8 + j
            if idx >= total:
                break
            if b & (0x80 >> j):
                nm = dict(_KEY_USAGE_BITS).get(idx)
                if nm:
                    names.append(nm)
    return ", ".join(names) or "（未声明）"


def _parse_cert_extensions(exts_val: bytes, d: dict):
    """[3] EXPLICIT Extensions（内容为 SEQUENCE OF Extension）；提取
    keyUsage / basicConstraints / EKU。"""
    try:
        _, seqv, _ = _ber_tlv(exts_val, 0)  # Extensions ::= SEQUENCE OF Extension 的全部内容
    except Exception:
        return
    o = 0
    while o + 2 <= len(seqv):
        try:
            _, ev, off = _ber_tlv(seqv, o)  # 单个 Extension ::= SEQ{ extnID, critical?, extnValue }
            _, oid_b, o2 = _ber_tlv(ev, 0)
            ext_oid = _ber_oid_str(oid_b)
            t2, v2, o2 = _ber_tlv(ev, o2)
            if t2 == 0x01:  # 可选 critical(BOOLEAN)，其后才是 extnValue(OCTET STRING)
                _, evb, _ = _ber_tlv(ev, o2)
            else:
                evb = v2
            if ext_oid == "2.5.29.15":
                _, kb, _ = _ber_tlv(evb, 0)
                d["key_usage"] = _key_usage_text_raw(kb)
            elif ext_oid == "2.5.29.19":
                _, bcseq, _ = _ber_tlv(evb, 0)
                ca = False
                bo2 = 0
                if bo2 < len(bcseq):
                    t1, v1, bo2 = _ber_tlv(bcseq, bo2)
                    if t1 == 0x01:
                        ca = v1 != b"\x00"
                d["basic_constraints"] = "is_ca=%s" % ca
            elif ext_oid == "2.5.29.37":
                names = []
                bo2 = 0
                while bo2 < len(evb):
                    _, oidb, bo2 = _ber_tlv(evb, bo2)
                    names.append(_EKU_NAME.get(_ber_oid_str(oidb), _ber_oid_str(oidb)))
                if names:
                    d["ext_key_usage"] = ", ".join(names)
            o = off
        except Exception:
            break


def _fmt_pubkey(pub):
    try:
        if isinstance(pub, __import__('cryptography.hazmat.primitives.asymmetric.ec', fromlist=['EllipticCurvePublicKey']).EllipticCurvePublicKey):
            return "EC %s (%d bit)" % (pub.curve.name, pub.key_size)
        if hasattr(pub, 'key_size'):
            alg = pub.__class__.__name__.replace('PublicKey', '')
            return "%s (%d bit)" % (alg, pub.key_size)
    except Exception:
        pass
    return pub.__class__.__name__


def _sha256(b: bytes) -> str:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    d = hashes.Hash(hashes.SHA256(), backend=default_backend())
    d.update(b)
    return d.finalize().hex()


def parse_certificate_verify(body: bytes):
    """CertificateVerify：签名算法 + 签名值。"""
    d = OrderedDict()
    if len(body) < 4:
        return d
    scheme = struct.unpack(">H", body[0:2])[0]
    sn = struct.unpack(">H", body[2:4])[0]
    d["signature_scheme"] = "%s (0x%04X)" % (_sig_name(scheme), scheme)
    d["signature"] = body[4:4 + sn].hex()
    d["signature_len"] = sn
    return d


def _parse_der_ecdsa(sig: bytes):
    """拆分 DER 编码的 ECDSA/SM2 签名：SEQUENCE { INTEGER r, INTEGER s }；失败返回 None。"""
    try:
        if not sig or sig[0] != 0x30:
            return None
        off = 1
        ln = sig[off]
        off += 1
        if ln & 0x80:  # 长格式长度
            nl = ln & 0x7F
            ln = int.from_bytes(sig[off:off + nl], "big")
            off += nl
        if off + 2 > len(sig) or sig[off] != 0x02:
            return None
        rl = sig[off + 1]
        off += 2
        r = sig[off:off + rl]
        off += rl
        if off + 1 >= len(sig) or sig[off] != 0x02:
            return None
        sl = sig[off + 1]
        off += 2
        s = sig[off:off + sl]
        return r, s
    except Exception:
        return None


def _sig_fields(d, sig):
    """若签名是 DER 编码的 ECDSA/SM2（r, s），附加解析字段。"""
    der = _parse_der_ecdsa(sig)
    if der:
        r, s = der
        d["signature_r"] = r.hex()
        d["signature_s"] = s.hex()


def parse_server_key_exchange(body: bytes):
    """ServerKeyExchange：兼容两种形态。

    - TLS1.2 ECDHE（RFC 4492）：curve_type(1..3) + 命名曲线 + ECPoint + 签名；
    - TLCP / GB/T 38636 ECC-SM2-EXPORT：无内嵌曲线与临时公钥，整个消息 = 2 字节签名
      长度 + DER 编码的 SM2 签名（对应 Wireshark 的 "ECC-SM2-EXPORT Server Params /
      Signature Length / Signature"）。
    """
    d = OrderedDict()
    if not body:
        return d
    d["length"] = "%d字节" % len(body)
    ptype = body[0]
    if ptype in (1, 2, 3) and len(body) > 4:  # RFC 4492 ECDHE
        off = 1
        if ptype == 3 and off + 2 < len(body):  # named_curve
            grp = struct.unpack(">H", body[off:off + 2])[0]
            off += 2
            plen = body[off]
            off += 1
            d["curve_type"] = "named_curve (命名椭圆曲线)"
            d["named_group"] = _group_name(grp)
            if off + plen <= len(body):
                d["ec_pubkey"] = body[off:off + plen].hex()
                off += plen
        elif ptype == 1:
            d["curve_type"] = "explicit_prime (显式素数域曲线)"
        elif ptype == 2:
            d["curve_type"] = "explicit_char2 (显式特征 2 域曲线)"
        if off + 4 <= len(body):
            scheme = struct.unpack(">H", body[off:off + 2])[0]
            slen = struct.unpack(">H", body[off + 2:off + 4])[0]
            off += 4
            sig = body[off:off + slen]
            d["signature_scheme"] = "%s (0x%04X)" % (_sig_name(scheme), scheme)
            d["signature_length"] = "%dB" % slen
            d["signature"] = sig.hex()
            _sig_fields(d, sig)
        return d
    # TLCP / GB/T 38636 ECC-SM2-EXPORT：无内嵌参数，整个消息 = 2 字节长度 + DER SM2 签名
    d["curve_type"] = "ecc_sm2_export (ECC-SM2-EXPORT 导出模式，无内嵌曲线/临时公钥)"
    d["params"] = "无内嵌参数（仅对握手消息做 SM2 签名）"
    if len(body) >= 2:
        slen = struct.unpack(">H", body[0:2])[0]
        sig = body[2:2 + slen]
        d["signature_length"] = "%dB" % slen
        d["signature"] = sig.hex()
        d["signature_algorithm"] = "SM2 签名 (DER 编码)" if sig and sig[0] == 0x30 else "（非 DER）"
        _sig_fields(d, sig)
    return d


def parse_finished(body: bytes):
    return {"verify_data": body.hex()}


# ---------------------------------------------------------------- TCP 流重组 + 全量解析

def _flow_key(pkt):
    """归一化 TCP 流 key：把 IP 对排序，保证 A<->B 两条方向合并到同一流。"""
    if IP in pkt:
        a, b = pkt[IP].src, pkt[IP].dst
        sp, dp = pkt[TCP].sport, pkt[TCP].dport
    elif IPv6 in pkt:
        a, b = pkt[IPv6].src, pkt[IPv6].dst
        sp, dp = pkt[TCP].sport, pkt[TCP].dport
    else:
        return None
    # 统一方向：使返回的 (addr_a, port_a) 总指向"较小键"，另一侧为 b
    if (a, sp) <= (b, dp):
        return (a, sp, b, dp)
    return (b, dp, a, sp)


PROXY_V2_SIG = b"\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a"


def _strip_proxy(data: bytes):
    """剥离 PROXY 协议头（v1 纯文本 / v2 二进制签名），返回 (剥离后的字节流, 剥离长度)。

    部分国密网关连接在 TLCP 握手记录前会先发一条 PROXY 头（如 "PROXY TCP4 …\\r\\n"），
    它不属于 TLS/TLCP 记录，会破坏记录边界解析，必须在解析前剥掉。"""
    if not data:
        return data, 0
    n = 0
    if data.startswith(b"PROXY "):
        e = data.find(b"\r\n")
        if e != -1:
            n = e + 2
    elif data.startswith(PROXY_V2_SIG) and len(data) >= 16:
        ln = struct.unpack(">H", data[14:16])[0]
        n = min(16 + ln, len(data))
    if 0 < n < len(data):
        return data[n:], n
    return data, 0


def _skip_preamble(data: bytes):
    """跳过 TLS/TLCP 握手记录之前的网关私有前置报文（非 PROXY 的专有头）。

    拨号业务通道等网关会在 TLCP 握手前先发设备注册/版本协商等私有报文，
    导致流首字节不是记录头、TLS/TLCP 无法识别。做法：向后扫描第一个
    “记录类型 0x16(握手) + 版本号合法 + 长度可容纳” 的起点，把之前的私有报文
    一并跳过。仅在字节流本身不以记录类型开头时才扫描，扫描不到则原样返回。
    """
    if not data or data[0] in (0x14, 0x15, 0x16, 0x17, 0x18):
        return data, 0
    n = len(data)
    if n <= 5:
        return data, 0
    limit = min(n - 5, 1 << 20)
    for i in range(limit + 1):
        if data[i] != 0x16:
            continue
        ver = struct.unpack(">H", data[i + 1:i + 3])[0]
        if ver not in (0x0001, 0x0002, 0x0101, 0x0300, 0x0301, 0x0302, 0x0303, 0x0304):
            continue
        ln = struct.unpack(">H", data[i + 3:i + 5])[0]
        if i + 5 + ln > n:
            continue
        return data[i:], i
    return data, 0


def _join_segments(seg_map: dict):
    """把 {seq: payload} 按 TCP 序列号顺序拼成连续字节，处理重叠与重传。"""
    if not seg_map:
        return b""
    segs = sorted(seg_map.items())
    base = segs[0][0]
    result = b""
    for seq, pl in segs:
        start = seq - base
        end = start + len(pl)
        if end <= len(result):  # 完全被已有数据覆盖（重传）
            continue
        if start <= len(result):  # 部分重叠，只补新尾部
            result += pl[len(result) - start:]
        else:  # 中间有空洞，标记占位
            result += b"\x00" * (start - len(result)) + pl
    return result


def _reassemble_flows(pkts):
    """按 TCP 流 + 方向重组 payload，返回 {key: {'ab': bytes, 'ba': bytes, 'a':.., 'b':..}}。"""
    flows = defaultdict(lambda: {"ab": {}, "ba": {}, "ab_num": {}, "ba_num": {}, "a": "", "b": "", "init": ""})
    for no, p in enumerate(pkts, 1):
        if not (p.haslayer(TCP) and (IP in p or IPv6 in p)):
            continue
        key = _flow_key(p)
        if key is None:
            continue
        a, ap, b, bp = key
        if IP in p:
            src, dst, sp, dp = p[IP].src, p[IP].dst, p[TCP].sport, p[TCP].dport
        else:
            src, dst, sp, dp = p[IPv6].src, p[IPv6].dst, p[TCP].sport, p[TCP].dport
        payload = bytes(p[TCP].payload)
        if not payload:
            continue
        flows[key]["a"], flows[key]["b"] = a, b
        if p[TCP].flags & 0x02 and not (p[TCP].flags & 0x10) and not flows[key]["init"]:
            # 记录 TCP 发起方（首个 SYN 源），无 ClientHello 时据此校准客户端方向
            flows[key]["init"] = "ab" if (src, sp) == (a, ap) else "ba"
        d = "ab" if (src, sp) == (a, ap) else "ba"
        flows[key][d][p[TCP].seq] = payload
        flows[key][d + "_num"][p[TCP].seq] = no
    out = {}
    for key, f in flows.items():
        out[key] = {
            "ab": _join_segments(f["ab"]),
            "ba": _join_segments(f["ba"]),
            "ab_base": min(f["ab"]) if f["ab"] else 0,
            "ba_base": min(f["ba"]) if f["ba"] else 0,
            "ab_num": dict(f["ab_num"]),
            "ba_num": dict(f["ba_num"]),
            "ab_len": dict((seq, len(pl)) for seq, pl in f["ab"].items()),
            "ba_len": dict((seq, len(pl)) for seq, pl in f["ba"].items()),
            "a": f["a"], "b": f["b"], "init": f.get("init", ""),
        }
    return out


def _msg_packet_no(segs, abs_seq):
    """字节偏移 abs_seq 落在哪一段 TCP 载荷中，返回该段的抓包包号（scapy number）。

    segs: 升序的 [(起始TCP序号, 载荷长度, 包号)]；空洞区域返回 None。"""
    if abs_seq is None or not segs:
        return None
    for start, ln, number in segs:
        if start <= abs_seq < start + ln:
            return number
    return None


def _parse_record_stream(data: bytes, direction: str, base: int, proto: str, segs=None):
    """把单方向已重组的字节流解析为 TLS/TLCP 明文握手消息列表。

    segs: [(起始TCP序号, 载荷长度, 包号)]，用于给每条消息标注其所在抓包包号（随机序）。
    """
    out_msgs = []
    rec_type_map = TLCP_RECORD_TYPE if proto == "TLCP" else TLS_RECORD_TYPE
    _, records = split_proto_records(data, default=proto)
    for typ, ver, payload, rec_off in records:
        if typ not in rec_type_map:
            continue
        # ChangeCipherSpec（记录类型 0x14/20）：单独成一条消息，是协商序列的固定环节
        if typ != 22:
            if typ == 20 and payload == b"\x01":
                out_msgs.append({
                    "dir": direction,
                    "proto": proto,
                    "type": rec_type_map[typ],
                    "summary": "切换为加密通信",
                    "fields": {"change_cipher_spec": "已切换为加密通信"},
                    "offset": base + rec_off,
                    "no": _msg_packet_no(segs, base + rec_off),
                })
            continue
        for mt, body, msg_off in split_handshake_messages(payload):
            name = HANDSHAKE_TYPE.get(mt, "type%d" % mt)
            fields = _fields_for(mt, body, proto)
            summary = _summary_for(mt, fields)
            out_msgs.append({
                "dir": direction,
                "proto": proto,
                "type": name,
                "summary": summary,
                "fields": fields,
                "offset": base + rec_off + msg_off,
                "no": _msg_packet_no(segs, base + rec_off + msg_off),
            })
    return out_msgs


def analyze_flows(pkts):
    """对 pcap 包列表做 TCP 流重组并逐流解析（TLS / TLCP / SSH 等）。

    返回 dict：
      overview         汇总信息
      flows            {flow_key: {client, server, proto, dirs, messages}}
      msg_counter      Counter[消息类型]
      record_counter   Counter[记录类型]
    """
    flows = _reassemble_flows(pkts)

    flow_out = {}
    record_counter = Counter()
    msg_counter = Counter()
    cipher_used = Counter()
    sni_set = set()
    alpn_set = set()

    for key, f in flows.items():
        a, ap, b, bp = key
        conv_msgs = []
        flow_proto = ""
        for direction, data, base in (("A->B", f["ab"], f["ab_base"]), ("B->A", f["ba"], f["ba_base"])):
            if not data:
                continue
            # 剥离 PROXY 协议头（不影响包号定位：剥离长度并入 base 偏移即可）
            data, stripped = _strip_proxy(data)
            base += stripped
            # 跳过网关私有前置报文（同样并入 base 偏移，保证包号/偏移仍准确）
            data, skipped = _skip_preamble(data)
            base += skipped
            if not data:
                continue
            proto, _ = split_proto_records(data)
            if not flow_proto:
                flow_proto = proto
            # 每方向段的 (起始TCP序号, 长度, 包号) 升序表：给消息标注原始包号
            d_key = "ab" if direction == "A->B" else "ba"
            len_map = f[d_key + "_len"]
            num_map = f[d_key + "_num"]
            segs = sorted((seq, len_map.get(seq, 0), num_map.get(seq))
                          for seq in num_map) if num_map else []
            # 若首方向数据不是 TLS/TLCP 记录（非 0x16/0x14/0x15/0x17/0x18 开头），跳过，交给更高层识别
            rec_type_map = TLCP_RECORD_TYPE if proto == "TLCP" else TLS_RECORD_TYPE
            for typ, ver, payload, rec_off in split_tls_records(data):
                if typ in rec_type_map:
                    record_counter[rec_type_map[typ]] += 1
                if typ != 22:
                    continue
            msgs = _parse_record_stream(data, direction, base, proto, segs)
            for m in msgs:
                msg_counter[m["type"]] += 1
                fd = m["fields"]
                if m["type"] == "ServerHello":
                    cs = fd.get("selected_cipher_suite")
                    if cs:
                        cipher_used[cs] += 1
                if fd.get("SNI"):
                    sni_set.add(fd["SNI"])
                if fd.get("ext_application_layer_protocol_negotiation (ALPN)"):
                    alpn_set.add(fd["ext_application_layer_protocol_negotiation (ALPN)"])
            conv_msgs.extend(msgs)

        if not conv_msgs:
            continue
        conv_msgs.sort(key=lambda x: x["offset"])
        client, server = ("%s:%d" % (a, ap), "%s:%d" % (b, bp))
        # 客户端 = ClientHello 的来源方向（比首条消息方向更可靠）；
        # 无 ClientHello 时退回 TCP 发起方（SYN 源）方向；仍未知再退回首条消息方向
        cdir = next((m["dir"] for m in conv_msgs if m.get("type") == "ClientHello"), None)
        if cdir is None:
            init = f.get("init", "")
            if init == "ba":
                cdir = "B->A"
            elif init == "ab":
                cdir = "A->B"
            else:
                cdir = conv_msgs[0]["dir"] if conv_msgs else "A->B"
        if cdir == "B->A":
            client, server = server, client
        flow_out[key] = {
            "client": client,
            "server": server,
            "proto": flow_proto or "TLS",
            "messages": [{k: v for k, v in m.items() if k != "offset"} for m in conv_msgs],
        }

    overview = OrderedDict()
    overview["握手消息总数"] = sum(msg_counter.values())
    overview["握手消息分布"] = ", ".join("%s×%d" % kv for kv in msg_counter.most_common())
    overview["记录类型分布"] = ", ".join("%s×%d" % kv for kv in record_counter.most_common())
    if cipher_used:
        overview["协商的加密套件"] = ", ".join("%s×%d" % kv for kv in cipher_used.most_common())
    if sni_set:
        overview["SNI 域名"] = ", ".join(sorted(sni_set))
    if alpn_set:
        overview["ALPN 协议"] = ", ".join(sorted(alpn_set))

    return {
        "overview": overview,
        "flows": flow_out,
        "msg_counter": msg_counter,
        "record_counter": record_counter,
    }


def analyze_tls(path: str):
    """对 pcap/pcapng 做 TLS / TLCP 深度解析（兼容旧接口）。

    返回 dict：
      overview / conversations / messages / msg_counter / record_counter
    """
    pkts = rdpcap(path)
    r = analyze_flows(pkts)
    convos = []
    flat_msgs = []
    for key, fl in r["flows"].items():
        convos.append({"client": fl["client"], "server": fl["server"],
                       "proto": fl["proto"],
                       "messages": fl["messages"]})
        flat_msgs.extend(fl["messages"])
    return {
        "overview": r["overview"],
        "conversations": convos,
        "messages": flat_msgs,
        "msg_counter": r["msg_counter"],
        "record_counter": r["record_counter"],
    }


def parse_client_key_exchange(body: bytes) -> dict:
    """TLS 1.2 ClientKeyExchange：客户端发给服务端的密钥交换数据。

    - EC / X25519：1 字节点长度 + 公钥点（如 0x20 + 32 字节 X25519 公钥）
    - RSA：2 字节长度 + 加密的预主密钥
    - TLS 1.3 客户端可能发送空 CKE（载荷 0 字节）
    """
    d = OrderedDict()
    if not body:
        d["key_exchange"] = "空载荷（TLS 1.3 空密钥交换）"
        return d
    klen = body[0]
    if 1 + klen == len(body) and klen >= 1:
        pub = body[1:1 + klen]
        d["key_exchange_len"] = len(body)
        d["pubkey_len"] = klen
        d["pubkey_hex"] = pub.hex()
    elif len(body) >= 2:
        rlen = struct.unpack(">H", body[:2])[0]
        d["key_exchange_len"] = len(body)
        d["encrypted_premaster_len"] = rlen
        d["encrypted_premaster_hex"] = body[2:2 + rlen].hex()
    else:
        d["key_exchange_len"] = len(body)
        d["key_exchange_hex"] = body.hex()
    return d


def _fields_for(mt: int, body: bytes, proto: str = "TLS"):
    if mt == 1:
        return parse_client_hello(body, proto)
    if mt == 2:
        return parse_server_hello(body, proto)
    if mt == 11:
        certs = parse_certificate(body, is_tls13=False)
        d = OrderedDict()
        d["cert_chain_count"] = len(certs)
        for i, c in enumerate(certs):
            for k, v in c.items():
                d["cert%d_%s" % (i + 1, k)] = v
        return d
    if mt == 15:
        return parse_certificate_verify(body)
    if mt == 12:
        return parse_server_key_exchange(body)
    if mt == 16:
        return parse_client_key_exchange(body)
    if mt == 20:
        return parse_finished(body)
    if mt == 4:
        # NewSessionTicket: lifetime(4) age_add(4) nonce_len(1) nonce ticket_len(2) ticket
        if len(body) >= 10:
            tlen = struct.unpack(">H", body[8:10])[0]
            return {"ticket_len": tlen, "ticket_hex": body[10:10 + tlen].hex()}
        return {}
    return {}


def _summary_for(mt: int, fields: dict) -> str:
    if mt == 1:
        return ("legacy_version=%s; ciphers=%s" % (fields.get('legacy_version', '?'),
                                                   (fields.get('cipher_suites', '') or '')[:80]))[:160]
    if mt == 2:
        return "cipher=%s; %s" % (fields.get('selected_cipher_suite', '?'),
                                  _ext_summary(fields))
    if mt == 11:
        n = fields.get("cert_chain_count", 0)
        if n:
            subj = fields.get("cert1_subject", "")
            sig = fields.get("cert1_sig_algorithm", "")
            return "%d 张证书; 主体=%s; 签名算法=%s" % (n, subj, sig)
        return "0 张证书"
    if mt == 15:
        return "scheme=%s; sig=%s…" % (fields.get("signature_scheme", '?'),
                                       (fields.get("signature", '') or '')[:40])
    if mt == 12:
        if "sm2" in str(fields.get("curve_type", "")).lower() or "导出" in str(fields.get("curve_type", "")):
            return "ECC-SM2-EXPORT; 签名长度=%s; 签名=%s…" % (
                fields.get("signature_length", '?'), (fields.get("signature", '') or '')[:24])
        return "group=%s; scheme=%s" % (fields.get("named_group", '?'),
                                        fields.get("signature_scheme", '?'))
    if mt == 16:
        return "key_exchange=%dB; pubkey_len=%s" % (fields.get("key_exchange_len", 0),
                                                    fields.get("pubkey_len", '?'))
    if mt == 20:
        return "verify_data=%s…" % (fields.get("verify_data", '')[:32])
    if mt == 4:
        return "ticket.len=%s" % fields.get("ticket_len", '?')
    return ""


def _ext_summary(fields: dict) -> str:
    parts = []
    for k, v in fields.items():
        if k.startswith("ext_") and v:
            parts.append("%s" % v)
    if fields.get("SNI"):
        parts.insert(0, "SNI=%s" % fields["SNI"])
    return "; ".join(parts)[:120]
