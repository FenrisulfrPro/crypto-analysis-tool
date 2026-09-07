# -*- coding: utf-8 -*-
"""X.509 证书分析核心逻辑（PEM / DER），完整支持国密 SM2 证书。

cryptography 库不支持 SM2 曲线（1.2.156.10197.1.301），对国密证书调用
.public_key() 会抛 UnsupportedAlgorithm。本模块通过 ASN.1（BER/DER TLV）直接
从 SubjectPublicKeyInfo 中提取 SM2 未压缩公钥点（04||X||Y），完整展开公钥坐标。
"""
from collections import OrderedDict
import base64

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
from cryptography.x509.oid import ExtensionOID

# 国密相关 OID
SM2_KEY_OID = "1.2.156.10197.1.301"   # SM2 公钥
SM2_SIG_OID = "1.2.156.10197.1.501"   # SM3withSM2 签名算法
EC_PUBKEY_OID = "1.2.840.10045.2.1"   # id-ecPublicKey


def _load_cert(text: str = None, path: str = None) -> x509.Certificate:
    """从 PEM 文本或文件（PEM / DER / 无 PEM 外壳的 base64）加载证书。

    三级容错：
      1. PEM（-----BEGIN CERTIFICATE-----）
      2. DER
      3. 容错修复后 DER（移除显式编码的默认值，如 BasicConstraints.ca=FALSE）；
         若原始内容为不带 PEM 外壳的 base64 文本则先解码再走 2/3。
    """
    if path:
        raw = open(path, 'rb').read()
    elif text:
        raw = text.encode('utf-8')
    else:
        raise ValueError("没有可分析的证书内容")
    try:
        return x509.load_pem_x509_certificate(raw)
    except Exception:
        pass

    der = _as_der_candidate(raw)
    err = None
    for candidate in (der, _repair_der(der)):
        try:
            cert = x509.load_der_x509_certificate(candidate)
            list(cert.extensions)          # 触发懒解析：BasicConstraints 等错误此时才暴露
            return cert
        except Exception as e:
            if err is None:
                err = e
    raise ValueError("无法解析证书：%s" % err)


def _as_der_candidate(raw: bytes) -> bytes:
    """将原始字节规整为 DER 候选：已是 DER 则原样，否则按无外壳 base64 解码。"""
    if raw.startswith(b'\x30'):
        return raw
    text = b''.join(raw.split())
    try:
        dec = base64.b64decode(text)
    except Exception:
        return raw
    if dec.startswith(b'\x30'):
        return dec
    return raw


def _der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def _tlv_end(content: bytes) -> int:
    """返回按 TLV 完整解析 content 所消耗的字节数（供“内嵌 DER”判定）。"""
    o = 0
    while o < len(content):
        _, _, o = _ber_tlv(content, o)
    return o


def _repair_der(data: bytes) -> bytes:
    """非严格 DER 容错：删除 SEQUENCE/SET 子元素中的显式默认值（BOOLEAN FALSE，
    DER 规定缺省时应省略，国密证书常被错误显式编码，导致 cryptography 拒解析）。

    扩展项的 DER 值被包在 OCTET STRING 里，因此对能以完整 TLV 解析的
    OCTET STRING（内嵌 DER）也递归修复。
    """

    def walk(content: bytes) -> bytes:
        out = b''
        o = 0
        while o < len(content):
            tag, val, nxt = _ber_tlv(content, o)
            if tag == 0x01 and val == b'\x00':   # BOOLEAN FALSE 显式编码 -> 移除
                o = nxt
                continue
            seg = content[o:nxt]
            if tag & 0x20:                        # 构造类型：递归修复子元素
                inner = walk(val)
                seg = bytes([tag]) + _der_len(len(inner)) + inner
            elif tag == 0x04 and val.startswith(b'\x30'):
                sub = walk(val)
                if _tlv_end(sub) == len(sub):     # 确认为完整内嵌 DER 才回写
                    seg = bytes([tag]) + _der_len(len(sub)) + sub
            out += seg
            o = nxt
        return out

    try:
        return walk(data)
    except Exception:
        return data


# ---------------------------------------------------------------- ASN.1 工具（SM2 公钥点解析）

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


def _oid_dotted(oid_bytes: bytes) -> str:
    """OID 原始字节转点分字符串。"""
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


def _cert_der(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def _children(content: bytes):
    """解析 DER 内容体（不含自身 tag/length）的顶层子元素列表，返回 [(tag, value)]。"""
    out = []
    o = 0
    while o < len(content):
        tag, val, o = _ber_tlv(content, o)
        out.append((tag, val))
    return out


def _tbs_seqs(der: bytes):
    """提取证书 TBS 内按序出现的 SEQUENCE 列表。"""
    _, body, _ = _ber_tlv(der, 0)          # Certificate ::= SEQ { tbs, sigAlg, sig }
    _, tbs, _ = _ber_tlv(body, 0)
    seqs = []
    o = 0
    while o < len(tbs):
        tag, val, o = _ber_tlv(tbs, o)
        if tag == 0x30:
            seqs.append(val)
    return seqs


def _spki_alg_and_point(content: bytes):
    """从 SPKI 内容体中提取 (算法OID串, 曲线参数OID串或None, BIT STRING 公钥内容)。

    content 为 SPKI 的元素体（不含 SEQ 头）。支持两种国密编码：
      A) alg OID = 1.2.156.10197.1.301（SM2 专用算法，无额外参数）
      B) alg OID = 1.2.840.10045.2.1（ecPublicKey），params = SM2 曲线 OID
    """
    alg_oid = None
    curve_oid = None
    pub_bitstring = None
    for tag, val in _children(content):
        if tag == 0x30:  # AlgorithmIdentifier ::= SEQ { OID, PARAMS? }
            kids = _children(val)
            if kids and kids[0][0] == 0x06:
                alg_oid = _oid_dotted(kids[0][1])
                if len(kids) > 1:
                    # params 形式：常见为 OID(曲线) 或 NULL
                    pt, pv = kids[1]
                    if pt == 0x06:
                        curve_oid = _oid_dotted(pv)
                        # 注意：kids[1] 可能是 BIT STRING 外的内容，
                        # 此处只负责算法参数；公钥取独立 BIT STRING
        elif tag == 0x03:  # BIT STRING
            pub_bitstring = val[1:]  # 去掉 unused bits 计数字节
    if curve_oid is None and alg_oid == SM2_KEY_OID:
        # 形式 A：算法本身就是 SM2，则曲线即 SM2
        curve_oid = SM2_KEY_OID
    return alg_oid, curve_oid, pub_bitstring


def _extract_sm2_pubpoint(cert):
    """从证书 DER 的 SPKI 中提取 SM2 未压缩公钥点 04||X||Y。

    返回 (x_hex, y_hex, point_hex, point_len) 或 None。
    cryptography 不支持 SM2 曲线（.public_key() 抛 UnsupportedAlgorithm），
    因此直接解析 SubjectPublicKeyInfo 的 BIT STRING。
    """
    try:
        seqs = _tbs_seqs(_cert_der(cert))
        if len(seqs) < 5:
            return None
        spki_content = seqs[4]                    # SubjectPublicKeyInfo 内容体
        alg_oid, curve_oid, point = _spki_alg_and_point(spki_content)
        if curve_oid != SM2_KEY_OID and alg_oid != SM2_KEY_OID:
            return None
        if not point:
            return None
        if len(point) == 65 and point[0] == 0x04:     # 未压缩点 04||X||Y
            x, y = point[1:33], point[33:65]
            return x.hex().upper(), y.hex().upper(), point.hex().upper(), len(point)
        if len(point) == 64:                          # 裸 X||Y
            x, y = point[:32], point[32:]
            return x.hex().upper(), y.hex().upper(), ("04" + point.hex()).upper(), len(point) + 1
        if len(point) in (33,) and point[0] == 0x04:  # 兼容 04 + 64
            return point[1:33].hex().upper(), point[33:65].hex().upper(), point.hex().upper(), len(point)
        return None
    except Exception:
        return None


def _spki_curve_is_sm2(cert) -> bool:
    """判断 SPKI 算法参数是否为国密 SM2 曲线 OID（用于兜底识别）。"""
    try:
        seqs = _tbs_seqs(_cert_der(cert))
        if len(seqs) < 5:
            return False
        alg_oid, curve_oid, _ = _spki_alg_and_point(seqs[4])
        return curve_oid == SM2_KEY_OID or alg_oid == SM2_KEY_OID
    except Exception:
        return False


def _sm2_pubkey_info(cert):
    """SM2 国密公钥完整信息：曲线 OID + 未压缩公钥点 X/Y 坐标。"""
    label = "SM2 国密公钥（OID %s）" % SM2_KEY_OID
    pt = _extract_sm2_pubpoint(cert)
    if pt:
        x, y, point_hex, plen = pt
        return label, (
            "未压缩公钥点 04||X||Y（共 %d 字节）:\n%s\nX = %s\nY = %s"
            % (plen, point_hex, x, y))
    return label, "（曲线 OID %s，未能从 SPKI 中展开公钥点坐标）" % SM2_KEY_OID


# ---------------------------------------------------------------- 公钥信息总入口

def _pubkey_info(cert: x509.Certificate):
    """返回 (公钥算法描述, 公钥参数描述)；SM2 国密证书展开公钥点坐标。"""
    # 情况一：公钥算法 OID 直接为国密 SM2
    try:
        if cert.public_key_algorithm_oid.dotted_string == SM2_KEY_OID:
            return _sm2_pubkey_info(cert)
    except Exception:
        pass
    # 情况二：RSA / EC / DSA / EdDSA 等 cryptography 原生支持
    try:
        pk = cert.public_key()
    except Exception as e:
        # SM2 曲线（位于 EC 公钥算法参数中）→ UnsupportedAlgorithm
        import re
        m = re.search(r'1\.2\.156\.10197\.1\.\d+', str(e))
        if m and m.group(0) == SM2_KEY_OID:
            return _sm2_pubkey_info(cert)
        try:
            if _spki_curve_is_sm2(cert):
                return _sm2_pubkey_info(cert)
        except Exception:
            pass
        raise
    if isinstance(pk, rsa.RSAPublicKey):
        nu = pk.public_numbers()
        return "RSA %d 位" % pk.key_size, "指数 e = 0x%x" % nu.e
    if isinstance(pk, ec.EllipticCurvePublicKey):
        return "EC %s" % pk.curve.name, "曲线 %s（参数 OID %s）" % (pk.curve.name,
                                                                pk.curve.oid.dotted_string if hasattr(pk.curve, 'oid') else '')
    if isinstance(pk, dsa.DSAPublicKey):
        return "DSA %d 位" % pk.key_size, ""
    if isinstance(pk, ed25519.Ed25519PublicKey):
        return "Ed25519", ""
    if isinstance(pk, ed448.Ed448PublicKey):
        return "Ed448", ""
    return type(pk).__name__, ""


def _name_str(name: x509.Name) -> str:
    try:
        return name.rfc4514_string()
    except Exception:
        return str(name)


def _fmt_time(dt) -> str:
    if dt is None:
        return ''
    try:
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return str(dt)


def _fingerprint(cert: x509.Certificate, algo: str) -> str:
    if algo == "SHA1":
        h = cert.fingerprint(hashes.SHA1())
    else:
        h = cert.fingerprint(hashes.SHA256())
    return ':'.join('%02X' % b for b in h)


def _oid_name(oid) -> str:
    try:
        if oid._name:
            return oid._name
    except Exception:
        pass
    try:
        return oid.dotted_string
    except Exception:
        return str(oid)


def _extensions(cert: x509.Certificate) -> OrderedDict:
    exts = OrderedDict()
    try:
        bc = cert.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
        v = bc.value
        etype = 'Subject Type = CA' if v.ca else 'Subject Type = End Entity'
        desc = 'CA = %s（%s）' % ('True' if v.ca else 'False', etype)
        desc += '，Path Length Constraint = %s' % (str(v.path_length) if v.path_length is not None else 'None')
        exts['基本约束 BasicConstraints'] = desc
    except x509.ExtensionNotFound:
        pass
    try:
        ku = cert.extensions.get_extension_for_oid(ExtensionOID.KEY_USAGE)
        v = ku.value
        raw = []
        mapping = {
            'digital_signature': '数字签名', 'content_commitment': '不可否认性',
            'key_encipherment': '密钥加密', 'data_encipherment': '数据加密',
            'key_agreement': '密钥协商', 'key_cert_sign': '证书签名',
            'crl_sign': 'CRL签名', 'encipher_only': '仅加密', 'decipher_only': '仅解密',
        }
        for attr, zh in mapping.items():
            try:
                if getattr(v, attr):
                    raw.append(zh)
            except Exception:
                pass
        exts['密钥用途 KeyUsage'] = ', '.join(raw) if raw else '无'
    except x509.ExtensionNotFound:
        pass
    try:
        eku = cert.extensions.get_extension_for_oid(ExtensionOID.EXTENDED_KEY_USAGE)
        names = [_oid_name(o) for o in eku.value]
        exts['扩展密钥用途 EKU'] = ', '.join(names)
    except x509.ExtensionNotFound:
        pass
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        exts['主体备用名 SAN'] = ', '.join(str(e.value) for e in san.value)
    except x509.ExtensionNotFound:
        pass
    try:
        ski = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_KEY_IDENTIFIER)
        sv = ski.value
        if hasattr(sv, 'digest'):
            sv = sv.digest
        if isinstance(sv, (bytes, bytearray)):
            exts['主体密钥标识 SKI'] = ' '.join('%02X' % b for b in sv)
    except x509.ExtensionNotFound:
        pass
    except Exception:
        pass
    try:
        aki = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_KEY_IDENTIFIER)
        v = aki.value
        if v.key_identifier:
            exts['颁发者密钥标识 AKI'] = ' '.join('%02X' % b for b in v.key_identifier)
    except x509.ExtensionNotFound:
        pass
    try:
        crldp = cert.extensions.get_extension_for_oid(ExtensionOID.CRL_DISTRIBUTION_POINTS)
        if crldp.value and crldp.value[0].full_name:
            exts['CRL 分发点'] = crldp.value[0].full_name[0].value
    except x509.ExtensionNotFound:
        pass
    try:
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        out = []
        for a in aia.value:
            out.append('%s: %s' % (_oid_name(a.access_method), a.access_location.value))
        exts['授权信息访问 AIA'] = ', '.join(out)
    except x509.ExtensionNotFound:
        pass
    return exts


def analyze_cert(text: str = None, path: str = None) -> OrderedDict:
    """分析证书，返回有序字段字典 {label: value}"""
    cert = _load_cert(text, path)

    fields = OrderedDict()
    try:
        fields['版本 Version'] = cert.version.name
    except Exception:
        fields['版本 Version'] = str(cert.version)

    serial = int(cert.serial_number)
    fields['序列号 SerialNumber'] = '%X' % serial if serial != 0 else '0'

    try:
        sig_oid = cert.signature_algorithm_oid
        if sig_oid.dotted_string == SM2_SIG_OID:
            fields['签名算法'] = 'SM3withSM2（OID %s）' % SM2_SIG_OID
        else:
            fields['签名算法'] = '%s（OID %s）' % (_oid_name(sig_oid), sig_oid.dotted_string)
    except Exception:
        fields['签名算法'] = '未知'

    try:
        pub_oid = cert.public_key_algorithm_oid.dotted_string
        if pub_oid == SM2_KEY_OID or _spki_curve_is_sm2(cert):
            fields['公钥算法'] = 'SM2 国密'
    except Exception:
        pass

    fields['签发者 Issuer'] = _name_str(cert.issuer)
    fields['主体 Subject'] = _name_str(cert.subject)

    fields['有效期从 notBefore'] = _fmt_time(cert.not_valid_before_utc if hasattr(cert, 'not_valid_before_utc') else cert.not_valid_before)
    fields['有效期至 notAfter'] = _fmt_time(cert.not_valid_after_utc if hasattr(cert, 'not_valid_after_utc') else cert.not_valid_after)

    pk_label, pk_detail = _pubkey_info(cert)
    fields['公钥算法'] = pk_label
    if pk_detail:
        fields['公钥参数'] = pk_detail

    try:
        sig_block = cert.signature
        fields['签名值(前32字节)'] = ' '.join('%02X' % b for b in sig_block[:32]) + (' ...（共 %d 字节）' % len(sig_block) if len(sig_block) > 32 else '')
    except Exception:
        pass

    # 完整签名值（HEX 原文），供核对
    try:
        sig_block = cert.signature
        fields['签名值 HEX'] = sig_block.hex().upper()
    except Exception:
        pass

    fields['指纹 SHA1'] = _fingerprint(cert, 'SHA1')
    fields['指纹 SHA256'] = _fingerprint(cert, 'SHA256')
    fields['是否自签名'] = '是' if _name_str(cert.issuer) == _name_str(cert.subject) else '否'

    for k, v in _extensions(cert).items():
        if v:
            fields[k] = v

    return fields
