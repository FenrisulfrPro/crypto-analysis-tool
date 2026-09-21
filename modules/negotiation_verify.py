# -*- coding: utf-8 -*-
"""密钥协商过程的签名验签（TLS 1.2 / TLCP / TLS 1.3 / SSH 可验证性判定）。

CSSH 的验签在 ``cssh_parser`` 中完成（M = random-client ∥ random-server）。
本模块补齐其余协议，并把结论统一注入消息 ``fields``（供时序图 / 协商总结渲染）：

    验签结果      通过 / 失败 / 不可用
    验签详情      文字说明（签名数据构造、所用证书、异常原因）
    签名算法      如 RSA-PSS-SHA256 / SM2 with SM3
    签名证书      验签所用证书主体
    被签名证书    被签入待签名数据的证书（TLCP：加密证书）
    待签名数据    构造说明（含字节数）
    签名公钥      验签公钥摘要（可读文本）

各协议签名数据构造（依据规范/实测抓包）：

* TLS 1.2（RFC 5246 §7.4.3）::

      signed = client_random ∥ server_random ∥ ServerKeyExchange.params

  支持 RSA-PKCS1 / RSA-PSS / ECDSA / Ed25519（cryptography 验签）。

* TLCP（GB/T 38636 §6.4.5.4，实测抓包确认）::

      signed = client_random ∥ server_random ∥ ASN.1Cert（3 字节长度 + 证书）

  验签用链中「签名证书」公钥（keyUsage 含 digitalSignature），
  被签入的是「加密证书」（keyUsage 含 keyEncipherment / dataEncipherment），
  签名算法为 SM2-with-SM3（用户标识 "1234567812345678"）。

* TLS 1.3：CertificateVerify 位于加密记录中、且依赖完整握手转录哈希，
  被动抓包无法重算 → 结论「不可用」并说明原因。

* SSH（RFC 4253 §8）：服务端签名覆盖交换哈希
  ``H = HASH(V_C ∥ V_S ∥ I_C ∥ I_S ∥ K_S ∥ e ∥ f ∥ K)``，
  其中 K 为 DH 共享密钥、不在报文中 → 被动抓包无法验证；
  可展示主机密钥类型与 SHA256 指纹（TOFU 比对用）。
"""

_PASS = "通过"
_FAIL = "失败"
_NA = "不可用"

SCHEME_RSA_PSS = {
    0x0804: "sha256", 0x0805: "sha384", 0x0806: "sha512",
    0x0809: "sha256", 0x080a: "sha384", 0x080b: "sha512",
}
SCHEME_RSA_PKCS1 = {0x0201: "sha1", 0x0401: "sha256", 0x0501: "sha384", 0x0601: "sha512"}
SCHEME_ECDSA = {0x0203: "sha1", 0x0403: "sha256", 0x0503: "sha384", 0x0603: "sha512"}
SCHEME_ED = {0x0807: "ed25519", 0x0808: "ed448"}

_SCHEME_NAMES = {
    0x0201: "RSA-PKCS1-SHA1", 0x0401: "RSA-PKCS1-SHA256",
    0x0501: "RSA-PKCS1-SHA384", 0x0601: "RSA-PKCS1-SHA512",
    0x0804: "RSA-PSS-PSS-SHA256", 0x0805: "RSA-PSS-PSS-SHA384", 0x0806: "RSA-PSS-PSS-SHA512",
    0x0809: "RSA-PSS-RSAE-SHA256", 0x080a: "RSA-PSS-RSAE-SHA384", 0x080b: "RSA-PSS-RSAE-SHA512",
    0x0203: "ECDSA-SHA1", 0x0403: "ECDSA-SECP256R1-SHA256",
    0x0503: "ECDSA-SECP384R1-SHA384", 0x0603: "ECDSA-SECP521R1-SHA512",
    0x0807: "Ed25519", 0x0808: "Ed448",
}

_TLCP_UID = "1234567812345678"
_EMBED_PREFIX = "ASN.1Cert（3 字节长度前缀）"


def wrap_hex(hex_str, width: int = 64, sep: str = "<br>") -> str:
    """把长 HEX 字符串按固定字符数折行，避免在 QLabel/QTextBrowser 中横向溢出。

    协商总结要求「数据不省略、全部展示」，长签名数据统一用本函数折行展示。"""
    s = str(hex_str or "")
    if not s:
        return ""
    return sep.join(s[i:i + width] for i in range(0, len(s), width))


# ---------------------------------------------------------------- 通用小工具（避免与 tls_parser 循环依赖）

def _ber_tlv(data, off):
    tag = data[off]
    off += 1
    ln = data[off]
    off += 1
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(data[off:off + n], "big")
        off += n
    return tag, data[off:off + ln], off + ln


def _sm2_point(der):
    """从证书 DER 提取 SM2 公钥点 → '04‖X‖Y' HEX（65 字节）。"""
    try:
        _, body, _ = _ber_tlv(der, 0)
        _, tbs, _ = _ber_tlv(body, 0)
        tg, _, off = _ber_tlv(tbs, 0)
        if tg == 0xA0:
            _, _, off = _ber_tlv(tbs, off)
        cnt, spki = 0, None
        while off < len(tbs):
            tg, val, off = _ber_tlv(tbs, off)
            if tg == 0x30:
                cnt += 1
                if cnt >= 5:
                    spki = val
                    break
        if spki is None:
            return None
        _, _, o2 = _ber_tlv(spki, 0)
        _, bitstr, _ = _ber_tlv(spki, o2)
        raw = bitstr[1:]
        if raw[:1] == b"\x04" and len(raw) == 65:
            return raw.hex()
    except Exception:
        return None
    return None


def _der_rs(sig_der):
    """DER 签名 (30 .. r .. s ..) → 64 字节 raw r‖s。"""
    try:
        if not sig_der or sig_der[0] != 0x30:
            return None
        o = 1
        ln = sig_der[o]
        o += 1
        if ln & 0x80:
            n = ln & 0x7F
            o += n
        if sig_der[o] != 0x02:
            return None
        rl = sig_der[o + 1]
        r = int.from_bytes(sig_der[o + 2:o + 2 + rl], "big")
        o = o + 2 + rl
        if sig_der[o] != 0x02:
            return None
        sl = sig_der[o + 1]
        s = int.from_bytes(sig_der[o + 2:o + 2 + sl], "big")
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
    except Exception:
        return None


def _sm2_verify(sig_der, message, pub_hex):
    """SM2-with-SM3 验签（默认用户标识）。返回 (ok|None, detail)。"""
    try:
        from gmssl.sm2 import CryptSM2, default_ecc_table
    except Exception:
        return None, "未安装 gmssl 库，无法验签（pip install gmssl）"
    raw = _der_rs(sig_der)
    if not raw:
        return None, "签名值不是 DER 编码的 (r,s)"
    if not pub_hex:
        return None, "未能从证书提取 SM2 公钥点"
    try:
        sm2 = CryptSM2(private_key=None, public_key=pub_hex, ecc_table=default_ecc_table)
        ok = bool(sm2.verify_with_sm3(raw.hex(), message))
        return ok, ("SM2 验签通过" if ok else "SM2 验签失败")
    except Exception as e:
        return None, "验签异常：%s" % e


def _rsa_ecdsa_verify(der, scheme, signed, sig):
    """用证书公钥验证 TLS 数字签名。返回 (ok|None, detail)。"""
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding
    except Exception:
        return None, "未安装 cryptography，无法验签"
    name = _SCHEME_NAMES.get(scheme, "0x%04X" % scheme)
    try:
        pub = x509.load_der_x509_certificate(der).public_key()
    except Exception as e:
        return None, "证书公钥解析失败：%s" % e
    hmap = {"sha1": hashes.SHA1(), "sha256": hashes.SHA256(),
            "sha384": hashes.SHA384(), "sha512": hashes.SHA512()}
    try:
        if scheme in SCHEME_RSA_PSS:
            h = hmap[SCHEME_RSA_PSS[scheme]]
            pub.verify(sig, signed, padding.PSS(mgf=padding.MGF1(h),
                                                salt_length=h.digest_size), h)
            return True, "%s 验签通过" % name
        if scheme in SCHEME_RSA_PKCS1:
            h = hmap[SCHEME_RSA_PKCS1[scheme]]
            pub.verify(sig, signed, padding.PKCS1v15(), h)
            return True, "%s 验签通过" % name
        if scheme in SCHEME_ECDSA:
            h = hmap[SCHEME_ECDSA[scheme]]
            pub.verify(sig, signed, ec.ECDSA(h))
            return True, "%s 验签通过" % name
        if scheme in SCHEME_ED:
            if SCHEME_ED[scheme] == "ed25519":
                pub.verify(sig, signed)
            else:
                pub.verify(sig, signed)
            return True, "%s 验签通过" % name
    except Exception as e:
        return False, "%s 验签失败：%s" % (name, e)
    return None, "暂不支持的签名方案 %s" % name


# ---------------------------------------------------------------- 消息字段读取

def _fd(msg):
    fd = msg.get("fields")
    if isinstance(fd, dict):
        return fd
    return dict(fd or [])


def _title(msg):
    return msg.get("title") or msg.get("type") or ""


def _raw(msg, key, default=None):
    return (msg.get("_raw") or {}).get(key, default)


def _certs(fd):
    """返回 [(序号, DER, keyUsage 文本), …]（序号从 1 起）。"""
    out = []
    for i in range(1, 64):
        der_hex = fd.get("cert%d_der_hex" % i)
        if not der_hex:
            break
        try:
            der = bytes.fromhex(der_hex)
        except Exception:
            continue
        out.append((i, der, str(fd.get("cert%d_key_usage" % i) or "")))
    return out


def _set(msg, **kw):
    fd = msg.get("fields")
    if isinstance(fd, dict):
        fd.update(kw)
    else:
        fd = dict(fd or [])
        fd.update(kw)
        msg["fields"] = fd


# ---------------------------------------------------------------- TLS 1.2 / TLCP

def _verify_tls_ske(msg, fd, cr, sr, cert_fd):
    """TLS 1.2 ServerKeyExchange 数字签名（RSA / ECDSA / Ed25519）。"""
    params = _raw(msg, "params")
    sig = _raw(msg, "sig")
    scheme = _raw(msg, "scheme", 0)
    if not (cr and sr and params is not None and sig):
        _set(msg, 验签结果=_NA, 验签详情="缺少 client_random / server_random / 签名参数，无法验签")
        return
    signed = cr + sr + params
    certs = _certs(cert_fd)
    if not certs:
        _set(msg, 验签结果=_NA, 验签详情="未捕获到服务端证书，无法提取验签公钥")
        return
    last = "验签失败"
    for idx, der, _ku in certs:
        ok, detail = _rsa_ecdsa_verify(der, scheme, signed, sig)
        if ok is True:
            _set(msg,
                 验签结果=_PASS,
                 验签详情="%s；待签名数据 = client_random ∥ server_random ∥ ServerKeyExchange.params"
                          "（%d 字节），使用服务端证书链第 %d 张公钥"
                          % (detail, len(signed), idx),
                 签名算法=_SCHEME_NAMES.get(scheme, "0x%04X" % scheme),
                 签名证书=cert_fd.get("cert%d_subject" % idx, ""),
                 待签名数据="client_random(32) ∥ server_random(32) ∥ params(%d) = %d 字节"
                            % (len(params), len(signed)),
                 待签名数据HEX=signed.hex(),
                 签名值=sig.hex(),
                 签名公钥=str(cert_fd.get("cert%d_pubkey" % idx) or ""))
            return
        if detail:
            last = detail
    _set(msg, 验签结果=_FAIL, 验签详情=last,
         签名算法=_SCHEME_NAMES.get(scheme, "0x%04X" % scheme),
         待签名数据="client_random(32) ∥ server_random(32) ∥ params(%d) = %d 字节"
                    % (len(params), len(signed)),
         待签名数据HEX=signed.hex(),
         签名值=sig.hex())


def _verify_tlcp_ske(msg, fd, cr, sr, cert_fd):
    """TLCP ServerKeyExchange SM2 签名（GB/T 38636 §6.4.5.4）。"""
    sig = _raw(msg, "sig")
    if not (cr and sr and sig):
        _set(msg, 验签结果=_NA,
             验签详情="缺少 client_random / server_random / SM2 签名，无法验签",
             签名值=(sig.hex() if sig else ""))
        return
    certs = _certs(cert_fd)
    if not certs:
        _set(msg, 验签结果=_NA, 验签详情="未捕获到服务端证书，无法提取 SM2 公钥")
        return

    def _order(pred):
        hit = [c for c in certs if pred(c[2])]
        return hit + [c for c in certs if c not in hit]

    key_order = _order(lambda ku: "digitalSignature" in ku or "数字签名" in ku)
    embed_order = _order(lambda ku: "keyEncipherment" in ku or "dataEncipherment" in ku
                         or "加密" in ku)
    for ki, kder, _kku in key_order:
        pub = _sm2_point(kder)
        if not pub:
            continue
        for ei, eder, _eku in embed_order:
            signed = cr + sr + len(eder).to_bytes(3, "big") + eder
            ok, detail = _sm2_verify(sig, signed, pub)
            if ok is True:
                _set(msg,
                     验签结果=_PASS,
                     验签详情="%s；待签名数据 = client_random ∥ server_random ∥ %s"
                              "（GB/T 38636 §6.4.5.4），验签证书为链第 %d 张，"
                              "被签入的加密证书为链第 %d 张"
                              % (detail, _EMBED_PREFIX, ki, ei),
                     签名算法="SM2 with SM3（用户标识 %s）" % _TLCP_UID,
                     签名证书=cert_fd.get("cert%d_subject" % ki, ""),
                     被签名证书=cert_fd.get("cert%d_subject" % ei, ""),
                     待签名数据="client_random(32) ∥ server_random(32) ∥ ASN.1Cert(%d) = %d 字节"
                                % (len(eder), len(signed)),
                     待签名数据HEX=signed.hex(),
                     签名值=sig.hex(),
                     签名公钥="SM2 公钥点（完整，%d 字节）%s" % (len(pub) // 2, pub))
                return
    _set(msg, 验签结果=_FAIL, 签名值=sig.hex(),
         验签详情="未找到与签名匹配的组合（已尝试链中每张证书作为验签公钥，"
                  "并尝试把链中每张证书作为被签入的 ASN.1Cert）",
         签名算法="SM2 with SM3（用户标识 %s）" % _TLCP_UID,
         待签名数据="client_random(32) ∥ server_random(32) ∥ ASN.1Cert（加密证书）")


def _try_client_cv(msg, fd, cr, sr, cert_fd, tlcp=False):
    """客户端 CertificateVerify：TLCP 按 GB/T 38636 同款构造尝试；其余按素材展示。"""
    sig = _raw(msg, "sig")
    if not (sig and cr and sr):
        _set(msg, 验签结果=_NA, 验签详情="缺少 client_random / server_random / 签名值，无法验签")
        return
    certs = _certs(cert_fd)
    if not certs:
        _set(msg, 验签结果=_NA, 验签详情="客户端未出示自身证书，无法获取验签公钥")
        return
    if not tlcp:
        _set(msg, 验签结果=_NA,
             验签详情="客户端 CertificateVerify 覆盖完整握手转录哈希，"
                      "当前按签名素材展示（转录重算见后续版本）")
        return
    key_order = [c for c in certs if "digitalSignature" in c[2] or "数字签名" in c[2]] or certs
    for ki, kder, _kku in key_order:
        pub = _sm2_point(kder)
        if not pub:
            continue
        for ei, eder, _eku in certs:
            signed = cr + sr + len(eder).to_bytes(3, "big") + eder
            ok, detail = _sm2_verify(sig, signed, pub)
            if ok is True:
                _set(msg,
                     验签结果=_PASS,
                     验签详情="%s；待签名数据 = client_random ∥ server_random ∥ %s，"
                              "验签证书为客户端链第 %d 张，被签入证书为链第 %d 张"
                              % (detail, _EMBED_PREFIX, ki, ei),
                     签名算法="SM2 with SM3（用户标识 %s）" % _TLCP_UID,
                     签名证书=cert_fd.get("cert%d_subject" % ki, ""),
                     被签名证书=cert_fd.get("cert%d_subject" % ei, ""),
                     待签名数据="client_random(32) ∥ server_random(32) ∥ ASN.1Cert(%d) = %d 字节"
                                % (len(eder), len(signed)),
                     待签名数据HEX=signed.hex(),
                     签名值=sig.hex(),
                     签名公钥="SM2 公钥点（完整，%d 字节）%s" % (len(pub) // 2, pub))
                return
    _set(msg, 验签结果=_NA, 签名值=sig.hex(),
         验签详情="客户端 CertificateVerify 签名数据构造未匹配（已尝试 cr∥sr∥ASN.1Cert 组合），"
                  "仅展示签名素材")


def _attach_tls_like(messages, proto):
    """TLS / TLCP：把验签素材与结论挂到消息上。"""
    ch = next((m for m in messages if _title(m) == "ClientHello"), None)
    sh = next((m for m in messages if _title(m) == "ServerHello"), None)
    cr = _raw(ch, "random") if ch else None
    sr = _raw(sh, "random") if sh else None
    sdir = sh.get("dir") if sh else None
    cdir = ch.get("dir") if ch else None
    scert = next((m for m in messages
                  if _title(m) == "Certificate" and m.get("dir") == sdir), None)
    ccert = next((m for m in messages
                  if _title(m) == "Certificate" and m.get("dir") == cdir), None)
    sfd = _fd(scert) if scert else {}
    cfd = _fd(ccert) if ccert else {}
    for m in messages:
        if _title(m) == "ServerKeyExchange":
            if proto == "TLCP":
                _verify_tlcp_ske(m, _fd(m), cr, sr, sfd)
            else:
                _verify_tls_ske(m, _fd(m), cr, sr, sfd)
        elif _title(m) == "CertificateVerify":
            if m.get("dir") == cdir:
                _try_client_cv(m, _fd(m), cr, sr, cfd, tlcp=(proto == "TLCP"))


def _tls13_reason(messages, proto):
    """无 ServerKeyExchange 时的原因说明（TLS 1.3 / RSA 密钥交换）。"""
    if proto == "TLCP":
        return "未捕获到 ServerKeyExchange，无法进行服务端签名验证"
    sh = next((m for m in messages if _title(m) == "ServerHello"), None)
    fd = _fd(sh) if sh else {}
    vers = str(fd.get("ext_supported_versions") or "")
    if "1.3" in vers:
        return ("TLS 1.3 的 CertificateVerify 位于加密握手记录中，"
                "且签名覆盖完整握手转录哈希，被动抓包无法重算")
    if fd:
        return "该密码套件无 ServerKeyExchange 签名（如 RSA 密钥交换），服务端身份仅由证书承载"
    return "未捕获到密钥协商消息"


# ---------------------------------------------------------------- 入口

def attach_flow_verify(messages, proto):
    """对一条流的所有消息执行验签并注入结论（就地修改）。"""
    if not messages:
        return
    try:
        if proto in ("TLS", "TLCP"):
            _attach_tls_like(messages, proto)
            # 没有任何 ServerKeyExchange 时，把原因挂到 ServerHello 上供总结展示
            has_ske = any(_title(m) == "ServerKeyExchange" for m in messages)
            if not has_ske:
                sh = next((m for m in messages if _title(m) == "ServerHello"), None)
                if sh is not None:
                    _set(sh, 验签结果=_NA, 验签详情=_tls13_reason(messages, proto))
            else:
                for m in messages:
                    if _title(m) == "ServerKeyExchange":
                        fd = _fd(m)
                        if not fd.get("验签结果"):
                            _set(m, 验签结果=_NA,
                                 验签详情="该 ServerKeyExchange 未提供可验证的签名参数")
    except Exception as e:  # 验签失败不应影响解析
        for m in messages:
            if _title(m) in ("ServerKeyExchange", "CertificateVerify", "ServerHello"):
                _set(m, 验签结果=_NA, 验签详情="验签过程异常：%s" % e)


def strip_raw(messages):
    """移除仅用于验签的原始字节（不进入界面展示）。"""
    for m in messages:
        m.pop("_raw", None)
