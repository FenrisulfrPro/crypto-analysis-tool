# -*- coding: utf-8 -*-
"""CSSH（GM/T 0129-2023 国密 SSH 协议）解析模块。

Wireshark 等工具无法识别 CSSH（只能看到 TCP），本模块直接深入 TCP
负载字节流检索并重组 CSSH 会话：

* 按 "CSSH-1.0-" 版本前缀定位会话；
* 按 RFC 4253 传输层分帧（packet_length / padding_length / payload / padding）
  重组每个方向的握手报文；
* 解析国密扩展消息：KEX_REQUEST(200)、KEX_REPLY(201)、KEX(202)；
* 从 KEX_REPLY 中提取双证书（签名证书 || 加密证书）、random-server 与 SM2 签名；
* 还原 SKE 验签：M = random-client || random-server，用签名证书公钥做 SM2 验签
  （默认用户标识 "1234567812345678"，签名按 GB/T 35276 DER 编码）。
"""

import re
import struct
from html import escape

from . import tls_parser as _tl

# ------------------------------------------------------------- 常量

CSSH_VERSION_PREFIX = b"CSSH-1.0"
_MSG_NAMES = {
    20: "KEXINIT（协商初始化）",
    21: "NEWKEYS（新密钥生效）",
    200: "KEX_REQUEST（密钥协商请求）",
    201: "KEX_REPLY（密钥协商应答）",
    202: "KEX（密钥协商-加密主密钥）",
    1: "DISCONNECT（断开连接）",
    5: "SERVICE_REQUEST（服务请求）",
    6: "SERVICE_ACCEPT（服务同意）",
    50: "USERAUTH_REQUEST（用户鉴别请求）",
    51: "USERAUTH_FAILURE（鉴别失败）",
    52: "USERAUTH_SUCCESS（鉴别成功）",
    53: "USERAUTH_BANNER（横幅）",
    56: "USERAUTH_PK_OK（公钥确认）",
    210: "USERAUTH_CHALLENGE（鉴别挑战）",
    211: "USERAUTH_RESPOND（鉴别响应）",
}
_KEXINIT_NAMES = (
    "密钥交换算法", "服务端主机密钥算法",
    "加密算法(客户端→服务端)", "加密算法(服务端→客户端)",
    "MAC 算法(客户端→服务端)", "MAC 算法(服务端→客户端)",
    "压缩算法(客户端→服务端)", "压缩算法(服务端→客户端)",
    "语言(客户端→服务端)", "语言(服务端→客户端)",
)
MAX_PACKET_LEN = 1 << 20  # 1MB，超限视为进入加密阶段

# ------------------------------------------------------------- 国密算法高亮

# 命中即视为国密算法：SM2/SM3/SM4 系列（含曲线 curvesm2）、CBC-MAC、国密 HMAC(SM3)
_GM_RE = re.compile(
    r"(?i)\bsm2\b|\bsm3\b|\bsm4\b|curvesm2|hmac-sm3|cbc-mac")


def is_gm_algo(name):
    """该协商算法名是否为国密算法（用于协商算法列表中只高亮国密项）。"""
    n = str(name or "").strip()
    if not n:
        return False
    if _GM_RE.search(n):
        return True
    return n.upper() in ("CBC-MAC", "HMAC")


def highlight_algs(text):
    """把逗号分隔的算法列表渲染成 HTML：只对国密算法加高亮徽标，其余保持普通文本。"""
    items = [x.strip() for x in str(text or "").split(",") if x.strip()]
    parts = []
    for it in items:
        if is_gm_algo(it):
            parts.append("<span style='background:#DCFCE7;color:#166534;border-radius:3px;"
                         "padding:0 4px;font-weight:bold'>%s</span>" % escape(it))
        else:
            parts.append(escape(it))
    return ",".join(parts)

# ------------------------------------------------------------- TCP 流重组


def _flow_stream(pkts, sip, sport, dip, dport):
    """同 _flow_payloads，但保留每段的真实包号，返回 (合并字节流, [(包号, 分段字节)])。"""
    parts = []
    for i, pkt in enumerate(pkts):
        try:
            if (pkt.haslayer("TCP") and pkt["IP"].src == sip
                    and pkt["TCP"].sport == sport and pkt["IP"].dst == dip
                    and pkt["TCP"].dport == dport):
                parts.append((int(pkt["TCP"].seq), bytes(pkt["TCP"].payload), i + 1))
        except Exception:
            continue
    if not parts:
        return b"", []
    parts.sort()
    merged = []
    i = 0
    while i < len(parts):
        seq, b, no = parts[i]
        j = i
        best, best_no = b, no
        while j + 1 < len(parts) and parts[j + 1][0] == seq:
            j += 1
            if len(parts[j][1]) > len(best):
                best, best_no = parts[j][1], parts[j][2]
        merged.append((best_no, best))
        i = j + 1
    return b"".join(b for _, b in merged), merged


def _pkt_no_at(merged, byte_off):
    """字节偏移 → 该偏移所在 TCP 段的真实包号。"""
    acc = 0
    for no, seg in merged:
        if byte_off < acc + len(seg):
            return no
        acc += len(seg)
    return None


def _flow_payloads(pkts, sip, sport, dip, dport):
    """收集一个方向的 TCP 载荷并按序拼接。

    注意：抓包中同一 seq 可能先出现空 ACK 包后出现数据包（scapy 视图下的
    分段表现），因此按 seq 分组时取载荷最长的那段，避免把版本串 / KEXINIT
    误当重传丢弃。
    """
    parts = []
    for pkt in pkts:
        try:
            if (pkt.haslayer("TCP") and pkt["IP"].src == sip
                    and pkt["TCP"].sport == sport and pkt["IP"].dst == dip
                    and pkt["TCP"].dport == dport):
                parts.append((int(pkt["TCP"].seq), bytes(pkt["TCP"].payload)))
        except Exception:
            continue
    if not parts:
        return b""
    parts.sort()
    out = []
    i = 0
    while i < len(parts):
        seq, b = parts[i]
        j = i
        best = b
        while j + 1 < len(parts) and parts[j + 1][0] == seq:
            j += 1
            if len(parts[j][1]) > len(best):
                best = parts[j][1]
        out.append(best)
        i = j + 1
    return b"".join(out)


def _flow_packet_nos(pkts, sip, sport, dip, dport):
    nos = []
    for i, pkt in enumerate(pkts):
        try:
            if (pkt.haslayer("TCP") and pkt["IP"].src == sip
                    and pkt["TCP"].sport == sport and pkt["IP"].dst == dip
                    and pkt["TCP"].dport == dport):
                nos.append(i + 1)
        except Exception:
            continue
    return nos


def _split_version(data):
    """返回 (version_line, 数据起点)。version 以 CRLF 或 LF 结尾。"""
    nl = data.find(b"\n")
    if nl < 0:
        return data, 0
    return data[:nl].rstrip(b"\r"), nl + 1


def _records(data):
    """按传输层分帧切出 [(type, payload_bytes, msg_no)]，无法继续时停止。"""
    out = []
    o = 0
    while o + 5 <= len(data):
        plen = struct.unpack(">I", data[o:o + 4])[0]
        if plen < 4 or plen > MAX_PACKET_LEN:
            break
        if o + 4 + plen > len(data):
            break
        pdl = data[o + 4]
        if pdl > 255 or plen - 1 - pdl < 0:
            break
        payload = data[o + 5:o + 5 + plen - 1 - pdl]
        out.append(payload)
        o += 4 + plen
    return out, o


def _rd_byte(p, o):
    return p[o], o + 1


def _rd_string(p, o):
    n = struct.unpack(">I", p[o:o + 4])[0]
    o += 4
    return p[o:o + n], o + n


# ------------------------------------------------------------- 握手消息解析


def _parse_kexinit(payload):
    """SSH_MSG_KEXINIT(20): cookie + 10 个 name/串 + first_kex + reserved。"""
    fields = []
    cookie, o = _rd_string(b"\x00\x00\x00\x10" + payload[1:17], 0)
    fields.append(("Cookie 随机数", cookie.hex()))
    o = 17
    for name in _KEXINIT_NAMES:
        s, o = _rd_string(payload, o)
        fields.append((name, s.decode("utf-8", "replace") or "(空)"))
    if o + 5 <= len(payload):
        fk = payload[o]
        fields.append(("first_kex_packet_follows", "是" if fk else "否"))
    return fields


def _parse_kex_request(payload):
    """KEX_REQUEST(200): string random-client(8字节)。"""
    rc, o = _rd_string(payload, 1)
    return [("random-client", rc.hex()), ("random-client 长度", "%d 字节" % len(rc))]


def _parse_kex_reply(payload, session):
    """KEX_REPLY(201): string 签名证书, string 加密证书, string random-server, string sign。"""
    fields = []
    sign_der, o = _rd_string(payload, 1)
    enc_der, o = _rd_string(payload, o)
    rs, o = _rd_string(payload, o)
    sig, o = _rd_string(payload, o)
    fields.append(("签名证书 DER", "%d 字节（%s）" % (len(sign_der), "有效" if sign_der[:1] == b"\x30" else "异常")))
    fields.append(("加密证书 DER", "%d 字节（%s）" % (len(enc_der), "有效" if enc_der[:1] == b"\x30" else "异常")))
    fields.append(("random-server", rs.hex() if len(rs) >= 8 else rs.hex()))
    fields.append(("签名值 (DER)", sig.hex()))
    session["reply"] = {
        "sign_der": sign_der, "enc_der": enc_der, "random_server": rs, "sign": sig,
    }
    return fields


def _parse_kex(payload):
    """KEX(202): string enc(K)（SM2 公钥加密的 32 字节主密钥）。"""
    enc, o = _rd_string(payload, 1)
    info = "SM2 密文，%d 字节" % len(enc)
    if len(enc) >= 66 and enc[0] == 0x04:
        info += "（C1=65 字节未压缩点 + C3=32 字节 SM3 + C2=%d 字节密文）" % (len(enc) - 97)
    return [("enc(K)（SM2 加密主密钥）", enc.hex()), ("enc(K) 说明", info)]


# ------------------------------------------------------------- 会话汇总


def _cert_parse(der):
    try:
        return _tl._parse_der_cert(der) or {}
    except Exception:
        return {"error": "证书解析失败"}


def _pubkey_point_hex(der):
    """从证书 DER 提取 SM2 公钥点 → '04||X||Y' HEX（65 字节）。"""
    try:
        _, body, _ = _tl._ber_tlv(der, 0)
        _, tbs, off = _tl._ber_tlv(body, 0)
        _, _, off = _tl._ber_tlv(tbs, 0)          # version [0]（或 serial）
        if tbs[0] == 0xA0:
            _, _, off = _tl._ber_tlv(tbs, off)    # serial
        cnt = 0
        spki = None
        while off < len(tbs):
            tg, val, off = _tl._ber_tlv(tbs, off)
            if tg == 0x30:
                cnt += 1
                if cnt >= 5:   # sig,issuer,validity,subject,spki
                    spki = val
                    break
        if spki is None:
            return None
        _, _, o2 = _tl._ber_tlv(spki, 0)
        _, bitstr, _ = _tl._ber_tlv(spki, o2)
        raw = bitstr[1:]
        if raw[:1] == b"\x04" and len(raw) == 65:
            return raw.hex()
        return None
    except Exception:
        return None


def _derive_sign_raw(sig_der):
    """GB/T 35276 DER 签名 (30 .. r .. s ..) → 64 字节 raw r||s。"""
    try:
        if not sig_der or sig_der[0] != 0x30:
            return None
        o = 2
        assert sig_der[o] == 0x02
        rl = sig_der[o + 1]
        r = int.from_bytes(sig_der[o + 2:o + 2 + rl], "big")
        o = o + 2 + rl
        assert sig_der[o] == 0x02
        sl = sig_der[o + 1]
        s = int.from_bytes(sig_der[o + 2:o + 2 + sl], "big")
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
    except Exception:
        return None


def _sm2_verify(sign_der, message, pubkey_hex):
    """SM2 验签（默认用户标识 1234567812345678）。返回 (ok, detail)。"""
    try:
        from gmssl.sm2 import CryptSM2, default_ecc_table
    except Exception:
        return None, "未安装 gmssl 库，无法验签（pip install gmssl）"
    raw = _derive_sign_raw(sign_der)
    if not raw:
        return None, "签名值不是 DER 编码（r,s）"
    if not pubkey_hex:
        return None, "未能从签名证书提取 SM2 公钥点"
    try:
        sm2 = CryptSM2(private_key=None, public_key=pubkey_hex,
                       ecc_table=default_ecc_table)
        ok = sm2.verify_with_sm3(raw.hex(), message)
        return bool(ok), "通过" if ok else "失败"
    except Exception as e:
        return None, "验签异常：%s" % e


# ------------------------------------------------------------- 主入口


def analyze_cssh(pkts):
    """扫描 pcap，返回所有 CSSH 会话（含握手消息、双证书、验签结果）。

    返回列表，每个元素：
      client / server / client_version / server_version
      messages: [{no, dir, title, fields}]
      kex: 汇总 {random_client, random_server, sign_verify, sign_cert, enc_cert,
                 enc_k, algorithms, cookie_c, cookie_s}
    """
    # 第一遍：找出所有含 CSSH 版本串的流，并按版本串时间先后确定客户端方向
    cssh = {}
    for i, pkt in enumerate(pkts):
        if not pkt.haslayer("TCP"):
            continue
        try:
            sip, sport = pkt["IP"].src, pkt["TCP"].sport
            dip, dport = pkt["IP"].dst, pkt["TCP"].dport
        except Exception:
            continue
        pay = bytes(pkt["TCP"].payload)
        if CSSH_VERSION_PREFIX not in pay:
            continue
        key = tuple(sorted(((sip, sport), (dip, dport))))
        entry = cssh.setdefault(key, {"ends_time": {}, "no": i + 1})
        # 只登记「发送端」自身版本串的 (时间, 包序号)，避免把目的端误绑到同一包号；
        # 回环抓包两端时间戳可能完全相同，需 (时间, 包序号) 联合排序，先发版本串者为客户端
        entry["ends_time"].setdefault((sip, sport), (float(pkt.time), i + 1))
    if not cssh:
        return []

    sessions = []
    for key in sorted(cssh, key=lambda k: cssh[k]["no"]):
        ends_time = cssh[key]["ends_time"]
        client = min(ends_time, key=ends_time.get)  # 版本串先发出者为客户端
        server = max(ends_time, key=ends_time.get)
        c2s, c_merged = _flow_stream(pkts, *client, *server)
        s2c, s_merged = _flow_stream(pkts, *server, *client)
        cv, c_off = _split_version(c2s)
        sv, s_off = _split_version(s2c)
        session = {
            "client": client, "server": server,
            "client_version": cv.decode("utf-8", "replace"),
            "server_version": sv.decode("utf-8", "replace"),
            "messages": [], "kex": {},
        }
        def feed(payload, no, d):
            if not payload:
                return
            mt = payload[0]
            title = _MSG_NAMES.get(mt, "USERVAR/未知 (type=%d)" % mt)
            fields = []
            if mt == 20:
                fields = _parse_kexinit(payload)
            elif mt == 200:
                fields = _parse_kex_request(payload)
            elif mt == 201:
                fields = _parse_kex_reply(payload, session)
            elif mt == 202:
                fields = _parse_kex(payload)
            else:
                fields = [("备注", "未在该版解析器中细化，或为加密后报文")]
            session["messages"].append({
                "no": no, "dir": d, "title": title, "type": mt, "fields": fields,
            })

        # 流内按记录推进偏移，用真实包号标注每条握手消息
        def walk(stream, base_off, merged, d):
            off = 0
            while off + 5 <= len(stream):
                plen = struct.unpack(">I", stream[off:off + 4])[0]
                if plen < 4 or plen > MAX_PACKET_LEN or off + 4 + plen > len(stream):
                    return
                pdl = stream[off + 4]
                if pdl > 255 or plen - 1 - pdl < 0:
                    return
                payload = stream[off + 5:off + 5 + plen - 1 - pdl]
                no = _pkt_no_at(merged, base_off + off)
                feed(payload, no, d)
                off += 4 + plen

        walk(c2s[c_off:], c_off, c_merged, "c->s")
        walk(s2c[s_off:], s_off, s_merged, "s->c")

        # 按通信顺序排序消息（以包号为准）
        session["messages"].sort(key=lambda m: (m["no"] is None, m["no"] or 0))

        kex = session.setdefault("kex", {})
        kex["cookie_c"] = kex["cookie_s"] = None
        kex["alg_kex"] = kex["alg_enc"] = kex["alg_mac"] = None
        for m in session["messages"]:
            f = dict(m.get("fields") or [])
            if m["dir"] == "c->s" and m.get("type") == 200:
                kex["random_client"] = f.get("random-client")
        reply = session.get("reply")
        if reply:
            kex["random_server"] = reply["random_server"].hex()
            kex["sign_der"] = reply["sign"]
            kex["sign_der_hex"] = reply["sign"].hex()
            kex["sign_cert"] = _cert_parse(reply["sign_der"])
            kex["enc_cert"] = _cert_parse(reply["enc_der"])
            sign_pt = _pubkey_point_hex(reply["sign_der"])
            kex["sign_pubkey_hex"] = sign_pt
            rc = bytes.fromhex(kex.get("random_client") or "")
            rs = reply["random_server"]
            if rc and len(rs) == 8 and sign_pt:
                ok, detail = _sm2_verify(reply["sign"], rc + rs, sign_pt)
                kex["sign_verify"] = ok
                kex["sign_verify_detail"] = detail
            else:
                kex["sign_verify"] = None
                kex["sign_verify_detail"] = "缺少 random-client / random-server / 公钥，无法验签"
            # enc(K)
            for m in session["messages"]:
                if m.get("type") == 202:
                    fe = dict(m.get("fields") or [])
                    kex["enc_k"] = fe.get("enc(K)（SM2 加密主密钥）")
        # KEXINIT 算法汇总
        for m in session["messages"]:
            if m.get("type") == 20 and m["dir"] == "c->s":
                f = dict(m.get("fields") or [])
                kex["cookie_c"] = f.get("Cookie 随机数")
                kex["alg_kex"] = f.get("密钥交换算法")
                kex["alg_enc"] = f.get("加密算法(客户端→服务端)")
                kex["alg_mac"] = f.get("MAC 算法(客户端→服务端)")
            elif m.get("type") == 20 and m["dir"] == "s->c":
                kex["cookie_s"] = dict(m.get("fields") or []).get("Cookie 随机数")
        sessions.append(session)
    return sessions


# ------------------------------------------------------------- HTML 汇总


def session_summary_html(session):
    """把一次 CSSH 会话渲染成摘要 HTML（主窗口展示 / 弹窗复用）。"""
    k = session.get("kex") or {}
    sc, ec = k.get("sign_cert") or {}, k.get("enc_cert") or {}

    h = []
    h.append("<div style='background:#FFFFFF;border:1px solid #E5E7EB;border-radius:8px;"
             "padding:10px 14px;font-size:12px;line-height:1.8;color:#374151'>")

    h.append("<b style='color:#1F2937'>%s ⇄ %s</b>　<span style='color:#1565C0;font-weight:bold'>CSSH 国密 SSH（GM/T 0129-2023）</span><br>" % (
        ":".join(map(str, session["client"])), ":".join(map(str, session["server"]))))
    h.append("客户端版本：%s<br>服务端版本：%s<br>" % (
        escape(session.get("client_version", "")), escape(session.get("server_version", ""))))

    if k.get("alg_kex"):
        h.append("<b>协商算法</b>：KEX %s<br>&nbsp;&nbsp;加密 %s<br>&nbsp;&nbsp;MAC %s<br>"
                 % (highlight_algs(k.get("alg_kex")),
                    highlight_algs(k.get("alg_enc") or ""),
                    highlight_algs(k.get("alg_mac") or "")))
    if k.get("cookie_c") or k.get("cookie_s"):
        h.append("Cookie(C)=%s<br>Cookie(S)=%s<br>" % (escape(k.get("cookie_c") or "-"),
                                                        escape(k.get("cookie_s") or "-")))

    if k.get("random_client") and k.get("random_server"):
        ok = k.get("sign_verify")
        if ok is True:
            badge = "<span style='background:#DCFCE7;color:#15803D;border-radius:4px;padding:1px 6px;font-weight:bold'>验签通过 ✓</span>"
        elif ok is False:
            badge = "<span style='background:#FEE2E2;color:#B91C1C;border-radius:4px;padding:1px 6px;font-weight:bold'>验签失败 ✗</span>"
        else:
            badge = "<span style='background:#FEF3C7;color:#92400E;border-radius:4px;padding:1px 6px;font-weight:bold'>未能验签 ⚠</span>"
        h.append("<b>服务端身份鉴别（SM2 验签）</b>%s<br>" % badge)
        h.append("&nbsp;&nbsp;random-client = <code>%s</code><br>"
                 "&nbsp;&nbsp;random-server = <code>%s</code><br>"
                 "&nbsp;&nbsp;待签名数据 M = rc ∥ rs（16 字节，用户标识 1234567812345678）<br>"
                 % (escape(k["random_client"]), escape(k["random_server"])))
        if k.get("sign_der_hex"):
            h.append("&nbsp;&nbsp;签名值 (DER) = <code>%s</code><br>" % escape(k["sign_der_hex"]))
        if k.get("sign_pubkey_hex"):
            h.append("&nbsp;&nbsp;签名公钥（签名证书 SPKI）：<code>%s…</code><br>"
                     % escape(k["sign_pubkey_hex"][:48]))
        h.append("&nbsp;&nbsp;验签结果：%s<br>"
                 % escape(k.get("sign_verify_detail") or ""))

    for label, cert in (("签名证书", sc), ("加密证书", ec)):
        sub = cert.get("subject") or ""
        ser = cert.get("serial") or ""
        ku = cert.get("key_usage") or ""
        h.append("<b>%s</b>：使用者 %s（序列号 %s；密钥用途 %s）<br>"
                 % (label, escape(sub), escape(ser), escape(ku)))
    if sc.get("subject") and ec.get("subject") and sc.get("subject") == ec.get("subject"):
        h.append("<span style='color:#15803D'>双证书主体一致 ✓</span><br>")
    # 本测试床的"签名证书"虽用于 SM2 签名，但 keyUsage 未声明数字签名位（如实解析，非误判）
    if sc.get("key_usage") and "数字签名" not in sc.get("key_usage", ""):
        h.append("<span style='color:#B45309'>注：签名证书的 keyUsage 未声明「数字签名」（GB/T "
                 "38540 加密证书格式如实解析，本证书实际仍承担 SM2 签名）</span><br>")

    if k.get("enc_k"):
        h.append("<b>加密主密钥 enc(K)</b>：<code>%s…</code>（%d 字节）<br>" % (
            escape(k["enc_k"][:64]), len(k["enc_k"]) // 2))
    else:
        h.append("<span style='color:#9ca3af'>（未捕获到 SSH_MSG_KEX 加密主密钥报文）</span><br>")

    h.append("</div>")
    return "\n".join(h)


# ------------------------------------------------------------- 时序图流接口
# 与 tls_parser._parse_record_stream / packet_parser.parse_ssh_stream 同风格，
# 供主界面「协议分析」时序图（handshake_view）直接消费 CSSH 会话。

_CERT_KEYS = ("version", "serial", "subject", "issuer", "not_before", "not_after",
              "sig_algorithm", "pubkey", "pubkey_curve", "key_usage", "ext_key_usage",
              "basic_constraints", "sha256_thumb", "sig_value", "der_hex")


def direction_messages(data, direction, base=0, segs=None):
    """解析一个方向的 CSSH 重组流，返回 handshake_view 兼容的消息列表。

    每条消息形如 {"dir", "proto": "CSSH", "type", "summary", "fields"(dict),
                  "offset", "no"}。KEX_REPLY 消息额外携带服务端双证书的
    cert1_* / cert2_* 字段（供时序图证书卡 / 证书按钮 / 导出 .cer 使用）。
    """
    msgs = []
    version, off = _split_version(data)
    if version:
        vl = version.decode("utf-8", "replace")
        msgs.append({"dir": direction, "proto": "CSSH", "type": "版本交换",
                     "summary": vl, "no": _tl._msg_packet_no(segs, base),
                     "offset": base, "fields": {"版本串": vl}})
    while off + 5 <= len(data):
        plen = struct.unpack(">I", data[off:off + 4])[0]
        if plen < 4 or plen > MAX_PACKET_LEN or off + 4 + plen > len(data):
            break
        pdl = data[off + 4]
        if pdl > 255 or plen - 1 - pdl < 0:
            break
        payload = data[off + 5:off + 5 + plen - 1 - pdl]
        abs_off = base + off
        no = _tl._msg_packet_no(segs, abs_off)
        off += 4 + plen
        if not payload:
            continue
        mt = payload[0]
        if mt == 20:
            fd = dict(_parse_kexinit(payload))
            kx = (fd.get("密钥交换算法") or "").split(",")[0]
            msgs.append({"dir": direction, "proto": "CSSH", "type": "KEXINIT",
                         "summary": "算法协商（首选 kex=%s）" % kx,
                         "no": no, "offset": abs_off, "fields": fd})
        elif mt == 200:
            fd = dict(_parse_kex_request(payload))
            rc = fd.get("random-client") or ""
            msgs.append({"dir": direction, "proto": "CSSH", "type": "KEX_REQUEST",
                         "summary": "客户端密钥协商请求（random-client %s…）" % rc[:16],
                         "no": no, "offset": abs_off, "fields": fd})
        elif mt == 201:
            fd = _reply_fields(payload)
            rs = fd.get("random-server") or ""
            msgs.append({"dir": direction, "proto": "CSSH", "type": "KEX_REPLY",
                         "summary": "服务端应答：双证书（签名∥加密）+ random-server %s… + SM2 签名" % rs[:16],
                         "no": no, "offset": abs_off, "fields": fd})
        elif mt == 202:
            fd = dict(_parse_kex(payload))
            msgs.append({"dir": direction, "proto": "CSSH", "type": "KEX",
                         "summary": "客户端发送 enc(K)（SM2 加密主密钥，%d 字节）"
                         % (len(fd.get("enc(K)（SM2 加密主密钥）") or "") // 2),
                         "no": no, "offset": abs_off, "fields": fd})
        elif mt == 21:
            msgs.append({"dir": direction, "proto": "CSSH", "type": "NEWKEYS",
                         "summary": "切换至 SM4 会话加密", "no": no, "offset": abs_off,
                         "fields": {"说明": "双方切换至 SM4 会话加密，后续载荷不再按明文分帧解析"}})
        else:
            nm = _MSG_NAMES.get(mt, "消息 type=%d" % mt)
            msgs.append({"dir": direction, "proto": "CSSH", "type": nm,
                         "summary": nm, "no": no, "offset": abs_off,
                         "fields": {"说明": "未在解析器中细化的 USERVAR 消息或加密后载荷"}})
    return msgs


def _reply_fields(payload):
    """KEX_REPLY(201) → 字段 dict（含双证书 cert1_/cert2_ + 验签素材）。"""
    sign_der, o = _rd_string(payload, 1)
    enc_der, o = _rd_string(payload, o)
    rs, o = _rd_string(payload, o)
    sig, o = _rd_string(payload, o)
    fd = {
        "cert_chain_count": 2,
        "random-server": rs.hex(),
        "签名值 (DER)": sig.hex(),
        "签名证书 DER": "%d 字节（%s）" % (len(sign_der), "有效" if sign_der[:1] == b"\x30" else "异常"),
        "加密证书 DER": "%d 字节（%s）" % (len(enc_der), "有效" if enc_der[:1] == b"\x30" else "异常"),
    }
    fd["签名公钥"] = _pubkey_point_hex(sign_der) or ""
    for pre, der in (("cert1_", sign_der), ("cert2_", enc_der)):
        c = _cert_parse(der)
        for key in _CERT_KEYS:
            if c.get(key) is not None:
                fd[pre + key] = c[key]
    return fd


def flow_from_reassembly(ab, ba, ab_base=0, ba_base=0, ab_segs=None, ba_segs=None, init=""):
    """从 tls_parser._reassemble_flows 的重组流字典构建 CSSH 时序消息。

    返回 (msgs, cdir_txt, client_version, server_version)；非 CSSH 返回 (None, None, None, None)。
    msgs 已按真实抓包包号排序（跨方向真实时序），KEX_REPLY 附带验签结果字段。
    """
    if not (ab.startswith(CSSH_VERSION_PREFIX) or ba.startswith(CSSH_VERSION_PREFIX)):
        return None, None, None, None
    m_ab = direction_messages(ab, "A->B", ab_base, ab_segs) if ab.startswith(CSSH_VERSION_PREFIX) else []
    m_ba = direction_messages(ba, "B->A", ba_base, ba_segs) if ba.startswith(CSSH_VERSION_PREFIX) else []
    msgs = m_ab + m_ba
    if not msgs:
        return None, None, None, None
    # 客户端判定：CSSH 客户端先发版本串（权威）；同留 TCP 发起方 init 兜底
    # （回环/长连接场景首个 SYN 往往不在抓包内，init 不可靠）
    cdir = init if init in ("ab", "ba") else "ab"
    ver_no = {m["dir"]: m["no"] for m in msgs if m["type"] == "版本交换" and m.get("no") is not None}
    if len(ver_no) == 2:
        cdir = "ab" if ver_no["A->B"] < ver_no["B->A"] else "ba"
    elif len(ver_no) == 1:
        cdir = "ab" if next(iter(ver_no)) == "A->B" else "ba"

    c2s = [m for m in msgs if m["dir"] == ("A->B" if cdir == "ab" else "B->A")]
    s2c = [m for m in msgs if m["dir"] != ("A->B" if cdir == "ab" else "B->A")]
    req = next((m["fields"] for m in c2s if m["type"] == "KEX_REQUEST"), None)
    rep = next((m for m in s2c if m["type"] == "KEX_REPLY"), None)
    if req and rep:
        rc = req.get("random-client") or ""
        rs = rep["fields"].get("random-server") or ""
        sig = rep["fields"].get("签名值 (DER)") or ""
        pub = rep["fields"].get("签名公钥") or ""
        if rc and rs and sig and pub:
            ok, detail = _sm2_verify(bytes.fromhex(sig), bytes.fromhex(rc) + bytes.fromhex(rs), pub)
            rep["fields"]["验签结果"] = {True: "通过", False: "失败", None: "不可用"}.get(ok)
            rep["fields"]["验签详情"] = detail
            rep["fields"]["待签名数据"] = rc + rs
            rep["fields"]["用户标识"] = "1234567812345678"
            if ok is True:
                rep["summary"] = "服务端应答：双证书 + 验签通过 ✓（random-server %s…）" % rs[:16]

    msgs.sort(key=lambda m: m["no"] if m["no"] is not None else (1 << 30))
    for m in msgs:
        m.pop("offset", None)
    ver = {}
    for m in msgs:
        if m["type"] == "版本交换":
            ver[m["dir"]] = m["fields"].get("版本串", "")
    cver = ver.get("A->B" if cdir == "ab" else "B->A", "")
    sver = ver.get("B->A" if cdir == "ab" else "A->B", "")
    return msgs, ("A->B" if cdir == "ab" else "B->A"), cver, sver
