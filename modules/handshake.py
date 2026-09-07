# -*- coding: utf-8 -*-
"""TLS / TLCP / SSH 协商过程关键步骤提取

面向「国密协议协商过程」分析场景：从 pcap 中提取客户端与服务端之间的
关键握手（协商）消息，按真实包时序组织为「步骤时间线」，供界面以
卡片式时间线展示。多余 TCP 包（SYN / ACK / 重传 / HelloRequest /
纯应用数据）不进步骤列表，仅统计计数。

核心函数：
    extract_handshakes(pkts, max_flows=64) -> list[HandshakeFlow]
    summarize(path) -> str

HandshakeFlow:
    key / client / server / proto(TLS|TLCP|SSH) / sni / selected_cipher
    extra_count / steps

Step:
    dir('C->S'|'S->C'|'-') / title / subtitle / records /
    fields[(label,value)] / certs[(tab,[(label,value)])] / fold / highlight
"""
import struct
from collections import OrderedDict, defaultdict

from scapy.all import rdpcap, IP, IPv6, TCP

try:
    from modules import tls_parser as _tl
    from modules import packet_parser as _pp
except ImportError:
    import tls_parser as _tl
    import packet_parser as _pp


# ---------------------------------------------------------------- 工具

def _fmt_hex(data: bytes, limit: int = 120) -> str:
    h = data.hex()
    if len(h) > limit * 2:
        h = h[:limit * 2] + "…"
    return h


# ---------------------------------------------------------------- 带时间戳的流重组

def _dedup_segs(segs):
    """同 TCP seq 的多个段取 payload 最长者，剔除 keep-alive / 零长探测等干扰。"""
    by_seq = {}
    for seq, pl, ts in segs:
        cur = by_seq.get(seq)
        if cur is None or len(pl) > len(cur[1]):
            by_seq[seq] = (seq, pl, ts)
    return [by_seq[s] for s in sorted(by_seq)]


def _merge_stream(segs):
    """按 seq 合并重叠/重传段为连续字节流。

    入参 segs 需已按 seq 升序（_dedup_segs 的产物）。
    返回 (stream, tsmap)，tsmap 记录各合并段起点字节偏移 → 该段时间戳，
    供后续按字节偏移反查消息时间。
    """
    if not segs:
        return b"", {}
    base = segs[0][0]
    merged = []
    for seq, pl, ts in segs:
        start = seq - base
        if merged:
            last_pos, last_pl = merged[-1][0], merged[-1][1]
            last_end = last_pos + len(last_pl)
            if start < last_end:
                # 部分/完全重叠：只补尚未覆盖的尾部
                if start + len(pl) > last_end:
                    merged.append((last_end, pl[last_end - start:], ts))
                continue
            if start > last_end:
                merged.append((start, pl, ts))
                continue
            merged.append((last_end, pl, ts))
        else:
            merged.append((start, pl, ts))
    if not merged:
        return b"", {}
    # 拼流（保留空洞占位）并记录每段头偏移的 ts
    stream = b""
    tsmap = {}
    for pos, pl, ts in merged:
        if pos > len(stream):
            stream += b"\x00" * (pos - len(stream))
        elif pos < len(stream):
            pl = pl[len(stream) - pos:]
        tsmap[len(stream)] = ts
        stream += pl
    return stream, tsmap


def _reassemble_ts(pkts):
    """按 TCP 流重组，并保留每条记录首包时间戳。

    返回 {key: {'a','b', 'ab_recs':[(typ,ver,payload,ts)], 'ba_recs':[...]}}
    只保留含有 TLS/TLCP 记录头或 SSH 版本行的流。
    """
    flows = defaultdict(lambda: {"a": "", "b": "", "ab": [], "ba": []})
    for p in pkts:
        if not (p.haslayer(TCP) and (IP in p or IPv6 in p)):
            continue
        if IP in p:
            src, dst = p[IP].src, p[IP].dst
        else:
            src, dst = p[IPv6].src, p[IPv6].dst
        sp, dp = p[TCP].sport, p[TCP].dport
        payload = bytes(p[TCP].payload)
        if not payload:
            continue
        key = _tl._flow_key(p)
        if key is None:
            continue
        a, ap, b, bp = key
        f = flows[key]
        f["a"], f["b"] = a, b
        d = "ab" if (src, sp) == (a, ap) else "ba"
        ts = float(p.time)
        f[d].append((p[TCP].seq, payload, ts))

    out = {}
    for key, f in flows.items():
        # SSH 识别：任一侧首包以 "SSH-"/"CSSH-" 开头 → 保留原始字节流与时间戳映射
        is_ssh = False
        raw = {}
        tsmap = {}
        for d_key in ("ab", "ba"):
            segs = _dedup_segs(f[d_key])
            if segs and segs[0][1].startswith((b"SSH-", b"CSSH-")):
                is_ssh = True
            if segs:
                raw[d_key], tsmap[d_key] = _merge_stream(segs)
        if is_ssh:
            out[key] = {"a": f["a"], "b": f["b"], "ab_recs": [], "ba_recs": [],
                        "ab_bytes": raw.get("ab", b""), "ba_bytes": raw.get("ba", b""),
                        "ab_tsmap": tsmap.get("ab", {}), "ba_tsmap": tsmap.get("ba", {})}
            continue
        recs = {}
        for d_key in ("ab", "ba"):
            segs = _dedup_segs(f[d_key])
            if not segs:
                continue
            stream, tsmap = _merge_stream(segs)
            if not stream:
                continue
            # 拆 TLS/TLCP 记录
            items = []
            off = 0
            while off + 5 <= len(stream):
                typ = stream[off]
                ver = struct.unpack(">H", stream[off + 1:off + 3])[0]
                ln = struct.unpack(">H", stream[off + 3:off + 5])[0]
                if off + 5 + ln > len(stream):
                    break
                ts = None
                for p0, t0 in sorted(tsmap.items()):
                    if p0 <= off:
                        ts = t0
                    else:
                        break
                if ts is None and tsmap:
                    ts = min(tsmap.values())
                items.append((typ, ver, stream[off + 5:off + 5 + ln], ts))
                off += 5 + ln
            if items:
                recs[d_key] = items
        if not recs:
            continue
        out[key] = {"a": f["a"], "b": f["b"], "ab_recs": recs.get("ab", []),
                    "ba_recs": recs.get("ba", []), "ab_bytes": b"", "ba_bytes": b""}
    return out


# ---------------------------------------------------------------- 握手消息 → 步骤骨架

def _sig_note(scheme: int) -> str:
    name = _tl.SIG_SCHEMES.get(scheme, "")
    if scheme == 0xFFFF:
        return "SM2（国密签名）"
    return "%s (0x%04X)" % (name, scheme) if name else "0x%04X" % scheme


def _parse_client_key_exchange(body: bytes) -> OrderedDict:
    d = OrderedDict()
    if not body:
        return d
    b0 = body[0]
    if b0 == len(body) - 1 and len(body) >= 32:
        d["交换类型"] = "ECDHE 临时公钥 (ECDH Yc)"
        d["公钥长度"] = "%d 字节" % b0
        d["客户端临时公钥"] = _fmt_hex(body[1:], 96)
        if b0 == 65:
            d["公钥点格式"] = "未压缩点 04 || X || Y"
    else:
        d["交换类型"] = "加密的 PreMasterSecret（RSA / SM2）"
        d["密文长度"] = "%d 字节" % len(body)
        d["密文前缀"] = _fmt_hex(body[:20], 20)
    return d


def _parse_server_key_exchange(body: bytes, proto: str = "TLS") -> OrderedDict:
    d = OrderedDict()
    if len(body) < 8:
        return d
    if proto == "TLCP":
        # TLCP / 国密 SSL：ServerKeyExchange = 命名曲线ID(2B) + SM2 DER 签名（GB/T 38636）
        curve = struct.unpack(">H", body[0:2])[0]
        d["命名曲线ID（TLCP）"] = "0x%04X" % curve
        sig = body[2:]
        if sig.startswith(b"\x30"):
            d["签名格式"] = "国密 SM2 签名（DER SEQUENCE，r‖s）"
            d["签名长度"] = "%d 字节" % len(sig)
            d["签名值"] = _fmt_hex(sig, 200)
        else:
            d["后续数据"] = _fmt_hex(sig, 120)
        return d
    curve_type = body[0]
    off = 1
    if curve_type == 3:
        grp = struct.unpack(">H", body[1:3])[0]
        plen = body[3]
        d["椭圆曲线"] = _tl._group_name(grp)
        d["服务端临时公钥"] = _fmt_hex(body[4:4 + plen], 96)
        off = 4 + plen
    else:
        d["椭圆曲线类型"] = "0x%02X" % curve_type
    if off + 4 <= len(body):
        scheme = struct.unpack(">H", body[off:off + 2])[0]
        slen = struct.unpack(">H", body[off + 2:off + 4])[0]
        d["签名算法"] = _sig_note(scheme)
        d["签名长度"] = slen
        d["签名值"] = _fmt_hex(body[off + 4:off + 4 + slen], 200)
    return d


def _msg_to_step(mt: int, body: bytes, proto: str = "TLS") -> dict:
    name = _tl.HANDSHAKE_TYPE.get(mt, "type%d" % mt)
    step = {"title": name, "records": 1, "subtitle": "", "fields": [],
            "certs": [], "fold": False, "highlight": []}

    if mt == 1:
        d = _tl.parse_client_hello(body, proto)
        f = OrderedDict()
        if d.get("legacy_version"):
            f["协议版本"] = d["legacy_version"]
        if d.get("random"):
            f["随机数"] = d["random"]
        if d.get("session_id"):
            f["会话 ID"] = d["session_id"]
        if d.get("cipher_suites"):
            f["支持的密码套件"] = d["cipher_suites"]
        if d.get("SNI"):
            f["服务器名称 (SNI)"] = d["SNI"]
        if "supported_groups" in d and d["supported_groups"]:
            f["支持的命名曲线"] = d["supported_groups"]
        if "ext_signature_algorithms" in d and d["ext_signature_algorithms"]:
            f["支持的签名算法"] = d["ext_signature_algorithms"]
        if "ext_supported_versions" in d and d["ext_supported_versions"]:
            f["支持的版本"] = d["ext_supported_versions"]
        step["title"] = "ClientHello（客户端问候）"
        step["fields"] = list(f.items())

    elif mt == 2:
        d = _tl.parse_server_hello(body, proto)
        f = OrderedDict()
        f["TLS 版本"] = d.get("legacy_version", "?")
        f["随机数"] = d.get("random", "-")
        f["最终选定密码套件"] = d.get("selected_cipher_suite", "-")
        step["title"] = "ServerHello（服务端应答）"
        step["fields"] = list(f.items())

    elif mt == 11:
        certs = _tl.parse_certificate(body, is_tls13=False)
        step["title"] = "Certificate（证书链）"
        step["subtitle"] = "共 %d 张证书" % len(certs)
        tabs = []
        for i, c in enumerate(certs):
            cf = OrderedDict()
            cf["主体 Subject"] = c.get("subject", "-")
            cf["签发者 Issuer"] = c.get("issuer", "-")
            if c.get("not_before"):
                cf["有效期从"] = c["not_before"]
            if c.get("not_after"):
                cf["有效期至"] = c["not_after"]
            cf["序列号"] = c.get("serial", "-")
            cf["签名算法"] = c.get("sig_algorithm", "-")
            cf["公钥"] = c.get("pubkey", "-") or "-"
            if c.get("sha256_thumb"):
                cf["SHA-256 指纹"] = c["sha256_thumb"]
            if c.get("sig_value"):
                cf["证书签名值"] = c["sig_value"]
            if c.get("note"):
                cf["备注"] = c["note"]
            tabs.append(("证书 %d" % (i + 1), list(cf.items())))
        step["certs"] = tabs
        step["fields"] = [("证书链数量", "%d 张" % len(certs))]

    elif mt == 12:
        s = _parse_server_key_exchange(body, proto)
        step["title"] = "ServerKeyExchange（服务端密钥交换）"
        step["fields"] = list(s.items()) if s else [("原始长度", "%d 字节" % len(body))]
        step["highlight"] = ["签名长度", "签名值"]

    elif mt == 14:
        step["title"] = "ServerHelloDone"
        step["fields"] = [("说明", "服务端密钥协商参数发送完毕，等待客户端密钥交换")]

    elif mt == 16:
        step["title"] = "ClientKeyExchange（客户端密钥交换）"
        s = _parse_client_key_exchange(body)
        step["fields"] = list(s.items()) if s else [("原始长度", "%d 字节" % len(body))]

    elif mt == 15:
        d = _tl.parse_certificate_verify(body)
        f = OrderedDict()
        f["签名算法"] = str(d.get("signature_scheme", "-"))
        f["签名长度"] = d.get("signature_len", "-")
        f["签名值"] = d.get("signature", "-")
        step["title"] = "CertificateVerify（持证方签名）"
        step["fields"] = list(f.items())
        step["highlight"] = ["签名长度", "签名值"]

    elif mt == 20:
        step["title"] = "Finished"
        vd = _tl.parse_finished(body).get("verify_data", "-")
        step["fields"] = [("verify_data（完整性校验）", vd)]
        step["subtitle"] = "加密通道建立后的首条校验消息"

    elif mt == 4:
        tlen = struct.unpack(">H", body[8:10])[0] if len(body) >= 10 else 0
        step["title"] = "NewSessionTicket（会话票据）"
        step["fields"] = [("票据长度", "%d 字节" % tlen),
                          ("票据", _fmt_hex(body[10:10 + tlen], 64) if len(body) >= 10 else "-")]

    elif mt == 0:  # HelloRequest 噪音
        step["title"] = None
        return step

    else:
        step["fields"] = [("消息类型", name), ("长度", "%d 字节" % len(body)),
                          ("十六进制预览", _fmt_hex(body, 96))]
    return step


# ---------------------------------------------------------------- 流级组装

class _Msg:
    __slots__ = ("side", "typ", "mt", "body", "ts", "kind")

    def __init__(self, side, typ, mt, body, ts):
        self.side = side          # 'A' ab 侧 / 'B' ba 侧
        self.typ = typ
        self.mt = mt
        self.body = body
        self.ts = ts or 0.0
        self.kind = "ccs" if typ == 20 else ("alert" if typ == 21 else
                                             ("app" if typ in (23, 24) else "hs"))


def _assemble_msgs(ab_recs, ba_recs):
    """两个方向的记录 → 按 ts 排序的全局消息序列。"""
    msgs = []
    for side, recs in (("A", ab_recs), ("B", ba_recs)):
        for typ, ver, payload, ts in recs:
            if typ == 22:
                if payload:
                    for mt, body, _ in _tl.split_handshake_messages(payload):
                        msgs.append(_Msg(side, typ, mt, body, ts))
            elif typ == 20:
                msgs.append(_Msg(side, typ, None, b"", ts))
            elif typ in (23, 24, 21):
                msgs.append(_Msg(side, typ, None, b"", ts))
    msgs.sort(key=lambda m: (m.ts, 0 if m.side == "A" else 1))
    return msgs


def _client_ab_of(ab_recs, ba_recs) -> bool:
    """判定客户端方向：先发出 ClientHello(mt==1) 的一端为客户端。
    双向鉴别场景中可能出现服务端反向发起、仅含 ServerHello 的流：
    此时首条握手消息（ServerHello 等）所在侧视为服务端。"""
    def _first_hs(recs):
        for typ, ver, payload, ts in recs:
            if typ == 22:
                hs = _tl.split_handshake_messages(payload) if payload else []
                if hs:
                    return hs[0][0]
        return None
    a1, b1 = _first_hs(ab_recs), _first_hs(ba_recs)
    if a1 == 1 and b1 != 1:
        return True
    if b1 == 1 and a1 != 1:
        return False
    # 无 ClientHello：首条握手消息所在侧为服务端，另一侧为客户端
    if a1 is not None and b1 is None:
        return False
    if b1 is not None and a1 is None:
        return True
    return True


def _build_steps(msgs, client_label, proto="TLS"):
    """消息序列 →（步骤列表, extra）。client_label: 'A'/'B' 表示客户端所在侧。"""
    steps = []
    app_c = app_s = 0
    extra = 0
    n = len(msgs)
    i = 0
    while i < n:
        m = msgs[i]
        is_client = (m.side == client_label)
        dir_lbl = "C->S" if is_client else "S->C"

        if m.kind == "app":
            if is_client:
                app_c += 1
            else:
                app_s += 1
            i += 1
            continue
        if m.kind == "alert":
            extra += 1
            i += 1
            continue
        if m.kind == "ccs":
            st = {"dir": dir_lbl, "title": "ChangeCipherSpec（切换加密）", "records": 1,
                  "subtitle": "通知对端：其后消息使用协商密钥加密传输",
                  "fields": [], "certs": [], "fold": True, "highlight": []}
            steps.append(st)
            i += 1
            continue

        step = _msg_to_step(m.mt, m.body, proto)
        if step["title"] is None:
            extra += 1
            i += 1
            continue
        step["dir"] = dir_lbl

        # 合并：客户端 ClientKeyExchange 吸收紧随的 CCS + Finished
        if m.mt == 16 and is_client:
            fields = list(step["fields"])
            j = i + 1
            saw_ccs = saw_fin = False
            while j < n:
                jm = msgs[j]
                if jm.side != client_label:
                    break
                if jm.kind == "ccs" and not saw_ccs:
                    saw_ccs = True
                    fields.append(("切换加密", "ChangeCipherSpec：此后消息加密传输"))
                    j += 1
                    continue
                if jm.kind == "hs" and jm.mt == 20 and not saw_fin:
                    saw_fin = True
                    vd = _tl.parse_finished(jm.body).get("verify_data", "")
                    fields.append(("Finished verify_data", vd))
                    j += 1
                    continue
                break
            if saw_ccs or saw_fin:
                step["title"] = "ClientKeyExchange / ChangeCipherSpec / Finished"
                step["fields"] = fields
                i = j
        steps.append(step)
        i += 1

    if app_c or app_s:
        total = app_c + app_s
        steps.append({"dir": "-", "title": "ApplicationData（加密应用数据，已折叠）",
                      "records": total, "subtitle": "",
                      "fields": [("说明", "协商完成后双向业务数据共 %d 条，不展开" % total)],
                      "certs": [], "fold": True, "highlight": []})
    return steps, extra


def extract_handshakes(pkts, max_flows=64):
    flows = _reassemble_ts(pkts)
    results = []
    for key, f in flows.items():
        a, ap, b, bp = key
        ab_r, ba_r = f["ab_recs"], f["ba_recs"]
        ab_b, ba_b = f["ab_bytes"], f["ba_bytes"]

        # ---- SSH 分支：以真实版本行识别（SSH- 或 CSSH-）
        if ab_b.startswith((b"SSH-", b"CSSH-")) or ba_b.startswith((b"SSH-", b"CSSH-")):
            ssh_msgs = []
            for data, tsm, dname in ((ab_b, f["ab_tsmap"], "A->B"),
                                     (ba_b, f["ba_tsmap"], "B->A")):
                if data.startswith((b"SSH-", b"CSSH-")):
                    ssh_msgs.extend(_pp.parse_ssh_stream(data, dname, tsm))
            # 按真实时序交错排序（版本交换/密钥协商严格按包序）
            ssh_msgs.sort(key=lambda m: (m.get("ts") is None, m.get("ts") or 0))
            if not ssh_msgs:
                continue
            first = ssh_msgs[0]["dir"]
            client = "%s:%d" % (a, ap) if first == "A->B" else "%s:%d" % (b, bp)
            server = "%s:%d" % (b, bp) if first == "A->B" else "%s:%d" % (a, ap)
            steps = []
            for m in ssh_msgs:
                t = m["type"]
                dir_lbl = "C->S" if m["dir"] == first else "S->C"
                fd = m["fields"]
                if t == "SSH 版本交换":
                    steps.append({"dir": dir_lbl, "title": "SSH 版本交换", "records": 1,
                                  "subtitle": "", "fields": list(fd.items()),
                                  "certs": [], "fold": False, "highlight": []})
                elif t == "SSH_MSG_KEXINIT":
                    kv = []
                    for k, v in fd.items():
                        if k == "kex_algorithms":
                            kv.append(("密钥交换算法", v))
                        elif k == "server_host_key_algorithms":
                            kv.append(("主机密钥算法", v))
                        elif k.startswith("encryption"):
                            kv.append(("加密算法", v))
                        elif k.startswith("mac"):
                            kv.append(("MAC 算法", v))
                        elif k.startswith("compression"):
                            kv.append(("压缩算法", v))
                    kv.append(("消息长度", fd.get("payload_len", "-")))
                    steps.append({"dir": dir_lbl, "title": "SSH_MSG_KEXINIT（算法协商）",
                                  "records": 1, "subtitle": "", "fields": kv,
                                  "certs": [], "fold": False, "highlight": []})
                elif t == "SSH_MSG_NEWKEYS":
                    steps.append({"dir": dir_lbl, "title": "SSH_MSG_NEWKEYS", "records": 1,
                                  "subtitle": "密钥交换完成，启用协商的加密与 MAC 算法",
                                  "fields": [], "certs": [], "fold": False, "highlight": []})
                elif t.startswith("SSH_MSG_KEX"):
                    kv = [("消息长度", fd.get("payload_len", "-"))]
                    steps.append({"dir": dir_lbl, "title": t, "records": 1, "subtitle": "",
                                  "fields": kv, "certs": [], "fold": False, "highlight": []})
            results.append({
                "key": "%s:%d-%s:%d" % (a, ap, b, bp), "client": client, "server": server,
                "proto": "SSH", "sni": "", "selected_cipher": "", "extra_count": 0,
                "handshake_messages": len(steps), "steps": steps,
            })
            continue

        # ---- TLS / TLCP
        p_ab = "TLCP" if ab_r and ab_r[0][1] in (0x0001, 0x0002, 0x0101) else "TLS"
        p_ba = "TLCP" if ba_r and ba_r[0][1] in (0x0001, 0x0002, 0x0101) else "TLS"
        proto = "TLCP" if (p_ab == "TLCP" or p_ba == "TLCP") else "TLS"

        cli_ab = _client_ab_of(ab_r, ba_r)
        msgs = _assemble_msgs(ab_r, ba_r)
        if not msgs:
            continue
        client_label = "A" if cli_ab else "B"
        steps, extra = _build_steps(msgs, client_label, proto)
        if not steps:
            continue
        client = "%s:%d" % (a, ap) if cli_ab else "%s:%d" % (b, bp)
        server = "%s:%d" % (b, bp) if cli_ab else "%s:%d" % (a, ap)
        sni = sel = ""
        for st in steps:
            for k, v in st["fields"]:
                if k == "服务器名称 (SNI)" and v:
                    sni = v
                if k == "最终选定密码套件" and v:
                    sel = str(v)
        results.append({
            "key": "%s:%d-%s:%d" % (a, ap, b, bp), "client": client, "server": server,
            "proto": proto, "sni": sni, "selected_cipher": sel, "extra_count": extra,
            "handshake_messages": len([s for s in steps]), "steps": steps,
        })

    results.sort(key=lambda r: len(r["steps"]), reverse=True)
    return results[:max_flows]


def summarize(path: str, max_flows=8) -> str:
    pkts = rdpcap(path)
    flows = extract_handshakes(pkts)
    if not flows:
        return "未在文件中发现 TLS / TLCP / SSH 明文协商过程"
    lines = ["识别到 %d 条含协商过程的会话流：" % len(flows)]
    for i, fl in enumerate(flows[:max_flows], 1):
        sel = (" | 套件: %s" % fl["selected_cipher"]) if fl["selected_cipher"] else ""
        sni = (" | SNI: " + fl["sni"]) if fl["sni"] else ""
        lines.append("  #%d [%s] %s ⇄ %s  步骤 %d%s%s" %
                     (i, fl["proto"], fl["client"], fl["server"], len(fl["steps"]), sel, sni))
    return "\n".join(lines)
