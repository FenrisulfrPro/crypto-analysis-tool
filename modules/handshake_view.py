# -*- coding: utf-8 -*-
"""握手时序图数据提取（纯逻辑，无 GUI 依赖）

从 pcap 流中提取"客户端 ⇄ 服务端"密钥协商过程中的关键数据包：
  - TLS / TLCP / SSH 应用层握手消息（ClientHello / ServerHello / Certificate …
    / ChangeCipherSpec / Finished 等），仅保留 ClientHello 起到服务端 Finished 止
  - TCP 三次握手（SYN / SYN-ACK / ACK）与空消息（如 HelloRequest）不进入展示

供主界面「协议分析」的时序图模式渲染：客户端在左、服务端在右，
箭头按时间顺序（seq = ①②③…）从发送方指向接收方。
"""

# 事件结构：
#   {"seq": int,        # 1 起序号，时序图左侧圆圈编号
#    "dir": "c->s"|"s->c",
#    "kind": "SYN"|"SYN-ACK"|"ACK"|"TLS"|"TLCP"|"SSH"|"…",
#    "title": str,      # 消息名（如 ClientHello）
#    "detail": str,     # 概要（如 TLS 1.3, SNI=…, 17 套件）
#    "no": int|None,    # 原始包号（若有）
#    "ts": float|None}

from scapy.all import IP, IPv6, TCP


def _norm_key(p):
    """把数据包归一到流 key（与 tls_parser._flow_key 一致）。"""
    if p is None:
        return None
    if IP in p and p.haslayer(TCP):
        a, b = p[IP].src, p[IP].dst
        sp, dp = p[TCP].sport, p[TCP].dport
    elif IPv6 in p and p.haslayer(TCP):
        a, b = p[IPv6].src, p[IPv6].dst
        sp, dp = p[TCP].sport, p[TCP].dport
    else:
        return None
    if (a, sp) <= (b, dp):
        return (a, sp, b, dp)
    return (b, dp, a, sp)


def _src_endpoint(p) -> str:
    if IP in p:
        return "%s:%d" % (p[IP].src, p[TCP].sport)
    return "%s:%d" % (p[IPv6].src, p[TCP].sport)


def find_tcp_handshake(pkts, key, client_endpoint: str, max_events: int = 3):
    """在数据包列表中定位该 TCP 流的 SYN / SYN-ACK / ACK 三次握手。

    返回按时间顺序的事件列表（最多一条握手，若干缺失也可）。"""
    a, ap, b, bp = key
    syn = synack = ack = None
    for p in pkts:
        if _norm_key(p) != key:
            continue
        flags = int(p[TCP].flags)
        if not (flags & (0x02 | 0x10)):
            continue
        src_e = _src_endpoint(p)
        if IP in p:
            seq, ackn = p[TCP].seq, p[TCP].ack
        else:
            seq, ackn = p[TCP].seq, p[TCP].ack
        no = getattr(p, "number", None)
        ts = float(getattr(p, "time", 0.0))
        if flags & 0x02 and not (flags & 0x10):
            if syn is None and src_e == client_endpoint:
                syn = {"seq": 0, "dir": "c->s", "kind": "SYN", "title": "SYN",
                       "detail": "Seq=%d" % seq, "no": no, "ts": ts,
                       "fields": [("Seq", seq)]}
        elif flags & 0x02 and (flags & 0x10):
            if synack is None and syn is not None:
                synack = {"seq": 0, "dir": "s->c", "kind": "SYN-ACK", "title": "SYN+ACK",
                          "detail": "Seq=%d, Ack=%d" % (seq, ackn), "no": no, "ts": ts,
                          "fields": [("Seq", seq), ("Ack", ackn)]}
        elif (flags & 0x10) and not (flags & 0x02):
            if ack is None and syn is not None and synack is not None:
                ack = {"seq": 0, "dir": "c->s", "kind": "ACK", "title": "ACK",
                       "detail": "Seq=%d, Ack=%d" % (seq, ackn), "no": no, "ts": ts,
                       "fields": [("Seq", seq), ("Ack", ackn)]}
                break
    evs = [e for e in (syn, synack, ack) if e]
    for i, e in enumerate(evs, 1):
        e["seq"] = i
    return evs


def messages_to_events(messages, cdir=None):
    """把流解析出的应用层消息列表转成时序图事件。

    messages 条目形如 {"dir": "A->B"|"B->A", "proto": …, "type": …, "summary": …}，
    首个消息方向默认即 客户端→服务端 方向（SSH 流可显式传 cdir 修正）。
    事件附带完整 fields 供点击后展开关键参数；形如 `X_full`/`X_list` 的字段
    用于多行完整展示，展示时隐藏对应的截断版基字段。"""
    if not messages:
        return []
    if cdir is None:
        cdir = next((m["dir"] for m in messages if m.get("type") == "ClientHello"),
                    messages[0]["dir"])
    evs = []
    for m in messages:
        d = "c->s" if m["dir"] == cdir else "s->c"
        fields = list((m.get("fields") or {}).items())
        keys = [k for k, _ in fields]
        drop = {k[:-5] for k in keys if k.endswith("_full")} | {k[:-5] for k in keys if k.endswith("_list")}
        if drop:
            fields = [(k, v) for k, v in fields if k not in drop]
        evs.append({
            "seq": 0,
            "dir": d,
            "kind": m.get("proto", "TLS"),
            "title": m.get("type", "消息"),
            "detail": (m.get("summary") or "").strip(),
            "no": m.get("no"),
            "ts": m.get("ts"),
            "fields": fields,
        })
    return evs


def _ssh_summary_html(fd):
    """把“SSH 协商算法”汇总字段渲染为参考工具风格的报告块。

    fd 形如 {SSH 版本/会话状态/密钥交换方法 (kex)/…/客户端交换值/…/会话过滤器/精确帧过滤器/帧数量}。"""
    from html import escape

    def esc(v):
        return escape(str(v))

    def show(v):
        return v if v not in (None, "", "-") else "-"

    head = "<span style='color:#2563EB'><b>%s</b></span>" % esc(fd.get("SSH 版本") or "SSH")
    st = fd.get("会话状态") or ""
    if st:
        color = {"完整": "#16a34a", "不完整": "#d97706"}.get(st, "#6b7280")
        head += "　<span style='color:%s;font-weight:bold'>%s</span>" % (color, esc(st))

    def kv(name, key):
        return "%s：<span style='color:#2563EB'><b>%s</b></span>" % (name, esc(show(fd.get(key))))

    rows = ["　".join([
        kv("密钥交换", "密钥交换方法 (kex)"),
        kv("加密算法", "加密算法 c→s"),
        kv("完整性算法", "MAC 算法 c→s"),
        kv("服务端签名", "主机密钥算法 (host key)"),
    ])]

    sup = []
    for name, key in (("密钥协商算法", "服务端支持·密钥交换算法"),
                      ("加密算法", "服务端支持·加密算法"),
                      ("完整性算法", "服务端支持·完整性算法")):
        v = fd.get(key)
        if not v or v == "-":
            sup.append("%s：-" % name)
        else:
            items = [x for x in str(v).split(" | ") if x.strip()]
            sup.append("%s：%d 项（%s…）" % (name, len(items), items[0][:40]))
    rows.append("<span style='color:#4b5563'>服务端支持：</span>" + "　".join(sup))

    params = []
    for name, key in (("客户端交换值", "客户端交换值"), ("服务端交换值", "服务端交换值")):
        v = fd.get(key)
        if v not in (None, "", "-"):
            params.append("%s <span style='font-family:Consolas'>%s…</span>" % (name, esc(str(v))[:48]))
    sa = fd.get("服务端签名算法")
    if sa not in (None, "", "-"):
        params.append("服务端签名算法 %s" % esc(str(sa)))
    hk = fd.get("服务端主机密钥格式")
    hkv = fd.get("服务端主机密钥")
    if hk not in (None, "", "-") or hkv not in (None, "", "-"):
        if hk not in (None, "", "-"):
            params.append("服务端主机密钥（%s）<span style='font-family:Consolas'>%s…</span>"
                          % (esc(str(hk)), esc(str(hkv or ""))[:48]))
        else:
            params.append("服务端主机密钥 <span style='font-family:Consolas'>%s…</span>" % esc(str(hkv))[:48])
    rows.append("<span style='color:#4b5563'>密钥协商参数：</span>" +
                ("　".join(params) if params else "（未捕获到 KEXDH 消息）"))

    loc = fd.get("会话过滤器")
    fr = fd.get("精确帧过滤器")
    fc = fd.get("帧数量")
    if loc or fr:
        s = ""
        if loc:
            s += esc(str(loc))
        if fr:
            s += " · %s" % esc(str(fr))
        if fc:
            s += "（%s 帧）" % esc(str(fc))
        rows.append("<span style='color:#78909C'>Wireshark 定位：%s</span>" % s)
    return head + "<br>" + "<br>".join(rows)


def _summary_inner(client, server, events, proto=""):
    """生成单段协商总结的正文（协商版本/套件/服务端证书），不含外层容器与标题行。"""
    from html import escape
    f_client = None   # ClientHello fields
    f_server = None   # ServerHello fields
    f_cert = None   # Certificate fields（取第一张）
    chain_n = 0
    for e in events or []:
        d = {k: v for k, v in (e.get("fields") or [])}
        t = e.get("title") or ""
        if not t:
            continue
        if t == "ClientHello" and f_client is None:
            f_client = d
        elif t == "ServerHello" and f_server is None:
            f_server = d
        elif t == "Certificate" and f_cert is None:
            f_cert = d
            chain_n = d.get("cert_chain_count") or 0

    def esc(v):
        return escape(str(v))

    ver = (f_client or {}).get("legacy_version") or (f_server or {}).get("legacy_version") or ""
    suite = (f_server or {}).get("selected_cipher_suite") or ""
    version_html = "<span style='color:#2563EB'><b>%s</b></span>" % esc(ver or "—")
    suite_html = "<span style='color:#2563EB'><b>%s</b></span>" % esc(suite or "—")
    ps = ("协商版本：%s　·　<b>最终选定密码套件：%s</b>" % (version_html, suite_html))
    # SSH：无 TLS 风格的 ClientHello/ServerHello，改展示参考工具风格的 SSH 协商报告
    if not f_client and not f_server:
        for e in events or []:
            if e.get("title") == "SSH 协商算法":
                fd = {k: v for k, v in (e.get("fields") or [])}
                ps = _ssh_summary_html(fd)
                break
        else:
            ps = ("<span style='color:#9ca3af'>SSH 握手解析：详见下方时序卡片"
                  "（版本交换 / KEXINIT / KEXDH_INIT / KEXDH_REPLY / NEWKEYS）</span>")
        return ps
    # 服务端密钥交换（ECC-SM2-EXPORT / ECDHE 参数与签名）并入协商参数
    ske = None
    cv_verify = None
    for e in events or []:
        d = {k: v for k, v in (e.get("fields") or [])}
        t = e.get("title") or ""
        if not t:
            continue
        if t == "ServerKeyExchange" and e.get("dir") == "s->c" and ske is None:
            ske = d
        elif t == "CertificateVerify" and e.get("dir") == "c->s" and cv_verify is None:
            cv_verify = d

    if f_cert:
        rows = []
        rows.append(("<b>服务端证书</b>·共 %d 张" % chain_n) if chain_n else "<b>服务端证书</b>")
        add = []
        if f_cert.get("cert1_subject"):
            add.append("主体 %s" % esc(f_cert["cert1_subject"]))
        if f_cert.get("cert1_issuer"):
            add.append("签发者 %s" % esc(f_cert["cert1_issuer"]))
        if f_cert.get("cert1_pubkey"):
            add.append("公钥算法 %s" % esc(f_cert["cert1_pubkey"]))
        if f_cert.get("cert1_pubkey_curve"):
            add.append("公钥曲线 %s" % esc(f_cert["cert1_pubkey_curve"]))
        if f_cert.get("cert1_sig_algorithm"):
            add.append("签名算法 %s" % esc(f_cert["cert1_sig_algorithm"]))
        sig = esc(f_cert.get("cert1_sig_value") or "")
        if sig:
            add.append("签名值 <span style='font-family:Consolas'>%s</span>" % sig)
        thumb = esc(f_cert.get("cert1_sha256_thumb") or "")
        if thumb:
            add.append("指纹(SHA256) %s" % thumb)
        rows.append("<br>".join("· " + a for a in add))
        if chain_n and chain_n > 1:
            rows.append("<span style='color:#9ca3af'>… 其余 %d 张证书：点击时序图卡片中的「证书 N」按钮逐一查看</span>" % (chain_n - 1))
        ps += "<br>" + "<br>".join(rows)
    else:
        ps += "<br><span style='color:#9ca3af'>未捕获到服务端证书（TLS 1.3 加密握手或缺失流量）</span>"

    if ske:
        parts = []
        if ske.get("curve_type"):
            parts.append("曲线 %s" % esc(ske["curve_type"]))
        if ske.get("named_group"):
            parts.append("组 %s" % esc(ske["named_group"]))
        if ske.get("signature_algorithm"):
            parts.append("算法 %s" % esc(ske["signature_algorithm"]))
        if ske.get("signature_scheme"):
            parts.append("签名方案 %s" % esc(ske["signature_scheme"]))
        sksig = esc(ske.get("signature") or "")
        if sksig:
            parts.append("签名值 <span style='font-family:Consolas'>%s</span>" % sksig)
        ps += "<br><span style='color:#4b5563'>服务端密钥交换（ServerKeyExchange）：</span>" + \
              ("　".join("· " + p for p in parts) if parts else "（未能解析）")

    if cv_verify:
        cvp = []
        sch = esc(cv_verify.get("signature_scheme") or "")
        if sch:
            cvp.append("签名方案 %s" % sch)
        cvs = esc(cv_verify.get("signature") or "")
        if cvs:
            cvp.append("签名值 <span style='font-family:Consolas'>%s</span>" % cvs)
        if cvp:
            ps += "<br><span style='color:#B45309'>客户端 CertificateVerify（身份鉴别）：</span>" + \
                  ("　".join("· " + p for p in cvp))
    return ps


def negotiation_summary_html(client, server, events, proto=""):
    """生成"本次密钥协商"总结的富文本 HTML（协商视图上方摘要横幅）。

    汇总：协商版本、最终选定的密码套件、服务端证书关键信息
    （主体 / 公钥算法 / 签名算法 / 签名值 / 指纹等）。返回 HTML 供 QLabel 显示。
    """
    from html import escape
    ps = ("<b>密钥协商总结</b>"
          "<span style='color:#78909C'>　%s ⇄ %s%s</span><br>"
          % (escape(client or "客户端"), escape(server or "服务端"),
             "（%s）" % escape(proto) if proto else ""))
    ps += _summary_inner(client, server, events, proto)
    return "<div style='background:#FFFFFF;border:1px solid #E5E7EB;border-radius:8px;" \
           "padding:8px 12px;font-size:12px;line-height:1.7;color:#374151'>%s</div>" % ps


def _client_auth_inner(events):
    """客户端（反向）身份鉴别总结：客户端出示的自身证书 + CertificateVerify。"""
    from html import escape
    certd = None
    verify = None
    for e in events or []:
        d = {k: v for k, v in (e.get("fields") or [])}
        t = e.get("title")
        dd = e.get("dir")
        if t == "Certificate" and dd == "c->s" and certd is None:
            certd = d
        elif t == "CertificateVerify" and dd == "c->s" and verify is None:
            verify = d

    def esc(v):
        return escape(str(v))

    ps = ""
    if certd:
        rows = []
        n = certd.get("cert_chain_count") or 1
        if n:
            rows.append("客户端证书链：%d 张" % n)
        if certd.get("cert1_subject"):
            rows.append("主体：%s" % esc(certd["cert1_subject"]))
        if certd.get("cert1_issuer"):
            rows.append("签发者：%s" % esc(certd["cert1_issuer"]))
        if certd.get("cert1_pubkey"):
            rows.append("公钥算法：%s" % esc(certd["cert1_pubkey"]))
        if certd.get("cert1_pubkey_curve"):
            rows.append("公钥曲线：%s" % esc(certd["cert1_pubkey_curve"]))
        if certd.get("cert1_sig_algorithm"):
            rows.append("签名算法：%s" % esc(certd["cert1_sig_algorithm"]))
        csig = esc(certd.get("cert1_sig_value") or "")
        if csig:
            rows.append("签名值：<span style='font-family:Consolas'>%s</span>" % csig)
        if certd.get("cert1_ext_key_usage"):
            rows.append("证书用途(EKU)：%s" % esc(certd["cert1_ext_key_usage"]))
        if certd.get("cert1_key_usage"):
            rows.append("密钥用途：%s" % esc(certd["cert1_key_usage"]))
        if certd.get("cert1_basic_constraints"):
            rows.append("CA约束：%s" % esc(certd["cert1_basic_constraints"]))
        if rows:
            ps += ("<span style='color:#B45309'>客户端出示自身证书（本次双向鉴别的反向阶段）：</span><br>"
                   + "　".join("· " + r for r in rows))
    if verify:
        if ps:
            ps += "<br>"
        sch = verify.get("signature_scheme")
        sig = verify.get("signature")
        if sch:
            ps += "· CertificateVerify 签名方案：%s" % esc(sch)
        if sig:
            ps += "<br>· 客户端签名值：<span style='font-family:Consolas'>%s</span>" % esc(sig)
        if not sch and not sig:
            ps += "· CertificateVerify（签名值与方案见时序图卡片）"
    if certd is None and verify is None:
        ps += "<span style='color:#9ca3af'>该阶段无客户端证书（非客户端鉴别）</span>"
    return ps


def _wrap_field(value) -> str:
    """字段值展示：以 ' | ' 分隔的列表（如密码套件）转成多行清单，其余保持原样。"""
    s = str(value)
    if " | " in s:
        parts = [p.strip() for p in s.split(" | ")]
        return "\n".join("    %d. %s" % (i, p) for i, p in enumerate(parts, 1))
    return s


def event_detail_text(ev) -> str:
    """点击时序图消息后，生成供下方面板展开的关键参数文本。"""
    dir_txt = "客户端 → 服务端" if ev.get("dir") == "c->s" else "服务端 → 客户端"
    lines = ["〔#%s〕 %s" % (ev.get("seq", ""), ev.get("title", "")),
             "方向：%s    协议：%s" % (dir_txt, ev.get("kind", ""))]
    if ev.get("no") is not None:
        lines.append("原始包号：%s" % ev["no"])
    if ev.get("ts") is not None:
        lines.append("时间(s)：%.4f" % ev["ts"])
    lines.append("")
    fields = ev.get("fields") or []
    if fields:
        lines.append("关键参数：")
        for k, v in fields:
            if k == "der_hex":
                continue
            s = str(v)
            if " | " in s:
                parts = [x for x in s.split(" | ") if x.strip()]
                k_disp = k[:-5] if k.endswith("_full") or k.endswith("_list") else k
                lines.append("  %s（%d 项）：" % (k_disp, len(parts)))
                lines.append(_wrap_field(s))
            else:
                lines.append("  %s：%s" % (k, s))
    else:
        lines.append("摘要：%s" % ev.get("detail", ""))
    return "\n".join(lines)


def _negotiation_stage(title, side):
    """把消息映射到参考协商序列的阶段号，用于跨方向排序。

    阶段与参考序列一致，同阶段内保持各方向原有的流内顺序：
      0 ClientHello → 1 ServerHello/Certificate/ServerKeyExchange/CertificateRequest
      → 2 ServerHelloDone → 3 ClientCertificate/ClientKeyExchange/CertificateVerify
      → 4 ChangeCipherSpec(客户端) → 5 Finished(客户端)
      → 6 ChangeCipherSpec(服务端) → 7 Finished(服务端)
    """
    if title == "ClientHello":
        return 0
    if title in ("ServerHello", "EncryptedExtensions", "Certificate", "ServerKeyExchange",
                 "CertificateRequest", "NewSessionTicket"):
        if title == "Certificate" and side == "client":
            return 3
        return 1
    if title == "ServerHelloDone":
        return 2
    if title in ("ClientCertificate", "ClientKeyExchange", "CertificateVerify"):
        return 3
    if title == "ChangeCipherSpec":
        return 4 if side == "client" else 6
    if title == "Finished":
        return 5 if side == "client" else 7
    return 9


def negotiation_events(app_events):
    """只保留密钥协商过程中存在信息的关键数据包。

    规则：
      - 无内容的消息一律不展示（fields 为空且 detail 为空，如空载荷的
        ServerHelloDone、HelloRequest 等），视图只显示有信息的包；
      - 按参考协商序列（ClientHello → … → Server Finished）跨方向排序；
      - 展示窗口：从 ClientHello 起到最后一个 Finished 截止。
    """
    evs = []
    for e in app_events:
        if not e.get("fields") and not (e.get("detail") or "").strip():
            continue
        evs.append(e)
    evs.sort(key=lambda e: _negotiation_stage(e.get("title") or "",
                                              "client" if e.get("dir") == "c->s" else "server"))
    end = len(evs)
    for i, e in enumerate(evs):
        if e.get("title") == "Finished":
            end = i + 1
    return evs[:end]


def build_sequence(app_events, max_events: int = 120):
    """把应用层协商消息过滤、定界并统一编号成最终时序图事件列表。

    不再并入 TCP 三次握手（SYN / SYN-ACK / ACK），仅展示 ClientHello 起、
    到服务端 Finished 止的关键协商数据包。"""
    evs = negotiation_events(list(app_events or []))
    if len(evs) > max_events:
        evs = evs[:max_events]
        evs.append({"seq": 0, "dir": "c->s", "kind": "…", "title": "…",
                    "detail": "其余 %d 条消息略去" % (len(evs) - max_events), "no": None, "ts": None})
    for i, e in enumerate(evs, 1):
        e["seq"] = i
    return evs


def _flow_completed(evs):
    """流是否完成密钥协商：出现 Finished，或客户端与服务端均已发出 ChangeCipherSpec。

    真实抓包中 Finished 常为加密载荷（TLS1.2/TLCP 在 CCS 之后才加密），
    因此以「双向 CCS 均已切换加密」作为完成判据；同时兼容能解出明文 Finished 的情况。
    """
    if any(e.get("title") == "Finished" for e in evs):
        return True
    has_c = any(e.get("dir") == "c->s" and e.get("title") == "ChangeCipherSpec" for e in evs)
    has_s = any(e.get("dir") == "s->c" and e.get("title") == "ChangeCipherSpec" for e in evs)
    return has_c and has_s


def first_completed_key(flows):
    """按抓包顺序选出「第一个完成密钥协商」的流（完成点 = 协商相关消息的最大包号最小者）。

    抓包通常在首次协商结束后即停止，因此第一个完成协商的流就是本次抓包想展示的内容。
    返回该流 key；若没有任何流完成协商，返回 None（调用方应回退到全部会话）。
    """
    best = None
    for key, fl in (flows or {}).items():
        evs = negotiation_events(messages_to_events(fl.get("messages") or [], fl.get("cdir")))
        if not _flow_completed(evs):
            continue
        fin = max((e.get("no") for e in evs if e.get("no") is not None), default=None)
        if fin is None:
            continue
        if best is None or fin < best[1]:
            best = (key, fin)
    return best[0] if best else None


def flow_combo_items(flows, only_first: bool = False):
    """把 {flow_key: fl} 转成 (显示文本, key) 列表，按握手消息数降序。

    only_first=True 时只保留按包序第一个完成密钥协商的会话（其余 ip 的协商忽略）。
    """
    if only_first:
        k = first_completed_key(flows)
        if k is None:
            return []
        fl = flows[k]
        n = len(fl.get("messages") or [])
        return [("%s → %s  [%s] · %d 条握手消息" % (
            fl.get("client"), fl.get("server"), fl.get("proto", "?"), n), k)]
    items = []
    for key, fl in flows.items():
        n = len(fl.get("messages") or [])
        items.append(("%s → %s  [%s] · %d 条握手消息" % (
            fl.get("client"), fl.get("server"), fl.get("proto", "?"), n), key))
    items.sort(key=lambda it: -(len(flows[it[1]].get("messages") or [])))
    return items


# ------------------------------------------------------------ 协商集（TLS 首次 / TLCP 双向）

def _build_raw_events(fl):
    """流的原始应用层事件（未过滤，供双向鉴别等判定使用）。"""
    return messages_to_events(fl.get("messages") or [], fl.get("cdir"))


def _phase_events(fl, split="all"):
    """取一个流的协商关键事件（已完成过滤与阶段排序）。

    split="phase1" 时只取到客户端出示证书之前（服务端鉴别段）；
    split="phase2" 时只取客户端出示证书起（客户端鉴别段）；否则取全部。
    """
    evs = negotiation_events(_build_raw_events(fl))
    if split == "phase1":
        end = _client_cert_start(evs)
        return evs if end is None else evs[:end]
    if split == "phase2":
        start = _client_cert_start(evs)
        return [] if start is None else evs[start:]
    return evs


def _client_cert_start(evs):
    """客户端出示自身证书的事件下标（第一个 c->s 的 Certificate / CertificateVerify），无则 None。"""
    for i, e in enumerate(evs):
        t = e.get("title")
        if e.get("dir") == "c->s" and t in ("Certificate", "CertificateVerify"):
            return i
    return None


def _fin_no(evs):
    """协商完成点包号：协商相关消息的最大原始包号（无则 None）。"""
    return max((e.get("no") for e in evs if e.get("no") is not None), default=None)


def _srv_ip(fl):
    """服务端地址的 IP 部分（用于把同一对端的不同端口流分到一组）。"""
    s = fl.get("server") or ""
    if ":" in s:
        ip, port = s.rsplit(":", 1)
        if port.isdigit():
            return ip
    return s


def _has_client_auth(fl, evs=None):
    """会话是否真正实现了（反向）客户端身份鉴别：
    服务端请求客户端证书（CertificateRequest），或客户端在 c->s 方向出示自身证书 / 证书验证。
    evs 缺省时用未过滤的原始事件判定（避免 CertificateRequest 等空载荷消息被展示过滤丢弃）。"""
    if evs is None:
        evs = _build_raw_events(fl)
    for e in evs:
        t = e.get("title")
        d = e.get("dir")
        if t == "CertificateRequest":
            return True
        if t == "Certificate" and d == "c->s":
            return True
        if t == "CertificateVerify" and d == "c->s":
            return True
    return False


PHASE1_LABEL = "① 第一次协商 · 服务端出示证书（客户端鉴别服务端）"
PHASE2_LABEL = "② 反向协商 · 客户端出示证书（服务端鉴别客户端）"


def negotiation_sets(flows):
    """按抓包事实选取要展示的「协商集」（供主界面会话下拉框与时序图使用）。

    规则：
      - 完成协商的 TLCP 流按对端 IP 分组；组内若存在客户端出示自身证书或服务端请求客户端
        证书（CertificateRequest / c->s 的 Certificate / CertificateVerify），说明确实做了
        「双向身份鉴别」→ 该对端展示两段协商：
          ① 服务端鉴别（包序第一个完成）　② 客户端鉴别（客户端出示证书，包序第一个完成）。
        否则只展示单段（包序第一个完成）。
      - TLS / SSH 只取包序上第一个完成协商的会话（遇到 TLS 只取第一次协商过程）。

    返回 list(set)，set 形如
      {"label","proto","client","server","phases":[{"label","key","client","server"}, …]}
    """
    completed = []
    for key, fl in (flows or {}).items():
        evs = _phase_events(fl)
        fin = _fin_no(evs)
        if not _flow_completed(evs) or fin is None:
            continue
        completed.append((key, fl, evs, fin))
    if not completed:
        return []
    completed.sort(key=lambda x: x[3])

    peers, order = {}, []
    for key, fl, evs, fin in completed:
        if fl.get("proto") == "TLCP":
            srv = _srv_ip(fl)
            if srv not in peers:
                peers[srv] = []
                order.append(srv)
            peers[srv].append((key, fl, evs, fin))

    used = set()
    sets_ = []
    for srv in order:
        items = peers[srv]
        key0, fl0, evs0, fin0 = items[0]
        ca = next((it for it in items if _has_client_auth(it[1])), None)
        bidir = ca is not None
        if bidir and ca[0] != key0:
            # 双向鉴别发生在两条独立流（对端反向连接）：①服务端鉴别 ②反向客户端鉴别
            ck, cfl, cevs, cfin = ca
            phases = [{"label": PHASE1_LABEL, "key": key0,
                       "split": "all",
                       "client": fl0.get("client"), "server": fl0.get("server")},
                      {"label": PHASE2_LABEL, "key": ck,
                       "split": "all",
                       "client": cfl.get("client"), "server": cfl.get("server")}]
            used.add(ck)
        elif bidir:
            # 双向鉴别发生在同一条流内：①服务端鉴别（客户端出示证书前）②客户端鉴别（出示证书起）
            phases = [{"label": PHASE1_LABEL, "key": key0,
                       "split": "phase1",
                       "client": fl0.get("client"), "server": fl0.get("server")},
                      {"label": PHASE2_LABEL, "key": key0,
                       "split": "phase2",
                       "client": fl0.get("client"), "server": fl0.get("server")}]
        else:
            phases = [{"label": PHASE1_LABEL, "key": key0,
                       "split": "all",
                       "client": fl0.get("client"), "server": fl0.get("server")}]
        used.add(key0)
        sets_.append({
            "label": "%s ⇄ %s · TLCP %s" % (
                fl0.get("client"), fl0.get("server"),
                "双向身份鉴别（2 段协商）" if bidir else "协商（单向）"),
            "proto": "TLCP", "client": fl0.get("client"), "server": fl0.get("server"),
            "phases": phases,
        })
    # TLS / SSH：只取包序第一个完成协商的会话（TLCP 已在上方成组，不再单列）
    for key, fl, evs, fin in completed:
        if key in used or fl.get("proto") == "TLCP":
            continue
        proto = fl.get("proto", "?")
        sets_.append({
            "label": "%s → %s · %s 协商（首次）" % (fl.get("client"), fl.get("server"), proto),
            "proto": proto, "client": fl.get("client"), "server": fl.get("server"),
            "phases": [{"label": "密钥协商", "key": key,
                        "client": fl.get("client"), "server": fl.get("server")}],
        })
        break
    # 不改变相对抓包顺序（按各阶段完成点最小包号升序）
    sets_.sort(key=lambda s: _set_min_fin(s, flows))
    return sets_


def _set_min_fin(aset, flows):
    return min((_fin_no(_phase_events(flows.get(p["key"] or {})))
                for p in aset.get("phases") or [] if p.get("key") in flows), default=0)


def fallback_sets(flows):
    """没有任何流完成协商时的兜底：把所有能解出握手消息的流各视作一个单段协商集。"""
    sets_ = []
    for key, fl in (flows or {}).items():
        if not _phase_events(fl):
            continue
        proto = fl.get("proto", "?")
        sets_.append({
            "label": "%s → %s · %s 协商" % (fl.get("client"), fl.get("server"), proto),
            "proto": proto, "client": fl.get("client"), "server": fl.get("server"),
            "phases": [{"label": "密钥协商", "key": key,
                        "client": fl.get("client"), "server": fl.get("server")}],
        })
    return sets_


def set_to_events(flows, aset, max_events: int = 120):
    """把协商集展开为时序图事件列表：每阶段前插入一条全宽阶段横幅（kind='phase'），
    其下紧跟该阶段的关键协商消息（已按参考协商序列排序）。"""
    evs = []
    phases = aset.get("phases") or []
    multi = len(phases) > 1
    for ph in phases:
        fl = flows.get(ph.get("key")) or {}
        sub = "%s ⇄ %s" % (ph.get("client") or "", ph.get("server") or "")
        if multi:
            # 单段协商不插横幅（保持原有卡片索引不变）；双向鉴别才用横幅区分两段
            evs.append({"kind": "phase", "dir": "center", "title": ph.get("label", "协商"),
                        "detail": sub, "no": None, "ts": None, "fields": []})
        evs.extend(_phase_events(fl, ph.get("split", "all")))
    if len(evs) > max_events:
        evs = evs[:max_events]
        evs.append({"kind": "…", "dir": "c->s", "title": "…",
                    "detail": "其余 %d 条消息略去" % (len(evs) - max_events),
                    "no": None, "ts": None, "fields": []})
    for i, e in enumerate(evs, 1):
        e["seq"] = i
    return evs


def negotiation_set_html(flows, aset, proto=""):
    """协商集总结横幅：逐阶段输出白底分节（阶段①版式/套件/服务端证书；
    阶段②额外汇总客户端出示的自身证书与 CertificateVerify）。"""
    from html import escape
    boxes = []
    for i, ph in enumerate(aset.get("phases") or []):
        fl = flows.get(ph.get("key")) or {}
        evs = _phase_events(fl)
        inner = _summary_inner(ph.get("client") or "", ph.get("server") or "", evs,
                               aset.get("proto", fl.get("proto", proto)))
        if _has_client_auth(fl, evs):
            inner = _client_auth_inner(evs) + "<br>----<br>" + inner
        badge = "第 %d 段" % (i + 1)
        boxes.append(
            "<div style='background:#FFFFFF;border:1px solid #E5E7EB;border-radius:8px;"
            "padding:8px 12px;font-size:12px;line-height:1.7;color:#374151'>"
            "<span style='background:#EEF2FF;color:#4338CA;border-radius:4px;padding:1px 6px;"
            "font-weight:bold'>%s</span>　<span style='color:#1F2937;font-weight:bold'>%s</span>"
            "<span style='color:#78909C'>　%s</span><br>%s</div>"
            % (escape(badge), escape(ph.get("label") or "协商"),
               escape("%s ⇄ %s" % (ph.get("client") or "", ph.get("server") or "")), inner))
    if not boxes:
        boxes.append("<span style='color:#B71C1C'>未识别到协商消息。</span>")
    return "\n".join(boxes)
