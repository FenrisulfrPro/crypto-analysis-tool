# -*- coding: utf-8 -*-
"""协议数据包逐包 / 逐流深度解析（Wireshark 式字段视图）

覆盖：
  - 二层：Ethernet / ARP
  - 三层：IPv4 / IPv6
  - 四层：TCP / UDP
  - 应用层：DNS / HTTP / SSH / TLS / TLCP（国密 SSL）
供主界面「协议分析 (pcap)」页点击数据包行时展示协议数据（含证书主体、签名算法、签名值等）。
"""
import struct
from collections import OrderedDict

from scapy.all import IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw

try:
    from modules import tls_parser as _tl
except ImportError:  # 直接运行本文件时
    import tls_parser as _tl

# ---------------------------------------------------------------- 工具

def _fmt_hex(data: bytes, limit: int = 96) -> str:
    h = data.hex()
    if len(h) > limit * 2:
        h = h[:limit * 2] + "…"
    return h


def _mac(addr) -> str:
    """把 MAC 地址（scapy 字符串或整数）规整为 'AA-BB-CC-DD-EE-FF' 形式。"""
    s = str(addr)
    try:
        s = s.replace('.', ':')
        hexs = s.split(':')
        return '-'.join('%02X' % int(h, 16) for h in hexs)
    except Exception:
        return s


def _txt(b: bytes) -> str:
    try:
        return b.decode('utf-8', 'replace')
    except Exception:
        return b.hex()


def hexdump(data: bytes, max_bytes: int = 8192) -> str:
    """16 字节一行的标准 Hex + ASCII 转储（分方向显示时便于对照）。"""
    if max_bytes and len(data) > max_bytes:
        data = data[:max_bytes]
        truncated = True
    else:
        truncated = False
    lines = []
    for off in range(0, len(data), 16):
        chunk = data[off:off + 16]
        hx = ' '.join('%02X' % b for b in chunk)
        asc = ''.join(chr(b) if 0x20 <= b < 0x7f else '.' for b in chunk)
        lines.append('%08X  %-47s  |%s|' % (off, hx, asc))
    suffix = "\n…（数据已截断，共 %d 字节显示前 %d 字节）" % (len(data), max_bytes) if truncated else ""
    return "\n".join(lines) + suffix


# ---------------------------------------------------------------- 应用层识别

HTTP_METHODS = ("GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "OPTIONS ", "CONNECT ", "PATCH ", "PROPFIND ")


def detect_app_layer(payload: bytes) -> str:
    """识别应用层协议：DNS / HTTP / SSH / TLCP / TLS / Other。"""
    if not payload:
        return ""
    if payload[:4] == b"SSH-":
        return "SSH"
    if payload and payload[0] in (0x14, 0x15, 0x16, 0x17, 0x18) and len(payload) >= 3:
        ver = struct.unpack(">H", payload[1:3])[0]
        if ver in (0x0001, 0x0002, 0x0101):
            return "TLCP"
        if 0x0300 <= ver <= 0x0305:
            return "TLS"
    if payload[:4].upper() in (b"HTTP",) or payload[:4] in (b"HTTP",):
        return "HTTP"
    for m in HTTP_METHODS:
        if payload.startswith(m.encode()):
            return "HTTP"
    return "OTHER"


# ================================================================ HTTP
def parse_http(payload: bytes) -> OrderedDict:
    d = OrderedDict()
    try:
        head, _, body = payload.partition(b"\r\n\r\n")
        if not head:
            head = payload
        head_txt = head.decode('utf-8', 'replace')
        lines = head_txt.split("\r\n")
        d["请求/响应行"] = lines[0] if lines else ""
        shown = 0
        for ln in lines[1:]:
            if not ln.strip():
                continue
            d["头部 %d" % shown] = ln
            shown += 1
            if shown >= 12:
                break
        if body:
            d["Body 大小"] = "%d 字节" % len(body)
    except Exception as e:
        d["error"] = str(e)
    return d


# ================================================================ DNS
def parse_dns(pkt) -> OrderedDict:
    d = OrderedDict()
    try:
        dl = pkt[DNS]
        d["Transaction ID"] = "0x%04X" % dl.id
        flags = []
        if dl.qr:
            flags.append("响应")
        else:
            flags.append("查询")
        flags.append("opcode=%d" % dl.opcode)
        if dl.aa:
            flags.append("AA")
        if dl.rd:
            flags.append("RD")
        if dl.ra:
            flags.append("RA")
        d["标志"] = " ".join(flags)
        d["问题数 QD"] = dl.qdcount
        d["应答数 AN"] = dl.ancount
        if dl.qd:
            try:
                d["问题"] = "%s (%s)" % (dl.qd.qname.decode('utf-8', 'replace'), "type=%d" % dl.qd.qtype)
            except Exception:
                d["问题"] = str(dl.qd)
        if dl.an:
            ans = []
            for a in dl.an:
                try:
                    ans.append(str(a.rdata))
                except Exception:
                    ans.append("(rdata)")
            d["应答"] = ", ".join(ans[:8])
    except Exception:
        pass
    return d


# ================================================================ SSH
def _ssh_str(buf: bytes, off: int):
    """读取 SSH string：uint32 长度 + 内容。返回 (content, next_off)。"""
    if off + 4 > len(buf):
        return b"", len(buf)
    n = int.from_bytes(buf[off:off + 4], "big")
    off += 4
    return buf[off:off + n], off + n


SSH_MSG_NAME = {
    1: "SSH_MSG_DISCONNECT", 2: "SSH_MSG_IGNORE", 3: "SSH_MSG_UNIMPLEMENTED",
    4: "SSH_MSG_DEBUG", 5: "SSH_MSG_SERVICE_REQUEST", 6: "SSH_MSG_SERVICE_ACCEPT",
    20: "SSH_MSG_KEXINIT", 21: "SSH_MSG_NEWKEYS",
    30: "SSH_MSG_KEXDH_INIT", 31: "SSH_MSG_KEXDH_REPLY",
    80: "SSH_MSG_USERAUTH_REQUEST", 90: "SSH_MSG_CHANNEL_OPEN",
    98: "SSH_MSG_CHANNEL_DATA", 100: "SSH_MSG_CHANNEL_EOF",
}

# 只有 SSH 客户端会发起的消息（用于在无 SYN 抓包时判定客户端方向）
SSH_CLIENT_MARKERS = (
    "SSH_MSG_KEXDH_INIT", "SSH_MSG_KEX_ECDH_INIT",
    "SSH_MSG_KEX_DH_GEX_REQUEST", "SSH_MSG_KEX_DH_GEX_INIT",
    "SSH_MSG_USERAUTH_REQUEST",
)

# 只有 SSH 服务端会回的消息（当只抓到服务端方向流量时，据此反推客户端）
SSH_SERVER_MARKERS = (
    "SSH_MSG_KEXDH_REPLY", "SSH_MSG_KEX_ECDH_REPLY",
    "SSH_MSG_KEX_DH_GEX_GROUP", "SSH_MSG_KEX_DH_GEX_REPLY",
    "SSH_MSG_SERVICE_ACCEPT", "SSH_MSG_USERAUTH_SUCCESS",
    "SSH_MSG_USERAUTH_FAILURE", "SSH_MSG_CHANNEL_OPEN_CONFIRMATION",
)


def parse_ssh_kexinit(msg: bytes) -> OrderedDict:
    """SSH_MSG_KEXINIT(20)：cookie + 10 个 name-list（算法协商）。

    列表字段输出两版：`label` 为完整逗号串（供协商计算与展示），
    `label_list` 为逐项清单（供时序图卡片多行展示，不截断）。"""
    d = OrderedDict()
    if len(msg) < 17:
        return d
    cookie = msg[1:17]
    d["cookie"] = _fmt_hex(cookie, 32)
    off = 17
    names = ["kex_algorithms", "server_host_key_algorithms",
             "encryption c->s", "encryption s->c",
             "mac c->s", "mac s->c",
             "compression c->s", "compression s->c",
             "languages c->s", "languages s->c"]
    for label in names:
        try:
            val, off = _ssh_str(msg, off)
        except Exception:
            break
        if not val:
            d[label] = "(空)"
            continue
        items = [x.decode('utf-8', 'replace') for x in val.split(b",") if x]
        d[label] = ", ".join(items)
        d[label + "_list"] = " | ".join(items)
    return d


def split_ssh_packets(data: bytes):
    """把 SSH 二进制包序列拆成列表。条目为 (msg_type, full_payload, offset)。"""
    pkts = []
    off = 0
    while off + 5 <= len(data):
        pkt_len = int.from_bytes(data[off:off + 4], "big")
        if pkt_len <= 0 or pkt_len > 4096 or off + 4 + pkt_len > len(data):
            break
        pad_len = data[off + 4]
        payload = data[off + 5:off + 4 + pkt_len - pad_len]
        if payload:
            pkts.append((payload[0], payload, off))
        off += 4 + pkt_len
    return pkts


def _ts_at(tsmap, off):
    """取字节偏移 off 处最近一段的起始时间戳（tsmap: offset→ts）。"""
    ts = None
    for p0, t0 in sorted(tsmap.items()):
        if p0 <= off:
            ts = t0
        else:
            break
    return ts


def parse_ssh_kexdh_init(msg: bytes) -> OrderedDict:
    """SSH_MSG_KEXDH_INIT(30)：string e（客户端椭圆曲线公钥 / 交换值）。"""
    d = OrderedDict()
    d["消息"] = "SSH_MSG_KEXDH_INIT"
    off = 1
    if off + 4 <= len(msg):
        n = int.from_bytes(msg[off:off + 4], "big")
        off += 4
        e = msg[off:off + n]
        d["客户端交换值"] = e.hex().upper() if e else "(空)"
        d["交换值长度"] = "%d 字节" % len(e)
        if len(e) >= 32:
            d["客户端交换值"] = e.hex().upper()
    d["载荷长度"] = "%d 字节" % (len(msg) - 1)
    return d


def parse_ssh_kexdh_reply(msg: bytes) -> OrderedDict:
    """SSH_MSG_KEXDH_REPLY(31)：string K_S（主机密钥）｜string f（服务端交换值）｜
    string 签名（含签名算法名与签名值）。"""
    d = OrderedDict()
    d["消息"] = "SSH_MSG_KEXDH_REPLY"
    off = 1

    def _rs():
        nonlocal off
        if off + 4 > len(msg):
            raise ValueError("KEXDH_REPLY 截断")
        n = int.from_bytes(msg[off:off + 4], "big")
        off += 4
        v = msg[off:off + n]
        off += n
        return v

    try:
        ks = _rs()
        f = _rs()
        sig = _rs()
        d["服务端主机密钥"] = ks.hex().upper() if ks else "(空)"
        d["服务端主机密钥长度"] = "%d 字节" % len(ks)
        # K_S 首串即主机密钥算法格式（如 ssh-rsa / ssh-ed25519）
        if len(ks) >= 4:
            kn = int.from_bytes(ks[:4], "big")
            if 4 + kn <= len(ks) and kn > 0:
                fmt = ks[4:4 + kn].decode('utf-8', 'replace')
                d["服务端主机密钥格式"] = fmt
        d["服务端交换值"] = f.hex().upper() if f else "(空)"
        if len(sig) >= 4:
            n = int.from_bytes(sig[:4], "big")
            algo = sig[4:4 + n]
            if algo:
                d["服务端签名算法"] = algo.decode('utf-8', 'replace')
                raw = sig[4 + n:]
                # 部分实现签名内还带一层 mpint 长度前缀
                if len(raw) >= 4:
                    sn = int.from_bytes(raw[:4], "big")
                    if 0 < sn == len(raw) - 4:
                        raw = raw[4:]
                d["服务端签名值"] = raw.hex().upper() if raw else "(空)"
        d["载荷长度"] = "%d 字节" % (len(msg) - 1)
    except Exception as e:
        d["错误"] = str(e)
    return d


def _frame_ranges(nums):
    """把帧号列表压成 Wireshark 式范围串，如 '16..39 46..48 51..53 55..57'。"""
    nums = sorted(set(int(n) for n in nums if n is not None))
    if not nums:
        return ""
    out = []
    start = prev = nums[0]
    for n in nums[1:]:
        if n == prev + 1:
            prev = n
            continue
        out.append("%d..%d" % (start, prev) if start != prev else str(start))
        start = prev = n
    out.append("%d..%d" % (start, prev) if start != prev else str(start))
    return " ".join(out)


def parse_ssh_stream(data: bytes, direction: str, segs=None, base=0, tsmap=None):
    """解析一条方向上重组的 SSH 流，返回消息列表。data 可含版本行 + 二进制包。

    segs: [(起始TCP序号, 载荷长度, 包号)]，用于给每条消息标注其所在抓包包号；
    base: 该方向重组流的起始 TCP 序号（字节偏移 0 对应的序号）。"""
    tsmap = tsmap or {}
    msgs = []
    off = 0
    if data.startswith((b"SSH-", b"CSSH-")):
        nl = data.find(b"\n")
        line = data[:nl].decode('utf-8', 'replace') if nl >= 0 else _txt(data[:64])
        msgs.append({"dir": direction, "proto": "SSH", "type": "SSH 版本交换",
                     "summary": line, "ts": _ts_at(tsmap, 0),
                     "no": _tl._msg_packet_no(segs, base),
                     "fields": OrderedDict([("version_line", line)])})
        off = nl + 1 if nl >= 0 else 0
    pkt_off = off
    for mt, payload, _boff in split_ssh_packets(data[off:]):
        pno = _tl._msg_packet_no(segs, base + pkt_off + _boff)
        ts = _ts_at(tsmap, pkt_off + _boff)
        if mt == 20:
            fd = parse_ssh_kexinit(payload)
            fd["timestamp"] = (str(ts) if ts is not None else "")
            kx = (fd.get("kex_algorithms") or "").split(",")[0]
            msgs.append({"dir": direction, "proto": "SSH", "type": "SSH_MSG_KEXINIT",
                         "summary": "算法协商（首选 kex=%s）" % kx,
                         "ts": ts, "no": pno, "fields": fd})
        elif mt == 30:
            fd = parse_ssh_kexdh_init(payload)
            ev = fd.get("客户端交换值", "")
            msgs.append({"dir": direction, "proto": "SSH", "type": "SSH_MSG_KEXDH_INIT",
                         "summary": "客户端密钥交换（交换值 %s…）" % ev[:24],
                         "ts": ts, "no": pno, "fields": fd})
        elif mt == 31:
            fd = parse_ssh_kexdh_reply(payload)
            alg = fd.get("服务端签名算法") or "?"
            sig = fd.get("服务端签名值") or ""
            msgs.append({"dir": direction, "proto": "SSH", "type": "SSH_MSG_KEXDH_REPLY",
                         "summary": "服务端密钥交换（签名算法=%s，签名值 %s…）" % (alg, sig[:24]),
                         "ts": ts, "no": pno, "fields": fd})
        else:
            nm = SSH_MSG_NAME.get(mt, "SSH_MSG_%d" % mt)
            msgs.append({"dir": direction, "proto": "SSH", "type": nm,
                         "summary": nm + ("（载荷 %d 字节）" % (len(payload) - 1)),
                         "ts": ts, "no": pno,
                         "fields": OrderedDict([
                             ("message", nm),
                             ("payload_len", len(payload) - 1),
                             ("payload_hex", _fmt_hex(payload[1:26], 48)),
                         ])})
    return msgs


def ssh_client_direction(f):
    """按重组流字典 f 判定 SSH 客户端方向，返回 'ab' 或 'ba'。

    判定依据（可靠性递减）：SYN 发起方 → 客户端特有消息（KEXDH_INIT 等）
    → 若只有服务端特有消息（KEXDH_REPLY 等）则另一方为客户端
    → 版本行先被捕获的一方（SSH 客户端先发识别字符串）。
    """
    ab, ba = f.get("ab", b""), f.get("ba", b"")
    init = f.get("init", "")
    if init == "ab":
        return "ab"
    if init == "ba":
        return "ba"
    msgs = []
    if ab.startswith(b"SSH-"):
        msgs.extend(parse_ssh_stream(ab, "A->B"))
    if ba.startswith(b"SSH-"):
        msgs.extend(parse_ssh_stream(ba, "B->A"))
    c = next((m["dir"] for m in msgs if m.get("type") in SSH_CLIENT_MARKERS), None)
    if c is not None:
        return "ab" if c == "A->B" else "ba"
    s = next((m["dir"] for m in msgs if m.get("type") in SSH_SERVER_MARKERS), None)
    if s is not None:
        return "ba" if s == "A->B" else "ab"
    a_min = min(f["ab_num"].values()) if f.get("ab_num") else None
    b_min = min(f["ba_num"].values()) if f.get("ba_num") else None
    if a_min is not None and (b_min is None or a_min < b_min):
        return "ab"
    return "ba"


# 逐类别列出 KEXINIT 中可协商的算法字段（RFC 4253 §7.1：取客户端列表中服务端也支持的第一项）
_NEG_FIELDS = (
    ("kex_algorithms", "密钥交换方法 (kex)"),
    ("server_host_key_algorithms", "主机密钥算法 (host key)"),
    ("encryption c->s", "加密算法 c→s"),
    ("encryption s->c", "加密算法 s→c"),
    ("mac c->s", "MAC 算法 c→s"),
    ("mac s->c", "MAC 算法 s→c"),
    ("compression c->s", "压缩算法 c→s"),
    ("compression s->c", "压缩算法 s→c"),
)


def _kex_list(value):
    """把 KEXINIT 字段值（逗号分隔，可能带 '…（共 N 项）' 尾巴）还原成列表。"""
    if not value or value == "(空)":
        return []
    items = [x.strip() for x in str(value).split(",")]
    if items and "（共" in items[-1]:
        items[-1] = items[-1].split("（共", 1)[0].strip()
    return [x for x in items if x]


def _ssh_negotiation_summary(msgs, cdir_txt, stream_no=None, frames=None):
    """生成一条“SSH 协商算法”综合消息插入时序图（每个 SSH 流都有，含不完整流）。

    汇总：SSH 版本 / 会话完整状态 / 双端最终选定算法 / 服务端支持的算法 /
    密钥协商参数（客户端交换值、服务端交换值、服务端签名算法、服务端签名值）/
    Wireshark 定位（tcp.stream、精确帧过滤器、帧数量）。
    cdir_txt 为客户端方向（'A->B'/'B->A'）。"""
    if not msgs:
        return None
    ck = next((m for m in msgs if m.get("dir") == cdir_txt and m.get("type") == "SSH_MSG_KEXINIT"), None)
    sk = next((m for m in msgs if m.get("dir") != cdir_txt and m.get("type") == "SSH_MSG_KEXINIT"), None)
    newkeys_c = any(m.get("type") == "SSH_MSG_NEWKEYS" and m.get("dir") == cdir_txt for m in msgs)
    newkeys_s = any(m.get("type") == "SSH_MSG_NEWKEYS" and m.get("dir") != cdir_txt for m in msgs)
    complete = bool(ck and sk and newkeys_c and newkeys_s)

    fd = OrderedDict()
    vers = [(m.get("fields") or {}).get("version_line", "") for m in msgs if m.get("type") == "SSH 版本交换"]
    fd["SSH 版本"] = "SSH 2.0" if any("2.0" in str(v) for v in vers) else (vers[0] if vers else "SSH")
    fd["会话状态"] = "完整" if complete else "不完整"

    if ck and sk:
        ckv = ck.get("fields") or {}
        skv = sk.get("fields") or {}
        for field, name in _NEG_FIELDS:
            cl = _kex_list(ckv.get(field))
            sl = _kex_list(skv.get(field))
            fd[name] = next((x for x in cl if x in sl), "-") if cl else "-"

        def _sup(field):
            return " | ".join(_kex_list(skv.get(field))) or "-"

        fd["服务端支持·密钥交换算法"] = _sup("kex_algorithms")
        fd["服务端支持·加密算法"] = _sup("encryption s->c")
        fd["服务端支持·完整性算法"] = _sup("mac s->c")
    else:
        for _f, name in _NEG_FIELDS:
            fd[name] = "-"
        # 不完整会话（缺客户端 KEXINIT）：以服务端 KEXINIT 首选主机密钥算法作“服务端签名”最佳估计
        if sk:
            hk = _kex_list((sk.get("fields") or {}).get("server_host_key_algorithms"))
            if hk:
                fd["主机密钥算法 (host key)"] = hk[0]

    init = next((m for m in msgs if m.get("type") == "SSH_MSG_KEXDH_INIT"), None)
    rep = next((m for m in msgs if m.get("type") == "SSH_MSG_KEXDH_REPLY"), None)
    fd["客户端交换值"] = (init.get("fields") or {}).get("客户端交换值") or "-" if init else "-"
    if rep:
        rf = rep.get("fields") or {}
        fd["服务端交换值"] = rf.get("服务端交换值") or "-"
        fd["服务端主机密钥"] = rf.get("服务端主机密钥") or "-"
        fd["服务端主机密钥格式"] = rf.get("服务端主机密钥格式") or "-"
        fd["服务端签名算法"] = rf.get("服务端签名算法") or "-"
        fd["服务端签名值"] = rf.get("服务端签名值") or "-"
    else:
        fd["服务端交换值"] = "-"
        fd["服务端主机密钥"] = "-"
        fd["服务端主机密钥格式"] = "-"
        fd["服务端签名算法"] = "-"
        fd["服务端签名值"] = "-"

    if stream_no is not None:
        fd["会话过滤器"] = "tcp.stream == %d" % stream_no
    if frames:
        fd["精确帧过滤器"] = "frame.number in {%s}" % _frame_ranges(frames)
        fd["帧数量"] = "%d" % len(frames)

    nos = [m.get("no") for m in msgs if m.get("no") is not None]
    no = max(nos) if nos else None
    kex = fd.get("密钥交换方法 (kex)") or "-"
    enc = fd.get("加密算法 c→s") or "-"
    mac = fd.get("MAC 算法 c→s") or "-"
    hk = fd.get("主机密钥算法 (host key)") or "-"
    return {
        "dir": cdir_txt, "proto": "SSH", "type": "SSH 协商算法",
        "summary": "%s · %s：密钥交换=%s，加密=%s，完整性=%s，服务端签名=%s"
                   % (fd.get("SSH 版本"), fd.get("会话状态"), kex, enc, mac, hk),
        "no": no, "ts": None,
        "fields": fd,
    }


def parse_ssh_packet(payload: bytes) -> OrderedDict:
    """单包 SSH 解析：版本行 + 本包内的二进制包（可能不完整）。"""
    d = OrderedDict()
    if payload.startswith(b"SSH-"):
        nl = payload.find(b"\n")
        d["版本交换"] = payload.split(b"\n")[0].decode('utf-8', 'replace')
        rest = payload[nl + 1:] if nl >= 0 else b""
        if rest:
            msgs = [m for m in parse_ssh_stream(rest, "?")]
            if msgs:
                for i, m in enumerate(msgs):
                    d["包 %d: %s" % (i + 1, m["type"])] = m["summary"]
    return d


# ================================================================ TLS / TLCP 单包
def parse_tls_packet(payload: bytes) -> OrderedDict:
    """单包 TLS / TLCP 解析：按 Record 拆分，握手消息给出字段；若跨包则提示。"""
    proto, records = _tl.split_proto_records(payload)
    d = OrderedDict()
    d["协议"] = "TLCP（国密 SSL）" if proto == "TLCP" else "TLS"
    if not records:
        d["说明"] = "未识别到完整记录头"
        return d
    rec_names = _tl.TLCP_RECORD_TYPE if proto == "TLCP" else _tl.TLS_RECORD_TYPE
    handshake_count = 0
    for i, (typ, ver, rec_payload, off) in enumerate(records):
        name = rec_names.get(typ, "type(%d)" % typ)
        # 验证记录是否被截断（下一片段在后续包）
        d["记录 %d" % (i + 1)] = "%s | version=%s | length=%d" % (
            name, _tl._ver_name(ver, proto), len(rec_payload))
        if typ == 22:  # Handshake
            for mt, body, mo in _tl.split_handshake_messages(rec_payload):
                handshake_count += 1
                mname = _tl.HANDSHAKE_TYPE.get(mt, "type%d" % mt)
                fields = _tl._fields_for(mt, body, proto)
                if mname == "Certificate":
                    d["  握手 %d: Certificate" % handshake_count] = (
                        "证书链=%s 张 | 第1张 主体=%s | 签名算法=%s"
                        % (fields.get("cert_chain_count"), fields.get("cert1_subject"),
                           fields.get("cert1_sig_algorithm")))
                    # Certificate：签名值 / 公钥等关键字段单独展开，便于直接查看
                    for fk, fv in fields.items():
                        if fk == "der_hex":
                            continue
                        d["    ├ %s" % fk] = str(fv)
                else:
                    d["  握手 %d: %s" % (handshake_count, mname)] = _tl._summary_for(mt, fields)
    # 检查尾巴是否可能是跨包记录
    if payload and payload[0] in (0x14, 0x15, 0x16, 0x17, 0x18) and len(payload) < 5 + 2:
        d["提示"] = "记录可能跨多个 TCP 包，完整解析请参考下方 TCP 流视图"
    return d


# ================================================================ 单包全层解析
def build_packet_tree(pkt) -> OrderedDict:
    """把单个数据包解析成分组字段树 {分组: {字段: 值}}。"""
    tree = OrderedDict()

    # ---- Ethernet
    eth = OrderedDict()
    try:
        if pkt.haslayer("Ether"):
            et = pkt["Ether"]
            eth["源 MAC"] = _mac(et.src)
            eth["目的 MAC"] = _mac(et.dst)
            eth["类型"] = "0x%04X" % et.type
        if pkt.haslayer(ARP):
            ap = pkt[ARP]
            eth["ARP 操作"] = "请求" if ap.op == 1 else ("应答" if ap.op == 2 else "op=%d" % ap.op)
            eth["ARP 源 MAC/IP"] = "%s / %s" % (ap.hwsrc, ap.psrc)
            eth["ARP 目标 MAC/IP"] = "%s / %s" % (ap.hwdst, ap.pdst)
    except Exception:
        pass
    if eth:
        tree["Ethernet / ARP"] = eth

    # ---- IPv4 / IPv6
    net = OrderedDict()
    try:
        if IP in pkt:
            ip = pkt[IP]
            net["版本"] = ip.version
            net["源地址"] = ip.src
            net["目的地址"] = ip.dst
            net["协议号"] = ip.proto
            net["TTL"] = ip.ttl
            net["总长度"] = ip.len
            try:
                net["标识"] = "0x%04X" % ip.id
            except Exception:
                pass
        elif IPv6 in pkt:
            ip6 = pkt[IPv6]
            net["版本"] = 6
            net["源地址"] = ip6.src
            net["目的地址"] = ip6.dst
            net["下一个头"] = ip6.nh
            net["流标签"] = ip6.fl
    except Exception:
        pass
    if net:
        tree["IPv4/IPv6"] = net

    # ---- 传输层
    tr = OrderedDict()
    if pkt.haslayer(TCP):
        t = pkt[TCP]
        tr["源端口"] = t.sport
        tr["目的端口"] = t.dport
        tr["序列号"] = t.seq
        tr["确认号"] = t.ack
        flags = []
        try:
            fl = t.flags.value if hasattr(t.flags, "value") else int(t.flags)
        except Exception:
            fl = 0
        fm = ((0x01, "FIN"), (0x02, "SYN"), (0x04, "RST"), (0x08, "PSH"),
              (0x10, "ACK"), (0x20, "URG"), (0x40, "ECE"), (0x80, "CWR"))
        for bit, nm in fm:
            if fl & bit:
                flags.append(nm)
        tr["标志"] = "/".join(flags) or "(无)"
        tr["窗口"] = t.window
        tr["载荷大小"] = len(bytes(t.payload))
    elif pkt.haslayer(UDP):
        u = pkt[UDP]
        tr["源端口"] = u.sport
        tr["目的端口"] = u.dport
        tr["长度"] = u.len
        tr["载荷大小"] = len(bytes(u.payload))
    elif ICMP in pkt:
        ic = pkt[ICMP]
        tr["ICMP 类型"] = ic.type
        tr["ICMP 代码"] = ic.code
    if tr:
        tree["TCP / UDP / ICMP"] = tr

    # ---- 应用层
    app = OrderedDict()
    app_hex = ""
    try:
        if pkt.haslayer(TCP):
            payload_bytes = bytes(pkt[TCP].payload)
        elif pkt.haslayer(UDP):
            payload_bytes = bytes(pkt[UDP].payload)
        else:
            payload_bytes = bytes(pkt[Raw]) if pkt.haslayer(Raw) else b""
    except Exception:
        payload_bytes = b""

    proto_name = detect_app_layer(payload_bytes)
    if proto_name == "DNS":
        app["协议"] = "DNS"
        for k, v in parse_dns(pkt).items():
            app[k] = v
    elif proto_name == "HTTP":
        app["协议"] = "HTTP"
        for k, v in parse_http(payload_bytes).items():
            app[k] = v
    elif proto_name == "SSH":
        app["协议"] = "SSH"
        for k, v in parse_ssh_packet(payload_bytes).items():
            app[k] = v
    elif proto_name in ("TLS", "TLCP"):
        for k, v in parse_tls_packet(payload_bytes).items():
            app[k] = v
    else:
        app["协议"] = proto_name or "（无应用层数据）"
        if payload_bytes:
            app["载荷 Hex"] = _fmt_hex(payload_bytes, 160)
            app_hex = payload_bytes
    if app:
        tree["应用层"] = app

    # ---- 十六进制视图
    hexview = OrderedDict()
    raw_bytes = b""
    try:
        raw_bytes = bytes(pkt[Raw]) if pkt.haslayer(Raw) else bytes(pkt)
    except Exception:
        raw_bytes = b""
    if raw_bytes:
        hexview["Hex Dump"] = _fmt_hex(raw_bytes, 320)
        hexview["总大小"] = "%d 字节" % len(raw_bytes)
        tree["原始字节"] = hexview
    return tree


# ================================================================ 流级（全部 TCP 流，含 SSH/TLCP）
def analyze_streams(pkts) -> dict:
    """全文件 TCP 流重组解析，返回 {flow_key: {client, server, proto, dirs, messages}}。

    TLS / TLCP 借重 tls_parser.analyze_flows；SSH 单独解析。
    """
    flows = dict(_tl.analyze_flows(pkts)["flows"])
    raw_flows = _tl._reassemble_flows(pkts)
    # Wireshark 式 tcp.stream 编号 + 每流全部 TCP 帧号（按抓包顺序）
    stream_idx = {}
    stream_frames = {}
    for i, p in enumerate(pkts):
        try:
            k = _tl._flow_key(p)
        except Exception:
            continue
        if k is None:
            continue
        if k not in stream_idx:
            stream_idx[k] = len(stream_idx)
            stream_frames[k] = []
        stream_frames[k].append(i + 1)
    for key, f in raw_flows.items():
        if key in flows:
            continue
        ab, ba = f["ab"], f["ba"]
        if ab.startswith(b"SSH-") or ba.startswith(b"SSH-"):
            msgs = []
            if ab.startswith(b"SSH-"):
                msgs.extend(parse_ssh_stream(ab, "A->B", _ssh_segs(f, "ab"), f["ab_base"]))
            if ba.startswith(b"SSH-"):
                msgs.extend(parse_ssh_stream(ba, "B->A", _ssh_segs(f, "ba"), f["ba_base"]))
            if msgs:
                # 按抓包包号归并成真实时序（ab/ba 是按端点排序，不代表时间先后）
                msgs.sort(key=lambda m: m.get("no") if m.get("no") is not None else 1 << 30)
                a, ap, b, bp = key
                client, server = ("%s:%d" % (a, ap), "%s:%d" % (b, bp))
                cdir_txt = "A->B" if ssh_client_direction(f) == "ab" else "B->A"
                if cdir_txt == "B->A":
                    client, server = server, client
                # 生成“SSH 协商算法”综合消息（含完整状态/选定算法/服务端支持/协商参数/定位）
                neg = _ssh_negotiation_summary(msgs, cdir_txt,
                                               stream_idx.get(key), stream_frames.get(key))
                if neg is not None:
                    msgs.append(neg)
                    msgs.sort(key=lambda m: m.get("no") if m.get("no") is not None else 1 << 30)
                flows[key] = {"client": client, "server": server,
                              "proto": "SSH", "cdir": cdir_txt,
                              "stream": stream_idx.get(key),
                              "frames": stream_frames.get(key),
                              "messages": msgs}
    return flows


def _ssh_segs(f, d):
    """把方向 d 的 (起始TCP序号→包号) 映射转成 [(seq, 长度, 包号)] 升序列表。"""
    num = f.get(d + "_num") or {}
    ln = f.get(d + "_len") or {}
    return sorted((seq, ln.get(seq, 0), num.get(seq, 0)) for seq in num)


def flow_key_of(pkt):
    """归一化 TCP 流 key（与 tls_parser 一致）。"""
    return _tl._flow_key(pkt)


def reassemble_flows(pkts) -> dict:
    """按 TCP 流 + 方向重组原始载荷（公开接口，供原文视图使用）。

    返回 {flow_key: {'ab': bytes, 'ba': bytes, 'a': ip, 'b': ip}}，
    ab 方向 = 键中较小的端点 → 较大端点，ba 反之。
    """
    return _tl._reassemble_flows(pkts)
