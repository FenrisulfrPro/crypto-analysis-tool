# -*- coding: utf-8 -*-
"""pcap / pcapng 协议分析核心逻辑（Wireshark 式表格）
每行输出： No | 时间 | 源(IP:端口) | 目的(IP:端口) | 协议 | 长度 | 概要
协议列简洁直观：TLS / TLCP / SSH / HTTP / DNS / TCP / UDP / ARP / ICMP
概要列体现握手消息（Client Hello / Server Hello / Certificate 等）或 SSH 版本等。
"""
import struct
from collections import Counter, OrderedDict

from scapy.all import rdpcap, IP, IPv6, TCP, UDP, ICMP, ARP, DNS, Raw

from modules import tls_parser, packet_parser

# TLS / TLCP 记录类型头部判断（两者 type 同为 0x14~0x18，用版本号区分）
_REC_TYPES = (20, 21, 22, 23, 24)          # 0x14-0x18
_TLCP_VERSIONS = (0x0001, 0x0002, 0x0101)
_TLS_VERSIONS = (0x0300, 0x0301, 0x0302, 0x0303, 0x0304)
_HTTP_STARTS = (b"GET ", b"POST", b"PUT ", b"HEAD", b"DELE", b"OPTI", b"HTTP/")


def _detect_proto(payload: bytes):
    """按 TCP payload 头部判定上层协议：返回 'TLS' / 'TLCP' / 'SSH' / 'HTTP' 或 None。"""
    if not payload:
        return None
    if payload.startswith(b"SSH-"):
        return "SSH"
    if payload[:4] in _HTTP_STARTS:
        return "HTTP"
    if len(payload) >= 5:
        typ = payload[0]
        if typ in _REC_TYPES:
            ver = struct.unpack(">H", payload[1:3])[0]
            if ver in _TLCP_VERSIONS:
                return "TLCP"
            if ver in _TLS_VERSIONS:
                return "TLS"
    return None


def _proto_short(pkt):
    """识别简洁协议名：TLS / TLCP / SSH / HTTP / DNS / TCP / UDP / ARP / ICMP 等。"""
    if pkt.haslayer(ARP):
        return "ARP"
    if pkt.haslayer(ICMP):
        return "ICMP"
    has_tcp = pkt.haslayer(TCP)
    has_udp = pkt.haslayer(UDP)
    if has_tcp:
        payload = bytes(pkt[TCP].payload)
        p = _detect_proto(payload)
        if p:
            return p
        # SSH 也可能由 scapy 直接解析（SSH 层）
        try:
            if pkt.haslayer("SSH"):
                return "SSH"
        except Exception:
            pass
        return "TCP"
    if has_udp:
        if DNS in pkt or pkt[UDP].sport == 53 or pkt[UDP].dport == 53:
            return "DNS"
        return "UDP"
    if IP in pkt:
        return "IP#%d" % pkt[IP].proto
    if IPv6 in pkt:
        return "IPv6"
    return "Other"


def _endpoint(ip: str, port) -> str:
    if port:
        return "%s:%d" % (ip, port)
    return ip


def _tcp_flags_str(pkt) -> str:
    f = int(pkt[TCP].flags)
    parts = []
    if f & 0x02: parts.append("SYN")
    if f & 0x01: parts.append("FIN")
    if f & 0x04: parts.append("RST")
    if f & 0x10: parts.append("ACK")
    if f & 0x08: parts.append("PSH")
    if f & 0x20: parts.append("URG")
    return ",".join(parts)


def _tls_record_info(payload: bytes, proto: str):
    """把单个包内的 TLS/TLCP 记录解析成 Wireshark 式概要（如 'Server Hello'）。"""
    real_proto, records = tls_parser.split_proto_records(payload, default=proto)
    parts = []
    for typ, ver, rpayload, _ in records:
        if typ == 22:  # Handshake
            msgs = tls_parser.split_handshake_messages(rpayload)
            for mt, body, _ in msgs:
                name = tls_parser.HANDSHAKE_TYPE.get(mt, "type%d" % mt)
                extra = ""
                ver_txt = tls_parser._ver_name(ver, real_proto)
                if mt == 1:
                    ch = tls_parser.parse_client_hello(body, real_proto)
                    ver_txt = ch.get("legacy_version", ver_txt)
                elif mt == 2:
                    sh = tls_parser.parse_server_hello(body, real_proto)
                    ver_txt = sh.get("legacy_version", ver_txt)
                    extra = ", Cipher: %s" % sh.get("selected_cipher_suite", "?")
                elif mt == 11:
                    try:
                        certs = tls_parser.parse_certificate(body)
                        extra = " (%d 张证书)" % len(certs)
                    except Exception:
                        extra = ""
                elif mt == 12:
                    ske = tls_parser.parse_server_key_exchange(body)
                    extra = ", Group: %s" % ske.get("named_group", "?")
                elif mt == 15:
                    cv = tls_parser.parse_certificate_verify(body)
                    extra = ", Scheme: %s" % cv.get("signature_scheme", "?")
                elif mt == 20:
                    extra = ", VerifyData: %s…" % str(tls_parser.parse_finished(body).get("verify_data", ""))[:40]
                parts.append("%s, Version: %s%s" % (name, ver_txt, extra))
        elif typ in (20, 0x14):
            parts.append("ChangeCipherSpec")
        elif typ == 21:
            parts.append("Alert")
        elif typ == 23:
            parts.append("Application Data (已加密)")
        elif typ == 0x18:
            parts.append("EOF (TLCP 结束)")
        elif typ == 24:
            parts.append("Heartbeat")
    return real_proto, " | ".join(parts) if parts else proto


def _ssh_flow_map(pkts):
    """识别文件中所有 SSH 流（任一方首字节为 SSH 识别串）。

    返回 (ssh_flow_keys 集合, {flow_key: 客户端方向 'ab'/'ba'})。
    SSH 二进制报文单包头部无固定特征，须按 TCP 流整体识别后反标每个包。"""
    keys = set()
    cdirs = {}
    for key, f in tls_parser._reassemble_flows(pkts).items():
        if f["ab"].startswith(b"SSH-") or f["ba"].startswith(b"SSH-"):
            keys.add(key)
            cdirs[key] = packet_parser.ssh_client_direction(f)
    return keys, cdirs


def _packet_info(pkt, proto: str, ssh_cdir=None):
    """生成 Wireshark 式信息摘要。返回 (协议名, 信息字符串)。

    ssh_cdir: {flow_key: 客户端方向 'ab'/'ba'}，用于 SSH 包标注 Client/Server。"""
    try:
        if proto in ("TLS", "TLCP"):
            payload = bytes(pkt[TCP].payload)
            return _tls_record_info(payload, proto)
        if proto == "SSH":
            payload = bytes(pkt[TCP].payload)
            role = "Client"
            if ssh_cdir:
                try:
                    if IP in pkt:
                        a, b = pkt[IP].src, pkt[IP].dst
                    else:
                        a, b = pkt[IPv6].src, pkt[IPv6].dst
                    sp, dp = pkt[TCP].sport, pkt[TCP].dport
                    key = (a, sp, b, dp) if (a, sp) <= (b, dp) else (b, dp, a, sp)
                    d = "ab" if (a, sp) == key[:2] else "ba"
                    role = "Client" if d == ssh_cdir.get(key, d) else "Server"
                except Exception:
                    pass
            if payload.startswith(b"SSH-"):
                first = payload.split(b"\r\n", 1)[0].split(b"\n", 1)[0].decode('utf-8', 'replace')
                return "SSH", "%s: %s" % (role, first)
            try:
                msgs = list(packet_parser.split_ssh_packets(payload))
            except Exception:
                msgs = []
            if msgs:
                mt = msgs[0][0]
                nm = packet_parser.SSH_MSG_NAME.get(mt, "SSH_MSG_%d" % mt)
                return "SSH", "%s: %s (len=%d)" % (role, nm, len(payload))
            return "SSH", "%s: 加密数据 (len=%d)" % (role, len(payload))
        if proto == "HTTP":
            payload = bytes(pkt[TCP].payload)
            line = payload.split(b"\r\n", 1)[0].split(b"\n", 1)[0].decode('utf-8', 'replace')
            return "HTTP", line[:120]
        if proto == "DNS":
            try:
                q = pkt[DNS].qd
                if q:
                    name = q.qname
                    if isinstance(name, bytes):
                        name = name.decode('utf-8', 'replace').rstrip('.')
                    return "DNS", "Standard query 0x%04x %s" % (pkt[DNS].id, name)
            except Exception:
                pass
            return "DNS", ""
        if proto == "TCP":
            return "TCP", "%s → %s [%s] Seq=%d" % (
                pkt[TCP].sport, pkt[TCP].dport, _tcp_flags_str(pkt), pkt[TCP].seq)
        if proto == "UDP":
            return "UDP", "%s → %s Len=%d" % (pkt[UDP].sport, pkt[UDP].dport,
                                               (len(bytes(pkt[UDP].payload)) if pkt[UDP].payload else 0))
        if proto == "ARP":
            op = "Reply" if pkt[ARP].op == 2 else ("Request" if pkt[ARP].op == 1 else "op%d" % pkt[ARP].op)
            return "ARP", "%s, %s → %s" % (op, pkt[ARP].psrc, pkt[ARP].pdst)
        if proto == "ICMP":
            return "ICMP", "type=%d code=%d" % (int(pkt[ICMP].type), int(pkt[ICMP].code))
        if proto.startswith("IP#"):
            try:
                return proto, pkt.summary()
            except Exception:
                return proto, ""
        return proto, ""
    except Exception:
        return proto, ""


def analyze_pcap(path: str, max_rows: int = 50000):
    """解析 pcap / pcapng，返回结构化分析结果"""
    pkts = rdpcap(path)
    total = len(pkts)
    if total == 0:
        raise ValueError("文件中没有数据包")

    start_time = float(pkts[0].time)
    end_time = float(pkts[-1].time)
    duration = max(end_time - start_time, 1e-6)

    proto_counter = Counter()
    src_counter = Counter()
    dst_counter = Counter()
    sport_counter = Counter()
    dport_counter = Counter()
    len_sum = 0
    size_counter = Counter()

    rows = []
    ssh_keys, ssh_cdir = _ssh_flow_map(pkts)
    for idx, pkt in enumerate(pkts):
        ts = float(pkt.time)
        delta = ts - start_time
        length = int(getattr(pkt, 'len', 0)) or int(pkt.wirelen if hasattr(pkt, 'wirelen') else 0)
        if length <= 0:
            try:
                length = len(bytes(pkt))
            except Exception:
                length = 0
        len_sum += length

        proto = _proto_short(pkt)
        # SSH 二进制包首字节无固定特征，按流识别后反标（该流任一方向有载荷的 TCP 包）
        if proto != "SSH" and proto == "TCP" and pkt.haslayer(TCP):
            try:
                if ssh_keys and bytes(pkt[TCP].payload):
                    if tls_parser._flow_key(pkt) in ssh_keys:
                        proto = "SSH"
            except Exception:
                pass
        proto_counter[proto] += 1
        src, dst = _ip_of(pkt)
        if src and src != '0.0.0.0':
            src_counter[src] += 1
        if dst and dst != '0.0.0.0':
            dst_counter[dst] += 1
        sp, dp = _port_of(pkt)
        if sp:
            sport_counter[sp] += 1
        if dp:
            dport_counter[dp] += 1

        r = int(getattr(pkt, 'len', 0))
        if r > 0:
            bucket = '<=64' if r <= 64 else ('<=128' if r <= 128 else ('<=512' if r <= 512 else ('<=1024' if r <= 1024 else '>1024')))
            size_counter[bucket] += 1

        if idx < max_rows:
            info = ""
            try:
                proto, info = _packet_info(pkt, proto, ssh_cdir)
            except Exception:
                info = ""
            rows.append((
                idx + 1,
                delta,
                _endpoint(src, sp),
                _endpoint(dst, dp),
                proto,
                length,
                info,
            ))

    summary = OrderedDict()
    summary['文件包数'] = total
    summary['起始时间'] = _fmt_ts(start_time)
    summary['结束时间'] = _fmt_ts(end_time)
    summary['时长(秒)'] = round(duration, 3)
    summary['平均包速率(包/秒)'] = round(total / duration, 1)
    summary['平均包长(字节)'] = round(len_sum / total, 1)
    summary['总字节数'] = len_sum

    proto_stats = sorted(proto_counter.items(), key=lambda kv: -kv[1])
    top_src = src_counter.most_common(10)
    top_dst = dst_counter.most_common(10)
    top_sport = sport_counter.most_common(10)
    top_dport = dport_counter.most_common(10)
    size_stats = sorted(size_counter.items(), key=lambda kv: -kv[1])

    return {
        'summary': summary,
        'proto_stats': proto_stats,
        'top_src': top_src,
        'top_dst': top_dst,
        'top_sport': top_sport,
        'top_dport': top_dport,
        'size_stats': size_stats,
        'rows': rows,
        'total': total,
    }


def _ip_of(pkt):
    if IP in pkt:
        return pkt[IP].src, pkt[IP].dst
    if IPv6 in pkt:
        return pkt[IPv6].src, pkt[IPv6].dst
    if ARP in pkt:
        return pkt[ARP].psrc, pkt[ARP].pdst
    return "", ""


def _port_of(pkt):
    if pkt.haslayer(TCP):
        return pkt[TCP].sport, pkt[TCP].dport
    if pkt.haslayer(UDP):
        return pkt[UDP].sport, pkt[UDP].dport
    return None, None


def _fmt_ts(ts: float) -> str:
    import datetime
    return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
