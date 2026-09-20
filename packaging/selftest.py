# -*- coding: utf-8 -*-
"""打包流水线自检：依赖导入、国密验签、scapy 解析、CSSH 解析与 GUI 启动。

可以源码方式运行（python packaging/selftest.py），用于 CI 在打包前后验证环境。
环境变量 SELFTEST_SKIP_GUI=1 时跳过 GUI 段（无图形库的构建容器使用）。"""
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)


def check_gmssl():
    from gmssl.sm2 import CryptSM2, default_ecc_table
    private = "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8"
    pub = CryptSM2(private_key=private, public_key="",
                   ecc_table=default_ecc_table)._kg(int(private, 16),
                                                    default_ecc_table["g"])
    signer = CryptSM2(private_key=private, public_key=pub, ecc_table=default_ecc_table)
    raw = signer.sign_with_sm3(b"cssh-selftest")
    verifier = CryptSM2(private_key=None, public_key=pub, ecc_table=default_ecc_table)
    assert verifier.verify_with_sm3(raw, b"cssh-selftest"), "SM2 验签自检失败"
    print("SELFTEST gmssl ok")


def check_scapy():
    import tempfile
    from scapy.all import Ether, IP, TCP, Raw, rdpcap, wrpcap
    pkt = Ether() / IP(src="127.0.0.1", dst="127.0.0.1") / TCP(sport=10022, dport=48380) / Raw(b"x")
    fd, path = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    try:
        wrpcap(path, [pkt])
        pkts = rdpcap(path)
    finally:
        os.unlink(path)
    assert len(pkts) == 1 and bytes(pkts[0][TCP].payload) == b"x", "scapy pcap 读写自检失败"
    print("SELFTEST scapy ok")


def check_cssh():
    from modules import cssh_parser as C
    payload = (bytes([20]) + bytes(16)
               + b"".join(struct.pack(">I", 0) for _ in range(10))
               + b"\x00" + b"\x00" * 4)
    frame = struct.pack(">I", 1 + len(payload) + 4) + bytes([4]) + payload + bytes(4)
    stream = b"CSSH-1.0-LINXSSH-1.0\r\n" + frame
    msgs = C.direction_messages(stream, "A->B", 0, None)
    assert any(m["type"] == "KEXINIT" for m in msgs), "CSSH KEXINIT 解析自检失败"
    assert "DCFCE7" in C.highlight_algs("SM2-SM3,aes128-ctr"), "国密算法高亮自检失败"
    assert "DCFCE7" not in C.highlight_algs("aes128-ctr"), "非国密算法不应高亮"
    print("SELFTEST cssh ok")


def check_gui():
    if os.environ.get("SELFTEST_SKIP_GUI"):
        print("SELFTEST gui skipped")
        return
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    import main as app_main
    app = QApplication.instance() or QApplication([])
    win = app_main.MainWindow()
    app.processEvents()
    assert win.centralWidget().count() >= 6, "主窗口页签数量异常"
    win.close()
    print("SELFTEST gui ok")


def main():
    check_gmssl()
    check_scapy()
    check_cssh()
    check_gui()
    print("SELFTEST ALL OK")


if __name__ == "__main__":
    main()
