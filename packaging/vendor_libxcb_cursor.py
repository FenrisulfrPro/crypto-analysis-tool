# -*- coding: utf-8 -*-
"""把「目标兼容版本」的 libxcb-cursor.so.0 纳入 PyInstaller 产物。

背景：PySide6 wheel 中的 Qt xcb 平台插件 libqxcb.so 硬依赖 libxcb-cursor.so.0
（DT_NEEDED），但 PyInstaller 不会从系统收集它；该库又不在 PySide6 wheel 内，
于是构建机有、目标机（凝思/Debian 10）没有 → xcb 平台插件加载失败，程序无法启动。

做法：从 Debian buster 官方仓库下载 libxcb-cursor0_0.1.1-4_amd64.deb
（glibc ≤ 2.28，与目标机一致），解出 libxcb-cursor.so.0 放进产物 _internal/。
PyInstaller 启动器会把 _internal 加入库搜索路径，故放此处即可被加载。

严禁使用构建机（Ubuntu 24.04 / openEuler）自带的同名片——它们要求更高 glibc。

使用：python packaging/vendor_libxcb_cursor.py dist/CryptoAnalysisTool
"""
import io
import os
import socket
import sys
import tarfile
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from target_libs import elf_versions, is_elf, GLIBC_LIMIT  # noqa: E402

DEB_PATHS = [
    "debian-archive/debian/pool/main/x/xcb-util-cursor/libxcb-cursor0_0.1.1-4_amd64.deb",
    "debian/pool/main/x/xcb-util-cursor/libxcb-cursor0_0.1.1-4_amd64.deb",
]
BASES = [
    "https://mirror.nju.edu.cn/",
    "http://archive.debian.org/",
    "https://mirrors.aliyun.com/",
    "https://mirrors.cloud.tencent.com/",
    "https://snapshot.debian.org/archive/debian/20210601T000000Z/archive/",
]
MEMBER = "libxcb-cursor.so.0.0.0"
SONAME = "libxcb-cursor.so.0"


def download_deb():
    socket.setdefaulttimeout(90)
    last = None
    for base in BASES:
        for rel in DEB_PATHS:
            url = base + rel
            print("下载 libxcb-cursor0(buster):", url, flush=True)
            try:
                data = urllib.request.urlopen(url, timeout=90).read()
                if data[:8] == b"!<arch>\n":
                    print("  下载完成 %d 字节" % len(data), flush=True)
                    return data
                last = "内容不是 .deb (ar 归档)"
            except Exception as exc:  # noqa: BLE001
                last = exc
                print("  该源失败:", exc, flush=True)
    raise SystemExit("所有 libxcb-cursor0 下载源均失败: %s" % last)


def ar_members(data):
    """解析 ar 归档，返回 {成员名: bytes}。"""
    out = {}
    off = 8
    while off + 60 <= len(data):
        hdr = data[off:off + 60]
        off += 60
        name = hdr[0:16].decode("utf-8", "replace").strip()
        try:
            size = int(hdr[48:58].decode().strip())
        except ValueError:
            break
        out[name] = data[off:off + size]
        off += size + (1 if size % 2 else 0)
    return out


def extract_member(data):
    members = ar_members(data)
    for key in ("data.tar.xz", "data.tar.gz", "data.tar.bz2", "data.tar"):
        blob = members.get(key)
        if blob is None:
            continue
        mode = {"data.tar": "r:", "data.tar.xz": "r:xz", "data.tar.gz": "r:gz",
                "data.tar.bz2": "r:bz2"}[key]
        tf = tarfile.open(fileobj=io.BytesIO(blob), mode=mode)
        for m in tf.getmembers():
            if os.path.basename(m.name) == MEMBER and m.isfile():
                return tf.extractfile(m).read()
    raise SystemExit("deb 内未找到 %s" % MEMBER)


def main():
    dist = sys.argv[1] if len(sys.argv) > 1 else "dist/CryptoAnalysisTool"
    internal = os.path.join(dist, "_internal")
    if not os.path.isdir(internal):
        print("目录不存在:", internal)
        return 2
    dest = os.path.join(internal, SONAME)
    if is_elf(dest):
        print("已存在，跳过:", dest)
        return 0
    blob = extract_member(download_deb())
    if blob[:4] != b"\x7fELF":
        print("提取到的文件不是 ELF")
        return 3
    g, c, a = elf_versions(blob)
    if SONAME.encode() not in blob:
        print("提取到的库 SONAME 不符（未找到 %s）" % SONAME)
        return 4
    if g > GLIBC_LIMIT:
        print("提取到的库要求 GLIBC 2.%d > %d，拒绝使用" % (g, GLIBC_LIMIT))
        return 5
    with open(dest, "wb") as fp:
        fp.write(blob)
    os.chmod(dest, 0o755)
    print("已写入 %s（%d 字节，最高 GLIBC 2.%d）" % (dest, len(blob), g))
    return 0


if __name__ == "__main__":
    sys.exit(main())
