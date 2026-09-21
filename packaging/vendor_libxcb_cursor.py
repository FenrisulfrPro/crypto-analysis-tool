# -*- coding: utf-8 -*-
"""把「目标兼容版本」的 X11/XKB 成套库纳入 PyInstaller 产物（取自 Debian buster 官方仓库）。

背景（两类缺陷同源）：
  1) Qt6 的 xcb 平台插件 libqxcb.so / libQt6XcbQpa.so.6 硬依赖一批 xcb 辅助库
     （libxcb-cursor/icccm/image/keysyms/randr/render/render-util/shape/shm/sync/
     util/xfixes/xkb/glx）与 libxkbcommon(-x11)，PySide6 wheel 不含它们；
  2) 若让 PyInstaller 收集构建机（Ubuntu 24.04 / openEuler）的同名库，就会把
     「构建机版本」混进产物：例如新版 libxkbcommon-x11 配目标机旧版 libxkbcommon，
     在 XKB 键盘映射初始化时段错误（v2.1，退出码 139）。

做法：整套从 **目标发行版 buster** 官方仓库下载 deb，解出 .so 放入产物 _internal/，
版本与目标机（凝思/Debian 10）同源；并保证 libxkbcommon 与 libxkbcommon-x11 成对携带。
构建机自带的 X11/XKB 库由 prune_bundle.py 事先全部剔除（prune 的 FORBIDDEN 规则）。

使用：python packaging/vendor_libxcb_cursor.py dist/CryptoAnalysisTool
"""
import io
import os
import socket
import sys
import tarfile
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from target_libs import elf_versions, is_elf, GLIBC_LIMIT, VENDORED_X11  # noqa: E402

# ------------------------------------------------------------------ 成套清单（buster 官方包）
# (deb 相对路径, 产物内 SONAME)；deb 内按 SONAME 前缀匹配实际文件（各库内部版本号不同，
# 例如 libxcb-randr.so.0 的实际文件是 libxcb-randr.so.0.1.0）。
PACKAGES = [
    # xcb-util 系列
    ("debian-archive/debian/pool/main/x/xcb-util-cursor/libxcb-cursor0_0.1.1-4_amd64.deb",
     "libxcb-cursor.so.0"),
    ("debian-archive/debian/pool/main/x/xcb-util-image/libxcb-image0_0.4.0-1+b2_amd64.deb",
     "libxcb-image.so.0"),
    ("debian-archive/debian/pool/main/x/xcb-util-renderutil/libxcb-render-util0_0.3.9-1+b1_amd64.deb",
     "libxcb-render-util.so.0"),
    ("debian-archive/debian/pool/main/x/xcb-util/libxcb-util0_0.3.8-3+b2_amd64.deb",
     "libxcb-util.so.0"),
    ("debian-archive/debian/pool/main/x/xcb-util-keysyms/libxcb-keysyms1_0.4.0-1+b2_amd64.deb",
     "libxcb-keysyms.so.1"),
    ("debian-archive/debian/pool/main/x/xcb-util-wm/libxcb-icccm4_0.4.1-1.1_amd64.deb",
     "libxcb-icccm.so.4"),
    # libxcb 系列（同一源码包 1.13.1-2）
    ("debian-archive/debian/pool/main/libx/libxcb/libxcb-randr0_1.13.1-2_amd64.deb",
     "libxcb-randr.so.0"),
    ("debian-archive/debian/pool/main/libx/libxcb/libxcb-render0_1.13.1-2_amd64.deb",
     "libxcb-render.so.0"),
    ("debian-archive/debian/pool/main/libx/libxcb/libxcb-shape0_1.13.1-2_amd64.deb",
     "libxcb-shape.so.0"),
    ("debian-archive/debian/pool/main/libx/libxcb/libxcb-shm0_1.13.1-2_amd64.deb",
     "libxcb-shm.so.0"),
    ("debian-archive/debian/pool/main/libx/libxcb/libxcb-sync1_1.13.1-2_amd64.deb",
     "libxcb-sync.so.1"),
    ("debian-archive/debian/pool/main/libx/libxcb/libxcb-xfixes0_1.13.1-2_amd64.deb",
     "libxcb-xfixes.so.0"),
    ("debian-archive/debian/pool/main/libx/libxcb/libxcb-xkb1_1.13.1-2_amd64.deb",
     "libxcb-xkb.so.1"),
    ("debian-archive/debian/pool/main/libx/libxcb/libxcb-glx0_1.13.1-2_amd64.deb",
     "libxcb-glx.so.0"),
    # libxkbcommon 必须成对（x11 依赖基础库，避免「只打一半」再次造成 ABI 错配）
    ("debian-archive/debian/pool/main/libx/libxkbcommon/libxkbcommon0_0.8.2-1_amd64.deb",
     "libxkbcommon.so.0"),
    ("debian-archive/debian/pool/main/libx/libxkbcommon/libxkbcommon-x11-0_0.8.2-1_amd64.deb",
     "libxkbcommon-x11.so.0"),
]

BASES = [
    "https://mirror.nju.edu.cn/",
    "http://archive.debian.org/",
    "https://mirrors.aliyun.com/",
    "https://mirrors.cloud.tencent.com/",
    "https://snapshot.debian.org/archive/debian/20210601T000000Z/archive/",
]


def download_deb(rel):
    """按镜像顺序下载 deb；rel 形如 'debian-archive/debian/pool/...'。"""
    socket.setdefaulttimeout(90)
    last = None
    for base in BASES:
        url = base + rel
        try:
            data = urllib.request.urlopen(url, timeout=90).read()
            if data[:8] == b"!<arch>\n":
                return data
            last = "内容不是 .deb (ar 归档)"
        except Exception as exc:  # noqa: BLE001
            last = exc
    raise RuntimeError("下载失败: %s (%s)" % (rel, last))


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


def extract_member(deb, soname):
    """从 deb 的 data.tar.* 中取出该 SONAME 对应的实际库文件（按前缀匹配，取最长名）。"""
    members = ar_members(deb)
    for key in ("data.tar.xz", "data.tar.gz", "data.tar.bz2", "data.tar"):
        blob = members.get(key)
        if blob is None:
            continue
        mode = {"data.tar": "r:", "data.tar.xz": "r:xz", "data.tar.gz": "r:gz",
                "data.tar.bz2": "r:bz2"}[key]
        tf = tarfile.open(fileobj=io.BytesIO(blob), mode=mode)
        best = None
        for m in tf.getmembers():
            if not m.isfile():
                continue
            base = os.path.basename(m.name)
            if base == soname or base.startswith(soname + "."):
                if best is None or len(base) > len(best[0]):
                    best = (base, m)
        if best is not None:
            return tf.extractfile(best[1]).read()
    raise RuntimeError("deb 内未找到 %s" % soname)


def fetch_one(rel, soname, internal):
    dest = os.path.join(internal, soname)
    if is_elf(dest):
        # 已有同名文件：必须是「低 glibc」的目标版拷贝，否则（构建机旧拷贝）删除重取
        try:
            with open(dest, "rb") as fp:
                cur = fp.read()
            g_cur = elf_versions(cur)[0]
        except OSError:
            g_cur = None
        if g_cur is not None and g_cur <= GLIBC_LIMIT and soname.encode() in cur:
            print("  已存在目标版，跳过:", soname, flush=True)
            return True
        print("  已有同名库但非目标版（GLIBC 2.%s），删除重取" % g_cur, flush=True)
        try:
            os.remove(dest)
        except OSError:
            pass
    try:
        blob = extract_member(download_deb(rel), soname)
    except Exception as exc:  # noqa: BLE001
        print("  失败:", soname, exc, flush=True)
        return False
    if blob[:4] != b"\x7fELF":
        print("  提取到的文件不是 ELF:", soname, flush=True)
        return False
    if soname.encode() not in blob:
        print("  SONAME 不符（未找到 %s）: %s" % (soname, soname), flush=True)
        return False
    g, c, a = elf_versions(blob)
    if g > GLIBC_LIMIT:
        print("  %s 要求 GLIBC 2.%d > %d，拒绝使用" % (soname, g, GLIBC_LIMIT), flush=True)
        return False
    with open(dest, "wb") as fp:
        fp.write(blob)
    os.chmod(dest, 0o755)
    print("  写入 %s（%d 字节，最高 GLIBC 2.%d）" % (soname, len(blob), g), flush=True)
    return True


def main():
    dist = sys.argv[1] if len(sys.argv) > 1 else "dist/CryptoAnalysisTool"
    internal = os.path.join(dist, "_internal")
    if not os.path.isdir(internal):
        print("目录不存在:", internal)
        return 2
    print("从目标发行版(buster)补齐 X11/XKB 成套库（%d 个）…" % len(PACKAGES), flush=True)
    ok = 0
    for rel, soname in PACKAGES:
        print("下载 %s ..." % soname, flush=True)
        if fetch_one(rel, soname, internal):
            ok += 1
    # 校验：白名单里的库是否都已就位
    missing = [s for s in sorted(VENDORED_X11) if not is_elf(os.path.join(internal, s))]
    if missing:
        print("缺少成套库:", ", ".join(missing))
        return 4
    if ok < len(PACKAGES):
        print("有 %d 个包未成功下载（但白名单已齐全，可能之前已存在）" % (len(PACKAGES) - ok))
    print("X11/XKB 成套库已就位（%d/%d）" % (len(PACKAGES) - len(missing), len(PACKAGES)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
