# -*- coding: utf-8 -*-
"""裁剪 PyInstaller 产物中混入的构建宿主系统库，保证可在 Debian 10 (buster/凝思) 运行。

策略：
  1. 移除未使用的可选组件：FFmpeg 多媒体库（会把 openEuler 的 libssl.so.3 拖进来）、
     GTK3 主题插件（libqgtk3.so 依赖 GTK 全家桶）、PDF 插件（依赖 libatomic.so.1）、
     Wayland 平台后端（依赖目标机没有的 libwayland-*，目标机为 X11）；
  2. 扫描剩余 ELF，删除所有超出 buster 基线（GLIBC_2.28 / GLIBCXX_3.4.25 / CXXABI_1.3.11）的库
     —— 前提是该库名在「buster 系统自带」白名单中（运行时由目标系统提供）；
  3. 若仍有非白名单超标库（如 libssl.so.3），直接报错退出，避免打出静默损坏的包。

使用：python packaging/prune_bundle.py dist/CryptoAnalysisTool
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from target_libs import (GLIBC_LIMIT, GLIBCXX_LIMIT, CXXABI_LIMIT,  # noqa: E402
                         SYSTEM_OK)

FFMPEG_PAT = re.compile(r"^lib(avcodec|avformat|avutil|avdevice|avfilter|swresample|swscale|postproc)")
MULTIMEDIA_PAT = re.compile(r"^libQt6(Multimedia|SpatialAudio|TextToSpeech|WebEngine|WebChannel)")
PDF_PAT = re.compile(r"^libQt6Pdf")
# Wayland 后端：目标机为 X11 桌面，剔除可去掉 libwayland-* 依赖
WAYLAND_PAT = re.compile(r"^libQt6(Wayland|WlShellIntegration)")
# 可选插件：多媒体/语音/TLS/GTK3 主题(会把 GTK 全家桶拉成未满足依赖)/Wayland/PDF 图像插件
DROP_PLUGIN_PAT = re.compile(
    r"(plugins[/\\](multimedia|texttospeech|tls|platformthemes"
    r"|wayland-decoration-client|wayland-graphics-integration-client|wayland-shell-integration)[/\\]"
    r"|imageformats[/\\]libqpdf"
    r"|platforms[/\\]libqwayland)")

# 这些库目标系统（Debian 10）没有同名版本（有 .so.1.1 而非 .so.3），
# 只有在确认产物中已无文件引用它们时才允许删除
DROP_IF_UNREFERENCED = {"libssl.so.3", "libcrypto.so.3"}


def elf_versions(path):
    try:
        with open(path, "rb") as fp:
            if fp.read(4) != b"\x7fELF":
                return None
            data = fp.read()
    except OSError:
        return None
    g = c = a = -1
    for m in re.findall(rb"GLIBC_2\.(\d+)", data):
        g = max(g, int(m))
    for m in re.findall(rb"GLIBCXX_3\.4\.(\d+)", data):
        c = max(c, int(m))
    for m in re.findall(rb"CXXABI_1\.3\.(\d+)", data):
        a = max(a, int(m))
    return g, c, a


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "dist/CryptoAnalysisTool"
    if not os.path.isdir(root):
        print("目录不存在:", root)
        return 2
    removed = []
    offenders = []
    drop_later = []
    for dirpath, dirs, files in os.walk(root):
        for fn in list(files):
            path = os.path.join(dirpath, fn)
            name = fn
            if (FFMPEG_PAT.match(name) or MULTIMEDIA_PAT.match(name)
                    or PDF_PAT.match(name) or WAYLAND_PAT.match(name)
                    or DROP_PLUGIN_PAT.search(path)):
                try:
                    os.remove(path)
                    removed.append(path)
                except OSError:
                    pass
                continue
            ver = elf_versions(path)
            if ver is None:
                continue
            g, c, a = ver
            if g > GLIBC_LIMIT or c > GLIBCXX_LIMIT or a > CXXABI_LIMIT:
                base = re.sub(r"\.?\d+$", "", name)
                if name in SYSTEM_OK or base in SYSTEM_OK:
                    try:
                        os.remove(path)
                        removed.append(path)
                    except OSError:
                        pass
                elif name in DROP_IF_UNREFERENCED:
                    drop_later.append((path, name))
                else:
                    offenders.append((path, g, c, a))
    for path, name in drop_later:
        needle = name.encode()
        referenced = False
        for dirpath, _dirs, files in os.walk(root):
            for fn in files:
                p = os.path.join(dirpath, fn)
                if p == path:
                    continue
                ver = elf_versions(p)
                if ver is None:
                    continue
                try:
                    with open(p, "rb") as fp:
                        data = fp.read()
                except OSError:
                    continue
                if needle in data:
                    referenced = True
                    print("仍被引用:", name, "<-", p)
                    break
            if referenced:
                break
        if referenced:
            offenders.append((path, 0, 0, 0))
        else:
            try:
                os.remove(path)
                removed.append(path)
            except OSError:
                pass
    print("已移除 %d 个文件：" % len(removed))
    for p in removed:
        print("  删", p)
    if offenders:
        print("仍有非系统库超出基线（需处理）：")
        for p, g, c, a in offenders:
            print("  %s [GLIBC 2.%d / GLIBCXX 3.4.%d / CXXABI 1.3.%d]" % (p, g, c, a))
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
