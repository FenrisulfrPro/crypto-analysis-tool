# -*- coding: utf-8 -*-
"""打包产物的目标环境（Debian 10 buster / 凝思 Linx，glibc 2.28）契约。

集中定义三类信息，供 prune_bundle / check_compat / check_selfcontained 复用，避免漂移：
  1. 符号版本基线：GLIBC_2.28 / GLIBCXX_3.4.25 / CXXABI_1.3.11；
  2. SYSTEM_OK：目标系统必然自带、允许不随包携带的库（也是超出基线时允许删除的库）；
  3. 显卡/内核驱动类库：无法也不应随包分发，允许由目标机提供。
"""
import os
import re

GLIBC_LIMIT = 28
GLIBCXX_LIMIT = 25
CXXABI_LIMIT = 11

# glibc 家族：内核/加载器提供，永远由目标系统提供
GLIBC_FAMILY = {
    "ld-linux-x86-64.so.2", "ld-linux.so.2",
    "libc.so.6", "libm.so.6", "libmvec.so.1", "libdl.so.2", "libpthread.so.0",
    "librt.so.1", "libresolv.so.2", "libnsl.so.1", "libutil.so.1", "libanl.so.1",
    "libcrypt.so.1", "libnss_files.so.2", "libnss_dns.so.2",
}

# 目标系统（buster/凝思）必然自带的库：允许不随包携带，也允许在超标时删除
SYSTEM_OK = {
    "libstdc++.so.6", "libgcc_s.so.1",
    "libglib-2.0.so.0", "libgio-2.0.so.0", "libgmodule-2.0.so.0", "libgobject-2.0.so.0",
    "libgssapi_krb5.so.2", "libkrb5.so.3", "libk5crypto.so.3", "libkrb5support.so.0",
    "libcom_err.so.2", "libselinux.so.1", "libmount.so.1", "libblkid.so.1",
    "libzstd.so.1", "libz.so.1", "libcrypt.so.1", "libuuid.so.1", "libpcre.so.3",
    "libpcre2-8.so.0", "libffi.so.6", "libffi.so.8", "libexpat.so.1", "libdbus-1.so.3",
    "libxcb.so.1", "libxdmcp.so.6", "libbsd.so.0", "libxau.so.6", "libxkbcommon.so.0",
    "libxkbcommon-x11.so.0", "libfontconfig.so.1", "libfreetype.so.6", "libpng16.so.16",
    "libresolv.so.2", "libnsl.so.1", "libgdbm.so.6", "libgdbm_compat.so.4",
    "libX11.so.6", "libX11-xcb.so.1", "libXau.so.6", "libXdmcp.so.6", "libXext.so.6", "libXi.so.6",
    "libXrender.so.1", "libXfixes.so.3", "libXrandr.so.2", "libXcursor.so.1",
    "libXinerama.so.1", "libXcomposite.so.1", "libXdamage.so.1", "libXtst.so.6",
    "libSM.so.6", "libICE.so.6", "liblzma.so.5", "libgcrypt.so.20", "libcap.so.2",
    "libxml2.so.2", "libgpg-error.so.0", "libsystemd.so.0", "libm.so.6",
}

# 显卡 / 内核驱动类：由目标机显卡驱动提供
DRIVER_RE = re.compile(
    r"^lib(GL|GLX|EGL|GLdispatch|OpenGL|glapi|drm|gbm|nvidia|nvcuvid|nvidia-|cuda|vdpau|va|XvMC)"
)

# ---------------------------------------------------------------- X11 / XKB 系统库
# 教训（v2.1 段错误，退出码 139）：构建机上较新的 libxkbcommon-x11.so.0 被部分打进产物，
# 而与之配套的 libxkbcommon.so.0 没打 → 目标机（Debian 10）自带的旧版 libxkbcommon 0.8.2
# 被新版 x11 库调用，ABI 不匹配，在 xkb_x11_keymap_new_from_device 处崩溃。
# 结论：这类 X11/XKB 系统库必须「成套打包或整套不打」，绝不能只带其中一部分。
#
# 本项目的策略：
#   * 基础 X11/XKB（libX11/libxcb.so.1/libXau/libXdmcp/libX11-xcb）→ 整套不打，由目标机提供；
#   * Qt xcb 插件必需的 xcb 辅助库与 xkbcommon 成套 → 统一从「目标发行版 buster」官方仓库取出
#     （版本与目标机同源，见 VENDORED_X11），构建机自带的同名库一律剔除。
X11_XKB_RE = re.compile(
    r"^libxcb[-.]|^libX11|^libXext|^libXi\.|^libXrender|^libXfixes|^libXrandr|^libXcursor"
    r"|^libXinerama|^libXcomposite|^libXdamage|^libXtst|^libXss|^libXxf86vm|^libXau|^libXdmcp"
    r"|^libSM\.|^libICE\.|^libxkbcommon|^libxshmfence"
)

# 允许随包携带的 X11/XKB 家族库（全部取自 buster 官方 deb，glibc ≤ 2.28）：
# 覆盖 Qt6 xcb 插件（libQt6XcbQpa / libqxcb / libqxcb-glx-integration）的完整依赖集合，
# 且 libxkbcommon 与 libxkbcommon-x11 成对携带，杜绝版本错配。
VENDORED_X11 = {
    "libxcb-cursor.so.0",
    "libxcb-glx.so.0",
    "libxcb-icccm.so.4",
    "libxcb-image.so.0",
    "libxcb-keysyms.so.1",
    "libxcb-randr.so.0",
    "libxcb-render-util.so.0",
    "libxcb-render.so.0",
    "libxcb-shape.so.0",
    "libxcb-shm.so.0",
    "libxcb-sync.so.1",
    "libxcb-util.so.0",
    "libxcb-xfixes.so.0",
    "libxcb-xkb.so.1",
    "libxkbcommon.so.0",
    "libxkbcommon-x11.so.0",
}


def is_allowed_system(name):
    """该库是否允许由目标系统/驱动提供（不随包携带）。"""
    if name in GLIBC_FAMILY or name in SYSTEM_OK:
        return True
    return bool(DRIVER_RE.match(name))


def is_x11_xkb(name):
    """是否属于 X11/XKB 系统库家族（必须成套处理）。"""
    if not name:
        return False
    if name in VENDORED_X11:
        return True
    return bool(X11_XKB_RE.match(name))


def is_forbidden_bundled(name):
    """禁止随包携带的库：构建机拷贝的 X11/XKB 库（成套白名单之外的）。"""
    return is_x11_xkb(name) and name not in VENDORED_X11


def is_elf(path):
    try:
        with open(path, "rb") as fp:
            return fp.read(4) == b"\x7fELF"
    except OSError:
        return False


def elf_versions(data):
    """返回 (max_glibc_minor, max_glibcxx_patch, max_cxxabi_patch)，缺失记 -1。"""
    g = c = a = -1
    for m in re.findall(rb"GLIBC_2\.(\d+)", data):
        g = max(g, int(m))
    for m in re.findall(rb"GLIBCXX_3\.4\.(\d+)", data):
        c = max(c, int(m))
    for m in re.findall(rb"CXXABI_1\.3\.(\d+)", data):
        a = max(a, int(m))
    return g, c, a
