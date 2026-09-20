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
    "libX11.so.6", "libXau.so.6", "libXdmcp.so.6", "libXext.so.6", "libXi.so.6",
    "libXrender.so.1", "libXfixes.so.3", "libXrandr.so.2", "libXcursor.so.1",
    "libXinerama.so.1", "libXcomposite.so.1", "libXdamage.so.1", "libXtst.so.6",
    "libSM.so.6", "libICE.so.6", "liblzma.so.5", "libgcrypt.so.20", "libcap.so.2",
    "libxml2.so.2", "libgpg-error.so.0", "libsystemd.so.0", "libm.so.6",
}

# 显卡 / 内核驱动类：由目标机显卡驱动提供
DRIVER_RE = re.compile(
    r"^lib(GL|GLX|EGL|GLdispatch|OpenGL|glapi|drm|gbm|nvidia|nvcuvid|nvidia-|cuda|vdpau|va|XvMC)"
)


def is_allowed_system(name):
    """该库是否允许由目标系统/驱动提供（不随包携带）。"""
    if name in GLIBC_FAMILY or name in SYSTEM_OK:
        return True
    return bool(DRIVER_RE.match(name))


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
