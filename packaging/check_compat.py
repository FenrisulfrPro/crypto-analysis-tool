# -*- coding: utf-8 -*-
"""扫描打包产物内 ELF 文件的 glibc / libstdc++ 符号需求，校验可在 Debian 10 (buster) 运行。

使用：python packaging/check_compat.py dist/CryptoAnalysisTool
超过基线（GLIBC_2.28 / GLIBCXX_3.4.25 / CXXABI_1.3.11，对应 buster 的 glibc 与 gcc-8）即失败。"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from target_libs import GLIBC_LIMIT, GLIBCXX_LIMIT, CXXABI_LIMIT  # noqa: E402


def scan(root):
    max_glibc = max_cxx = max_abi = -1
    f_glibc = f_cxx = f_abi = ""
    offenders = []
    scanned = 0
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            path = os.path.join(dirpath, fn)
            try:
                with open(path, "rb") as fp:
                    if fp.read(4) != b"\x7fELF":
                        continue
                    data = fp.read()
            except OSError:
                continue
            scanned += 1
            g = c = a = -1
            for m in re.findall(rb"GLIBC_2\.(\d+)", data):
                g = max(g, int(m))
            for m in re.findall(rb"GLIBCXX_3\.4\.(\d+)", data):
                c = max(c, int(m))
            for m in re.findall(rb"CXXABI_1\.3\.(\d+)", data):
                a = max(a, int(m))
            if g > max_glibc:
                max_glibc, f_glibc = g, path
            if c > max_cxx:
                max_cxx, f_cxx = c, path
            if a > max_abi:
                max_abi, f_abi = a, path
            if g > GLIBC_LIMIT or c > GLIBCXX_LIMIT or a > CXXABI_LIMIT:
                offenders.append((path, g, c, a))
    return max_glibc, f_glibc, max_cxx, f_cxx, max_abi, f_abi, offenders, scanned


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "dist/CryptoAnalysisTool"
    if not os.path.isdir(root):
        print("目录不存在:", root)
        return 2
    g, fg, c, fc, a, fa, offenders, scanned = scan(root)
    print("已扫描 ELF 文件数:", scanned)
    print("最高 GLIBC  需求: 2.%d  (%s)" % (g, fg))
    print("最高 GLIBCXX 需求: 3.4.%d (%s)" % (c, fc))
    print("最高 CXXABI  需求: 1.3.%d (%s)" % (a, fa))
    if offenders:
        print("超限文件清单（%d 个）：" % len(offenders))
        for path, og, oc, oa in sorted(offenders):
            print("  %s  [GLIBC 2.%d / GLIBCXX 3.4.%d / CXXABI 1.3.%d]" % (path, og, oc, oa))
    ok = g <= GLIBC_LIMIT and c <= GLIBCXX_LIMIT and a <= CXXABI_LIMIT
    print("Debian 10 (buster/凝思) 兼容性:", "通过" if ok else "不通过")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
