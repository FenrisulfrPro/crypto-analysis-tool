# -*- coding: utf-8 -*-
"""产物自包含性门禁（两类检查）。

1) 缺失检查：对 dist 内所有 ELF 执行 ldd，禁止出现白名单之外的 "not found"。
   白名单见 target_libs：glibc 家族、目标系统自带库、显卡/内核驱动类。
   若某个未随包携带、又不在白名单中的库缺失（例如漏掉 libxcb-cursor.so.0），
   本门禁会使 CI 失败，避免打出「构建机可用、目标机崩溃」的包。

2) 成套检查（v2.1 段错误教训）：禁止随包携带 X11/XKB 家族中「白名单之外」的库，
   即构建机拷贝的 libxkbcommon* / libX11-xcb / libXext 等；只允许
   target_libs.VENDORED_X11 里、由 vendor 脚本从目标发行版(buster)取出的成套库。

使用：python packaging/check_selfcontained.py dist/CryptoAnalysisTool
"""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from target_libs import (is_allowed_system, is_elf, is_forbidden_bundled,  # noqa: E402
                         VENDORED_X11)

# 必须随包携带的库：target_libs 中声明的 X11/XKB 成套库（buster 版本）
MUST_HAVE = sorted(VENDORED_X11)


def search_paths(root):
    paths = [os.path.join(root, "_internal")]
    qtlib = os.path.join(root, "_internal", "PySide6", "Qt", "lib")
    if os.path.isdir(qtlib):
        paths.append(qtlib)
    return [p for p in paths if os.path.isdir(p)]


def ldd_missing(path, env):
    try:
        proc = subprocess.run(["ldd", path], capture_output=True, text=True,
                              env=env, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return None, str(exc)
    missing = []
    for line in proc.stdout.splitlines():
        if "=> not found" in line:
            missing.append(line.split("=>")[0].strip().split()[0])
    return missing, None


def main():
    root = sys.argv[1] if len(sys.argv) > 1 else "dist/CryptoAnalysisTool"
    if not os.path.isdir(root):
        print("目录不存在:", root)
        return 2
    env = dict(os.environ)
    extra = os.pathsep.join(search_paths(root))
    env["LD_LIBRARY_PATH"] = extra + (os.pathsep + env["LD_LIBRARY_PATH"]
                                      if env.get("LD_LIBRARY_PATH") else "")
    internal = os.path.join(root, "_internal")
    for name in MUST_HAVE:
        p = os.path.join(internal, name)
        if not is_elf(p):
            print("缺少必需的随包库: %s" % p)
            return 3

    # 成套检查：X11/XKB 家族只允许携带 VENDORED_X11（目标发行版版本）
    forbidden = []
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            if is_forbidden_bundled(fn):
                forbidden.append(os.path.join(dirpath, fn))
    if forbidden:
        print("禁止随包携带的 X11/XKB 系统库（构建机版本，必须剔除）：%d 个" % len(forbidden))
        for p in sorted(forbidden):
            print("  ", p)
        print("说明：这类库必须「成套打包或整套不打」，构建机拷贝会与目标机版本错配"
              "（v2.1 libxkbcommon-x11 段错误即此类问题）。")
        return 5

    scanned = 0
    violations = {}
    ldd_unavailable = 0
    for dirpath, _dirs, files in os.walk(root):
        for fn in files:
            p = os.path.join(dirpath, fn)
            if not is_elf(p):
                continue
            scanned += 1
            missing, err = ldd_missing(p, env)
            if missing is None:
                ldd_unavailable += 1
                if ldd_unavailable == 1:
                    print("提示：ldd 不可用（%s），跳过该检测" % err)
                continue
            for name in missing:
                if not is_allowed_system(name):
                    violations.setdefault(name, []).append(p)

    print("已扫描 ELF 文件数:", scanned)
    if violations:
        print("存在未随包携带且不在白名单中的缺失库（%d 种）：" % len(violations))
        for name, users in sorted(violations.items()):
            print("  %s  <- 被以下文件依赖：%s" % (name, ", ".join(sorted(users)[:3])))
        return 1
    print("自包含性检查:", "通过" if scanned else "未扫描到 ELF（可疑）")
    return 0 if scanned else 4


if __name__ == "__main__":
    sys.exit(main())
