#!/usr/bin/env bash
# Linux x86_64 绿色包构建脚本（在构建容器内运行，GitLab CI 与 GitHub Actions 复用）。
#
# 流程：便携 Python(glibc 2.17 基线) → 按 manylinux_2_28/2014 安装固定依赖 →
#       自检 → PyInstaller → 裁剪宿主库 → 补齐目标版 libxcb-cursor → 双门禁 →
#       offscreen/xcb 冒烟 → 打 tar.gz
#
# 依赖：bash, tar, python3(系统自带，仅用于下载解压便携 Python), 可选 Xvfb。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

PREFIX="${PREFIX:-/opt/pystd}"
PY="$PREFIX/python/bin/python3"
DIST="dist/CryptoAnalysisTool"
APP="$DIST/CryptoAnalysisTool"
PKG="CryptoAnalysisTool-linux-x86_64.tar.gz"

if [ ! -x "$PY" ]; then
  echo "== 下载便携 Python（python-build-standalone，glibc 2.17 基线）=="
  python3 - "$PREFIX" <<'PYEOF'
import os
import socket
import sys
import tarfile
import urllib.request

prefix = sys.argv[1]
socket.setdefaulttimeout(120)
urls = [
    "https://mirror.nju.edu.cn/github-release/astral-sh/python-build-standalone/20260901/"
    "cpython-3.11.16%2B20260901-x86_64-unknown-linux-gnu-install_only.tar.gz",
    "https://github.com/astral-sh/python-build-standalone/releases/download/20260901/"
    "cpython-3.11.16%2B20260901-x86_64-unknown-linux-gnu-install_only.tar.gz",
]
if os.environ.get("PYSTD_PREFER_GITHUB"):
    urls.reverse()
tgz = "/tmp/pystd.tar.gz"
for url in urls:
    print("下载便携Python:", url, flush=True)
    try:
        urllib.request.urlretrieve(url, tgz)
        print("下载完成", flush=True)
        break
    except Exception as exc:  # noqa: BLE001
        print("该源失败:", exc, flush=True)
else:
    raise SystemExit("所有下载源均失败")
os.makedirs(prefix, exist_ok=True)
with tarfile.open(tgz, "r:gz") as tf:
    tf.extractall(prefix)
print("已解压到", prefix, flush=True)
PYEOF
fi

echo "== Python =="
"$PY" -V

echo "== 安装固定版本依赖（仅 manylinux 轮子）=="
"$PY" -m pip install --no-cache-dir \
  --target "$PREFIX/python/lib/python3.11/site-packages" \
  --platform manylinux_2_28_x86_64 --platform manylinux2014_x86_64 \
  --python-version 311 --implementation cp --abi abi3 --abi cp311 --abi none \
  --only-binary=:all: -r packaging/requirements-build.txt

echo "== 依赖自检 =="
SELFTEST_SKIP_GUI=1 "$PY" packaging/selftest.py

echo "== PyInstaller 打包 =="
"$PY" -m PyInstaller --noconfirm --clean --windowed --name CryptoAnalysisTool \
  --distpath dist --workpath build --specpath build \
  --collect-submodules scapy \
  --exclude-module matplotlib --exclude-module numpy --exclude-module PIL \
  --exclude-module tkinter --exclude-module _tkinter \
  main.py

echo "== 裁剪宿主系统库 =="
"$PY" packaging/prune_bundle.py "$DIST"

echo "== 补齐目标兼容版 libxcb-cursor.so.0 =="
"$PY" packaging/vendor_libxcb_cursor.py "$DIST"

echo "== 门禁：符号版本兼容性 =="
"$PY" packaging/check_compat.py "$DIST"

echo "== 门禁：自包含性（ldd）=="
"$PY" packaging/check_selfcontained.py "$DIST"

echo "== 冒烟：offscreen =="
QT_QPA_PLATFORM=offscreen "$APP" >/tmp/app_offscreen.log 2>&1 &
APP_PID=$!
sleep 15
if kill -0 "$APP_PID" 2>/dev/null; then
  kill "$APP_PID" 2>/dev/null || true
  echo OFFSCREEN_SMOKE_OK
else
  echo OFFSCREEN_SMOKE_FAIL
  tail -n 60 /tmp/app_offscreen.log
  exit 1
fi

echo "== 冒烟：xcb 平台（Xvfb，真实加载 libqxcb.so）=="
if command -v Xvfb >/dev/null 2>&1; then
  Xvfb :99 -screen 0 1280x800x24 >/tmp/xvfb.log 2>&1 &
  XVFB_PID=$!
  sleep 3
  DISPLAY=:99 QT_QPA_PLATFORM=xcb "$APP" >/tmp/app_xcb.log 2>&1 &
  APP_PID=$!
  sleep 20
  if kill -0 "$APP_PID" 2>/dev/null; then
    kill "$APP_PID" 2>/dev/null || true
    if grep -q "已启动" /tmp/app_xcb.log; then
      echo "XCB_SMOKE_OK（已确认启动日志）"
    else
      echo "XCB_SMOKE_OK（进程存活）"
    fi
  else
    echo XCB_SMOKE_FAIL
    tail -n 80 /tmp/app_xcb.log
    kill "$XVFB_PID" 2>/dev/null || true
    exit 1
  fi
  kill "$XVFB_PID" 2>/dev/null || true
else
  echo "警告：未安装 Xvfb，跳过 xcb 冒烟"
fi

echo "== 归档 =="
tar -czf "$PKG" -C dist CryptoAnalysisTool
ls -lh "$PKG"
echo BUILD_ALL_OK
