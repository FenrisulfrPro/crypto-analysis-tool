#!/usr/bin/env sh
# CryptoAnalysisTool - Linux 一键启动（双击或 ./run.sh 运行）
cd "$(dirname "$0")"

# ---- 检查 Python ----
if ! command -v python3 >/dev/null 2>&1; then
    echo "[ERROR] 未找到 python3，请先安装 Python 3.9+："
    echo "   Ubuntu/Debian:  sudo apt install python3 python3-pip python3-venv"
    exit 1
fi

# ---- 检查 / 安装依赖（首次运行自动安装） ----
if ! python3 -c "import PySide6, gmssl, scapy, cryptography" >/dev/null 2>&1; then
    echo "[INFO] 首次运行：正在安装依赖，请稍候..."
    python3 -m pip install -r requirements.txt
    if [ $? -ne 0 ]; then
        echo "[ERROR] 依赖安装失败，请手动执行："
        echo "   python3 -m pip install -r requirements.txt"
        exit 1
    fi
fi

echo "[OK] 启动 CryptoAnalysisTool..."
python3 main.py
