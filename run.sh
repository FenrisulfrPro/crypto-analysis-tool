#!/usr/bin/env bash
#===============================================================
# 项目启动脚本 (uv 版本)
# 系统: Ubuntu 24.04
# 依赖: PySide6, gmssl, scapy, cryptography, matplotlib
#===============================================================
set -e  # 任一步骤失败立即退出

#------------------- 配置区 -------------------
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${PROJECT_DIR}/.venv"
REQUIREMENTS="${PROJECT_DIR}/requirements.txt"
MAIN_FILE="${PROJECT_DIR}/main.py"

cd "${PROJECT_DIR}"

#===============================================================
# 步骤 1: 检查 uv 是否存在
#===============================================================
echo "==> [1/4] 检查 uv 是否已安装..."

if command -v uv &>/dev/null; then
    UV_VERSION=$(uv --version)
    echo "    ✅ uv 已安装: ${UV_VERSION}"
else
    echo "    ❌ 未检测到 uv，正在自动安装..."
    curl -LsSf https://astral.sh/uv/install.sh | sh

    # 加载环境变量（安装后 uv 位于 ~/.local/bin）
    export PATH="$HOME/.local/bin:$PATH"

    # 再次验证
    if command -v uv &>/dev/null; then
        echo "    ✅ uv 安装成功: $(uv --version)"
    else
        echo "    ❌ uv 安装失败，请手动安装后重试"
        exit 1
    fi
fi

#===============================================================
# 步骤 2: 检查虚拟环境是否存在
#===============================================================
echo "==> [2/4] 检查虚拟环境..."

if [ -d "${VENV_DIR}" ]; then
    echo "    ✅ 虚拟环境已存在: ${VENV_DIR}"
else
    echo "    ⚠️  虚拟环境不存在，正在创建..."
    uv venv "${VENV_DIR}"
    echo "    ✅ 虚拟环境创建成功"
fi

#===============================================================
# 步骤 3: 检查并安装依赖包
#===============================================================
echo "==> [3/4] 检查并安装依赖包..."

# 使用 uv pip 安装 requirements.txt
# uv 有全局缓存，已安装/已缓存的包会秒级跳过，重复执行无副作用
uv pip install \
    --python "${VENV_DIR}/bin/python" \
    -r "${REQUIREMENTS}"

echo "    ✅ 依赖检查完成，当前已安装的包:"
uv pip list --python "${VENV_DIR}/bin/python" | grep -Ei "pyside6|gmssl|scapy|cryptography|matplotlib" || true

#===============================================================
# 步骤 4: 启动项目
#===============================================================
echo "==> [4/4] 启动项目..."

if [ ! -f "${MAIN_FILE}" ]; then
    echo "    ❌ 未找到启动文件: ${MAIN_FILE}"
    exit 1
fi

echo "    🚀 使用 $(realpath "${VENV_DIR}/bin/python") 运行 main.py"
echo "---------------------------------------------------------------"

# 用虚拟环境的 python 直接运行（无需 activate）
exec "${VENV_DIR}/bin/python" "${MAIN_FILE}"
