#!/usr/bin/env bash
# ============================================================
#  LVCHA Bridge 启动脚本 (Linux ARM64 / x86_64 通用)
#  SOCKS5 监听 127.0.0.1:10808, 前台运行 (Ctrl+C 停止)
#  依赖: python3 + python3-venv (首次运行自动创建 .venv 并装 pycryptodome)
# ============================================================
set -u
cd "$(dirname "$0")"

PY=python3
VENV=".venv"
BRIDGE="src/lvcha_bridge.py"
PORT=10808

# 1. python3 检查
if ! command -v "$PY" >/dev/null 2>&1; then
    echo "[LVCHA Bridge] 未找到 python3, 请先安装: apt install python3 python3-venv"
    exit 1
fi

# 2. venv 创建 (仅首次)
if [ ! -x "$VENV/bin/python" ]; then
    echo "[LVCHA Bridge] 创建虚拟环境 $VENV ..."
    "$PY" -m venv "$VENV" || { echo "[LVCHA Bridge] venv 创建失败 (缺 python3-venv?)"; exit 1; }
fi

# 3. 依赖安装 (仅缺时)
if ! "$VENV/bin/python" -c "import Crypto" 2>/dev/null; then
    echo "[LVCHA Bridge] 安装 pycryptodome ..."
    "$VENV/bin/pip" install --quiet pycryptodome || exit 1
fi

# 4. 端口占用检查 (ss 或 netstat)
if { ss -ltn 2>/dev/null || netstat -ltn 2>/dev/null; } | awk '{print $4}' | grep -q ":$PORT$"; then
    echo "[LVCHA Bridge] 端口 $PORT 已被占用, 请先运行 ./stop_bridge.sh"
    exit 1
fi

# 5. 前台运行
echo "[LVCHA Bridge] 启动 (127.0.0.1:$PORT), Ctrl+C 停止 ..."
exec "$VENV/bin/python" "$BRIDGE" --port "$PORT" --host 0.0.0.0
