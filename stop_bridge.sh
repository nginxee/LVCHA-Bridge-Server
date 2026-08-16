#!/usr/bin/env bash
# ============================================================
#  停止 LVCHA Bridge (清理残留实例)
# ============================================================
set -u

PIDS=$(pgrep -f "lvcha_bridge.py" 2>/dev/null || true)
if [ -z "$PIDS" ]; then
    echo "[LVCHA Bridge] 未发现运行中的桥接进程"
    exit 0
fi

echo "[LVCHA Bridge] 停止进程: $PIDS"
kill $PIDS 2>/dev/null
sleep 1

# 强制清理未退出的
PIDS=$(pgrep -f "lvcha_bridge.py" 2>/dev/null || true)
if [ -n "$PIDS" ]; then
    echo "[LVCHA Bridge] 强制结束: $PIDS"
    kill -9 $PIDS 2>/dev/null
fi
echo "[LVCHA Bridge] 已停止"
