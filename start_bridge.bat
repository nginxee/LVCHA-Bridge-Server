@echo off
title LVCHA Service
rem ============================================================
rem  LVCHA Bridge 启动 (前台终端, 实时显示日志)
rem  SOCKS5 监听 127.0.0.1:10808, 日志同时写入 captures\logsridge.log
rem  退出: Ctrl+C 或直接关闭本窗口
rem ============================================================
cd /d "%~dp0"

rem 检查端口是否已被占用
powershell -NoProfile -Command "if (Get-NetTCPConnection -LocalPort 10808 -State Listen -ErrorAction SilentlyContinue) { exit 1 } else { exit 0 }"
if %errorlevel%==1 (
    echo [LVCHA Bridge] 端口 10808 已在监听, 可能已运行。
    echo 若需停止: 运行 stop_bridge.bat
    if /i not "%~1"=="/q" pause
    exit /b 1
)

echo [LVCHA Bridge] 启动中 (127.0.0.1:10808) ...
echo 按 Ctrl+C 停止本窗口
echo.
python "%~dp0src\lvcha_bridge.py" --port 10808 --host 0.0.0.0

echo.
echo [LVCHA Bridge] 已退出。
if /i not "%~1"=="/q" pause
