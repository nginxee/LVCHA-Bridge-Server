@echo off
rem ============================================================
rem  LVCHA Bridge 停止 (按 10808 端口定位进程, 不影响其他程序)
rem  用法: stop_bridge.bat [/q]   (/q = 静默, 不暂停)
rem ============================================================
powershell -NoProfile -Command "$p = Get-NetTCPConnection -LocalPort 10808 -State Listen -ErrorAction SilentlyContinue | Select-Object -ExpandProperty OwningProcess -Unique; if ($p) { $p | ForEach-Object { Stop-Process -Id $_ -Force }; Write-Host '[OK] 桥接已停止' } else { Write-Host '[INFO] 桥接未在运行' }"
if /i not "%~1"=="/q" pause
