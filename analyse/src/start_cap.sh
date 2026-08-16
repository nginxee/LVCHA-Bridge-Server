#!/system/bin/sh
# 5分钟抓包脚本 - 用 root 执行
LOG=/data/local/tmp/capture.pcap
DURATION=300

echo "[CAP] start at $(date '+%H:%M:%S')"
tcpdump -i any -s 0 -w "$LOG" 2>/dev/null &
TCPDUMP_PID=$!
echo "[CAP] tcpdump pid=$TCPDUMP_PID"
sleep $DURATION
kill $TCPDUMP_PID 2>/dev/null
wait $TCPDUMP_PID 2>/dev/null
echo "[CAP] stop at $(date '+%H:%M:%S'), file ready"
ls -lh "$LOG"
