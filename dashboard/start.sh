#!/bin/bash
# AI Radar Dashboard 启动脚本
# 用法: ./dashboard/start.sh        (前台运行)
#       ./dashboard/start.sh daemon  (后台守护运行)

cd "$(dirname "$0")/.."
LOG="/tmp/ai-radar-dashboard.log"
PIDFILE="/tmp/ai-radar-dashboard.pid"

stop_existing() {
    if [ -f "$PIDFILE" ]; then
        OLD_PID=$(cat "$PIDFILE")
        if kill -0 "$OLD_PID" 2>/dev/null; then
            echo "[Dashboard] Stopping existing process (PID $OLD_PID)..."
            kill "$OLD_PID"
            sleep 1
        fi
        rm -f "$PIDFILE"
    fi
    # Also kill any other instances
    pkill -f "python3 dashboard/server.py" 2>/dev/null || true
}

if [ "$1" = "daemon" ]; then
    stop_existing
    echo "[Dashboard] Starting in daemon mode..."
    nohup python3 dashboard/server.py > "$LOG" 2>&1 &
    echo $! > "$PIDFILE"
    sleep 2
    if curl -s http://localhost:9090/api/stats > /dev/null 2>&1; then
        echo "[Dashboard] Running at http://localhost:9090 (PID $(cat $PIDFILE))"
        echo "[Dashboard] Log: $LOG"
    else
        echo "[Dashboard] FAILED to start. Check $LOG"
        cat "$LOG" | tail -20
    fi
elif [ "$1" = "stop" ]; then
    stop_existing
    echo "[Dashboard] Stopped."
elif [ "$1" = "status" ]; then
    if [ -f "$PIDFILE" ] && kill -0 "$(cat $PIDFILE)" 2>/dev/null; then
        echo "[Dashboard] Running (PID $(cat $PIDFILE))"
    else
        echo "[Dashboard] Not running"
    fi
else
    stop_existing
    echo "[Dashboard] Starting at http://localhost:9090 (Ctrl+C to stop)"
    python3 dashboard/server.py
fi
