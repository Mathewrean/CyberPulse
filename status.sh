#!/usr/bin/env bash
# CyberPulse Status Script
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
PIDFILE="$DIR/cyberpulse.pid"
PORT=8844

echo "========================================================"
echo "  CyberPulse Status (Spotify Edition)"
echo "========================================================"

RUNNING=0
if [ -f "$PIDFILE" ]; then
    PID=$(cat "$PIDFILE")
    if ps -p "$PID" > /dev/null 2>&1; then
        RUNNING=1
        echo "Status:          RUNNING (PID: $PID)"
        echo "Dashboard:       http://127.0.0.1:$PORT"
        echo "Memory RSS:      $(ps -o rss= -p "$PID" | awk '{print int($1/1024) " MB"}')"
        echo "CPU Usage:       $(ps -o %cpu= -p "$PID")%"
    fi
fi

if [ "$RUNNING" -eq 0 ]; then
    PIDS=$(pgrep -f "app.py --host 127.0.0.1 --port $PORT")
    if [ -n "$PIDS" ]; then
        echo "Status:          RUNNING (PID: $PIDS)"
        echo "Dashboard:       http://127.0.0.1:$PORT"
        RUNNING=1
    else
        echo "Status:          STOPPED"
    fi
fi

if [ "$RUNNING" -eq 1 ]; then
    echo ""
    echo "Querying API Health..."
    HEALTH=$(curl -s "http://127.0.0.1:$PORT/api/health" 2>/dev/null)
    if [ -n "$HEALTH" ]; then
        echo "API Response:    $HEALTH"
    fi
    STATS=$(curl -s "http://127.0.0.1:$PORT/api/stats" 2>/dev/null)
    if [ -n "$STATS" ]; then
        python3 -c "
import json, sys
data = json.loads('''$STATS''')
print(f'Total Tools:     {data.get(\"total_tools\")} ({data.get(\"installed_tools\")} installed, {data.get(\"missing_tools\")} missing)')
print(f'Active Right Now:{len(data.get(\"live_active\", []))} running tools')
" 2>/dev/null
    fi
fi
echo "========================================================"
