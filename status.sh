#!/usr/bin/env bash
# CyberPulse Status Script
set -u

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
PIDFILE="$DIR/cyberpulse.pid"
HOST="127.0.0.1"
PORT=8844

if command -v python3 >/dev/null 2>&1 && [ -f "$DIR/config.yaml" ]; then
    read -r HOST PORT < <(python3 - "$DIR/config.yaml" <<'PY'
import sys, re
path = sys.argv[1]
text = open(path).read()
m_host = re.search(r'^host:\s*"([^"]+)"', text, re.M)
m_port = re.search(r'^port:\s*(\d+)', text, re.M)
print((m_host.group(1) if m_host else "127.0.0.1"), (m_port.group(1) if m_port else "8844"))
PY
    )
fi

echo "========================================================"
echo "  CyberPulse Status"
echo "========================================================"

RUNNING=0
PID=""
if [ -f "$PIDFILE" ]; then
    PID=$(cat "$PIDFILE" 2>/dev/null)
    if [ -n "$PID" ] && ps -p "$PID" > /dev/null 2>&1; then
        RUNNING=1
    fi
fi

if [ "$RUNNING" -eq 0 ]; then
    FOUND=$(pgrep -f "app.py --host $HOST --port $PORT" 2>/dev/null | head -n1)
    if [ -n "$FOUND" ]; then
        PID="$FOUND"
        RUNNING=1
        echo "$PID" > "$PIDFILE"
    fi
fi

if [ "$RUNNING" -eq 1 ]; then
    echo "Status:          RUNNING (PID: $PID)"
    echo "Dashboard:       http://$HOST:$PORT"
    echo "Memory RSS:      $(ps -o rss= -p "$PID" 2>/dev/null | awk '{print int($1/1024) " MB"}')"
    echo "CPU Usage:       $(ps -o %cpu= -p "$PID" 2>/dev/null)%"
else
    echo "Status:          STOPPED"
fi

if [ "$RUNNING" -eq 1 ]; then
    echo ""
    echo "Querying API Health..."
    HEALTH=$(curl -s "http://$HOST:$PORT/api/health" 2>/dev/null)
    if [ -n "$HEALTH" ]; then
        echo "API Response:    $HEALTH"
    fi
    STATS=$(curl -s "http://$HOST:$PORT/api/stats" 2>/dev/null)
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
