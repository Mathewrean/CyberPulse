#!/usr/bin/env bash
# CyberPulse Startup Script
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
PIDFILE="$DIR/cyberpulse.pid"
LOGFILE="$DIR/cyberpulse.log"
PYTHON="/usr/bin/python3"
PORT=8844

if [ -f "$PIDFILE" ]; then
    PID=$(cat "$PIDFILE")
    if ps -p "$PID" > /dev/null 2>&1; then
        echo "[CyberPulse] Already running (PID: $PID) at http://127.0.0.1:$PORT"
        exit 0
    else
        rm -f "$PIDFILE"
    fi
fi

echo "[CyberPulse] Starting CyberPulse daemon on http://127.0.0.1:$PORT ..."
nohup "$PYTHON" "$DIR/app.py" --host 127.0.0.1 --port "$PORT" > "$LOGFILE" 2>&1 &
NEW_PID=$!
echo "$NEW_PID" > "$PIDFILE"

# Wait a brief moment to ensure startup
sleep 1.5

if ps -p "$NEW_PID" > /dev/null 2>&1; then
    echo "[CyberPulse] Successfully started (PID: $NEW_PID)."
    echo "[CyberPulse] Access dashboard at: http://127.0.0.1:$PORT"
    
    # Attempt to open browser if running interactively in desktop session
    if [ -n "$DISPLAY" ] && which xdg-open > /dev/null 2>&1; then
        xdg-open "http://127.0.0.1:$PORT" > /dev/null 2>&1 &
    fi
else
    echo "[CyberPulse] Failed to start. Checking log:"
    tail -n 20 "$LOGFILE"
    exit 1
fi
