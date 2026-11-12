#!/usr/bin/env bash
# CyberPulse Startup Script - idempotent
# Binds to 127.0.0.1 only (not exposed to the network).
set -u

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
PIDFILE="$DIR/cyberpulse.pid"
LOGFILE="$DIR/cyberpulse.log"
PYTHON="${CYBERPULSE_PYTHON:-/usr/bin/python3}"

# Read host/port from config.yaml if available, else defaults
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

if [ -f "$PIDFILE" ]; then
    OLD_PID=$(cat "$PIDFILE" 2>/dev/null)
    if [ -n "$OLD_PID" ] && ps -p "$OLD_PID" > /dev/null 2>&1; then
        echo "[CyberPulse] Already running (PID: $OLD_PID) at http://$HOST:$PORT"
        exit 0
    else
        rm -f "$PIDFILE"
    fi
fi

# Fallback: detect any already-running instance on the same port
RUNNING_PID=$(pgrep -f "app.py --host $HOST --port $PORT" 2>/dev/null | head -n1)
if [ -n "$RUNNING_PID" ]; then
    echo "[CyberPulse] Already running (PID: $RUNNING_PID) at http://$HOST:$PORT"
    echo "$RUNNING_PID" > "$PIDFILE"
    exit 0
fi

echo "[CyberPulse] Starting CyberPulse daemon on http://$HOST:$PORT ..."
nohup "$PYTHON" "$DIR/app.py" --host "$HOST" --port "$PORT" > "$LOGFILE" 2>&1 &
NEW_PID=$!
echo "$NEW_PID" > "$PIDFILE"

# Wait briefly to confirm startup
sleep 1.5

if ps -p "$NEW_PID" > /dev/null 2>&1; then
    echo "[CyberPulse] Successfully started (PID: $NEW_PID)."
    echo "[CyberPulse] Access dashboard at: http://$HOST:$PORT"
    if [ -n "${DISPLAY:-}" ] && which xdg-open > /dev/null 2>&1; then
        xdg-open "http://$HOST:$PORT" > /dev/null 2>&1 &
    fi
else
    echo "[CyberPulse] Failed to start. Checking log:"
    tail -n 20 "$LOGFILE" 2>/dev/null
    rm -f "$PIDFILE"
    exit 1
fi
