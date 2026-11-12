#!/usr/bin/env bash
# CyberPulse Stop Script
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
PIDFILE="$DIR/cyberpulse.pid"

if [ -f "$PIDFILE" ]; then
    PID=$(cat "$PIDFILE")
    if ps -p "$PID" > /dev/null 2>&1; then
        echo "[CyberPulse] Stopping process PID $PID ..."
        kill "$PID"
        sleep 1
        if ps -p "$PID" > /dev/null 2>&1; then
            echo "[CyberPulse] Force terminating PID $PID ..."
            kill -9 "$PID"
        fi
        echo "[CyberPulse] Stopped."
    else
        echo "[CyberPulse] Process $PID is not running."
    fi
    rm -f "$PIDFILE"
else
    # Fallback to pkill if pidfile wasn't found
    PIDS=$(pgrep -f "app.py --host 127.0.0.1 --port 8844")
    if [ -n "$PIDS" ]; then
        echo "[CyberPulse] Stopping active instances ($PIDS) ..."
        kill $PIDS
        echo "[CyberPulse] Stopped."
    else
        echo "[CyberPulse] No running instance detected."
    fi
fi
