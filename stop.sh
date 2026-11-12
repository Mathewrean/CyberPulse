#!/usr/bin/env bash
# CyberPulse Stop Script - idempotent
set -u

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
PIDFILE="$DIR/cyberpulse.pid"
HOST="127.0.0.1"
PORT=8844

if [ -f "$PIDFILE" ]; then
    PID=$(cat "$PIDFILE" 2>/dev/null)
    if [ -n "$PID" ] && ps -p "$PID" > /dev/null 2>&1; then
        echo "[CyberPulse] Stopping process PID $PID ..."
        kill "$PID" 2>/dev/null || true
        for i in $(seq 1 10); do
            if ! ps -p "$PID" > /dev/null 2>&1; then
                break
            fi
            sleep 0.5
        done
        if ps -p "$PID" > /dev/null 2>&1; then
            echo "[CyberPulse] Force terminating PID $PID ..."
            kill -9 "$PID" 2>/dev/null || true
        fi
        echo "[CyberPulse] Stopped."
    else
        echo "[CyberPulse] Process $PID is not running."
    fi
    rm -f "$PIDFILE"
fi

# Fallback: stop any instance matching the app on this host/port
PIDS=$(pgrep -f "app.py --host $HOST --port $PORT" 2>/dev/null)
if [ -n "$PIDS" ]; then
    echo "[CyberPulse] Stopping active instances ($PIDS) ..."
    kill $PIDS 2>/dev/null || true
    sleep 1
    for p in $PIDS; do
        kill -9 "$p" 2>/dev/null || true
    done
    echo "[CyberPulse] Stopped."
else
    if [ ! -f "$PIDFILE" ]; then
        echo "[CyberPulse] No running instance detected."
    fi
fi
