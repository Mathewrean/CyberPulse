#!/usr/bin/env bash
# CyberPulse Restart Script
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
"$DIR/stop.sh"
sleep 1
"$DIR/start.sh"
