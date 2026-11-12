#!/usr/bin/env bash
# CyberPulse uninstall script
# Stops the service and removes the app files. User data (data/*.db) is kept by default.
set -u

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
WIPE_DATA=0

for arg in "$@"; do
    case "$arg" in
        --wipe-data) WIPE_DATA=1 ;;
        -h|--help)
            echo "Usage: $0 [--wipe-data]"
            echo "  --wipe-data  Also delete data/cyberpulse.db and logs"
            exit 0
            ;;
    esac
done

echo "============================================================"
echo "  CyberPulse Uninstaller"
echo "============================================================"

# 1. Stop running instance
if [ -f "$DIR/stop.sh" ]; then
    "$DIR/stop.sh" 2>/dev/null || true
fi
pkill -f "app.py --host 127.0.0.1 --port 8844" 2>/dev/null || true

# 2. Remove systemd user service
if [ -f "$HOME/.config/systemd/user/cyberpulse.service" ]; then
    systemctl --user disable --now cyberpulse.service 2>/dev/null || true
    systemctl --user daemon-reload 2>/dev/null || true
    rm -f "$HOME/.config/systemd/user/cyberpulse.service"
    echo "[+] Removed systemd user service."
fi

# 3. Remove runtime artifacts (logs, pid, pycache)
rm -f "$DIR/cyberpulse.log" "$DIR/cyberpulse.pid"
rm -rf "$DIR/backend/__pycache__"
echo "[+] Removed runtime artifacts (logs, pid, __pycache__)."

# 4. Optionally wipe user data
if [ "$WIPE_DATA" -eq 1 ]; then
    rm -f "$DIR/data/cyberpulse.db" "$DIR/data/cyberpulse.db-journal"
    rm -rf "$DIR/data/manuals" "$DIR/data/exports"
    echo "[+] Wiped user data (data/*.db, manuals, exports)."
else
    echo "[~] Kept user data in data/ (use --wipe-data to remove)."
fi

echo ""
echo "============================================================"
echo "  Uninstall complete."
echo "============================================================"
