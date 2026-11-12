#!/usr/bin/env bash
# CyberPulse install script
# Installs runtime dependencies and makes the suite ready to run on Kali/Debian.
set -u

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
PYTHON="${CYBERPULSE_PYTHON:-python3}"

echo "============================================================"
echo "  CyberPulse Installer"
echo "============================================================"

# 1. Python 3
if ! command -v "$PYTHON" >/dev/null 2>&1; then
    echo "[!] $PYTHON not found. Install it first (e.g. sudo apt install python3)."
    exit 1
fi
echo "[+] Python: $($PYTHON --version)"

# 2. Runtime dependencies (fastapi, uvicorn, psutil). Prefer system packages, fall back to pip.
install_via_pip=0
if command -v apt-get >/dev/null 2>&1; then
    if dpkg -s python3-fastapi python3-uvicorn python3-psutil >/dev/null 2>&1; then
        echo "[+] System packages python3-fastapi/python3-uvicorn/python3-psutil present."
    else
        echo "[~] Installing system packages (may require sudo)..."
        sudo apt-get update -y && sudo apt-get install -y python3-fastapi python3-uvicorn python3-psutil || install_via_pip=1
    fi
else
    install_via_pip=1
fi

if [ "$install_via_pip" -eq 1 ]; then
    echo "[~] Installing via pip..."
    "$PYTHON" -m pip install --upgrade pip
    "$PYTHON" -m pip install fastapi uvicorn psutil
fi

# 3. Make scripts executable
chmod +x "$DIR/start.sh" "$DIR/stop.sh" "$DIR/status.sh" "$DIR/restart.sh" "$DIR/share_bundle.sh"
echo "[+] Scripts made executable."

# 4. Ensure config.local.yaml exists (machine-specific overrides, not committed)
if [ ! -f "$DIR/config.local.yaml" ]; then
    cp "$DIR/config.yaml" "$DIR/config.local.yaml" 2>/dev/null || true
    echo "[~] Created config.local.yaml (edit for machine-specific paths)."
fi

# 5. Optional systemd user service
if [ -d "$HOME/.config/systemd/user" ] || mkdir -p "$HOME/.config/systemd/user" 2>/dev/null; then
    cp "$DIR/cyberpulse.service" "$HOME/.config/systemd/user/cyberpulse.service"
    # Rewrite WorkingDirectory/ExecStart to point at this install dir
    sed -i "s#WorkingDirectory=.*#WorkingDirectory=$DIR#" "$HOME/.config/systemd/user/cyberpulse.service"
    sed -i "s#ExecStart=.*#ExecStart=$PYTHON $DIR/app.py --host 127.0.0.1 --port 8844#" "$HOME/.config/systemd/user/cyberpulse.service"
    systemctl --user daemon-reload 2>/dev/null || true
    echo "[~] systemd user service installed (not enabled). Run: systemctl --user enable --now cyberpulse.service"
fi

echo ""
echo "============================================================"
echo "  Install complete."
echo "  Run:  cd $DIR && ./start.sh"
echo "  Open: http://127.0.0.1:8844"
echo "============================================================"
