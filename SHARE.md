# Sharing CyberPulse With Other Users

CyberPulse is packaged to run on any Linux system (Kali, Debian, Ubuntu, Mint, Parrot OS, Arch, Fedora) with Python 3.

---

## 1. Generating the Shareable Archive
On your machine, simply run:
```bash
cd ~/Desktop/CyberPulse
./share_bundle.sh
```
This produces two clean archives directly on your Desktop:
- `CyberPulse_Distribution.zip`
- `CyberPulse_Distribution.tar.gz`

---

## 2. Recipient Quick Setup Instructions
Give the `.zip` or `.tar.gz` to the recipient. On their machine:

### Step 1: Extract
```bash
unzip CyberPulse_Distribution.zip
# Or: tar -xzf CyberPulse_Distribution.tar.gz
cd CyberPulse*
```

### Step 2: Install Minimal Requirements (if needed)
CyberPulse uses Python standard libraries plus `fastapi`, `uvicorn`, and `psutil`. On Kali/Debian/Ubuntu:
```bash
sudo apt update && sudo apt install -y python3-fastapi python3-uvicorn python3-psutil
```

### Step 3: Launch
```bash
./start.sh
```
Open `http://127.0.0.1:8844` in any web browser.

### Step 4: Optional 24/7 Autostart (Systemd)
To have CyberPulse run automatically on their machine:
```bash
mkdir -p ~/.config/systemd/user
cp cyberpulse.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now cyberpulse.service
```
