# CyberPulse Security Suite (Spotify Edition)

> **A Comprehensive Cybersecurity Tool Checklist, Real-Time Process & Usage Monitor, and Incident & Scenario Advisor**  
> Custom-engineered for Kali Linux and Debian systems with authentic Spotify Dark and Light design themes.

---

## 🌟 Key Features

1. **System-Wide Deep Tool Detection & Checklist (260+ Tools)**
   - Scans system binary `$PATH` (`/usr/bin`, `/usr/sbin`, `/usr/local/bin`, `~/.local/bin`, `/opt/*`).
   - Parses Kali Linux Desktop applications (`/usr/share/applications/kali-*.desktop`).
   - Rapidly queries the Debian/Kali `dpkg` database in batch.
   - Detects custom security installations (e.g. `/opt/burpsuite_pro`, `/opt/PenligentV3`, `/opt/pt`).
   - Categorizes tools across 15 standard domains:
     - *Information Gathering*
     - *Web Applications*
     - *Active Directory & Post-Exploitation*
     - *Password Attacks*
     - *Wireless Attacks*
     - *Forensics & Incident Response*
     - *Reverse Engineering*
     - *Sniffing & Spoofing*
     - *Exploitation Tools*
     - *Privilege Escalation*
     - *Database Assessment*
     - *Collection & Exfiltration*
     - *Defense Evasion*
     - *Reporting & Documentation*
     - *General Security*

2. **Rich Tool Details & Educational Knowledge Base**
   - **Usage Description**: Clear operational overview of what each tool does.
   - **Cheatsheet & Syntax**: Ready-to-copy commands with one-click clipboard copying.
   - **Real-World Scenarios**: Concrete incident response or penetration testing use cases.
   - **MITRE ATT&CK Mappings**: Tactics and techniques (e.g. `T1046`, `T1003`, `T1190`).
   - **Learning References**: Direct links to official documentation, Kali tools pages, TryHackMe/HackTheBox labs, and manuals.
   - **Mastery Tracker**: Mark tools as *Not Started*, *Learning*, *Practicing*, or *Mastered*.

3. **Background Process & Usage Time Monitor ("Always Running")**
   - Continuously monitors active running processes using lightweight background polling.
   - Detects tool executions (e.g., `nmap`, `burpsuite`, `hydra`, `wireshark`, `tcpdump`, `ffuf`, etc.).
   - Tracks:
     - **Execution Count**: Number of times each tool was launched.
     - **Active Uptime**: Cumulative runtime duration (seconds, minutes, hours).
     - **Live Monitor**: Active PIDs, live duration timer, CPU %, and memory usage.
     - **Historical Telemetry**: Execution logs stored in local SQLite database.

4. **Incident & Scenario Advisor (Offline Expert + Online AI)**
   - Paste any security incident alert, CTF challenge, or penetration testing objective:
     - e.g. *"Internal workstation sending repetitive Kerberos TGS requests and dumping SAM credentials over SMB."*
   - Returns:
     - **Detected Incident Domain & MITRE ATT&CK Mapping**.
     - **Tool Readiness**: Highlights which recommended tools are **Installed & Ready** vs **Missing / Available to Install** (with exact `sudo apt install` commands).
     - **Phased Playbook**: Stage 1 (Triage & Recon), Stage 2 (Execution & Investigation), Stage 3 (Post-Analysis & Containment), and Remediation & Hardening.
     - **Executable Commands**: Copy-paste terminal snippets with placeholders (`<TARGET_IP>`, `<PCAP>`, etc.).
   - **Dual Engine**: Works 100% offline via embedded threat engine, and automatically enhances recommendations with online AI when an internet connection is detected.

5. **Spotify Aesthetic (Dark & Light Modes)**
   - Signature Spotify Green accents (`#1DB954` / `#1ED760`).
   - High-contrast Spotify Dark (`#121212` canvas, `#181818` cards).
   - Clean Spotify Light mode with soft shadows and sharp typography.
   - Bottom persistent "Now Playing" bar displaying active tool status and uptime.

---

## 🚀 Quick Start & Management

CyberPulse is installed in its own directory on the Desktop:
```bash
cd ~/Desktop/CyberPulse
```

### Management Commands
```bash
./start.sh      # Starts CyberPulse in background and opens dashboard
./stop.sh       # Stops CyberPulse
./status.sh     # Displays status, PID, memory, tool counts
./restart.sh    # Restarts service
```

### Accessing the Web Dashboard
Open your browser to:
```
http://127.0.0.1:8844
```
Or double-click the **CyberPulse Security Suite** icon on your Desktop or Kali Applications menu!

---

## ⚙️ Running Always (Systemd Service)

CyberPulse is configured as an automated systemd user service so it automatically starts on boot and stays running 24/7:
```bash
# Check service status
systemctl --user status cyberpulse.service

# Stop / Start / Restart service
systemctl --user stop cyberpulse.service
systemctl --user start cyberpulse.service
systemctl --user restart cyberpulse.service
```

---

## 📦 Sharing with Other Users

To share CyberPulse with classmates, colleagues, or transfer to another computer:
```bash
cd ~/Desktop/CyberPulse
./share_bundle.sh
```
This generates:
- `~/Desktop/CyberPulse_Distribution.zip`
- `~/Desktop/CyberPulse_Distribution.tar.gz`

See [SHARE.md](file:///home/mathewrean/Desktop/CyberPulse/SHARE.md) for recipient setup instructions.
