# CyberPulse Security Suite (Spotify Edition) v2.0.0

> **A Comprehensive Cybersecurity Tool Checklist, Real-Time Process & Usage Monitor, and Incident & Scenario Advisor**  
> Custom-engineered for Kali Linux and Debian systems with authentic Spotify Dark and Light design themes.

**Status:** offline-first, local-only (127.0.0.1). Online AI is **opt-in and off by default**.

---

## 🌟 Key Features

1. **System-Wide Deep Tool Detection & Checklist**
   - Scans system binary `$PATH`, Kali desktop applications, dpkg database, and custom security installations.
   - Categorizes tools across 15 standard domains.
   - **Tool count**: run `python3 app.py --scan` to print the exact number of discovered/installed tools backing the claim.

2. **Rich Tool Details & Educational Knowledge Base**
   - **Usage Description**: Clear operational overview of what each tool does.
   - **Cheatsheet & Syntax**: Ready-to-copy commands with one-click clipboard copying.
   - **Real-World Scenarios**: Concrete incident response or penetration testing use cases.
   - **MITRE ATT&CK Mappings**: Tactics and techniques (e.g. `T1046`, `T1003`, `T1190`).
   - **Learning References**: Direct links to official documentation, Kali tools pages, TryHackMe/HackTheBox labs, and manuals.
   - **Mastery Tracker**: Mark tools as *Not Started*, *Learning*, *Practicing*, or *Mastered*.

3. **Background Process & Usage Time Monitor ("Always Running")**
   - Continuously monitors active running processes using lightweight background polling.
   - **Accuracy note**: polling samples the process table every few seconds, so very
     short-lived commands (a quick `nmap` or `ffuf` run) can finish between samples
     and be missed. For complete capture, enable the optional shell hook (bash/zsh/fish)
     or wrapper shims (see Configuration).
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
     - **Tool Readiness**: Highlights which recommended tools are **Installed & Ready** vs **Missing / Available to Install** (with exact `sudo apt install` commands shown for you to copy — commands are **never run automatically**).
     - **Phased Playbook**: Stage 1 (Triage & Recon), Stage 2 (Execution & Investigation), Stage 3 (Post-Analysis & Containment), and Remediation & Hardening.
     - **Executable Commands**: Copy-paste terminal snippets with placeholders (`<TARGET_IP>`, `<PCAP>`, etc.).
    - **Dual Engine**: Works 100% offline via embedded threat engine. Online AI enhancement is **opt-in and off by default**; when enabled, scenario text is redacted (IPs, hashes, emails, usernames, MACs) before it leaves the machine, and a preview of exactly what will be sent is shown. No text is transmitted unless you explicitly turn AI on.

5. **Spotify Aesthetic (Dark & Light Modes)**
   - Signature Spotify Green accents (`#1DB954` / `#1ED760`).
   - High-contrast Spotify Dark (`#121212` canvas, `#181818` cards).
   - Clean Spotify Light mode with soft shadows and sharp typography.
   - Bottom persistent "Now Playing" bar displaying active tool status and uptime.

---

## 🔒 Privacy & Threat Model

**What is stored (locally, in `data/cyberpulse.db`, never leaves the machine):**
- Detected security tools, install paths, versions, and your checklist status/notes.
- Usage sessions: tool name, PID, command line, start/end time, duration, source collector.
- Incident/scenario advisor history: the scenario text you paste, detected domain, and recommended tools.
- App settings: theme and (optionally) an online AI API key — stored plaintext in SQLite; do not enter keys you cannot protect.

**What leaves the machine:**
- Nothing by default. Online AI is **off by default**.
- Only if you explicitly enable AI mode AND have internet AND configure an API key: the (redacted) scenario text is sent to the provider (Gemini). IPs, CIDR ranges, MAC addresses, hashes, emails and obvious usernames are masked first, and a preview of exactly what will be sent is shown before any request.

**What it needs:**
- Binds to `127.0.0.1` only (not exposed to the network). No remote access by default.
- Optional `sudo` only for kernel-level collection (auditd/eBPF) — gracefully skipped if unavailable.
- Optional shell-hook/wrappers require editing your shell rc files and `PATH`.

**Data retention:** usage sessions and scenario history are kept forever unless you set retention days (via `/api/retention`) or use the one-click wipe (`/api/data/wipe`).

**Trust boundary:** treat CyberPulse as a local single-user tool. It has no authentication; do not expose it beyond `127.0.0.1`.

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

---

## ⚙️ Configuration

CyberPulse is configured via `config.yaml` (shipped defaults). Create `config.local.yaml`
for machine-specific overrides — it is **not** committed and takes precedence.

Key settings:
- `host` / `port`: bind address (default `127.0.0.1:8844`, local-only).
- `custom_paths`: machine-specific install dirs (e.g. `/opt/PenligentV3`, `/opt/pt`).
- `ai.enabled`: online AI mode — **off by default**, opt-in only.
- `ai.redact_before_send`: redact IPs/hashes/emails/usernames/MACs before any text leaves the machine (default true).
- `monitor.interval_sec`: psutil poll interval (default 3s); adaptive when a tool is running.
- `retention.usage_sessions_days` / `scenario_history_days`: days to keep data (0 = forever).

Example `config.local.yaml`:
```yaml
host: "127.0.0.1"
port: 8844
custom_paths:
  - "/opt/PenligentV3"
  - "/opt/pt"
ai:
  enabled: false
  redact_before_send: true
monitor:
  interval_sec: 3
retention:
  usage_sessions_days: 90
```

---

## 🖼️ Screenshots

Screenshots of the Spotify-themed dashboard, tool checklist, live monitor, incident advisor,
and manual tabs belong here. Capture them from `http://127.0.0.1:8844` after first run and
place them in `docs/screenshots/`, then reference them:

- `docs/screenshots/dashboard.png` — Home dashboard with mastery ring and today's activity.
- `docs/screenshots/checklist.png` — Tool checklist with categories and filters.
- `docs/screenshots/manual.png` — Tool Manual tab with examples and "Explain this command".
- `docs/screenshots/advisor.png` — Incident Advisor playbook with tool readiness.

---

## 📊 Collector Comparison

| Collector | Short-lived commands | Privilege | Opt-in | Notes |
|-----------|---------------------|-----------|--------|-------|
| psutil polling (baseline) | ❌ missed between samples | No | Yes (default) | Adaptive interval: fast while a tool runs, slower when idle |
| Shell hook (bash/zsh/fish) | ✅ captured via preexec | No | Yes (rc snippet) | Logs cmd, args, cwd, exit code, duration |
| Wrapper shims (`~/.cyberpulse/bin`) | ✅ captured at exec | No | Yes (PATH shim) | Wraps chosen tools, logs to `data/wrapper.log` |
| auditd / eBPF execsnoop | ✅ kernel exec events | Yes (sudo) | Yes | Gracefully skipped if unavailable |
| Desktop launcher (.desktop) | ℹ️ inventory only | No | Yes | Lists Kali menu launchers |
| Manual lab session | ✅ user-declared | No | Yes | Start/Stop session with target, notes, tools |

Events are de-duplicated across methods by `(tool, PID, start timestamp)`.

---

## ❓ FAQ

**Q: Is online AI on by default?**
A: No. `ai.enabled` is `false` by default. You must explicitly opt in, and text is redacted
before it leaves the machine with a preview shown first.

**Q: Does polling miss fast commands?**
A: Yes. A quick `nmap`/`ffuf` can finish between 3s samples. Enable the shell hook or
wrapper shims to catch short-lived commands.

**Q: Where is data stored?**
A: `data/cyberpulse.db` (SQLite) on your machine only. Nothing is sent remotely unless you
enable online AI.

**Q: Can I wipe my data?**
A: Yes — `POST /api/data/wipe` is a one-click wipe of usage and scenario data (keeps the
tool catalogue). Retention can auto-delete old rows via `/api/retention`.

**Q: How do I add custom tool paths like /opt/PenligentV3?**
A: Add them to `custom_paths` in `config.local.yaml` — no code changes needed.

**Q: Does it run as root?**
A: No. It binds to `127.0.0.1` and runs as your user. Kernel-level collection (auditd/eBPF)
is optional and skipped if unavailable.

