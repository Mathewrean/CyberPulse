"""
CyberPulse Incident & Scenario Intelligence Engine
Analyzes user scenarios, incidents, and security objectives.
Recommends optimal tools (flagging installed vs missing), produces executable playbooks,
and integrates with online AI/LLM when internet connectivity is active.
"""

import os
import re
import json
import socket
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional
from datetime import datetime

from .database import get_connection, save_scenario_query, get_setting

def check_internet_connection(timeout: float = 1.5) -> bool:
    """Fast check for external internet connectivity."""
    targets = [("1.1.1.1", 53), ("8.8.8.8", 53), ("dns.google", 443)]
    for host, port in targets:
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.close()
            return True
        except (socket.timeout, OSError):
            continue
    return False

# Rule-based incident patterns for offline analysis
INCIDENT_PATTERNS = [
    {
        "domain": "Active Directory & Windows Domain",
        "keywords": ["active directory", "kerberos", "kerberoast", "asrep", "dcsync", "ntlm", "smb", "pass the hash", "bloodhound", "domain controller", "mimikatz", "winrm", "ldap", "ntds.dit", "lateral movement", "lsa"],
        "primary_tools": ["bloodhound", "netexec", "responder", "evil-winrm", "hashcat", "john"],
        "mitre": ["T1003 - OS Credential Dumping", "T1558 - Steal or Forge Kerberos Tickets", "T1021.002 - SMB/Windows Admin Shares"],
        "playbook": {
            "stage_1_recon": "Map domain trust relationships and attack paths using BloodHound ingestor.",
            "stage_2_execution": "Harvest credentials or Kerberos tickets using NetExec (nxc) and Responder.",
            "stage_3_post_exploit": "Authenticate laterally using Evil-WinRM via Pass-The-Hash or cracked service account credentials.",
            "remediation": "Enforce AES Kerberos encryption, restrict Local Administrator Password Solution (LAPS), enable SMB signing, and disable LLMNR/NBT-NS."
        }
    },
    {
        "domain": "Web Application Security",
        "keywords": ["sql injection", "sqli", "xss", "cross site", "ssrf", "idor", "csrf", "burp", "web app", "api", "endpoint", "graphql", "rest", "fuzz", "directory traversal", "lfi", "rfi", "upload", "jwt", "auth bypass", "deserialization", "phpggc", "smuggling", "laravel"],
        "primary_tools": ["burpsuite", "sqlmap", "httpx", "nuclei", "ffuf", "feroxbuster", "phpggc", "laravel-crypto-killer", "gobuster", "nikto", "wpscan"],
        "mitre": ["T1190 - Exploit Public-Facing Application", "T1059.007 - JavaScript", "T1083 - File and Directory Discovery"],
        "playbook": {
            "stage_1_recon": "Probe active web servers with HTTPX, discover hidden routes with Feroxbuster/FFuF, and scan for known CVEs using Nuclei.",
            "stage_2_execution": "Intercept traffic with Burp Suite, audit SQL injection with SQLMap, or generate deserialization chains using PHPGGC.",
            "stage_3_post_exploit": "Test for remote code execution or file upload bypasses to secure command execution.",
            "remediation": "Implement parameterized queries (Prepared Statements), Content Security Policy (CSP), strict server-side validation, and WAF rules."
        }
    },
    {
        "domain": "Digital Forensics & Incident Response",
        "keywords": ["forensic", "memory dump", "ransomware", "encrypted files", "pcap", "wireshark", "packet", "beacon", "c2", "carve", "disk image", "volatility", "autopsy", "binwalk", "yara", "malware", "reverse engineering"],
        "primary_tools": ["wireshark", "tcpdump", "autopsy", "binwalk", "yara", "ghidra", "bulk_extractor"],
        "mitre": ["T1005 - Data from Local System", "T1071 - Application Layer Protocol", "T1027 - Obfuscated Files"],
        "playbook": {
            "stage_1_recon": "Preserve volatile memory and disk evidence using bitstream imaging (E01/dd). Inspect network pcaps with Wireshark.",
            "stage_2_execution": "Scan filesystem artifacts for webshells or malware IOCs using YARA signatures and carve firmware/blobs with Binwalk.",
            "stage_3_post_exploit": "Decompile suspicious payloads in Ghidra to extract hardcoded C2 configurations and encryption keys.",
            "remediation": "Isolate compromised endpoints from VLAN, revoke active Kerberos TGTs, and block external C2 IP addresses at boundary firewalls."
        }
    },
    {
        "domain": "Password Cracking & Credential Attacks",
        "keywords": ["password", "crack", "hash", "brute force", "wordlist", "rockyou", "zip", "pdf", "ntds", "sha256", "md5", "hydra", "john", "hashcat", "dictionary", "login"],
        "primary_tools": ["hashcat", "john", "hydra", "fcrackzip", "cewl"],
        "mitre": ["T1110 - Brute Force", "T1110.002 - Password Cracking"],
        "playbook": {
            "stage_1_recon": "Identify target hash algorithm using hashid or John format identification.",
            "stage_2_execution": "Execute GPU-accelerated dictionary attack with Hashcat (-m <type> -a 0) or John the Ripper with hybrid rules.",
            "stage_3_post_exploit": "For network login services (SSH/FTP/RDP), audit brute force resistance with THC Hydra.",
            "remediation": "Implement Multi-Factor Authentication (MFA), account lockout thresholds, and minimum 16-character passphrase policies."
        }
    },
    {
        "domain": "Wireless Network Attacks",
        "keywords": ["wifi", "wireless", "wpa", "wpa2", "wpa3", "handshake", "aircrack", "deauth", "beacon", "access point", "bssid", "essid", "pmkid", "airmon"],
        "primary_tools": ["aircrack-ng", "hashcat", "kismet", "reaver"],
        "mitre": ["T1040 - Network Sniffing", "T1110 - Brute Force"],
        "playbook": {
            "stage_1_recon": "Switch wireless adapter to monitor mode with airmon-ng and map target APs with airodump-ng.",
            "stage_2_execution": "Capture WPA 4-way handshake using targeted aireplay-ng deauthentication or PMKID clientless capture.",
            "stage_3_post_exploit": "Crack captured handshake offline using Hashcat mode 22000 or Aircrack-ng with custom wordlists.",
            "remediation": "Migrate to WPA3-Enterprise (802.1X/EAP-TLS) with certificate authentication; disable WPS and legacy WEP/WPA."
        }
    },
    {
        "domain": "Network Reconnaissance & Discovery",
        "keywords": ["port scan", "rustscan", "nmap", "recon", "subnet", "firewall", "fingerprint", "osint", "subdomain", "dns", "masscan", "whois", "discovery", "host", "perimeter", "httpx"],
        "primary_tools": ["rustscan", "nmap", "masscan", "httpx", "amass", "theharvester", "sherlock", "whatweb"],
        "mitre": ["T1595 - Active Scanning", "T1046 - Network Service Discovery", "T1596 - Search Open Technical Databases"],
        "playbook": {
            "stage_1_recon": "Perform ultra-fast port scanning with RustScan to detect all 65k listening ports in seconds, then map domains via theHarvester and Amass.",
            "stage_2_execution": "Pipe discovered open ports directly into Nmap (-sS -sV -sC) for service fingerprinting and probe HTTP ports with HTTPX.",
            "stage_3_post_exploit": "Audit exposed services for known CVE vulnerabilities using Nmap Scripting Engine (NSE) or Nuclei.",
            "remediation": "Close unnecessary public ports, place administrative interfaces behind VPNs with MFA, and configure egress filtering."
        }
    },
    {
        "domain": "Linux Privilege Escalation & Post-Exploitation",
        "keywords": ["privilege escalation", "privesc", "suid", "sudo", "root", "cron", "linpeas", "gtfobins", "kernel exploit", "capabilities", "linenum"],
        "primary_tools": ["linpeas", "netcat", "socat", "gdb", "strace"],
        "mitre": ["T1068 - Exploitation for Privilege Escalation", "T1548.003 - Sudo and Sudo Caching"],
        "playbook": {
            "stage_1_recon": "Execute LinPEAS to automate local host misconfiguration discovery.",
            "stage_2_execution": "Inspect sudo -l permissions, SUID binaries (find / -perm -4000 2>/dev/null), and writable cron jobs.",
            "stage_3_post_exploit": "Apply GTFOBins syntax on permitted binaries to spawn interactive root shell.",
            "remediation": "Audit /etc/sudoers for NOPASSWD entries, eliminate unnecessary SUID flags, and keep Linux kernel updated."
        }
    }
]

def analyze_scenario_offline(scenario_text: str) -> Dict[str, Any]:
    """Analyzes a scenario using the built-in threat intelligence engine."""
    text_lower = scenario_text.lower()
    
    # Score each incident pattern
    best_pattern = None
    max_score = 0
    
    for pattern in INCIDENT_PATTERNS:
        score = 0
        for kw in pattern["keywords"]:
            if re.search(r'\b' + re.escape(kw) + r'\b', text_lower):
                score += 2
            elif kw in text_lower:
                score += 1
        if score > max_score:
            max_score = score
            best_pattern = pattern
            
    # Default fallback pattern if vague
    if not best_pattern or max_score == 0:
        best_pattern = INCIDENT_PATTERNS[5] # Network Recon & Discovery
        detected_domain = "General Threat Analysis / Network Recon"
    else:
        detected_domain = best_pattern["domain"]

    # Match primary tools against system database
    conn = get_connection()
    cursor = conn.cursor()
    
    recommended_tools_info = []
    installed_ready = []
    missing_to_install = []
    
    for tname in best_pattern["primary_tools"]:
        cursor.execute("SELECT * FROM tools WHERE name = ? OR name LIKE ?", (tname, f"%{tname}%"))
        row = cursor.fetchone()
        if row:
            tdata = dict(row)
            tdata["syntax_examples"] = json.loads(tdata.get("syntax_examples") or "[]")
            tdata["learning_refs"] = json.loads(tdata.get("learning_refs") or "[]")
            
            tool_summary = {
                "name": tdata["name"],
                "display_name": tdata["display_name"],
                "category": tdata["category"],
                "installed": bool(tdata["installed"]),
                "binary_path": tdata.get("binary_path", ""),
                "version": tdata.get("version", ""),
                "install_command": tdata.get("install_command", f"sudo apt install {tdata['name']}"),
                "syntax_examples": tdata["syntax_examples"][:2],
                "learning_refs": tdata["learning_refs"][:2]
            }
            recommended_tools_info.append(tool_summary)
            if tool_summary["installed"]:
                installed_ready.append(tool_summary)
            else:
                missing_to_install.append(tool_summary)
                
    conn.close()

    result = {
        "status": "success",
        "engine": "Offline Threat Engine (Rule-based Expert)",
        "detected_domain": detected_domain,
        "mitre_mapping": best_pattern.get("mitre", []),
        "playbook": best_pattern.get("playbook", {}),
        "recommended_tools": recommended_tools_info,
        "installed_count": len(installed_ready),
        "missing_count": len(missing_to_install),
        "installed_tools": installed_ready,
        "missing_tools": missing_to_install,
        "summary": f"Detected incident domain: {detected_domain}. Recommended {len(recommended_tools_info)} specialized tools ({len(installed_ready)} installed and ready on this system)."
    }
    
    save_scenario_query(
        query=scenario_text,
        category=detected_domain,
        tools=[t["name"] for t in recommended_tools_info],
        playbook=result
    )
    
    return result

def query_online_ai(scenario_text: str, detected_domain: str, candidate_tools: List[str]) -> Optional[Dict[str, Any]]:
    """Attempts to query external LLM API if network and API key are configured."""
    gemini_key = get_setting("gemini_api_key") or os.environ.get("GEMINI_API_KEY", "")
    
    if not gemini_key:
        return None

    # Call Gemini REST API
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={gemini_key}"
        prompt = (
            f"You are a master cybersecurity incident responder and penetration tester. "
            f"A security professional presents this scenario: '{scenario_text}'. "
            f"The local system has these tools available: {', '.join(candidate_tools)}. "
            f"Provide an actionable response in JSON format with fields: "
            f"playbook (object with stage_1_recon, stage_2_execution, stage_3_post_exploit, remediation), "
            f"recommended_commands (array of strings), advice (string)."
        )
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {"response_mime_type": "application/json"}
        }
        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=10) as response:
            res_data = json.loads(response.read().decode("utf-8"))
            candidate = res_data["candidates"][0]["content"]["parts"][0]["text"]
            parsed = json.loads(candidate)
            return parsed
    except Exception:
        return None

def analyze_scenario(scenario_text: str, force_offline: bool = False) -> Dict[str, Any]:
    """Unified entry point for scenario analysis. Balances offline speed with online depth."""
    offline_result = analyze_scenario_offline(scenario_text)
    
    if force_offline:
        return offline_result
        
    is_online = check_internet_connection(timeout=1.0)
    offline_result["is_online"] = is_online
    
    # If online, attempt AI augmentation
    if is_online:
        tools_list = [t["name"] for t in offline_result.get("recommended_tools", [])]
        ai_data = query_online_ai(scenario_text, offline_result["detected_domain"], tools_list)
        if ai_data:
            offline_result["ai_enhanced"] = True
            offline_result["engine"] = "Hybrid: Online AI (Gemini) + System Knowledge Base"
            if "playbook" in ai_data:
                offline_result["playbook"].update(ai_data["playbook"])
            if "recommended_commands" in ai_data:
                offline_result["ai_commands"] = ai_data["recommended_commands"]
            if "advice" in ai_data:
                offline_result["ai_advice"] = ai_data["advice"]
    else:
        offline_result["ai_enhanced"] = False
        
    return offline_result
