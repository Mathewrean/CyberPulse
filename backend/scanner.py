"""
CyberPulse Multi-Source Tool Scanner & Categorizer
Deep-scans:
1. System binaries & APT packages (dpkg)
2. Kali Linux desktop applications
3. Cargo (Rust) binaries (~/.cargo/bin)
4. Go (Golang) binaries (~/go/bin)
5. GitHub cloned repositories (~/ctf, ~/tools, ~/git, /opt, ~/cloud, ~/Desktop, etc.)
6. Snap packages (/snap/bin, snap list)
7. Flatpak applications (flatpak list)
8. Pipx & Python user utilities (~/.local/share/pipx, ~/.local/bin)
9. AppImages (*.AppImage) and /opt custom builds
"""

import os
import glob
import shutil
import subprocess
import json
import re
from datetime import datetime
from typing import Dict, Any, List, Set

from .knowledge_base import CURATED_TOOLS
from .database import upsert_tool, set_setting

# Augment process PATH to ensure all user runtime locations are searchable
EXTRA_PATHS = [
    os.path.expanduser("~/.cargo/bin"),
    os.path.expanduser("~/go/bin"),
    os.path.expanduser("~/.local/bin"),
    "/snap/bin",
    "/var/lib/flatpak/exports/bin",
    os.path.expanduser("~/.local/share/flatpak/exports/bin"),
    "/usr/local/bin",
    "/usr/bin",
    "/usr/sbin",
    "/opt"
]
current_path = os.environ.get("PATH", "")
for ep in EXTRA_PATHS:
    if ep not in current_path:
        current_path = f"{ep}:{current_path}"
os.environ["PATH"] = current_path

CATEGORY_MAP = {
    "kali-reconnaissance": "Information Gathering",
    "kali-identify": "Information Gathering",
    "kali-host-information": "Information Gathering",
    "kali-network-information": "Information Gathering",
    "kali-network-information-dns": "Information Gathering",
    "kali-remote-system-discovery": "Information Gathering",
    "kali-network-service-discovery": "Information Gathering",
    "kali-discovery": "Information Gathering",
    "kali-vulnerability-scanning": "Vulnerability Analysis",
    "kali-web-scanning": "Web Applications",
    "kali-web-vulnerability-scanning": "Web Applications",
    "kali-databases": "Database Assessment",
    "kali-password-cracking": "Password Attacks",
    "kali-brute-force": "Password Attacks",
    "kali-credential-access": "Password Attacks",
    "kali-password-profiling-wordlists": "Password Attacks",
    "kali-hash-identification": "Password Attacks",
    "kali-wifi": "Wireless Attacks",
    "kali-wifi-credential-access": "Wireless Attacks",
    "kali-bluetooth": "Wireless Attacks",
    "kali-radio-frequency": "Wireless Attacks",
    "kali-nfc": "Wireless Attacks",
    "kali-active-directory": "Active Directory & Post-Exploitation",
    "kali-lateral-movement": "Active Directory & Post-Exploitation",
    "kali-kerberoasting": "Active Directory & Post-Exploitation",
    "kali-pass-the-hash": "Active Directory & Post-Exploitation",
    "kali-os-credential-dumping": "Active Directory & Post-Exploitation",
    "kali-unsecured-credentials": "Active Directory & Post-Exploitation",
    "kali-privilege-escalation": "Privilege Escalation",
    "kali-execution": "Exploitation Tools",
    "kali-initial-access": "Exploitation Tools",
    "kali-command-and-control": "Exploitation Tools",
    "kali-network-sniffing": "Sniffing & Spoofing",
    "kali-application-layer-protocol": "Sniffing & Spoofing",
    "kali-non-application-layer-protocol": "Sniffing & Spoofing",
    "kali-protocol-tunneling": "Sniffing & Spoofing",
    "kali-defense-evasion": "Defense Evasion & Evasion",
    "kali-digital-forensics": "Forensics",
    "kali-forensic-carving-tools": "Forensics",
    "kali-forensic-imaging-tools": "Forensics",
    "kali-sleuth-kit-suite": "Forensics",
    "kali-pdf-forensics-tools": "Forensics",
    "kali-forensics": "Forensics",
    "kali-recover": "Forensics",
    "kali-reporting-tools": "Reporting & Documentation",
    "kali-resource-development": "Reverse Engineering",
    "kali-collection": "Collection & Exfiltration",
    "kali-exfiltration": "Collection & Exfiltration"
}

def map_category(cats_str: str) -> str:
    if not cats_str:
        return "General Security"
    for part in cats_str.split(";"):
        part = part.strip()
        if part in CATEGORY_MAP:
            return CATEGORY_MAP[part]
    return "General Security"

def detect_source_from_path(binary_path: str) -> str:
    if not binary_path:
        return "APT (System)"
    p = binary_path.lower()
    if ".cargo" in p:
        return "Cargo (Rust)"
    if "/go/bin" in p or "go/bin" in p:
        return "Go Binary"
    if "snap" in p:
        return "Snap"
    if "flatpak" in p:
        return "Flatpak"
    if "pipx" in p or ".local/bin" in p:
        return "Pipx / Python"
    if "/opt" in p:
        return "Custom /opt"
    return "APT (System)"

def get_installed_dpkg_cache() -> Dict[str, str]:
    """Retrieves all installed debian packages in a single fast call."""
    pkgs = {}
    try:
        res = subprocess.run(
            ["dpkg-query", "-W", "-f=${Package}|${Version}|${Status}\n"],
            capture_output=True,
            text=True,
            timeout=5
        )
        for line in res.stdout.splitlines():
            parts = line.split("|")
            if len(parts) >= 3 and "installed" in parts[2]:
                pkgs[parts[0]] = parts[1]
    except Exception:
        pass
    return pkgs

def scan_all_tools() -> Dict[str, Any]:
    dpkg_cache = get_installed_dpkg_cache()
    discovered_tools = {}

    # ---------------------------------------------------------
    # 1. Curated Knowledge Base Tools (Nmap, Burp, RustScan, etc.)
    # ---------------------------------------------------------
    for item in CURATED_TOOLS:
        name = item["name"]
        tool_data = dict(item)

        binary_path = ""
        for b in item.get("binary_names", [name]):
            # Try expanded PATH
            found = shutil.which(b)
            if found:
                binary_path = found
                break
            # Check explicit known locations
            for p in [
                os.path.expanduser(f"~/.cargo/bin/{b}"),
                os.path.expanduser(f"~/go/bin/{b}"),
                os.path.expanduser(f"~/.local/bin/{b}"),
                f"/snap/bin/{b}",
                f"/usr/bin/{b}",
                f"/usr/sbin/{b}",
                f"/usr/local/bin/{b}"
            ]:
                if os.path.exists(p) and os.access(p, os.X_OK):
                    binary_path = p
                    break
            if binary_path:
                break

        pkg_name = item.get("package_name", "")
        pkg_version = dpkg_cache.get(pkg_name, "")

        is_installed = bool(binary_path) or bool(pkg_version)
        tool_data["installed"] = is_installed
        tool_data["binary_path"] = binary_path or ""
        
        # Auto-detect or refine installation source
        if binary_path:
            tool_data["install_source"] = detect_source_from_path(binary_path)
        else:
            tool_data["install_source"] = item.get("install_source", "APT (System)")

        tool_data["version"] = pkg_version if pkg_version else ("Installed" if is_installed else "Not Installed")
        discovered_tools[name] = tool_data

    # ---------------------------------------------------------
    # 2. Cargo (Rust) Binaries (~/.cargo/bin)
    # ---------------------------------------------------------
    cargo_bin_dir = os.path.expanduser("~/.cargo/bin")
    if os.path.exists(cargo_bin_dir):
        for f in os.listdir(cargo_bin_dir):
            bin_path = os.path.join(cargo_bin_dir, f)
            if os.path.isfile(bin_path) and os.access(bin_path, os.X_OK):
                clean_name = f.lower()
                # Skip rustup toolchain internal wrappers if not primary
                if clean_name in ["rustc", "rustdoc", "rustfmt", "rustup", "cargo", "cargo-clippy", "cargo-fmt", "cargo-miri", "clippy-driver", "rls", "rust-analyzer", "rust-gdb", "rust-gdbgui", "rust-lldb"]:
                    continue
                if clean_name in discovered_tools:
                    discovered_tools[clean_name]["installed"] = True
                    discovered_tools[clean_name]["binary_path"] = bin_path
                    discovered_tools[clean_name]["install_source"] = "Cargo (Rust)"
                    continue

                cat = "Information Gathering" if clean_name in ["rustscan", "sniffglue"] else ("Web Applications" if clean_name in ["feroxbuster", "ripgen"] else "General Security")
                discovered_tools[clean_name] = {
                    "name": clean_name,
                    "display_name": f"{clean_name} (Rust/Cargo)",
                    "category": cat,
                    "subcategory": "Rust Security Tool",
                    "description": f"High-performance utility compiled with Rust and installed via Cargo into ~/.cargo/bin.",
                    "installed": True,
                    "binary_path": bin_path,
                    "package_name": clean_name,
                    "version": "Cargo Build",
                    "install_command": f"cargo install {clean_name}",
                    "install_source": "Cargo (Rust)",
                    "mitre_tactics": [cat],
                    "mitre_techniques": [],
                    "syntax_examples": [{"cmd": f"{clean_name} --help", "desc": "Display usage flags."}],
                    "scenarios": [{"title": f"Engagement use: {clean_name}", "incident_type": cat, "description": f"Execute Rust-based {clean_name}.", "steps": [f"{clean_name} --help"]}],
                    "learning_refs": [{"title": "Crates.io Package", "url": f"https://crates.io/crates/{clean_name}", "type": "doc"}]
                }

    # ---------------------------------------------------------
    # 3. Go (Golang) Binaries (~/go/bin)
    # ---------------------------------------------------------
    go_bin_dir = os.path.expanduser("~/go/bin")
    if os.path.exists(go_bin_dir):
        for f in os.listdir(go_bin_dir):
            bin_path = os.path.join(go_bin_dir, f)
            if os.path.isfile(bin_path) and os.access(bin_path, os.X_OK):
                clean_name = f.lower()
                if clean_name in discovered_tools:
                    discovered_tools[clean_name]["installed"] = True
                    discovered_tools[clean_name]["binary_path"] = bin_path
                    discovered_tools[clean_name]["install_source"] = "Go Binary"
                    continue

                cat = "Information Gathering" if any(k in clean_name for k in ["enum", "sub", "scan", "recon"]) else "Web Applications"
                discovered_tools[clean_name] = {
                    "name": clean_name,
                    "display_name": f"{clean_name} (Go)",
                    "category": cat,
                    "subcategory": "Go Binary",
                    "description": f"Compiled Golang security tool installed in ~/go/bin.",
                    "installed": True,
                    "binary_path": bin_path,
                    "package_name": clean_name,
                    "version": "Go Binary",
                    "install_command": f"go install github.com/.../{clean_name}@latest",
                    "install_source": "Go Binary",
                    "mitre_tactics": [cat],
                    "mitre_techniques": [],
                    "syntax_examples": [{"cmd": f"{clean_name} -h", "desc": "Show Go CLI flags."}],
                    "scenarios": [{"title": f"Operation with {clean_name}", "incident_type": cat, "description": f"Run Go binary {clean_name}.", "steps": [f"{clean_name} -h"]}],
                    "learning_refs": [{"title": "Go Tool Guide", "url": f"https://pkg.go.dev/", "type": "doc"}]
                }

    # ---------------------------------------------------------
    # 4. Snap Packages (/snap/bin, snap list)
    # ---------------------------------------------------------
    try:
        snap_res = subprocess.run(["snap", "list"], capture_output=True, text=True, timeout=3)
        system_snaps = {"bare", "core22", "core24", "snapd", "gtk-common-themes", "gnome-46-2404", "kf6-core24", "mesa-2404"}
        for line in snap_res.stdout.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 2:
                sname = parts[0].lower()
                sver = parts[1]
                if sname in system_snaps:
                    continue
                bin_path = f"/snap/bin/{sname}"
                if not os.path.exists(bin_path):
                    bin_path = shutil.which(sname) or ""

                if sname in discovered_tools:
                    discovered_tools[sname]["installed"] = True
                    discovered_tools[sname]["binary_path"] = bin_path
                    discovered_tools[sname]["install_source"] = "Snap"
                    discovered_tools[sname]["version"] = sver
                    continue

                cat = "Sniffing & Spoofing" if sname in ["ngrok", "wireshark"] else "General Security"
                discovered_tools[sname] = {
                    "name": sname,
                    "display_name": f"{sname} (Snap)",
                    "category": cat,
                    "subcategory": "Snap Application",
                    "description": f"Snap containerized application ({sname} v{sver}).",
                    "installed": True,
                    "binary_path": bin_path,
                    "package_name": sname,
                    "version": sver,
                    "install_command": f"sudo snap install {sname}",
                    "install_source": "Snap",
                    "mitre_tactics": [cat],
                    "mitre_techniques": [],
                    "syntax_examples": [{"cmd": f"{sname} --help", "desc": "Display help."}],
                    "scenarios": [{"title": f"Run Snap app: {sname}", "incident_type": cat, "description": f"Execute {sname} installed via Snap.", "steps": [f"{sname} --help"]}],
                    "learning_refs": [{"title": "Snapcraft Store", "url": f"https://snapcraft.io/{sname}", "type": "doc"}]
                }
    except Exception:
        pass

    # ---------------------------------------------------------
    # 5. Flatpak Applications (flatpak list)
    # ---------------------------------------------------------
    try:
        fp_res = subprocess.run(["flatpak", "list", "--app", "--columns=application,version"], capture_output=True, text=True, timeout=3)
        for line in fp_res.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 1:
                app_id = parts[0].strip()
                sver = parts[1] if len(parts) > 1 else "Flatpak"
                short_name = app_id.split(".")[-1].lower()
                
                if short_name in discovered_tools:
                    discovered_tools[short_name]["installed"] = True
                    discovered_tools[short_name]["install_source"] = "Flatpak"
                    discovered_tools[short_name]["version"] = sver
                    continue

                discovered_tools[short_name] = {
                    "name": short_name,
                    "display_name": f"{short_name} (Flatpak)",
                    "category": "General Security",
                    "subcategory": "Flatpak Application",
                    "description": f"Sandboxed Flatpak application: {app_id}.",
                    "installed": True,
                    "binary_path": f"flatpak run {app_id}",
                    "package_name": app_id,
                    "version": sver,
                    "install_command": f"flatpak install flathub {app_id}",
                    "install_source": "Flatpak",
                    "mitre_tactics": ["General Security"],
                    "mitre_techniques": [],
                    "syntax_examples": [{"cmd": f"flatpak run {app_id}", "desc": "Launch Flatpak application."}],
                    "scenarios": [{"title": f"Launch Flatpak {short_name}", "incident_type": "Application", "description": "Execute sandboxed flatpak.", "steps": [f"flatpak run {app_id}"]}],
                    "learning_refs": [{"title": "Flathub Page", "url": f"https://flathub.org/apps/{app_id}", "type": "doc"}]
                }
    except Exception:
        pass

    # ---------------------------------------------------------
    # 6. Pipx & Python Virtual Environment Tools (~/.local/share/pipx/venvs)
    # ---------------------------------------------------------
    pipx_dir = os.path.expanduser("~/.local/share/pipx/venvs")
    if os.path.exists(pipx_dir):
        for v in os.listdir(pipx_dir):
            clean_name = v.lower()
            bin_path = os.path.join(pipx_dir, v, "bin", v)
            if not os.path.exists(bin_path):
                bin_path = shutil.which(clean_name) or ""

            if clean_name in discovered_tools:
                discovered_tools[clean_name]["installed"] = True
                discovered_tools[clean_name]["binary_path"] = bin_path
                discovered_tools[clean_name]["install_source"] = "Pipx / Python"
                continue

            discovered_tools[clean_name] = {
                "name": clean_name,
                "display_name": f"{clean_name} (Pipx)",
                "category": "Web Applications" if clean_name in ["httpie", "requests"] else "General Security",
                "subcategory": "Python CLI Utility",
                "description": f"Python CLI application installed in isolated virtual environment via Pipx.",
                "installed": True,
                "binary_path": bin_path,
                "package_name": clean_name,
                "version": "Pipx Virtualenv",
                "install_command": f"pipx install {clean_name}",
                "install_source": "Pipx / Python",
                "mitre_tactics": ["General Security"],
                "mitre_techniques": [],
                "syntax_examples": [{"cmd": f"{clean_name} --help", "desc": "Show tool usage flags."}],
                "scenarios": [{"title": f"Execute {clean_name}", "incident_type": "Utility", "description": "Run Python utility.", "steps": [f"{clean_name} --help"]}],
                "learning_refs": [{"title": "PyPI Package", "url": f"https://pypi.org/project/{clean_name}/", "type": "doc"}]
            }

    # ---------------------------------------------------------
    # 7. GitHub / Git Cloned Repositories Scanner
    # ---------------------------------------------------------
    search_dirs = [
        os.path.expanduser("~/ctf"),
        os.path.expanduser("~/tools"),
        os.path.expanduser("~/git"),
        os.path.expanduser("~/github"),
        os.path.expanduser("~/cloud"),
        os.path.expanduser("~/Desktop"),
        os.path.expanduser("~/Documents"),
        os.path.expanduser("~"),
        "/opt"
    ]
    
    seen_git_paths: Set[str] = set()
    for sdir in search_dirs:
        if not os.path.exists(sdir):
            continue
        try:
            for entry in os.listdir(sdir):
                if entry.startswith(".") and entry not in [".git"]:
                    continue
                dir_path = os.path.join(sdir, entry)
                if not os.path.isdir(dir_path):
                    continue
                
                target_repos = []
                if os.path.exists(os.path.join(dir_path, ".git")):
                    target_repos.append(dir_path)
                else:
                    try:
                        for sub in os.listdir(dir_path):
                            sp = os.path.join(dir_path, sub)
                            if os.path.isdir(sp) and os.path.exists(os.path.join(sp, ".git")):
                                target_repos.append(sp)
                    except Exception:
                        pass

                for repo_dir in target_repos:
                    if repo_dir in seen_git_paths or "CyberPulse" in repo_dir or ".cache" in repo_dir:
                        continue
                    seen_git_paths.add(repo_dir)

                    rname = os.path.basename(repo_dir).lower()
                    cfg_file = os.path.join(repo_dir, ".git", "config")
                    origin_url = ""
                    if os.path.exists(cfg_file):
                        with open(cfg_file, "r", errors="ignore") as fp:
                            for l in fp:
                                if "url =" in l:
                                    origin_url = l.split("=", 1)[1].strip()
                                    break

                    readme_desc = ""
                    for rm_candidate in ["README.md", "readme.md", "README", "Readme.md"]:
                        rm_p = os.path.join(repo_dir, rm_candidate)
                        if os.path.exists(rm_p):
                            try:
                                with open(rm_p, "r", errors="ignore") as fp:
                                    for line in fp:
                                        clean_l = line.strip()
                                        if clean_l and not clean_l.startswith(("#", "!", "<", "[")):
                                            readme_desc = clean_l[:180]
                                            break
                            except Exception:
                                pass
                            if readme_desc:
                                break

                    exec_cmd = f"cd {repo_dir}"
                    entry_file = ""
                    for f in os.listdir(repo_dir):
                        fp = os.path.join(repo_dir, f)
                        if os.path.isfile(fp):
                            if f == rname or f == f"{rname}.py" or f == f"{rname}.sh":
                                entry_file = fp
                                break
                            elif f in ["main.py", "app.py", "run.py", "cli.py"] and not entry_file:
                                entry_file = fp

                    if entry_file:
                        exec_cmd = entry_file if os.access(entry_file, os.X_OK) else f"python3 {entry_file}"

                    cat = "Exploitation Tools" if any(k in rname for k in ["exploit", "cve", "pwn", "killer", "ggc", "gadget"]) else (
                        "Wireless Attacks" if "wifi" in rname or "hotspot" in rname else (
                            "Web Applications" if any(k in rname for k in ["web", "api", "fuzz", "smuggl"]) else "General Security"
                        )
                    )

                    if rname in discovered_tools:
                        discovered_tools[rname]["installed"] = True
                        discovered_tools[rname]["binary_path"] = entry_file or repo_dir
                        discovered_tools[rname]["install_source"] = "GitHub Clone"
                        if origin_url:
                            discovered_tools[rname]["learning_refs"].insert(0, {"title": "GitHub Repository", "url": origin_url, "type": "doc"})
                        continue

                    display_title = rname.replace("-", " ").title()
                    discovered_tools[rname] = {
                        "name": rname,
                        "display_name": f"{display_title} (GitHub)",
                        "category": cat,
                        "subcategory": "GitHub Cloned Repository",
                        "description": readme_desc or f"Security tool cloned from Git repository: {origin_url or repo_dir}.",
                        "installed": True,
                        "binary_path": entry_file or repo_dir,
                        "package_name": rname,
                        "version": "Git Master",
                        "install_command": f"git clone {origin_url or repo_dir}",
                        "install_source": "GitHub Clone",
                        "mitre_tactics": [cat],
                        "mitre_techniques": [],
                        "syntax_examples": [{"cmd": exec_cmd, "desc": "Execute entry point from repository."}],
                        "scenarios": [{"title": f"Engagement operation: {display_title}", "incident_type": cat, "description": f"Execute custom Git tool {rname}.", "steps": [exec_cmd]}],
                        "learning_refs": [{"title": "GitHub Repository", "url": origin_url or f"file://{repo_dir}", "type": "doc"}]
                    }
        except Exception:
            continue

    # ---------------------------------------------------------
    # 8. Kali Desktop Applications (/usr/share/applications/kali-*.desktop)
    # ---------------------------------------------------------
    kali_desktop_files = glob.glob("/usr/share/applications/kali-*.desktop")
    for f in kali_desktop_files:
        try:
            entry = {}
            with open(f, "r", errors="ignore") as fp:
                for line in fp:
                    if "=" in line:
                        k, v = line.strip().split("=", 1)
                        entry[k] = v

            raw_name = entry.get("Name", "").strip()
            if not raw_name or "installer" in raw_name.lower() or "bug" in raw_name.lower():
                continue

            clean_name = raw_name.lower().replace(" ", "-")
            if clean_name in discovered_tools:
                continue

            pkg_name = entry.get("X-Kali-Package", clean_name)
            comment = entry.get("Comment", f"{raw_name} security utility")
            categories_raw = entry.get("Categories", "")
            category = map_category(categories_raw)

            binary_path = shutil.which(clean_name)
            if not binary_path and pkg_name:
                binary_path = shutil.which(pkg_name)

            pkg_version = dpkg_cache.get(pkg_name, "")
            is_installed = bool(binary_path) or bool(pkg_version)

            learning_refs = [
                {"title": f"Kali Tools: {pkg_name}", "url": f"https://www.kali.org/tools/{pkg_name}/", "type": "doc"}
            ]

            syntax_examples = [
                {"cmd": f"{clean_name} --help", "desc": "Display command-line help and usage flags."},
                {"cmd": f"man {clean_name}", "desc": "Open comprehensive manual page."}
            ]

            scenarios = [
                {
                    "title": f"Engagement Usage: {raw_name}",
                    "incident_type": category,
                    "description": f"Applied during security engagements requiring {category.lower()} techniques.",
                    "steps": [
                        f"Review usage options: {clean_name} --help",
                        f"Execute against target with proper scope authorization: {clean_name} <target>"
                    ]
                }
            ]

            discovered_tools[clean_name] = {
                "name": clean_name,
                "display_name": raw_name,
                "category": category,
                "subcategory": categories_raw.split(";")[0] if categories_raw else "Kali Tool",
                "description": comment,
                "installed": is_installed,
                "binary_path": binary_path or "",
                "package_name": pkg_name,
                "version": pkg_version if pkg_version else ("Installed" if is_installed else "Not Installed"),
                "install_command": f"sudo apt install {pkg_name}",
                "install_source": "APT (System)",
                "mitre_tactics": [category],
                "mitre_techniques": [],
                "syntax_examples": syntax_examples,
                "scenarios": scenarios,
                "learning_refs": learning_refs
            }
        except Exception:
            continue

    # ---------------------------------------------------------
    # 9. Custom /opt and AppImage Installations
    # ---------------------------------------------------------
    custom_opt = [
        {"name": "burpsuite_pro", "display_name": "Burp Suite Professional (/opt)", "path": "/opt/burpsuite_pro", "cat": "Web Applications", "src": "Custom /opt"},
        {"name": "penligent", "display_name": "Penligent AI Pen-testing (/opt)", "path": "/opt/PenligentV3", "cat": "Exploitation Tools", "src": "Custom /opt"},
        {"name": "packettracer", "display_name": "Cisco Packet Tracer", "path": "/opt/pt", "cat": "Reporting & Documentation", "src": "AppImage"}
    ]
    for c in custom_opt:
        if os.path.exists(c["path"]):
            cname = c["name"]
            discovered_tools[cname] = {
                "name": cname,
                "display_name": c["display_name"],
                "category": c["cat"],
                "subcategory": "Custom / Opt Installation",
                "description": f"Custom cybersecurity suite installed in {c['path']}.",
                "installed": True,
                "binary_path": c["path"],
                "package_name": cname,
                "version": "Custom Build",
                "install_command": f"cd {c['path']}",
                "install_source": c["src"],
                "mitre_tactics": [c["cat"]],
                "mitre_techniques": [],
                "syntax_examples": [{"cmd": f"cd {c['path']}", "desc": "Access tool installation directory."}],
                "scenarios": [{"title": f"Operation with {c['display_name']}", "incident_type": c["cat"], "description": "Run custom installed package.", "steps": [f"Launch from {c['path']}"]}],
                "learning_refs": [{"title": "Local Directory", "url": f"file://{c['path']}", "type": "doc"}]
            }

    # ---------------------------------------------------------
    # 10. Upsert all into database
    # ---------------------------------------------------------
    installed_count = 0
    sources_summary = {}
    for name, tool_data in discovered_tools.items():
        if tool_data.get("installed"):
            installed_count += 1
            src = tool_data.get("install_source", "APT (System)")
            sources_summary[src] = sources_summary.get(src, 0) + 1
        upsert_tool(tool_data)

    set_setting("last_full_scan", datetime.now().isoformat())

    return {
        "total_scanned": len(discovered_tools),
        "total_installed": installed_count,
        "total_missing": len(discovered_tools) - installed_count,
        "sources_summary": sources_summary
    }
