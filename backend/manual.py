"""
CyberPulse Manual Engine - locally generated, cached tool manuals.

Sources (priority order):
  1. tldr pages (offline, if the `tldr` client is installed)
  2. `man <tool>`
  3. `<tool> --help`
  4. /usr/share/doc snippets
  5. curated JSON in data/knowledge/

Each manual is parsed into a fixed structure (never long verbatim manual text;
summarise and link to the source) and cached under data/manuals/.

Every worked example carries placeholders (<TARGET_IP>, <WORDLIST>, ...) and
the banner: "Authorised targets and your own lab only."
"""

import glob as _glob
import json
import os
import re
import shutil
import subprocess
from datetime import datetime
from typing import Any

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
KNOWLEDGE_DIR = os.path.join(DATA_DIR, "knowledge")
CACHE_DIR = os.path.join(DATA_DIR, "manuals")

BANNER = "Authorised targets and your own lab only."

# Example placeholder tokens that should appear in sample commands.
PLACEHOLDERS = ["<TARGET_IP>", "<TARGET>", "<WORDLIST>", "<PCAP>", "<INTERFACE>",
                "<HASH>", "<USER>", "<PORT>", "<DOMAIN>", "<URL>"]


def _ensure_dirs():
    os.makedirs(KNOWLEDGE_DIR, exist_ok=True)
    os.makedirs(CACHE_DIR, exist_ok=True)


def _cache_path(tool: str) -> str:
    return os.path.join(CACHE_DIR, f"{tool}.json")


def _load_cache(tool: str) -> dict[str, Any] | None:
    p = _cache_path(tool)
    if not os.path.exists(p):
        return None
    try:
        with open(p, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def _save_cache(tool: str, manual: dict[str, Any]) -> None:
    _ensure_dirs()
    manual["cached_at"] = datetime.utcnow().isoformat()
    with open(_cache_path(tool), "w", encoding="utf-8") as fh:
        json.dump(manual, fh, indent=2)


def _run(cmd: list[str], timeout: float = 4.0) -> str:
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return res.stdout or ""
    except Exception:
        return ""


def _try_tldr(tool: str) -> str | None:
    if shutil.which("tldr") is None:
        return None
    out = _run(["tldr", tool])
    return out.strip() or None


def _try_man(tool: str) -> str | None:
    if shutil.which("man") is None:
        return None
    out = _run(["man", tool])
    # Strip basic groff escapes crudely for readability
    text = re.sub(r"\x1b\[[0-9;]*m", "", out)
    text = re.sub(r".\x08", "", text)
    return text.strip() or None


def _try_help(tool: str) -> str | None:
    binary = shutil.which(tool)
    if not binary:
        return None
    out = _run([binary, "--help"])
    if not out:
        out = _run([binary, "-h"])
    return out.strip() or None


def _try_doc(tool: str) -> str | None:
    for pattern in [f"/usr/share/doc/{tool}", f"/usr/share/doc/{tool}*"]:
        for path in sorted(glob_paths(pattern)):
            if os.path.isfile(path):
                try:
                    with open(path, errors="ignore") as fh:
                        text = fh.read(4000)
                    if text.strip():
                        return text.strip()
                except Exception:
                    continue
    return None


def glob_paths(pattern: str) -> list[str]:
    return _glob.glob(pattern)


def _try_curated(tool: str) -> dict[str, Any] | None:
    _ensure_dirs()
    p = os.path.join(KNOWLEDGE_DIR, f"{tool}.json")
    if not os.path.exists(p):
        return None
    try:
        with open(p, encoding="utf-8") as fh:
            return json.load(fh)
    except Exception:
        return None


def _try_curated_kb(tool: str) -> dict[str, Any] | None:
    """Fallback to the existing knowledge_base.py CURATED_TOOLS catalogue."""
    try:
        from .knowledge_base import CURATED_TOOLS  # type: ignore
    except Exception:
        return None
    for item in CURATED_TOOLS:
        if item.get("name") == tool:
            return item
        for bn in item.get("binary_names", []):
            if bn == tool:
                return item
    return None


def _placeholderize(cmd: str) -> str:
    """Replace common concrete values with placeholders for safe examples."""
    # IP addresses
    cmd = re.sub(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", "<TARGET_IP>", cmd)
    # Hostnames/words after common flags is too fragile; keep IPs masked only.
    return cmd


def build_manual(tool: str, display_name: str = "", category: str = "",
                 curated: dict[str, Any] | None = None) -> dict[str, Any]:
    """Build (or load from cache) a structured manual for `tool`."""
    cached = _load_cache(tool)
    if cached:
        return cached

    _ensure_dirs()
    if curated is None:
        curated = _try_curated(tool)
    if curated is None:
        curated = _try_curated_kb(tool)

    # Gather raw sources
    tldr_text = _try_tldr(tool)
    man_text = _try_man(tool)
    help_text = _try_help(tool)
    doc_text = _try_doc(tool)

    source = "curated" if curated else ("tldr" if tldr_text else
                                         ("man" if man_text else
                                          ("help" if help_text else
                                           ("doc" if doc_text else "none"))))
    manual: dict[str, Any] = {
        "name": tool,
        "display_name": display_name or tool,
        "category": category or "General Security",
        "source": source,
        "purpose": "",
        "install_check": f"which {tool}",
        "options": [],
        "examples": [],
        "mistakes": "",
        "output": "",
        "related": [],
        "mitre": curated.get("mitre_techniques", []) if curated else [],
        "defensive": "",
        "banner": BANNER,
    }

    if curated:
        manual["purpose"] = curated.get("description", "")
        manual["install_check"] = curated.get("package_name", tool)
        manual["options"] = _options_from_examples(curated.get("syntax_examples", []))
        manual["examples"] = _examples_from_curated(curated.get("syntax_examples", []))
        manual["related"] = [r.get("title", "") for r in curated.get("learning_refs", [])][:5]
        manual["defensive"] = (f"Defenders can detect {tool} via process execution "
                               f"monitoring, network-flow logs, and endpoint EDR rules.")
    elif tldr_text:
        manual["purpose"] = _summarize(tldr_text)
        manual["options"] = _options_from_text(tldr_text)
        manual["examples"] = _examples_from_text(tldr_text)
    elif man_text:
        manual["purpose"] = _summarize(man_text)
        manual["options"] = _options_from_text(man_text)
        manual["examples"] = _examples_from_text(man_text)
    elif help_text:
        manual["purpose"] = _summarize(help_text)
        manual["options"] = _options_from_text(help_text)
        manual["examples"] = _examples_from_text(help_text)
    elif doc_text:
        manual["purpose"] = _summarize(doc_text)
        manual["options"] = []
        manual["examples"] = []

    if not manual["examples"]:
        manual["examples"] = [{
            "level": "Beginner",
            "cmd": f"{tool} --help",
            "desc": f"Display usage flags for {tool}.",
            "placeholder_cmd": f"{tool} --help",
        }]

    _save_cache(tool, manual)
    return manual


def _options_from_examples(examples: list[dict[str, Any]]) -> list[dict[str, str]]:
    opts = []
    for ex in examples[:8]:
        cmd = ex.get("cmd", "")
        flags = re.findall(r"-[a-zA-Z0-9\-]+", cmd)
        for f in flags[:3]:
            opts.append({"flag": f, "description": ex.get("desc", "")})
    return opts


def _examples_from_curated(examples: list[dict[str, Any]]) -> list[dict[str, str]]:
    out = []
    levels = ["Beginner", "Beginner", "Intermediate", "Intermediate", "Advanced"]
    for i, ex in enumerate(examples[:10]):
        cmd = _placeholderize(ex.get("cmd", ""))
        out.append({
            "level": levels[min(i, len(levels) - 1)],
            "cmd": cmd,
            "placeholder_cmd": cmd,
            "desc": ex.get("desc", ""),
        })
    return out


def _options_from_text(text: str) -> list[dict[str, str]]:
    opts = []
    for line in text.splitlines():
        m = re.match(r"\s*(-[a-zA-Z0-9]+|--[a-zA-Z0-9\-]+)\b(.*)", line)
        if m:
            opts.append({"flag": m.group(1), "description": m.group(2).strip()[:80]})
    return opts[:10]


def _examples_from_text(text: str) -> list[dict[str, str]]:
    out = []
    seen = set()
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if any(tok in line for tok in [":", "http", "https"]):
            continue
        if len(line) < 4 or len(line) > 120:
            continue
        if line in seen:
            continue
        seen.add(line)
        out.append({
            "level": "Beginner",
            "cmd": _placeholderize(line),
            "placeholder_cmd": _placeholderize(line),
            "desc": "Example from local manual source.",
        })
        if len(out) >= 6:
            break
    return out


def _summarize(text: str) -> str:
    """Produce a short purpose summary from raw text (first meaningful sentence)."""
    text = re.sub(r"\s+", " ", text).strip()
    # take up to the first period after 40 chars
    for m in re.finditer(r"[.!?]\s", text):
        if m.start() > 40:
            return text[:m.end()].strip()
    return text[:200].strip()


def explain_command(command: str) -> dict[str, Any]:
    """Offline flag-by-flag breakdown of a command. AI optional (not used here)."""
    tokens = command.split()
    if not tokens:
        return {"command": command, "flags": [], "summary": "Empty command."}
    binary = tokens[0]
    flags = []
    for tok in tokens[1:]:
        if tok.startswith("-"):
            flags.append({"flag": tok, "description": "Flag parsed from command line."})
        elif not tok.startswith("<"):
            flags.append({"flag": tok, "description": "Argument/value."})
    return {
        "command": command,
        "binary": binary,
        "flags": flags,
        "placeholders": [p for p in PLACEHOLDERS if p in command],
        "summary": f"{binary} invocation with {len(flags)} flag/argument tokens.",
        "banner": BANNER,
    }


def list_cached_manuals() -> list[str]:
    _ensure_dirs()
    return sorted([f[:-5] for f in os.listdir(CACHE_DIR) if f.endswith(".json")])
