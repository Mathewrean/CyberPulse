"""
CyberPulse layered usage collectors.

Each collector is a plugin auto-detected by CollectorManager. Events from all
plugins are de-duplicated by (pid, tool_name, start_time) before being written
to the database, so the same short-lived command isn't recorded twice.

Collectors:
  a) psutil polling          - baseline, adaptive interval
  b) shell hook              - opt-in rc snippet logging to data/shell_hook.log
  c) wrapper shims           - ~/.cyberpulse/bin wrappers logging to data/wrapper.log
  d) kernel-level (auditd/eBPF execsnoop) - graceful skip if unavailable
  e) desktop launcher hook   - Kali .desktop launch tracking
  f) manual lab session      - Start/Stop lab session button
"""

import glob
import json
import os
import shutil
import threading
import time
from datetime import datetime
from typing import Any

import psutil

from .config import monitor_interval
from .database import (
    get_all_tools,
    get_lab_sessions,
    record_usage_event,
    start_lab_session,
    stop_lab_session,
)

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data")
SHELL_LOG = os.path.join(DATA_DIR, "shell_hook.log")
WRAPPER_LOG = os.path.join(DATA_DIR, "wrapper.log")

# Dedup window (seconds): same pid+tool+start within this window is one event.
DEDUP_WINDOW_SEC = 3.0

_TOOL_NAME_CACHE: dict[str, str] = {}
_TOOL_NAME_CACHE_TS = 0.0


def _resolve_tool_name(cmdline: str, proc_name: str) -> str | None:
    """Best-effort mapping of a process to a known tool name."""
    now = time.time()
    global _TOOL_NAME_CACHE_TS
    if now - _TOOL_NAME_CACHE_TS > 30:
        _TOOL_NAME_CACHE.clear()
        try:
            for t in get_all_tools():
                name = t["name"]
                bp = t.get("binary_path") or ""
                _TOOL_NAME_CACHE[name.lower()] = name
                if bp:
                    _TOOL_NAME_CACHE[os.path.basename(bp).lower()] = name
            for alias, target in {
                "msfconsole": "metasploit", "tshark": "wireshark",
                "wireshark-gtk": "wireshark", "bloodhound-python": "bloodhound",
                "binwalk3": "binwalk", "nxc": "netexec",
            }.items():
                _TOOL_NAME_CACHE[alias] = target
        except Exception:
            pass
        _TOOL_NAME_CACHE_TS = now

    cl = (cmdline or "").lower()
    pn = (proc_name or "").lower()
    for token in set([pn] + cl.split()[:3]):
        token = token.strip("\"'").split("/")[-1]
        if token in _TOOL_NAME_CACHE:
            return _TOOL_NAME_CACHE[token]
    return None


def _hash_args(args: str) -> str:
    import hashlib
    return hashlib.sha256((args or "").encode("utf-8")).hexdigest()[:16]


class CollectorPlugin:
    name = "base"
    enabled = False

    def start(self) -> None:
        pass

    def stop(self) -> None:
        pass

    def get_status(self) -> dict[str, Any]:
        return {"name": self.name, "enabled": self.enabled, "available": False}

    def collect(self) -> list[dict[str, Any]]:
        """Return list of raw usage events to ingest."""
        return []


class PsutilCollector(CollectorPlugin):
    """a) psutil polling with adaptive interval."""
    name = "polling"
    enabled = True

    def __init__(self, base_interval: float = 3.0):
        self.base_interval = base_interval
        self._running = False
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        self._active: dict[int, dict[str, Any]] = {}

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="Cp-Psutil")
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)

    def _loop(self):
        fast_until = 0.0
        while self._running:
            try:
                events = self._check()
                if events:
                    fast_until = time.time() + 5.0  # stay fast for 5s
            except Exception:
                pass
            interval = 0.5 if time.time() < fast_until else self.base_interval
            time.sleep(interval)

    def _check(self) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        now = time.time()
        current_pids: set[int] = set()
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time']):
            try:
                pid = proc.info['pid']
                current_pids.add(pid)
                if pid in self._active:
                    continue
                cmdline_list = proc.info['cmdline'] or []
                cmdline_str = " ".join(cmdline_list)
                tool = _resolve_tool_name(cmdline_str, proc.info['name'] or "")
                if not tool:
                    continue
                self._active[pid] = {
                    "tool_name": tool, "start_time": proc.info.get('create_time') or now,
                    "cmdline": cmdline_str[:250],
                }
                events.append({
                    "tool_name": tool, "pid": pid,
                    "start_time": self._active[pid]["start_time"],
                    "cmdline": cmdline_str[:250],
                    "source_method": "polling",
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        terminated = []
        with self._lock:
            for pid, info in list(self._active.items()):
                if pid not in current_pids:
                    terminated.append((pid, info))
                    del self._active[pid]
        for pid, info in terminated:
            duration = max(0.1, now - info["start_time"])
            events.append({
                "tool_name": info["tool_name"], "pid": pid,
                "start_time": info["start_time"], "end_time": now,
                "duration_seconds": duration, "cmdline": info["cmdline"],
                "source_method": "polling", "exit_code": 0,
            })
        return events

    def get_status(self) -> dict[str, Any]:
        return {"name": self.name, "enabled": self.enabled,
                "active": len(self._active)}

    def get_live_status(self) -> list[dict[str, Any]]:
        """Currently running monitored processes with live stats."""
        now = time.time()
        live = []
        with self._lock:
            for pid, info in list(self._active.items()):
                try:
                    proc = psutil.Process(pid)
                    cpu = proc.cpu_percent(interval=None)
                    mem_mb = round(proc.memory_info().rss / (1024 * 1024), 1)
                except Exception:
                    cpu, mem_mb = 0.0, 0.0
                duration_sec = max(0, int(now - info["start_time"]))
                hours, rem = divmod(duration_sec, 3600)
                mins, secs = divmod(rem, 60)
                live.append({
                    "pid": pid,
                    "tool_name": info["tool_name"],
                    "cmdline": info["cmdline"],
                    "duration_seconds": duration_sec,
                    "duration_formatted": f"{hours:02d}h {mins:02d}m {secs:02d}s",
                    "cpu_percent": cpu,
                    "memory_mb": mem_mb,
                    "started_at": datetime.fromtimestamp(info["start_time"]).strftime("%H:%M:%S"),
                    "source_method": "polling",
                })
        return live


class ShellHookCollector(CollectorPlugin):
    """b) Shell hook: reads data/shell_hook.log written by an opt-in rc snippet."""
    name = "shell_hook"
    enabled = False

    def __init__(self):
        self._last_inode: int | None = None
        self._last_offset = 0

    def get_status(self) -> dict[str, Any]:
        return {"name": self.name, "enabled": self.enabled,
                "available": os.path.exists(SHELL_LOG) or self.enabled,
                "hint": "source the rc snippet in ~/.bashrc / ~/.zshrc / ~/.config/fish/config.fish"}

    def rc_snippet(self) -> str:
        return f'''\n# CyberPulse shell hook (opt-in) - log command usage
cyberpulse_log() {{
    local rc=$?
    local cmd="${{BASH_COMMAND:-$1}}"
    if [ -n "$cmd" ] && [ "$cmd" != "cyberpulse_log" ]; then
        echo "$(date +%s) ${{PPID}} ${{USER}} ${{PWD}} ${{rc}} ${{cmd}}" >> {SHELL_LOG}
    fi
}}
'''
    def fish_snippet(self) -> str:
        return f'''\n# CyberPulse shell hook (opt-in) for fish
function cyberpulse_log --on-event fish_postexec
    echo "(date +%s) (status) (pwd) (commandline)" >> {SHELL_LOG}
end
'''

    def collect(self) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        if not os.path.exists(SHELL_LOG):
            return events
        try:
            st = os.stat(SHELL_LOG)
            if self._last_inode is None:
                self._last_inode = st.st_ino
                self._last_offset = st.st_size
                return events
            if st.st_ino != self._last_inode:
                self._last_offset = 0
                self._last_inode = st.st_ino
            with open(SHELL_LOG, errors="ignore") as fh:
                fh.seek(self._last_offset)
                lines = fh.readlines()
                self._last_offset = fh.tell()
        except Exception:
            return events
        for line in lines:
            line = line.strip()
            if not line:
                continue
            parts = line.split(" ", 5)
            if len(parts) < 6:
                continue
            ts, ppid, user, cwd, rc, cmd = parts
            tool = _resolve_tool_name(cmd, "")
            if not tool:
                continue
            try:
                start_ts = float(ts)
            except ValueError:
                start_ts = time.time()
            events.append({
                "tool_name": tool, "pid": int(ppid) if ppid.isdigit() else 0,
                "start_time": start_ts, "end_time": time.time(),
                "duration_seconds": max(0.1, time.time() - start_ts),
                "cmdline": cmd[:250], "source_method": "shell_hook",
                "exit_code": int(rc) if rc.isdigit() else 0,
            })
        return events


class WrapperCollector(CollectorPlugin):
    """c) Wrapper shims in ~/.cyberpulse/bin (opt-in)."""
    name = "wrapper"
    enabled = False

    def __init__(self):
        self.bin_dir = os.path.expanduser("~/.cyberpulse/bin")
        self._seen: set[str] = set()

    def get_status(self) -> dict[str, Any]:
        return {"name": self.name, "enabled": self.enabled,
                "available": os.path.isdir(self.bin_dir),
                "hint": "place wrappers in ~/.cyberpulse/bin and prepend to PATH"}

    def setup_snippet(self) -> str:
        return '''# Add CyberPulse wrapper shims to PATH (opt-in)
export PATH="$HOME/.cyberpulse/bin:$PATH"
'''

    def collect(self) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        if not os.path.exists(WRAPPER_LOG):
            return events
        try:
            with open(WRAPPER_LOG, errors="ignore") as fh:
                lines = fh.readlines()
        except Exception:
            return events
        for line in lines:
            line = line.strip()
            if not line or line in self._seen:
                continue
            self._seen.add(line)
            try:
                payload = json.loads(line)
            except Exception:
                continue
            tool = payload.get("tool")
            if not tool:
                tool = _resolve_tool_name(payload.get("cmdline", ""), "")
            if not tool:
                continue
            events.append({
                "tool_name": tool, "pid": int(payload.get("pid", 0) or 0),
                "start_time": float(payload.get("start_time", time.time())),
                "end_time": float(payload.get("end_time", time.time())),
                "duration_seconds": float(payload.get("duration_seconds", 0.1)),
                "cmdline": str(payload.get("cmdline", ""))[:250],
                "source_method": "wrapper", "exit_code": int(payload.get("exit_code", 0) or 0),
            })
        return events


class AuditdCollector(CollectorPlugin):
    """d) Kernel-level: auditd rules or eBPF execsnoop. Graceful skip if unavailable."""
    name = "auditd"
    enabled = False

    def get_status(self) -> dict[str, Any]:
        has_auditd = shutil.which("auditctl") is not None
        has_execsnoop = shutil.which("execsnoop") is not None or shutil.which("bpftrace") is not None
        return {"name": self.name, "enabled": self.enabled,
                "available": has_auditd or has_execsnoop,
                "hint": "requires sudo; skipped gracefully if auditd/eBPF not present"}

    def collect(self) -> list[dict[str, Any]]:
        # Kernel-level collection requires privileged setup; skip gracefully.
        return []


class DesktopCollector(CollectorPlugin):
    """e) Desktop launcher hook: track Kali .desktop application launches."""
    name = "desktop"
    enabled = False

    def get_status(self) -> dict[str, Any]:
        desktop_dirs = ["/usr/share/applications", os.path.expanduser("~/.local/share/applications")]
        count = 0
        for d in desktop_dirs:
            if os.path.isdir(d):
                count += len(glob.glob(os.path.join(d, "*.desktop")))
        return {"name": self.name, "enabled": self.enabled,
                "available": count > 0, "launchers": count}

    def collect(self) -> list[dict[str, Any]]:
        # Passive: .desktop launch tracking would need a session bus monitor;
        # exposed as available inventory rather than background polling.
        return []


class CollectorManager:
    """Runs all collector plugins, de-duplicates, and persists events."""

    def __init__(self):
        self.plugins: list[CollectorPlugin] = [
            PsutilCollector(base_interval=monitor_interval()),
            ShellHookCollector(),
            WrapperCollector(),
            AuditdCollector(),
            DesktopCollector(),
        ]
        self._running = False
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()
        # dedup cache: key -> timestamp
        self._dedup: dict[tuple[str, int, float], float] = {}

    def get_status(self) -> list[dict[str, Any]]:
        return [p.get_status() for p in self.plugins]

    def get_live_status(self) -> list[dict[str, Any]]:
        for p in self.plugins:
            if p.name == "polling" and hasattr(p, "get_live_status"):
                return p.get_live_status()
        return []

    def set_enabled(self, name: str, enabled: bool) -> bool:
        for p in self.plugins:
            if p.name == name:
                p.enabled = bool(enabled)
                if bool(enabled) and not self._running:
                    self.start()
                return True
        return False

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._loop, daemon=True, name="Cp-Collectors")
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=3.0)
        for p in self.plugins:
            try:
                p.stop()
            except Exception:
                pass

    def _loop(self):
        while self._running:
            all_events: list[dict[str, Any]] = []
            for p in self.plugins:
                if not p.enabled:
                    continue
                try:
                    all_events.extend(p.collect())
                except Exception:
                    continue
            self._ingest(all_events)
            time.sleep(1.0)

    def _ingest(self, events: list[dict[str, Any]]):
        now = time.time()
        # De-duplicate by (tool_name, pid, start_time)
        unique: list[dict[str, Any]] = []
        with self._lock:
            for e in events:
                key = (e.get("tool_name", ""), e.get("pid", 0), e.get("start_time", now))
                last = self._dedup.get(key)
                if last is not None and now - last < DEDUP_WINDOW_SEC:
                    continue
                self._dedup[key] = now
                unique.append(e)
        # Prune stale dedup entries
        with self._lock:
            self._dedup = {k: v for k, v in self._dedup.items() if now - v < 60}
        for e in unique:
            try:
                record_usage_event(
                    tool_name=e.get("tool_name", "unknown"),
                    pid=int(e.get("pid", 0) or 0),
                    start_time=datetime.fromtimestamp(float(e.get("start_time", now))).isoformat(),
                    end_time=datetime.fromtimestamp(float(e.get("end_time", now))).isoformat() if e.get("end_time") else "",
                    duration_seconds=float(e.get("duration_seconds", 0.1)),
                    cmdline=e.get("cmdline", ""),
                    args_hash=_hash_args(e.get("cmdline", "")),
                    source_method=e.get("source_method", "polling"),
                    exit_code=int(e.get("exit_code", 0) or 0),
                    cpu_peak=0.0,
                    mem_peak=0.0,
                    session_id=e.get("session_id", ""),
                )
            except Exception:
                pass


# --- Lab session API (manual session log / phase f) ---

_lab_lock = threading.Lock()

def lab_start(session_id: str, name: str = "", target: str = "", notes: str = "", tools: list[str] = None) -> None:
    with _lab_lock:
        start_lab_session(session_id, name, target, notes, tools)

def lab_stop(session_id: str) -> None:
    with _lab_lock:
        stop_lab_session(session_id)

def lab_list(limit: int = 20) -> list[dict[str, Any]]:
    return get_lab_sessions(limit)


# Global singleton
_collector_manager: CollectorManager | None = None


def get_collector_manager() -> CollectorManager:
    global _collector_manager
    if _collector_manager is None:
        _collector_manager = CollectorManager()
    return _collector_manager
