"""
CyberPulse Real-Time Process Monitor & Tool Usage Tracker
Background daemon thread that tracks cybersecurity tool executions, runtimes,
PIDs, CPU/Memory resource consumption, and logs historic usage sessions.
"""

import threading
import time
from datetime import datetime
from typing import Any

import psutil

from .database import get_connection, record_process_start, record_process_stop


class ToolUsageMonitor:
    def __init__(self, check_interval: float = 3.0):
        self.check_interval = check_interval
        self._running = False
        self._thread: threading.Thread = None
        # Track active processes: { pid: { "tool_name": str, "start_time": float, "cmdline": str } }
        self.active_processes: dict[int, dict[str, Any]] = {}
        # Monitored tool names and binary identifiers
        self.monitored_tools: dict[str, str] = {} # { binary_or_proc_name_lower: canonical_tool_name }
        self._lock = threading.Lock()
        self.refresh_monitored_tools()

    def refresh_monitored_tools(self):
        """Loads canonical tool names and binary aliases from the database."""
        with self._lock:
            try:
                conn = get_connection()
                cursor = conn.cursor()
                cursor.execute("SELECT name, binary_path FROM tools WHERE installed = 1")
                rows = cursor.fetchall()
                conn.close()
                
                monitored = {}
                for r in rows:
                    name = r["name"].lower()
                    monitored[name] = r["name"]
                    bin_path = r["binary_path"]
                    if bin_path:
                        base = bin_path.split("/")[-1].lower()
                        monitored[base] = r["name"]
                        
                # Add common binary name variants
                aliases = {
                    "msfconsole": "metasploit",
                    "tshark": "wireshark",
                    "wireshark-gtk": "wireshark",
                    "bloodhound-python": "bloodhound",
                    "binwalk3": "binwalk",
                    "python3-volatility": "volatility"
                }
                for alias, target in aliases.items():
                    if target in monitored:
                        monitored[alias] = target
                        
                self.monitored_tools = monitored
            except Exception:
                pass

    def start(self):
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True, name="CyberPulse-Monitor")
        self._thread.start()

    def stop(self):
        self._running = False
        if self._thread:
            self._thread.join(timeout=2.0)

    def _monitor_loop(self):
        while self._running:
            try:
                self._check_processes()
            except Exception:
                pass
            time.sleep(self.check_interval)

    def _check_processes(self):
        current_pids: set[int] = set()
        
        # Scan running processes
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'create_time', 'cpu_percent', 'memory_info']):
            try:
                pid = proc.info['pid']
                current_pids.add(pid)
                
                # Check if already tracked
                if pid in self.active_processes:
                    continue
                    
                pname = (proc.info['name'] or "").lower()
                cmdline_list = proc.info['cmdline'] or []
                cmdline_str = " ".join(cmdline_list)
                cmdline_lower = cmdline_str.lower()
                
                matched_tool = None
                
                # Direct match on process executable name
                if pname in self.monitored_tools:
                    matched_tool = self.monitored_tools[pname]
                else:
                    # Check first argument or script argument in cmdline
                    for arg in cmdline_list[:3]:
                        base_arg = arg.split("/")[-1].lower()
                        if base_arg in self.monitored_tools:
                            matched_tool = self.monitored_tools[base_arg]
                            break
                            
                # If matched, register new session
                if matched_tool:
                    start_time = proc.info.get('create_time') or time.time()
                    with self._lock:
                        self.active_processes[pid] = {
                            "tool_name": matched_tool,
                            "start_time": start_time,
                            "cmdline": cmdline_str[:250],
                            "proc_ref": proc
                        }
                    record_process_start(matched_tool, pid, cmdline_str[:250])
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        # Check for terminated processes that were tracked
        terminated_pids = []
        with self._lock:
            for pid, info in list(self.active_processes.items()):
                if pid not in current_pids:
                    terminated_pids.append((pid, info))
                    del self.active_processes[pid]

        # Record end for terminated processes
        now = time.time()
        for pid, info in terminated_pids:
            duration = max(1.0, now - info["start_time"])
            record_process_stop(info["tool_name"], pid, duration)

    def get_live_status(self) -> list[dict[str, Any]]:
        """Returns list of currently active security processes with live stats."""
        live = []
        now = time.time()
        with self._lock:
            for pid, info in self.active_processes.items():
                duration_sec = max(0, int(now - info["start_time"]))
                hours, rem = divmod(duration_sec, 3600)
                mins, secs = divmod(rem, 60)
                duration_str = f"{hours:02d}h {mins:02d}m {secs:02d}s"
                
                cpu = 0.0
                mem_mb = 0.0
                proc = info.get("proc_ref")
                if proc:
                    try:
                        cpu = proc.cpu_percent(interval=None)
                        mem_mb = round(proc.memory_info().rss / (1024 * 1024), 1)
                    except Exception:
                        pass
                        
                live.append({
                    "pid": pid,
                    "tool_name": info["tool_name"],
                    "cmdline": info["cmdline"],
                    "duration_seconds": duration_sec,
                    "duration_formatted": duration_str,
                    "cpu_percent": cpu,
                    "memory_mb": mem_mb,
                    "started_at": datetime.fromtimestamp(info["start_time"]).strftime("%H:%M:%S")
                })
        return live

# Global singleton monitor
_monitor_instance: ToolUsageMonitor = None

def get_monitor() -> ToolUsageMonitor:
    global _monitor_instance
    if _monitor_instance is None:
        _monitor_instance = ToolUsageMonitor()
    return _monitor_instance
