#!/usr/bin/env python3
"""
CyberPulse - Cybersecurity Tool Checklist, Usage Monitor & Scenario Advisor
Spotify Edition for Kali Linux / Debian
Main entry point.
"""

import os
import sys
import argparse
import uvicorn
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# Ensure package directory is on python path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from backend.api import app
from backend.database import init_db, get_all_tools
from backend.scanner import scan_all_tools
from backend.monitor import get_monitor

# Mount static files directory
STATIC_DIR = os.path.join(BASE_DIR, "static")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

@app.get("/")
def serve_root():
    return FileResponse(os.path.join(STATIC_DIR, "index.html"))

@app.on_event("startup")
def on_startup():
    print("[CyberPulse] Initializing SQLite database...")
    init_db()
    
    # Check if tools already scanned
    tools = get_all_tools()
    if not tools:
        print("[CyberPulse] First launch detected: running initial deep system scan...")
        res = scan_all_tools()
        print(f"[CyberPulse] Discovered {res['total_scanned']} tools ({res['total_installed']} installed).")
    else:
        print(f"[CyberPulse] Loaded {len(tools)} tools from database.")
        
    # Start background process monitor
    print("[CyberPulse] Launching background process usage monitor...")
    monitor = get_monitor()
    monitor.start()
    print("[CyberPulse] Monitor thread active. Tracking process table.")

@app.on_event("shutdown")
def on_shutdown():
    print("[CyberPulse] Shutting down monitor thread...")
    get_monitor().stop()

def main():
    parser = argparse.ArgumentParser(description="CyberPulse - Cybersecurity Tool Checklist & Activity Monitor")
    parser.add_argument("--host", default="127.0.0.1", help="Host interface to bind (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8844, help="Port to bind (default: 8844)")
    parser.add_argument("--scan", action="store_true", help="Force immediate full tool re-scan and exit")
    args = parser.parse_args()

    if args.scan:
        init_db()
        print("[CyberPulse] Running full system tool scan...")
        res = scan_all_tools()
        print(f"[CyberPulse] Scan complete: {res}")
        return

    print(f"================================================================")
    print(f"  CyberPulse Security Suite (Spotify Edition)")
    print(f"  Web Dashboard: http://{args.host}:{args.port}")
    print(f"  Codebase Path: {BASE_DIR}")
    print(f"================================================================")
    
    uvicorn.run(app, host=args.host, port=args.port, log_level="info")

if __name__ == "__main__":
    main()
