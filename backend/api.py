"""
CyberPulse FastAPI REST API
Serves tools data, statistics, live process monitoring, and scenario advice.
"""

from fastapi import FastAPI, HTTPException, Query, Body
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import os
import time

from .database import (
    get_all_tools, update_tool_status, get_statistics,
    get_setting, set_setting, get_scenario_history, DB_PATH
)
from .scanner import scan_all_tools
from .monitor import get_monitor
from .advisor import analyze_scenario, check_internet_connection

app = FastAPI(title="CyberPulse API", version="2.0.0")

class StatusUpdateRequest(BaseModel):
    checklist_status: Optional[str] = None
    is_favorite: Optional[int] = None
    user_notes: Optional[str] = None

class ScenarioRequest(BaseModel):
    scenario: str
    force_offline: bool = False

class SettingsUpdateRequest(BaseModel):
    theme: Optional[str] = None
    ai_provider: Optional[str] = None
    gemini_api_key: Optional[str] = None
    openai_api_key: Optional[str] = None

@app.get("/api/health")
def health():
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "internet_connected": check_internet_connection(timeout=1.0)
    }

@app.get("/api/tools")
def list_tools(
    search: Optional[str] = None,
    category: Optional[str] = None,
    source: Optional[str] = None,
    installed: Optional[str] = None, # "all", "1", "0"
    status: Optional[str] = None,
    favorite: Optional[int] = None
):
    all_tools = get_all_tools()
    filtered = []
    
    for t in all_tools:
        if search:
            q = search.lower()
            t_name = t["name"].lower()
            t_disp = t["display_name"].lower()
            t_desc = t["description"].lower()
            t_cat = t["category"].lower()
            t_src = (t.get("install_source") or "").lower()
            if q not in t_name and q not in t_disp and q not in t_desc and q not in t_cat and q not in t_src:
                continue
                
        if category and category.lower() != "all":
            if t["category"].lower() != category.lower():
                continue

        if source and source.lower() != "all":
            if (t.get("install_source") or "").lower() != source.lower():
                continue
                
        if installed is not None and installed != "all":
            want_inst = 1 if installed in ("1", "true", "installed") else 0
            if t["installed"] != want_inst:
                continue
                
        if status and status.lower() != "all":
            if t["checklist_status"].lower() != status.lower():
                continue
                
        if favorite is not None:
            if t["is_favorite"] != favorite:
                continue
                
        filtered.append(t)
        
    return {"total": len(filtered), "tools": filtered}

@app.get("/api/tools/{name}")
def get_tool(name: str):
    all_tools = get_all_tools()
    for t in all_tools:
        if t["name"].lower() == name.lower():
            return t
    raise HTTPException(status_code=404, detail="Tool not found")

@app.post("/api/tools/{name}/status")
def set_tool_status(name: str, payload: StatusUpdateRequest):
    update_tool_status(
        tool_name=name,
        status=payload.checklist_status,
        is_favorite=payload.is_favorite,
        notes=payload.user_notes
    )
    return {"status": "success", "tool": name}

@app.post("/api/scan")
def trigger_scan():
    result = scan_all_tools()
    get_monitor().refresh_monitored_tools()
    return {"status": "success", "scan_results": result}

@app.get("/api/stats")
def stats():
    st = get_statistics()
    live = get_monitor().get_live_status()
    st["live_active"] = live
    st["internet_connected"] = check_internet_connection(timeout=1.0)
    return st

@app.get("/api/monitor/live")
def monitor_live():
    live = get_monitor().get_live_status()
    return {"active_count": len(live), "processes": live}

@app.post("/api/advisor/analyze")
def advisor_analyze(payload: ScenarioRequest):
    if not payload.scenario.strip():
        raise HTTPException(status_code=400, detail="Scenario text cannot be empty")
    result = analyze_scenario(payload.scenario, force_offline=payload.force_offline)
    return result

@app.get("/api/advisor/history")
def advisor_history(limit: int = 10):
    return {"history": get_scenario_history(limit=limit)}

@app.get("/api/settings")
def get_settings():
    return {
        "theme": get_setting("theme", "dark"),
        "ai_provider": get_setting("ai_provider", "hybrid"),
        "gemini_api_key": get_setting("gemini_api_key", ""),
        "last_full_scan": get_setting("last_full_scan", "")
    }

@app.post("/api/settings")
def save_settings(payload: SettingsUpdateRequest):
    if payload.theme:
        set_setting("theme", payload.theme)
    if payload.ai_provider:
        set_setting("ai_provider", payload.ai_provider)
    if payload.gemini_api_key is not None:
        set_setting("gemini_api_key", payload.gemini_api_key)
    return {"status": "success"}

@app.get("/api/export")
def export_data():
    tools = get_all_tools()
    stats_data = get_statistics()
    export_payload = {
        "export_timestamp": time.time(),
        "total_tools": len(tools),
        "statistics": stats_data,
        "tools": tools
    }
    return JSONResponse(
        content=export_payload,
        headers={"Content-Disposition": "attachment; filename=cyberpulse_checklist_export.json"}
    )
