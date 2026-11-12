"""
CyberPulse FastAPI REST API
Serves tools data, statistics, live process monitoring, and scenario advice.
"""

import os
import shutil
import time
from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from .advisor import analyze_scenario, check_internet_connection
from .collectors import (
    SHELL_LOG,
    WRAPPER_LOG,
    get_collector_manager,
    lab_list,
    lab_start,
    lab_stop,
)
from .config import ai_enabled, ai_redact
from .database import (
    cleanup_retention,
    get_all_tools,
    get_retention,
    get_scenario_history,
    get_setting,
    get_statistics,
    set_retention,
    set_setting,
    update_tool_status,
    wipe_all_data,
    DB_PATH,
)
from .manual import build_manual, explain_command, list_cached_manuals
from .monitor import get_monitor
from .scanner import scan_all_tools

app = FastAPI(title="CyberPulse API", version="2.0.0")

# Maximum accepted size for free-text inputs (bytes). Prevents abuse.
MAX_TEXT_INPUT = 20000


def _validate_text(text: str | None, field: str = "text") -> str:
    if text is None:
        raise HTTPException(status_code=400, detail=f"{field} is required")
    if not isinstance(text, str):
        raise HTTPException(status_code=400, detail=f"{field} must be a string")
    if len(text.encode("utf-8")) > MAX_TEXT_INPUT:
        raise HTTPException(status_code=400, detail=f"{field} too large (max {MAX_TEXT_INPUT // 1024} KB)")
    return text

class StatusUpdateRequest(BaseModel):
    checklist_status: str | None = None
    is_favorite: int | None = None
    user_notes: str | None = None

class ScenarioRequest(BaseModel):
    scenario: str
    force_offline: bool = False

class SettingsUpdateRequest(BaseModel):
    theme: str | None = None
    ai_provider: str | None = None
    ai_enabled: bool | None = None
    ai_redact_before_send: bool | None = None
    gemini_api_key: str | None = None
    openai_api_key: str | None = None

@app.get("/api/health")
def health():
    return {
        "status": "healthy",
        "timestamp": time.time(),
        "internet_connected": check_internet_connection(timeout=1.0)
    }

@app.get("/api/tools")
def list_tools(
    search: str | None = None,
    category: str | None = None,
    source: str | None = None,
    installed: str | None = None, # "all", "1", "0"
    status: str | None = None,
    favorite: int | None = None
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
    live = get_collector_manager().get_live_status()
    st["live_active"] = live
    st["collectors"] = get_collector_manager().get_status()
    st["internet_connected"] = check_internet_connection(timeout=1.0)
    return st

@app.get("/api/monitor/live")
def monitor_live():
    live = get_collector_manager().get_live_status()
    return {"active_count": len(live), "processes": live}

@app.get("/api/monitor/collectors")
def collectors_list():
    return {"collectors": get_collector_manager().get_status()}

@app.post("/api/monitor/collectors/{name}")
def collectors_set(name: str, payload: dict[str, Any] = None):
    enabled = bool((payload or {}).get("enabled", False))
    ok = get_collector_manager().set_enabled(name, enabled)
    if not ok:
        raise HTTPException(status_code=404, detail="Collector not found")
    return {"status": "success", "collector": name, "enabled": enabled}

@app.get("/api/collectors/shell-hook")
def shell_hook_snippet():
    cm = get_collector_manager()
    for p in cm.plugins:
        if p.name == "shell_hook":
            return {"bash": p.rc_snippet(), "fish": p.fish_snippet(), "log": SHELL_LOG}
    raise HTTPException(status_code=404, detail="shell_hook collector not found")

@app.get("/api/collectors/wrapper")
def wrapper_snippet():
    cm = get_collector_manager()
    for p in cm.plugins:
        if p.name == "wrapper":
            return {"snippet": p.setup_snippet(), "bin_dir": p.bin_dir, "log": WRAPPER_LOG}
    raise HTTPException(status_code=404, detail="wrapper collector not found")

@app.post("/api/advisor/analyze")
def advisor_analyze(payload: ScenarioRequest):
    scenario = _validate_text(payload.scenario, "scenario")
    if not scenario.strip():
        raise HTTPException(status_code=400, detail="Scenario text cannot be empty")
    result = analyze_scenario(scenario, force_offline=payload.force_offline, ai_enabled=ai_enabled(), redact=ai_redact())
    return result

@app.get("/api/advisor/history")
def advisor_history(limit: int = 10):
    return {"history": get_scenario_history(limit=limit)}

@app.get("/api/settings")
def get_settings():
    return {
        "theme": get_setting("theme", "dark"),
        "ai_provider": get_setting("ai_provider", "hybrid"),
        "ai_enabled": get_setting("ai_enabled", "false"),
        "ai_redact_before_send": get_setting("ai_redact_before_send", "true"),
        "gemini_api_key": get_setting("gemini_api_key", ""),
        "last_full_scan": get_setting("last_full_scan", ""),
    }

@app.post("/api/settings")
def save_settings(payload: SettingsUpdateRequest):
    if payload.theme:
        set_setting("theme", payload.theme)
    if payload.ai_provider:
        set_setting("ai_provider", payload.ai_provider)
    if payload.ai_enabled is not None:
        set_setting("ai_enabled", "true" if payload.ai_enabled else "false")
    if payload.ai_redact_before_send is not None:
        set_setting("ai_redact_before_send", "true" if payload.ai_redact_before_send else "false")
    if payload.gemini_api_key is not None:
        set_setting("gemini_api_key", payload.gemini_api_key)
    return {"status": "success"}


@app.get("/api/retention")
def get_retention_endpoint():
    return {
        "usage_sessions_days": int(get_retention("usage_sessions_days", "0") or 0),
        "scenario_history_days": int(get_retention("scenario_history_days", "0") or 0),
    }

class RetentionUpdateRequest(BaseModel):
    usage_sessions_days: int | None = None
    scenario_history_days: int | None = None

@app.post("/api/retention")
def save_retention(payload: RetentionUpdateRequest):
    if payload.usage_sessions_days is not None:
        set_retention("usage_sessions_days", str(payload.usage_sessions_days))
    if payload.scenario_history_days is not None:
        set_retention("scenario_history_days", str(payload.scenario_history_days))
    return {"status": "success"}

@app.post("/api/retention/cleanup")
def run_retention_cleanup():
    deleted = cleanup_retention()
    return {"status": "success", "deleted": deleted}

@app.post("/api/data/wipe")
def wipe_data():
    counts = wipe_all_data()
    return {"status": "success", "wiped": counts}


# --- Manual lab session endpoints ---
class LabSessionRequest(BaseModel):
    session_id: str
    name: str | None = ""
    target: str | None = ""
    notes: str | None = ""
    tools: list[str] | None = []

@app.post("/api/lab/sessions")
def lab_sessions_start(payload: LabSessionRequest):
    lab_start(payload.session_id, payload.name, payload.target, payload.notes, payload.tools)
    return {"status": "success", "session_id": payload.session_id}

@app.post("/api/lab/sessions/{session_id}/stop")
def lab_sessions_stop(session_id: str):
    lab_stop(session_id)
    return {"status": "success", "session_id": session_id}

@app.get("/api/lab/sessions")
def lab_sessions_list(limit: int = 20):
    return {"sessions": lab_list(limit)}

@app.get("/api/manual/{tool}")
def manual_get(tool: str):
    manual = build_manual(tool)
    return manual

class ExplainRequest(BaseModel):
    command: str

@app.post("/api/manual/explain")
def manual_explain(payload: ExplainRequest):
    command = _validate_text(payload.command, "command")
    return explain_command(command)

@app.get("/api/manual/list")
def manual_list():
    return {"manuals": list_cached_manuals()}


@app.get("/api/export")
def export_data():
    tools = get_all_tools()
    stats_data = get_statistics()
    export_payload = {
        "export_timestamp": time.time(),
        "total_tools": len(tools),
        "statistics": stats_data,
        "tools": tools,
        "usage_sessions": stats_data.get("recent_sessions", []),
        "lab_sessions": lab_list(50),
    }
    return JSONResponse(
        content=export_payload,
        headers={"Content-Disposition": "attachment; filename=cyberpulse_export.json"}
    )


# --- Health page ---
class DependencyCheck(BaseModel):
    name: str
    available: bool
    detail: str | None = None


def _check_dependency(module_name: str, detail: str = "") -> DependencyCheck:
    try:
        __import__(module_name)
        return DependencyCheck(name=module_name, available=True, detail=detail)
    except Exception as exc:
        return DependencyCheck(name=module_name, available=False, detail=str(exc))


@app.get("/api/health/detailed")
def health_detailed():
    """Detailed health for the Health page: collectors, DB size, deps, self-test."""
    cm = get_collector_manager()
    deps = [
        _check_dependency("fastapi", "web framework"),
        _check_dependency("uvicorn", "ASGI server"),
        _check_dependency("psutil", "process monitoring"),
        _check_dependency("yaml", "config parsing"),
    ]
    missing = [d.name for d in deps if not d.available]

    # Database size
    db_size = 0
    db_exists = os.path.exists(DB_PATH)
    if db_exists:
        try:
            db_size = os.path.getsize(DB_PATH)
        except OSError:
            db_size = 0

    # Self-test: can we read tools + settings?
    self_test = {"db_readable": False, "settings_readable": False}
    try:
        get_all_tools()
        self_test["db_readable"] = True
    except Exception:
        pass
    try:
        get_setting("theme", "dark")
        self_test["settings_readable"] = True
    except Exception:
        pass

    return {
        "status": "healthy" if not missing and self_test["db_readable"] else "degraded",
        "internet_connected": check_internet_connection(timeout=1.0),
        "collectors": cm.get_status(),
        "live_active": len(cm.get_live_status()),
        "database": {
            "path": DB_PATH,
            "exists": db_exists,
            "size_bytes": db_size,
        },
        "dependencies": [d.model_dump() for d in deps],
        "missing_dependencies": missing,
        "ai": {
            "enabled": ai_enabled(),
            "redact_before_send": ai_redact(),
        },
        "self_test": self_test,
        "retention": {
            "usage_sessions_days": int(get_retention("usage_sessions_days", "0") or 0),
            "scenario_history_days": int(get_retention("scenario_history_days", "0") or 0),
        },
    }
