"""
CyberPulse SQLite Database Layer
Handles database schema creation, tool storage, stats tracking, and settings.
"""

import sqlite3
import os
import json
from datetime import datetime
from typing import List, Dict, Any, Optional

from .config import get

DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    get("data_dir", default="data"),
    "cyberpulse.db",
)

def get_connection() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=30.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()
    
    # 1. Tools table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS tools (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        display_name TEXT NOT NULL,
        category TEXT NOT NULL,
        subcategory TEXT DEFAULT '',
        description TEXT NOT NULL,
        installed INTEGER DEFAULT 0,
        binary_path TEXT DEFAULT '',
        package_name TEXT DEFAULT '',
        version TEXT DEFAULT '',
        install_command TEXT DEFAULT '',
        install_source TEXT DEFAULT 'APT (System)',
        mitre_tactics TEXT DEFAULT '[]',
        mitre_techniques TEXT DEFAULT '[]',
        syntax_examples TEXT DEFAULT '[]',
        scenarios TEXT DEFAULT '[]',
        learning_refs TEXT DEFAULT '[]',
        checklist_status TEXT DEFAULT 'not_started',
        is_favorite INTEGER DEFAULT 0,
        user_notes TEXT DEFAULT '',
        last_scanned TEXT DEFAULT ''
    )
    """)

    # Safe migration: add install_source column if older DB schema exists
    cursor.execute("PRAGMA table_info(tools)")
    cols = [r["name"] for r in cursor.fetchall()]
    if "install_source" not in cols:
        cursor.execute("ALTER TABLE tools ADD COLUMN install_source TEXT DEFAULT 'APT (System)'")
    
    # 2. Tool runtime statistics
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS tool_stats (
        tool_name TEXT PRIMARY KEY,
        total_runs INTEGER DEFAULT 0,
        total_seconds REAL DEFAULT 0.0,
        last_run TEXT DEFAULT '',
        currently_running INTEGER DEFAULT 0,
        current_pid INTEGER DEFAULT 0,
        current_started_at TEXT DEFAULT ''
    )
    """)
    
    # 3. Individual execution sessions
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS usage_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tool_name TEXT NOT NULL,
        pid INTEGER NOT NULL,
        session_id TEXT DEFAULT '',
        start_time TEXT NOT NULL,
        end_time TEXT DEFAULT '',
        duration_seconds REAL DEFAULT 0.0,
        cmdline TEXT DEFAULT '',
        args_hash TEXT DEFAULT '',
        source_method TEXT DEFAULT 'polling',
        exit_code INTEGER DEFAULT 0,
        cpu_peak REAL DEFAULT 0.0,
        mem_peak REAL DEFAULT 0.0
    )
    """)

    # Safe migrations for pre-existing databases
    cursor.execute("PRAGMA table_info(usage_sessions)")
    _cols = {r["name"] for r in cursor.fetchall()}
    for _col, _def in [
        ("session_id", "TEXT DEFAULT ''"),
        ("args_hash", "TEXT DEFAULT ''"),
        ("source_method", "TEXT DEFAULT 'polling'"),
        ("exit_code", "INTEGER DEFAULT 0"),
        ("cpu_peak", "REAL DEFAULT 0.0"),
        ("mem_peak", "REAL DEFAULT 0.0"),
    ]:
        if _col not in _cols:
            cursor.execute(f"ALTER TABLE usage_sessions ADD COLUMN {_col} {_def}")

    # Index for dedup / lookups
    cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_usage_sessions_tool_time
    ON usage_sessions(tool_name, start_time)
    """)
    cursor.execute("""
    CREATE INDEX IF NOT EXISTS idx_usage_sessions_pid
    ON usage_sessions(pid)
    """)

    # 4. Manual lab sessions (Start/Stop lab session)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS lab_sessions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT UNIQUE NOT NULL,
        name TEXT DEFAULT '',
        target TEXT DEFAULT '',
        notes TEXT DEFAULT '',
        tools TEXT DEFAULT '[]',
        start_time TEXT NOT NULL,
        end_time TEXT DEFAULT '',
        status TEXT DEFAULT 'active'
    )
    """)
    
    # 4. Incident / Scenario Advisor history
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS scenario_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        query_text TEXT NOT NULL,
        detected_category TEXT DEFAULT '',
        recommended_tools TEXT DEFAULT '[]',
        playbook TEXT DEFAULT '{}',
        created_at TEXT NOT NULL
    )
    """)
    
    # 5. App settings (Spotify theme, API keys, scanner settings)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS app_settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """)

    # 6. Data retention policy
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS data_retention (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )
    """)
    retention_defaults = {
        "usage_sessions_days": "0",
        "scenario_history_days": "0",
    }
    for k, v in retention_defaults.items():
        cursor.execute("INSERT OR IGNORE INTO data_retention (key, value) VALUES (?, ?)", (k, v))
    
    # Set default settings if not exist
    defaults = {
        "theme": "dark",
        "monitor_interval_sec": "3",
        "ai_provider": "hybrid",  # hybrid: offline expert engine + online fallback if connected
        "gemini_api_key": "",
        "openai_api_key": "",
        "last_full_scan": "",
        "ai_enabled": "false",
        "ai_redact_before_send": "true",
    }
    for k, v in defaults.items():
        cursor.execute("INSERT OR IGNORE INTO app_settings (key, value) VALUES (?, ?)", (k, v))
        
    conn.commit()
    conn.close()

# Tool Queries
def upsert_tool(tool_data: Dict[str, Any]):
    conn = get_connection()
    cursor = conn.cursor()
    
    # Check if tool already exists to preserve user customization (notes, checklist_status, is_favorite)
    cursor.execute("SELECT checklist_status, is_favorite, user_notes FROM tools WHERE name = ?", (tool_data["name"],))
    row = cursor.fetchone()
    
    checklist_status = row["checklist_status"] if row else tool_data.get("checklist_status", "not_started")
    is_favorite = row["is_favorite"] if row else tool_data.get("is_favorite", 0)
    user_notes = row["user_notes"] if row else tool_data.get("user_notes", "")
    
    cursor.execute("""
    INSERT INTO tools (
        name, display_name, category, subcategory, description, installed,
        binary_path, package_name, version, install_command, install_source, mitre_tactics,
        mitre_techniques, syntax_examples, scenarios, learning_refs,
        checklist_status, is_favorite, user_notes, last_scanned
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(name) DO UPDATE SET
        display_name=excluded.display_name,
        category=excluded.category,
        subcategory=excluded.subcategory,
        description=excluded.description,
        installed=excluded.installed,
        binary_path=excluded.binary_path,
        package_name=excluded.package_name,
        version=excluded.version,
        install_command=excluded.install_command,
        install_source=excluded.install_source,
        mitre_tactics=excluded.mitre_tactics,
        mitre_techniques=excluded.mitre_techniques,
        syntax_examples=excluded.syntax_examples,
        scenarios=excluded.scenarios,
        learning_refs=excluded.learning_refs,
        last_scanned=excluded.last_scanned
    """, (
        tool_data["name"],
        tool_data["display_name"],
        tool_data["category"],
        tool_data.get("subcategory", ""),
        tool_data["description"],
        1 if tool_data.get("installed", False) else 0,
        tool_data.get("binary_path", ""),
        tool_data.get("package_name", ""),
        tool_data.get("version", ""),
        tool_data.get("install_command", ""),
        tool_data.get("install_source", "APT (System)"),
        json.dumps(tool_data.get("mitre_tactics", [])),
        json.dumps(tool_data.get("mitre_techniques", [])),
        json.dumps(tool_data.get("syntax_examples", [])),
        json.dumps(tool_data.get("scenarios", [])),
        json.dumps(tool_data.get("learning_refs", [])),
        checklist_status,
        is_favorite,
        user_notes,
        datetime.utcnow().isoformat()
    ))
    conn.commit()
    conn.close()

def get_all_tools() -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    SELECT t.*, 
           COALESCE(s.total_runs, 0) as total_runs,
           COALESCE(s.total_seconds, 0.0) as total_seconds,
           COALESCE(s.last_run, '') as last_run,
           COALESCE(s.currently_running, 0) as currently_running,
           COALESCE(s.current_pid, 0) as current_pid
    FROM tools t
    LEFT JOIN tool_stats s ON t.name = s.tool_name
    ORDER BY t.installed DESC, t.name ASC
    """)
    rows = cursor.fetchall()
    tools = []
    for r in rows:
        d = dict(r)
        d["mitre_tactics"] = json.loads(d.get("mitre_tactics") or "[]")
        d["mitre_techniques"] = json.loads(d.get("mitre_techniques") or "[]")
        d["syntax_examples"] = json.loads(d.get("syntax_examples") or "[]")
        d["scenarios"] = json.loads(d.get("scenarios") or "[]")
        d["learning_refs"] = json.loads(d.get("learning_refs") or "[]")
        tools.append(d)
    conn.close()
    return tools

def update_tool_status(tool_name: str, status: Optional[str] = None, is_favorite: Optional[int] = None, notes: Optional[str] = None):
    conn = get_connection()
    cursor = conn.cursor()
    updates = []
    params = []
    if status is not None:
        updates.append("checklist_status = ?")
        params.append(status)
    if is_favorite is not None:
        updates.append("is_favorite = ?")
        params.append(is_favorite)
    if notes is not None:
        updates.append("user_notes = ?")
        params.append(notes)
        
    if updates:
        params.append(tool_name)
        sql = f"UPDATE tools SET {', '.join(updates)} WHERE name = ?"
        cursor.execute(sql, tuple(params))
        conn.commit()
    conn.close()

def record_process_start(tool_name: str, pid: int, cmdline: str,
                         session_id: str = "", source_method: str = "polling",
                         args_hash: str = ""):
    conn = get_connection()
    cursor = conn.cursor()
    now_iso = datetime.now().isoformat()

    # 1. Update or create tool_stats
    cursor.execute("""
    INSERT INTO tool_stats (tool_name, total_runs, total_seconds, last_run, currently_running, current_pid, current_started_at)
    VALUES (?, 1, 0.0, ?, 1, ?, ?)
    ON CONFLICT(tool_name) DO UPDATE SET
        total_runs = total_runs + 1,
        last_run = excluded.last_run,
        currently_running = 1,
        current_pid = excluded.current_pid,
        current_started_at = excluded.current_started_at
    """, (tool_name, now_iso, pid, now_iso))

    # 2. Insert into usage_sessions
    cursor.execute("""
    INSERT INTO usage_sessions (tool_name, pid, session_id, start_time, cmdline, args_hash, source_method)
    VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (tool_name, pid, session_id, now_iso, cmdline, args_hash, source_method))

    conn.commit()
    conn.close()

def record_process_stop(tool_name: str, pid: int, duration_sec: float,
                        exit_code: int = 0, cpu_peak: float = 0.0, mem_peak: float = 0.0):
    conn = get_connection()
    cursor = conn.cursor()
    now_iso = datetime.now().isoformat()

    # Update tool_stats
    cursor.execute("""
    UPDATE tool_stats
    SET total_seconds = total_seconds + ?,
        currently_running = 0,
        current_pid = 0,
        current_started_at = ''
    WHERE tool_name = ?
    """, (duration_sec, tool_name))

    # Update latest open session for this pid/tool
    cursor.execute("""
    UPDATE usage_sessions
    SET end_time = ?, duration_seconds = ?, exit_code = ?, cpu_peak = ?, mem_peak = ?
    WHERE tool_name = ? AND pid = ? AND end_time = ''
    """, (now_iso, duration_sec, exit_code, cpu_peak, mem_peak, tool_name, pid))

    conn.commit()
    conn.close()


def record_usage_event(tool_name: str, pid: int, start_time: str, end_time: str,
                       duration_seconds: float, cmdline: str, args_hash: str,
                       source_method: str, exit_code: int = 0,
                       cpu_peak: float = 0.0, mem_peak: float = 0.0,
                       session_id: str = "") -> int:
    """Insert a complete usage event from any collector plugin. Returns row id."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO usage_sessions
        (tool_name, pid, session_id, start_time, end_time, duration_seconds,
         cmdline, args_hash, source_method, exit_code, cpu_peak, mem_peak)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (tool_name, pid, session_id, start_time, end_time, duration_seconds,
          cmdline, args_hash, source_method, exit_code, cpu_peak, mem_peak))
    # Update tool_stats aggregates
    cursor.execute("""
    INSERT INTO tool_stats (tool_name, total_runs, total_seconds, last_run, currently_running, current_pid, current_started_at)
    VALUES (?, 1, ?, ?, 0, 0, '')
    ON CONFLICT(tool_name) DO UPDATE SET
        total_runs = total_runs + 1,
        total_seconds = total_seconds + excluded.total_seconds,
        last_run = excluded.last_run
    """, (tool_name, duration_seconds, end_time))
    row_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return row_id

def get_statistics():
    conn = get_connection()
    cursor = conn.cursor()
    
    # Total tools, installed tools, checklist status counts
    cursor.execute("SELECT COUNT(*) FROM tools")
    total_tools = cursor.fetchone()[0]
    
    cursor.execute("SELECT COUNT(*) FROM tools WHERE installed = 1")
    installed_tools = cursor.fetchone()[0]
    
    cursor.execute("SELECT checklist_status, COUNT(*) FROM tools GROUP BY checklist_status")
    status_counts = dict(cursor.fetchall())
    
    cursor.execute("SELECT category, COUNT(*), SUM(installed) FROM tools GROUP BY category")
    cat_rows = cursor.fetchall()
    categories = [
        {"category": r[0], "total": r[1], "installed": r[2] or 0}
        for r in cat_rows
    ]

    cursor.execute("SELECT install_source, COUNT(*), SUM(installed) FROM tools GROUP BY install_source")
    source_rows = cursor.fetchall()
    install_sources = [
        {"source": r[0] or "APT (System)", "total": r[1], "installed": r[2] or 0}
        for r in source_rows
    ]
    
    # Usage stats: Top 10 most used tools by total time
    cursor.execute("""
    SELECT s.tool_name, t.display_name, t.category, s.total_runs, s.total_seconds, s.last_run, s.currently_running
    FROM tool_stats s
    LEFT JOIN tools t ON s.tool_name = t.name
    WHERE s.total_runs > 0 OR s.total_seconds > 0
    ORDER BY s.total_seconds DESC, s.total_runs DESC
    LIMIT 15
    """)
    top_tools = [dict(r) for r in cursor.fetchall()]
    
    # Active currently running tools
    cursor.execute("""
    SELECT s.tool_name, t.display_name, t.category, s.current_pid, s.current_started_at
    FROM tool_stats s
    LEFT JOIN tools t ON s.tool_name = t.name
    WHERE s.currently_running = 1
    """)
    active_tools = [dict(r) for r in cursor.fetchall()]
    
    # Total cumulative time across all tools
    cursor.execute("SELECT COALESCE(SUM(total_seconds), 0.0), COALESCE(SUM(total_runs), 0) FROM tool_stats")
    agg = cursor.fetchone()
    total_time_seconds = agg[0]
    total_executions = agg[1]
    
    # Recent sessions
    cursor.execute("""
    SELECT id, tool_name, pid, start_time, end_time, duration_seconds, cmdline
    FROM usage_sessions
    ORDER BY id DESC
    LIMIT 20
    """)
    recent_sessions = [dict(r) for r in cursor.fetchall()]
    
    conn.close()
    return {
        "total_tools": total_tools,
        "installed_tools": installed_tools,
        "missing_tools": total_tools - installed_tools,
        "status_counts": status_counts,
        "categories": categories,
        "install_sources": install_sources,
        "top_tools": top_tools,
        "active_tools": active_tools,
        "total_time_seconds": total_time_seconds,
        "total_executions": total_executions,
        "recent_sessions": recent_sessions
    }

def get_setting(key: str, default: str = "") -> str:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM app_settings WHERE key = ?", (key,))
    row = cursor.fetchone()
    conn.close()
    return row["value"] if row else default

def set_setting(key: str, value: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO app_settings (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()


def get_retention(key: str, default: str = "0") -> str:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM data_retention WHERE key = ?", (key,))
    row = cursor.fetchone()
    conn.close()
    return row["value"] if row else default


def set_retention(key: str, value: str):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO data_retention (key, value) VALUES (?, ?)", (key, value))
    conn.commit()
    conn.close()


def cleanup_retention() -> Dict[str, int]:
    """Delete usage_sessions and scenario_history rows older than retention days.
    Returns counts of deleted rows per table. 0 days = keep forever."""
    from datetime import datetime, timedelta
    conn = get_connection()
    cursor = conn.cursor()
    deleted: Dict[str, int] = {}
    now = datetime.utcnow()

    usage_days = int(get_retention("usage_sessions_days", "0") or 0)
    if usage_days > 0:
        cutoff = (now - timedelta(days=usage_days)).isoformat()
        cursor.execute("DELETE FROM usage_sessions WHERE start_time < ?", (cutoff,))
        deleted["usage_sessions"] = cursor.rowcount

    scenario_days = int(get_retention("scenario_history_days", "0") or 0)
    if scenario_days > 0:
        cutoff = (now - timedelta(days=scenario_days)).isoformat()
        cursor.execute("DELETE FROM scenario_history WHERE created_at < ?", (cutoff,))
        deleted["scenario_history"] = cursor.rowcount

    conn.commit()
    conn.close()
    return deleted


def wipe_all_data() -> Dict[str, int]:
    """One-click wipe of all usage and scenario data (keeps tool catalogue)."""
    conn = get_connection()
    cursor = conn.cursor()
    counts: Dict[str, int] = {}
    for table in ("usage_sessions", "tool_stats", "scenario_history"):
        cursor.execute(f"SELECT COUNT(*) FROM {table}")
        counts[table] = cursor.fetchone()[0]
        cursor.execute(f"DELETE FROM {table}")
    conn.commit()
    conn.close()
    return counts

def save_scenario_query(query: str, category: str, tools: List[str], playbook: Dict[str, Any]):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT INTO scenario_history (query_text, detected_category, recommended_tools, playbook, created_at)
    VALUES (?, ?, ?, ?, ?)
    """, (query, category, json.dumps(tools), json.dumps(playbook), datetime.now().isoformat()))
    conn.commit()
    conn.close()

def get_scenario_history(limit: int = 10) -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scenario_history ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    res = []
    for r in rows:
        d = dict(r)
        d["recommended_tools"] = json.loads(d.get("recommended_tools") or "[]")
        d["playbook"] = json.loads(d.get("playbook") or "{}")
        res.append(d)
    conn.close()
    return res


# --- Manual lab session helpers ---
def start_lab_session(session_id: str, name: str = "", target: str = "", notes: str = "", tools: List[str] = None) -> None:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT OR REPLACE INTO lab_sessions (session_id, name, target, notes, tools, start_time, status)
    VALUES (?, ?, ?, ?, ?, ?, 'active')
    """, (session_id, name, target, notes, json.dumps(tools or []), datetime.now().isoformat()))
    conn.commit()
    conn.close()

def stop_lab_session(session_id: str) -> None:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
    UPDATE lab_sessions SET end_time = ?, status = 'completed' WHERE session_id = ? AND status = 'active'
    """, (datetime.now().isoformat(), session_id))
    conn.commit()
    conn.close()

def get_lab_sessions(limit: int = 20) -> List[Dict[str, Any]]:
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM lab_sessions ORDER BY start_time DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    res = []
    for r in rows:
        d = dict(r)
        d["tools"] = json.loads(d.get("tools") or "[]")
        res.append(d)
    conn.close()
    return res
