"""
Tests for database retention, wipe, and lab-session helpers using a temp DB.
"""

import os
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import backend.database as D


def setup_temp_db(monkeypatch):
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    os.unlink(tmp.name)
    monkeypatch.setattr(D, "DB_PATH", tmp.name)
    D.init_db()
    return tmp.name


def test_retention_get_set(monkeypatch):
    setup_temp_db(monkeypatch)
    D.set_retention("usage_sessions_days", "30")
    assert D.get_retention("usage_sessions_days", "0") == "30"
    assert D.get_retention("scenario_history_days", "0") == "0"


def test_wipe_all_data(monkeypatch):
    setup_temp_db(monkeypatch)
    # Insert a usage event and scenario
    from datetime import datetime
    D.record_usage_event("nmap", 1, datetime.utcnow().isoformat(), datetime.utcnow().isoformat(),
                         1.0, "nmap -sV 10.0.0.1", "abc", "polling", 0)
    D.save_scenario_query("test query", "cat", ["nmap"], {})
    counts = D.wipe_all_data()
    assert counts["usage_sessions"] == 1
    assert counts["scenario_history"] == 1


def test_lab_sessions(monkeypatch):
    setup_temp_db(monkeypatch)
    D.start_lab_session("lab-1", "Wireless Lab", "10.0.0.0/24", "notes", ["aircrack-ng"])
    sessions = D.get_lab_sessions()
    assert len(sessions) == 1
    assert sessions[0]["session_id"] == "lab-1"
    assert sessions[0]["status"] == "active"
    D.stop_lab_session("lab-1")
    sessions = D.get_lab_sessions()
    assert sessions[0]["status"] == "completed"
