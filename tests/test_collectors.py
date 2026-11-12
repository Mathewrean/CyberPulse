"""
Tests for the layered collectors (backend.collectors): hashing, tool name resolution,
and cross-plugin de-duplication.
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import backend.collectors as C
from backend.collectors import CollectorManager


def test_hash_args_deterministic():
    h1 = C._hash_args("nmap -sV 10.0.0.1")
    h2 = C._hash_args("nmap -sV 10.0.0.1")
    assert h1 == h2
    assert len(h1) == 16
    assert C._hash_args("different command") != h1


def test_resolve_tool_name_known():
    # nmap appears in knowledge_base curated tools
    assert C._resolve_tool_name("nmap -sV 10.0.0.1", "nmap") == "nmap"
    assert C._resolve_tool_name("", "msfconsole") == "metasploit"
    assert C._resolve_tool_name("", "tshark") == "wireshark"


def test_resolve_tool_name_unknown():
    assert C._resolve_tool_name("some_random_binary --flag", "some_random_binary") is None


def test_dedup_within_window():
    cm = CollectorManager()
    captured = []

    def fake_record(*args, **kwargs):
        captured.append(kwargs.get("tool_name"))

    import backend.collectors as CM
    orig = CM.record_usage_event
    CM.record_usage_event = fake_record
    try:
        now = time.time()
        events = [
            {"tool_name": "nmap", "pid": 123, "start_time": now, "end_time": now + 1,
             "duration_seconds": 1.0, "cmdline": "nmap -sV 10.0.0.1", "source_method": "polling"},
            {"tool_name": "nmap", "pid": 123, "start_time": now, "end_time": now + 1,
             "duration_seconds": 1.0, "cmdline": "nmap -sV 10.0.0.1", "source_method": "shell_hook"},
            {"tool_name": "nmap", "pid": 124, "start_time": now + 10, "end_time": now + 11,
             "duration_seconds": 1.0, "cmdline": "nmap -sV 10.0.0.2", "source_method": "polling"},
        ]
        cm._ingest(events)
    finally:
        CM.record_usage_event = orig

    # Two events share (tool, pid, start_time) -> deduped to one; third is distinct -> 2 total
    assert len(captured) == 2, f"expected 2, got {len(captured)}: {captured}"


def test_collector_status_shape():
    cm = CollectorManager()
    statuses = cm.get_status()
    names = {s["name"] for s in statuses}
    assert {"polling", "shell_hook", "wrapper", "auditd", "desktop"} <= names
    for s in statuses:
        assert "name" in s and "enabled" in s
        assert "available" in s or "active" in s
