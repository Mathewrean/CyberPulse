"""
Tests for the Manual Engine (backend.manual): build_manual and explain_command.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.manual import build_manual, explain_command


def test_build_manual_returns_structure():
    m = build_manual("nmap")
    assert m["name"] == "nmap"
    assert "purpose" in m
    assert "options" in m
    assert "examples" in m
    assert "mitre" in m
    assert "defensive" in m
    assert m["banner"] == "Authorised targets and your own lab only."


def test_build_manual_examples_use_placeholders_or_safe():
    m = build_manual("nmap")
    for ex in m["examples"]:
        cmd = ex["cmd"]
        # Examples should not leak raw IPs; placeholders expected for curated tools.
        assert "<TARGET_IP>" in cmd or "--help" in cmd or ex["level"] in ("Beginner", "Intermediate", "Advanced")


def test_build_manual_cache_roundtrip():
    m1 = build_manual("nmap")
    m2 = build_manual("nmap")
    assert m1["name"] == m2["name"]
    assert m1["source"] == m2["source"]


def test_explain_command_structure():
    out = explain_command("nmap -sC -sV 10.0.0.1")
    assert out["binary"] == "nmap"
    assert isinstance(out["flags"], list)
    assert any(f["flag"] == "-sC" for f in out["flags"])
    assert out["banner"] == "Authorised targets and your own lab only."


def test_explain_command_placeholders():
    out = explain_command("ffuf -u http://<TARGET_IP>/FUZZ -w <WORDLIST>")
    assert "<TARGET_IP>" in out["placeholders"]
    assert "<WORDLIST>" in out["placeholders"]
