"""
Tests for the online-AI redaction step (advisor.redact_text).
Ensures sensitive identifiers never leave the machine.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.advisor import preview_outbound, redact_text


def test_redact_ips():
    text = "Target at 192.168.1.100 and 10.0.0.5 are in scope."
    redacted, counts = redact_text(text)
    assert "192.168.1.100" not in redacted
    assert "10.0.0.5" not in redacted
    assert counts.get("ip", 0) == 2


def test_redact_cidr():
    text = "Subnet 192.168.0.0/16 is affected."
    redacted, counts = redact_text(text)
    assert "192.168.0.0/16" not in redacted
    assert counts.get("cidr", 0) == 1


def test_redact_hashes():
    text = "Hashes: d41d8cd98f00b204e9800998ecf8427e and 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8."
    redacted, counts = redact_text(text)
    assert "d41d8cd98f00b204e9800998ecf8427e" not in redacted
    assert "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8" not in redacted
    assert counts.get("hash", 0) >= 2


def test_redact_emails():
    text = "Contact admin@example.com and root@internal.host."
    redacted, counts = redact_text(text)
    assert "admin@example.com" not in redacted
    assert "root@internal.host" not in redacted
    assert counts.get("email", 0) >= 1


def test_redact_macs():
    text = "MAC 00:1A:2B:3C:4D:5E seen."
    redacted, counts = redact_text(text)
    assert "00:1A:2B:3C:4D:5E" not in redacted
    assert counts.get("mac", 0) == 1


def test_preview_includes_counts():
    text = "IP 8.8.8.8 and hash d41d8cd98f00b204e9800998ecf8427e."
    prev = preview_outbound(text, redact=True)
    assert prev["redacted"] is True
    assert prev["will_leave_machine"] is True
    assert "redaction_counts" in prev
    assert prev["redaction_counts"].get("ip", 0) == 1


def test_no_redact_shows_raw():
    text = "IP 8.8.8.8."
    prev = preview_outbound(text, redact=False)
    assert prev["redacted"] is False
    assert "8.8.8.8" in prev.get("raw_preview", "")
