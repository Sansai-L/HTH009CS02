import pytest
from app.guardrail.validator import is_authorized_lab_target

def test_authorized_private_ips():
    allowed_ips = ["127.0.0.1", "192.168.1.100", "10.0.0.5", "172.16.0.1", "localhost"]
    for ip in allowed_ips:
        is_auth, msg = is_authorized_lab_target(ip)
        assert is_auth is True
        assert "authorized" in msg.lower() or "whitelisted" in msg.lower()

def test_unauthorized_public_ips():
    rejected_ips = ["8.8.8.8", "1.1.1.1", "142.250.190.46", "google.com", "example.com"]
    for ip in rejected_ips:
        is_auth, msg = is_authorized_lab_target(ip)
        assert is_auth is False
        assert "SECURITY REJECTION" in msg
