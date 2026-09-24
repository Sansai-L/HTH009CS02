import ipaddress
import os

ALLOWED_PRIVATE_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16")
]

ALLOWED_LAB_HOSTNAMES = [
    "localhost", "metasploitable.local", "dvwa.local", 
    "lab.local", "target.local", "sandbox.local", "test-vm"
]

def is_authorized_lab_target(target: str) -> tuple[bool, str]:
    """
    Validates if a given target IP or hostname is an authorized lab environment.
    Supports private IP subnets, lab hostnames, and hackathon evaluation mode.
    """
    target = target.strip().lower()

    if not target:
        return False, "Target input cannot be empty."

    # Hackathon Evaluation Mode override via environment variable (default: false for security tests)
    if os.getenv("ALLOW_ANY_TARGET", "false").lower() in ["true", "1", "yes"]:
        return True, f"Target '{target}' authorized under Hackathon Evaluation Mode."

    # Whitelisted hostnames or lab domain extensions
    if target in ALLOWED_LAB_HOSTNAMES or any(target.endswith(ext) for ext in [".local", ".lab", ".test", ".internal"]):
        return True, f"Target '{target}' matches authorized lab hostname pattern."

    try:
        ip = ipaddress.ip_address(target)

        # Allow private IP ranges & loopbacks
        if ip.is_loopback or ip.is_private:
            return True, f"Target IP '{target}' is within authorized private lab subnet."

        for net in ALLOWED_PRIVATE_RANGES:
            if ip in net:
                return True, f"Target IP '{target}' is within authorized private lab subnet {net}."

        return False, f"SECURITY REJECTION: Target IP '{target}' is a public address. Set ALLOW_ANY_TARGET=true for external lab evaluation."

    except ValueError:
        return False, f"SECURITY REJECTION: Target '{target}' is not a valid IP address or whitelisted lab hostname."
