import ipaddress

ALLOWED_PRIVATE_RANGES = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16")
]

ALLOWED_LAB_HOSTNAMES = ["localhost", "metasploitable.local", "dvwa.local", "lab.local"]

def is_authorized_lab_target(target: str) -> tuple[bool, str]:
    """
    Validates if a given target is an authorized lab environment.
    Strictly forbids scanning public or non-private IP addresses.
    """
    target = target.strip().lower()
    
    if target in ALLOWED_LAB_HOSTNAMES:
        return True, f"Target '{target}' matches authorized lab hostname whitelist."
        
    try:
        ip = ipaddress.ip_address(target)
        for net in ALLOWED_PRIVATE_RANGES:
            if ip in net:
                return True, f"Target IP '{target}' is within authorized private lab subnet {net}."
        return False, f"SECURITY REJECTION: Target IP '{target}' is a public address or outside authorized lab ranges."
    except ValueError:
        return False, f"SECURITY REJECTION: Target '{target}' is not a valid IP address or whitelisted lab hostname."
