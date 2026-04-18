"""
Shared helper functions for IDS pipeline (reusable across all steps).
Includes network topology definitions, mapping utilities, and validation functions.
"""

import hashlib
import random

# ============================================================
# NETWORK TOPOLOGY DEFINITIONS (Shared across all steps)
# ============================================================

# IP ranges mapped to internal topology
IP_RANGES = {
    '192.168.1': ['User0', 'User1', 'User2', 'User3', 'User4'],
    '192.168.2': ['Enterprise0', 'Enterprise1', 'Enterprise2', 'Defender'],
    '192.168.3': ['OpHost0', 'OpHost1', 'OpHost2', 'OpServer0'],
    '10.0.3': ['OpHost0', 'OpHost1', 'OpHost2', 'OpServer0'],
}

# Hostname prefix to subnet mapping
SUBNET_MAPPING = {
    'User': 'Subnet 1 (User)',
    'Enterprise': 'Subnet 2 (Enterprise)',
    'Defender': 'Subnet 2 (Enterprise)',  # Defender is part of Enterprise subnet
    'OpHost': 'Subnet 3 (Operational)',
    'OpServer': 'Subnet 3 (Operational)',
}

# Destination port to service mapping
PORT_TO_SERVICE_MAP = {
    21: 'ftp',
    20: 'ftp-data',
    22: 'ssh',
    25: 'smtp',
    53: 'dns',
    67: 'dhcp',
    68: 'dhcp',
    80: 'http',
    110: 'pop3',
    143: 'imap',
    161: 'snmp',
    194: 'irc',
    388: 'radius',
    443: 'ssl',
    445: 'smb',
    3389: 'rdp',
}

# Reverse: service to typical port (for inference/validation)
SERVICE_TO_PORT_MAP = {v: k for k, v in PORT_TO_SERVICE_MAP.items()}


# ============================================================
# STEP 1: IP → SUBNET INFERENCE
# ============================================================

def map_subnet(host):
    """
    Infer subnet from hostname prefix.
    
    Args:
        host (str): Hostname (e.g., 'User1', 'Enterprise0', 'external_45')
    
    Returns:
        str: Subnet name or 'External' for external hosts
        
    Raises:
        ValueError: If hostname is invalid
    """
    if host.startswith('external_'):
        return 'External'
    
    for prefix, subnet in SUBNET_MAPPING.items():
        if host.startswith(prefix):
            return subnet
    
    raise ValueError(f"Invalid hostname: {host}. Must match topology or be external_*")


# ============================================================
# STEP 2: IP → HOST DETERMINISTIC MAPPING (Scenario-specific)
# ============================================================

def map_ip_to_host(ip_address, scenario_name):
    """
    Deterministically map IP to hostname using MD5(scenario + IP) hash.
    
    This ensures the same IP always maps to the same hostname within a scenario,
    but different scenarios may map the same IP to different hosts (due to
    scenario-specific context). External IPs are handled separately.
    
    Args:
        ip_address (str): IP address (e.g., '192.168.1.50')
        scenario_name (str): Scenario name for deterministic separation
        
    Returns:
        tuple: (hostname, subnet) or raises ValueError if invalid
        
    Raises:
        ValueError: If IP cannot be mapped to any known range
    """
    # External IP: extract last octet as identifier
    if not any(ip_address.startswith(pre) for pre in IP_RANGES.keys()):
        last_octet = ip_address.split('.')[-1]
        external_host = f"external_{last_octet}"
        return external_host, "External"
    
    # Internal IP: find matching prefix
    host_pool = None
    for prefix, hosts in IP_RANGES.items():
        if ip_address.startswith(prefix):
            host_pool = hosts
            break
    
    if not host_pool:
        raise ValueError(f"IP {ip_address} does not match any known range. "
                        f"Known ranges: {list(IP_RANGES.keys())}")
    
    # Deterministic selection via hash
    hash_seed = f"{scenario_name}:{ip_address}"
    hash_value = int(hashlib.md5(hash_seed.encode()).hexdigest(), 16)
    host_idx = hash_value % len(host_pool)
    host = host_pool[host_idx]
    subnet = map_subnet(host)
    
    return host, subnet


# ============================================================
# STEP 3: PORT → SERVICE INFERENCE
# ============================================================

def infer_service_from_port(dport):
    """
    Map destination port to service name.
    
    Args:
        dport (int): Destination port
        
    Returns:
        str: Service name ('ftp', 'ssh', 'http', etc.) or '-' if unknown
    """
    try:
        port_int = int(dport)
    except (ValueError, TypeError):
        return '-'
    
    return PORT_TO_SERVICE_MAP.get(port_int, '-')


def infer_dport_from_service(service):
    """
    Map service name to typical destination port (for consistency checks).
    
    Args:
        service (str): Service name
        
    Returns:
        int: Port number or None if unknown
    """
    return SERVICE_TO_PORT_MAP.get(service, None)


# ============================================================
# STEP 4: EPHEMERAL PORT GENERATION
# ============================================================

def generate_ephemeral_port(seed=None):
    """
    Generate a random ephemeral port (1024-65535).
    
    Args:
        seed (int, optional): Seed for determinism (unused here; for future use)
        
    Returns:
        int: Ephemeral port
    """
    return random.randint(1024, 65535)


# ============================================================
# VALIDATION UTILITIES
# ============================================================

def validate_host(host):
    """
    Check if hostname is valid (belongs to defined topology).
    
    Args:
        host (str): Hostname to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    if host.startswith('external_'):
        return True
    
    # Check against any known prefix
    for prefix in SUBNET_MAPPING.keys():
        if host.startswith(prefix):
            return True
    
    return False


def validate_subnet(subnet):
    """
    Check if subnet name is valid.
    
    Args:
        subnet (str): Subnet name
        
    Returns:
        bool: True if valid, False otherwise
    """
    valid_subnets = list(SUBNET_MAPPING.values()) + ['External']
    return subnet in valid_subnets


def validate_service(service):
    """
    Check if service name is valid (from UNSW dataset).
    
    Args:
        service (str): Service name
        
    Returns:
        bool: True if valid, False otherwise
    """
    # Accept all services from UNSW dataset, including unknown ('-')
    valid_services = list(PORT_TO_SERVICE_MAP.values()) + ['-']  
    return service in valid_services


def validate_attack_cat(attack_cat):
    """
    Check if attack category is valid.
    
    Args:
        attack_cat (str): Attack category from UNSW
        
    Returns:
        bool: True if valid, False otherwise
    """
    # UNSW-NB15 dataset contains these 10 categories
    valid_cats = ['Analysis', 'Backdoor', 'DoS', 'Exploits', 'Fuzzers', 
                  'Generic', 'Normal', 'Reconnaissance', 'Shellcode', 'Worms']
    return attack_cat in valid_cats


# ============================================================
# SCENARIOS DEFINITION (Shared across pipeline)
# ============================================================

SCENARIOS = ['WannaCry', 'Data_Theft', 'ShellShock', 'Netcat_Backdoor', 'passwd_gzip_scp']
