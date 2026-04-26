"""
Shared helper functions for IDS pipeline (reusable across all steps).
Includes network topology definitions, mapping utilities, and validation functions.
"""

import hashlib
import random

# ============================================================
# NETWORK TOPOLOGY DEFINITIONS (Shared across all steps)
# ============================================================

# IP ranges mapped to internal topology (from network_topology_output.json)
IP_RANGES = {
    '10.0.1': ['User0', 'User1', 'User2', 'User3', 'User4'],        # Subnet 1 (User)
    '10.0.2': ['Enterprise0', 'Enterprise1', 'Enterprise2', 'Defender'],  # Subnet 2 (Enterprise)
    '10.0.3': ['OpHost0', 'OpHost1', 'OpHost2', 'OpServer0'],       # Subnet 3 (Operational)
}

# Fixed IP addresses per topology specification
FIXED_HOST_IPS = {
    'User0': '10.0.1.10',
    'User1': '10.0.1.11',
    'User2': '10.0.1.12',
    'User3': '10.0.1.13',
    'User4': '10.0.1.14',
    'Enterprise0': '10.0.2.10',
    'Enterprise1': '10.0.2.11',
    'Enterprise2': '10.0.2.12',
    'Defender': '10.0.2.20',
    'OpHost0': '10.0.3.10',
    'OpHost1': '10.0.3.11',
    'OpHost2': '10.0.3.12',
    'OpServer0': '10.0.3.20',
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
# NETWORK ROUTING CONSTRAINTS (from global_constraints.json)
# ============================================================

def validate_malicious_event_hosts(src_host, dst_host, scenario_name):
    """
    Validate that malicious event follows allowed routing paths for a scenario.
    
    Constraints (from global_constraints.json):
      - Rule 1: User1 is ONLY designated entry point from Subnet 1 to Subnet 2
      - Rule 2: Enterprise2 is ONLY designated gateway from Subnet 2 to Subnet 3
      - Rule 3: No direct Subnet 1 ↔ Subnet 3 connections
    
    Args:
        src_host (str): Source hostname
        dst_host (str): Destination hostname
        scenario_name (str): Scenario name (for context)
    
    Returns:
        bool: True if valid path, False if violates constraints
    """
    # Get subnets
    try:
        src_subnet = map_subnet(src_host)
        dst_subnet = map_subnet(dst_host)
    except ValueError:
        return False
    
    # Same subnet is always allowed
    if src_subnet == dst_subnet:
        return True
    
    # User (Subnet 1) to Enterprise (Subnet 2): ONLY via User1
    if 'User' in src_subnet and 'Enterprise' in dst_subnet:
        return src_host == 'User1'  # Only User1 can cross to Enterprise
    
    # Enterprise (Subnet 2) to Operational (Subnet 3): ONLY via Enterprise2
    if 'Enterprise' in src_subnet and 'Operational' in dst_subnet:
        return src_host == 'Enterprise2'  # Only Enterprise2 can cross to Operational
    
    # No direct User (Subnet 1) to Operational (Subnet 3)
    if 'User' in src_subnet and 'Operational' in dst_subnet:
        return False  # Must route through Enterprise2
    
    # No direct Operational (Subnet 3) to User (Subnet 1)
    if 'Operational' in src_subnet and 'User' in dst_subnet:
        return False  # Must route through Enterprise2
    
    # Operational to Enterprise is allowed (responses)
    if 'Operational' in src_subnet and 'Enterprise' in dst_subnet:
        return True  # Can return to any Enterprise (response traffic)
    
    # Enterprise to User is allowed (responses)
    if 'Enterprise' in src_subnet and 'User' in dst_subnet:
        return True  # Can return to User (response traffic)
    
    return True  # Default: allow if not explicitly restricted


def get_allowed_routing_destinations(src_host, src_subnet):
    """
    Get list of allowed destination subnets and hosts for a given source.
    
    Args:
        src_host (str): Source hostname
        src_subnet (str): Source subnet name
    
    Returns:
        dict: {'allowed_subnets': [...], 'allowed_hosts': [...]}
    """
    allowed_hosts = []
    allowed_subnets = set()
    
    # All internal traffic stays within subnet
    if src_subnet == 'Subnet 1 (User)':
        allowed_subnets.add('Subnet 1 (User)')
        allowed_hosts = ['User0', 'User1', 'User2', 'User3', 'User4']
        
        # Only User1 can cross to Enterprise
        if src_host == 'User1':
            allowed_subnets.add('Subnet 2 (Enterprise)')
            allowed_hosts.extend(['Enterprise0', 'Enterprise1', 'Enterprise2'])
    
    elif src_subnet == 'Subnet 2 (Enterprise)':
        allowed_subnets.add('Subnet 2 (Enterprise)')
        allowed_hosts = ['Enterprise0', 'Enterprise1', 'Enterprise2']
        
        # Only Enterprise2 can cross to Operational
        if src_host == 'Enterprise2':
            allowed_subnets.add('Subnet 3 (Operational)')
            allowed_hosts.extend(['OpHost0', 'OpHost1', 'OpHost2', 'OpServer0'])
        
        # All Enterprise can respond to User
        allowed_subnets.add('Subnet 1 (User)')
        allowed_hosts.extend(['User0', 'User1', 'User2', 'User3', 'User4'])
    
    elif src_subnet == 'Subnet 3 (Operational)':
        allowed_subnets.add('Subnet 3 (Operational)')
        allowed_hosts = ['OpHost0', 'OpHost1', 'OpHost2', 'OpServer0']
        
        # All Operational can respond to Enterprise
        allowed_subnets.add('Subnet 2 (Enterprise)')
        allowed_hosts.extend(['Enterprise0', 'Enterprise1', 'Enterprise2'])
    
    return {
        'allowed_subnets': list(allowed_subnets),
        'allowed_hosts': list(set(allowed_hosts)),
    }


def is_defender(hostname):
    """
    Check if hostname is Defender (special monitoring system).
    Defender should NOT be randomly selected as regular destination.
    
    Args:
        hostname (str): Hostname to check
    
    Returns:
        bool: True if Defender, False otherwise
    """
    return hostname == 'Defender'


def get_random_internal_host_excluding_defender(allowed_prefixes):
    """
    Return a random internal hostname from allowed prefixes, EXCLUDING Defender.
    
    Args:
        allowed_prefixes (list): List of hostname prefixes (e.g., ['User', 'Enterprise'])
    
    Returns:
        str: Hostname (e.g., 'User1', 'Enterprise0') or None if no valid hosts
    """
    prefix = random.choice(allowed_prefixes)
    
    # Get all hosts under this prefix
    for ip_prefix, hosts in IP_RANGES.items():
        matching_hosts = [h for h in hosts if h.startswith(prefix) and h != 'Defender']
        if matching_hosts:
            return random.choice(matching_hosts)
    
    # Fallback
    return f"{prefix}0" if prefix != 'Defender' else None


def get_deterministic_ip_for_host(scenario_name, hostname, network_topology=None):
    """
    Return deterministic IP address for a hostname within a scenario.
    Uses concrete IPs from network_topology_output.json, or generates deterministic external IP.
    
    Priority:
      1. network_topology parameter (concrete IPs from AWS infrastructure)
      2. FIXED_HOST_IPS fallback (hardcoded mapping)
      3. Deterministic hash for external_* hosts
    
    Args:
        scenario_name (str): Scenario name
        hostname (str): Hostname (e.g., 'User1', 'Enterprise0', 'external_45')
        network_topology (dict, optional): Loaded network_topology_output.json for concrete IPs
    
    Returns:
        str: IP address
    """
    # PRIORITY 1: Use concrete IP from network_topology if available
    if network_topology is not None:
        try:
            return get_concrete_ip_for_host(hostname, network_topology)
        except ValueError:
            # Host not found in topology; fall through to fallback
            pass
    
    # PRIORITY 2: Check if internal host with fixed IP (fallback for when network_topology not provided)
    if hostname in FIXED_HOST_IPS:
        return FIXED_HOST_IPS[hostname]
    
    # PRIORITY 3: External IPs - generate deterministically from hostname hash
    if hostname.startswith('external_'):
        hash_seed = f"{scenario_name}:{hostname}"
        hash_value = int(hashlib.md5(hash_seed.encode()).hexdigest(), 16)
        octet3 = (hash_value % 256)
        octet4 = ((hash_value >> 8) % 254) + 1
        return f"203.0.{octet3}.{octet4}"
    
    # Final fallback (should not reach here if hostname is valid)
    return "10.0.1.1"


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
    Deterministically map IP to hostname using fixed topology or MD5 hash.
    
    This ensures the same IP always maps to the same hostname within a scenario.
    Uses fixed IPs from FIXED_HOST_IPS for known hosts, or hash for others.
    
    Args:
        ip_address (str): IP address (e.g., '10.0.1.11')
        scenario_name (str): Scenario name for deterministic separation
        
    Returns:
        tuple: (hostname, subnet) or raises ValueError if invalid
        
    Raises:
        ValueError: If IP cannot be mapped to any known range
    """
    # Reverse lookup: check fixed IPs first
    for hostname, fixed_ip in FIXED_HOST_IPS.items():
        if ip_address == fixed_ip:
            subnet = map_subnet(hostname)
            return hostname, subnet
    
    # External IP: extract last octet as identifier
    if not any(ip_address.startswith(pre) for pre in IP_RANGES.keys()):
        last_octet = ip_address.split('.')[-1]
        external_host = f"external_{last_octet}"
        return external_host, "External"
    
    # Internal IP: find matching prefix (for dynamic IPs, should not normally occur)
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

SCENARIOS = ['WannaCry', 'Data_Theft', 'ShellShock', 'Netcat_Backdoor', 'passwd_gzip_scp', 'No_Attack']


# ============================================================
# STEP 1: TEMPLATE VALIDATION UTILITIES
# ============================================================

def validate_scenario_template(scenario_dict, scenario_index):
    """
    Validate that a single scenario template has all required fields with correct structure.
    
    Args:
        scenario_dict (dict): Single scenario from zero_day_templates.json
        scenario_index (int): Index of scenario (for error reporting)
        
    Returns:
        dict: Validation result with 'valid' (bool) and 'errors' (list of strings)
        
    Raises:
        None (returns errors instead)
    """
    errors = []
    
    # Required top-level fields
    required_fields = [
        'scenario_name',
        'attack_description',
        'entry_point',
        'target_asset',
        'key_attack_behaviors',
        'unsw_filtering',
        'feature_constraints',
        'temporal_architecture',
        'false_alarm_distribution',
        'expected_tier'
    ]
    
    for field in required_fields:
        if field not in scenario_dict:
            errors.append(f"  Scenario {scenario_index}: Missing required field '{field}'")
    
    # Get scenario name and malicious_count for conditional validation
    scenario_name = scenario_dict.get('scenario_name', 'Unknown')
    malicious_count = scenario_dict.get('malicious_count', 0)
    
    # Validate entry_point and target_asset structure (null allowed for No_Attack)
    if 'entry_point' in scenario_dict:
        entry = scenario_dict['entry_point']
        if entry is not None:  # Allow null for No_Attack scenario
            if not isinstance(entry, dict):
                errors.append(f"  Scenario {scenario_index}: 'entry_point' must be dict, got {type(entry)}")
            elif 'host' not in entry or 'subnet' not in entry:
                errors.append(f"  Scenario {scenario_index}: 'entry_point' missing 'host' or 'subnet'")
        elif malicious_count > 0:  # Null not allowed for attack scenarios
            errors.append(f"  Scenario {scenario_index}: 'entry_point' cannot be null for attack scenario")
    
    if 'target_asset' in scenario_dict:
        target = scenario_dict['target_asset']
        if target is not None:  # Allow null for No_Attack scenario
            if not isinstance(target, dict):
                errors.append(f"  Scenario {scenario_index}: 'target_asset' must be dict, got {type(target)}")
            elif 'host' not in target or 'subnet' not in target:
                errors.append(f"  Scenario {scenario_index}: 'target_asset' missing 'host' or 'subnet'")
        elif malicious_count > 0:  # Null not allowed for attack scenarios
            errors.append(f"  Scenario {scenario_index}: 'target_asset' cannot be null for attack scenario")
    
    # Validate key_attack_behaviors structure (null allowed for No_Attack)
    if 'key_attack_behaviors' in scenario_dict:
        behaviors = scenario_dict['key_attack_behaviors']
        if behaviors is not None:  # Allow null for No_Attack scenario
            if not isinstance(behaviors, dict):
                errors.append(f"  Scenario {scenario_index}: 'key_attack_behaviors' must be dict, got {type(behaviors)}")
            else:
                required_behaviors = ['initial_access', 'lateral_movement', 'payload_execution', 'data_exfiltration']
                for behavior in required_behaviors:
                    if behavior not in behaviors:
                        errors.append(f"  Scenario {scenario_index}: 'key_attack_behaviors' missing '{behavior}'")
        elif malicious_count > 0:  # Null not allowed for attack scenarios
            errors.append(f"  Scenario {scenario_index}: 'key_attack_behaviors' cannot be null for attack scenario")
    
    # Validate unsw_filtering structure
    if 'unsw_filtering' in scenario_dict:
        unsw = scenario_dict['unsw_filtering']
        if not isinstance(unsw, dict):
            errors.append(f"  Scenario {scenario_index}: 'unsw_filtering' must be dict, got {type(unsw)}")
        else:
            required_unsw = ['attack_cat', 'proto', 'dport', 'behavioral_cues']
            for field in required_unsw:
                if field not in unsw:
                    errors.append(f"  Scenario {scenario_index}: 'unsw_filtering' missing '{field}'")
    
    # Validate feature_constraints structure (may be empty for now)
    if 'feature_constraints' in scenario_dict:
        fc = scenario_dict['feature_constraints']
        if not isinstance(fc, dict):
            errors.append(f"  Scenario {scenario_index}: 'feature_constraints' must be dict, got {type(fc)}")
        else:
            required_fc = ['duration', 'bytes', 'packets', 'rate', 'dport']
            for field in required_fc:
                if field not in fc:
                    errors.append(f"  Scenario {scenario_index}: 'feature_constraints' missing '{field}'")
    
    # Validate temporal_architecture structure
    if 'temporal_architecture' in scenario_dict:
        ta = scenario_dict['temporal_architecture']
        if not isinstance(ta, dict):
            errors.append(f"  Scenario {scenario_index}: 'temporal_architecture' must be dict, got {type(ta)}")
        else:
            required_ta = ['total_duration', 'phases', 'false_alarm_zones']
            for field in required_ta:
                if field not in ta:
                    errors.append(f"  Scenario {scenario_index}: 'temporal_architecture' missing '{field}'")
            
            if 'total_duration' in ta and ta['total_duration'] != 1800:
                errors.append(f"  Scenario {scenario_index}: 'total_duration' should be 1800, got {ta['total_duration']}")
    
    # Validate false_alarm_distribution structure
    if 'false_alarm_distribution' in scenario_dict:
        fad = scenario_dict['false_alarm_distribution']
        if not isinstance(fad, dict):
            errors.append(f"  Scenario {scenario_index}: 'false_alarm_distribution' must be dict, got {type(fad)}")
        else:
            required_fad = ['type_1_unusual_port_benign_service', 'type_2_high_volume_low_risk', 'type_3_rare_duration_benign']
            for field in required_fad:
                if field not in fad:
                    errors.append(f"  Scenario {scenario_index}: 'false_alarm_distribution' missing '{field}'")
    
    # Validate scenario_name
    if 'scenario_name' in scenario_dict:
        name = scenario_dict['scenario_name']
        if name not in SCENARIOS:
            errors.append(f"  Scenario {scenario_index}: scenario_name '{name}' not in SCENARIOS list")
    
    return {
        'valid': len(errors) == 0,
        'errors': errors
    }


def validate_all_templates(templates_dict):
    """
    Validate entire zero_day_templates.json structure.
    
    Args:
        templates_dict (dict): Parsed zero_day_templates.json
        
    Returns:
        dict: Validation results with 'valid', 'total_scenarios', 'valid_scenarios', 'errors' (list)
    """
    errors = []
    
    # Check top-level structure
    if 'scenarios' not in templates_dict:
        errors.append("Top-level: Missing 'scenarios' key")
        return {
            'valid': False,
            'total_scenarios': 0,
            'valid_scenarios': 0,
            'errors': errors
        }
    
    if not isinstance(templates_dict['scenarios'], list):
        errors.append(f"'scenarios' must be list, got {type(templates_dict['scenarios'])}")
        return {
            'valid': False,
            'total_scenarios': 0,
            'valid_scenarios': 0,
            'errors': errors
        }
    
    scenarios = templates_dict['scenarios']
    total = len(scenarios)
    valid_count = 0
    
    # Expected number of scenarios
    expected_scenarios = len(SCENARIOS)
    if total != expected_scenarios:
        errors.append(f"Expected {expected_scenarios} scenarios, found {total}")
    
    # Validate each scenario
    for idx, scenario in enumerate(scenarios):
        result = validate_scenario_template(scenario, idx)
        if result['valid']:
            valid_count += 1
        else:
            errors.extend(result['errors'])
    
    return {
        'valid': len(errors) == 0,
        'total_scenarios': total,
        'valid_scenarios': valid_count,
        'errors': errors
    }


def load_templates(template_path):
    """
    Load zero_day_templates.json from file.
    
    Args:
        template_path (str): Path to zero_day_templates.json
        
    Returns:
        dict: Parsed JSON or raises FileNotFoundError
        
    Raises:
        FileNotFoundError: If template file not found
        json.JSONDecodeError: If JSON is malformed
    """
    import json
    from pathlib import Path
    
    path = Path(template_path)
    if not path.exists():
        raise FileNotFoundError(f"Template file not found: {template_path}")
    
    with open(path, 'r') as f:
        try:
            return json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Invalid JSON in {template_path}: {e}")


def save_templates(template_dict, template_path):
    """
    Save validated templates to zero_day_templates.json.
    
    Args:
        template_dict (dict): Template dictionary to save
        template_path (str): Path to save JSON to
        
    Returns:
        None
        
    Raises:
        Exception: If write fails
    """
    import json
    from pathlib import Path
    
    path = Path(template_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(path, 'w') as f:
        json.dump(template_dict, f, indent=2)


def initialize_working_templates(source_templates_path, working_templates_path):
    """
    Initialize a fresh working templates file from the clean source templates.
    Overwrites any existing working templates file.
    
    This keeps the source zero_day_templates.json immutable while all intermediate
    steps write to the working templates file.
    
    Args:
        source_templates_path (str): Path to clean zero_day_templates.json (read-only)
        working_templates_path (str): Path to _working_templates.json (working copy)
        
    Returns:
        dict: The loaded and saved templates dictionary
        
    Raises:
        Exception: If source file cannot be read
    """
    import json
    from pathlib import Path
    
    # Load source templates
    source_path = Path(source_templates_path)
    if not source_path.exists():
        raise FileNotFoundError(f"Source templates file not found: {source_templates_path}")
    
    with open(source_path, 'r') as f:
        templates = json.load(f)
    
    # Save to working templates location
    save_templates(templates, working_templates_path)
    
    return templates


def cleanup_zero_day_templates(templates_path):
    """
    Remove all intermediate/accumulated pipeline data from zero_day_templates.json.
    
    Removes fields prefixed with underscore that were added during pipeline execution:
      - _step2_stats
      - _step3_malicious_events
      - _step4_benign_events
      - _step5_false_alarm_events
    
    This is safe because:
      1. These fields are regenerated fresh each pipeline run
      2. They are now persisted in _working_templates.json instead
      3. The source template should contain only static scenario definitions
    
    Args:
        templates_path (str): Path to zero_day_templates.json
        
    Returns:
        dict: The cleaned templates dictionary
        
    Raises:
        Exception: If file cannot be read/written
    """
    import json
    from pathlib import Path
    
    path = Path(templates_path)
    if not path.exists():
        raise FileNotFoundError(f"Templates file not found: {templates_path}")
    
    with open(path, 'r') as f:
        templates = json.load(f)
    
    # Fields to remove (all intermediate pipeline data)
    intermediate_fields = [
        '_step2_stats',
        '_step3_malicious_events',
        '_step4_benign_events',
        '_step5_false_alarm_events'
    ]
    
    removed_count = 0
    
    # Remove intermediate fields from each scenario
    if 'scenarios' in templates and isinstance(templates['scenarios'], list):
        for scenario in templates['scenarios']:
            for field in intermediate_fields:
                if field in scenario:
                    del scenario[field]
                    removed_count += 1
    
    # Save cleaned templates
    save_templates(templates, str(path))
    
    return templates, removed_count


def get_scenario_by_name(templates_dict, scenario_name):
    """
    Retrieve a single scenario template by name.
    
    Args:
        templates_dict (dict): Parsed templates dictionary
        scenario_name (str): Name of scenario to retrieve
        
    Returns:
        dict: Scenario template or None if not found
    """
    for scenario in templates_dict.get('scenarios', []):
        if scenario.get('scenario_name') == scenario_name:
            return scenario
    return None


# ============================================================
# UTILITY FUNCTIONS FOR EVENT GENERATION (Steps 3-6)
# ============================================================

def get_random_internal_host(allowed_prefixes):
    """
    Return a random internal hostname from allowed prefixes.
    
    Args:
        allowed_prefixes (list): List of hostname prefixes (e.g., ['User', 'Enterprise'])
    
    Returns:
        str: Hostname (e.g., 'User1', 'Enterprise0')
    """
    prefix = random.choice(allowed_prefixes)
    
    for ip_prefix, hosts in IP_RANGES.items():
        matching_hosts = [h for h in hosts if h.startswith(prefix)]
        if matching_hosts:
            return random.choice(matching_hosts)
    
    return f"{prefix}0"


def violates_routing_constraint(src_subnet, dst_subnet):
    """
    Check if communication violates routing constraints.
    
    Constraint: No direct User ↔ Operational (must route through Enterprise).
    
    Args:
        src_subnet (str): Source subnet
        dst_subnet (str): Destination subnet
    
    Returns:
        bool: True if violates constraint
    """
    if src_subnet == dst_subnet:
        return False  # Same subnet is always allowed
    
    src_is_user = 'User' in src_subnet
    src_is_op = 'Operational' in src_subnet
    dst_is_user = 'User' in dst_subnet
    dst_is_op = 'Operational' in dst_subnet
    
    # No direct User ↔ Operational
    if (src_is_user and dst_is_op) or (src_is_op and dst_is_user):
        return True
    
    return False


# ============================================================
# STEP 2: FEATURE CONSTRAINTS (Stub - Non-critical)
# ============================================================

def fill_feature_constraints(templates_path):
    """
    Stub function: Populate feature_constraints from computed STEP 2 statistics.
    
    NOTE: This is a non-critical function. If statistics are unavailable,
    the feature_constraints will remain empty/static, which is acceptable
    for the current pipeline.
    
    Args:
        templates_path (str): Path to templates JSON file
        
    Returns:
        None
    """
    # Stub implementation - returns successfully without modification
    # Actual feature constraint population logic would go here if needed
    pass


# ============================================================
# AWS NETWORK TOPOLOGY v2 HELPERS (NEW - Phase 2)
# Extract host-to-IP mappings from network_topology_output.json
# ============================================================

def get_concrete_ip_for_host(hostname, network_topology):
    """
    Get concrete IP address for a hostname from network_topology_output.json.
    Replaces MD5-based synthetic IP generation.
    
    Args:
        hostname (str): Hostname (e.g., 'User1', 'Enterprise0', 'OpServer0')
        network_topology (dict): Loaded network_topology_output.json
    
    Returns:
        str: Concrete IP address from topology (e.g., '10.0.1.11')
        
    Raises:
        ValueError: If hostname not found in topology
    """
    # Check User subnet IPs
    if 'user_private_ips' in network_topology:
        ips = network_topology['user_private_ips'].get('value', {})
        if hostname in ips:
            return ips[hostname]
    
    # Check Enterprise subnet IPs
    if 'enterprise_private_ips' in network_topology:
        ips = network_topology['enterprise_private_ips'].get('value', {})
        if hostname in ips:
            return ips[hostname]
    
    # Check Operational subnet IPs
    if 'operational_private_ips' in network_topology:
        ips = network_topology['operational_private_ips'].get('value', {})
        if hostname in ips:
            return ips[hostname]
    
    # External hosts: generate deterministically
    if hostname.startswith('external_'):
        hash_seed = f"{hostname}"
        hash_value = int(hashlib.md5(hash_seed.encode()).hexdigest(), 16)
        octet3 = (hash_value % 256)
        octet4 = ((hash_value >> 8) % 254) + 1
        return f"203.0.{octet3}.{octet4}"
    
    raise ValueError(f"Hostname '{hostname}' not found in network topology")


def get_subnet_cidr_for_host(hostname, network_topology):
    """
    Get subnet CIDR block for a hostname using network_topology_output.json.
    
    Args:
        hostname (str): Hostname
        network_topology (dict): Loaded network_topology_output.json
    
    Returns:
        str: Subnet CIDR block (e.g., '10.0.1.0/24')
        
    Raises:
        ValueError: If hostname not found in topology
    """
    # Map hostname to subnet CIDR
    if hostname.startswith('User'):
        if 'user_subnet_cidr' in network_topology:
            return network_topology['user_subnet_cidr'].get('value')
    
    if hostname.startswith('Enterprise') or hostname == 'Defender':
        if 'enterprise_subnet_cidr' in network_topology:
            return network_topology['enterprise_subnet_cidr'].get('value')
    
    if hostname.startswith('OpHost') or hostname.startswith('OpServer'):
        if 'operational_subnet_cidr' in network_topology:
            return network_topology['operational_subnet_cidr'].get('value')
    
    if hostname.startswith('external_'):
        return None  # External hosts don't belong to internal subnets
    
    raise ValueError(f"Cannot determine subnet CIDR for hostname '{hostname}'")


def validate_host_in_topology(hostname, network_topology):
    """
    Confirm hostname exists in concrete network topology.
    
    Args:
        hostname (str): Hostname to validate
        network_topology (dict): Loaded network_topology_output.json
    
    Returns:
        bool: True if hostname is valid in topology
    """
    try:
        get_concrete_ip_for_host(hostname, network_topology)
        return True
    except ValueError:
        return False


def validate_ip_in_subnet(ip_address, subnet_cidr):
    """
    Check if IP address belongs to subnet using CIDR validation.
    
    Args:
        ip_address (str): IP address (e.g., '10.0.1.15')
        subnet_cidr (str): Subnet CIDR block (e.g., '10.0.1.0/24')
    
    Returns:
        bool: True if IP is in subnet, False otherwise
    """
    if subnet_cidr is None:
        return False
    
    try:
        import ipaddress
        ip = ipaddress.ip_address(ip_address)
        network = ipaddress.ip_network(subnet_cidr, strict=False)
        return ip in network
    except (ValueError, AttributeError):
        return False


def validate_routing_path_aws(src_host, dst_host, network_topology):
    """
    Enforce AWS routing constraints from network_topology_output.json.
    
    Strict routing path from network_topology_output.json:
      User1 (10.0.1.11) → Enterprise1 (10.0.2.11) → Enterprise2 (10.0.2.12) → OpServer0 (10.0.3.20)
    
    AWS Constraints:
      1. Intra-subnet: All hosts within same subnet can communicate freely
      2. Cross-subnet: ONLY through designated gateways:
         - User1 → Enterprise1 (User subnet gateway to Enterprise)
         - Enterprise1↔Enterprise2 (bidirectional within Enterprise)
         - Enterprise2 → OpServer0 (Enterprise to Operational gateway)
         - Response traffic: Enterprise ↔ User, Operational → Enterprise
      3. Defender: IDS/IPS monitor (cannot be regular event destination)
      4. External: Any host can communicate with external_* hosts via IGW
    
    Args:
        src_host (str): Source hostname
        dst_host (str): Destination hostname
        network_topology (dict): Loaded network_topology_output.json
    
    Returns:
        dict: {'valid': bool, 'reason': str}
    """
    # Defender exclusion: Cannot be destination for regular event traffic
    # Defender is IDS/IPS monitor with VPC visibility, not a routing node
    if dst_host == 'Defender' and src_host != 'Defender':
        return {'valid': False, 'reason': 'Defender (IDS/IPS) cannot be regular event destination; reserved for monitoring'}
    
    # Same subnet: always allowed (per network_topology_output.json: "All hosts within same subnet can communicate freely")
    if src_host.startswith('User') and dst_host.startswith('User'):
        return {'valid': True, 'reason': 'Same subnet (User): intra-subnet communication allowed'}


# ============================================================
# PIPELINE CONFIGURATION & ORCHESTRATION
# ============================================================

FALSE_ALARM_BINS = {
    "zero": {
        "label": "No false alarms",
        "pct": 0.0,
        "description": "Pure attack detection scenario (no triage training)"
    },
    "very_conservative": {
        "label": "Very conservative",
        "pct": 0.05,
        "description": "5% false alarm rate (minimal noise)"
    },
    "conservative": {
        "label": "Conservative",
        "pct": 0.10,
        "description": "10% false alarm rate (light noise)"
    },
    "standard": {
        "label": "Standard (default)",
        "pct": 0.15,
        "description": "15% false alarm rate (balanced)"
    },
    "elevated": {
        "label": "Elevated",
        "pct": 0.20,
        "description": "20% false alarm rate (more noise)"
    },
    "high": {
        "label": "High",
        "pct": 0.30,
        "description": "30% false alarm rate (maximum, safe for all scenarios)"
    }
}

FA_TYPE_RATIO_MODES = {
    "balanced": {
        "label": "Balanced",
        "ratios": {"type_1": 0.4, "type_2": 0.4, "type_3": 0.2},
        "description": "40:40:20 distribution (default - good mix of anomaly types)"
    },
    "port_heavy": {
        "label": "Port-heavy",
        "ratios": {"type_1": 0.6, "type_2": 0.2, "type_3": 0.2},
        "description": "60:20:20 distribution (easier to detect - visible port anomalies)"
    },
    "volume_heavy": {
        "label": "Volume-heavy",
        "ratios": {"type_1": 0.2, "type_2": 0.6, "type_3": 0.2},
        "description": "20:60:20 distribution (requires baselines - advanced analysis)"
    },
    "duration_heavy": {
        "label": "Duration-heavy",
        "ratios": {"type_1": 0.2, "type_2": 0.2, "type_3": 0.6},
        "description": "20:20:60 distribution (subtle patterns - hard to detect manually)"
    }
}


def validate_false_alarm_bin(bin_name):
    """Validate that false_alarm_bin exists in FALSE_ALARM_BINS"""
    if bin_name not in FALSE_ALARM_BINS:
        valid_bins = ", ".join(FALSE_ALARM_BINS.keys())
        raise ValueError(
            f"Invalid false_alarm_bin: '{bin_name}'. Must be one of: {valid_bins}"
        )
    return True


def validate_fa_type_ratio_mode(mode_name):
    """Validate that fa_type_ratio_mode exists in FA_TYPE_RATIO_MODES"""
    if mode_name not in FA_TYPE_RATIO_MODES:
        valid_modes = ", ".join(FA_TYPE_RATIO_MODES.keys())
        raise ValueError(
            f"Invalid fa_type_ratio_mode: '{mode_name}'. Must be one of: {valid_modes}"
        )
    return True


def validate_total_events(total_events):
    """Validate that total_events is in valid range"""
    if not isinstance(total_events, int) or not (18 <= total_events <= 45):
        raise ValueError(
            f"Invalid total_events_per_table: {total_events}. Must be integer between 18-45"
        )
    return True


def validate_per_scenario_feasibility(templates_data, total_events, false_alarm_pct):
    """
    Check if configuration is feasible for each scenario.
    Returns (is_valid, errors, warnings, malicious_count_dict, benign_count_dict, false_alarm_count_dict)
    """
    errors = []
    warnings = []
    malicious_count_per_scenario = {}
    benign_count_per_scenario = {}
    false_alarm_count_per_scenario = {}
    
    if 'scenarios' not in templates_data:
        errors.append("Templates JSON missing 'scenarios' key")
        return False, errors, warnings, {}, {}, {}
    
    for scenario in templates_data['scenarios']:
        scenario_name = scenario.get('scenario_name', 'UNKNOWN')
        
        # Get scenario-specific malicious count
        if 'malicious_count' not in scenario:
            errors.append(f"Scenario '{scenario_name}' missing 'malicious_count' field")
            continue
        
        malicious_count = scenario['malicious_count']
        
        # Compute false alarm count (rounded)
        false_alarm_count = round(total_events * false_alarm_pct)
        
        # Compute benign count (remainder)
        benign_count = total_events - malicious_count - false_alarm_count
        
        # Feasibility checks
        if benign_count < 0:
            errors.append(
                f"Scenario '{scenario_name}': Configuration infeasible. "
                f"Malicious({malicious_count}) + FalseAlarm({false_alarm_count}) "
                f"exceeds total({total_events}), leaving negative benign count({benign_count})"
            )
            continue
        
        # Store computed values
        malicious_count_per_scenario[scenario_name] = malicious_count
        benign_count_per_scenario[scenario_name] = benign_count
        false_alarm_count_per_scenario[scenario_name] = false_alarm_count
        
        # Warnings for edge cases
        if benign_count == 0:
            warnings.append(
                f"Scenario '{scenario_name}': No baseline traffic. "
                f"Dataset will contain only malicious + false alarm events."
            )
        
        if false_alarm_count == 0:
            warnings.append(
                f"Scenario '{scenario_name}': No false alarms. "
                f"Pure attack detection scenario (no triage training)."
            )
    
    is_valid = len(errors) == 0
    return is_valid, errors, warnings, malicious_count_per_scenario, benign_count_per_scenario, false_alarm_count_per_scenario


class PipelineConfig:
    """
    Configuration container for the IDS pipeline.
    Encapsulates all user-settable parameters with validation.
    """
    
    def __init__(self, total_events_per_table=30, false_alarm_bin="standard", fa_type_ratio_mode="balanced"):
        """
        Initialize pipeline configuration.
        
        Args:
            total_events_per_table (int): Number of events per table (18-45)
            false_alarm_bin (str): False alarm rate bin key
            fa_type_ratio_mode (str): False alarm distribution mode
            
        Raises:
            ValueError: If any parameter is invalid
        """
        self.total_events_per_table = total_events_per_table
        self.false_alarm_bin = false_alarm_bin
        self.fa_type_ratio_mode = fa_type_ratio_mode
        
        # Validate all parameters
        validate_total_events(total_events_per_table)
        validate_false_alarm_bin(false_alarm_bin)
        validate_fa_type_ratio_mode(fa_type_ratio_mode)
        
        # Pre-compute false alarm percentage
        self.false_alarm_pct = FALSE_ALARM_BINS[false_alarm_bin]["pct"]
    
    def print_summary(self):
        """Print configuration summary to console"""
        false_alarm_label = FALSE_ALARM_BINS[self.false_alarm_bin]["label"]
        print(f"\n{'='*70}")
        print(f"Pipeline Configuration:")
        print(f"{'='*70}")
        print(f"  Total events per table: {self.total_events_per_table}")
        print(f"  False alarm bin: {self.false_alarm_bin} ({self.false_alarm_pct*100:.0f}%)")
        print(f"  FA type ratio mode: {self.fa_type_ratio_mode}")
        print(f"  (Malicious counts fixed per scenario in templates)")
        print(f"  (Benign counts calculated as: total - malicious - false_alarm)")
        print(f"{'='*70}\n")


def run_pipeline(config):
    """
    Execute the complete IDS pipeline with given configuration.
    
    Args:
        config (PipelineConfig): Pipeline configuration parameters
        
    Raises:
        ValueError: If any step fails validation or execution
    """
    import pre_step
    import step_1
    import step_2
    import step_3
    import step_4
    import step_5
    import step_6
    import step_7
    from pathlib import Path
    import json as json_module
    
    # Print configuration
    config.print_summary()
    
    # Define file paths
    source_templates_path = Path("templates/zero_day_templates.json")
    working_templates_path = Path("templates/_working_templates.json")
    input_unsw_csv = Path("IDS_Datasets/UNSW_NB15_training-set(in).csv")
    output_transformed_csv = Path("IDS_Datasets/UNSW_NB15_transformed.csv")
    global_constraints_path = Path("templates/global_constraints.json")
    network_topology_path = Path("templates/network_topology_output.json")
    
    # ============================================================
    # INITIALIZE WORKING TEMPLATES
    # ============================================================
    print(f"Initializing working templates...")
    initialize_working_templates(str(source_templates_path), str(working_templates_path))
    print(f"  [OK] Working templates initialized: {working_templates_path}")
    
    # ============================================================
    # PRE-STEP: TRANSFORM DATA
    # ============================================================
    if output_transformed_csv.exists():
        print(f" Transformed dataset already exists: {output_transformed_csv}")
    else:
        print(f"Running Pre-Step: transforming UNSW data...")
        pre_step.batch_transform_unsw(str(input_unsw_csv), str(output_transformed_csv))
    
    # ============================================================
    # STEP 0: LOAD CONFIGURATION FILES
    # ============================================================
    for config_file in [global_constraints_path, network_topology_path]:
        if not config_file.exists():
            raise FileNotFoundError(f"Required config file not found: {config_file}")
    
    print(f" Global constraints file found: {global_constraints_path}")
    print(f" Network topology file found: {network_topology_path}")
    
    try:
        with open(global_constraints_path, 'r') as f:
            global_constraints = json_module.load(f)
        with open(network_topology_path, 'r') as f:
            network_topology = json_module.load(f)
    except json_module.JSONDecodeError as e:
        raise ValueError(f"JSON parse error in config files: {e}")
    
    # ============================================================
    # STEP 1: VALIDATE TEMPLATES
    # ============================================================
    print(f"Running Step 1: creating and validating zero-day templates...")
    step1_result = step_1.validate_templates_step(
        str(working_templates_path),
        str(global_constraints_path)
    )
    
    if not step1_result['success']:
        raise ValueError(
            f"Step 1 validation failed: {len(step1_result['errors'])} error(s)\n"
            + "\n".join(step1_result['errors'])
        )
    
    try:
        with open(working_templates_path, 'r') as f:
            templates_dict = json_module.load(f)
        
        if 'scenarios' not in templates_dict:
            raise ValueError("Templates JSON missing 'scenarios' key")
        if not isinstance(templates_dict['scenarios'], list):
            raise ValueError("Templates 'scenarios' must be a list")
        if len(templates_dict['scenarios']) == 0:
            raise ValueError("Templates 'scenarios' is empty")
        
        print(f" [OK] Templates validated: {working_templates_path}")
    except json_module.JSONDecodeError as e:
        raise ValueError(f"Templates JSON is malformed: {e}")
    except Exception as e:
        raise ValueError(f"Templates validation failed: {e}")
    
    # ============================================================
    # PRE-COMPUTATION: EVENT COUNTS
    # ============================================================
    print(f"\nValidating configuration feasibility for all scenarios...")
    is_valid, val_errors, val_warnings, malicious_count_per_scenario, benign_count_per_scenario, false_alarm_count_per_scenario = validate_per_scenario_feasibility(
        templates_dict, 
        config.total_events_per_table, 
        config.false_alarm_pct
    )
    
    if not is_valid:
        raise ValueError(
            f"Configuration validation failed:\n" + "\n".join([f"  ERROR: {e}" for e in val_errors])
        )
    
    if val_warnings:
        print(f"\n[WARNINGS during configuration validation]")
        for warning in val_warnings:
            print(f"  {warning}")
    
    print(f"\nPer-scenario event counts (computed):")
    for scenario in templates_dict['scenarios']:
        scenario_name = scenario.get('scenario_name', 'UNKNOWN')
        mal = malicious_count_per_scenario.get(scenario_name, 0)
        ben = benign_count_per_scenario.get(scenario_name, 0)
        fa = false_alarm_count_per_scenario.get(scenario_name, 0)
        total = mal + ben + fa
        print(f"  {scenario_name}: Malicious={mal}, Benign={ben}, FalseAlarm={fa}, Total={total}")
    
    output_dir = Path(f"IDS_tables/{config.total_events_per_table}events_{int(config.false_alarm_pct*100)}pct_fa")
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"\n Output directory: {output_dir}")
    
    # ============================================================
    # STEP 2: FILTER + TIER CLASSIFICATION
    # ============================================================
    scenarios_with_attacks = [s for s in templates_dict['scenarios'] if s.get('malicious_count', 0) > 0]
    scenarios_no_attack = [s for s in templates_dict['scenarios'] if s.get('malicious_count', 0) == 0]
    
    if scenarios_with_attacks:
        print(f"\nRunning Step 2: filtering & tier classification...")
        step2_result = step_2.process_step_2(
            str(output_transformed_csv),
            str(working_templates_path),
            str(global_constraints_path),
            network_topology=network_topology,
            output_report_path="step_2_summary.txt"
        )
        
        if not step2_result['success']:
            raise ValueError(
                f"Step 2 failed: {len(step2_result['errors'])} error(s)\n"
                + "\n".join(step2_result['errors'])
            )
    
    if scenarios_no_attack:
        print(f"\n[SKIPPED] Step 2 for attack-free scenarios: {[s['scenario_name'] for s in scenarios_no_attack]}")
        print(f"           (No UNSW filtering needed for pure benign traffic)")
    
    # ============================================================
    # STEP 3: MALICIOUS EVENTS
    # ============================================================
    if scenarios_with_attacks:
        print(f"\nRunning Step 3: generating malicious events...")
        step3_result = step_3.generate_malicious_events_step_3(
            str(output_transformed_csv),
            str(working_templates_path),
            str(global_constraints_path),
            network_topology=network_topology,
            malicious_count_per_scenario=malicious_count_per_scenario,
            random_seed=42
        )
        
        if not step3_result['success']:
            raise ValueError(
                f"Step 3 failed: {len(step3_result['errors'])} error(s)\n"
                + "\n".join(step3_result['errors'])
            )
    
    if scenarios_no_attack:
        print(f"\n[SKIPPED] Step 3 for attack-free scenarios: {[s['scenario_name'] for s in scenarios_no_attack]}")
        print(f"           (No malicious event generation needed)")
    
    # ============================================================
    # STEP 4: BENIGN EVENTS
    # ============================================================
    print(f"\nRunning Step 4: generating benign events...")
    step4_result = step_4.generate_benign_events_step_4(
        str(output_transformed_csv),
        str(working_templates_path),
        str(global_constraints_path),
        network_topology=network_topology,
        benign_count_per_scenario=benign_count_per_scenario,
        random_seed=42
    )
    
    if not step4_result['success']:
        raise ValueError(
            f"Step 4 failed: {len(step4_result['errors'])} error(s)\n"
            + "\n".join(step4_result['errors'])
        )
    
    # ============================================================
    # STEP 5: FALSE ALARMS
    # ============================================================
    print(f"\nRunning Step 5: generating false alarm events...")
    step5_result = step_5.generate_false_alarms_step_5(
        str(output_transformed_csv),
        str(working_templates_path),
        str(global_constraints_path),
        network_topology=network_topology,
        false_alarm_count_per_scenario=false_alarm_count_per_scenario,
        fa_type_ratio_mode=config.fa_type_ratio_mode,
        random_seed=42
    )
    
    if not step5_result['success']:
        raise ValueError(
            f"Step 5 failed: {len(step5_result['errors'])} error(s)\n"
            + "\n".join(step5_result['errors'])
        )
    
    # ============================================================
    # STEP 6: FINAL ASSEMBLY
    # ============================================================
    print(f"\nRunning Step 6: assembling {config.total_events_per_table}-event tables with temporal ordering...")
    step6_result = step_6.assemble_30_events_step_6(
        str(working_templates_path),
        str(global_constraints_path),
        network_topology=network_topology,
        output_dir=str(output_dir),
        malicious_count_per_scenario=malicious_count_per_scenario,
        benign_count_per_scenario=benign_count_per_scenario,
        false_alarm_count_per_scenario=false_alarm_count_per_scenario,
        total_events_param=config.total_events_per_table,
        false_alarm_pct_param=config.false_alarm_pct,
        output_report_path=str(output_dir / "step_6_summary.txt"),
        random_seed=42
    )
    
    if not step6_result['success']:
        print(f"\n[WARN] Step 6 completed with warnings/errors:")
        for err in step6_result['errors']:
            print(f"  - {err}")
    else:
        print(f"[OK] Step 6 completed successfully")
    
    print(f"\n  Generated CSV files:")
    for scenario, csv_path in step6_result['csv_paths'].items():
        print(f"    - {csv_path}")
    
    # ============================================================
    # STEP 7: AWS NETWORK TOPOLOGY VALIDATION
    # ============================================================
    print(f"\nRunning Step 7: validating AWS network topology constraints...")
    step7_result = step_7.validate_topology_step_7(
        str(output_dir),
        str(network_topology_path)
    )
    
    if not step7_result['success']:
        print(f"\n{'='*80}")
        print(f"VALIDATION ERRORS DETECTED")
        print(f"{'='*80}")
        print(f"\nTotal errors: {step7_result['total_errors']}")
        print(f"\nDetailed error report:")
        for error in step7_result['all_errors']:
            print(error)
        print(f"\n{'='*80}")
        raise ValueError(
            f"Step 7 validation failed with {step7_result['total_errors']} error(s). "
            f"Review error messages above for constraint violations."
        )
    else:
        print(f"\n[OK] Step 7 validation PASSED: All AWS topology constraints satisfied.")
    
    # ============================================================
    # FINAL SUMMARY
    # ============================================================
    print("\n" + "="*80)
    print(" PIPELINE COMPLETE: PRE-STEP THROUGH STEP 7")
    print("="*80)
    print(f"\nFinal outputs in {output_dir}/ folder:")
    for scenario in step6_result['csv_paths'].keys():
        basename = Path(step6_result['csv_paths'][scenario]).name
        print(f"  [OK] {basename}")
    print(f"\nValidation report: Step 7 AWS topology validation PASSED")
    print(f"Summary report: {output_dir}/step_6_summary.txt")


def get_all_hosts_from_topology(network_topology):
    """
    Extract complete list of all hosts from network_topology_output.json.
    
    Args:
        network_topology (dict): Loaded network_topology_output.json
    
    Returns:
        list: All internal hostnames (User0-4, Enterprise0-2, Defender, OpHost0-2, OpServer0)
    """
    all_hosts = []
    
    # User hosts
    if 'user_private_ips' in network_topology:
        all_hosts.extend(network_topology['user_private_ips'].get('value', {}).keys())
    
    # Enterprise hosts
    if 'enterprise_private_ips' in network_topology:
        all_hosts.extend(network_topology['enterprise_private_ips'].get('value', {}).keys())
    
    # Operational hosts
    if 'operational_private_ips' in network_topology:
        all_hosts.extend(network_topology['operational_private_ips'].get('value', {}).keys())
    
    return all_hosts
