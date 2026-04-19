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
    
    # Validate entry_point and target_asset structure
    if 'entry_point' in scenario_dict:
        entry = scenario_dict['entry_point']
        if not isinstance(entry, dict):
            errors.append(f"  Scenario {scenario_index}: 'entry_point' must be dict, got {type(entry)}")
        elif 'host' not in entry or 'subnet' not in entry:
            errors.append(f"  Scenario {scenario_index}: 'entry_point' missing 'host' or 'subnet'")
    
    if 'target_asset' in scenario_dict:
        target = scenario_dict['target_asset']
        if not isinstance(target, dict):
            errors.append(f"  Scenario {scenario_index}: 'target_asset' must be dict, got {type(target)}")
        elif 'host' not in target or 'subnet' not in target:
            errors.append(f"  Scenario {scenario_index}: 'target_asset' missing 'host' or 'subnet'")
    
    # Validate key_attack_behaviors structure
    if 'key_attack_behaviors' in scenario_dict:
        behaviors = scenario_dict['key_attack_behaviors']
        if not isinstance(behaviors, dict):
            errors.append(f"  Scenario {scenario_index}: 'key_attack_behaviors' must be dict, got {type(behaviors)}")
        else:
            required_behaviors = ['initial_access', 'lateral_movement', 'payload_execution', 'data_exfiltration']
            for behavior in required_behaviors:
                if behavior not in behaviors:
                    errors.append(f"  Scenario {scenario_index}: 'key_attack_behaviors' missing '{behavior}'")
    
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


def get_deterministic_ip_for_host(scenario_name, hostname):
    """
    Return a deterministic IP address for a hostname within a scenario.
    
    Args:
        scenario_name (str): Scenario name
        hostname (str): Hostname (e.g., 'User1', 'Enterprise0', 'external_45')
    
    Returns:
        str: IP address
    """
    if hostname.startswith('external_'):
        return f"203.0.{random.randint(0, 255)}.{random.randint(1, 254)}"
    
    for prefix, hosts in IP_RANGES.items():
        if hostname in hosts:
            hash_seed = f"{scenario_name}:{hostname}"
            hash_value = int(hashlib.md5(hash_seed.encode()).hexdigest(), 16)
            last_octet = (hash_value % 254) + 1
            return f"{prefix}.{last_octet}"
    
    return "192.168.1.100"


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
