"""
Step 4: Generate Benign Events
Purpose: Create 15 realistic benign events per scenario reflecting normal enterprise traffic.
         Events are scenario-independent (sampled from pooled benign data) and uniformly
         distributed across the 1800s observation window.
"""

import pandas as pd
import json
import random
from pathlib import Path
from helper_functions import (
    map_ip_to_host,
    map_subnet,
    infer_service_from_port,
    validate_host,
    validate_subnet,
    SCENARIOS,
    load_templates,
    save_templates,
    get_scenario_by_name,
    IP_RANGES,
    FIXED_HOST_IPS,
    get_allowed_routing_destinations,
    validate_malicious_event_hosts,
    is_defender,
    get_deterministic_ip_for_host,
)


# ============================================================
# BENIGN TRAFFIC CHARACTERISTICS
# ============================================================

BENIGN_SERVICE_TEMPLATES = {
    'http': {
        'ports': [80],
        'protocols': ['tcp'],
        'duration_range': (0.5, 30),
        'bytes_range': (500, 500000),
        'packets_range': (5, 200),
        'description': 'Web browsing',
    },
    'dns': {
        'ports': [53],
        'protocols': ['udp', 'tcp'],
        'duration_range': (0.01, 2),
        'bytes_range': (50, 1000),
        'packets_range': (1, 5),
        'description': 'DNS queries',
    },
    'ssh_admin': {
        'ports': [22],
        'protocols': ['tcp'],
        'duration_range': (10, 600),
        'bytes_range': (200, 100000),
        'packets_range': (10, 500),
        'description': 'SSH admin access',
    },
    'ftp': {
        'ports': [21],
        'protocols': ['tcp'],
        'duration_range': (5, 120),
        'bytes_range': (100000, 10000000),
        'packets_range': (50, 2000),
        'description': 'FTP file transfer',
    },
    'smtp': {
        'ports': [25],
        'protocols': ['tcp'],
        'duration_range': (1, 30),
        'bytes_range': (1000, 100000),
        'packets_range': (5, 100),
        'description': 'SMTP email',
    },
    'rdp': {
        'ports': [3389],
        'protocols': ['tcp'],
        'duration_range': (30, 1800),
        'bytes_range': (5000, 500000),
        'packets_range': (50, 1000),
        'description': 'RDP remote access',
    },
}


# ============================================================
# CORE FUNCTIONS: Event Generation
# ============================================================

def generate_benign_events_step_4(
    transformed_csv_path,
    templates_path,
    global_constraints_path,
    network_topology=None,
    benign_count_per_scenario=None,
    random_seed=42,
    output_debug=False
):
    """
    Main orchestrator for Step 4: Generate benign events for all scenarios.
    
    Args:
        transformed_csv_path (str): Path to UNSW_NB15_transformed.csv
        templates_path (str): Path to templates/zero_day_templates.json
        global_constraints_path (str): Path to templates/global_constraints_v2.json
        network_topology (dict, optional): Loaded network_topology_output.json for AWS topology validation
        benign_count_per_scenario (dict): Map of scenario_name -> benign_count
                                          If None, defaults to 15 for all scenarios
        random_seed (int): Seed for reproducibility
        output_debug (bool): Whether to output debug info
    
    Returns:
        dict: {
            'success': bool,
            'errors': [list of error strings],
            'benign_events_per_scenario': {
                'WannaCry': [benign event dicts],
                'Data_Theft': [benign event dicts],
                ...
            }
        }
    """
    
    random.seed(random_seed)
    errors = []
    benign_events_per_scenario = {}
    
    try:
        # Load transformed data
        transformed_df = pd.read_csv(transformed_csv_path)
        print(f"Loaded {len(transformed_df)} rows from transformed CSV")
        
        # Load templates and constraints
        templates_dict = load_templates(templates_path)
        with open(global_constraints_path, 'r') as f:
            global_constraints = json.load(f)
        
        # Extract pooled benign data (all scenarios combined)
        # Filter for attack_cat='Normal' without scenario filtering
        pooled_benign_df = transformed_df[
            transformed_df['attack_cat'] == 'Normal'
        ].copy()
        
        if len(pooled_benign_df) == 0:
            errors.append("No benign (attack_cat='Normal') data found in transformed CSV")
            return {
                'success': False,
                'errors': errors,
                'benign_events_per_scenario': {},
            }
        
        print(f"  Pooled benign data: {len(pooled_benign_df)} rows from all scenarios")
        
        # Generate benign events for each scenario
        for scenario_name in SCENARIOS:
            print(f"\n  Generating benign events for {scenario_name}...")
            
            try:
                scenario_template = get_scenario_by_name(templates_dict, scenario_name)
                if not scenario_template:
                    errors.append(f"Scenario {scenario_name} not found in templates")
                    continue
                
                # Get benign count from parameter or use default
                if benign_count_per_scenario and scenario_name in benign_count_per_scenario:
                    ben_count = benign_count_per_scenario[scenario_name]
                else:
                    ben_count = 15  # Default for backwards compatibility
                
                # Generate benign events (scenario-independent)
                events = _generate_benign_events_for_scenario(
                    scenario_name,
                    pooled_benign_df,
                    scenario_template,
                    global_constraints,
                    benign_count=ben_count,
                    network_topology=network_topology
                )
                
                benign_events_per_scenario[scenario_name] = events
                print(f"    [OK] Generated {len(events)} benign events")
                
            except Exception as e:
                errors.append(f"Error generating {scenario_name}: {str(e)}")
        
        # Update templates with benign events (for later steps)
        for scenario_dict in templates_dict['scenarios']:
            scenario_name = scenario_dict['scenario_name']
            if scenario_name in benign_events_per_scenario:
                scenario_dict['_step4_benign_events'] = benign_events_per_scenario[scenario_name]
        
        # Save updated templates
        save_templates(templates_dict, templates_path)
        print(f"\nUpdated templates saved: {templates_path}")
        
        return {
            'success': len(errors) == 0,
            'errors': errors,
            'benign_events_per_scenario': benign_events_per_scenario,
        }
    
    except Exception as e:
        return {
            'success': False,
            'errors': [f"Step 4 fatal error: {str(e)}"],
            'benign_events_per_scenario': {},
        }


def _generate_benign_events_for_scenario(scenario_name, pooled_benign_df, template, constraints, benign_count=15, network_topology=None):
    """
    Generate benign events for a single scenario.
    
    Strategy:
    - Sample benign_count random rows from pooled_benign_df (scenario-independent)
    - Assign to random services with concrete IP mapping from network_topology
    - Spread timestamps uniformly across [0, 1800] seconds
    - Apply topology constraints (routing rules)
    - Handle edge case: benign_count=0 (no benign events)
    
    Args:
        scenario_name (str): Scenario name (e.g., 'WannaCry')
        pooled_benign_df (pd.DataFrame): Benign rows from all scenarios combined
        template (dict): Scenario template
        constraints (dict): Global constraints
        benign_count (int): Number of benign events to generate (default: 15)
        network_topology (dict, optional): Loaded network_topology_output.json for concrete IPs
    
    Returns:
        list: Benign event dictionaries (may be empty if benign_count=0)
    """
    
    # Handle edge case: no benign events requested
    if benign_count == 0:
        return []
    
    # Sample benign_count random benign rows
    num_events = min(benign_count, len(pooled_benign_df))
    if len(pooled_benign_df) < num_events:
        sampled_df = pooled_benign_df.copy()
    else:
        sampled_df = pooled_benign_df.sample(n=num_events, random_state=None)
    
    sampled_df = sampled_df.reset_index(drop=True)
    
    # Generate uniform timestamps across [0, 1800]
    timestamps = sorted([random.uniform(0, 1800) for _ in range(len(sampled_df))])
    
    events = []
    for idx, (_, row) in enumerate(sampled_df.iterrows()):
        # Randomly select a benign service type
        service_type = random.choice(list(BENIGN_SERVICE_TEMPLATES.keys()))
        service_template = BENIGN_SERVICE_TEMPLATES[service_type]
        
        # Randomly select port and protocol from service template
        dport = random.choice(service_template['ports'])
        proto = random.choice(service_template['protocols'])
        
        # Randomly assign source from User or Enterprise subnet
        src_host = _get_random_internal_host(['User', 'Enterprise'])
        src_subnet = map_subnet(src_host)
        src_ip = get_deterministic_ip_for_host(scenario_name, src_host, network_topology=network_topology)
        
        # Randomly assign destination with 70% intra-subnet preference (realistic traffic)
        use_external = random.choice([True, False])
        
        if use_external:
            # External traffic: 5-10% of total traffic
            dst_host = f"external_{random.randint(1, 100)}"
            dst_subnet = 'External'
            dst_ip = get_deterministic_ip_for_host(scenario_name, dst_host, network_topology=network_topology)
        else:
            # Internal destination (90-95% of traffic)
            # 70% stay in same subnet, 30% cross-subnet but to allowed destinations
            if random.random() < 0.7:
                # Intra-subnet communication (most common)
                src_prefix = src_host[0] if src_host[0].isalpha() else 'User'
                for prefix in ['User', 'Enterprise', 'OpHost', 'OpServer']:
                    if src_host.startswith(prefix):
                        src_prefix = prefix
                        break
                dst_host = _get_random_internal_host([src_prefix])
            else:
                # Cross-subnet communication (less common, must follow routing rules)
                allowed_dests = get_allowed_routing_destinations(src_host, src_subnet)
                if allowed_dests['allowed_hosts']:
                    dst_host = random.choice(allowed_dests['allowed_hosts'])
                else:
                    # Fallback: DNS queries or Enterprise services
                    if service_type == 'dns':
                        dst_host = random.choice(['Enterprise0', 'Enterprise1'])
                    else:
                        dst_host = 'Enterprise0'
            
            dst_subnet = map_subnet(dst_host)
            dst_ip = get_deterministic_ip_for_host(scenario_name, dst_host, network_topology=network_topology)
        
        # Extract feature values from UNSW row
        duration = row.get('duration', 0.1)
        bytes_total = max(row.get('sbytes', 0) + row.get('dbytes', 0), 1)  # Ensure non-zero
        packets_total = max(row.get('spkts', 0) + row.get('dpkts', 0), 1)  # Ensure non-zero
        
        # Adjust features to be within benign service ranges
        duration = max(service_template['duration_range'][0], 
                      min(service_template['duration_range'][1], duration))
        bytes_total = max(service_template['bytes_range'][0], 
                         min(service_template['bytes_range'][1], bytes_total))
        packets_total = max(service_template['packets_range'][0], 
                           min(service_template['packets_range'][1], packets_total))
        
        # Build event dictionary (all 23 columns)
        event = {
            'timestamp': timestamps[idx],
            'src_host': src_host,
            'dst_host': dst_host,
            'src_subnet': src_subnet,
            'dst_subnet': dst_subnet,
            'proto': proto,
            'sport': row.get('sport', random.randint(1024, 65535)),
            'dport': dport,
            'service': service_type,
            'duration': duration,
            'bytes': bytes_total,
            'packets': packets_total,
            'sttl': int(row.get('sttl', 64 if random.random() > 0.3 else 128)),
            'dttl': int(row.get('dttl', 64 if random.random() > 0.3 else 128)),
            'state': row.get('state', 'CON'),
            'sloss': int(row.get('sloss', 0)),
            'dloss': int(row.get('dloss', 0)),
            'ct_src_dport_ltm': int(row.get('ct_src_dport_ltm', 1)),
            'ct_dst_src_ltm': int(row.get('ct_dst_src_ltm', 1)),
            'attack_cat': 'Normal',
            'label': 'Benign',
            '_unsw_row_id': int(row.get('_unsw_row_id', idx)),
            'scenario_name': scenario_name,
            '_source': 'UNSW_benign',
        }
        
        # Validation
        if not validate_host(event['src_host']):
            raise ValueError(f"Invalid src_host: {event['src_host']}")
        if not validate_host(event['dst_host']):
            raise ValueError(f"Invalid dst_host: {event['dst_host']}")
        if not validate_subnet(event['src_subnet']):
            raise ValueError(f"Invalid src_subnet: {event['src_subnet']}")
        if not validate_subnet(event['dst_subnet']):
            raise ValueError(f"Invalid dst_subnet: {event['dst_subnet']}")
        
        events.append(event)
    
    return events


def _get_random_internal_host(allowed_prefixes):
    """
    Return a random internal hostname from allowed prefixes.
    
    Args:
        allowed_prefixes (list): List of hostname prefixes (e.g., ['User', 'Enterprise'])
    
    Returns:
        str: Hostname (e.g., 'User1', 'Enterprise0')
    """
    prefix = random.choice(allowed_prefixes)
    
    # Get all hosts under this prefix
    for ip_prefix, hosts in IP_RANGES.items():
        matching_hosts = [h for h in hosts if h.startswith(prefix)]
        if matching_hosts:
            return random.choice(matching_hosts)
    
    # Fallback
    return f"{prefix}0"


def _violates_routing_constraint(src_subnet, dst_subnet):
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
