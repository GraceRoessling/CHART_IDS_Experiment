"""
Step 5: Generate False Alarm Events
Purpose: Create 4-5 locally anomalous but globally benign events per scenario.
         Events are UNSW-grounded (use benign UNSW data as templates with anomaly injection),
         scenario-independent, and spread across the observation window.

False Alarm Taxonomy:
  - Type 1: Unusual port + benign service (2 events)
    Example: External DNS query on port 12345 instead of 53
  - Type 2: High volume + benign service (2 events)
    Example: Very large DNS response (anomalous but benign)
  - Type 3: Rare duration + benign service (1 event)
    Example: Very long SSH session (rare but benign)
"""

import pandas as pd
import json
import random
import hashlib
from pathlib import Path
from helper_functions import (
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
    get_random_internal_host_excluding_defender,
    get_deterministic_ip_for_host,
    validate_malicious_event_hosts,
    is_defender,
)


# ============================================================
# FALSE ALARM CHARACTERISTICS (read from global_constraints.json)
# ============================================================

def get_false_alarm_types(global_constraints):
    """
    Get false alarm type definitions from global_constraints.json.
    
    Args:
        global_constraints (dict): Global constraints configuration
    
    Returns:
        dict: False alarm types with counts and descriptions
    """
    try:
        if 'false_alarm_taxonomy' in global_constraints:
            fa_taxonomy = global_constraints['false_alarm_taxonomy']
            
            # Convert JSON structure to usable format
            false_alarm_types = {}
            for fa_type_key, fa_type_info in fa_taxonomy.items():
                if isinstance(fa_type_info, dict):
                    false_alarm_types[fa_type_key] = {
                        'count': fa_type_info.get('typical_features', {}).get('count', 2) if 'typical_features' in fa_type_info else (1 if 'type_3' in fa_type_key else 2),
                        'description': fa_type_info.get('description', ''),
                        'anomaly': fa_type_info.get('anomaly', ''),
                    }
            
            if false_alarm_types:
                return false_alarm_types
    except Exception as e:
        print(f"  Warning: Could not read false_alarm_taxonomy from global_constraints ({str(e)}). Using defaults.")
    
    # Fallback defaults (matches original hardcoded values)
    return {
        'type_1_unusual_port_benign_service': {
            'count': 2,
            'description': 'Unusual port + benign service (looks suspicious but harmless)',
            'anomaly': 'port',
        },
        'type_2_high_volume_benign_service': {
            'count': 2,
            'description': 'High volume + benign service (large transfer but harmless)',
            'anomaly': 'bytes',
        },
        'type_3_rare_duration_benign_service': {
            'count': 1,
            'description': 'Rare duration + benign service (long session but harmless)',
            'anomaly': 'duration',
        },
    }


# ============================================================
# CORE FUNCTIONS: Event Generation
# ============================================================

def generate_false_alarms_step_5(
    transformed_csv_path,
    templates_path,
    global_constraints_path,
    false_alarm_count_per_scenario=None,
    fa_type_ratio_mode="balanced",
    random_seed=42,
    output_debug=False
):
    """
    Main orchestrator for Step 5: Generate false alarm events for all scenarios.
    
    Args:
        transformed_csv_path (str): Path to UNSW_NB15_transformed.csv
        templates_path (str): Path to templates/zero_day_templates.json
        global_constraints_path (str): Path to templates/global_constraints.json
        false_alarm_count_per_scenario (dict): Map of scenario_name -> false_alarm_count
                                               If None, defaults to 5 for all scenarios
        fa_type_ratio_mode (str): Distribution mode for false alarm types
                                  One of: balanced | port_heavy | volume_heavy | duration_heavy
        random_seed (int): Seed for reproducibility
        output_debug (bool): Whether to output debug info
    
    Returns:
        dict: {
            'success': bool,
            'errors': [list of error strings],
            'false_alarm_events_per_scenario': {
                'WannaCry': [false alarm event dicts],
                'Data_Theft': [false alarm event dicts],
                ...
            }
        }
    """
    
    random.seed(random_seed)
    errors = []
    false_alarm_events_per_scenario = {}
    
    try:
        # Load transformed data
        transformed_df = pd.read_csv(transformed_csv_path)
        print(f"Loaded {len(transformed_df)} rows from transformed CSV")
        
        # Load templates and constraints
        templates_dict = load_templates(templates_path)
        with open(global_constraints_path, 'r') as f:
            global_constraints = json.load(f)
        
        # Extract pooled benign data (all scenarios combined) - UNSW-grounded
        pooled_benign_df = transformed_df[
            transformed_df['attack_cat'] == 'Normal'
        ].copy()
        
        if len(pooled_benign_df) == 0:
            errors.append("No benign (attack_cat='Normal') data found in transformed CSV")
            return {
                'success': False,
                'errors': errors,
                'false_alarm_events_per_scenario': {},
            }
        
        print(f"  Pooled benign data: {len(pooled_benign_df)} rows from all scenarios")
        
        # Calculate benign feature statistics (90th percentile for high-volume anomalies)
        benign_stats = _compute_benign_stats(pooled_benign_df)
        print(f"  Benign stats computed: bytes 90th percentile={benign_stats['bytes_90th']}, duration 90th percentile={benign_stats['duration_90th']}")
        
        # Get false alarm types from configuration
        false_alarm_types = get_false_alarm_types(global_constraints)
        print(f"  False alarm types loaded: {list(false_alarm_types.keys())}")
        
        # Generate false alarms for each scenario
        for scenario_name in SCENARIOS:
            print(f"\n  Generating false alarms for {scenario_name}...")
            
            try:
                scenario_template = get_scenario_by_name(templates_dict, scenario_name)
                if not scenario_template:
                    errors.append(f"Scenario {scenario_name} not found in templates")
                    continue
                
                # Get false alarm count from parameter or use default
                if false_alarm_count_per_scenario and scenario_name in false_alarm_count_per_scenario:
                    fa_count = false_alarm_count_per_scenario[scenario_name]
                else:
                    fa_count = 5  # Default for backwards compatibility
                
                # Generate false alarms with specified count and type distribution
                events = _generate_false_alarms_for_scenario(
                    scenario_name,
                    pooled_benign_df,
                    benign_stats,
                    scenario_template,
                    global_constraints,
                    false_alarm_count=fa_count,
                    fa_type_ratio_mode=fa_type_ratio_mode,
                    false_alarm_types=false_alarm_types
                )
                
                false_alarm_events_per_scenario[scenario_name] = events
                print(f"    [OK] Generated {len(events)} false alarm events")
                
            except Exception as e:
                errors.append(f"Error generating {scenario_name}: {str(e)}")
        
        # Validate all false alarms
        for scenario_name, events in false_alarm_events_per_scenario.items():
            fa_count = (false_alarm_count_per_scenario.get(scenario_name, 5) 
                       if false_alarm_count_per_scenario else 5)
            validation_errors = _validate_false_alarms(events, scenario_name, expected_count=fa_count)
            if validation_errors:
                errors.extend(validation_errors)
        
        # Update templates with false alarm events
        for scenario_dict in templates_dict['scenarios']:
            scenario_name = scenario_dict['scenario_name']
            if scenario_name in false_alarm_events_per_scenario:
                scenario_dict['_step5_false_alarm_events'] = false_alarm_events_per_scenario[scenario_name]
        
        # Save updated templates
        save_templates(templates_dict, templates_path)
        print(f"\nUpdated templates saved: {templates_path}")
        
        return {
            'success': len(errors) == 0,
            'errors': errors,
            'false_alarm_events_per_scenario': false_alarm_events_per_scenario,
        }
    
    except Exception as e:
        return {
            'success': False,
            'errors': [f"Step 5 fatal error: {str(e)}"],
            'false_alarm_events_per_scenario': {},
        }


def _compute_benign_stats(benign_df):
    """
    Compute statistics from benign UNSW data for anomaly thresholds.
    
    Args:
        benign_df (pd.DataFrame): Benign rows from all scenarios
    
    Returns:
        dict: Statistics with 90th percentiles for bytes and duration
    """
    stats = {
        'bytes_median': benign_df['bytes'].median(),
        'bytes_mean': benign_df['bytes'].mean(),
        'bytes_90th': benign_df['bytes'].quantile(0.90),
        'bytes_max': benign_df['bytes'].max(),
        'duration_median': benign_df['duration'].median(),
        'duration_mean': benign_df['duration'].mean(),
        'duration_90th': benign_df['duration'].quantile(0.90),
        'duration_max': benign_df['duration'].max(),
    }
    return stats


def _generate_false_alarms_for_scenario(scenario_name, pooled_benign_df, benign_stats, template, constraints, false_alarm_count=5, fa_type_ratio_mode="balanced", false_alarm_types=None):
    """
    Generate false alarm events for a single scenario.
    
    Strategy:
    - Distribute false_alarm_count across 3 types using fa_type_ratio_mode
    - Type 1: Unusual port + benign service (uses benign UNSW row as template)
    - Type 2: High volume + benign service (high bytes, otherwise benign features)
    - Type 3: Rare duration + benign service (high duration, otherwise benign features)
    - All events marked as attack_cat='Normal', label='False Alarm'
    - Spread timestamps across [0, 1800] seconds
    
    Args:
        scenario_name (str): Scenario name
        pooled_benign_df (pd.DataFrame): Benign rows from all scenarios combined
        benign_stats (dict): Computed stats from benign data
        template (dict): Scenario template
        constraints (dict): Global constraints
        false_alarm_count (int): Total number of false alarm events to generate (default: 5)
        fa_type_ratio_mode (str): Distribution mode for types. Default: "balanced" (40:40:20)
        false_alarm_types (dict): False alarm types config (from JSON). If None, uses defaults.
    
    Returns:
        list: False alarm event dictionaries (may be empty if false_alarm_count=0)
    """
    
    # Use provided false_alarm_types or get defaults from constraints
    if false_alarm_types is None:
        false_alarm_types = get_false_alarm_types(constraints)
    
    # Handle edge case: no false alarms requested
    if false_alarm_count == 0:
        return []
    
    # Type distribution ratios (default balanced: 40% Type1, 40% Type2, 20% Type3)
    type_ratios = {
        "balanced": {"type_1": 0.4, "type_2": 0.4, "type_3": 0.2},
        "port_heavy": {"type_1": 0.6, "type_2": 0.2, "type_3": 0.2},
        "volume_heavy": {"type_1": 0.2, "type_2": 0.6, "type_3": 0.2},
        "duration_heavy": {"type_1": 0.2, "type_2": 0.2, "type_3": 0.6},
    }
    
    # Get distribution for this mode (default to balanced if invalid)
    distribution = type_ratios.get(fa_type_ratio_mode, type_ratios["balanced"])
    
    # Compute type counts from distribution
    type_1_count = int(false_alarm_count * distribution["type_1"])
    type_2_count = int(false_alarm_count * distribution["type_2"])
    type_3_count = false_alarm_count - type_1_count - type_2_count  # Remainder
    
    # Sample required number of benign rows as templates
    num_templates = min(false_alarm_count, len(pooled_benign_df))
    if num_templates == 0:
        return []
    
    if len(pooled_benign_df) < num_templates:
        sampled_df = pooled_benign_df.copy()
    else:
        sampled_df = pooled_benign_df.sample(n=num_templates, random_state=None)
    
    sampled_df = sampled_df.reset_index(drop=True)
    
    # Generate timestamps spread across [0, 1800]
    timestamps = sorted([random.uniform(0, 1800) for _ in range(false_alarm_count)])
    
    events = []
    event_idx = 0
    
    # Type 1: Unusual Port + Benign Service
    type1_count = false_alarm_types.get('type_1_unusual_port_benign_service', {}).get('count', 2)
    for i in range(type1_count):
        if event_idx < len(sampled_df):
            row = sampled_df.iloc[event_idx]
            event = _generate_type1_unusual_port(
                scenario_name, row, timestamps[event_idx], benign_stats
            )
            events.append(event)
            event_idx += 1
    
    # Type 2: High Volume + Benign Service
    type2_count = false_alarm_types.get('type_2_high_volume_benign_service', {}).get('count', 2)
    for i in range(type2_count):
        if event_idx < len(sampled_df):
            row = sampled_df.iloc[event_idx]
            event = _generate_type2_high_volume(
                scenario_name, row, timestamps[event_idx], benign_stats
            )
            events.append(event)
            event_idx += 1
    
    # Type 3: Rare Duration + Benign Service
    type3_count = false_alarm_types.get('type_3_rare_duration_benign_service', {}).get('count', 1)
    for i in range(type3_count):
        if event_idx < len(sampled_df):
            row = sampled_df.iloc[event_idx]
            event = _generate_type3_rare_duration(
                scenario_name, row, timestamps[event_idx], benign_stats
            )
            events.append(event)
            event_idx += 1
    
    return events


def _generate_type1_unusual_port(scenario_name, base_row, timestamp, benign_stats):
    """
    Generate Type 1 false alarm: Unusual port + benign service.
    
    Anomaly: High port number (ephemeral/unusual) communicates with benign service.
    
    Args:
        scenario_name (str): Scenario name
        base_row (pd.Series): UNSW row used as template
        timestamp (float): Timestamp [0, 1800]
        benign_stats (dict): Benign statistics
    
    Returns:
        dict: Event dictionary
    """
    
    # Choose a benign service (DNS, HTTP, etc.)
    benign_service = random.choice(['dns', 'http', 'smtp'])
    
    # Unusual port: high ephemeral range instead of standard port
    dport = random.randint(10000, 65535)  # Unusual/rare port
    
    # Source and destination
    src_host = get_random_internal_host_excluding_defender(['Enterprise'])
    src_subnet = map_subnet(src_host)
    src_ip = get_deterministic_ip_for_host(scenario_name, src_host)
    
    dst_host = f"external_{random.randint(1, 100)}"
    dst_subnet = 'External'
    dst_ip = f"203.0.{random.randint(0, 255)}.{random.randint(1, 254)}"
    
    # Features from UNSW template
    duration = base_row.get('duration', 0.5)
    bytes_total = max(base_row.get('sbytes', 100) + base_row.get('dbytes', 100), 100)
    packets_total = max(base_row.get('spkts', 5) + base_row.get('dpkts', 5), 5)
    
    # Keep duration and bytes within normal ranges (not anomalous in those dimensions)
    duration = max(0.1, min(benign_stats['duration_90th'], duration))
    bytes_total = max(100, min(benign_stats['bytes_90th'], bytes_total))
    
    event = {
        'timestamp': timestamp,
        'src_host': src_host,
        'dst_host': dst_host,
        'src_subnet': src_subnet,
        'dst_subnet': dst_subnet,
        'proto': 'tcp',
        'sport': random.randint(1024, 65535),
        'dport': dport,
        'service': benign_service,
        'duration': duration,
        'bytes': bytes_total,
        'packets': packets_total,
        'sttl': 64,
        'dttl': 64,
        'state': 'CON',
        'sloss': 0,
        'dloss': 0,
        'ct_src_dport_ltm': 1,
        'ct_dst_src_ltm': 1,
        'attack_cat': 'Normal',
        'label': 'False Alarm',
        '_unsw_row_id': -1,
        'scenario_name': 'unknown',
        '_source': 'synthetic_false_alarm_type1',
    }
    
    # Validate
    if not validate_host(event['src_host']):
        raise ValueError(f"Invalid src_host: {event['src_host']}")
    if not validate_subnet(event['src_subnet']):
        raise ValueError(f"Invalid src_subnet: {event['src_subnet']}")
    
    return event


def _generate_type2_high_volume(scenario_name, base_row, timestamp, benign_stats):
    """
    Generate Type 2 false alarm: High volume + benign service.
    
    Anomaly: Very large data transfer on benign service port.
    
    Args:
        scenario_name (str): Scenario name
        base_row (pd.Series): UNSW row used as template
        timestamp (float): Timestamp [0, 1800]
        benign_stats (dict): Benign statistics
    
    Returns:
        dict: Event dictionary
    """
    
    # Benign service at standard port
    benign_service = random.choice(['dns', 'smtp'])
    dport = {'dns': 53, 'smtp': 25}[benign_service]
    
    # Source and destination
    src_host = get_random_internal_host_excluding_defender(['User', 'Enterprise'])
    src_subnet = map_subnet(src_host)
    src_ip = get_deterministic_ip_for_host(scenario_name, src_host)
    
    dst_host = f"external_{random.randint(1, 100)}"
    dst_subnet = 'External'
    dst_ip = f"203.0.{random.randint(0, 255)}.{random.randint(1, 254)}"
    
    # Features: ANOMALOUS bytes (high volume), normal duration
    duration = base_row.get('duration', 5.0)
    bytes_total = int(benign_stats['bytes_90th'] * random.uniform(2, 5))  # 2-5x the normal high
    packets_total = max(int(bytes_total / 500), 10)  # Scale packets with bytes
    
    # Keep duration normal
    duration = max(1, min(benign_stats['duration_90th'], duration))
    
    event = {
        'timestamp': timestamp,
        'src_host': src_host,
        'dst_host': dst_host,
        'src_subnet': src_subnet,
        'dst_subnet': dst_subnet,
        'proto': 'tcp',
        'sport': random.randint(1024, 65535),
        'dport': dport,
        'service': benign_service,
        'duration': duration,
        'bytes': bytes_total,
        'packets': packets_total,
        'sttl': 64,
        'dttl': 64,
        'state': 'CON',
        'sloss': 0,
        'dloss': 0,
        'ct_src_dport_ltm': 1,
        'ct_dst_src_ltm': 1,
        'attack_cat': 'Normal',
        'label': 'False Alarm',
        '_unsw_row_id': -1,
        'scenario_name': 'unknown',
        '_source': 'synthetic_false_alarm_type2',
    }
    
    # Validate
    if not validate_host(event['src_host']):
        raise ValueError(f"Invalid src_host: {event['src_host']}")
    if not validate_subnet(event['src_subnet']):
        raise ValueError(f"Invalid src_subnet: {event['src_subnet']}")
    
    return event


def _generate_type3_rare_duration(scenario_name, base_row, timestamp, benign_stats):
    """
    Generate Type 3 false alarm: Rare duration + benign service.
    
    Anomaly: Unusually long/short duration for benign service.
    
    Args:
        scenario_name (str): Scenario name
        base_row (pd.Series): UNSW row used as template
        timestamp (float): Timestamp [0, 1800]
        benign_stats (dict): Benign statistics
    
    Returns:
        dict: Event dictionary
    """
    
    # Benign service (SSH is often used for long sessions)
    benign_service = 'ssh_admin'
    dport = 22
    
    # Source and destination
    src_host = get_random_internal_host_excluding_defender(['Enterprise'])
    src_subnet = map_subnet(src_host)
    src_ip = get_deterministic_ip_for_host(scenario_name, src_host)
    
    dst_host = f"external_{random.randint(1, 100)}"
    dst_subnet = 'External'
    dst_ip = f"203.0.{random.randint(0, 255)}.{random.randint(1, 254)}"
    
    # Features: ANOMALOUS duration (very long), normal bytes
    duration = benign_stats['duration_90th'] * random.uniform(3, 10)  # 3-10x the high percentile
    bytes_total = base_row.get('sbytes', 1000) + base_row.get('dbytes', 1000)
    packets_total = base_row.get('spkts', 20) + base_row.get('dpkts', 20)
    
    # Keep bytes normal
    bytes_total = max(100, min(benign_stats['bytes_90th'], bytes_total))
    
    event = {
        'timestamp': timestamp,
        'src_host': src_host,
        'dst_host': dst_host,
        'src_subnet': src_subnet,
        'dst_subnet': dst_subnet,
        'proto': 'tcp',
        'sport': random.randint(1024, 65535),
        'dport': dport,
        'service': benign_service,
        'duration': duration,
        'bytes': bytes_total,
        'packets': packets_total,
        'sttl': 64,
        'dttl': 64,
        'state': 'CON',
        'sloss': 0,
        'dloss': 0,
        'ct_src_dport_ltm': 1,
        'ct_dst_src_ltm': 1,
        'attack_cat': 'Normal',
        'label': 'False Alarm',
        '_unsw_row_id': -1,
        'scenario_name': 'unknown',
        '_source': 'synthetic_false_alarm_type3',
    }
    
    # Validate
    if not validate_host(event['src_host']):
        raise ValueError(f"Invalid src_host: {event['src_host']}")
    if not validate_subnet(event['src_subnet']):
        raise ValueError(f"Invalid src_subnet: {event['src_subnet']}")
    
    return event


def _validate_false_alarms(events, scenario_name, expected_count=5):
    """
    Validate false alarm events.
    
    Basic check: All false alarms must have attack_cat='Normal' and label='False Alarm'.
    
    Args:
        events (list): False alarm events
        scenario_name (str): Scenario name
        expected_count (int): Expected number of false alarm events (default: 5, backwards compatible)
    
    Returns:
        list: List of error strings (empty if all valid)
    """
    errors = []
    
    if expected_count == 0:
        # If no false alarms expected, that's valid
        if len(events) == 0:
            return errors
        else:
            errors.append(f"{scenario_name}: Expected 0 false alarms but got {len(events)}")
            return errors
    
    if not events:
        errors.append(f"{scenario_name}: No false alarm events generated (expected {expected_count})")
        return errors
    
    # Check that all have attack_cat='Normal'
    normal_count = sum(1 for e in events if e.get('attack_cat') == 'Normal')
    if normal_count != len(events):
        errors.append(
            f"{scenario_name}: {len(events) - normal_count} false alarms missing attack_cat='Normal'"
        )
    
    # Check count (allow for small rounding differences)
    if len(events) != expected_count:
        errors.append(f"{scenario_name}: Expected {expected_count} false alarms, got {len(events)}")
    
    return errors



