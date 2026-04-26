"""
Step 3: Generate Malicious Events
Purpose: Create 10-11 realistic malicious events per scenario using tiered synthesis
         with scenario-aware phase-based causality.
"""

import pandas as pd
import json
import random
import hashlib
from pathlib import Path
from helper_functions import (
    map_ip_to_host,
    map_subnet,
    infer_service_from_port,
    SCENARIOS,
    FIXED_HOST_IPS,
    load_templates,
    save_templates,
    get_scenario_by_name,
    validate_malicious_event_hosts,
    get_deterministic_ip_for_host,
)


# ============================================================
# PHASE DEFINITIONS PER SCENARIO (Feature generation uses scenario templates)
# ============================================================

PHASE_TIMELINE = {
    'initial_access': (300, 350),     # ~T=300–350s, initial compromise
    'progression': (350, 600),        # ~T=350–600s, lateral movement/reconnaissance
    'objective': (600, 900),          # ~T=600–900s, target reached, data exfiltration
}

SCENARIO_PHASES = {
    'WannaCry': {
        'phases': ['initial_access', 'progression', 'progression', 'objective'],
        'description': 'Scanning → Exploitation → Propagation',
        'port_primary': 445,
        'byte_trend': 'increasing',  # Payloads get larger
    },
    'Data_Theft': {
        'phases': ['initial_access', 'progression', 'progression', 'objective'],
        'description': 'Initial Access → File Staging → Compression → Exfiltration',
        'port_primary': [21, 22],  # FTP/SCP
        'byte_trend': 'high',      # Large file transfers expected
    },
    'ShellShock': {
        'phases': ['initial_access', 'progression', 'progression', 'objective'],
        'description': 'HTTP Request → Bash Execution → Data Access',
        'port_primary': 80,
        'byte_trend': 'moderate',  # HTTP responses
    },
    'Netcat_Backdoor': {
        'phases': ['initial_access', 'progression', 'progression', 'objective'],
        'description': 'Initial Access → Installation → Connections → Commands',
        'port_primary': range(10000, 20000),  # High-numbered ephemeral ports
        'byte_trend': 'low',  # Command/response traffic
    },
    'passwd_gzip_scp': {
        'phases': ['initial_access', 'progression', 'progression', 'objective'],
        'description': 'System Access → File Access → Compression → SCP Transfer',
        'port_primary': 22,  # SSH/SCP
        'byte_trend': 'moderate',  # File transfer
    },
}


# ============================================================
# CORE FUNCTIONS: Event Generation
# ============================================================

def generate_malicious_events_step_3(
    transformed_csv_path,
    templates_path,
    global_constraints_path,
    network_topology=None,
    malicious_count_per_scenario=None,
    random_seed=42,
    output_debug=False
):
    """
    Main orchestrator for Step 3: Generate malicious events for all scenarios.
    
    Args:
        transformed_csv_path (str): Path to UNSW_NB15_transformed.csv
        templates_path (str): Path to templates/zero_day_templates.json
        global_constraints_path (str): Path to templates/global_constraints_v2.json
        network_topology (dict, optional): Loaded network_topology_output.json for AWS topology validation
        malicious_count_per_scenario (dict): Map of scenario_name -> malicious_count
                                             If None, derives from templates (backwards compatible)
        random_seed (int): Seed for reproducibility
        output_debug (bool): Whether to output debug info
    
    Returns:
        dict: {
            'success': bool,
            'errors': [list of error strings],
            'malicious_events_per_scenario': {
                'WannaCry': [malicious event dicts],
                'Data_Theft': [malicious event dicts],
                ...
            }
        }
    """
    
    random.seed(random_seed)
    errors = []
    malicious_events_per_scenario = {}
    
    try:
        # Load transformed data
        transformed_df = pd.read_csv(transformed_csv_path)
        print(f"Loaded {len(transformed_df)} rows from transformed CSV")
        
        # Load templates and constraints
        templates_dict = load_templates(templates_path)
        with open(global_constraints_path, 'r') as f:
            global_constraints = json.load(f)
        
        # Generate malicious events for each scenario
        for scenario_name in SCENARIOS:
            print(f"\n  Generating malicious events for {scenario_name}...")
            
            try:
                scenario_template = get_scenario_by_name(templates_dict, scenario_name)
                if not scenario_template:
                    errors.append(f"Scenario {scenario_name} not found in templates")
                    continue
                
                # Get malicious count (check early, skip if none)
                if malicious_count_per_scenario and scenario_name in malicious_count_per_scenario:
                    mal_count = malicious_count_per_scenario[scenario_name]
                else:
                    mal_count = scenario_template.get('malicious_count', 11)
                
                # SKIP scenarios with no malicious events (e.g., No_Attack)
                if mal_count == 0:
                    print(f"    [SKIPPED] No malicious events to generate")
                    malicious_events_per_scenario[scenario_name] = []
                    continue
                
                # Filter UNSW data for this scenario
                scenario_df = transformed_df[
                    transformed_df['scenario_name'] == scenario_name
                ].copy()
                
                if len(scenario_df) == 0:
                    errors.append(f"No UNSW data for scenario {scenario_name}")
                    continue
                
                # Get tier classification and feature stats from Step 2
                expected_tier = scenario_template.get('expected_tier', 1)
                step2_stats = scenario_template.get('_step2_stats', {})
                
                # Generate events (TIER 1 uses real data, TIER 2 adds parameterized)
                if expected_tier == 1:
                    events = _generate_tier1_events(
                        scenario_name,
                        scenario_df,
                        scenario_template,
                        step2_stats,
                        malicious_count=mal_count,
                        network_topology=network_topology
                    )
                else:
                    events = _generate_tier2_events(
                        scenario_name,
                        scenario_df,
                        scenario_template,
                        step2_stats,
                        malicious_count=mal_count,
                        network_topology=network_topology
                    )
                
                malicious_events_per_scenario[scenario_name] = events
                print(f"    [OK] Generated {len(events)} malicious events")
                
            except Exception as e:
                errors.append(f"Error generating {scenario_name}: {str(e)}")
        
        # Update templates with malicious events (for later steps)
        for scenario_dict in templates_dict['scenarios']:
            scenario_name = scenario_dict['scenario_name']
            if scenario_name in malicious_events_per_scenario:
                scenario_dict['_step3_malicious_events'] = malicious_events_per_scenario[scenario_name]
        
        # Save updated templates
        save_templates(templates_dict, templates_path)
        print(f"\nUpdated templates saved: {templates_path}")
        
        return {
            'success': len(errors) == 0,
            'errors': errors,
            'malicious_events_per_scenario': malicious_events_per_scenario,
        }
    
    except Exception as e:
        return {
            'success': False,
            'errors': [f"Step 3 fatal error: {str(e)}"],
            'malicious_events_per_scenario': {},
        }


def _generate_tier1_events(scenario_name, filtered_df, template, stats, malicious_count=11, network_topology=None):
    """
    TIER 1 (≥10 UNSW rows): Sample real events from filtered UNSW.
    
    Args:
        scenario_name (str): Scenario name (e.g., 'WannaCry')
        filtered_df (pd.DataFrame): Filtered UNSW rows for this scenario
        template (dict): Scenario template with entry_point, target_asset
        stats (dict): Feature statistics from Step 2
        malicious_count (int): Number of malicious events to generate
        network_topology (dict, optional): Loaded network_topology_output.json for concrete IPs
    
    Returns:
        list: Malicious event dictionaries
    """
    
    # Sample the specified number of events (or fewer if not enough data)
    num_events = min(malicious_count, len(filtered_df))
    if len(filtered_df) < num_events:
        sampled_df = filtered_df.copy()
    else:
        sampled_df = filtered_df.sample(n=num_events, random_state=None)
    
    sampled_df = sampled_df.reset_index(drop=True)
    
    # Assign to phases
    events_by_phase = _assign_events_to_phases(scenario_name, sampled_df, template, network_topology=network_topology)
    
    # Order within phases and generate timestamps
    all_events = []
    for phase_name, events_in_phase in events_by_phase.items():
        phase_start, phase_end = PHASE_TIMELINE[phase_name]
        
        # Order events within phase with timestamps
        for event_idx, event_row in enumerate(events_in_phase):
            timestamp = phase_start + (event_idx * ((phase_end - phase_start) / (len(events_in_phase) + 1)))
            
            event_dict = _row_to_event(
                row=event_row,
                scenario_name=scenario_name,
                timestamp=timestamp,
                phase=phase_name,
                source='UNSW_actual',
                template=template,
                network_topology=network_topology
            )
            all_events.append(event_dict)
    
    # Sort by timestamp
    all_events.sort(key=lambda e: e['timestamp'])
    
    return all_events


def _generate_tier2_events(scenario_name, filtered_df, template, stats, malicious_count=11, network_topology=None):
    """
    TIER 2 (<10 UNSW rows): Use available data + parameterized variations.
    
    Args:
        scenario_name (str): Scenario name
        filtered_df (pd.DataFrame): Limited UNSW rows for this scenario
        template (dict): Scenario template
        stats (dict): Feature statistics from Step 2
        malicious_count (int): Number of malicious events to generate
        network_topology (dict, optional): Loaded network_topology_output.json for concrete IPs
    
    Returns:
        list: Malicious event dictionaries (mix of actual + parameterized)
    """
    
    # Keep all actual rows
    actual_rows = filtered_df.copy().reset_index(drop=True)
    num_actual = len(actual_rows)
    num_needed = malicious_count
    num_parameterized = max(0, num_needed - num_actual)
    
    # Create parameterized variations
    parameterized_rows = []
    for i in range(num_parameterized):
        base_row = actual_rows.sample(n=1).iloc[0].copy()
        
        # Perturb features
        base_row['duration'] = base_row['duration'] * random.uniform(0.8, 1.2)
        base_row['bytes'] = int(base_row['bytes'] * random.uniform(0.85, 1.15))
        base_row['packets'] = max(1, int(base_row['packets'] * random.uniform(0.85, 1.15)))
        
        # Vary source/dest host within same subnet (if applicable)
        base_row['src_host'] = base_row['src_host']  # Keep for now
        base_row['dst_host'] = base_row['dst_host']
        
        parameterized_rows.append(base_row)
    
    # Combine actual + parameterized
    combined_df = pd.concat(
        [actual_rows, pd.DataFrame(parameterized_rows)],
        ignore_index=True
    )
    
    # Assign to phases and order
    events_by_phase = _assign_events_to_phases(scenario_name, combined_df, template, network_topology=network_topology)
    
    all_events = []
    for phase_name, events_in_phase in events_by_phase.items():
        phase_start, phase_end = PHASE_TIMELINE[phase_name]
        
        for event_idx, event_row in enumerate(events_in_phase):
            timestamp = phase_start + (event_idx * ((phase_end - phase_start) / (len(events_in_phase) + 1)))
            
            # Mark as parameterized if from synthetic row
            source = 'UNSW_parameterized' if event_idx >= num_actual else 'UNSW_actual'
            
            event_dict = _row_to_event(
                row=event_row,
                scenario_name=scenario_name,
                timestamp=timestamp,
                phase=phase_name,
                source=source,
                template=template,
                network_topology=network_topology
            )
            all_events.append(event_dict)
    
    all_events.sort(key=lambda e: e['timestamp'])
    
    return all_events


def _assign_events_to_phases(scenario_name, rows_df, template, network_topology=None):
    """
    Assign UNSW rows to attack phases based on scenario-specific logic.
    
    Args:
        scenario_name (str): Scenario name
        rows_df (pd.DataFrame): UNSW rows to assign
        template (dict): Scenario template
        network_topology (dict, optional): Loaded network_topology_output.json for concrete IPs
    
    Returns:
        dict: {phase_name: [list of rows for that phase]}
    """
    
    phases_order = SCENARIO_PHASES[scenario_name]['phases']
    rows_list = rows_df.to_dict('records')
    
    # Assign rows to phases sequentially
    events_by_phase = {phase: [] for phase in set(phases_order)}
    
    # Simple assignment: distribute rows across phases in order
    rows_per_phase = len(rows_list) / len(phases_order)
    
    row_idx = 0
    for phase_idx, phase_name in enumerate(phases_order):
        phase_end_idx = int((phase_idx + 1) * rows_per_phase)
        while row_idx < phase_end_idx and row_idx < len(rows_list):
            events_by_phase[phase_name].append(rows_list[row_idx])
            row_idx += 1
    
    return events_by_phase


def _row_to_event(row, scenario_name, timestamp, phase, source, template=None, network_topology=None):
    """
    Convert UNSW row to malicious event dictionary (preserves ALL 23 columns).
    Enforces scenario-specific entry_point and target_asset constraints.
    Uses concrete IPs from network_topology when available.
    
    Args:
        row (dict or pd.Series): UNSW row
        scenario_name (str): Scenario name
        timestamp (float): Event timestamp in seconds
        phase (str): Attack phase name
        source (str): 'UNSW_actual' or 'UNSW_parameterized'
        template (dict, optional): Scenario template
        network_topology (dict, optional): Loaded network_topology_output.json for concrete IPs
    
    Returns:
        dict: Event dictionary with all 23 required columns
    """
    
    if isinstance(row, pd.Series):
        row = row.to_dict()
    
    # Determine source/dest hosts using deterministic mapping
    src_ip = row.get('src_host', 'unknown')
    dst_ip = row.get('dst_host', 'unknown')
    
    try:
        src_host, src_subnet = map_ip_to_host(src_ip, scenario_name)
    except:
        src_host, src_subnet = 'User0', 'Subnet 1 (User)'
    
    try:
        dst_host, dst_subnet = map_ip_to_host(dst_ip, scenario_name)
    except:
        dst_host, dst_subnet = 'Enterprise0', 'Subnet 2 (Enterprise)'
    
    # ENFORCE ENTRY POINT CONSTRAINTS (from scenario template)
    if template and phase in ['initial_access', 'progression', 'objective']:
        entry_host = template.get('entry_point', {}).get('host')
        target_host = template.get('target_asset', {}).get('host')
        
        if phase == 'initial_access' and entry_host:
            # Initial access MUST originate from entry point
            src_host = entry_host
            src_subnet = map_subnet(src_host)
            src_ip = get_deterministic_ip_for_host(scenario_name, src_host, network_topology=network_topology)
        
        elif phase == 'progression' and entry_host:
            # Progression is lateral movement FROM entry point
            src_host = entry_host
            src_subnet = map_subnet(src_host)
            src_ip = get_deterministic_ip_for_host(scenario_name, src_host, network_topology=network_topology)
        
        elif phase == 'objective' and target_host:
            # Objective phase targets the final asset
            dst_host = target_host
            dst_subnet = map_subnet(dst_host)
            dst_ip = get_deterministic_ip_for_host(scenario_name, dst_host, network_topology=network_topology)
        
        # Validate routing constraints
        if not validate_malicious_event_hosts(src_host, dst_host, scenario_name):
            # If path violates routing, adjust to intermediate gateway
            if 'User' in src_subnet and 'Operational' in dst_subnet:
                dst_host = 'Enterprise2'
                dst_subnet = map_subnet(dst_host)
                dst_ip = get_deterministic_ip_for_host(scenario_name, dst_host, network_topology=network_topology)
    
    # Extract key features
    dport = int(row.get('dport', 0))
    service = infer_service_from_port(dport)
    
    event = {
        'timestamp': timestamp,
        'src_host': src_host,
        'dst_host': dst_host,
        'src_subnet': src_subnet,
        'dst_subnet': dst_subnet,
        'proto': row.get('proto', 'tcp'),
        'sport': int(row.get('sport', 0)),
        'dport': dport,
        'service': service,
        'duration': float(row.get('duration', 0.0)),
        'bytes': int(row.get('bytes', 0)),
        'packets': int(row.get('packets', 0)),
        'sttl': int(row.get('sttl', 64)),
        'dttl': int(row.get('dttl', 64)),
        'state': row.get('state', 'CON'),
        'sloss': int(row.get('sloss', 0)),
        'dloss': int(row.get('dloss', 0)),
        'ct_src_dport_ltm': int(row.get('ct_src_dport_ltm', 1)),
        'ct_dst_src_ltm': int(row.get('ct_dst_src_ltm', 1)),
        'attack_cat': row.get('attack_cat', 'Unknown'),
        'label': 'Malicious',
        '_unsw_row_id': int(row.get('_unsw_row_id', -1)),
        'scenario_name': scenario_name,
        'phase': phase,
        '_source': source,
    }
    
    return event
