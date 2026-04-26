"""
Step 6: Assemble Final IDS Tables with Temporal Ordering and Dynamic Phase Allocation
Purpose: Combine malicious (scenario-specific), benign (parameterized), and false alarm (parameterized) events.
         Assign timestamps using phase architecture.
         Output final CSV tables (23 columns: 21 schema + 2 tracking).

Temporal Architecture (all scenarios):
  - Fixed: 5 phases distributed over 1800s observation window (0-300s, 300-600s, 600-900s, 900-1200s, 1200-1800s)
  - Dynamic: Phase event_count allocations computed based on actual malicious/benign/false_alarm counts
  - Benign baseline and recovery phases preserve minimum viable coverage
  - Attack phases scale with malicious_count parameter
  - False alarm events distributed in recovery phase based on false_alarm_count parameter

Parameterization Note:
  - Malicious event count: Fixed per scenario template (WannaCry=11, Data_Theft=9, ShellShock=9, etc.)
  - Benign event count: Computed as (TOTAL_EVENTS_PER_TABLE - malicious - false_alarm)
  - False alarm event count: Computed as round(TOTAL_EVENTS_PER_TABLE × FALSE_ALARM_BIN_PCT)
  - Phase event_count slots: Dynamically allocated based on above values (see get_temporal_architecture())
"""

import pandas as pd
import json
import random
from pathlib import Path
from helper_functions import (
    load_templates,
    save_templates,
    get_scenario_by_name,
    SCENARIOS,
)
from pathlib import Path


# ============================================================
# TEMPORAL ARCHITECTURE: Read from templates & constraints
# ============================================================

def get_temporal_architecture(scenario_template, global_constraints, 
                               malicious_count=None, benign_count=None, 
                               false_alarm_count=None):
    """
    Extract temporal architecture for a scenario with DYNAMIC phase allocation.
    
    CHANGED: Now accepts event count parameters to dynamically allocate phase slots.
    Instead of hardcoding 6+4+4+2+9=25 event slots (only works for total=30),
    this function now scales phase slots based on actual event counts passed.
    
    - Phases come from scenario template (zero_day_templates.json)
    - False alarm zones come from global_constraints.json
    - Phase event_count allocations are NOW COMPUTED based on event parameters
    
    Args:
        scenario_template (dict): Scenario from zero_day_templates.json
        global_constraints (dict): Global constraints configuration
        malicious_count (int): Number of malicious events (required for dynamic allocation)
        benign_count (int): Number of benign events (required for dynamic allocation)
        false_alarm_count (int): Number of false alarm events (optional, for phase distribution info)
    
    Returns:
        dict: Temporal architecture with phases and false_alarm_zones
    """
    phases = []
    false_alarm_zones = [(600, 700), (1200, 1300), (1400, 1500)]  # Default zones
    
    # NEW: Compute total events from passed parameters
    total_events = (malicious_count or 0) + (benign_count or 0) + (false_alarm_count or 0)
    
    try:
        # Read phases from scenario template
        if scenario_template and 'temporal_architecture' in scenario_template:
            scenario_ta = scenario_template['temporal_architecture']
            if 'phases' in scenario_ta:
                phases = scenario_ta.get('phases', [])
    except Exception as e:
        print(f"  Warning: Could not read phases from template ({str(e)}). Using dynamic defaults.")
    
    # If no phases from template, use DYNAMIC fallback based on event counts
    if not phases:
        # CHANGED: Instead of hardcoding 6+4+4+2+9=25 slots,
        # dynamically allocate based on actual event counts
        
        if total_events > 0:
            # Allocate phase slots proportionally to event counts
            # Phase 1 (baseline): 25-30% of benign
            # Phases 2-4 (attack): 100% of malicious
            # Phase 5 (recovery): 70-75% of benign + false alarms
            
            baseline_benign = max(2, int(benign_count * 0.25) if benign_count else 1)
            recovery_benign = max(2, (benign_count or 0) - baseline_benign)
            
            # Distribute malicious across 3 attack phases (roughly 40:40:20 ratio)
            attack_1 = int((malicious_count or 0) * 0.40)
            attack_2 = int((malicious_count or 0) * 0.40)
            attack_3 = max(0, (malicious_count or 0) - attack_1 - attack_2)
            
            phases = [
                {'name': 'benign_baseline', 'start': 0, 'end': 300, 'type': 'benign', 
                 'event_count': baseline_benign},
                {'name': 'attack_phase_1', 'start': 300, 'end': 600, 'type': 'attack', 
                 'event_count': attack_1},
                {'name': 'attack_phase_2', 'start': 600, 'end': 900, 'type': 'attack', 
                 'event_count': attack_2},
                {'name': 'attack_phase_3', 'start': 900, 'end': 1200, 'type': 'attack', 
                 'event_count': attack_3},
                {'name': 'benign_recovery', 'start': 1200, 'end': 1800, 'type': 'benign', 
                 'event_count': recovery_benign + (false_alarm_count or 0)},
            ]
        else:
            # Fallback for edge case where all counts are zero
            phases = [
                {'name': 'benign_baseline', 'start': 0, 'end': 300, 'type': 'benign', 'event_count': 0},
                {'name': 'attack_phase_1', 'start': 300, 'end': 600, 'type': 'attack', 'event_count': 0},
                {'name': 'attack_phase_2', 'start': 600, 'end': 900, 'type': 'attack', 'event_count': 0},
                {'name': 'attack_phase_3', 'start': 900, 'end': 1200, 'type': 'attack', 'event_count': 0},
                {'name': 'benign_recovery', 'start': 1200, 'end': 1800, 'type': 'benign', 'event_count': 0},
            ]
    
    # Read false_alarm_zones from global_constraints (not from template)
    try:
        if global_constraints and 'temporal_architecture_principles' in global_constraints:
            tap = global_constraints['temporal_architecture_principles']
            # Look for false_alarm_placement description; extract zone timestamps
            # Expected format: "Scattered in temporally isolated zones (NOT adjacent to malicious chain); typically 600-700s and 1200-1300s"
            # Default zones are hardcoded above; config just documents the expected zones
    except Exception as e:
        print(f"  Warning: Could not read false_alarm zones from global_constraints ({str(e)}). Using defaults.")
    
    return {
        'total_duration': 1800,
        'phases': phases,
        'false_alarm_zones': false_alarm_zones,
    }


# ============================================================
# CORE FUNCTIONS: Event Assembly & Timestamping
# ============================================================

def assign_timestamps_to_events(
    malicious_events,
    benign_events,
    false_alarm_events,
    scenario_name,
    scenario_template=None,
    global_constraints=None,
    random_seed=42,
):
    """
    Assign timestamps to all events based on phase architecture.
    Dynamically allocates actual event counts across phases.
    
    Args:
        malicious_events (list): List of malicious event dicts
        benign_events (list): List of benign event dicts
        false_alarm_events (list): List of false alarm event dicts
        scenario_name (str): Scenario name (used to index TEMPORAL_ARCHITECTURE)
        scenario_template (dict): Scenario template (to read temporal_architecture from)
        global_constraints (dict): Global constraints (fallback for architecture)
        random_seed (int): Seed for reproducibility
        
    Returns:
        list: All events with timestamps assigned, sorted chronologically
        
    Raises:
        ValueError: If event counts don't match architecture
    """
    random.seed(random_seed)
    timestamped_events = []
    
    # Get temporal architecture from template with DYNAMIC phase allocation
    # Now pass actual event counts so phases scale correctly
    malicious_count = len(malicious_events) if malicious_events else 0
    benign_count = len(benign_events) if benign_events else 0
    false_alarm_count = len(false_alarm_events) if false_alarm_events else 0
    
    if scenario_template:
        arch = get_temporal_architecture(
            scenario_template, global_constraints or {},
            malicious_count=malicious_count,
            benign_count=benign_count,
            false_alarm_count=false_alarm_count
        )
    else:
        arch = get_temporal_architecture(
            {}, global_constraints or {},
            malicious_count=malicious_count,
            benign_count=benign_count,
            false_alarm_count=false_alarm_count
        )
    
    phases = arch['phases']
    
    # Count attack and benign phases to determine distribution
    # Infer type from phase name if 'type' key is missing
    def get_phase_type(phase):
        if 'type' in phase:
            return phase['type']
        # Infer from name using multiple strategies
        name = phase.get('name', '').lower()
        # Check for explicit keywords
        if 'attack' in name or 'initial_access' in name or 'lateral_movement' in name or 'objective_execution' in name:
            return 'attack'
        # Baseline and recovery phases are benign
        if 'baseline' in name or 'recovery' in name:
            return 'benign'
        # Default to benign
        return 'benign'
    
    attack_phases = [p for p in phases if get_phase_type(p) == 'attack']
    benign_phases = [p for p in phases if get_phase_type(p) == 'benign']
    
    # Distribute malicious events across attack phases evenly
    mal_per_phase = []
    if attack_phases:
        events_per_attack_phase = len(malicious_events) // len(attack_phases)
        remainder = len(malicious_events) % len(attack_phases)
        for i in range(len(attack_phases)):
            count = events_per_attack_phase + (1 if i < remainder else 0)
            mal_per_phase.append(count)
    
    # Distribute benign events across benign phases evenly
    ben_per_phase = []
    if benign_phases:
        events_per_benign_phase = len(benign_events) // len(benign_phases)
        remainder = len(benign_events) % len(benign_phases)
        for i in range(len(benign_phases)):
            count = events_per_benign_phase + (1 if i < remainder else 0)
            ben_per_phase.append(count)
    
    # Process each phase with dynamically calculated event counts
    malicious_idx = 0
    benign_idx = 0
    attack_phase_idx = 0
    benign_phase_idx = 0
    
    for phase in phases:
        phase_name = phase['name']
        phase_start = phase['start']
        phase_end = phase['end']
        phase_type = get_phase_type(phase)
        phase_duration = phase_end - phase_start
        
        # Determine how many events go in this phase
        if phase_type == 'attack':
            phase_event_count = mal_per_phase[attack_phase_idx] if attack_phase_idx < len(mal_per_phase) else 0
            attack_phase_idx += 1
        else:  # benign phase
            phase_event_count = ben_per_phase[benign_phase_idx] if benign_phase_idx < len(ben_per_phase) else 0
            benign_phase_idx += 1
        
        # Assign timestamps for this phase
        for i in range(phase_event_count):
            if phase_type == 'attack':
                # Malicious: use sequential ordering
                if malicious_idx >= len(malicious_events):
                    continue
                
                event = malicious_events[malicious_idx].copy()
                malicious_idx += 1
                
                # Sequential timestamp within phase
                interval = phase_duration / phase_event_count if phase_event_count > 0 else phase_duration
                event['timestamp'] = phase_start + (i * interval) + random.uniform(0, max(interval * 0.1, 0.01))
                event['label'] = 'Malicious'
                
            else:  # benign phase
                # Benign: use scattered random timestamps
                if benign_idx >= len(benign_events):
                    continue
                
                event = benign_events[benign_idx].copy()
                benign_idx += 1
                
                # Random timestamp within phase
                event['timestamp'] = phase_start + random.uniform(0, phase_duration)
                event['label'] = 'Benign'
            
            timestamped_events.append(event)
    
    # Add false alarm events to isolated zones
    false_alarm_zones = arch.get('false_alarm_zones', [])
    for fa_idx, fa_event in enumerate(false_alarm_events):
        event = fa_event.copy()
        
        # Scatter false alarms across zones
        if fa_idx < len(false_alarm_zones):
            zone_start, zone_end = false_alarm_zones[fa_idx]
        else:
            # Reuse zones or use a default
            zone_start, zone_end = false_alarm_zones[-1] if false_alarm_zones else (1200, 1800)
        
        event['timestamp'] = zone_start + random.uniform(0, zone_end - zone_start)
        event['label'] = 'False Alarm'
        
        timestamped_events.append(event)
    
    # Sort all events by timestamp
    timestamped_events.sort(key=lambda e: e['timestamp'])
    
    return timestamped_events


def validate_event_table(events, scenario_name, expected_total=30, expected_malicious=10, 
                             expected_benign=15, expected_false_alarm=5):
    """
    Validate that final event table meets all requirements.
    
    CHANGED: Function renamed from validate_30_event_table to validate_event_table
    to reflect that it now supports parameterized event counts (not just 30-event tables).
    
    Args:
        events (list): List of event dicts
        scenario_name (str): Scenario name (for reporting)
        expected_total (int): Expected total events (caller must provide actual value, not just default of 30)
        expected_malicious (int): Expected malicious events (caller must provide scenario-specific value)
        expected_benign (int): Expected benign events (caller must provide computed value)
        expected_false_alarm (int): Expected false alarm events (caller must provide computed value)
        
    Returns:
        dict: {
            'valid': bool,
            'total_events': int,
            'malicious_count': int,
            'benign_count': int,
            'false_alarm_count': int,
            'errors': [list of error strings],
            'warnings': [list of warning strings],
        }
    """
    errors = []
    warnings = []
    
    total_events = len(events)
    malicious_count = sum(1 for e in events if e.get('label') == 'Malicious')
    benign_count = sum(1 for e in events if e.get('label') == 'Benign')
    false_alarm_count = sum(1 for e in events if e.get('label') == 'False Alarm')
    
    # Check 1: Event count within tolerance (±1 due to rounding)
    if not (expected_total - 1 <= total_events <= expected_total + 1):
        errors.append(f"Expected ~{expected_total} events, got {total_events}")
    
    # Check 2: Label counts match expected (with tolerance for rounding)
    if malicious_count != expected_malicious:
        errors.append(f"Malicious count {malicious_count} != expected {expected_malicious}")
    
    if benign_count != expected_benign:
        errors.append(f"Benign count {benign_count} != expected {expected_benign}")
    
    if false_alarm_count != expected_false_alarm:
        if expected_false_alarm == 0:
            # If zero false alarms expected, any generation is an error
            errors.append(f"False alarm count {false_alarm_count} != expected {expected_false_alarm}")
        else:
            # Otherwise just warn if close
            errors.append(f"False alarm count {false_alarm_count} != expected {expected_false_alarm}")
    
    # Check 3: Timestamps strictly increasing
    if len(events) > 1:
        timestamps = [e.get('timestamp', 0) for e in events]
        for i in range(len(timestamps) - 1):
            if timestamps[i] > timestamps[i + 1]:
                errors.append(f"Timestamps not strictly increasing at event {i}")
                break
    
    # Check 4: Timestamps in valid range [0, 1800]
    for i, event in enumerate(events):
        ts = event.get('timestamp', 0)
        if not (0 <= ts <= 1800):
            errors.append(f"Event {i} timestamp {ts} outside valid range [0, 1800]")
    
    # Check 5: All required columns present
    required_columns = [
        'timestamp', 'src_host', 'dst_host', 'src_ip', 'dst_ip', 'src_subnet', 'dst_subnet',
        'proto', 'sport', 'dport', 'service', 'duration', 'bytes', 'packets',
        'sttl', 'dttl', 'state', 'sloss', 'dloss', 'ct_src_dport_ltm', 'ct_dst_src_ltm',
        'attack_cat', 'label', '_unsw_row_id', 'scenario_name'
    ]
    
    for i, event in enumerate(events):
        for col in required_columns:
            if col not in event:
                errors.append(f"Event {i} missing column: {col}")
    
    return {
        'valid': len(errors) == 0,
        'total_events': total_events,
        'malicious_count': malicious_count,
        'benign_count': benign_count,
        'false_alarm_count': false_alarm_count,
        'errors': errors,
        'warnings': warnings,
    }


def write_scenario_csv(
    events,
    scenario_name,
    output_dir,
    total_events_param=30,
    false_alarm_pct_param=0.15,
    malicious_count=10,
    benign_count=15,
    false_alarm_count=5,
    output_report_path=None,
):
    """
    Write final IDS table to CSV for a single scenario with metadata columns.
    
    Metadata columns (positions 0-4):
    - _total_events_param: Total events config parameter
    - _false_alarm_pct_param: False alarm percentage as decimal
    - _malicious_count_param: Malicious events in this scenario
    - _benign_count_param: Benign events in this scenario
    - _false_alarm_count_param: False alarm events in this scenario
    
    Args:
        events (list): List of validated event dicts
        scenario_name (str): Scenario name
        output_dir (str/Path): Directory to save CSV
        total_events_param (int): Total events config parameter (default: 30)
        false_alarm_pct_param (float): False alarm percentage as decimal (default: 0.15)
        malicious_count (int): Malicious event count (default: 10)
        benign_count (int): Benign event count (default: 15)
        false_alarm_count (int): False alarm event count (default: 5)
        output_report_path (str): Optional path to write summary report
        
    Returns:
        dict: {
            'success': bool,
            'csv_path': str,
            'row_count': int,
            'errors': [error strings]
        }
    """
    errors = []
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    try:
        # Create DataFrame
        df = pd.DataFrame(events)
        
        # Add metadata columns at the beginning
        metadata_df = pd.DataFrame({
            '_total_events_param': [total_events_param] * len(df),
            '_false_alarm_pct_param': [false_alarm_pct_param] * len(df),
            '_malicious_count_param': [malicious_count] * len(df),
            '_benign_count_param': [benign_count] * len(df),
            '_false_alarm_count_param': [false_alarm_count] * len(df),
        })
        
        # Concatenate metadata columns with existing columns
        df = pd.concat([metadata_df, df], axis=1)
        
        # Add ID column (1-indexed)
        df.insert(0, 'id', range(1, len(df) + 1))
        
        # Write to CSV
        csv_path = output_dir / f"{scenario_name}_{total_events_param}events.csv"
        df.to_csv(csv_path, index=False)
        
        row_count = len(df)
        
        # Append to report if provided
        if output_report_path:
            with open(output_report_path, 'a', encoding='utf-8') as f:
                f.write(f"\n{'='*80}\n")
                f.write(f"Scenario: {scenario_name}\n")
                f.write(f"{'='*80}\n")
                f.write(f"CSV Path: {csv_path}\n")
                f.write(f"Row Count: {row_count}\n")
                f.write(f"Total Columns (metadata + flow): {len(df.columns)}\n")
                f.write(f"\nMetadata Columns (first 5):\n")
                f.write(f"  1. _total_events_param: {total_events_param}\n")
                f.write(f"  2. _false_alarm_pct_param: {false_alarm_pct_param:.2f}\n")
                f.write(f"  3. _malicious_count_param: {malicious_count}\n")
                f.write(f"  4. _benign_count_param: {benign_count}\n")
                f.write(f"  5. _false_alarm_count_param: {false_alarm_count}\n")
                f.write(f"\nLabel Distribution:\n")
                for label in ['Malicious', 'Benign', 'False Alarm']:
                    count = sum(1 for e in events if e.get('label') == label)
                    pct = (count / row_count * 100) if row_count > 0 else 0
                    f.write(f"  {label}: {count:2d} ({pct:5.1f}%)\n")
                f.write(f"\nTime Range:\n")
                timestamps = [e.get('timestamp', 0) for e in events]
                f.write(f"  Min: {min(timestamps):.1f}s\n")
                f.write(f"  Max: {max(timestamps):.1f}s\n")
        
        return {
            'success': True,
            'csv_path': str(csv_path),
            'row_count': row_count,
            'errors': []
        }
    
    except Exception as e:
        errors.append(f"Failed to write CSV for {scenario_name}: {str(e)}")
        return {
            'success': False,
            'csv_path': None,
            'row_count': 0,
            'errors': errors
        }


# ============================================================
# MAIN ORCHESTRATOR: STEP 6
# ============================================================

def assemble_30_events_step_6(
    templates_path,
    global_constraints_path,
    network_topology=None,
    output_dir='IDS_tables',
    malicious_count_per_scenario=None,
    benign_count_per_scenario=None,
    false_alarm_count_per_scenario=None,
    total_events_param=30,
    false_alarm_pct_param=0.15,
    output_report_path='step_6_summary.txt',
    random_seed=42,
):
    """
    Main orchestrator for Step 6: Assemble final IDS tables with parameterized event counts.
    
    Args:
        templates_path (str): Path to templates/zero_day_templates.json
        global_constraints_path (str): Path to templates/global_constraints.json
        network_topology (dict, optional): Loaded network_topology_output.json for AWS topology validation
        output_dir (str): Directory to save output CSVs
        malicious_count_per_scenario (dict): Map of scenario_name -> malicious_count
        benign_count_per_scenario (dict): Map of scenario_name -> benign_count
        false_alarm_count_per_scenario (dict): Map of scenario_name -> false_alarm_count
        total_events_param (int): Total events per table (for metadata column, default: 30)
        false_alarm_pct_param (float): False alarm percentage (for metadata column, default: 0.15)
        output_report_path (str): Path to save summary report
        random_seed (int): Seed for reproducibility
        
    Returns:
        dict: {
            'success': bool,
            'errors': [error strings],
            'csv_paths': {scenario_name: csv_path},
            'validation_results': {scenario_name: validation_dict},
        }
    """
    
    random.seed(random_seed)
    errors = []
    csv_paths = {}
    validation_results = {}
    
    try:
        # Load templates and global constraints
        print("\nStep 6: Assembling final IDS tables with temporal ordering...")
        print(f"  Loading templates from {templates_path}")
        print(f"  Loading constraints from {global_constraints_path}")
        templates = load_templates(templates_path)
        
        with open(global_constraints_path, 'r') as f:
            global_constraints = json.load(f)
        
        # Create output directory
        output_dir_path = Path(output_dir)
        output_dir_path.mkdir(parents=True, exist_ok=True)
        print(f"  Output directory: {output_dir_path}")
        
        # Clear/create report
        report_path = Path(output_report_path)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("="*80 + "\n")
            f.write("STEP 6: FINAL IDS TABLE ASSEMBLY WITH PARAMETERIZED COUNTS\n")
            f.write("="*80 + "\n\n")
            f.write(f"Timestamp: {pd.Timestamp.now()}\n")
            f.write(f"Output Directory: {output_dir}\n")
            f.write(f"Total Events Per Table: {total_events_param}\n")
            f.write(f"False Alarm Percentage: {false_alarm_pct_param*100:.0f}%\n")
            f.write(f"Random Seed: {random_seed}\n\n")
        
        # Process each scenario
        for scenario_name in SCENARIOS:
            print(f"\n  Processing scenario: {scenario_name}")
            
            # Get scenario from templates
            scenario = get_scenario_by_name(templates, scenario_name)
            if not scenario:
                errors.append(f"Scenario {scenario_name} not found in templates")
                continue
            
            # Get event counts from parameters or defaults
            mal_count = (malicious_count_per_scenario.get(scenario_name, 10) 
                        if malicious_count_per_scenario else 10)
            ben_count = (benign_count_per_scenario.get(scenario_name, 15) 
                        if benign_count_per_scenario else 15)
            fa_count = (false_alarm_count_per_scenario.get(scenario_name, 5) 
                       if false_alarm_count_per_scenario else 5)
            
            # Extract events from templates
            malicious_events = scenario.get('_step3_malicious_events', [])
            benign_events = scenario.get('_step4_benign_events', [])
            false_alarm_events = scenario.get('_step5_false_alarm_events', [])
            
            print(f"    Malicious: {len(malicious_events)}, Benign: {len(benign_events)}, "
                  f"False Alarms: {len(false_alarm_events)}")
            
            # Assign timestamps
            timestamped_events = assign_timestamps_to_events(
                malicious_events,
                benign_events,
                false_alarm_events,
                scenario_name,
                scenario_template=scenario,
                global_constraints=global_constraints,
                random_seed=random_seed
            )
            
            # Validate
            validation = validate_event_table(
                timestamped_events,
                scenario_name,
                expected_total=mal_count + ben_count + fa_count,
                expected_malicious=mal_count,
                expected_benign=ben_count,
                expected_false_alarm=fa_count
            )
            validation_results[scenario_name] = validation
            
            if not validation['valid']:
                for err in validation['errors']:
                    errors.append(f"  {scenario_name}: {err}")
                print(f"    [FAIL] Validation failed: {validation['errors']}")
            else:
                print(f"    [OK] Validation passed")
            
            for warning in validation['warnings']:
                print(f"    ⚠ {warning}")
            
            # Write CSV with metadata columns
            write_result = write_scenario_csv(
                timestamped_events,
                scenario_name,
                output_dir,
                total_events_param=total_events_param,
                false_alarm_pct_param=false_alarm_pct_param,
                malicious_count=mal_count,
                benign_count=ben_count,
                false_alarm_count=fa_count,
                output_report_path=output_report_path
            )
            
            if write_result['success']:
                csv_paths[scenario_name] = write_result['csv_path']
                print(f"    [OK] CSV written: {write_result['csv_path']}")
            else:
                for err in write_result['errors']:
                    errors.append(err)
                print(f"    [FAIL] Failed to write CSV: {write_result['errors']}")
        
        # Write final summary to report
        with open(output_report_path, 'a', encoding='utf-8') as f:
            f.write(f"\n\n{'='*80}\n")
            f.write("FINAL SUMMARY\n")
            f.write(f"{'='*80}\n")
            f.write(f"Total Scenarios Processed: {len(SCENARIOS)}\n")
            f.write(f"Successful CSVs: {len(csv_paths)}\n")
            f.write(f"Errors: {len(errors)}\n")
            
            if errors:
                f.write(f"\nErrors:\n")
                for err in errors:
                    f.write(f"  - {err}\n")
        
        print(f"\n[OK] Step 6 completed")
        print(f"  Report: {output_report_path}")
        
        # CLEANUP: Delete working templates file at end of run
        # This ensures a clean state for the next pipeline run while preserving current run's data for inspection
        try:
            working_templates_path = Path(templates_path)
            if working_templates_path.exists():
                working_templates_path.unlink()
                print(f"  [CLEANUP] Wiped working templates: {templates_path}")
        except Exception as cleanup_err:
            print(f"  [WARN] Could not wipe working templates: {cleanup_err}")
        
        return {
            'success': len(errors) == 0,
            'errors': errors,
            'csv_paths': csv_paths,
            'validation_results': validation_results,
        }
    
    except Exception as e:
        errors.append(f"Fatal error in Step 6: {str(e)}")
        print(f"[FAIL] Fatal error: {e}")
        return {
            'success': False,
            'errors': errors,
            'csv_paths': {},
            'validation_results': {},
        }
