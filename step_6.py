"""
Step 6: Assemble Final 30-Event IDS Tables with Temporal Ordering
Purpose: Combine malicious (10-11), benign (15), and false alarm (4-5) events.
         Assign timestamps using phase architecture.
         Output final CSV tables (23 columns: 21 schema + 2 tracking).

Temporal Architecture (all scenarios):
  - Phase 0 (Benign Baseline):     0-300s,     6 events (benign)
  - Phase 1 (Attack Phase 1):    300-600s,     3 events (malicious)
  - Phase 2 (Attack Phase 2):    600-900s,     3 events (malicious)
  - Phase 3 (Attack Phase 3):    900-1200s,    2 events (malicious)
  - Phase 4 (Benign Recovery):   1200-1800s,   9 events (benign + false alarms)
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


# ============================================================
# TEMPORAL ARCHITECTURE: PHASE DEFINITIONS
# ============================================================

TEMPORAL_ARCHITECTURE = {
    'WannaCry': {
        'total_duration': 1800,
        'phases': [
            {'name': 'benign_baseline', 'start': 0, 'end': 300, 'type': 'benign', 'event_count': 6},
            {'name': 'attack_phase_1', 'start': 300, 'end': 600, 'type': 'attack', 'event_count': 4},
            {'name': 'attack_phase_2', 'start': 600, 'end': 900, 'type': 'attack', 'event_count': 4},
            {'name': 'attack_phase_3', 'start': 900, 'end': 1200, 'type': 'attack', 'event_count': 2},
            {'name': 'benign_recovery', 'start': 1200, 'end': 1800, 'type': 'benign', 'event_count': 9},
        ],
        'false_alarm_zones': [(600, 700), (1200, 1300), (1400, 1500)],  # Isolated from attack
    },
    'Data_Theft': {
        'total_duration': 1800,
        'phases': [
            {'name': 'benign_baseline', 'start': 0, 'end': 300, 'type': 'benign', 'event_count': 6},
            {'name': 'unauthorized_access', 'start': 300, 'end': 500, 'type': 'attack', 'event_count': 4},
            {'name': 'file_staging', 'start': 500, 'end': 800, 'type': 'attack', 'event_count': 4},
            {'name': 'compression', 'start': 800, 'end': 1000, 'type': 'attack', 'event_count': 2},
            {'name': 'benign_recovery', 'start': 1000, 'end': 1800, 'type': 'benign', 'event_count': 9},
        ],
        'false_alarm_zones': [(1000, 1100), (1200, 1400)],
    },
    'ShellShock': {
        'total_duration': 1800,
        'phases': [
            {'name': 'benign_baseline', 'start': 0, 'end': 300, 'type': 'benign', 'event_count': 6},
            {'name': 'initial_http_request', 'start': 300, 'end': 500, 'type': 'attack', 'event_count': 4},
            {'name': 'bash_execution', 'start': 500, 'end': 800, 'type': 'attack', 'event_count': 4},
            {'name': 'data_access', 'start': 800, 'end': 1100, 'type': 'attack', 'event_count': 3},
            {'name': 'benign_recovery', 'start': 1100, 'end': 1800, 'type': 'benign', 'event_count': 9},
        ],
        'false_alarm_zones': [(1100, 1200), (1400, 1600)],
    },
    'Netcat_Backdoor': {
        'total_duration': 1800,
        'phases': [
            {'name': 'benign_baseline', 'start': 0, 'end': 300, 'type': 'benign', 'event_count': 6},
            {'name': 'initial_access', 'start': 300, 'end': 500, 'type': 'attack', 'event_count': 4},
            {'name': 'netcat_install', 'start': 500, 'end': 800, 'type': 'attack', 'event_count': 4},
            {'name': 'persistent_connection', 'start': 800, 'end': 1100, 'type': 'attack', 'event_count': 2},
            {'name': 'benign_recovery', 'start': 1100, 'end': 1800, 'type': 'benign', 'event_count': 9},
        ],
        'false_alarm_zones': [(1100, 1200), (1400, 1600)],
    },
    'passwd_gzip_scp': {
        'total_duration': 1800,
        'phases': [
            {'name': 'benign_baseline', 'start': 0, 'end': 300, 'type': 'benign', 'event_count': 6},
            {'name': 'system_access', 'start': 300, 'end': 500, 'type': 'attack', 'event_count': 4},
            {'name': 'file_access', 'start': 500, 'end': 800, 'type': 'attack', 'event_count': 4},
            {'name': 'compression_transfer', 'start': 800, 'end': 1100, 'type': 'attack', 'event_count': 2},
            {'name': 'benign_recovery', 'start': 1100, 'end': 1800, 'type': 'benign', 'event_count': 9},
        ],
        'false_alarm_zones': [(1100, 1200), (1400, 1600)],
    },
}


# ============================================================
# CORE FUNCTIONS: Event Assembly & Timestamping
# ============================================================

def assign_timestamps_to_events(
    malicious_events,
    benign_events,
    false_alarm_events,
    scenario_name,
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
        random_seed (int): Seed for reproducibility
        
    Returns:
        list: All events with timestamps assigned, sorted chronologically
        
    Raises:
        ValueError: If event counts don't match architecture
    """
    random.seed(random_seed)
    timestamped_events = []
    
    if scenario_name not in TEMPORAL_ARCHITECTURE:
        raise ValueError(f"Scenario {scenario_name} not in TEMPORAL_ARCHITECTURE")
    
    arch = TEMPORAL_ARCHITECTURE[scenario_name]
    phases = arch['phases']
    
    # Count attack and benign phases to determine distribution
    attack_phases = [p for p in phases if p['type'] == 'attack']
    benign_phases = [p for p in phases if p['type'] == 'benign']
    
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
        phase_type = phase['type']
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


def validate_30_event_table(events, scenario_name, expected_total=30, expected_malicious=10, 
                             expected_benign=15, expected_false_alarm=5):
    """
    Validate that final event table meets all requirements.
    
    Args:
        events (list): List of event dicts
        scenario_name (str): Scenario name (for reporting)
        expected_total (int): Expected total events (default: 30, for compatibility)
        expected_malicious (int): Expected malicious events (default: 10, for compatibility)
        expected_benign (int): Expected benign events (default: 15, for compatibility)
        expected_false_alarm (int): Expected false alarm events (default: 5, for compatibility)
        
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
        'timestamp', 'src_host', 'dst_host', 'src_subnet', 'dst_subnet',
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
                random_seed=random_seed
            )
            
            # Validate
            validation = validate_30_event_table(
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
