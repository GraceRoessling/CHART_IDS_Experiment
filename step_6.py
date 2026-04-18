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
    
    # Process each phase
    malicious_idx = 0
    benign_idx = 0
    
    for phase in phases:
        phase_name = phase['name']
        phase_start = phase['start']
        phase_end = phase['end']
        phase_type = phase['type']
        phase_event_count = phase['event_count']
        phase_duration = phase_end - phase_start
        
        # Assign timestamps for this phase
        for i in range(phase_event_count):
            if phase_type == 'attack':
                # Malicious: use sequential ordering
                if malicious_idx >= len(malicious_events):
                    # Not enough malicious events; skip
                    continue
                
                event = malicious_events[malicious_idx].copy()
                malicious_idx += 1
                
                # Sequential timestamp within phase
                interval = phase_duration / phase_event_count
                event['timestamp'] = phase_start + (i * interval) + random.uniform(0, interval * 0.1)
                event['label'] = 'Malicious'
                
            else:  # benign phase
                # Benign: use scattered random timestamps
                if benign_idx >= len(benign_events):
                    # Not enough benign events; skip
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


def validate_30_event_table(events, scenario_name):
    """
    Validate that 30-event table meets all requirements.
    
    Args:
        events (list): List of event dicts (should have ~30)
        scenario_name (str): Scenario name (for reporting)
        
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
    
    # Check 1: Approximately 30 events (29-31 range to accommodate 10-11 mal + 15 ben + 4-5 FA)
    if not (29 <= total_events <= 31):
        errors.append(f"Expected ~30 events (29-31 range), got {total_events}")
    
    # Check 2: Label counts in range
    if not (10 <= malicious_count <= 11):
        errors.append(f"Malicious count {malicious_count} not in range [10-11]")
    
    if benign_count != 15:
        warnings.append(f"Benign count {benign_count} differs from target 15")
    
    if not (4 <= false_alarm_count <= 5):
        warnings.append(f"False alarm count {false_alarm_count} not in range [4-5]")
    
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
    output_report_path=None,
):
    """
    Write 30-event table to CSV for a single scenario.
    
    Args:
        events (list): List of validated event dicts (30 events)
        scenario_name (str): Scenario name
        output_dir (str/Path): Directory to save CSV
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
        
        # Column order (EXACT as spec: 23 columns)
        columns_ordered = [
            'timestamp', 'src_host', 'dst_host', 'src_subnet', 'dst_subnet',
            'proto', 'sport', 'dport', 'service', 'duration', 'bytes', 'packets',
            'sttl', 'dttl', 'state', 'sloss', 'dloss', 'ct_src_dport_ltm', 'ct_dst_src_ltm',
            'attack_cat', 'label',
            '_unsw_row_id', 'scenario_name'  # Tracking columns
        ]
        
        # Reorder columns
        df = df[columns_ordered]
        
        # Write to CSV
        csv_path = output_dir / f"{scenario_name}_30_events.csv"
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
                f.write(f"Column Count: {len(columns_ordered)}\n")
                f.write(f"\nColumn Order:\n")
                for i, col in enumerate(columns_ordered, 1):
                    f.write(f"  {i:2d}. {col}\n")
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
    output_dir='IDS_tables',
    output_report_path='step_6_summary.txt',
    random_seed=42,
):
    """
    Main orchestrator for Step 6: Assemble final 30-event IDS tables.
    
    Args:
        templates_path (str): Path to themes/zero_day_templates.json
        output_dir (str): Directory to save output CSVs
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
        # Load templates
        print("\nStep 6: Assembling final 30-event IDS tables...")
        print(f"  Loading templates from {templates_path}")
        templates = load_templates(templates_path)
        
        # Clear/create report
        report_path = Path(output_report_path)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("="*80 + "\n")
            f.write("STEP 6: FINAL 30-EVENT IDS TABLE ASSEMBLY\n")
            f.write("="*80 + "\n\n")
            f.write(f"Timestamp: {pd.Timestamp.now()}\n")
            f.write(f"Output Directory: {output_dir}\n")
            f.write(f"Random Seed: {random_seed}\n\n")
        
        # Process each scenario
        for scenario_name in SCENARIOS:
            print(f"\n  Processing scenario: {scenario_name}")
            
            # Get scenario from templates
            scenario = get_scenario_by_name(templates, scenario_name)
            if not scenario:
                errors.append(f"Scenario {scenario_name} not found in templates")
                continue
            
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
            validation = validate_30_event_table(timestamped_events, scenario_name)
            validation_results[scenario_name] = validation
            
            if not validation['valid']:
                for err in validation['errors']:
                    errors.append(f"  {scenario_name}: {err}")
                print(f"    [FAIL] Validation failed: {validation['errors']}")
            else:
                print(f"    [OK] Validation passed")
            
            for warning in validation['warnings']:
                print(f"    ⚠ {warning}")
            
            # Write CSV
            write_result = write_scenario_csv(
                timestamped_events,
                scenario_name,
                output_dir,
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
