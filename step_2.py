"""
STEP 2: Filter & Tier Classification

Objective:
    - Load transformed UNSW-NB15 dataset
    - For each scenario, filter by scenario_name + unsw_filtering rules
    - Compute feature statistics (percentiles, ranges)
    - Determine TIER classification (1 or 2)
    - Update templates/zero_day_templates.json with:
        * expected_tier
        * temporal_architecture.phases
        * false_alarm_distribution
    - Generate summary report

Inputs:
    - IDS_Datasets/UNSW_NB15_transformed.csv (from Pre-Step)
    - templates/zero_day_templates.json (with unsw_filtering rules)
    - templates/global_constraints.json (validation reference)

Outputs:
    - Updated templates/zero_day_templates.json
    - step_2_summary.txt (human-readable report)
"""

import json
import pandas as pd
from pathlib import Path
from helper_functions import load_templates, save_templates, SCENARIOS, fill_feature_constraints


def compute_feature_stats(df, scenario_name):
    """
    Extract feature statistics from filtered data.
    
    Args:
        df (pd.DataFrame): Filtered scenario data
        scenario_name (str): Name of scenario (for reporting)
    
    Returns:
        dict: Statistics dict with row_count, duration ranges, bytes ranges, packets ranges
    """
    stats = {
        'scenario': scenario_name,
        'row_count': len(df),
        'duration_min': float(df['duration'].min()),
        'duration_max': float(df['duration'].max()),
        'duration_median': float(df['duration'].median()),
        'duration_mean': float(df['duration'].mean()),
        'bytes_min': int(df['bytes'].min()),
        'bytes_max': int(df['bytes'].max()),
        'bytes_median': int(df['bytes'].median()),
        'bytes_mean': float(df['bytes'].mean()),
        'packets_min': int(df['packets'].min()),
        'packets_max': int(df['packets'].max()),
        'packets_median': int(df['packets'].median()),
        'packets_mean': float(df['packets'].mean()),
        'proto_unique': df['proto'].unique().tolist(),
        'dport_unique': sorted(df['dport'].unique().tolist()),
    }
    return stats


def determine_tier(row_count):
    """
    Classify TIER based on filtered UNSW row count.
    
    Args:
        row_count (int): Number of UNSW rows after filtering
    
    Returns:
        int: TIER (1 or 2)
    
    Raises:
        ValueError: If row_count < 5
    """
    if row_count >= 10:
        return 1  # Use actual UNSW events
    elif row_count >= 5:
        return 2  # Mix actual + parameterized variations
    else:
        raise ValueError(
            f"Only {row_count} UNSW rows after filtering. "
            f"Minimum 5 required for TIER 2. Review unsw_filtering rules."
        )


def filter_scenario_data(df, scenario_name, unsw_filters):
    """
    Filter transformed data for a specific scenario.
    
    CRITICAL: Filter by scenario_name FIRST, then apply UNSW filters.
    
    Args:
        df (pd.DataFrame): Full transformed dataset (all scenarios mixed)
        scenario_name (str): Scenario to filter for
        unsw_filters (dict): Scenario-specific filters (attack_cat, proto, dport)
    
    Returns:
        pd.DataFrame: Filtered data for scenario
    
    Raises:
        ValueError: If scenario_name filter results in empty dataset
    """
    # CRITICAL: Filter by scenario_name FIRST
    scenario_df = df[df['scenario_name'] == scenario_name].copy()
    
    if len(scenario_df) == 0:
        raise ValueError(
            f"Scenario '{scenario_name}' not found in transformed dataset. "
            f"Unknown scenario or Pre-Step not completed."
        )
    
    filtered_df = scenario_df.copy()
    
    # Apply attack_cat filter
    if 'attack_cat' in unsw_filters and unsw_filters['attack_cat']:
        attack_cats = unsw_filters['attack_cat']
        filtered_df = filtered_df[filtered_df['attack_cat'].isin(attack_cats)]
    
    # Apply proto filter
    if 'proto' in unsw_filters and unsw_filters['proto']:
        protos = unsw_filters['proto']
        filtered_df = filtered_df[filtered_df['proto'].isin(protos)]
    
    # Apply dport filter
    if 'dport' in unsw_filters and unsw_filters['dport']:
        dports = unsw_filters['dport']
        filtered_df = filtered_df[filtered_df['dport'].isin(dports)]
    
    if len(filtered_df) == 0:
        raise ValueError(
            f"Scenario '{scenario_name}': No UNSW rows match filters. "
            f"Review attack_cat/proto/dport in unsw_filtering."
        )
    
    return filtered_df


def get_standard_phases(global_constraints):
    """
    Return standard phase schedule from global_constraints.json.
    
    Args:
        global_constraints (dict): Global constraints dict with temporal_architecture_principles
    
    Returns:
        list: Phase definitions with standardized structure
    """
    try:
        # Read from global_constraints if available
        if 'temporal_architecture_principles' in global_constraints:
            phase_structure = global_constraints['temporal_architecture_principles'].get('phase_structure', {})
            phases = []
            
            # Convert phase_structure to standard format
            for phase_name, phase_info in phase_structure.items():
                if isinstance(phase_info, dict) and 'timeband_seconds' in phase_info:
                    # Parse "0-300" format
                    timeband = phase_info['timeband_seconds'].split('-')
                    if len(timeband) == 2:
                        phases.append({
                            "name": phase_name,
                            "start": int(timeband[0]),
                            "end": int(timeband[1]),
                            "event_count": phase_info.get('event_count', '').split('-')[0] if '-' in str(phase_info.get('event_count', '')) else 6
                        })
            
            if phases:
                return phases
    except Exception as e:
        print(f"  Warning: Could not read phases from global_constraints ({str(e)}). Using defaults.")
    
    # Fallback to hardcoded defaults if JSON read fails
    return [
        {"name": "benign_baseline", "start": 0, "end": 300, "event_count": 6},
        {"name": "attack_phase_1", "start": 300, "end": 600, "event_count": 3},
        {"name": "attack_phase_2", "start": 600, "end": 900, "event_count": 3},
        {"name": "attack_phase_3", "start": 900, "end": 1200, "event_count": 2},
        {"name": "benign_recovery", "start": 1200, "end": 1800, "event_count": 9}
    ]


def process_step_2(
    transformed_csv_path,
    templates_path,
    constraints_path,
    network_topology=None,
    output_report_path="step_2_summary.txt"
):
    """
    Main Step 2 function: Filter data, compute stats, determine TIER, update templates.
    
    Args:
        transformed_csv_path (str): Path to UNSW_NB15_transformed.csv
        templates_path (str): Path to zero_day_templates.json
        constraints_path (str): Path to global_constraints.json (for reference)
        network_topology (dict, optional): Loaded network_topology_output.json for AWS topology validation
        output_report_path (str): Path to save summary report (default: step_2_summary.txt)
    
    Returns:
        dict: Summary with 'success', 'errors', 'scenarios_processed'
    
    Raises:
        FileNotFoundError: If input files not found
        ValueError: If validation fails
    """
    
    print("\n" + "="*80)
    print("STEP 2: FILTER & TIER CLASSIFICATION")
    print("="*80)
    
    # Load templates
    try:
        templates = load_templates(templates_path)
    except Exception as e:
        raise ValueError(f"Failed to load templates: {e}")
    
    # Load global constraints
    global_constraints = {}
    try:
        with open(constraints_path, 'r') as f:
            global_constraints = json.load(f)
        print(f"Loaded global constraints from {constraints_path}")
    except Exception as e:
        print(f"Warning: Could not load global_constraints ({str(e)}). Proceeding with defaults.")
    
    # Load transformed CSV
    try:
        print(f"\nLoading transformed dataset from {transformed_csv_path}...")
        transformed_df = pd.read_csv(transformed_csv_path)
        print(f"  [OK] Loaded {len(transformed_df)} total rows (all scenarios mixed)")
    except FileNotFoundError:
        raise FileNotFoundError(f"Transformed CSV not found: {transformed_csv_path}")
    except Exception as e:
        raise ValueError(f"Failed to load transformed CSV: {e}")
    
    # Process each scenario
    report_lines = []
    report_lines.append("=" * 80)
    report_lines.append("STEP 2: FILTER & TIER CLASSIFICATION - SUMMARY REPORT")
    report_lines.append("=" * 80)
    report_lines.append("")
    
    scenarios_processed = []
    errors = []
    
    for scenario_idx, scenario_template in enumerate(templates['scenarios']):
        scenario_name = scenario_template.get('scenario_name')
        
        if not scenario_name:
            errors.append(f"Scenario {scenario_idx}: Missing scenario_name")
            continue
        
        # SKIP scenarios with no malicious events (e.g., No_Attack)
        malicious_count = scenario_template.get('malicious_count', 0)
        if malicious_count == 0:
            print(f"\n--- Processing {scenario_name} (SKIPPED) ---")
            print(f"    [No malicious events - pure benign scenario]")
            report_lines.append(f"\nSCENARIO: {scenario_name}")
            report_lines.append("-" * 80)
            report_lines.append(f"  Status: SKIPPED - No UNSW filtering needed (malicious_count=0)")
            continue
        
        print(f"\n--- Processing {scenario_name} ---")
        report_lines.append(f"\nSCENARIO: {scenario_name}")
        report_lines.append("-" * 80)
        
        try:
            # Extract unsw_filtering rules
            unsw_filters = scenario_template.get('unsw_filtering', {})
            
            # Filter data
            filtered_df = filter_scenario_data(
                transformed_df, 
                scenario_name, 
                unsw_filters
            )
            
            row_count = len(filtered_df)
            print(f"  Filtered rows: {row_count}")
            report_lines.append(f"  UNSW rows after filtering: {row_count}")
            
            # Determine TIER
            tier = determine_tier(row_count)
            print(f"  TIER: {tier}")
            report_lines.append(f"  Assigned TIER: {tier}")
            
            # Compute feature statistics
            stats = compute_feature_stats(filtered_df, scenario_name)
            print(f"  Duration range: {stats['duration_min']:.2f}s - {stats['duration_max']:.2f}s (median: {stats['duration_median']:.2f}s)")
            print(f"  Bytes range: {stats['bytes_min']} - {stats['bytes_max']} (median: {stats['bytes_median']})")
            print(f"  Packets range: {stats['packets_min']} - {stats['packets_max']} (median: {stats['packets_median']})")
            
            report_lines.append(f"  Duration range: {stats['duration_min']:.2f}s - {stats['duration_max']:.2f}s (median: {stats['duration_median']:.2f}s)")
            report_lines.append(f"  Bytes range: {stats['bytes_min']} - {stats['bytes_max']} (median: {stats['bytes_median']})")
            report_lines.append(f"  Packets range: {stats['packets_min']} - {stats['packets_max']} (median: {stats['packets_median']})")
            report_lines.append(f"  Unique protocols: {', '.join(stats['proto_unique'])}")
            report_lines.append(f"  Unique destination ports: {', '.join(map(str, stats['dport_unique']))}")
            
            # Update template with computed values
            templates['scenarios'][scenario_idx]['expected_tier'] = tier
            templates['scenarios'][scenario_idx]['temporal_architecture']['phases'] = get_standard_phases(global_constraints)
            templates['scenarios'][scenario_idx]['false_alarm_distribution'] = {
                "type_1_unusual_port_benign_service": 2,
                "type_2_high_volume_low_risk": 2,
                "type_3_rare_duration_benign": 1
            }
            
            # Store stats for later reference (optional, not required by spec)
            templates['scenarios'][scenario_idx]['_step2_stats'] = stats
            
            report_lines.append(f"  Status: OK - Ready for synthesis")
            scenarios_processed.append({
                'name': scenario_name,
                'tier': tier,
                'row_count': row_count,
                'stats': stats
            })
            
        except Exception as e:
            error_msg = f"Error processing {scenario_name}: {str(e)}"
            print(f"  ERROR - {error_msg}")
            report_lines.append(f"  Status: FAILED - {str(e)}")
            errors.append(error_msg)
    
    # Save updated templates
    try:
        print(f"\nSaving updated templates to {templates_path}...")
        save_templates(templates, templates_path)
        print("  OK - Templates saved successfully")
        report_lines.append("\n" + "=" * 80)
        report_lines.append("OK - Updated templates saved successfully")
    except Exception as e:
        error_msg = f"Failed to save templates: {str(e)}"
        print(f"  ❌ {error_msg}")
        report_lines.append(f"\n❌ {error_msg}")
        errors.append(error_msg)
    
    # Populate feature_constraints from _step2_stats
    try:
        print(f"\nFilling feature_constraints from computed statistics...")
        fill_feature_constraints(templates_path)
        print("  OK - Feature constraints populated successfully")
        report_lines.append("OK - Feature constraints populated from statistics")
    except Exception as e:
        error_msg = f"Failed to fill feature_constraints: {str(e)}"
        print(f"  [WARN] {error_msg}")
        report_lines.append(f"[WARN] {error_msg}")
        # Don't add to errors list - this is non-critical
    
    # Save report
    try:
        report_lines.append("\n" + "=" * 80)
        report_lines.append(f"Total scenarios processed: {len(scenarios_processed)}")
        if errors:
            report_lines.append(f"Errors encountered: {len(errors)}")
            report_lines.append("\nERROR DETAILS:")
            for err in errors:
                report_lines.append(f"  - {err}")
        else:
            report_lines.append("All scenarios processed successfully!")
        report_lines.append("=" * 80)
        
        # Write with UTF-8 encoding to handle special characters
        with open(output_report_path, 'w', encoding='utf-8') as f:
            f.write('\n'.join(report_lines))
        print(f"\nSummary report saved to {output_report_path}")
    except Exception as e:
        print(f"Warning: Failed to save report: {e}")
    
    success = len(errors) == 0 and len(scenarios_processed) > 0
    
    return {
        'success': success,
        'scenarios_processed': len(scenarios_processed),
        'total_scenarios': len(SCENARIOS),
        'errors': errors,
        'report_path': output_report_path
    }
