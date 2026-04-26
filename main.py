"""
IDS Pipeline (Main Orchestrator)
"""

import json
import os
import pre_step
import step_1
import step_2
import step_3
import step_4
import step_5
import step_6
import step_7
from pathlib import Path
from helper_functions import initialize_working_templates


# ============================================================
# PARAMETERIZATION CONSTANTS
# ============================================================

# ============================================================
# WORKING TEMPLATES PATH (hard-coded, consistent across runs)
# Clean zero_day_templates.json remains untouched
# ============================================================
WORKING_TEMPLATES_PATH = "templates/_working_templates.json"

# ============================================================
# FALSE ALARM RATE BINS (safe for ALL scenarios)
# Global constraint: use minimum of all scenario maxes
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

# ============================================================
# FALSE ALARM TYPE DISTRIBUTION RATIOS
# ============================================================
# Distribute false_alarm_count across 3 types:
#   Type 1: Unusual port + benign service (e.g., DNS on port 12345)
#   Type 2: High volume + benign service (e.g., massive DNS response)
#   Type 3: Rare duration + benign service (e.g., very long SSH session)
#
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


# ============================================================
# HELPER FUNCTIONS FOR VALIDATION AND PRE-COMPUTATION
# ============================================================

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


def load_templates_with_validation(templates_path):
    """Load and validate templates JSON structure"""
    if not Path(templates_path).exists():
        raise FileNotFoundError(f"Templates file not found: {templates_path}")
    
    with open(templates_path, 'r') as f:
        try:
            templates = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"Templates JSON is malformed: {e}")
    
    # Quick validation
    if 'scenarios' not in templates:
        raise ValueError("Templates JSON missing 'scenarios' key")
    if not isinstance(templates['scenarios'], list):
        raise ValueError("Templates 'scenarios' must be a list")
    if len(templates['scenarios']) == 0:
        raise ValueError("Templates 'scenarios' is empty")
    
    return templates


def main():

    # ============================================================
    # USER-CONFIGURABLE PIPELINE PARAMETERS
    # ============================================================
    
    # Table size configuration
    total_events_per_table = 30  # Range: 18-45 (default: 30)
    
    # False alarm bin selection (ONLY predefined bins allowed)
    false_alarm_bin = "standard"  # Choose from: zero | very_conservative | conservative | standard | elevated | high
    
    # False alarm type distribution ratio mode
    fa_type_ratio_mode = "balanced"  # Choose from: balanced | port_heavy | volume_heavy | duration_heavy
    
    # ============================================================
    # PARAMETER VALIDATION
    # ============================================================
    
    try:
        validate_total_events(total_events_per_table)
        validate_false_alarm_bin(false_alarm_bin)
        validate_fa_type_ratio_mode(fa_type_ratio_mode)
    except ValueError as e:
        raise ValueError(f"Configuration validation failed: {e}")
    
    # Convert bin to percentage
    false_alarm_pct = FALSE_ALARM_BINS[false_alarm_bin]["pct"]
    
    print(f"\n{'='*70}")
    print(f"Pipeline Configuration:")
    print(f"{'='*70}")
    print(f"  Total events per table: {total_events_per_table}")
    print(f"  False alarm bin: {false_alarm_bin} ({false_alarm_pct*100:.0f}%)")
    print(f"  FA type ratio mode: {fa_type_ratio_mode}")
    print(f"  (Malicious counts fixed per scenario in templates)")
    print(f"  (Benign counts calculated as: total - malicious - false_alarm)")
    print(f"{'='*70}\n")

    # ============================================================
    # INITIALIZE WORKING TEMPLATES
    # Create a fresh copy of zero_day_templates.json for this pipeline run
    # All intermediate steps will modify working_templates, not the source
    # ============================================================
    
    source_templates_path = Path("templates/zero_day_templates.json")
    working_templates_path = Path(WORKING_TEMPLATES_PATH)
    
    try:
        print(f"Initializing working templates...")
        initialize_working_templates(str(source_templates_path), str(working_templates_path))
        print(f"  ✓ Working templates initialized: {working_templates_path}")
    except Exception as e:
        raise ValueError(f"Failed to initialize working templates: {e}")

    # ============================================================
    # PRE-STEP: TRANSFORM DATA
    # Load raw UNSW dataset and convert to standardized schema
    # ============================================================
    input_unsw_csv = Path("IDS_Datasets/UNSW_NB15_training-set(in).csv")
    output_transformed_csv = Path("IDS_Datasets/UNSW_NB15_transformed.csv")
    
    # Only run Pre-Step if output doesn't exist
    if output_transformed_csv.exists():
        print(f" Transformed dataset already exists: {output_transformed_csv}")
    else:
        print(f"Running Pre-Step: transforming UNSW data...")
        pre_step.batch_transform_unsw(str(input_unsw_csv), str(output_transformed_csv))


    # ============================================================
    # STEP 0: GLOBAL CONSTRAINTS + AWS NETWORK TOPOLOGY
    # Define experiment rules (event counts, label ratios, topology, time window)
    # Store all shared configuration parameters for downstream steps
    # References:
    #   - global_constraints_v2.json (event generation rules + routing constraints)
    #   - network_topology_output.json (AWS infrastructure + concrete IPs)
    # ============================================================
    
    global_constraints_path = Path("templates/global_constraints_v2.json")
    network_topology_path = Path("templates/network_topology_output.json")
    
    # VALIDATION: Verify both files exist and are well-formed
    for config_file in [global_constraints_path, network_topology_path]:
        if not config_file.exists():
            raise FileNotFoundError(f"Required config file not found: {config_file}")
    
    print(f" Global constraints file (v2) found: {global_constraints_path}")
    print(f" Network topology file found: {network_topology_path}")
    
    # Load and validate JSON files
    try:
        with open(global_constraints_path, 'r') as f:
            global_constraints = json.load(f)
        with open(network_topology_path, 'r') as f:
            network_topology = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"JSON parse error in config files: {e}")
    
    # Note: global_constraints_v2.json contains:
    #   - label_distribution (Malicious 10-11, Benign 15, False Alarm 4-5)
    #   - network_topology_reference (delegates to network_topology_output.json for concrete data)
    #   - unsw_grounding_principles (UNSW as template library, not sequences)
    #   - tiered_synthesis_framework (TIER 1/2/3 based on UNSW row count)
    #   - false_alarm_taxonomy (3 types: unusual_port, high_volume, rare_duration)
    #   - temporal_architecture (5 phases over 1800s observation window)
    #   - output_schema (23 columns: 21 schema + 2 tracking)
    #   - validation_checkpoints (15 critical sanity checks)
    #
    # network_topology_output.json contains:
    #   - vpc_id, vpc_cidr (AWS VPC identifiers)
    #   - subnet definitions with CIDR blocks (10.0.1.0/24, 10.0.2.0/24, 10.0.3.0/24)
    #   - concrete host-to-IP mappings (User0-4, Enterprise0-2, Defender, OpHost0-2, OpServer0)
    #   - routing_paths (attack path: User1→Enterprise1→Enterprise2→OpServer0)
    #   - gateway info (User1 is entry point, Defender monitors all)


    # ============================================================
    # STEP 1: STRUCTURE & VALIDATE ZERO-DAY TEMPLATES
    # Ensure all scenario templates have required fields
    # Validate structure against global constraints
    # Output: validated templates ready for Step 2
    # ============================================================
    
    # Use working templates (initialized above)
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
    
    # Load validated templates from working file
    try:
        with open(working_templates_path, 'r') as f:
            templates_dict = json.load(f)
        
        # Quick validation: check for required scenarios structure
        if 'scenarios' not in templates_dict:
            raise ValueError("Templates JSON missing 'scenarios' key")
        if not isinstance(templates_dict['scenarios'], list):
            raise ValueError("Templates 'scenarios' must be a list")
        if len(templates_dict['scenarios']) == 0:
            raise ValueError("Templates 'scenarios' is empty")
        
        print(f" ✓ Templates validated: {working_templates_path}")
    except json.JSONDecodeError as e:
        raise ValueError(f"Templates JSON is malformed: {e}")
    except Exception as e:
        raise ValueError(f"Templates validation failed: {e}")


    # ============================================================
    # PER-SCENARIO PRE-COMPUTATION: EVENT COUNTS
    # Validate configuration for each scenario and pre-compute per-scenario counts
    # ============================================================
    
    print(f"\nValidating configuration feasibility for all scenarios...")
    is_valid, val_errors, val_warnings, malicious_count_per_scenario, benign_count_per_scenario, false_alarm_count_per_scenario = validate_per_scenario_feasibility(
        templates_dict, 
        total_events_per_table, 
        false_alarm_pct
    )
    
    if not is_valid:
        raise ValueError(
            f"Configuration validation failed:\n" + "\n".join([f"  ERROR: {e}" for e in val_errors])
        )
    
    # Print warnings if any
    if val_warnings:
        print(f"\n[WARNINGS during configuration validation]")
        for warning in val_warnings:
            print(f"  {warning}")
    
    # Print per-scenario computed counts
    print(f"\nPer-scenario event counts (computed):")
    for scenario in templates_dict['scenarios']:
        scenario_name = scenario.get('scenario_name', 'UNKNOWN')
        mal = malicious_count_per_scenario.get(scenario_name, 0)
        ben = benign_count_per_scenario.get(scenario_name, 0)
        fa = false_alarm_count_per_scenario.get(scenario_name, 0)
        total = mal + ben + fa
        print(f"  {scenario_name}: Malicious={mal}, Benign={ben}, FalseAlarm={fa}, Total={total}")
    
    # Create parameterized output directory
    output_dir = Path(f"IDS_tables/{total_events_per_table}events_{int(false_alarm_pct*100)}pct_fa")
    output_dir.mkdir(parents=True, exist_ok=True)
    print(f"\n Output directory: {output_dir}")


    # ============================================================
    # STEP 2: FILTER + TIER CLASSIFICATION
    # Filter transformed data per scenario and compute feature statistics
    # Assign TIER (1 = sufficient data, 2 = limited data)
    # Output: updated templates with TIER + stats
    # 
    # NOTE: Skip for scenarios with malicious_count == 0 (e.g., No_Attack)
    # ============================================================
    
    # Check if any scenario is attack-free
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
    # Generate attack events using real data (TIER 1) or + variations (TIER 2)
    # Ensure logical attack progression and valid network structure
    # Output: malicious events (per scenario)
    #
    # NOTE: Skip for scenarios with malicious_count == 0 (e.g., No_Attack)
    #
    # CONFIG FILE DEPENDENCIES:
    #   - templates_path (zero_day_templates.json):
    #     * Provides scenario-specific malicious_count (e.g. 11 for WannaCry, 9 for Data_Theft)
    #   - global_constraints_path (global_constraints_v2.json):
    #     * Provides temporal_architecture (phases for timestamp assignment: 300-900s)
    #     * Provides network_topology (for host assignment validation)
    #     * Provides tiered_synthesis_framework (TIER 1/2/3 fallback rules)
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
    # Generate 15 normal traffic events (HTTP, DNS, SSH, etc.)
    # Use realistic feature ranges and valid host/subnet combinations
    # Output: benign events (per scenario)
    #
    # CONFIG FILE DEPENDENCIES:
    #   - templates_path (zero_day_templates.json):
    #     * Provides scenario-specific benign_count (derived from total - malicious - fa)
    #     * Provides feature_constraints for realistic traffic generation
    #   - global_constraints_path (global_constraints_v2.json):
    #     * Provides network_topology (enforces routing constraints: no direct User ↔ Operational)
    #     * Provides output_schema (column names and validation)
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
    # Generate suspicious-looking but benign events
    # UNSW-grounded, scenario-independent, 3 types
    # Output: false alarm events (per scenario)
    #
    # CONFIG FILE DEPENDENCIES:
    #   - templates_path (zero_day_templates.json):
    #     * Provides scenario-specific false_alarm_count (parameterized value)
    #     * Provides feature_constraints for realistic anomaly injection
    #   - global_constraints_path (global_constraints_v2.json):
    #     * Provides false_alarm_taxonomy (3 types: unusual_port, high_volume, rare_duration)
    #     * Provides temporal_architecture (isolation zones: 600-700s, 1200-1300s, 1400-1500s)
    #     * Provides network_topology (enforces valid host/subnet assignments)
    # ============================================================
    
    print(f"\nRunning Step 5: generating false alarm events...")
    step5_result = step_5.generate_false_alarms_step_5(
        str(output_transformed_csv),
        str(working_templates_path),
        str(global_constraints_path),
        network_topology=network_topology,
        false_alarm_count_per_scenario=false_alarm_count_per_scenario,
        fa_type_ratio_mode=fa_type_ratio_mode,
        random_seed=42
    )
    
    if not step5_result['success']:
        raise ValueError(
            f"Step 5 failed: {len(step5_result['errors'])} error(s)\n"
            + "\n".join(step5_result['errors'])
        )


    # ============================================================
    # STEP 6: FINAL ASSEMBLY
    # Combine all events, assign timestamps using phase structure
    # Sort chronologically and validate final dataset
    # Output: {scenario}_{total_events}events.csv with metadata columns
    #
    # CONFIG FILE DEPENDENCIES:
    #   - templates_path (zero_day_templates.json):
    #     * Provides all pre-computed event counts (malicious, benign, false_alarm)
    #     * Provides scenario-specific metadata for validation
    #   - global_constraints_path (global_constraints_v2.json):
    #     * Provides temporal_architecture (phase structure for 1800s window)
    #     * Provides output_schema (final column names and format)
    #     * Provides validation_checkpoints (sanity check rules)
    # ============================================================
    
    print(f"\nRunning Step 6: assembling {total_events_per_table}-event tables with temporal ordering...")
    step6_result = step_6.assemble_30_events_step_6(
        str(working_templates_path),
        str(global_constraints_path),
        network_topology=network_topology,
        output_dir=str(output_dir),
        malicious_count_per_scenario=malicious_count_per_scenario,
        benign_count_per_scenario=benign_count_per_scenario,
        false_alarm_count_per_scenario=false_alarm_count_per_scenario,
        total_events_param=total_events_per_table,
        false_alarm_pct_param=false_alarm_pct,
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
    # Validate all generated IDS tables against the AWS network topology
    # defined in network_topology_output.json
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
        print(f"\n✓ Step 7 validation PASSED: All AWS topology constraints satisfied.")

    # ============================================================
    # PIPELINE FLOW
    # Run steps in order: Pre-Step -> 0 -> 1 -> 2 -> 3 -> 4 -> 5 -> 6 -> 7
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


if __name__ == "__main__":
    main()

