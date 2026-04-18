"""
IDS Pipeline (Main Orchestrator)
"""

import json
import pre_step
import step_1
import step_2
import step_3
import step_4
import step_5
from pathlib import Path

def main():

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
    # STEP 0: GLOBAL CONSTRAINTS
    # Define experiment rules (event counts, label ratios, topology, time window)
    # Store all shared configuration parameters for downstream steps
    # Reference: global_constraints.json (pre-populated with constraints)
    # ============================================================
    
    global_constraints_path = Path("templates/global_constraints.json")
    
    # VALIDATION: Verify global_constraints.json exists and is well-formed
    if not global_constraints_path.exists():
        raise FileNotFoundError(f"Global constraints file not found: {global_constraints_path}")
    
    print(f" Global constraints file found: {global_constraints_path}")
    
    # Note: global_constraints.json contains:
    #   - label_distribution (Malicious 10-11, Benign 15, False Alarm 4-5)
    #   - network_topology (3 subnets, 15 hosts total, routing rules)
    #   - unsw_grounding_principles (UNSW as template library, not sequences)
    #   - tiered_synthesis_framework (TIER 1/2/3 based on UNSW row count)
    #   - false_alarm_taxonomy (3 types: unusual_port, high_volume, rare_duration)
    #   - temporal_architecture (5 phases over 1800s observation window)
    #   - output_schema (23 columns: 21 schema + 2 tracking)
    #   - validation_checkpoints (15 critical sanity checks)


    # ============================================================
    # STEP 1: STRUCTURE & VALIDATE ZERO-DAY TEMPLATES
    # Ensure all scenario templates have required fields
    # Validate structure against global constraints
    # Output: validated templates ready for Step 2
    # ============================================================
    
    templates_path = Path("templates/zero_day_templates.json")
    
    # Check if templates file exists
    if not templates_path.exists():
        print(f"Running Step 1: creating and validating zero-day templates...")
        step1_result = step_1.validate_templates_step(
            str(templates_path),
            str(global_constraints_path)
        )
        
        if not step1_result['success']:
            raise ValueError(
                f"Step 1 validation failed: {len(step1_result['errors'])} error(s)\n"
                + "\n".join(step1_result['errors'])
            )
    else:
        # Verify templates are valid JSON without rerunning Step 1
        try:
            with open(templates_path, 'r') as f:
                templates_dict = json.load(f)
            
            # Quick validation: check for required scenarios structure
            if 'scenarios' not in templates_dict:
                raise ValueError("Templates JSON missing 'scenarios' key")
            if not isinstance(templates_dict['scenarios'], list):
                raise ValueError("Templates 'scenarios' must be a list")
            if len(templates_dict['scenarios']) == 0:
                raise ValueError("Templates 'scenarios' is empty")
            
            print(f" Templates file exists and is valid JSON: {templates_path}")
        except json.JSONDecodeError as e:
            raise ValueError(f"Templates JSON is malformed: {e}")
        except Exception as e:
            raise ValueError(f"Templates validation failed: {e}")


    # ============================================================
    # STEP 2: FILTER + TIER CLASSIFICATION
    # Filter transformed data per scenario and compute feature statistics
    # Assign TIER (1 = sufficient data, 2 = limited data)
    # Output: updated templates with TIER + stats
    # ============================================================
    
    print(f"\nRunning Step 2: filtering & tier classification...")
    step2_result = step_2.process_step_2(
        str(output_transformed_csv),
        str(templates_path),
        str(global_constraints_path),
        output_report_path="step_2_summary.txt"
    )
    
    if not step2_result['success']:
        raise ValueError(
            f"Step 2 failed: {len(step2_result['errors'])} error(s)\n"
            + "\n".join(step2_result['errors'])
        )


    # ============================================================
    # STEP 3: MALICIOUS EVENTS
    # Generate 10-11 attack events using real data (TIER 1) or + variations (TIER 2)
    # Ensure logical attack progression and valid network structure
    # Output: malicious events (per scenario)
    # ============================================================
    
    print(f"\nRunning Step 3: generating malicious events...")
    step3_result = step_3.generate_malicious_events_step_3(
        str(output_transformed_csv),
        str(templates_path),
        str(global_constraints_path),
        random_seed=42
    )
    
    if not step3_result['success']:
        raise ValueError(
            f"Step 3 failed: {len(step3_result['errors'])} error(s)\n"
            + "\n".join(step3_result['errors'])
        )


    # ============================================================
    # STEP 4: BENIGN EVENTS
    # Generate 15 normal traffic events (HTTP, DNS, SSH, etc.)
    # Use realistic feature ranges and valid host/subnet combinations
    # Output: benign events (per scenario)
    # ============================================================
    
    print(f"\nRunning Step 4: generating benign events...")
    step4_result = step_4.generate_benign_events_step_4(
        str(output_transformed_csv),
        str(templates_path),
        str(global_constraints_path),
        random_seed=42
    )
    
    if not step4_result['success']:
        raise ValueError(
            f"Step 4 failed: {len(step4_result['errors'])} error(s)\n"
            + "\n".join(step4_result['errors'])
        )


    # ============================================================
    # STEP 5: FALSE ALARMS
    # Generate 5 suspicious-looking but benign events
    # UNSW-grounded, scenario-independent, 3 types
    # Output: false alarm events (per scenario)
    # ============================================================
    
    print(f"\nRunning Step 5: generating false alarm events...")
    step5_result = step_5.generate_false_alarms_step_5(
        str(output_transformed_csv),
        str(templates_path),
        str(global_constraints_path),
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
    # Output: {scenario}_30_events.csv
    # ============================================================
    # TODO: Implement Step 6


    # ============================================================
    # PIPELINE FLOW
    # Run steps in order: Pre-Step -> 0 -> 1 -> 2 -> 3 -> 4 -> 5
    # Then per scenario: 6
    # ============================================================
    print("\n" + "="*80)
    print(" PIPELINE STEPS 0-5 COMPLETED SUCCESSFULLY")
    print("="*80)


if __name__ == "__main__":
    main()
