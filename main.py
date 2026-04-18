"""
IDS Pipeline (Main Orchestrator - Comment Only)
"""

import pre_step
import step_1
from pathlib import Path

def main():

    # ============================================================
    # PRE-STEP: TRANSFORM DATA
    # Load raw UNSW dataset and convert to standardized schema
    # ============================================================
    input_unsw_csv = Path("IDS_Datasets/UNSW_NB15_training-set(in).csv")
    output_transformed_csv = Path("IDS_Datasets/UNSW_NB15_transformed.csv")
    
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
    
    step1_result = step_1.validate_templates_step(
        str(templates_path),
        str(global_constraints_path)
    )
    
    if not step1_result['success']:
        raise ValueError(
            f"Step 1 validation failed: {len(step1_result['errors'])} error(s)\n"
            + "\n".join(step1_result['errors'])
        )


    # ============================================================
    # STEP 2: FILTER + TIER CLASSIFICATION
    # Filter transformed data per scenario and compute feature statistics
        # Assign TIER (1 = sufficient data, 2 = limited data)
        # Output: updated templates with TIER + stats


    # ============================================================
    # STEP 3: MALICIOUS EVENTS
    # Generate 10–11 attack events using real data (TIER 1) or + variations (TIER 2)
        # Ensure logical attack progression and valid network structure
        # Output: malicious events (per scenario)


    # ============================================================
    # STEP 4: BENIGN EVENTS
    # Generate 15 normal traffic events (HTTP, DNS, SSH, etc.)
        # Use realistic feature ranges and valid host/subnet combinations
        # Output: benign events (per scenario)


    # ============================================================
    # STEP 5: FALSE ALARMS
    # Generate 5 “suspicious-looking but benign” events (2 types)
        # Maintain realism while introducing local anomalies
        # Output: false alarm events (per scenario)


    # ============================================================
    # STEP 6: FINAL ASSEMBLY
    # Combine all events, assign timestamps using phase structure
        # Sort chronologically and validate final dataset
        # Output: {scenario}_30_events.csv


    # ============================================================
    # PIPELINE FLOW
    # Run steps in order: Pre-Step → 0 → 1 → 2
    # Then per scenario: 3 → 4 → 5 → 6


if __name__ == "__main__":
    main()