"""
IDS Pipeline (Main Orchestrator - Comment Only)
"""

import pre_step
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
        # Output: global_constraints.json


    # ============================================================
    # STEP 1: SCENARIO TEMPLATES
    # Expand scenario templates with placeholders (TIER, temporal structure, FA dist.)
        # Align templates with global constraints
        # Output: updated zero_day_templates.json


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