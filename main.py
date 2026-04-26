r"""
IDS Pipeline - Main Entry Point

Simple, parameterized pipeline orchestrator.
Set your configuration parameters below, then run.

IMPORTANT: Dataset Setup
  The UNSW_NB15_transformed.csv dataset is stored on Google Drive (too large for GitHub).
  Ensure your Google Drive is mounted/accessible before running this pipeline.
  The path is defined in helper_functions.py:
    G:\.shortcut-targets-by-id\1zFPkx_p8sPRshZUcZ95mHkYUPR3dh1-i\...\UNSW_NB15_transformed.csv
"""

from helper_functions import PipelineConfig, run_pipeline


# ============================================================
# USER CONFIGURATION
# ============================================================
# Modify these three lines to customize the pipeline run:

TOTAL_EVENTS_PER_TABLE = 18           # Range: 18-45 events per table
FALSE_ALARM_BIN = "high"             # Options: zero | very_conservative | conservative | standard | elevated | high
FA_TYPE_RATIO_MODE = "balanced"      # Options: balanced | port_heavy | volume_heavy | duration_heavy

# ============================================================
# END OF USER CONFIGURATION
# ============================================================


if __name__ == "__main__":
    # Create configuration object with validation
    config = PipelineConfig(
        total_events_per_table=TOTAL_EVENTS_PER_TABLE,
        false_alarm_bin=FALSE_ALARM_BIN,
        fa_type_ratio_mode=FA_TYPE_RATIO_MODE
    )
    
    # Run the pipeline
    run_pipeline(config)
