"""
IDS Pipeline - Main Entry Point

Simple, parameterized pipeline orchestrator.
Set your configuration parameters below, then run.
"""

from helper_functions import PipelineConfig, run_pipeline


# ============================================================
# USER CONFIGURATION
# ============================================================
# Modify these three lines to customize the pipeline run:

TOTAL_EVENTS_PER_TABLE = 30           # Range: 18-45 events per table
FALSE_ALARM_BIN = "standard"         # Options: zero | very_conservative | conservative | standard | elevated | high
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

