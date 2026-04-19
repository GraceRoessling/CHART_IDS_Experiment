#!/usr/bin/env python3
"""
Clean up zero_day_templates.json

Removes all intermediate pipeline data that was accumulated from previous runs:
  - _step2_stats
  - _step3_malicious_events
  - _step4_benign_events
  - _step5_false_alarm_events

This is safe because:
  1. These fields are regenerated fresh each pipeline run
  2. They are now persisted in _working_templates.json instead
  3. The source template should contain only static scenario definitions

Usage:
  python cleanup_templates.py
"""

import json
from pathlib import Path
from helper_functions import cleanup_zero_day_templates

def main():
    templates_path = Path("templates/zero_day_templates.json")
    
    if not templates_path.exists():
        print(f"❌ Template file not found: {templates_path}")
        return
    
    # Get size before cleanup
    size_before = templates_path.stat().st_size / 1024
    print(f"📄 Template file size before cleanup: {size_before:.1f} KB")
    
    print(f"\n🧹 Cleaning intermediate pipeline data from {templates_path}...")
    print(f"   Fields to remove: _step2_stats, _step3_malicious_events, _step4_benign_events, _step5_false_alarm_events\n")
    
    try:
        templates, removed_count = cleanup_zero_day_templates(str(templates_path))
        
        # Get size after cleanup
        size_after = templates_path.stat().st_size / 1024
        size_saved = size_before - size_after
        
        print(f"✅ Cleanup successful!")
        print(f"   Removed fields: {removed_count}")
        print(f"   Size after cleanup: {size_after:.1f} KB")
        print(f"   Space saved: {size_saved:.1f} KB ({(size_saved/size_before)*100:.0f}%)")
        print(f"\n📌 The source template is now clean and ready for use in future runs.")
        print(f"   Intermediate data will be stored in _working_templates.json during pipeline execution.")
        
    except Exception as e:
        print(f"❌ Error during cleanup: {e}")
        raise

if __name__ == "__main__":
    main()
