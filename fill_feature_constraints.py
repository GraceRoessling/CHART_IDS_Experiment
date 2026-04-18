"""
Fill feature_constraints in zero_day_templates.json from _step2_stats.

This script extracts computed statistics from _step2_stats and populates
feature_constraints with practical ranges for feature generation in later steps.

Approach:
- Use actual min/max from UNSW data (already in _step2_stats)
- For rate, compute bytes_per_second from median duration and bytes
- Include unique dports from statistics
"""

import json
from pathlib import Path


def fill_feature_constraints(templates_path):
    """
    Load templates, populate feature_constraints from _step2_stats, and save.
    
    Args:
        templates_path: Path to zero_day_templates.json
    """
    with open(templates_path, 'r') as f:
        templates = json.load(f)
    
    for scenario in templates.get('scenarios', []):
        scenario_name = scenario.get('scenario_name', 'Unknown')
        stats = scenario.get('_step2_stats', {})
        
        if not stats:
            print(f"[WARN] {scenario_name}: No _step2_stats found, skipping.")
            continue
        
        # Extract ranges from statistics
        duration_min = stats.get('duration_min', 0)
        duration_max = stats.get('duration_max', 1)
        duration_median = stats.get('duration_median', 0.5)
        
        bytes_min = stats.get('bytes_min', 60)
        bytes_max = stats.get('bytes_max', 1000)
        bytes_median = stats.get('bytes_median', 500)
        
        packets_min = stats.get('packets_min', 1)
        packets_max = stats.get('packets_max', 100)
        packets_median = stats.get('packets_median', 10)
        
        dports = stats.get('dport_unique', [])
        
        # Compute rate (bytes per second) from median values
        rate_mbps = None
        if duration_median > 0 and bytes_median > 0:
            bytes_per_sec = bytes_median / duration_median
            rate_mbps = round(bytes_per_sec * 8 / 1_000_000, 6)  # Convert to Mbps
        
        # Populate feature_constraints
        feature_constraints = scenario.get('feature_constraints', {})
        feature_constraints['duration'] = {
            'min': round(duration_min, 6),
            'max': round(duration_max, 6),
            'median': round(duration_median, 6),
            '_note': 'seconds'
        }
        feature_constraints['bytes'] = {
            'min': int(bytes_min),
            'max': int(bytes_max),
            'median': int(bytes_median),
            '_note': 'total bytes (sbytes + dbytes)'
        }
        feature_constraints['packets'] = {
            'min': int(packets_min),
            'max': int(packets_max),
            'median': int(packets_median),
            '_note': 'total packets (spkts + dpkts)'
        }
        feature_constraints['rate'] = {
            'median_mbps': rate_mbps,
            '_note': 'computed from median duration and bytes'
        }
        feature_constraints['dport'] = {
            'unique_values': dports,
            '_note': 'destination ports observed in filtered UNSW data'
        }
        
        scenario['feature_constraints'] = feature_constraints
        
        print(f"[OK] {scenario_name}:")
        print(f"   Duration: {duration_min:.6f}s - {duration_max:.6f}s (median: {duration_median:.6f}s)")
        print(f"   Bytes: {bytes_min} - {bytes_max} (median: {bytes_median})")
        print(f"   Packets: {packets_min} - {packets_max} (median: {packets_median})")
        print(f"   Rate: {rate_mbps} Mbps (median)")
        print(f"   Unique dports: {len(dports)} values")
    
    # Save updated templates
    with open(templates_path, 'w') as f:
        json.dump(templates, f, indent=2)
    
    print(f"\n[OK] Updated {templates_path}")


if __name__ == '__main__':
    templates_path = Path(__file__).parent / 'templates' / 'zero_day_templates.json'
    fill_feature_constraints(templates_path)
