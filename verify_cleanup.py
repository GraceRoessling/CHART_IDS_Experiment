#!/usr/bin/env python3
"""Quick verification that cleanup preserved necessary data"""
import json

with open('templates/zero_day_templates.json', 'r') as f:
    templates = json.load(f)

scenario = templates['scenarios'][0]

print("✅ Cleaned template contains (KEPT):")
print(f"   Scenario: {scenario.get('scenario_name')}")
print(f"   Malicious Count: {scenario.get('malicious_count')}")
print(f"   Has attack_description: {'attack_description' in scenario}")
print(f"   Has feature_constraints: {'feature_constraints' in scenario}")
print(f"   Has temporal_architecture: {'temporal_architecture' in scenario}")
print(f"   Has entry_point: {'entry_point' in scenario}")

print(f"\n❌ Intermediate fields (should be ABSENT):")
print(f"   _step2_stats: {'_step2_stats' in scenario}")
print(f"   _step3_malicious_events: {'_step3_malicious_events' in scenario}")
print(f"   _step4_benign_events: {'_step4_benign_events' in scenario}")
print(f"   _step5_false_alarm_events: {'_step5_false_alarm_events' in scenario}")
