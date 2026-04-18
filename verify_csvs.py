#!/usr/bin/env python
"""Verify all generated CSV files."""
import csv

scenarios = ['WannaCry', 'Data_Theft', 'ShellShock', 'Netcat_Backdoor', 'passwd_gzip_scp']

print("=" * 80)
print("CSV VERIFICATION REPORT")
print("=" * 80)

for scenario in scenarios:
    csv_path = f"IDS_tables/{scenario}_30_events.csv"
    
    with open(csv_path) as f:
        reader = csv.DictReader(f)
        data = list(reader)
        timestamps = [float(row['timestamp']) for row in data]
        
        # Label distribution
        labels = [row['label'] for row in data]
        label_counts = {}
        for label in labels:
            label_counts[label] = label_counts.get(label, 0) + 1
        
        # Check if sorted
        is_sorted = all(timestamps[i] <= timestamps[i+1] for i in range(len(timestamps)-1))
        
        print(f"\n{scenario}:")
        print(f"  Total events: {len(data)}")
        print(f"  Malicious: {label_counts.get('Malicious', 0)}")
        print(f"  Benign: {label_counts.get('Benign', 0)}")
        print(f"  False Alarm: {label_counts.get('False Alarm', 0)}")
        print(f"  Timestamp range: {min(timestamps):.2f}s - {max(timestamps):.2f}s")
        print(f"  Timestamps ordered: {is_sorted}")
        print(f"  Columns: {len(data[0]) if data else 0}")

print("\n" + "=" * 80)
