# IDS Table Generation Pipeline (Pre-Step + Steps 0-6)

**Purpose:** Generate realistic 30-event IDS tables simulating five zero-day attack scenarios, grounded in UNSW-NB15 dataset with synthetic causal chaining.

**Scope:** WannaCry, Data Theft (FTP/SSH), ShellShock, Netcat Backdoor, passwd-gzip-scp

**UNSW-NB15 Dataset:** `C:\Users\groessli\Documents\GitHub\CHART_IDS_Experiment\IDSD_Datasets\UNSW_NB15_training-set(in).csv`

**Principle:** UNSW rows are independent flow observations (not sequences). Use as feature templates + synthetic timestamping for realistic causal chains.

---

## **PRE-STEP: Transform UNSW Dataset to Output Schema (Gap 6: Schema Mapping)**

**Objective:** Map UNSW-NB15 columns to output IDS schema, creating an intermediate CSV file for all downstream processing.

**Inputs:**
- UNSW-NB15 CSV (`UNSW_NB15_training-set(in).csv`)
- Network topology definition
- Output schema specification

**Outputs:**
- `UNSW_NB15_transformed.csv` — Aligned dataset with output columns pre-populated where possible

### Pre-Step Rationale

UNSW-NB15 and output IDS tables have misaligned schemas:
- UNSW has raw IPs; output needs hostnames + subnets
- UNSW has directional bytes (sbytes, dbytes); output needs totals
- UNSW lacks temporal/network context; output requires phase-based timing, host mapping

**By transforming upfront**, all subsequent steps (0-6) work with a consistent, ready-to-use dataset.

### Pre-Step Action Items

1. **Create IP→Host Mapping Rules:**

   ```python
   import hashlib
   
   # Define IP ranges to topology
   IP_RANGES = {
       '192.168.1': ['User0', 'User1', 'User2', 'User3', 'User4'],
       '192.168.2': ['Enterprise0', 'Enterprise1', 'Enterprise2', 'Defender'],
       '192.168.3': ['OpHost0', 'OpHost1', 'OpHost2', 'OpServer0'],
       '10.0.3': ['OpHost0', 'OpHost1', 'OpHost2', 'OpServer0'],
   }
   
   SUBNET_MAPPING = {
       'User': 'Subnet 1 (User)',
       'Enterprise': 'Subnet 2 (Enterprise)',
       'OpHost': 'Subnet 3 (Operational)',
       'OpServer': 'Subnet 3 (Operational)',
   }
   
   def map_subnet(host):
       """Infer subnet from hostname prefix."""
       for prefix, subnet in SUBNET_MAPPING.items():
           if host.startswith(prefix):
               return subnet
       return 'Unknown'
   ```

2. **Define IP→Host Deterministic Mapping:**

   ```python
   def map_ip_to_host(ip_address, scenario_name):
       """Deterministically map IP to hostname using MD5 hash."""
       
       # External IP → external_XXX
       if not any(ip_address.startswith(pre) for pre in IP_RANGES.keys()):
           last_octet = ip_address.split('.')[-1]
           return f"external_{last_octet}", "External"
       
       # Determine host pool from IP range
       host_pool = None
       for prefix, hosts in IP_RANGES.items():
           if ip_address.startswith(prefix):
               host_pool = hosts
               break
       
       if not host_pool:
           return None, None
       
       # Deterministic selection: hash(scenario + IP) → consistent mapping
       hash_seed = f"{scenario_name}:{ip_address}"
       hash_value = int(hashlib.md5(hash_seed.encode()).hexdigest(), 16)
       host_idx = hash_value % len(host_pool)
       host = host_pool[host_idx]
       subnet = map_subnet(host)
       
       return host, subnet
   ```

3. **Create Row Transformation Function:**

   ```python
   def infer_service_from_port(dport):
       """Map destination port to service name."""
       port_map = {
           21: 'ftp', 22: 'ssh', 25: 'smtp', 53: 'dns',
           80: 'http', 110: 'pop3', 143: 'imap', 443: 'https',
           445: 'smb', 3389: 'rdp',
       }
       return port_map.get(int(dport), '-')
   
   def transform_unsw_row(unsw_row, scenario_name):
       """Transform single UNSW row to output schema."""
       
       src_ip = unsw_row.get('src_ip')
       dst_ip = unsw_row.get('dst_ip')
       
       src_host, src_subnet = map_ip_to_host(src_ip, scenario_name)
       dst_host, dst_subnet = map_ip_to_host(dst_ip, scenario_name)
       
       # Aggregate directional features
       total_bytes = unsw_row.get('sbytes', 0) + unsw_row.get('dbytes', 0)
       total_packets = unsw_row.get('spkts', 0) + unsw_row.get('dpkts', 0)
       
       transformed = {
           'timestamp': None,  # Will be assigned in Step 6
           'src_host': src_host,
           'dst_host': dst_host,
           'src_subnet': src_subnet,
           'dst_subnet': dst_subnet,
           'proto': unsw_row.get('proto', 'tcp'),
           'sport': int(unsw_row.get('sprt', 0)),
           'dport': int(unsw_row.get('dprt', 0)),
           'service': infer_service_from_port(unsw_row.get('dprt', 0)),
           'duration': float(unsw_row.get('dur', 0)),
           'bytes': int(total_bytes),
           'packets': int(total_packets),
           'attack_cat': unsw_row.get('attack_cat', 'Normal'),
           'label': None,  # Will be set by Step 3 logic
           '_unsw_row_id': unsw_row.get('id'),  # For traceability
           'scenario_name': scenario_name,  # Track which scenario this row belongs to
       }
       
       return transformed
   ```

4. **Batch Transform Full Dataset:**

   ```python
   import pandas as pd
   
   def batch_transform_unsw(input_csv_path, output_csv_path):
       """Transform entire UNSW dataset to output schema."""
       
       # Load UNSW
       unsw_df = pd.read_csv(input_csv_path)
       print(f"Loaded {len(unsw_df)} rows from UNSW-NB15")
       
       transformed_rows = []
       
       for idx, row in unsw_df.iterrows():
           # Map to all 5 scenarios (each IP mapping is scenario-specific)
           for scenario in ['WannaCry', 'Data_Theft', 'ShellShock', 'Netcat_Backdoor', 'passwd_gzip_scp']:
               transformed = transform_unsw_row(row, scenario)
               transformed_rows.append(transformed)
       
       # Create DataFrame with exact column order (from global_constraints.json)
       output_df = pd.DataFrame(transformed_rows)
       
       columns_ordered = [
           'timestamp', 'src_host', 'dst_host', 'src_subnet', 'dst_subnet',
           'proto', 'sport', 'dport', 'service', 'duration', 'bytes', 'packets',
           'attack_cat', 'label', '_unsw_row_id', 'scenario_name'
       ]
       
       output_df = output_df[columns_ordered]
       
       # Validation
       print(f"\nTransformation Summary:")
       print(f"  Original rows: {len(unsw_df)}")
       print(f"  Transformed rows (5 scenarios): {len(output_df)}")
       print(f"  Null hosts: {output_df[['src_host', 'dst_host']].isnull().sum().sum()}")
       print(f"  Subnet distribution:\n{output_df['src_subnet'].value_counts()}")
       
       # Save
       output_df.to_csv(output_csv_path, index=False)
       print(f"\n✅ Saved transformed dataset: {output_csv_path}")
       
       return output_df
   ```

5. **Run Transformation:**

   ```python
   # Execute before any pipeline steps
   batch_transform_unsw(
       input_csv_path="IDSD_Datasets/UNSW_NB15_training-set(in).csv",
       output_csv_path="UNSW_NB15_transformed.csv"
   )
   ```

6. **Validate Transformation:**

   ```python
   # Quick sanity checks
   transformed_df = pd.read_csv("UNSW_NB15_transformed.csv")
   
   # Check 1: No null critical columns
   assert transformed_df[['src_host', 'dst_host', 'src_subnet', 'dst_subnet']].notnull().all().all(), \
       "Missing hostnames or subnets"
   
   # Check 2: Service matches port
   for idx, row in transformed_df.iterrows():
       dport = row['dport']
       service = row['service']
       # Spot-check sample
       if dport == 445 and service != 'smb':
           print(f"Warning: Port {dport} should be 'smb', got '{service}'")
   
   # Check 3: Bytes/packets consistency
   assert (transformed_df['bytes'] >= 0).all(), "Negative bytes found"
   assert (transformed_df['packets'] >= 0).all(), "Negative packets found"
   
   print("✅ Transformation validation complete")
   ```

---

## **STEP 0: Define Global Constraints Template**

**Objective:** Establish cross-scenario constraints that apply to ALL five tables.

**Inputs:**
- `ids_pipeline_remediation.md` (Gaps 1-5 analysis)
- Cyber attack domain knowledge

**Outputs:**
- `global_constraints.json` — Master constraints for all scenarios

### Step 0 Action Items

1. **Extract Global Constraints** from `ids_pipeline_remediation.md`:
   - Label distribution (35% malicious, 50% benign, 15% false alarm)
   - Network topology (3 subnets, specific hosts)
   - Observation window (1800 seconds)
   - Output schema (14 columns with ordering)
   - UNSW grounding principles
   - Tiered synthesis framework (TIER 1/2/3)
   - False alarm taxonomy (3 types)
   - Temporal architecture (5 phases)
   - Validation checkpoints

2. **Populate `global_constraints.json`** with:
   - All constraints above in structured JSON format
   - Documentation strings explaining each constraint
   - References to remediation document sections

3. **Validation:** Ensure `global_constraints.json` is parseable and references are consistent with remediation doc.

---

## **STEP 1: Structure Zero-Day Templates JSON**

**Objective:** Define per-scenario configuration with fields for both static metadata and analysis-derived data (to be populated in Step 2+).

**Inputs:**
- Current `zero_day_templates.json` (existing 5 scenarios)
- `global_constraints.json`

**Outputs:**
- Updated `zero_day_templates.json` with new fields (analysis-dependent fields left empty)

### Step 1 Action Items

1. **Preserve Existing Fields** (do NOT modify):
   - `scenario_name`
   - `attack_description`
   - `entry_point`
   - `target_asset`
   - `key_attack_behaviors`
   - `unsw_filtering` (attack_cat, proto, dport constraints)

2. **Add New Fields (leave empty for Step 2+)**:

   a) **`feature_constraints`** (to be populated in Step 2, validated from UNSW):
   ```json
   "feature_constraints": {
     "duration": null,  // [min, max] in seconds; from UNSW percentiles
     "bytes": null,     // [min, max]; from UNSW percentiles
     "packets": null,   // [min, max]; from UNSW percentiles
     "rate": null,      // [min, max] flows/sec; from UNSW filtering
     "dport": null      // Allowed ports; from unsw_filtering.dport
   }
   ```

   b) **`temporal_architecture`** (to be populated in Step 2 after understanding attack phases):
   ```json
   "temporal_architecture": {
     "total_duration": 1800,
     "phases": null,     // Array of phase objects; populated based on scenario attack narrative
     "false_alarm_zones": null  // [[start, end], ...]; placed outside attack progression
   }
   ```

   c) **`false_alarm_distribution`** (to be decided per scenario):
   ```json
   "false_alarm_distribution": {
     "type_1_unusual_port_benign_service": null,
     "type_2_high_volume_low_risk": null,
     "type_3_rare_duration_benign": null
   }
   ```

   d) **`expected_tier`** (to be determined in Step 2 via UNSW filtering):
   ```json
   "expected_tier": null  // 1, 2, or 3; based on UNSW row count after filtering
   ```

3. **Schema Validation:** Ensure JSON is well-formed.

---

## **STEP 2: Extract & Validate UNSW Data**

**Objective:** Filter transformed UNSW-NB15 by scenario, extract feature statistics, determine tier classification, and validate against global constraints.

**Inputs:**
- `UNSW_NB15_transformed.csv` (output from Pre-Step; schema-aligned)
- `zero_day_templates.json` (with unsw_filtering rules)
- `global_constraints.json` (validation thresholds)

**Outputs:**
- Scenario-specific feature statistics
- UNSW row counts (determines TIER)
- Validation report
- Updated `zero_day_templates.json` with feature_constraints, temporal_architecture scaffolding, false_alarm_distribution, expected_tier

### Step 2 Action Items

1. **For each scenario, load transformed data:**

   ```python
   import pandas as pd
   
   # Load transformed dataset (from Pre-Step output)
   transformed_df = pd.read_csv("UNSW_NB15_transformed.csv")
   print(f"Loaded {len(transformed_df)} transformed rows")
   
   # Note: transformed_df has 5x rows (one for each scenario's IP mapping)
   # Filter to current scenario using the scenario_name column added in Pre-Step
   ```

2. **Filter by scenario's `unsw_filtering` rules:**

   ```python
   # Example (WannaCry)
   filters = {
       "attack_cat": ["Exploits", "Worms"]
   }
   
   # Filter for current scenario first (scenario_name column added in Pre-Step)
   filtered_df = transformed_df[transformed_df['scenario_name'] == scenario_name].copy()
   print(f"Scenario {scenario_name}: {len(filtered_df)} rows after scenario filter")
   
   # Apply attack_cat filter
   for col, values in filters.items():
       if col in filtered_df.columns:
           filtered_df = filtered_df[filtered_df[col].isin(values)]
   
   # Additional scenario-specific filters (from unsw_filtering)
   scenario_config = zero_day_templates['scenarios'][0]  # WannaCry
   unsw_filters = scenario_config['unsw_filtering']
   
   if 'dport' in unsw_filters and unsw_filters['dport']:
       filtered_df = filtered_df[filtered_df['dport'].isin(unsw_filters['dport'])]
   
   if 'proto' in unsw_filters and unsw_filters['proto']:
       filtered_df = filtered_df[filtered_df['proto'].isin(unsw_filters['proto'])]
   ```

3. **Compute feature statistics (percentiles):**
   ```python
   stats = {
     "row_count": len(filtered_df),
     "duration": {
       "min": filtered_df['duration'].min(),
       "max": filtered_df['duration'].max(),
       "p5": filtered_df['duration'].quantile(0.05),
       "p95": filtered_df['duration'].quantile(0.95),
       "mean": filtered_df['duration'].mean(),
       "median": filtered_df['duration'].median()
     },
     "bytes": { /* similar */ },
     "packets": { /* similar */ },
     "dport_unique": filtered_df['dport'].unique().tolist(),
     "proto_unique": filtered_df['proto'].unique().tolist()
   }
   ```

   d) **Determine TIER classification:**
   ```python
   # TIER classification (simplified: TIER 1 or TIER 2 only)
   if len(filtered_df) >= 10:
       tier = 1  # Use actual UNSW events
   elif len(filtered_df) >= 5:
       tier = 2  # Mix actual + parameterized variations
   else:
       raise ValueError(f"{scenario_name}: Only {len(filtered_df)} UNSW rows after filtering. "
                        f"Minimum 5 required for TIER 2. Review unsw_filtering rules.")
   
   # Basic sanity check: non-empty dataset
   if len(filtered_df) == 0:
       raise ValueError(f"{scenario_name}: No UNSW rows match filters. Review attack_cat/proto/dport constraints.")
   
   print(f"✅ {scenario_name}: {len(filtered_df)} filtered rows → TIER {tier}")
   ```

2. **Compute Percentile Ranges (for informational purposes):**

   ```python
   # Simple feature statistics extraction (no complex validation)
   def compute_feature_stats(df, scenario_name):
       """Extract percentile ranges from filtered data."""
       stats = {
           'scenario': scenario_name,
           'row_count': len(df),
           'duration_min': df['duration'].min(),
           'duration_max': df['duration'].max(),
           'duration_median': df['duration'].median(),
           'bytes_min': df['bytes'].min(),
           'bytes_max': df['bytes'].max(),
           'bytes_median': df['bytes'].median(),
           'packets_min': df['packets'].min(),
           'packets_max': df['packets'].max(),
       }
       print(f"  Duration range: {stats['duration_min']:.2f}s - {stats['duration_max']:.2f}s (median: {stats['duration_median']:.2f}s)")
       print(f"  Bytes range: {stats['bytes_min']} - {stats['bytes_max']} (median: {stats['bytes_median']})")
       return stats
   ```

3. **Create Summary Report (printed to console):**

   For each scenario, print:
   - Number of UNSW rows after filtering
   - Assigned TIER
   - Feature statistics (duration/bytes ranges)

   Example output:
   ```yaml
   WannaCry:
     unsw_rows_after_filtering: 312
     tier: 1
     duration_stats: min=0.03s, max=15.2s, median=0.6s
     bytes_stats: min=200, max=85000, median=2400
     status: ✅ Ready for synthesis
   ```

3. **Update `zero_day_templates.json`** with computed TIER:

   a) **`expected_tier`** = computed TIER (1 or 2)

   b) **`temporal_architecture.phases`** (standard schedule for all scenarios):
   ```json
   "phases": [
     {"name": "benign_baseline", "start": 0, "end": 300, "event_count": 6},
     {"name": "attack_phase_1", "start": 300, "end": 600, "event_count": 3},
     {"name": "attack_phase_2", "start": 600, "end": 900, "event_count": 3},
     {"name": "attack_phase_3", "start": 900, "end": 1200, "event_count": 2},
     {"name": "benign_recovery", "start": 1200, "end": 1800, "event_count": 9}
   ]
   ```

   c) **`false_alarm_distribution`** (simplified to 2 types; see Step 5):
   ```json
   {
     "type_1_unusual_benign": 2,
     "type_2_high_volume_benign": 3
   }
   ```

---

## **STEP 3: Generate Synthetic Malicious Events**

**Objective:** Create 10-11 realistic malicious events per scenario using tiered synthesis based on Step 2 TIER classification.

**Inputs:**
- Filtered UNSW data (from Step 2)
- Scenario `entry_point`, `target_asset`, `key_attack_behaviors`
- TIER classification (1 or 2)

**Outputs:**
- List of 10-11 malicious event dictionaries with fields:
  - `timestamp` (placeholder, to be assigned in Step 6)
  - `src_host`, `dst_host`
  - `src_subnet`, `dst_subnet`
  - `proto`, `sport`, `dport`, `service`
  - `duration`, `bytes`, `packets`
  - `attack_cat`, `label` (='Malicious')
  - `_source` (tracking: UNSW_actual / UNSW_parameterized)

### Step 3 Action Items

1. **TIER 1 (≥ 10 UNSW rows):**

   a) Randomly sample 10-11 rows from filtered UNSW data
   b) Assign deterministic `src_host` / `dst_host` mapping (preserving subnet topology)
   c) Set `label` = 'Malicious', `_source` = 'UNSW_actual'
   d) Preserve original `duration`, `bytes`, `packets` (from UNSW)

2. **TIER 2 (5-9 UNSW rows):**

   a) Keep all actual rows (5-9 events)
   b) For remaining events needed (to reach 10-11):
      - Select base row from filtered UNSW
      - Create parameterized variation:
        - Vary `src_host` within same subnet (e.g., User1 → User3)
        - Vary `dst_host` (different target, same vulnerability class, same subnet)
        - Perturb `duration` by ±20% (random multiplier 0.8-1.2)
        - Scale `bytes` by ±15% (preserves relative magnitude)
        - Adjust `packets` proportionally to maintain byte/packet ratio
      - Set `_source` = 'UNSW_parameterized'

3. **Ordering & Causality:**

   a) Order malicious events to form a logical attack chain (entry_point → target_asset progression)
   b) Ensure cross-subnet transitions follow topology rules (e.g., User1 → Enterprise* → Operational if applicable)
   c) Later events should show evidence of progression (higher bytes for exfiltration, privilege escalation)

---

## **STEP 4: Generate Benign Events**

**Objective:** Create 15 routine enterprise events unrelated to attack progression.

**Inputs:**
- Network topology
- UNSW benign flows (attack_cat='Normal')

**Outputs:**
- List of 15 benign event dictionaries

### Step 4 Action Items

1. **General Benign Traffic Types:**

   - Web browsing: proto=http, dport=80, low bytes (5KB-500KB), duration 1-30s
   - DNS queries: proto=tcp/udp, dport=53, low bytes (100-1000), duration <2s
   - SSH admin: dport=22, duration 10-600s, medium bytes
   - FTP file transfer: dport=21, higher bytes, duration 5-120s
   - SMTP email: dport=25, moderate bytes
   - RDP remote access: dport=3389, sustained connections

2. **Generation Strategy (Gap 7 Implementation - Scenario-Independent Benign Events):**

   **Design Principle:** Benign events are intentionally **generic across all scenarios**. The IDS system has no prior knowledge of the specific zero-day attack, so network baseline traffic is indistinguishable between scenarios. This reflects realistic operational assumptions.

   a) Sample from UNSW rows where `attack_cat`='Normal' (from any scenario, not per-scenario)
   b) Randomly assign sources from User/Enterprise subnets
   c) Randomly assign destinations (internal or external, appropriate to service)
   d) Assign deterministic hostnames (preserving topology)
   e) Ensure variety (not all same service/port)

3. **Constraints:**

   a) Must be internally consistent (bytes, packets, duration aligned)
   b) No sensitive ports (22, 445 for persistent connections in benign events—unless SSH admin is expected)
   c) Label = 'Benign', attack_cat = 'Normal'

---

## **STEP 5: Generate False Alarm Events**

**Objective:** Create 4-5 locally anomalous but globally common events.

**Inputs:**
- False alarm distribution from `zero_day_templates.json` (simplified to 2 types)
- Network topology

**Outputs:**
- List of 4-5 false alarm event dictionaries

### Step 5 Action Items

1. **Generate by Type (simplified taxonomy: 2 types instead of 3):**

   **Type 1: Unusual Port + Benign Service (2 events)**
   ```python
   def generate_type1_unusual_benign(count=2):
       """Event looks suspicious (unusual port) but service is harmless."""
       events = []
       for i in range(count):
           event = {
               'src_host': random.choice(['Enterprise0', 'Enterprise1', 'Enterprise2']),
               'dst_host': f'8.8.8.{10+i}',  # External
               'proto': 'tcp',
               'dport': random.randint(10000, 65535),  # High/unusual port
               'service': 'dns',  # But benign service
               'duration': random.uniform(0.5, 2.0),
               'bytes': random.randint(100, 500),
               'packets': random.randint(5, 20),
               'attack_cat': 'Normal',
               'label': 'False Alarm'
           }
           events.append(event)
       return events
   ```

   **Type 2: High Volume + Low-Risk Service (3 events)**
   ```python
   def generate_type2_high_volume_benign(count=3):
       """Event looks suspicious (huge volume) but context is harmless."""
       events = []
       for i in range(count):
           event = {
               'src_host': random.choice(['User0', 'User1', 'User2', 'Enterprise1']),
               'dst_host': random.choice(['1.1.1.1', '8.8.8.8']),  # External
               'proto': 'tcp',
               'dport': 53,  # DNS—low-risk port
               'service': 'dns',
               'duration': random.uniform(30, 180),  # Long duration
               'bytes': random.randint(5000000, 50000000),  # 5-50 MB (unusual for DNS)
               'packets': random.randint(500, 3000),
               'attack_cat': 'Normal',
               'label': 'False Alarm'
           }
           events.append(event)
       return events
   ```

2. **Distribution Logic:**

   a) Generate Type 1: 2 events
   b) Generate Type 2: 3 events
   c) Total: 5 false alarm events
   d) Shuffle order before passing to Step 6

3. **Basic Sanity Check:**

   ```python
   def validate_false_alarms(fa_events, scenario_name):
       """Quick check: all false alarms marked as 'Normal' attack_cat."""
       normal_count = sum(1 for e in fa_events if e.get('attack_cat') == 'Normal')
       assert normal_count == len(fa_events), \
           f"ERROR: {len(fa_events) - normal_count} false alarms missing 'Normal' attack_cat"
       print(f"  ✅ {scenario_name}: {len(fa_events)} false alarms validated")
   ```

---

## **STEP 6: Assemble 30-Event Tables with Temporal Ordering**

**Objective:** Combine malicious (10-11), benign (15), and false alarm (5) events; assign timestamps following phase architecture; output final CSV.

**Inputs:**
- Malicious events from Step 3
- Benign events from Step 4
- False alarm events from Step 5 (now exactly 5 events)
- Temporal architecture from Step 1

**Outputs:**
- CSV table (30 rows, 14 columns) with timestamps in increasing order

### Step 6 Action Items

1. **Assign Timestamps Using Phase Architecture:**

   ```python
   import random
   
   # Phase schedule (standard for all scenarios)
   phases = [
       {'name': 'benign_baseline', 'start': 0, 'end': 300, 'event_count': 6},
       {'name': 'attack_phase_1', 'start': 300, 'end': 600, 'event_count': 3},
       {'name': 'attack_phase_2', 'start': 600, 'end': 900, 'event_count': 3},
       {'name': 'attack_phase_3', 'start': 900, 'end': 1200, 'event_count': 2},
       {'name': 'benign_recovery', 'start': 1200, 'end': 1800, 'event_count': 9}
   ]
   
   timestamped_events = []
   
   for phase in phases:
       phase_name = phase['name']
       phase_start = phase['start']
       phase_end = phase['end']
       phase_event_count = phase['event_count']
       
       # Select events for this phase
       if 'attack' in phase_name:
           event_pool = malicious_events if len(malicious_events) > 0 else []
           events_to_assign = [event_pool.pop(0) for _ in range(min(phase_event_count, len(event_pool)))]
       else:
           event_pool = benign_events + false_alarm_events
           events_to_assign = [event_pool.pop(0) for _ in range(min(phase_event_count, len(event_pool)))]
       
       # Assign timestamps
       for i, event in enumerate(events_to_assign):
           if 'attack' in phase_name:
               # Attack events: sequential and regular spacing
               interval = (phase_end - phase_start) / phase_event_count
               t = phase_start + (i * interval) + random.uniform(0, 5)  # Small random jitter
           else:
               # Benign/false alarm events: scattered randomly
               t = phase_start + random.uniform(0, phase_end - phase_start)
           
           event['timestamp'] = t
           timestamped_events.append(event)
   
   # Sort all events by timestamp
   timestamped_events.sort(key=lambda e: e['timestamp'])
   ```

2. **Basic Sanity Checks:**

   ```python
   def validate_output(timestamped_events, scenario_name):
       """Quick sanity checks on final output."""
       # Check 1: Event count = 30
       assert len(timestamped_events) == 30, \
           f"ERROR: Expected 30 events, got {len(timestamped_events)}"
       
       # Check 2: Timestamps strictly increasing
       timestamps = [e['timestamp'] for e in timestamped_events]
       assert all(timestamps[i] <= timestamps[i+1] for i in range(len(timestamps)-1)), \
           "ERROR: Timestamps not in increasing order"
       
       # Check 3: Label distribution roughly correct
       mal_count = sum(1 for e in timestamped_events if e['label'] == 'Malicious')
       ben_count = sum(1 for e in timestamped_events if e['label'] == 'Benign')
       fa_count = sum(1 for e in timestamped_events if e['label'] == 'False Alarm')
       
       print(f"  ✅ {scenario_name}: {mal_count} malicious, {ben_count} benign, {fa_count} false alarms")
       print(f"     Time range: {timestamps[0]:.1f}s - {timestamps[-1]:.1f}s")
   ```

3. **Write CSV Output:**

   ```python
   import pandas as pd
   
   # Convert to DataFrame
   output_df = pd.DataFrame(timestamped_events)
   
   # Select columns in exact order (from global_constraints.json)
   columns_ordered = [
       'timestamp', 'src_host', 'dst_host', 'src_subnet', 'dst_subnet',
       'proto', 'sport', 'dport', 'service', 'duration', 'bytes', 'packets',
       'attack_cat', 'label'
   ]
   
   output_df = output_df[columns_ordered]
   
   # Write CSV
   output_df.to_csv(f"{scenario_name}_30_events.csv", index=False)
   ```

---

## **Output Schema Specification**

### Column Definitions (EXACT ORDER REQUIRED)

| Column | Type | Constraints | Example |
|--------|------|-------------|---------|
| **timestamp** | float | 0 ≤ t ≤ 1800 (strictly increasing) | 45.3 |
| **src_host** | string | Must be defined host (User0-4, Enterprise0-2, Defender, OpHost0-2, OpServer0, or external_XXXX) | User1 |
| **dst_host** | string | Must be defined host | Enterprise2 |
| **src_subnet** | string | Inferred from src_host; one of: "Subnet 1 (User)", "Subnet 2 (Enterprise)", "Subnet 3 (Operational)", "External" | Subnet 1 (User) |
| **dst_subnet** | string | Inferred from dst_host | Subnet 2 (Enterprise) |
| **proto** | string | tcp \| udp \| http | tcp |
| **sport** | int | 1024-65535 (ephemeral) | 54321 |
| **dport** | int | Scenario-specific | 445 |
| **service** | string | http \| ftp \| ssh \| dns \| snmp \| smtp \| smb \| - | smb |
| **duration** | float | Scenario-constrained; seconds | 0.85 |
| **bytes** | int | Feature-consistent with duration/packets | 5000 |
| **packets** | int | Feature-consistent with bytes/duration | 25 |
| **attack_cat** | string | UNSW category: Normal \| Exploits \| Worms \| Backdoor \| Shellcode | Worms |
| **label** | string | Benign \| Malicious \| False Alarm | Malicious |

---

## **Sanity Checks (All Steps)**

- [ ] Exactly 30 events per scenario
- [ ] Label distribution: 10-11 malicious, 15 benign, 4-5 false alarms (±1 tolerance)
- [ ] All host assignments valid (belong to defined topology)
- [ ] All timestamps strictly increasing (0-1800s)
- [ ] Malicious events form coherent attack chain (contiguous ~900s window)
- [ ] False alarms NOT temporally adjacent to malicious chain
- [ ] All feature values internally consistent (bytes↔packets↔duration)
- [ ] Service matches dport (80→http, 22→ssh, 53→dns, 21→ftp, 445→smb)
- [ ] All attack_cat values from UNSW categories
- [ ] CSV column order exact
- [ ] No missing or NaN values in output

---

## **Key References**

- [UNSW-NB15 Dataset](IDSD_Datasets/UNSW_NB15_training-set(in).csv) — Original source data
- [UNSW_NB15_transformed.csv](UNSW_NB15_transformed.csv) — Transformed output from Pre-Step (schema-aligned, ready for Steps 0-6)
- [global_constraints.json](global_constraints.json) — Master constraints for all scenarios
- [zero_day_templates.json](zero_day_templates.json) — Per-scenario metadata
- [ids_pipeline_remediation.md](ids_pipeline_remediation.md) — Detailed gap analysis and remediation strategies (Gaps 1-6, with Gap 6 addressed in Pre-Step)

---

## **Simplified Pipeline Execution Order**

1. ✅ **Pre-Step**: Transform UNSW → `UNSW_NB15_transformed.csv`
2. ✅ **Step 0**: Define global constraints → `global_constraints.json` (manual JSON)
3. ✅ **Step 1**: Update scenario templates → `zero_day_templates.json` (add TIER + phases)
4. ✅ **Step 2**: Extract UNSW stats & classify TIER (1 or 2 only)
5. ✅ **Step 3**: Generate malicious events (TIER 1 or 2, no KDE)
6. ✅ **Step 4**: Generate benign events (15 events)
7. ✅ **Step 5**: Generate false alarm events (5 events, 2 types)
8. ✅ **Step 6**: Assemble & timestamp → Final 30-event CSV tables

---

## **Implementation Notes**

- **Pre-Step critical**: Transforms UNSW to output format. All downstream steps depend on it.
- **Scenario tracking**: `scenario_name` column in transformed CSV ensures proper filtering by scenario.
- **Deterministic IP→host mapping**: Same IP always maps to same hostname within scenario (MD5 hash-based).
- **Simplicity focus**: Each step is self-contained and testable. No complex interdependencies.
- **Manual intervention points**: If data looks wrong (e.g., too few UNSW rows after filtering), adjust `unsw_filtering` rules in JSON manually; don't try to auto-remediate.
- **CSV validation**: Output CSVs should have exactly 30 rows with timestamps 0-1800s in increasing order. Check in Excel or with `head/tail` commands.

---

## **Simplified Design: Key Decisions**

### **Decision 1: TIER 1 & 2 Only (No KDE)**
- **Rationale**: Simpler, more transparent. Most scenarios have sufficient UNSW data.
- **Implementation**: If ≥10 UNSW rows: use actual events (TIER 1). If 5-9: mix actual + parameterized (TIER 2).
- **Minimum threshold**: 5 rows (anything less fails with error; adjust filters manually).

### **Decision 2: Simplified False Alarms (2 Types, 5 Total Events)**
- **Type 1: Unusual_Benign** (2 events) — High port + benign service (looks suspicious, isn't)
- **Type 2: High_Volume_Benign** (3 events) — Large bytes + low-risk service (looks like exfil, isn't)
- **Removed**: "Rare_Duration_Benign" type (3rd type; was overspecified)

### **Decision 3: No Feature Validation/Remediation**
- **Rationale**: Feature stats are informational only. If filtered data looks wrong, adjust UNSW filter rules in JSON manually.
- **Implementation**: Just print duration/bytes ranges for each scenario; no violation checks or remediation strategies.

### **Decision 4: Basic Temporal Ordering (No Exhaustive Validation)**
- **Phase-based assignment**: Attack events sequential (0-1200s), benign/false alarms scattered
- **No thresholds**: Skip checks like "attack window ≤ 1000s" or "no isolated malicious events". Just verify timestamps increasing.
- **No visualization**: Skip matplotlib. Check CSV in Excel/Python directly.

### **Decision 5: Deterministic But Simple Hostnames**
- **Approach**: Map IPs to hosts using scenario-specific hash (Pre-Step). Same IP always → same hostname within scenario.
- **No dynamic updates**: Hostnames don't change; they're set once and reused.

---

## **What This Means: Comparison**

| Aspect | Original | Simplified |
|--------|----------|-----------|
| TIER approach | 1/2/3 (with KDE) | 1/2 only (no KDE) |
| False alarm types | 3 types | 2 types |
| Feature validation | Exhaustive (violation checks, remediation) | Informational only |
| Temporal validation | 4 thresholds (attack window, isolation, adjacency) | Basic (timestamps increasing) |
| Visualization | Timeline PNG | CSV only |
| Libraries needed | pandas + scipy + matplotlib | pandas only |
| Scripts | ~6 (total ~900 lines) | ~6 (total ~600 lines) |
| Time expected | 1-2 weeks | 1-2 days |

---

## **Quick Start: Simplified Pipeline Summary**

This document now reflects a **pragmatic, simplified approach** to generating synthetic IDS event tables.

### **What Changed:**

✅ **TIER 1 & 2 only** — No KDE synthesis. Use real UNSW data or simple ±20% parameterized variations.

✅ **2 false alarm types** — Cut from 3 to 2 types (Unusual_Benign + High_Volume_Benign = 5 total events).

✅ **Basic stats only** — Extract feature ranges but skip fancy validation/remediation. If data looks wrong, adjust filters manually.

✅ **Simple temporal ordering** — Phase-based assignment (attack events sequential, benign scattered). Skip threshold checks and PNG visualization.

✅ **pandas only** — Removed scipy (no KDE) and matplotlib (no timeline PNG).

### **You Will Need:**

- Python 3.7+
- pandas (`pip install pandas`)
- Input CSV: `IDSD_Datasets/UNSW_NB15_training-set(in).csv`
- JSON templates: `global_constraints.json` + `zero_day_templates.json`

### **You Will Create:**

6 Python scripts (~600 lines total):
1. **Pre-Step**: Transform UNSW to schema (~150 lines)
2. **Step 2**: Extract stats & classify TIER (~140 lines)
3. **Step 3**: Generate malicious events (~180 lines)
4. **Step 4**: Generate benign events (~120 lines)
5. **Step 5**: Generate false alarms (~100 lines)
6. **Step 6**: Assemble & output CSV (~130 lines)

Plus manual setup:
- **Step 0**: Create `global_constraints.json` (hand-written JSON, ~50 lines)
- **Step 1**: Update `zero_day_templates.json` with TIER + phases (JSON edits, ~10 lines per scenario)

### **Expected Output:**

5 CSV files (one per scenario):
- `WannaCry_30_events.csv`
- `Data_Theft_30_events.csv`
- `ShellShock_30_events.csv`
- `Netcat_Backdoor_30_events.csv`
- `passwd_gzip_scp_30_events.csv`

Each: exactly 30 rows, 14 columns, timestamps 0-1800s increasing, label distribution: ~11 malicious, 15 benign, 5 false alarms.

### **Next Steps:**

1. **Run Pre-Step** to transform UNSW dataset
2. **Manually edit JSON files** (Steps 0-1)
3. **Run Scripts 2-6** sequentially (or in a loop for each scenario)
4. **Validate output CSVs** in Excel/Python (check row count, timestamps, label distribution)
5. Done! Ready for downstream analysis.

For questions: refer to the step-by-step descriptions above. Each step is self-contained and includes example code.

