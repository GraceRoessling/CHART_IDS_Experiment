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

   d) **Determine TIER classification and run feature validation:**
   ```python
   # TIER classification
   if len(filtered_df) >= 10:
       tier = 1  # Use actual UNSW events
   elif 5 <= len(filtered_df) < 10:
       tier = 2  # Mix actual + parameterized
   elif len(filtered_df) >= 2:  # Minimum for KDE reliability
       tier = 3  # Synthesis (KDE); requires at least 2 events for meaningful distribution
   else:
       raise ValueError(f"{scenario_name}: Only {len(filtered_df)} UNSW rows after filtering. "
                        f"Minimum 2 required for TIER 3. Review unsw_filtering rules.")
   
   # Feature validation (Gap 2 remediation)
   validation_report = validate_filtered_features(scenario_name, filtered_df, FEATURE_CONSTRAINTS)
   
   # Decision: Apply remediation if >30% violations
   if validation_report['violation_rate'] > 0.30:
       print(f"⚠️ WARNING: {scenario_name} has {validation_report['violation_rate']*100:.1f}% violations")
       remediation_strategy = apply_feature_remediation(scenario_name, filtered_df, validation_report)
       print(f"   Applied remediation: {remediation_strategy['type']}")
       filtered_df = remediation_strategy['result_df']
   else:
       print(f"✅ {scenario_name} feature validation passed ({validation_report['violation_rate']*100:.1f}% violations)")
   ```

2. **Feature Validation Functions (Gap 2 Implementation):**

   ```python
   # Define per-scenario feature constraints (from global_constraints.json)
   FEATURE_CONSTRAINTS = {
       'WannaCry': {
           'duration': [0.1, 2.0],  # seconds (based on rapid SMB scanning)
           'bytes': [200, 100000],  # quick bursts, not large transfers
           'packets': [5, 100],
           'dport': [445],  # SMB only
       },
       'Data_Theft': {
           'duration': [10, 300],  # longer sessions for file ops
           'bytes': [1000000, 100000000],  # high-volume exfiltration
           'packets': [100, 200000],
           'dport': [21, 22],  # FTP/SSH
       },
       # ... (similar for ShellShock, Netcat_Backdoor, passwd_gzip_scp)
   }
   
   def validate_filtered_features(scenario_name, df, constraints):
       """Validate that filtered rows match expected feature ranges (Gap 2)."""
       if scenario_name not in constraints:
           return {'violation_rate': 0.0, 'violations': []}
       
       c = constraints[scenario_name]
       violations = []
       
       for idx, row in df.iterrows():
           if not (c['duration'][0] <= row['duration'] <= c['duration'][1]):
               violations.append(('duration', row['duration'], f"{c['duration']}"))
           if not (c['bytes'][0] <= row['bytes'] <= c['bytes'][1]):
               violations.append(('bytes', row['bytes'], f"{c['bytes']}"))
           if row['dport'] not in c['dport']:
               violations.append(('dport', row['dport'], f"{c['dport']}"))
       
       return {
           'violation_rate': len(violations) / max(len(df), 1),
           'violations': violations
       }
   
   def apply_feature_remediation(scenario_name, df, validation_report):
       """Apply Gap 2 remediation: Resample, Scale, or Replace."""
       violation_rate = validation_report['violation_rate']
       
       # Strategy A: Resample (if < 70% valid, filter more strictly)
       if violation_rate > 0.30 and len(df) > 5:
           print(f"  Applying Strategy A: Re-filtering with stricter constraints")
           # (Re-apply filters with tighter bounds; user must adjust unsw_filtering rules)
           return {'type': 'resample', 'result_df': df}  # Placeholder
       
       # Strategy B: Scale (if duration too short, scale all by factor)
       elif any(v[0] == 'duration' for v in validation_report['violations']):
           print(f"  Applying Strategy B: Scaling durations by 1.5x")
           df_scaled = df.copy()
           df_scaled['duration'] = df_scaled['duration'] * 1.5
           return {'type': 'scale_duration', 'result_df': df_scaled}
       
       # Strategy C: Replace (if >30% violations, generate synthetic)
       else:
           print(f"  No remediation applied (violation rate acceptable or non-critical)")
           return {'type': 'none', 'result_df': df}
   ```

3. **Create Validation Report:**

   Document for each scenario:
   - Number of UNSW rows after filtering
   - Feature statistics (min, max, percentiles)
   - Assigned TIER
   - Feature violation rate and remediation applied

   Example output:
   ```yaml
   WannaCry:
     unsw_rows_after_filtering: 312
     tier: 1
     feature_violations: 8/312 (2.6%)
     remediation_applied: none
     duration_stats:
       min: 0.03 seconds
       max: 15.2 seconds
       p5: 0.08 seconds
       p95: 2.1 seconds
       median: 0.6 seconds
     bytes_stats:
       min: 200 bytes
       max: 85000 bytes
       median: 2400 bytes
     dport_unique: [445]
     proto_unique: ['tcp']
     validation_notes: "✅ All rows have dport=445; feature violations <3% (acceptable)"
   ```

3. **Update `zero_day_templates.json`** with Step 1 fields:

   a) **`expected_tier`** = computed TIER

   b) **`feature_constraints`** = UNSW percentile ranges (e.g., [p5, p95] or [min, max] depending on scenario needs):
   ```python
   # Conservative approach: use [p5, p95] to exclude extreme outliers
   feature_constraints = {
     "duration": [stats['duration']['p5'], stats['duration']['p95']],
     "bytes": [stats['bytes']['p5'], stats['bytes']['p95']],
     "packets": [stats['packets']['p5'], stats['packets']['p95']],
     "rate": null,  # Computed later from event frequency
     "dport": stats['dport_unique'].tolist()
   }
   ```

   c) **`temporal_architecture.phases`** (scaffolding, refined in Steps 3-6):
   ```json
   "phases": [
     {"name": "benign_baseline", "start": 0, "end": 300, "event_count": 6},
     {"name": "attack_phase_1", "start": 300, "end": 600, "event_count": 3},
     {"name": "attack_phase_2", "start": 600, "end": 900, "event_count": 3},
     {"name": "attack_phase_3", "start": 900, "end": 1200, "event_count": 2},
     {"name": "benign_recovery", "start": 1200, "end": 1800, "event_count": 9}
   ]
   ```

   d) **`false_alarm_distribution`** (assign based on scenario; see Step 5):
   ```json
   {
     "type_1_unusual_port_benign_service": 2,
     "type_2_high_volume_low_risk": 1,
     "type_3_rare_duration_benign": 2
   }
   ```

---

## **STEP 3: Generate Synthetic Malicious Events**

**Objective:** Create 10-11 realistic malicious events per scenario using tiered synthesis based on Step 2 TIER classification.

**Inputs:**
- Filtered UNSW data (from Step 2)
- Scenario `entry_point`, `target_asset`, `key_attack_behaviors`
- Feature constraints and tier classification

**Outputs:**
- List of 10-11 malicious event dictionaries with fields:
  - `timestamp` (placeholder, to be assigned in Step 6)
  - `src_host`, `dst_host`
  - `src_subnet`, `dst_subnet`
  - `proto`, `sport`, `dport`, `service`
  - `duration`, `bytes`, `packets`
  - `attack_cat`, `label` (='Malicious')
  - `_source` (tracking: UNSW_actual / UNSW_parameterized / UNSW_synthetic_KDE)

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
        - Vary `src_host` within same subnet
        - Vary `dst_host` (different target, same vulnerability class)
        - Perturb `duration` by ±20% (random multiplier 0.8-1.2)
        - Scale `bytes` by ±15% (preserves relative magnitude)
        - Adjust `packets` to maintain byte/packet correlation
      - Set `_source` = 'UNSW_parameterized'

   c) Ensure feature correlations match UNSW baselines (e.g., Corr(bytes, duration))

3. **TIER 3 (2-4 UNSW rows):**

   **Important:** TIER 3 requires minimum 2 UNSW rows for KDE reliability. If fewer available after filtering, review unsw_filtering rules in zero_day_templates.json.

   a) Use filtered UNSW rows (2-4 events) as KDE templates
   b) Fit Gaussian KDE to key features: `duration`, `bytes`, `packets`
   c) Generate synthetic events by:
      - Resample from KDE (clip to [p5, p95] percentiles to avoid outliers)
      - Assign scenario-appropriate `proto`, `dport`, `service`
      - Ensure cross-subnet attack progression (entry_point → target_asset)
   d) Set `_source` = 'UNSW_synthetic_KDE'
   e) **Post-generation validation**: Verify Corr(bytes, packets) ≈ UNSW baseline (must differ by <0.15)

4. **Ordering & Causality:**

   a) Order malicious events to form attack chain (entry_point → target_asset progression)
   b) Ensure cross-subnet transitions follow topology rules (User1 → Enterprise* → Operational if applicable)
   c) Later events should show increased privilege/data access (higher bytes for exfiltration)

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
- False alarm taxonomy from `global_constraints.json`
- Scenario `false_alarm_distribution` (from Step 1)

**Outputs:**
- List of 4-5 false alarm event dictionaries

### Step 5 Action Items

1. **Generate by Type (per scenario distribution from Step 1):**

   **Type 1: Unusual Port + Benign Service**
   ```python
   def generate_type1(count=2):
       events = []
       for i in range(count):
           event = {
               'src_host': random.choice(['Enterprise0', 'Enterprise2', 'Defender']),
               'dst_host': f'8.8.8.{8+i}',  # External DNS variation
               'proto': 'tcp',
               'dport': random.randint(10000, 65535),  # High port
               'service': 'dns',
               'duration': random.uniform(0.2, 3.0),
               'bytes': random.randint(100, 1000),
               'packets': random.randint(5, 50),
               'attack_cat': 'Normal',
               'label': 'False Alarm',
               '_fa_type': 'unusual_port_benign_service'
           }
           events.append(event)
       return events
   ```

   **Type 2: High Volume + Low-Risk Service**
   ```python
   def generate_type2(count=1):
       events = []
       for i in range(count):
           event = {
               'src_host': random.choice(['User0', 'User1', 'Enterprise1']),
               'dst_host': '1.1.1.1',  # External DNS
               'proto': 'tcp',
               'dport': 53,
               'service': 'dns',
               'duration': random.uniform(60, 300),  # Long session
               'bytes': random.randint(10000000, 100000000),  # 10-100 MB
               'packets': random.randint(2000, 10000),
               'attack_cat': 'Normal',
               'label': 'False Alarm',
               '_fa_type': 'high_volume_low_risk'
           }
           events.append(event)
       return events
   ```

   **Type 3: Rare Duration + Benign Context**
   ```python
   def generate_type3(count=1):
       events = []
       for i in range(count):
           event = {
               'src_host': random.choice(['User1', 'User2', 'User3']),
               'dst_host': random.choice(['Enterprise0', 'Enterprise1']),
               'proto': 'tcp',
               'dport': 22,
               'service': 'ssh',
               'duration': random.uniform(0.01, 0.05),  # Very short
               'bytes': random.randint(50, 500),
               'packets': random.randint(2, 10),
               'attack_cat': 'Normal',
               'label': 'False Alarm',
               '_fa_type': 'rare_duration_benign'
           }
           events.append(event)
       return events
   ```

2. **Distribution Logic:**

   a) Refer to `zero_day_templates.json['false_alarm_distribution']` for type counts per scenario
   b) Generate type counts and merge into single false alarm list
   c) Ensure total = 4-5

3. **False Alarm Coherence Validation (Gap 5 Implementation):**

   ```python
   def validate_false_alarms(fa_events, scenario_name):
       """Verify false alarms are realistic and properly distributed."""
       type_counts = {}
       for event in fa_events:
           fa_type = event.get('_fa_type', 'unknown')
           type_counts[fa_type] = type_counts.get(fa_type, 0) + 1
       
       print(f"\n{scenario_name} False Alarms ({len(fa_events)} total):")
       for fa_type, count in type_counts.items():
           print(f"  {fa_type}: {count}")
       
       # Sanity: All false alarms labeled as 'Normal' attack_cat
       normal_count = sum(1 for e in fa_events if e.get('attack_cat') == 'Normal')
       assert normal_count == len(fa_events), \
           f"FALSE ALARM ERROR: {len(fa_events) - normal_count} events not labeled 'Normal' attack_cat"
       
       # Sanity: No false alarms on sensitive ports unless appropriate
       for event in fa_events:
           if event.get('dport') == 445 and event.get('_fa_type') != 'unusual_port_benign_service':
               print(f"  ⚠️ WARNING: Port 445 used in false alarm (should typically be on unusual port)")
       
       print(f"  ✅ False alarm validation passed")
       return True
   ```

---

## **STEP 6: Assemble 30-Event Tables with Temporal Ordering**

**Objective:** Combine malicious (10-11), benign (15), and false alarm (4-5) events; assign timestamps following phase architecture; verify sanity checks.

**Inputs:**
- Malicious events from Step 3
- Benign events from Step 4
- False alarm events from Step 5
- Temporal architecture from Step 1

**Outputs:**
- CSV table (30 rows, 14 columns) with strict temporal ordering

### Step 6 Action Items

1. **Assign Timestamps Using Phase Architecture:**

   ```python
   # From global_constraints.json + zero_day_templates.json
   phases = scenario_config['temporal_architecture']['phases']
   false_alarm_zones = scenario_config['temporal_architecture']['false_alarm_zones']
   
   timestamped_events = []
   
   # Assign timestamps to each phase
   for phase in phases:
       phase_name = phase['name']
       phase_start = phase['start']
       phase_end = phase['end']
       phase_event_count = phase['events']
       
       event_pool = get_events_for_phase(phase_name, malicious_events, 
                                         benign_events, false_alarm_events)
       
       for i in range(phase_event_count):
           if not event_pool:
               continue
           event = event_pool.pop(0)
           
           # Timestamp assignment
           if 'attack' in phase_name.lower():
               # Sequential: events spaced evenly (25-50s apart)
               interval = (phase_end - phase_start) / phase_event_count
               t = phase_start + (i * interval) + random.uniform(0, interval * 0.1)
           else:
               # Benign: scattered randomly
               t = phase_start + random.uniform(0, phase_end - phase_start)
           
           event['timestamp'] = t
           timestamped_events.append(event)
   
   # Add false alarms in designated zones
   for zone_start, zone_end in false_alarm_zones:
       for fa_event in false_alarm_events:
           fa_event['timestamp'] = random.uniform(zone_start, zone_end)
           timestamped_events.append(fa_event)
   
   # Sort by timestamp
   timestamped_events.sort(key=lambda e: e['timestamp'])
   ```

2. **Validate Temporal Coherence and Generate Timeline Visualization (Gap 4 Implementation):**

   ```python
   def validate_temporal_coherence(timestamped_events, scenario_name):
       """Validate temporal coherence with threshold justification (Gap 4)."""
       # Check 1: Strictly increasing timestamps
       timestamps = [e['timestamp'] for e in timestamped_events]
       assert all(timestamps[i] <= timestamps[i+1] for i in range(len(timestamps)-1)), \
           "Timestamps must be strictly increasing"
       
       # Separate by label
       mal_events = [e for e in timestamped_events if e['label']=='Malicious']
       ben_events = [e for e in timestamped_events if e['label']=='Benign']
       fa_events = [e for e in timestamped_events if e['label']=='False Alarm']
       
       # Check 2: Attack window is contiguous
       # JUSTIFICATION: Realistic attacks unfold over minutes (300-900s), not randomly scattered.
       # Threshold 1000s allows for slower-paced reconnaissance + exploitation.
       if mal_events:
           mal_timestamps = [e['timestamp'] for e in mal_events]
           attack_window = max(mal_timestamps) - min(mal_timestamps)
           assert attack_window <= 1000, \
               f"Attack spread over {attack_window}s (expected ≤1000s for coherent chain)"
           print(f"  Attack window: {attack_window:.1f}s (acceptable)")
       
       # Check 3: No isolated malicious events
       # JUSTIFICATION: Real attacks form clusters; isolated events break causal chain perception.
       # Threshold 120s (2 minutes) ensures neighboring events feel related.
       for i, event in enumerate(mal_events):
           if len(timestamped_events) > 1:
               all_others = [e for e in timestamped_events if e != event]
               nearest = min([abs(e['timestamp'] - event['timestamp']) for e in all_others])
               assert nearest < 120, \
                   f"Malicious event isolated ({nearest:.1f}s from neighbor; threshold 120s)"
       
       # Check 4: False alarms NOT adjacent to malicious chain
       # JUSTIFICATION: False alarms should be temporally separated from true attack to avoid
       # creating confusion about causal relationships. Threshold 30s avoids false causal inference.
       for fa_event in fa_events:
           adjacencies = [abs(fa_event['timestamp'] - m['timestamp']) for m in mal_events]
           if adjacencies:
               nearest = min(adjacencies)
               assert nearest >= 30, \
                   f"False alarm within 30s of malicious event ({nearest:.1f}s; must be isolated)"
       
       print(f"  ✅ Temporal coherence validated for {scenario_name}")
       return True
   
   def generate_timeline_visualization(timestamped_events, scenario_name):
       """Generate timeline diagram showing event distribution (Gap 4 visualization)."""
       import matplotlib.pyplot as plt
       import matplotlib.patches as patches
       
       fig, ax = plt.subplots(figsize=(14, 6))
       
       # Color mapping
       colors = {'Malicious': 'red', 'Benign': 'blue', 'False Alarm': 'orange'}
       
       # Plot events as timeline
       for event in timestamped_events:
           t = event['timestamp']
           label = event['label']
           color = colors.get(label, 'gray')
           ax.scatter(t, 1, s=100, c=color, alpha=0.7, edgecolors='black', linewidth=0.5)
       
       # Annotations for malicious events
       mal_events = [e for e in timestamped_events if e['label']=='Malicious']
       if mal_events:
           mal_timestamps = [e['timestamp'] for e in mal_events]
           ax.axvspan(min(mal_timestamps) - 50, max(mal_timestamps) + 50, 
                     alpha=0.1, color='red', label='Attack Window')
       
       ax.set_xlim(-50, 1850)
       ax.set_ylim(0.5, 1.5)
       ax.set_xlabel('Time (seconds)', fontsize=12)
       ax.set_title(f'{scenario_name}: 30-Event Timeline', fontsize=14)
       ax.set_yticks([])
       
       # Legend
       from matplotlib.patches import Patch
       legend_elements = [Patch(facecolor='red', alpha=0.7, label='Malicious'),
                         Patch(facecolor='blue', alpha=0.7, label='Benign'),
                         Patch(facecolor='orange', alpha=0.7, label='False Alarm')]
       ax.legend(handles=legend_elements, loc='upper right')
       
       plt.tight_layout()
       plt.savefig(f'timeline_{scenario_name}.png', dpi=150)
       print(f"  Timeline saved: timeline_{scenario_name}.png")
       plt.close()
   
   # Run both validations
   validate_temporal_coherence(timestamped_events, scenario_name)
   generate_timeline_visualization(timestamped_events, scenario_name)
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

## **Pipeline Execution Order**

1. ✅ **Pre-Step**: Transform UNSW → `UNSW_NB15_transformed.csv` (Gap 6)
2. ✅ **Step 0**: Define global constraints → `global_constraints.json`
3. ✅ **Step 1**: Structure scenario templates → Updated `zero_day_templates.json`
4. ✅ **Step 2**: Extract & validate UNSW filtered data (uses transformed CSV)
5. ✅ **Step 3**: Generate malicious events (TIER-based synthesis)
6. ✅ **Step 4**: Generate benign events
7. ✅ **Step 5**: Generate false alarm events
8. ✅ **Step 6**: Assemble & temporalize → Final 30-event CSV tables

---

## **Implementation Notes**

- **Pre-Step critical**: All downstream steps depend on transformed dataset
- **Scenario tracking**: `scenario_name` column added in Pre-Step for proper filtering in Step 2
- **Deterministic IP mapping**: Same IP always maps to same hostname within scenario
- **Data traceability**: `_unsw_row_id` field added for provenance tracking
- **Schema alignment**: Pre-Step ensures no column mismatches or extrapolation needed
- Each step produces artifacts for next step (pass-through validation)

---

## **Design Decisions: Gap Coverage**

### **Gap 1: Causal Chain Construction**
**Status**: ✅ **ADDRESSED**
- UNSW rows treated as independent feature templates (acknowledged in preamble)
- Synthetic temporal sequencing applied in Steps 3 & 6 to create causal chains
- Step 3 orders malicious events by attack progression; Step 6 assigns timestamps via phase architecture

### **Gap 2: Feature Realism Validation**
**Status**: ✅ **ADDRESSED**
- Feature validation function `validate_filtered_features()` added to Step 2
- Remediation strategies (Resample, Scale) documented and callable
- Triggers on >30% violation rate; logs remediation applied to validation report

### **Gap 3: Event Count & Label Distribution**
**Status**: ✅ **ADDRESSED**
- TIER classification (1/2/3) determines synthesis strategy in Step 3
- TIER 3 KDE requires minimum 2 UNSW rows (clarified in Step 3)
- 30-event target with label ratios (35% malicious, 50% benign, 15% false alarm) enforced in Step 6

### **Gap 4: Temporal Coherence**
**Status**: ✅ **ADDRESSED**
- Staged temporal architecture defined in Steps 1 & 2
- Validation checks with **threshold justifications** added to Step 6:
  - Attack window ≤ 1000s (coherent attack progression)
  - Malicious events < 120s apart (no isolation)
  - False alarms ≥ 30s from malicious chain (temporal separation)
- Timeline visualization function `generate_timeline_visualization()` added for post-generation review

### **Gap 5: False Alarm Generation**
**Status**: ✅ **ADDRESSED**
- 3-type taxonomy fully specified in Step 5 (Type 1/2/3 generation functions)
- Type distribution per scenario via `zero_day_templates.json['false_alarm_distribution']`
- Validation function `validate_false_alarms()` added to Step 5 for coherence checks

### **Gap 6: Schema Mapping**
**Status**: ✅ **ADDRESSED**
- Pre-Step provides deterministic IP→host mapping via `map_ip_to_host(scenario_name, ip)`
- Transformed CSV includes `scenario_name` column for scenario-specific filtering
- `service` inferred from `dport` via `infer_service_from_port()`
- All UNSW columns mapped to output schema with no data loss

### **Gap 7: Network Grounding**
**Status**: ✅ **ADDRESSED**
- **Design Decision**: Benign events are deliberately **scenario-independent** (Step 4)
- **Rationale**: IDS has no prior knowledge of attack type; baseline traffic is uniformly generated
- Explicitly documented in Step 4 Generation Strategy comment

### **Gap 8: Rarity Operationalization**
**Status**: ✅ **ADDRESSED**
- **Design Decision**: Rarity simplified to **heuristics** (not full transition probability matrix)
- **Rationale**: UNSW labels (`attack_cat`) implicitly encode rarity; no separate computation needed in generation phase
- **Post-generation**: Downstream NoDOZE validation can compute transition probabilities if needed
- Documented here for clarity; not a runtime computation

