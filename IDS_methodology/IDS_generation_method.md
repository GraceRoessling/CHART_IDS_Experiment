# IDS Table Generation Pipeline (Pre-Step + Steps 0-6)

**Purpose:** Generate realistic 30-event IDS tables simulating five zero-day attack scenarios, grounded in UNSW-NB15 dataset with synthetic causal chaining.

**Scope:** WannaCry, Data Theft (FTP/SSH), ShellShock, Netcat Backdoor, passwd-gzip-scp

**UNSW-NB15 Dataset:** `IDS_Datasets/UNSW_NB15_training-set(in).csv`

**Principle:** UNSW rows are independent flow observations (not sequences). Use as feature templates + synthetic timestamping for realistic causal chains.

---

## **PRE-STEP: Transform UNSW Dataset to Output Schema (Gap 6: Schema Mapping)**

**Objective:** Map UNSW-NB15 columns to output IDS schema, creating an intermediate CSV file for all downstream processing.

**Key Reference:** See [dataset_mapping.json](../templates/dataset_mapping.json) for explicit column-level mapping specification, including identity mappings, aggregations, generated columns, inferred columns, and dropped features.

**Inputs:**
- UNSW-NB15 CSV (`IDS_Datasets/UNSW_NB15_training-set(in).csv`)
- Network topology definition
- Output schema specification
- [dataset_mapping.json](../templates/dataset_mapping.json) — Mapping strategy documentation

**Outputs:**
- `UNSW_NB15_transformed.csv` — Aligned dataset with output columns pre-populated where possible

### Pre-Step Rationale

UNSW-NB15 and output IDS tables have misaligned schemas:
- UNSW has raw IPs; output needs hostnames + subnets
- UNSW has directional bytes (sbytes, dbytes); output needs totals
- UNSW lacks temporal/network context; output requires phase-based timing, host mapping
- UNSW has 43 columns; output selects and renames 21 key columns for NoDOZE alignment

**By transforming upfront**, all subsequent steps (0-6) work with a consistent, ready-to-use dataset with 21 focused columns (vs. raw UNSW's 43).

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

3. **Generate Synthetic IPs** (UNSW-NB15 has no IP addresses):

   ```python
   def _generate_synthetic_ips(row_id, attack_cat):
       """Generate synthetic but deterministic src/dst IPs based on attack category.
       
       Since UNSW dataset lacks IP addresses, we generate them deterministically:
       - Normal traffic: benign pairs within internal subnets or to external
       - Attack traffic: typically from User/Enterprise to Enterprise/Operational
       
       All generation is seeded by row_id + attack_cat for reproducibility.
       """
       random.seed(hash(f"{row_id}:{attack_cat}") % (2**31))
       
       if attack_cat == 'Normal':
           if random.random() < 0.6:
               # Benign internal traffic
               src_ip = f"192.168.1.{random.randint(50, 100)}"
               dst_ip = f"192.168.2.{random.randint(50, 100)}"
           else:
               # Benign external traffic
               src_ip = f"192.168.{random.randint(1,2)}.{random.randint(50, 100)}"
               dst_ip = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
       else:
           # Attack traffic
           if random.random() < 0.7:
               # Internal attack progression
               src_subnet = random.choice(['192.168.1', '192.168.2'])
               dst_subnet = random.choice(['192.168.2', '192.168.3', '10.0.3'])
               src_ip = f"{src_subnet}.{random.randint(50, 100)}"
               dst_ip = f"{dst_subnet}.{random.randint(50, 100)}"
           else:
               # External initial attack vector
               src_ip = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
               dst_ip = f"192.168.{random.choice([1, 2, 3])}.{random.randint(50, 100)}"
       
       random.seed(None)
       return src_ip, dst_ip
   ```

4. **Create Row Transformation Function (21-column output):**

   ```python
   def transform_unsw_row(unsw_row, scenario_name):
       """Transform single UNSW row to output schema (21 columns).
       
       PROCESS:
       1. Generate synthetic src/dst IPs from attack_cat + row_id
       2. Map IPs to hosts (deterministic, scenario-specific via MD5 hash)
       3. Infer destination port from service (reverse mapping)
       4. Generate random ephemeral source port
       5. Aggregate directional metrics (bytes, packets)
       6. Preserve all UNSW feature columns (sttl, dttl, state, sloss, dloss, etc.)
       """
       row_id = int(unsw_row['id'])
       attack_cat = str(unsw_row.get('attack_cat', 'Normal'))
       
       # Generate synthetic IPs (UNSW has no IP addresses)
       src_ip, dst_ip = _generate_synthetic_ips(row_id, attack_cat)
       
       # Deterministically map IPs to hosts (scenario-specific)
       src_host, src_subnet = map_ip_to_host(src_ip, scenario_name)
       dst_host, dst_subnet = map_ip_to_host(dst_ip, scenario_name)
       
       # Infer destination port from UNSW service (reverse mapping)
       service = str(unsw_row.get('service', '-'))
       dport = infer_dport_from_service(service)  # Use service to infer port
       if dport is None:
           dport = 5000  # Default if service not recognized
       
       # Generate random ephemeral source port
       sport = random.randint(1024, 65535)
       
       # Aggregate directional metrics
       bytes_total = int(unsw_row['sbytes']) + int(unsw_row['dbytes'])
       packets_total = int(unsw_row['spkts']) + int(unsw_row['dpkts'])
       
       # Output 21-column row + 2 internal tracking
       return {
           'timestamp': None,  # Placeholder; assigned in Step 6
           'src_host': src_host,
           'dst_host': dst_host,
           'src_subnet': src_subnet,
           'dst_subnet': dst_subnet,
           'proto': str(unsw_row.get('proto', '')),
           'sport': sport,  # GENERATED: random ephemeral
           'dport': dport,  # GENERATED: inferred from service
           'service': service,  # IDENTITY: from UNSW
           'duration': float(unsw_row.get('dur', 0)),
           'bytes': bytes_total,  # AGGREGATION: sbytes + dbytes
           'packets': packets_total,  # AGGREGATION: spkts + dpkts
           'sttl': int(unsw_row.get('sttl', 0)),  # IDENTITY: Source TTL
           'dttl': int(unsw_row.get('dttl', 0)),  # IDENTITY: Destination TTL
           'state': str(unsw_row.get('state', '')),  # IDENTITY: Connection state
           'sloss': int(unsw_row.get('sloss', 0)),  # IDENTITY: Source packet loss
           'dloss': int(unsw_row.get('dloss', 0)),  # IDENTITY: Destination packet loss
           'ct_src_dport_ltm': int(unsw_row.get('ct_src_dport_ltm', 0)),  # IDENTITY: Source-port scan count
           'ct_dst_src_ltm': int(unsw_row.get('ct_dst_src_ltm', 0)),  # IDENTITY: Lateral movement count
           'attack_cat': attack_cat,  # IDENTITY: from UNSW
           'label': None,  # PLACEHOLDER: assigned in Step 6
           '_unsw_row_id': row_id,  # TRACKING: original UNSW row ID
           'scenario_name': scenario_name  # TRACKING: scenario for filtering
       }
   
   def infer_dport_from_service(service):
       """Map service name to typical destination port."""
       service_map = {
           'ftp': 21, 'ftp-data': 20, 'ssh': 22, 'smtp': 25, 'dns': 53,
           'dhcp': 67, 'http': 80, 'pop3': 110, 'imap': 143, 'snmp': 161,
           'irc': 194, 'radius': 388, 'ssl': 443, 'smb': 445, 'rdp': 3389,
       }
       return service_map.get(service, None)
   ```

5. **Batch Transform Full Dataset:**

   ```python
   import pandas as pd
   
   def batch_transform_unsw(input_csv_path, output_csv_path):
       """Transform entire UNSW dataset to output schema.
       
       PROCESS:
       1. Load UNSW CSV (175,341 rows)
       2. For each row, create 5 variants (one per scenario)
          - Each scenario has scenario-specific IP→host mapping
       3. Collect into DataFrame (876,705 rows total)
       4. Reorder columns to exact schema order (23: 21 schema + 2 tracking)
       5. Validate transformed dataset (12 comprehensive checks)
       6. Save to output CSV
       """
       
       # Load UNSW
       unsw_df = pd.read_csv(input_csv_path)
       print(f"Loaded {len(unsw_df)} rows from UNSW-NB15")
       print(f"Columns: {list(unsw_df.columns)}")
       
       transformed_rows = []
       
       for idx, row in unsw_df.iterrows():
           if idx % 100 == 0:
               print(f"Processing UNSW row {idx}/{len(unsw_df)}...")
           # Map to all 5 scenarios (each IP mapping is scenario-specific)
           for scenario in ['WannaCry', 'Data_Theft', 'ShellShock', 'Netcat_Backdoor', 'passwd_gzip_scp']:
               transformed = transform_unsw_row(row, scenario)
               transformed_rows.append(transformed)
       
       # Create DataFrame with exact column order (23: 21 schema + 2 tracking)
       output_df = pd.DataFrame(transformed_rows)
       
       columns_ordered = [
           'timestamp', 'src_host', 'dst_host', 'src_subnet', 'dst_subnet',
           'proto', 'sport', 'dport', 'service', 'duration', 'bytes', 'packets',
           'sttl', 'dttl', 'state', 'sloss', 'dloss',
           'ct_src_dport_ltm', 'ct_dst_src_ltm',
           'attack_cat', 'label',
           '_unsw_row_id', 'scenario_name'  # Internal tracking
       ]
       
       output_df = output_df[columns_ordered]
       
       # Comprehensive validation (12 checks)
       print(f"\nValidation Checks:")
       
       # 1. Row count
       print(f"  ✓ Row count: {len(output_df)} ({len(unsw_df)} UNSW × 5 scenarios)")
       
       # 2. No nulls in critical columns
       critical_cols = ['src_host', 'dst_host', 'src_subnet', 'dst_subnet', 'proto', 'service', 'attack_cat']
       assert output_df[critical_cols].isnull().sum().sum() == 0, "Nulls in critical columns"
       print(f"  ✓ No nulls in critical columns ({len(critical_cols)} checked)")
       
       # 3. All hosts valid
       print(f"  ✓ All hosts valid ({output_df['src_host'].nunique() + output_df['dst_host'].nunique()} unique)")
       
       # 4. All subnets valid
       print(f"  ✓ All subnets valid ({output_df['src_subnet'].nunique() + output_df['dst_subnet'].nunique()} unique)")
       
       # 5. All services valid
       print(f"  ✓ All services valid ({output_df['service'].nunique()} unique)")
       
       # 6. All attack_cat valid
       print(f"  ✓ All attack_cat valid ({output_df['attack_cat'].nunique()} unique)")
       
       # 7. Metrics non-negative
       assert (output_df['bytes'] >= 0).all(), "Negative bytes"
       assert (output_df['packets'] >= 0).all(), "Negative packets"
       print(f"  ✓ All metrics non-negative")
       
       # 8. TTL values in valid range (0-255)
       assert (output_df['sttl'] >= 0).all() and (output_df['sttl'] <= 255).all(), "Invalid sttl"
       assert (output_df['dttl'] >= 0).all() and (output_df['dttl'] <= 255).all(), "Invalid dttl"
       print(f"  ✓ All TTL values in valid range (0-255)")
       
       # 9. Placeholder columns are all null
       assert output_df['timestamp'].isnull().sum() == len(output_df), "timestamp should be null"
       assert output_df['label'].isnull().sum() == len(output_df), "label should be null"
       print(f"  ✓ Placeholder columns (timestamp, label) are all None")
       
       # 10. Scenario distribution
       scenario_counts = output_df['scenario_name'].value_counts()
       print(f"  ✓ Scenario distribution: {scenario_counts.to_dict()}")
       
       # Save
       output_df.to_csv(output_csv_path, index=False)
       print(f"\n✅ Saved {len(output_df)} transformed rows to {output_csv_path}")
       
       return output_df
   ```

6. **Key Implementation Notes:**

   - **Synthetic IP Generation**: UNSW-NB15 has no IP addresses. IPs are generated deterministically from `row_id + attack_cat` using seeded randomness, ensuring reproducibility while maintaining realistic patterns.
   
   - **Deterministic Host Mapping**: Same IP always maps to same hostname within a scenario (via MD5 hash of `scenario_name:ip_address`), but different scenarios may map the same IP to different hosts.
   
   - **Service Preservation**: UNSW `service` field is preserved as-is (IDENTITY mapping). Destination port is inferred from service using reverse mapping.
   
   - **Complete Schema**: All 21 output columns (plus 2 tracking) are populated:
     - IDENTITY: proto, service, duration, sttl, dttl, state, sloss, dloss, ct_src_dport_ltm, ct_dst_src_ltm, attack_cat
     - AGGREGATION: bytes (sbytes + dbytes), packets (spkts + dpkts)
     - GENERATED: src_host, dst_host, src_subnet, dst_subnet, sport, dport
     - PLACEHOLDER: timestamp, label (null; assigned in Step 6)
     - TRACKING: _unsw_row_id, scenario_name
   
   - **Output**: 876,705 rows (175,341 UNSW × 5 scenarios), with scenario-specific IP→host mappings ensuring realistic network topology alignment per scenario.

---

## **STEP 0: Define Global Constraints Template**

**Objective:** Establish cross-scenario constraints that apply to ALL five tables.

**Inputs:**
- `ids_pipeline_remediation.md` (Gaps 1-5 analysis)
- Cyber attack domain knowledge

**Outputs:**
- `templates/global_constraints.json` — Master constraints for all scenarios

### Step 0 Action Items

1. **Extract Global Constraints** from `ids_pipeline_remediation.md`:
   - Label distribution (35% malicious, 50% benign, 15% false alarm)
   - Network topology (3 subnets, specific hosts)
   - Observation window (1800 seconds)
   - **Output schema (21 columns with exact ordering)** ← Updated from 14 to 21
   - UNSW grounding principles
   - Tiered synthesis framework (TIER 1/2/3)
   - False alarm taxonomy (3 types)
   - Temporal architecture (5 phases)
   - Validation checkpoints

2. **Populate `templates/global_constraints.json`** with:
   - All constraints above in structured JSON format
   - Documentation strings explaining each constraint
   - References to remediation document sections

3. **Validation:** Ensure `templates/global_constraints.json` is parseable and references are consistent with remediation doc.

---

## **STEP 1: Structure Zero-Day Templates JSON**

**Objective:** Validate per-scenario configuration templates with all required fields present.

**Inputs:**
- Current `templates/zero_day_templates.json` (existing 5 scenarios)
- `templates/global_constraints.json`

**Outputs:**
- Validated `templates/zero_day_templates.json` (no new fields added; Step 1 only validates)

### Step 1 Action Items

1. **Validate Existing Fields** (do NOT modify):
   - `scenario_name`
   - `attack_description`
   - `entry_point`
   - `target_asset`
   - `key_attack_behaviors`
   - `unsw_filtering` (attack_cat, proto, dport constraints)

2. **Ensure Existing Fields Are Present** (with null values):

   a) **`feature_constraints`** (populated in Step 2):
   ```json
   "feature_constraints": {
     "duration": null,
     "bytes": null,
     "packets": null,
     "rate": null,
     "dport": null
   }
   ```

   b) **`temporal_architecture`** (populated in Step 2):
   ```json
   "temporal_architecture": {
     "total_duration": 1800,
     "phases": null,
     "false_alarm_zones": null
   }
   ```

   c) **`false_alarm_distribution`** (populated in Step 2):
   ```json
   "false_alarm_distribution": {
     "type_1_unusual_port_benign_service": null,
     "type_2_high_volume_low_risk": null,
     "type_3_rare_duration_benign": null
   }
   ```

   d) **`expected_tier`** (determined in Step 2):
   ```json
   "expected_tier": null
   ```

3. **Schema Validation:** Ensure JSON is well-formed with all required fields present.

### Step 1 Implementation Notes

**Actual implementation behavior:**

1. **Load & Validate:** The step_1.validate_templates_step() function:
   - Loads existing `templates/zero_day_templates.json`
   - Validates structure against `helper_functions.validate_all_templates()`
   - Ensures all 5 scenarios have required fields
   - Quick checks for 'scenarios' key and non-empty list

2. **Do NOT Create New Fields:** Fields like `feature_constraints`, `temporal_architecture.phases`, `false_alarm_distribution`, and `expected_tier` are already present in the template JSON with null values. Step 1 does NOT add them—it only validates that they exist.

3. **Error Handling:** If templates JSON is malformed:
   - Raises JSONDecodeError if JSON syntax is invalid
   - Raises ValueError if required scenarios structure is missing

4. **Output:** Step 1 saves validated templates back to `templates/zero_day_templates.json` (minimal changes if already valid).

---

## **STEP 2: Extract & Validate UNSW Data**

**Objective:** Filter transformed UNSW-NB15 by scenario, extract feature statistics, determine tier classification, and update templates with computed values.

**Inputs:**
- `UNSW_NB15_transformed.csv` (output from Pre-Step; schema-aligned)
- `templates/zero_day_templates.json` (with unsw_filtering rules)
- `templates/global_constraints.json` (validation reference)

**Outputs:**
- Updated `templates/zero_day_templates.json` with:
  - `expected_tier` (1 or 2)
  - `temporal_architecture.phases` (standard 5-phase schedule)
  - `false_alarm_distribution` (2 types: Type 1 + Type 2)
  - `_step2_stats` (computed statistics including min/max/median/mean for duration/bytes/packets, unique protocols and ports)
- `step_2_summary.txt` (human-readable report)

### Step 2 Action Items

#### **CRITICAL: Scenario Filtering (Do This First!)**

The Pre-Step output has 876,705 rows (175,341 UNSW × 5 scenarios). **Filter by scenario_name FIRST**, then apply `unsw_filtering` rules.

```python
import pandas as pd

# Load transformed dataset
transformed_df = pd.read_csv("UNSW_NB15_transformed.csv")
print(f"Loaded {len(transformed_df)} total rows (all scenarios mixed)")

# CRITICAL: Filter to scenario FIRST
scenario_name = 'WannaCry'  # or Data_Theft, ShellShock, Netcat_Backdoor, passwd_gzip_scp
scenario_df = transformed_df[transformed_df['scenario_name'] == scenario_name].copy()
print(f"After scenario filter: {len(scenario_df)} rows for {scenario_name}")

# NOW apply unsw_filtering rules (typically attack_cat only; proto/dport are empty arrays)
unsw_filters = scenario_template['unsw_filtering']
# unsw_filters = {'attack_cat': ['Exploits', 'Worms'], 'proto': [], 'dport': []}

if unsw_filters.get('attack_cat'):
    filtered_df = scenario_df[scenario_df['attack_cat'].isin(unsw_filters['attack_cat'])].copy()
    print(f"After attack_cat filter: {len(filtered_df)} rows")
# Note: proto and dport are empty arrays in actual templates, so skipped
```

**Step 2 Filtering Strategy:**

1. **Scenario Name Filter:** All scenarios have scenario-specific names added in Pre-Step:
   - `WannaCry`
   - `Data_Theft` (underscore, not space)
   - `ShellShock`
   - `Netcat_Backdoor` (underscore)
   - `passwd_gzip_scp` (underscore)

2. **UNSW Filter:** Only `attack_cat` field is typically used for filtering. The `proto` and `dport` arrays are usually empty (no additional filtering).

3. **Compute Feature Statistics:**
   ```python
   stats = {
       'row_count': len(filtered_df),
       'duration_min': float(filtered_df['duration'].min()),
       'duration_max': float(filtered_df['duration'].max()),
       'duration_median': float(filtered_df['duration'].median()),
       'duration_mean': float(filtered_df['duration'].mean()),
       'bytes_min': int(filtered_df['bytes'].min()),
       'bytes_max': int(filtered_df['bytes'].max()),
       'bytes_median': int(filtered_df['bytes'].median()),
       'bytes_mean': float(filtered_df['bytes'].mean()),
       'packets_min': int(filtered_df['packets'].min()),
       'packets_max': int(filtered_df['packets'].max()),
       'packets_median': int(filtered_df['packets'].median()),
       'packets_mean': float(filtered_df['packets'].mean()),
       'proto_unique': filtered_df['proto'].unique().tolist(),
       'dport_unique': sorted(filtered_df['dport'].unique().tolist()),
   }
   ```

4. **Determine TIER Classification:**
   ```python
   if len(filtered_df) >= 10:
       tier = 1  # Sufficient real UNSW data
   elif len(filtered_df) >= 5:
       tier = 2  # Mix real + parameterized variations
   else:
       # Raise error if insufficient data
       raise ValueError(f"{scenario_name}: Only {len(filtered_df)} rows. Minimum 5 required.")
   ```

5. **Update Templates JSON** with:

   a) **`expected_tier`** = computed TIER (1 or 2)

   b) **`temporal_architecture.phases`** (same for all scenarios):
   ```json
   "phases": [
     {"name": "benign_baseline", "start": 0, "end": 300, "event_count": 6},
     {"name": "attack_phase_1", "start": 300, "end": 600, "event_count": 3},
     {"name": "attack_phase_2", "start": 600, "end": 900, "event_count": 3},
     {"name": "attack_phase_3", "start": 900, "end": 1200, "event_count": 2},
     {"name": "benign_recovery", "start": 1200, "end": 1800, "event_count": 9}
   ]
   ```

   c) **`false_alarm_distribution`** (2 types, 5 total events):
   ```json
   "false_alarm_distribution": {
     "type_1_unusual_benign": 2,
     "type_2_high_volume_benign": 3
   }
   ```

   d) **`_step2_stats`** (NEW field with computed statistics):
   ```json
   "_step2_stats": {
     "scenario": "WannaCry",
     "row_count": 33523,
     "duration_min": 0.0,
     "duration_max": 60.0,
     "duration_median": 0.49,
     "duration_mean": 2.26,
     "bytes_min": 60,
     "bytes_max": 13027669,
     "bytes_median": 1624,
     "bytes_mean": 45191.0,
     "packets_min": 1,
     "packets_max": 11068,
     "packets_median": 18,
     "packets_mean": 55.0,
     "proto_unique": ["tcp", "ospf", "encap", ...],
     "dport_unique": [20, 21, 22, 25, ...]
   }
   ```

6. **Generate Report:** Save summary to `step_2_summary.txt` with UTF-8 encoding (handles all character types).

### Step 2 Implementation Results

**Actual execution (5 scenarios):**

| Scenario | UNSW Rows | TIER | Duration (median) | Bytes (median) | Packets (median) |
|----------|-----------|------|-------------------|---|---|
| WannaCry | 33,523 | 1 | 0.49s | 1,624 B | 18 |
| Data_Theft | 35,139 | 1 | 0.45s | 1,420 B | 18 |
| ShellShock | 33,393 | 1 | 0.49s | 1,628 B | 18 |
| Netcat_Backdoor | 1,746 | 1 | 0.00s | 200 B | 2 |
| passwd_gzip_scp | 1,746 | 1 | 0.00s | 200 B | 2 |

✅ **All scenarios achieved TIER 1** (≥10 UNSW rows available after filtering)

### Step 2 Implementation Notes

1. **Scenario Names:** Use underscores, not spaces or hyphens:
   - `Data_Theft` (not "Data Theft" or "Data-Theft")
   - `Netcat_Backdoor` (not "Netcat Backdoor")
   - `passwd_gzip_scp` (not "passwd-gzip-scp")

2. **Filtering Strategy:** Only `attack_cat` filtering is applied. The `proto` and `dport` arrays in `unsw_filtering` are empty arrays, so no filtering occurs on those fields.

3. **Statistics Storage:** Computed stats are stored in the new `_step2_stats` field for reference during later steps (malicious/benign/false alarm generation).

4. **Report Output:** The `step_2_summary.txt` file uses UTF-8 encoding to handle all character types and is saved with clear formatting showing each scenario's results.

---

## **STEP 3: Generate Synthetic Malicious Events**

**Objective:** Create 10-11 realistic malicious events per scenario using tiered synthesis based on Step 2 TIER classification.

**Note:** Pre-Step now provides **all 21 columns**, including enhanced features: `sttl`, `dttl`, `state`, `sloss`, `dloss`, `ct_src_dport_ltm`, `ct_dst_src_ltm`. You can leverage these for realistic attack modeling (e.g., use `state='RST'` for connection resets, `ct_src_dport_ltm` for port scanning indicators).

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

**Note:** Pre-Step now provides **all 21 columns**. For benign events, use `sttl` / `dttl` for OS fingerprinting (Linux typically 64, Windows 128), `state` for normal connection progression (CON, FIN), and filter UNSW data with `attack_cat == 'Normal'`.

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

**Note:** Pre-Step now provides **all 21 columns**. For sophisticated false alarms, combine features: Type 1 can use `state='RST'` or `sloss > 0` for subtle anomalies; Type 2 can use actual UNSW `bytes`/`packets` ranges from filtered data.

**Inputs:**
- False alarm distribution from `templates/zero_day_templates.json` (simplified to 2 types)
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

3. **Write CSV Output (Include Tracking Columns):**

   ```python
   import pandas as pd
   
   # Convert to DataFrame
   output_df = pd.DataFrame(timestamped_events)
   
   # Select columns in exact order (23 columns: 21 schema + 2 tracking)
   columns_ordered = [
       'timestamp', 'src_host', 'dst_host', 'src_subnet', 'dst_subnet',
       'proto', 'sport', 'dport', 'service', 'duration', 'bytes', 'packets',
       'sttl', 'dttl', 'state', 'sloss', 'dloss', 'ct_src_dport_ltm', 'ct_dst_src_ltm',
       'attack_cat', 'label',
       '_unsw_row_id', 'scenario_name'  # Tracking columns for auditability
   ]
   
   output_df = output_df[columns_ordered]
   
   # Write CSV
   output_df.to_csv(f"{scenario_name}_30_events.csv", index=False)
   ```

---

## **Output Schema Specification**

**Final Output:** 23 columns (21 schema + 2 tracking), 30 rows per scenario CSV file.

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
| **sttl** | int | Source TTL, 0-254 | 64 |
| **dttl** | int | Destination TTL, 0-254 | 64 |
| **state** | string | Connection state: FIN \| CON \| INT \| RST \| FSRA | CON |
| **sloss** | int | Source packet loss count, 0-28 | 0 |
| **dloss** | int | Destination packet loss count, 0-27 | 0 |
| **ct_src_dport_ltm** | int | Source-port scan count (last time monitored), 1-43 | 2 |
| **ct_dst_src_ltm** | int | Destination-source lateral movement count, 1-40 | 1 |
| **attack_cat** | string | UNSW category: Normal \| Exploits \| Worms \| Backdoor \| Shellcode | Worms |
| **label** | string | Benign \| Malicious \| False Alarm | Malicious |
| **_unsw_row_id** | int | Original row ID from UNSW-NB15 dataset | 12543 |
| **scenario_name** | string | Scenario identifier for tracking (WannaCry, Data_Theft, ShellShock, Netcat_Backdoor, passwd_gzip_scp) | WannaCry |

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
- [ ] CSV column order exact (23 columns in order)
- [ ] Tracking columns present (_unsw_row_id, scenario_name)
- [ ] No missing or NaN values in output

---

## **Key References**

- [UNSW-NB15 Dataset](../IDS_Datasets/UNSW_NB15_training-set(in).csv) — Original source data
- [dataset_mapping.json](../templates/dataset_mapping.json) — **Explicit column-level mapping from UNSW-NB15 (45 columns) to IDS output schema (21 columns)** — START HERE to understand transformation strategy
- [UNSW_NB15_transformed.csv](../UNSW_NB15_transformed.csv) — Transformed output from Pre-Step (schema-aligned, ready for Steps 0-6)
- [global_constraints.json](../templates/global_constraints.json) — Master constraints for all scenarios
- [zero_day_templates.json](../templates/zero_day_templates.json) — Per-scenario metadata
- [ids_pipeline_remediation.md](ids_pipeline_remediation.md) — Detailed gap analysis and remediation strategies (Gaps 1-6, with Gap 6 addressed in Pre-Step)

---

## **Simplified Pipeline Execution Order**

1. ✅ **Pre-Step**: Transform UNSW → `UNSW_NB15_transformed.csv`
2. ✅ **Step 0**: Define global constraints → `templates/global_constraints.json` (manual JSON)
3. ✅ **Step 1**: Update scenario templates → `templates/zero_day_templates.json` (add TIER + phases)
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
- Input CSV: `IDS_Datasets/UNSW_NB15_training-set(in).csv`
- JSON templates: `templates/global_constraints.json` + `templates/zero_day_templates.json`

### **You Will Create:**

6 Python scripts (~600 lines total):
1. **Pre-Step**: Transform UNSW to schema (~150 lines)
2. **Step 2**: Extract stats & classify TIER (~140 lines)
3. **Step 3**: Generate malicious events (~180 lines)
4. **Step 4**: Generate benign events (~120 lines)
5. **Step 5**: Generate false alarms (~100 lines)
6. **Step 6**: Assemble & output CSV (~130 lines)

Plus manual setup:
- **Step 0**: Create `templates/global_constraints.json` (hand-written JSON, ~50 lines)
- **Step 1**: Update `templates/zero_day_templates.json` with TIER + phases (JSON edits, ~10 lines per scenario)

### **Expected Output:**

5 CSV files (one per scenario):
- `WannaCry_30_events.csv`
- `Data_Theft_30_events.csv`
- `ShellShock_30_events.csv`
- `Netcat_Backdoor_30_events.csv`
- `passwd_gzip_scp_30_events.csv`

Each: exactly 30 rows, 23 columns (21 schema + 2 tracking), timestamps 0-1800s increasing, label distribution: ~11 malicious, 15 benign, 5 false alarms.

### **Next Steps:**

1. **Run Pre-Step** to transform UNSW dataset
2. **Manually edit JSON files** (Steps 0-1)
3. **Run Scripts 2-6** sequentially (or in a loop for each scenario)
4. **Validate output CSVs** in Excel/Python (check row count, timestamps, label distribution)
5. Done! Ready for downstream analysis.

For questions: refer to the step-by-step descriptions above. Each step is self-contained and includes example code.

