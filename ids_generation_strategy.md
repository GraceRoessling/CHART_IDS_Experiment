# IDS Event Table Generation Strategy
## Methodological Framework for Synthetic Attack Scenario Synthesis

**Document Purpose:** Describe the complete methodology for generating synthetic 30-event intrusion detection system (IDS) tables representing five zero-day attack scenarios, grounded in real network traffic data (UNSW-NB15) with controlled temporal and causal structure.

**Scope:** WannaCry, Data Theft (FTP/SSH), ShellShock, Netcat Backdoor, passwd-gzip-scp

**Principle:** UNSW-NB15 rows are independent network flow observations (not attack sequences). This methodology uses UNSW flows as feature templates and applies synthetic temporal sequencing to construct realistic attack progressions.

---

## **Overview: Pipeline Architecture**

The methodology consists of **8 sequential steps** (Pre-Step + Steps 0-6), each producing specific artifacts for downstream steps.

| Step | Purpose | Input Artifacts | Output Artifacts |
|------|---------|-----------------|------------------|
| **Pre-Step** | Transform UNSW dataset to output schema | UNSW-NB15 CSV | UNSW_NB15_transformed.csv |
| **Step 0** | Define global constraints | Scenario descriptions | global_constraints.json |
| **Step 1** | Structure scenario templates | global_constraints.json | Updated zero_day_templates.json |
| **Step 2** | Extract UNSW statistics & classify tier | UNSW_NB15_transformed.csv + zero_day_templates.json | TIER classification + feature statistics |
| **Step 3** | Generate malicious events | Filtered UNSW data + TIER classification | 10-11 malicious events per scenario |
| **Step 4** | Generate benign events | Network topology rules | 15 benign events per scenario |
| **Step 5** | Generate false alarm events | False alarm taxonomy | 4-5 false alarm events per scenario |
| **Step 6** | Assemble 30-event tables | Malicious + benign + false alarm events | Final CSV: {scenario}_30_events.csv |

---

## **Pre-Step: Transform UNSW-NB15 Dataset to Output Schema**

### **Objective**

Map UNSW-NB15 dataset columns to the output IDS table schema, creating an intermediate transformed dataset used by all downstream steps. This ensures consistent column definitions, data types, and network topology assignments across the pipeline.

### **Scientific Rationale**

UNSW-NB15 and the target IDS table schema have misaligned structures:
- UNSW contains raw IP addresses; output requires hostname labels and subnet assignments
- UNSW separates directional bytes (sent/received); output aggregates total bytes
- UNSW lacks explicit scenario-level metadata; output requires per-scenario tagging for proper filtering

By transforming upfront, all downstream steps work with a standardized, ready-to-use dataset, improving reproducibility and maintainability.

### **Inputs**

1. **Data files:**
   - `IDSD_Datasets/UNSW_NB15_training-set(in).csv` — Original UNSW-NB15 dataset

2. **Configuration (defined in methodology, not user input):**
   - IP-to-hostname mapping rules (IP ranges assigned to predefined host pools: User0-4, Enterprise0-2, Defender, OpHost0-2, OpServer0)
   - Subnet mapping rules (hostname prefixes → subnet labels)
   - Port-to-service mapping (standard protocol-port associations)
   - Scenario list (five attack scenarios)

### **Outputs**

1. **Data file:**
   - `UNSW_NB15_transformed.csv` — Schema-aligned dataset with new columns

2. **Schema specification:**
   - 16 columns: timestamp, src_host, dst_host, src_subnet, dst_subnet, proto, sport, dport, service, duration, bytes, packets, attack_cat, label, _unsw_row_id, scenario_name
   - All rows from original UNSW dataset, replicated once per scenario (5× multiplicity) with scenario-specific IP-to-host mappings

### **Substeps**

1. **Load UNSW dataset** into memory as tabular data structure
2. **For each UNSW row and each scenario:**
   - Extract source IP, destination IP, protocol, ports, duration, bytes, packets, attack category
3. **For each IP address:**
   - Determine IP range (User, Enterprise, Operational, or External)
   - Apply deterministic mapping function (scenario-aware hash) to select hostname from pool
   - Infer subnet from hostname prefix
4. **Aggregate directional features:**
   - Sum sent bytes + received bytes → total bytes
   - Sum sent packets + received packets → total packets
5. **Infer service from destination port** using standard port-service lookup table
6. **Construct new row** with all output schema columns, leaving timestamp and label fields null (to be populated in later steps)
7. **Write transformed dataset** to CSV with exact column ordering

### **Validation Criteria (Sanity Checks)**

- [ ] Output CSV has exactly 5× input row count (one per scenario)
- [ ] All critical columns non-null: src_host, dst_host, src_subnet, dst_subnet, proto, dport, service
- [ ] Hostnames are recognizable (User0-4, Enterprise0-2, Defender, etc.; no malformed entries)
- [ ] Subnet assignments match hostname prefixes (User → "Subnet 1 (User)", etc.)
- [ ] Service matches dport (port 445 → 'smb', port 22 → 'ssh', etc.)
- [ ] Bytes and packets are non-negative integers
- [ ] scenario_name column correctly populated with one of five scenario names
- [ ] _unsw_row_id field populated with original UNSW row identifier for traceability

---

## **Step 0: Define Global Constraints**

### **Objective**

Establish cross-scenario constraints that all five attack scenarios must satisfy. These constraints define the acceptable solution space for event generation.

### **Scientific Rationale**

The generation pipeline must produce consistent, reproducible artifacts. Global constraints formalize the requirements (event counts, label distributions, temporal windows, network topology, valid services, output schema) to ensure every scenario adheres to the same specifications. This enables fair comparison across scenarios and controls confounding variables.

### **Inputs**

1. **Methodology guidelines** (derived from research questions):
   - Target event count: 30 events per scenario
   - Label distribution: 35% malicious (10-11 events), 50% benign (15 events), 15% false alarm (4-5 events)
   - Observation window: 1800 seconds
   - Network topology: 3 subnets (User, Enterprise, Operational) with predefined hosts
   - Valid services: http, ftp, ssh, dns, smtp, smb, rdp, others

2. **Scenario input files:**
   - Attack scenario descriptions (five predefined scenarios with entry points, target assets, behavioral patterns)

### **Outputs**

1. **Configuration file:**
   - `global_constraints.json` — Structured JSON file documenting all constraints

2. **Content includes:**
   - Label distribution (percentages and event counts)
   - Network topology (subnet definitions, host lists, IP ranges)
   - Temporal structure (observation window duration)
   - Output schema (14-column specification, required column ordering)
   - Valid values for categorical fields (proto, service, attack_cat, label)
   - Default phase schedule (benign/attack/recovery temporal phases)
   - False alarm taxonomy (types and distribution)

### **Substeps**

1. **Extract requirements** from research methodology documentation
2. **Define network topology:**
   - Subnet 1 (User): User0, User1, User2, User3, User4
   - Subnet 2 (Enterprise): Enterprise0, Enterprise1, Enterprise2, Defender
   - Subnet 3 (Operational): OpHost0, OpHost1, OpHost2, OpServer0
   - External: undefined external hosts (labeled as external_XXX)
3. **Specify temporal phases:**
   - Benign baseline (0-300s): 6 events
   - Attack phase 1 (300-600s): 3 events
   - Attack phase 2 (600-900s): 3 events
   - Attack phase 3 (900-1200s): 2 events
   - Benign recovery (1200-1800s): 9 events
4. **Document false alarm distribution:**
   - Type 1 (Unusual + Benign service): count per scenario
   - Type 2 (High volume + Low-risk service): count per scenario
   - Total: 5 false alarm events per scenario
5. **Specify valid values** for categorical fields and permissible ranges for continuous fields

### **Validation Criteria**

- [ ] JSON file is well-formed and parseable
- [ ] Total events = 30 (6+3+3+2+9+5)
- [ ] Label distribution totals 100% (35% + 50% + 15%)
- [ ] All required fields present in JSON structure
- [ ] Network topology contains all 11 internal hosts
- [ ] Event counts per phase sum to 23 benign+malicious, leaving 5 for false alarms
- [ ] Temporal phases are contiguous (no gaps, no overlaps) in 0-1800s window

---

## **Step 1: Structure Scenario Templates**

### **Objective**

Expand the scenario template file with additional fields required by downstream generation steps. These fields will be populated with computed values during Steps 2-5.

### **Scientific Rationale**

Scenario templates must capture both static metadata (unchanged throughout the pipeline) and computed metadata (derived from UNSW filtering and synthesis decisions). By structuring the template upfront, all steps reference a consistent format, reducing errors and improving reproducibility.

### **Inputs**

1. **Configuration files:**
   - `global_constraints.json` (from Step 0)
   - Existing `zero_day_templates.json` (five scenarios with attack descriptions, entry points, target assets, key behaviors, UNSW filtering rules)

### **Outputs**

1. **Configuration file:**
   - Updated `zero_day_templates.json` — Expanded with new fields

2. **New fields added (initially null, to be populated in Steps 2-5):**
   - `expected_tier`: TIER classification (1 or 2) based on UNSW row count
   - `temporal_architecture`: Phase schedule defining when events occur
   - `false_alarm_distribution`: Type counts for false alarm generation

### **Substeps**

1. **For each scenario:**
   - Preserve existing fields: scenario_name, attack_description, entry_point, target_asset, key_attack_behaviors, unsw_filtering rules
   - Add `expected_tier` field (value: null, to be computed in Step 2)
   - Add `temporal_architecture` object with:
     - total_duration: 1800 (seconds)
     - phases: array structure matching global_constraints (name, start, end, event_count)
     - (false_alarm_zones: optional, for advanced use)
   - Add `false_alarm_distribution` object with:
     - type_1_unusual_benign: null
     - type_2_high_volume_benign: null

2. **Validate JSON structure** to ensure all fields are present and properly nested

### **Validation Criteria**

- [ ] JSON file is well-formed and parseable
- [ ] All five scenarios have new fields (expected_tier, temporal_architecture, false_alarm_distribution)
- [ ] temporal_architecture phases match global_constraints phase names and timing
- [ ] false_alarm_distribution has two type fields
- [ ] Existing scenario metadata (attack descriptions, filtering rules) unchanged

---

## **Step 2: Extract UNSW Statistics and Classify Tier**

### **Objective**

For each scenario, filter the transformed UNSW dataset according to attack-specific rules, compute feature statistics, and determine which tier (TIER 1 or TIER 2) applies based on the quantity of real attack data available.

### **Scientific Rationale**

The amount of available real attack data determines the synthesis strategy. Scenarios with abundant attack flows (≥10 UNSW rows) can rely primarily on real data, while scenarios with fewer flows (5-9 rows) require parameterized variations to reach 10-11 malicious events. This tiered approach balances realism (prioritizing real data) with practical feasibility (generating enough events for analysis).

### **Inputs**

1. **Data files:**
   - `UNSW_NB15_transformed.csv` (from Pre-Step)

2. **Configuration files:**
   - `zero_day_templates.json` (with unsw_filtering rules per scenario)
   - `global_constraints.json`

### **Outputs**

1. **Output files/reporting:**
   - Printed or logged TIER classification and feature statistics for each scenario
   - Updated `zero_day_templates.json` with:
     - `expected_tier` field populated (1 or 2)
     - Feature statistics (informational; for research documentation)
     - Indication of data sufficiency per scenario

### **Substeps**

1. **For each scenario:**
   - Retrieve scenario-specific filtering rules from unsw_filtering section (e.g., attack_cat values, protocol constraints, port constraints)
   
2. **Filter transformed UNSW dataset:**
   - Select rows where scenario_name matches current scenario
   - Apply attack_cat filter (if specified): keep only rows with attack_cat in allowed list
   - Apply protocol filter (if specified): keep only rows with proto in allowed list
   - Apply dport filter (if specified): keep only rows with dport in allowed list
   
3. **Count filtered rows:**
   - If count ≥ 10: assign TIER 1
   - If count 5-9: assign TIER 2
   - If count < 5: raise error (insufficient data; user must adjust filtering rules in JSON)
   
4. **Compute descriptive statistics on filtered rows:**
   - Duration: minimum, maximum, median
   - Bytes: minimum, maximum, median
   - Packets: minimum, maximum, median
   - Unique values: dport, proto
   - Attack category distribution (counts per category)

5. **Document findings:**
   - Log TIER, row count, feature ranges
   - Update zero_day_templates.json with expected_tier

### **Validation Criteria**

- [ ] Each scenario has TIER classification (1 or 2)
- [ ] No scenario has TIER undefined (error case)
- [ ] Filtered row counts are non-zero and consistent with filtering rules
- [ ] Feature statistics show sensible ranges (e.g., duration > 0, bytes ≥ 0, packets ≥ 0)
- [ ] TIER 1 scenarios have ≥10 UNSW rows; TIER 2 have 5-9 rows
- [ ] zero_day_templates.json successfully updated with expected_tier
- [ ] Attack category counts match UNSW filtering rules applied

---

## **Step 3: Generate Malicious Events**

### **Objective**

Create 10-11 realistic malicious network events per scenario using tier-appropriate synthesis strategies. These events represent the attack progression from entry point to target compromise.

### **Scientific Rationale**

Malicious events must exhibit feature distributions consistent with real attacks while forming a coherent causal chain. TIER 1 scenarios (abundant real data) use actual UNSW flows directly, ensuring maximum realism. TIER 2 scenarios (limited real data) supplement with parameterized variations—systematically perturbed copies of real flows—to reach the required event count while maintaining statistical consistency.

### **Inputs**

1. **Data files:**
   - Filtered UNSW rows (from Step 2) for current scenario

2. **Configuration files:**
   - `zero_day_templates.json` with:
     - TIER classification (1 or 2)
     - entry_point, target_asset (for ordering attack chain)
     - key_attack_behaviors (for validation)

3. **Methodology parameters:**
   - TIER 1 strategy: random sampling of filtered UNSW rows
   - TIER 2 strategy: all actual rows + parameterized variations (±20% duration perturbation, ±15% bytes scaling)

### **Outputs**

1. **Malicious event list (10-11 events per scenario):**
   - Each event record contains: src_host, dst_host, src_subnet, dst_subnet, proto, sport, dport, service, duration, bytes, packets, attack_cat, label='Malicious'
   - Additional tracking field: _source (UNSW_actual or UNSW_parameterized)
   - Timestamp field: placeholder (to be assigned in Step 6)

### **Substeps**

**TIER 1 (≥10 UNSW rows):**

1. Randomly sample 10-11 rows from filtered UNSW data
2. Assign deterministic src_host/dst_host mapping preserving network topology
3. Set label='Malicious', _source='UNSW_actual'
4. Preserve all network features (proto, ports, duration, bytes, packets) from UNSW

**TIER 2 (5-9 UNSW rows):**

1. Retain all filtered UNSW rows (5-9 actual events)
2. For remaining needed events (to reach 10-11):
   - Select base row from filtered UNSW data (can reuse rows)
   - Create parameterized variation:
     - Vary src_host: select different host within same subnet as base row
     - Vary dst_host: select different host (can be same subnet or different, depending on scenario)
     - Perturb duration: multiply by random factor in [0.8, 1.2]
     - Scale bytes: multiply by random factor in [0.85, 1.15]
     - Adjust packets: maintain approximate byte-to-packet ratio from base row
   - Set label='Malicious', _source='UNSW_parameterized'
3. Preserve attack_cat from base row

**Both tiers:**

4. Order events to form attack chain:
   - Arrange events in logical progression from entry_point (e.g., User subnet) through intermediate compromises to target_asset (e.g., Enterprise/Operational subnet)
   - Later events should show evidence of progression (higher bytes for data exfiltration, cross-subnet transitions)
5. Ensure no duplicate events in final list

### **Validation Criteria**

- [ ] Exactly 10-11 malicious events generated per scenario
- [ ] All events have valid src_host, dst_host from defined topology
- [ ] All events have label='Malicious'
- [ ] TIER 1 events: all have _source='UNSW_actual', feature values unchanged from UNSW
- [ ] TIER 2 events: mix of _source='UNSW_actual' (5-9) and _source='UNSW_parameterized' (2-6)
- [ ] No missing fields (all network features populated)
- [ ] Feature distributions reasonable (bytes > 0, packets > 0, duration > 0)
- [ ] Byte-to-packet ratio approximately maintained (±20% acceptable variation)
- [ ] Events arranged in logical attack progression (cross-subnet transitions follow network topology)

---

## **Step 4: Generate Benign Events**

### **Objective**

Create 15 routine enterprise network events representing normal business operations, unrelated to attack progression.

### **Scientific Rationale**

Benign events provide baseline traffic context and increase realism. They are intentionally generic across all scenarios (not scenario-specific) because, in a real operational setting, the IDS has no a priori knowledge of the attack type. The baseline traffic pattern is indistinguishable between scenarios. Benign events use predefined service types (HTTP, DNS, SSH, FTP, SMTP, RDP) with realistic feature distributions drawn from UNSW normal traffic.

### **Inputs**

1. **Configuration files:**
   - `global_constraints.json` (network topology, valid services)
   - Service templates (port → service, typical duration ranges, typical byte ranges)

2. **Methodology parameters:**
   - Service types: HTTP (port 80, 1-30s, 5KB-500KB), DNS (port 53, <2s, 100-1000B), SSH (port 22, 10-600s, varies), FTP (port 21, 5-120s, large bytes), SMTP (port 25, moderate bytes), RDP (port 3389, sustained connections)
   - Source hosts: selected from User and Enterprise subnets
   - Destination hosts: internal (other subnets) or external (external_XXX)

### **Outputs**

1. **Benign event list (15 events):**
   - Each event record contains: src_host, dst_host, src_subnet, dst_subnet, proto, sport, dport, service, duration, bytes, packets, attack_cat='Normal', label='Benign'
   - Timestamp field: placeholder (to be assigned in Step 6)

### **Substeps**

1. **Define benign event distribution** (6 service types, 15 total events):
   - HTTP/web browsing: 3 events
   - DNS queries: 3 events
   - SSH admin access: 2 events
   - FTP file transfer: 3 events
   - SMTP email: 2 events
   - RDP remote access: 2 events

2. **For each benign event:**
   - Select service type from distribution
   - Assign src_host: randomly select from User or Enterprise subnets
   - Assign dst_host: 
     - If internal service (SSH, FTP, SMTP): randomly select from Enterprise/Operational subnets
     - If external service (HTTP web browsing, DNS, external services): select external_XXX
   - Assign proto: tcp or udp (depending on service)
   - Assign dport: standard port for service
   - Assign duration: randomly within service-typical range
   - Assign bytes: randomly within service-typical range (maintain realism; e.g., DNS << FTP)
   - Assign packets: derive from bytes and typical packet size for service
   - Assign attack_cat='Normal', label='Benign'

3. **Ensure variety:**
   - No two consecutive events use the same service
   - Mix of internal and external destinations

4. **Shuffle event order** (no specific temporal ordering at this stage; final ordering in Step 6)

### **Validation Criteria**

- [ ] Exactly 15 benign events
- [ ] All events have label='Benign', attack_cat='Normal'
- [ ] All src_hosts from User or Enterprise subnets
- [ ] All dst_hosts are either internal (recognized hosts) or external_XXX
- [ ] Service types match dport (port 80 → http, port 22 → ssh, etc.)
- [ ] Feature distributions realistic (DNS bytes << FTP bytes, HTTP duration typically < 60s)
- [ ] Bytes ≥ 0, packets ≥ 0, duration > 0
- [ ] No missing fields

---

## **Step 5: Generate False Alarm Events**

### **Objective**

Create 4-5 events that exhibit locally anomalous characteristics but are globally benign and common. These events represent situations where an IDS might incorrectly flag routine activity as suspicious.

### **Scientific Rationale**

False alarms form a critical category for IDS research. They represent the false positive problem: events that deviate from the baseline in one dimension but maintain benign context in others. The taxonomy (unusual_benign and high_volume_benign) captures two common false alarm scenarios: (1) legitimate services on non-standard ports, and (2) unusually high volumes of low-risk protocols. Including false alarms improves ecological validity for alert triage research.

### **Inputs**

1. **Configuration files:**
   - `global_constraints.json` (network topology, false alarm taxonomy)
   - `zero_day_templates.json` (false_alarm_distribution per scenario)

2. **Methodology parameters:**
   - Type 1 (Unusual port + Benign service): (any dport outside typical range) + (benign service like DNS)
   - Type 2 (High volume + Low-risk service): (unusually high bytes) + (low-risk port like 53 or 80)
   - Total: 5 false alarm events per scenario

### **Outputs**

1. **False alarm event list (5 events per scenario):**
   - Each event record contains: src_host, dst_host, src_subnet, dst_subnet, proto, sport, dport, service, duration, bytes, packets, attack_cat='Normal', label='False Alarm'
   - Timestamp field: placeholder (to be assigned in Step 6)

### **Substeps**

1. **Type 1: Unusual Port + Benign Service (2 events):**
   - Assign src_host: Enterprise subnet
   - Assign dst_host: external_XXX
   - Assign proto: tcp
   - Assign dport: random high port (10000-65535) instead of standard
   - Assign service: benign service like 'dns' (mismatch with unusual port creates suspicion)
   - Assign duration: short (0.5-2 seconds)
   - Assign bytes: small (100-500 bytes)
   - Assign packets: small (5-20)
   - Assign attack_cat='Normal', label='False Alarm'

2. **Type 2: High Volume + Low-Risk Service (3 events):**
   - Assign src_host: User or Enterprise subnet
   - Assign dst_host: external_XXX (e.g., 1.1.1.1, 8.8.8.8)
   - Assign proto: tcp
   - Assign dport: low-risk port (53 for DNS, 80 for HTTP)
   - Assign service: corresponding benign service
   - Assign duration: longer than typical (30-300 seconds)
   - Assign bytes: unusually high (5-50 MB), much higher than typical for service
   - Assign packets: high (500-3000)
   - Assign attack_cat='Normal', label='False Alarm'

3. **Shuffle events** to randomize order

### **Validation Criteria**

- [ ] Exactly 5 false alarm events (2 Type 1 + 3 Type 2)
- [ ] All events have label='False Alarm', attack_cat='Normal'
- [ ] Type 1 events: dport outside typical ranges (>10000), service inconsistent with port
- [ ] Type 2 events: bytes exceptionally high (>1MB), typical service (port 53 or 80)
- [ ] All src_hosts from internal subnets (User, Enterprise)
- [ ] All dst_hosts external (external_XXX)
- [ ] Bytes ≥ 0, packets ≥ 0, duration > 0
- [ ] No missing fields
- [ ] False alarms are realistic edge cases (not obviously impossible)

---

## **Step 6: Assemble 30-Event Tables and Apply Temporal Ordering**

### **Objective**

Combine malicious (10-11), benign (15), and false alarm (5) events into a single dataset; assign realistic timestamps using a phase-based temporal structure; output final CSV files.

### **Scientific Rationale**

Temporal ordering is crucial for attack sequence analysis. Events are assigned timestamps according to a five-phase temporal architecture: benign baseline → attack phase 1 → attack phase 2 → attack phase 3 → benign recovery. Malicious events are placed sequentially within attack phases (representing the unfolding attack), while benign and false alarm events are scattered across all phases (representing concurrent, unrelated traffic). This structure reflects realistic operational patterns where attacks unfold over minutes while baseline traffic continues.

### **Inputs**

1. **Event lists (from Steps 3-5):**
   - 10-11 malicious events
   - 15 benign events
   - 5 false alarm events

2. **Configuration files:**
   - `zero_day_templates.json` (temporal_architecture phases from Step 1)
   - `global_constraints.json` (phase definitions)

3. **Methodology parameters:**
   - Phase schedule: benign_baseline (0-300s, 6 events), attack_phase_1 (300-600s, 3 events), attack_phase_2 (600-900s, 3 events), attack_phase_3 (900-1200s, 2 events), benign_recovery (1200-1800s, 9 events)
   - Malicious events: sequential assignment within attack phases (even spacing, small random jitter)
   - Benign/false alarm events: random assignment across all phases

### **Outputs**

1. **Data file:**
   - `{scenario_name}_30_events.csv` — One CSV per scenario (5 total)

2. **CSV specification:**
   - Exactly 30 rows (10-11 malicious + 15 benign + 5 false alarm)
   - 14 columns in exact order: timestamp, src_host, dst_host, src_subnet, dst_subnet, proto, sport, dport, service, duration, bytes, packets, attack_cat, label
   - Timestamps strictly increasing from 0 to ~1800 seconds
   - No missing values (all cells populated)

### **Substeps**

1. **Initialize timestamp assignment:**
   - Set phase definitions from temporal_architecture
   - Total observation window: 1800 seconds

2. **Assign timestamps to malicious events:**
   - For each attack phase:
     - Distribute assigned number of events evenly across phase duration
     - Assign timestamps sequentially with small random jitter (±5 seconds)
     - Ordering: events progress through phases in attack chain order (entry → compromise → exfiltration)

3. **Assign timestamps to benign and false alarm events:**
   - Randomly select timestamps from entire 0-1800 range
   - Each event gets one unique timestamp

4. **Combine all events:**
   - Create unified event list with all 30 events

5. **Sort by timestamp:**
   - Apply ascending sort on timestamp column

6. **Verify temporal coherence:**
   - Check: timestamps strictly increasing
   - Check: no duplicate timestamps
   - Check: malicious events clustered in attack phases (not scattered)

7. **Format and output CSV:**
   - Write to CSV with exact column order specified
   - No index column
   - Use standard CSV formatting (comma-separated, quoted strings if necessary)
   - Repeat for each of five scenarios

### **Validation Criteria**

- [ ] Exactly 30 events per scenario
- [ ] Exactly 5 CSV files produced (one per scenario)
- [ ] Timestamps strictly increasing (no decreasing or equal consecutive values)
- [ ] Timestamp range: 0-1800 seconds
- [ ] No missing values in any cell
- [ ] Label distribution: ~11 malicious, 15 benign, ~5 false alarm (total 30)
- [ ] All column values valid and type-consistent (strings as strings, numbers as numbers)
- [ ] Column order matches specification exactly
- [ ] Malicious events form contiguous temporal cluster in 300-1200s range
- [ ] Benign events spread across all phases
- [ ] False alarms do not cluster with malicious events (temporal separation)
- [ ] CSV parseable without errors

---

## **Cross-Step Quality Assurance**

### **Artifact Preservation**

All intermediate artifacts from each step should be preserved (not deleted) to enable:
- Retracing results if problems occur in later steps
- Manual inspection of intermediate data
- Reproducibility and verification

**Intermediate artifacts to retain:**
- `UNSW_NB15_transformed.csv` (from Pre-Step)
- `global_constraints.json` (from Step 0)
- Updated `zero_day_templates.json` (from Steps 1-2)
- Log files or printed reports from Step 2 (TIER classifications, feature statistics)

### **Dependency Chain**

Steps have strict dependencies; they must be executed in order:
- Pre-Step must complete before Step 2 (Step 2 requires transformed UNSW)
- Steps 0-1 must complete before Step 2 (Step 2 requires constraints and templates)
- Step 2 must complete before Step 3 (Step 3 requires TIER classification)
- Steps 3-5 can be executed in any order (they are independent)
- Step 6 must execute last (requires outputs from Steps 3-5)

### **Human Oversight Checkpoints**

At each step, a human operator should verify:

1. **Pre-Step checkpoint:** Inspect sample rows from transformed CSV (verify IP→host mapping looks sensible, schema columns populated)

2. **Step 2 checkpoint:** Review TIER classifications and feature statistics (verify counts make sense, ranges are realistic, filtering captured intended attack types)

3. **Step 3 checkpoint:** Review malicious event list (verify 10-11 events generated, spatial progression sensible, _source mix matches TIER)

4. **Step 4 checkpoint:** Review benign event list (verify 15 events, service variety, no suspicious patterns)

5. **Step 5 checkpoint:** Review false alarm event list (verify 5 events, false alarm types sensible, contextually realistic)

6. **Step 6 checkpoint:** Inspect final CSV (verify 30 events, sorted timestamps, label distribution, no missing values, integrity)

---

## **Documentation and Reporting**

For journal submission, the following should be documented:

### **Methods Section Content**

- This document (ids_generation_strategy.md) serves as the methodological framework
- Specify TIER classifications assigned to each scenario (from Step 2)
- Report feature statistics per scenario (from Step 2)
- Document UNSW filtering rules applied per scenario (from zero_day_templates.json)
- Specify any deviations from standard methodology (e.g., adjusted thresholds)

### **Supplementary Materials**

- Intermediate data files and logs (Pre-Step→Step 2 outputs)
- Sample 30-event CSV files (one per scenario)
- Validation reports from each step
- Configuration files (global_constraints.json, zero_day_templates.json) with comments

### **Reproducibility

**To enable external reproducibility:**

1. Provide exact UNSW-NB15 dataset version and download source
2. Include complete configuration files (constraints, templates) used in generation
3. Document any Python library versions and dependencies
4. Provide step-by-step scripts (separate from this methodology document)
5. Report validation results for all steps
6. Include example output CSV files

---

## **Summary**

This strategy document describes a methodologically sound, reproducible pipeline for generating synthetic IDS event tables grounded in real attack data (UNSW-NB15). By following these steps sequentially, with human oversight at each checkpoint, researchers can generate high-quality synthetic datasets suitable for IDS alert triage research while maintaining scientific rigor and reproducibility.

