# IDS Pipeline Gaps & Remediation Strategy

**Document Purpose:** Identify critical ambiguities in the IDS generation pipeline and provide concrete action plans to resolve them.

**Scope:** Five attack scenarios (WannaCry, Data Theft, ShellShock, Netcat Backdoor, passwd-gzip-scp) using UNSW-NB15 grounding data.

**Last Updated:** April 2026

---

## Executive Summary

This document identifies **8 critical gaps** in the current IDS generation approach and provides structured remediation strategies for each. The most severe gaps are:

1. **Causal Chain Construction** (Gap 1): UNSW rows are independent; need explicit sequencing logic
2. **Schema Mapping** (Gap 6): UNSW columns don't align with output format; requires IP→hostname mapping
3. **False Alarm Generation** (Gap 5): Needs explicit taxonomy and generation rules
4. **Rarity Operationalization** (Gap 8): Requires transition probability scoring or simplified heuristics
5. **Feature Realism Validation** (Gap 2): Post-filter sanity checks essential

**Estimated Remediation Effort:** 40–60 hours for full implementation + validation.

---

## GAP 1: Causal Chain Construction

### Problem Statement

**Critical Finding:** UNSW-NB15 rows are **independent flow observations**, not causally-ordered sequences.

- Each row represents a single network flow session with no inherent relationship to adjacent rows
- Your assumption that consecutive rows form attack progressions (initial access → exploitation → payload) is **likely incorrect**
- Filtering for attack_cat="Backdoor" yields isolated observations, not a chain of events

**Why It Matters:**
- NoDOZE's core principle: Malicious behavior is detectable through **suspicious causal chains**, not isolated events
- False positives increase if events appear unrelated temporally/logically
- Output tables must show coherent attack narratives for cognitive realism

**Current Risk Level:** 🔴 **CRITICAL** — Breaks core realistic attack modeling

---

### Recommendation

Adopt a **hybrid approach** combining UNSW grounding with synthetic sequencing:

1. **Use UNSW rows as feature templates**, not as literal event sequences
2. **Extract contiguous subsequences by row index** as a proxy for temporal proximity
3. **Synthetically construct temporal chains** where malicious events are staged with timestamps reflecting attack phases
4. **Validate extracted sequences** against attack phase logic

---

### Action Plan

#### Phase 1: Temporal Ordering Assumption Validation (Week 1)

**Step 1.1 – Sample and inspect UNSW structure**
```python
# Load UNSW data
unsw_df = pd.read_csv("UNSW_NB15_training-set(in).csv")

# For each scenario, extract all rows matching attack_cat
wannacry_rows = unsw_df[unsw_df['attack_cat'].isin(['Exploits', 'Worms'])].reset_index(drop=True)

# Inspect first 10 rows: do consecutive rows share any causal markers?
# Check: src_host consistency, increasing byte counts, port progression
print(wannacry_rows[['src_host', 'dst_host', 'dport', 'bytes', 'duration']].head(10))
```

**Step 1.2 – Assess randomness of row ordering**
- Compute correlation between row index and feature values (duration, bytes, packets)
- If correlation < 0.1 → rows are independent; must synthesize sequences
- If correlation > 0.3 → rows may retain some temporal structure

**Step 1.3 – Document findings**
- Record: "UNSW rows are [independent / temporally structured]"
- If independent: Proceed to Phase 2 (synthetic sequencing)
- If structured: Use sliding windows (rows i, i+1, i+2) as pseudo-chains

---

#### Phase 2: Synthetic Chain Construction (Week 2–3)

**Step 2.1 – Define attack phase templates**

For each scenario, define expected phases:

- **WannaCry:**
  1. Initial Compromise (1–2 events, dport=random, establishing connection)
  2. Reconnaissance (3–4 events, SMB scanning on port 445)
  3. Exploitation (1–2 events, payload transfer, high bytes)
  4. Propagation (2–3 events, lateral movement, repeated port 445 connections)

- **Data Theft:**
  1. Unauthorized Access (1 event, unusual login or exploit)
  2. File Staging (2–3 events, high byte counts, internal transfers)
  3. Compression (1 event, intermediate data processing)
  4. Exfiltration (2 events, FTP/SCP outbound on ports 21/22)

- **ShellShock:**
  1. Initial HTTP Request (1–2 events, port 80, crafted payloads)
  2. Bash Execution (1–2 events, spawned processes)
  3. Data Access/Exfiltration (1–2 events, sensitive file access)

- **Netcat Backdoor:**
  1. Initial Access (1 event, exploit or credential compromise)
  2. Netcat Installation (1 event, high-numbered port listener)
  3. Persistent Connections (2–3 events, sustained backdoor access)
  4. Command Execution (1–2 events, activity through backdoor)

- **passwd-gzip-scp:**
  1. System Access (1 event, unauthorized entry)
  2. File Access (1 event, reading /etc/passwd)
  3. Compression (1 event, gzip operation)
  4. SCP Transfer (1–2 events, port 22 outbound, moderate bytes)

**Step 2.2 – Assign timestamps to phases**

```python
# For a 1800s (30 min) observation window:
base_timestamp = 0
phase_timeline = {
    'benign': [(0, 1800)],           # Spread throughout
    'initial_access': (300, 350),    # ~T=300–350s
    'progression': (350, 600),       # ~T=350–600s, 20–30s between events
    'objective': (600, 900),         # ~T=600–900s
}

# Example: WannaCry reconnaissance phase
phase_start = phase_timeline['progression'][0]
interval = 25  # 25 seconds between SMB scans
for i, event in enumerate(reconnaissance_events):
    event['timestamp'] = phase_start + (i * interval)
```

**Step 2.3 – Populate events by phase**

```python
chains = {}
for scenario in SCENARIOS:
    malicious_events = filter_unsw_by_attack(scenario)  # Get UNSW rows
    
    # Extract template features (duration, bytes, packets)
    template_features = malicious_events[['duration', 'bytes', 'packets', 
                                          'proto', 'dport', 'service']].values
    
    # Assign to phases with timestamp sequencing
    chain = assign_to_phases(scenario, template_features, phase_timeline)
    chains[scenario] = chain
```

**Step 2.4 – Validate phase progression**

For each chain, verify:
- ✅ Events progress from entry_point to target_asset
- ✅ Cross-subnet transitions follow topology rules (User→Enterprise→Operational)
- ✅ Timestamps are strictly increasing
- ✅ Port usage matches scenario (WannaCry=445, Data Theft=21/22, etc.)
- ✅ Byte counts increase through progression (exfiltration has higher bytes)

---

#### Phase 3: Documentation & Testing (Week 3)

**Step 3.1 – Create chain validation notebook**
- Load generated chains for all 5 scenarios
- Run phase progression checks
- Visualize: Timeline diagram + node count per phase

**Step 3.2 – Output specification**
- Document: "Chains constructed by [temporal ordering validation] + [synthetic phase assignment]"
- Store intermediate output: `chains_per_scenario.json` with phase assignments

---

### Risk Assessment

| Risk | Likelihood | Mitigation |
|------|-----------|-----------|
| Phases don't align with real attack timings | Medium | Use NoDOZE case studies to calibrate intervals |
| Synthetic sequencing reduces feature realism | Medium | Preserve UNSW feature distributions; vary only timestamps |
| Temporal order affects feature correlations | Low | Validate: Correlation(bytes, duration) consistent with UNSW |

---

## GAP 2: Feature Realism After Filtering

### Problem Statement

After filtering UNSW for (attack_cat="Backdoor" AND dport=22), will the resulting feature distributions (bytes, packets, duration) realistically represent SCP exfiltration? 

- Filtered subsets may have atypical distributions (e.g., short durations when real exfiltration requires sustained connections)
- Blending with benign events may amplify unrealistic outliers
- No explicit validation currently planned

**Why It Matters:**
- IDS systems detect anomalies partly through **feature distributions** (high bytes → high risk)
- Unrealistic features → invalid alert triage results in downstream experiments
- Users may recognize synthetic data as inauthentic

**Current Risk Level:** 🟡 **HIGH** — Degrades experimental validity

---

### Recommendation

Implement **per-scenario feature validation** with scenario-specific thresholds:

| Scenario | Validation Check | Acceptable Range | Action if Failed |
|----------|------------------|-----------------|-----------------|
| **WannaCry** | High `rate` (flows/sec), many short bursts | rate > 50, duration 0.1–2s | Flag; resample from UNSW or adjust |
| **Data Theft** | Long duration, high bytes | duration 10–300s, bytes 1M–100M | Flag; increase byte scale or duration |
| **ShellShock** | Port 80 HTTP, short duration | duration 0.1–5s, dport=80 | Flag; enforce port 80 |
| **Netcat** | Unusual high port, long duration | dport > 20000, duration > 60s | Flag; validate high port assignment |
| **passwd-gzip-scp** | Port 22, moderate bytes | dport=22, bytes 100K–10M, duration 5–60s | Flag; validate SSH-appropriate range |

---

### Action Plan

#### Phase 1: Define Feature Constraints (Week 1)

**Step 1.1 – Create validation schema per scenario**

```python
FEATURE_CONSTRAINTS = {
    'WannaCry': {
        'duration': (0.05, 2.0),          # Rapid SMB scans
        'bytes': (200, 10000),            # Exploit payloads, not huge
        'packets': (5, 100),              # Few packets per flow
        'rate': (20, 500),                # High-frequency scanning
        'dport': [445],                   # SMB only
    },
    'Data_Theft': {
        'duration': (5, 300),             # Sustained file transfer
        'bytes': (100000, 100000000),     # Large data exfiltration
        'packets': (50, 5000),            # Many packets for large transfers
        'rate': (1, 50),                  # Moderate flow rate
        'dport': [21, 22],                # FTP or SCP
    },
    'ShellShock': {
        'duration': (0.05, 5),            # Quick HTTP requests + execution
        'bytes': (500, 50000),            # Command responses
        'packets': (5, 500),              # HTTP request/response
        'rate': (10, 200),                # Multiple HTTP requests
        'dport': [80],                    # HTTP only
    },
    'Netcat_Backdoor': {
        'duration': (30, 3600),           # Persistent connection
        'bytes': (100, 100000),           # Low to moderate throughput
        'packets': (10, 1000),            # Ongoing session
        'rate': (0.1, 10),                # Low frequency (interactive)
        'dport': (10000, 65535),          # High-numbered ports
    },
    'passwd_gzip_scp': {
        'duration': (5, 60),              # Medium transfer
        'bytes': (100000, 10000000),      # File upload (passwd + archive)
        'packets': (50, 2000),            # SSH transfer
        'rate': (1, 50),                  # Moderate rate
        'dport': [22],                    # SSH/SCP only
    },
}
```

**Step 1.2 – Extract scenario subsets from UNSW**

```python
def validate_filtered_features(scenario_name, filtered_df):
    """Validate that filtered rows match expected feature ranges."""
    constraints = FEATURE_CONSTRAINTS[scenario_name]
    violations = []
    
    for col, (min_val, max_val) in constraints.items():
        if col == 'dport':
            # List of allowed values
            violating_rows = filtered_df[~filtered_df['dport'].isin(max_val)]
        else:
            # Range constraint
            violating_rows = filtered_df[
                (filtered_df[col] < min_val) | (filtered_df[col] > max_val)
            ]
        
        if len(violating_rows) > 0:
            violations.append({
                'column': col,
                'count': len(violating_rows),
                'pct': (len(violating_rows) / len(filtered_df)) * 100,
            })
    
    return violations
```

---

#### Phase 2: Iterative Refinement (Week 2)

**Step 2.1 – Test each scenario**

```python
scenarios = [
    ('WannaCry', {'attack_cat': ['Exploits', 'Worms']}),
    ('Data_Theft', {'attack_cat': ['Backdoor', 'Exploits'], 'dport': [21, 22]}),
    ('ShellShock', {'attack_cat': ['Shellcode'], 'dport': [80]}),
    ('Netcat_Backdoor', {'attack_cat': ['Backdoor']}),
    ('passwd_gzip_scp', {'attack_cat': ['Backdoor'], 'proto': ['tcp'], 'dport': [22]}),
]

for scenario_name, filters in scenarios:
    # Apply filters
    filtered_df = unsw_df.copy()
    for col, values in filters.items():
        filtered_df = filtered_df[filtered_df[col].isin(values)]
    
    # Validate
    violations = validate_filtered_features(scenario_name, filtered_df)
    
    print(f"\n{scenario_name}: {len(filtered_df)} rows found")
    if violations:
        print("  Violations:")
        for v in violations:
            print(f"    {v['column']}: {v['pct']:.1f}% out of range")
    else:
        print("  ✅ All features within expected ranges")
```

**Step 2.2 – Apply remediation strategies**

If violations detected:

- **Strategy A (Resample):** If < 70% of rows are valid, filter more strictly or use different attack_cat values
  ```python
  # Example: ShellShock filtering too loose?
  # Try: attack_cat='Shellcode' AND dport=80 AND duration < 5
  ```

- **Strategy B (Scale):** If duration is too short, scale all durations by a factor (e.g., ×2)
  ```python
  filtered_df['duration'] = filtered_df['duration'] * 1.5
  ```

- **Strategy C (Replace):** If too many violations (>30%), generate synthetic features using UNSW distribution as template
  ```python
  # Preserve time-ordered rows; regenerate bytes/duration from scenario-specific KDE
  from scipy.stats import gaussian_kde
  kde = gaussian_kde(scenario_template_df['bytes'])
  filtered_df['bytes'] = kde.resample(len(filtered_df))
  ```

**Step 2.3 – Document acceptance criteria**

For each scenario, record:
- % of filtered rows meeting all constraints
- Which constraints failed most often
- Remediation strategy applied

```yaml
WannaCry:
  rows_valid: 245 / 312 (78%)
  violations:
    - duration_too_long: 45 rows (14%)
    - dport_not_445: 22 rows (7%)
  remediation: Strategy B applied (scale duration ×0.5 for outliers)
  status: ✅ APPROVED
```

---

#### Phase 3: Downstream Validation (Week 3)

**Step 3.1 – Pre-generation sanity check**

Before generating final 30-event tables, revalidate all malicious events:

```python
def final_feature_check(scenario_events):
    """Pre-generation validation of all events."""
    valid_count = 0
    for event in scenario_events:
        if all_constraints_met(event, FEATURE_CONSTRAINTS[scenario]):
            valid_count += 1
    
    acceptance_rate = valid_count / len(scenario_events)
    if acceptance_rate < 0.85:
        raise ValueError(f"Only {acceptance_rate*100:.1f}% events valid. "
                         f"Run Gap 2 remediation again.")
```

**Step 3.2 – Log feature statistics**

For final output, generate summary statistics per scenario:

```
WannaCry (10 malicious events):
  duration: mean=0.8s, median=0.6s, range=(0.1–2.0)
  bytes: mean=2,500, median=1,800, range=(500–8,000)
  ✅ All within expected ranges
```

---

### Risk Assessment

| Risk | Likelihood | Mitigation |
|------|-----------|-----------|
| Filtered feature distributions are too atypical | Medium | Use Strategy B (scaling) or Strategy C (regeneration) |
| Remediation breaks feature correlations | Medium | After remediation, validate: Corr(bytes, packets) ≈ UNSW baseline |
| Benign/false alarm events further distort distribution | Low | Validate final merged table (Gap 2 check run post-merge) |

---

## GAP 3: Event Count and Label Distribution

### Problem Statement

The pipeline requires **exactly 30 events** with precise label ratios (35% malicious, 50% benign, 15% false alarms). However:

- UNSW filtering may yield variable counts per scenario (e.g., 3–50 rows depending on attack_cat prevalence)
- If Backdoor rows are scarce, you'll have only 5 malicious events for a 10–11 target
- Current approach unclear: Truncate output? Synthesize? Interpolate?

**Why It Matters:**
- Imbalanced labels → Different alert triage outcomes across scenarios
- Inconsistent table sizes → Confounding factor in user experiments
- Label distribution directly affects NoDoze anomaly scoring

**Current Risk Level:** 🟡 **HIGH** — Directly affects experimental design

---

### Recommendation

Adopt **scenario-specific synthesis with fallback strategies**:

1. If UNSW yields ≥ 10 malicious rows → Use actual rows (preferred)
2. If UNSW yields 5–9 rows → Augment with parameterized variations (feature-preserving synthesis)
3. If UNSW yields < 5 rows → Generate synthetically from scenario + feature templates

Maintain **strict 30-event target** and **label ratios** across all scenarios.

---

### Action Plan

#### Phase 1: Assess UNSW Availability (Week 1)

**Step 1.1 – Count rows per scenario**

```python
scenario_counts = {}
for scenario_name, filters in SCENARIOS.items():
    filtered_df = unsw_df.copy()
    for col, values in filters.items():
        filtered_df = filtered_df[filtered_df[col].isin(values)]
    
    scenario_counts[scenario_name] = len(filtered_df)
    print(f"{scenario_name}: {len(filtered_df)} malicious rows")
```

**Step 1.2 – Stratify by count tier**

```python
TIER_1 = {s: c for s, c in scenario_counts.items() if c >= 10}       # Use as-is
TIER_2 = {s: c for s, c in scenario_counts.items() if 5 <= c < 10}   # Augment
TIER_3 = {s: c for s, c in scenario_counts.items() if c < 5}         # Synthesize
```

**Step 1.3 – Document tier distribution**

Record findings:

```yaml
WannaCry:
  available: 245 rows
  tier: TIER_1 (use-as-is)
  strategy: Randomly sample 10–11 rows

Data_Theft:
  available: 8 rows
  tier: TIER_2 (augment)
  strategy: Use 8 rows + parameterize 2–3 variations

ShellShock:
  available: 3 rows
  tier: TIER_3 (synthesize)
  strategy: Use 3 rows as templates + generate 7–8 synthetic variants
```

---

#### Phase 2: Tier-Specific Event Generation (Week 2–3)

**Step 2.1 – TIER 1: Random Sampling**

```python
def generate_tier1_events(scenario_name, target_count=11):
    """Randomly sample malicious events from UNSW."""
    filtered_df = filter_by_scenario(scenario_name)
    
    if len(filtered_df) < target_count:
        raise ValueError(f"Expected ≥ {target_count}, got {len(filtered_df)}")
    
    sampled = filtered_df.sample(n=target_count, random_state=42)
    return sampled.to_dict('records')
```

---

**Step 2.2 – TIER 2: Parameterized Augmentation**

For scenarios with 5–9 base rows, generate variations by:

1. Using actual rows as-is
2. Creating 2–3 variations per base row with modified parameters:
   - Vary src/dst IPs (within same subnet constraints)
   - Perturb duration ±10–20%
   - Scale bytes ±15% (preserve relative magnitudes)
   - Shift timestamps by 5–15 seconds

```python
def parameterize_variation(base_event, variant_id):
    """Create parameter-varied copy of base event."""
    import random
    
    variant = base_event.copy()
    
    # Vary network parameters (preserve topology)
    variant['src_host'] = reassign_src_host(base_event['src_host'], variant_id)
    variant['dst_host'] = reassign_dst_host(base_event['dst_host'], variant_id)
    
    # Perturb temporal/volumetric features
    duration_scale = 1.0 + random.uniform(-0.2, 0.2)
    variant['duration'] = base_event['duration'] * duration_scale
    
    byte_scale = 1.0 + random.uniform(-0.15, 0.15)
    variant['bytes'] = int(base_event['bytes'] * byte_scale)
    
    # Preserve feature correlations
    packet_scale = byte_scale * (random.uniform(0.9, 1.1))
    variant['packets'] = int(base_event['packets'] * packet_scale)
    
    # Timestamp offset
    variant['timestamp'] = base_event['timestamp'] + random.randint(5, 15)
    
    return variant

def generate_tier2_events(scenario_name, target_count=11):
    """Use actual rows + parameterized variations."""
    filtered_df = filter_by_scenario(scenario_name)
    base_rows = filtered_df.to_dict('records')
    
    augmented = base_rows.copy()
    
    # Generate variations until target reached
    variant_id = 1
    while len(augmented) < target_count:
        base_idx = (variant_id - 1) % len(base_rows)
        variant = parameterize_variation(base_rows[base_idx], variant_id)
        augmented.append(variant)
        variant_id += 1
    
    return augmented[:target_count]
```

**Important:** Track which events are actual vs. parameterized in output:

```python
# Add metadata column
for i, event in enumerate(augmented):
    if i < len(base_rows):
        event['_source'] = 'UNSW_actual'
    else:
        event['_source'] = 'UNSW_parameterized'
    event['_variant_id'] = i
```

---

**Step 2.3 – TIER 3: Synthetic Generation**

For scenarios with < 5 base rows, generate synthetic events using Gaussian Kernel Density Estimation (KDE) on UNSW templates:

```python
from scipy.stats import gaussian_kde, norm
import numpy as np

def generate_tier3_events(scenario_name, base_rows_actual, target_count=11):
    """Generate synthetic events from KDE fitted to base rows."""
    
    # Fit KDE to base rows on key features
    features_to_fit = ['duration', 'bytes', 'packets', 'rate']
    
    synthetic_events = []
    
    for i in range(target_count - len(base_rows_actual)):
        synthetic_event = {}
        
        # Copy scenario-specific fixed values from base row template
        template = base_rows_actual[i % len(base_rows_actual)]
        synthetic_event['attack_cat'] = template['attack_cat']
        synthetic_event['proto'] = template['proto']
        synthetic_event['dport'] = template['dport']
        synthetic_event['service'] = template['service']
        
        # Generate features from KDE
        for feat in features_to_fit:
            kde = gaussian_kde(np.array([row[feat] for row in base_rows_actual]))
            synthetic_event[feat] = kde.resample(1)[0][0]
        
        # Ensure non-negative values
        synthetic_event['duration'] = max(0.01, synthetic_event['duration'])
        synthetic_event['bytes'] = max(1, int(synthetic_event['bytes']))
        synthetic_event['packets'] = max(1, int(synthetic_event['packets']))
        
        # Assign host/subnet (per topology rules)
        synthetic_event['src_host'], synthetic_event['src_subnet'] = \
            assign_source_per_scenario(scenario_name)
        synthetic_event['dst_host'], synthetic_event['dst_subnet'] = \
            assign_destination_per_scenario(scenario_name)
        
        synthetic_event['_source'] = 'UNSW_synthetic_KDE'
        synthetic_event['_variant_id'] = len(base_rows_actual) + i
        
        synthetic_events.append(synthetic_event)
    
    return base_rows_actual + synthetic_events
```

---

#### Phase 3: Label Distribution Assembly (Week 3)

**Step 3.1 – Populate benign and false alarm events**

After malicious events determined (11 per scenario):

```python
def assemble_30_events(malicious_events, scenario_name):
    """Assemble 30-event table with target label distribution."""
    
    # Calculate required counts
    total_malicious = len(malicious_events)           # 10–11
    total_benign = int(30 * 0.50)                     # 15 (50%)
    total_false_alarm = 30 - total_malicious - total_benign  # 4–5 (15%)
    
    # Sample benign events from UNSW (attack_cat != 'Normal')
    benign_df = unsw_df[unsw_df['attack_cat'] == 'Normal']
    benign_events = benign_df.sample(n=total_benign, random_state=42).to_dict('records')
    
    # Generate/sample false alarm events (see Gap 5)
    false_alarm_events = generate_false_alarms(scenario_name, total_false_alarm)
    
    # Combine and assign labels
    all_events = []
    
    for event in malicious_events:
        event['label'] = 'Malicious'
        all_events.append(event)
    
    for event in benign_events:
        event['label'] = 'Benign'
        all_events.append(event)
    
    for event in false_alarm_events:
        event['label'] = 'False Alarm'
        all_events.append(event)
    
    # Verify counts
    assert len(all_events) == 30, f"Expected 30 events, got {len(all_events)}"
    assert sum(1 for e in all_events if e['label'] == 'Malicious') == total_malicious
    assert sum(1 for e in all_events if e['label'] == 'Benign') == total_benign
    assert sum(1 for e in all_events if e['label'] == 'False Alarm') == total_false_alarm
    
    return all_events
```

**Step 3.2 – Timestamp assignment to final 30-event table**

(See Gap 4 for detailed timestamping logic)

---

#### Phase 4: Validation and Documentation (Week 3)

**Step 3.1 – Per-scenario output report**

```yaml
WannaCry_30events.csv:
  generation_strategy: TIER_1 (random sample)
  malicious_source: [245 rows from UNSW, randomly sampled 11]
  benign_source: [UNSW `Normal` label, sampled 15]
  false_alarm_source: [synthesized, see Gap 5]
  label_distribution:
    malicious: 11 (37%)  # NB: May vary ±1 due to calculation
    benign: 15 (50%)
    false_alarm: 4 (13%)
  feature_validity: ✅ See Gap 2 validation report
  temporal_coherence: ✅ See Gap 4 validation report
```

**Step 3.2 – Cross-scenario consistency check**

```python
def consistency_check(all_scenarios_events):
    """Verify label distributions consistent across scenarios."""
    for scenario, events in all_scenarios_events.items():
        total = len(events)
        mal_pct = sum(1 for e in events if e['label'] == 'Malicious') / total
        ben_pct = sum(1 for e in events if e['label'] == 'Benign') / total
        
        # Allow ±2% deviation
        assert 0.33 < mal_pct < 0.40, f"{scenario}: malicious ={mal_pct*100:.1f}%"
        assert 0.48 < ben_pct < 0.52, f"{scenario}: benign = {ben_pct*100:.1f}%"
        
        print(f"✅ {scenario}: distribution acceptable")
```

---

### Risk Assessment

| Risk | Likelihood | Mitigation |
|------|-----------|-----------|
| Parameterized events are too similar to base | Medium | Add larger perturbation (±25% instead of ±15%) |
| KDE-generated features are out-of-range | Medium | Post-generate, run Gap 2 validation; resample if needed |
| Label distribution drifts across scenarios | Low | Run consistency check; adjust benign/false_alarm counts |
| Synthetic events detected as fake by human raters | Medium | Add metadata column (`_source`) for post-hoc analysis; blind raters to source |

---

## GAP 4: Temporal Coherence and Ordering

### Problem Statement

The 30 events must be temporally ordered to show **realistic attack progression**. However:

- No explicit timestamping strategy defined
- Risk of scrambled sequences (benign events interrupting attack chain)
- NoDOZE expects causality visible in temporal ordering

**Why It Matters:**
- Cyber analysts expect attacks to unfold over minutes, not randomly scattered over time
- False alarms should be temporally isolated (not causal to attack)
- NoDOZE's anomaly scoring depends on event sequencing

**Current Risk Level:** 🟡 **HIGH** — Affects cognitive realism and NoDoze validity

---

### Recommendation

Implement **staged temporal architecture**:

```
Timeline (0–1800 seconds):
├─ Benign baseline (0–300s): 5–7 routine events
├─ Attack phase 1 (300–600s): Initial access + reconnaissance (3–4 events)
├─ Attack phase 2 (600–900s): Lateral movement + exploitation (3–4 events)
├─ Attack phase 3 (900–1200s): Objective execution (2–3 events)
├─ Benign recovery (1200–1800s): Post-attack baseline (7–8 events)
└─ False alarms: Scattered throughout, NOT adjacent to attack chain
```

---

### Action Plan

#### Phase 1: Define Temporal Architecture (Week 1)

**Step 1.1 – Assign phase timebands per scenario**

```python
TEMPORAL_ARCHITECTURE = {
    'WannaCry': {
        'total_duration': 1800,  # seconds (30 minutes)
        'phases': [
            {'name': 'benign_baseline', 'start': 0, 'end': 300, 'events': 6},
            {'name': 'initial_access', 'start': 300, 'end': 400, 'events': 2},
            {'name': 'reconnaissance', 'start': 400, 'end': 700, 'events': 3},
            {'name': 'exploitation', 'start': 700, 'end': 900, 'events': 2},
            {'name': 'propagation', 'start': 900, 'end': 1200, 'events': 2},
            {'name': 'benign_recovery', 'start': 1200, 'end': 1800, 'events': 9},
        ],
        'false_alarm_zones': [(600, 700), (1200, 1300)],  # Away from attack
    },
    # ... (similar for other scenarios)
}
```

**Step 1.2 – Justify phase timing**

Document reasoning:
- **WannaCry reconnaissance**: 3 events over 300s = 1 SMB scan every 100s (realistic)
- **Data Theft exfiltration**: 2 events over ~200s = staged file aggregation + transfer
- **ShellShock exploitation**: 2 events over 200s = initial request + response

---

#### Phase 2: Temporal Assignment Algorithm (Week 2)

**Step 2.1 – Assign events to phases**

```python
def assign_timestamps_to_30_events(malicious_events, benign_events, 
                                   false_alarm_events, scenario_name):
    """Assign timestamps to all 30 events based on phase architecture."""
    
    arch = TEMPORAL_ARCHITECTURE[scenario_name]
    total_duration = arch['total_duration']
    
    timestamped_events = []
    event_id = 0
    
    # Iterate through phases
    for phase in arch['phases']:
        phase_name = phase['name']
        phase_start = phase['start']
        phase_end = phase['end']
        phase_event_count = phase['events']
        phase_duration = phase_end - phase_start
        
        # Determine event pool for this phase
        if 'attack' in phase_name or phase_name in ['initial_access', 'reconnaissance']:
            # Draw from malicious_events
            event_pool = malicious_events
            label = 'Malicious'
        elif 'benign' in phase_name:
            # Draw from benign_events
            event_pool = benign_events
            label = 'Benign'
        else:
            event_pool = []
        
        # Assign timestamps uniformly within phase
        for i in range(phase_event_count):
            if len(event_pool) == 0:
                print(f"Warning: No events available for {phase_name}")
                continue
            
            # Sample from pool
            event = event_pool.pop(0)
            event['label'] = label
            
            # Timestamp: uniform distribution within phase
            # But attacks should be sequential (not scattered)
            if 'attack' in phase_name:
                # Sequential: t_i = phase_start + i * (phase_duration / phase_event_count)
                interval = phase_duration / phase_event_count
                event['timestamp'] = phase_start + (i * interval) + random.uniform(0, interval * 0.1)
            else:
                # Benign: scattered randomly
                event['timestamp'] = phase_start + random.uniform(0, phase_duration)
            
            event['event_id'] = event_id
            event_id += 1
            timestamped_events.append(event)
    
    # Add false alarms (scattered in allowed zones)
    for zone_start, zone_end in arch['false_alarm_zones']:
        for fa_event in false_alarm_events:
            fa_event['timestamp'] = random.uniform(zone_start, zone_end)
            fa_event['label'] = 'False Alarm'
            fa_event['event_id'] = event_id
            event_id += 1
            timestamped_events.append(fa_event)
    
    # Sort by timestamp
    timestamped_events.sort(key=lambda e: e['timestamp'])
    
    # Verify total count
    assert len(timestamped_events) == 30, f"Expected 30, got {len(timestamped_events)}"
    
    return timestamped_events
```

**Step 2.2 – Validate temporal coherence**

```python
def validate_temporal_coherence(events, scenario_name):
    """Check that attack events form contiguous sequences."""
    
    malicious_events = [e for e in events if e['label'] == 'Malicious']
    
    # Extract timestamps
    mal_timestamps = [e['timestamp'] for e in malicious_events]
    
    # Check 1: Timestamps are strictly increasing
    assert all(mal_timestamps[i] <= mal_timestamps[i+1] 
               for i in range(len(mal_timestamps)-1)), \
        "Timestamps NOT strictly increasing"
    
    # Check 2: Malicious events are clustered (not scattered throughout)
    # Calculate "attack window" = max_timestamp - min_timestamp
    attack_window = max(mal_timestamps) - min(mal_timestamps)
    
    # Attack should occur within ~900s, not spread over entire 1800s
    arch = TEMPORAL_ARCHITECTURE[scenario_name]
    expected_window = 0  # Sum of attack phase durations
    for phase in arch['phases']:
        if 'attack' in phase['name'].lower() or phase['name'] not in ['benign_baseline', 'benign_recovery']:
            expected_window += (phase['end'] - phase['start'])
    
    assert attack_window <= expected_window * 1.2, \
        f"Attack spread over {attack_window}s, expected ≤ {expected_window*1.2}s"
    
    print(f"✅ {scenario_name}: Temporal coherence validated")
    print(f"   Attack window: {attack_window}s (expected: ≤ {expected_window*1.2}s)")
    
    # Check 3: No single malicious event is isolated (shouldn't be alone in time)
    for i, event in enumerate(malicious_events):
        # Find nearest neighbor (benign or other malicious)
        nearest_other = float('inf')
        for other_event in events:
            if other_event['event_id'] != event['event_id']:
                time_diff = abs(other_event['timestamp'] - event['timestamp'])
                if time_diff > 0:
                    nearest_other = min(nearest_other, time_diff)
        
        assert nearest_other < 120, \
            f"Malicious event {event['event_id']} is isolated ({nearest_other}s from nearest)"
    
    return True
```

---

#### Phase 3: Visualization and Debugging (Week 2–3)

**Step 3.1 – Generate timeline diagram**

```python
import matplotlib.pyplot as plt

def plot_timeline(events, scenario_name):
    """Visualize event timeline with labels."""
    
    fig, ax = plt.subplots(figsize=(14, 6))
    
    # Plot events by label
    labels_to_color = {'Malicious': 'red', 'Benign': 'green', 'False Alarm': 'orange'}
    
    for label, color in labels_to_color.items():
        labeled_events = [e for e in events if e['label'] == label]
        timestamps = [e['timestamp'] for e in labeled_events]
        y_pos = [0 if label == 'Malicious' else (1 if label == 'Benign' else 2) 
                 for _ in timestamps]
        
        ax.scatter(timestamps, y_pos, c=color, s=100, label=label, alpha=0.6)
    
    ax.set_xlabel('Time (seconds)')
    ax.set_ylabel('Event Type')
    ax.set_yticks([0, 1, 2])
    ax.set_yticklabels(['Malicious', 'Benign', 'False Alarm'])
    ax.set_title(f'Event Timeline: {scenario_name}')
    ax.legend()
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(f'timeline_{scenario_name}.png', dpi=150)
    plt.close()
    
    print(f"✅ Timeline saved: timeline_{scenario_name}.png")
```

**Step 3.2 – Generate event sequence report**

```python
def print_event_sequence(events, scenario_name):
    """Print tabular sequence of events."""
    
    print(f"\n{'='*80}")
    print(f"Event Sequence: {scenario_name} (sorted by timestamp)")
    print(f"{'='*80}")
    print(f"{'ID':>3} | {'Time (s)':>8} | {'Label':<12} | {'Protocol':<6} | {'DPort':>5} | {'Bytes':>10}")
    print(f"{'-'*80}")
    
    for event in sorted(events, key=lambda e: e['timestamp']):
        print(f"{event['event_id']:>3} | {event['timestamp']:>8.1f} | {event['label']:<12} | "
              f"{event.get('proto', 'N/A'):<6} | {event.get('dport', 'N/A'):>5} | "
              f"{event.get('bytes', 0):>10,}")
```

---

### Risk Assessment

| Risk | Likelihood | Mitigation |
|------|-----------|-----------|
| Phases too predictable (obvious staging) | Low | Randomize within-phase timestamps ±10% |
| Malicious events appear unrelated to casual observer | Low | Ensure sequential ordering + add port consistency |
| False alarms clustered near real attack | Medium | Explicitly exclude false alarms from attack windows |
| Timestamps not realistically spaced | Low | Use UNSW inter-event timing as template |

---

## GAP 5: False Alarm Generation

### Problem Statement

False alarms must be **locally anomalous but globally common** (NoDOZE principle), but:

- Current approach vague: "filter/modify benign events"
- No specification of what makes an event "locally anomalous"
- Risk: False alarms look too suspicious (misclassified as malicious) or too benign

**Why It Matters:**
- NoDOZE alert triage effectiveness depends on false alarm authenticity
- Users must perceive false alarms as realistic vs. malicious alert candidates
- Label errors cascade to NoDoze scoring validation

**Current Risk Level:** 🔴 **CRITICAL** — False alarm realism directly affects experiments

---

### Recommendation

Implement **taxonomy of 3 false alarm types** with explicit generation rules:

| Type | Characteristic | Example | How it's Anomalous | How it's Common |
|------|---|---|---|---|
| **Type 1: Unusual Port + Benign Service** | Rare port, benign traffic | Port 9999 from trusted admin host, low bytes | Rare port (anomalous) | Admin tools use varied ports (globally common) |
| **Type 2: High Volume + Low-Risk Service** | Many packets/bytes, low-risk proto | 100MB DNS query | High bytes (anomalous) | DNS is routine (globally common) |
| **Type 3: Rare Duration + Benign Context** | Very short/long flow, benign host | 0.02s SSH connection | Unusual duration pattern | SSH logins common, but not at this scale |

---

### Action Plan

#### Phase 1: Define False Alarm Taxonomy (Week 1)

**Step 1.1 – Parameterize all false alarm types**

```python
FALSE_ALARM_TYPES = {
    'type_1_unusual_port_benign_service': {
        'description': 'High-numbered port from trusted host, benign service',
        'parameters': {
            'dport_range': (10000, 65535),          # Unusual port
            'src_host_constraint': 'trusted_admin', # E.g., Enterprise0, Defender
            'service': 'dns',                       # Common/benign service
            'bytes_range': (100, 1000),             # Low data transfer
            'duration_range': (0.1, 5.0),           # Short session
        },
        'real_world_justification': 'Admin uses unconventional port for DNS query via custom tool',
        'why_anomalous': 'Port 10000+ is rare in normal traffic',
        'why_common': 'DNS queries are routine; port variation within admin tools is expected',
    },
    
    'type_2_high_volume_low_risk': {
        'description': 'Large data transfer over normally low-volume service',
        'parameters': {
            'service': 'dns',                       # Normally low-volume
            'bytes_range': (10000000, 100000000),   # 10–100 MB (anomalous for DNS)
            'packets_range': (1000, 10000),         # Many packets
            'duration_range': (30, 300),            # Sustained session
            'proto': 'tcp',                         # TCP for large transfer
        },
        'real_world_justification': 'Zone transfer or DNS tunneling (benign data exfil)',
        'why_anomalous': 'DNS not normally used for bulk data',
        'why_common': 'DNS tunneling is a known benign technique',
    },
    
    'type_3_rare_duration_benign_context': {
        'description': 'Atypical connection duration from benign host',
        'parameters': {
            'src_host_constraint': 'benign_internal',  # User or Enterprise host
            'dport': [22],                             # SSH (benign)
            'duration_range': (0.01, 0.05),            # Very short (anomalous)
            'bytes_range': (50, 500),                  # Minimal data
            'service': 'ssh',
        },
        'real_world_justification': 'SSH connection attempt rejected, or connection timeout',
        'why_anomalous': 'SSH sessions rarely < 0.1s',
        'why_common': 'Failed SSH attempts common in enterprises',
    },
}
```

---

#### Phase 2: Generation Algorithms (Week 2)

**Step 2.1 – Type 1: Unusual Port + Benign Service**

```python
def generate_false_alarm_type1(scenario_name, count=2):
    """Unusual port + benign service from trusted host."""
    
    fa_events = []
    
    for i in range(count):
        # Select trusted admin host (varies by scenario)
        src_host = random.choice(['Enterprise0', 'Enterprise2', 'Defender'])
        src_subnet = 'Subnet 2 (Enterprise)'
        
        # Destination: benign external DNS server
        dst_host = f'8.8.8.{8+i}'  # Google DNS variations
        dst_subnet = 'External'
        
        # Random high port
        dport = random.randint(10000, 65535)
        sport = random.randint(49152, 65535)
        
        # DNS query (low bytes, short duration)
        event = {
            'timestamp': None,  # Will be assigned in Gap 4
            'src_host': src_host,
            'dst_host': dst_host,
            'src_subnet': src_subnet,
            'dst_subnet': dst_subnet,
            'proto': 'tcp',
            'sport': sport,
            'dport': dport,
            'service': 'dns',
            'duration': random.uniform(0.2, 3.0),
            'bytes': random.randint(100, 1000),
            'packets': random.randint(5, 50),
            'attack_cat': 'Normal',
            'label': 'False Alarm',
            '_fa_type': 'unusual_port_benign_service',
            '_fa_reason': f'High port {dport} with DNS service anomalous but admin queries over varied ports are normal'
        }
        
        fa_events.append(event)
    
    return fa_events
```

**Step 2.2 – Type 2: High Volume + Low-Risk Service**

```python
def generate_false_alarm_type2(scenario_name, count=1):
    """High volume DNS transfer (tunneling)."""
    
    fa_events = []
    
    for i in range(count):
        # Internal host to external DNS server
        src_host = random.choice(['User0', 'User1', 'Enterprise1'])
        src_subnet = 'Subnet 1 (User)' if 'User' in src_host else 'Subnet 2 (Enterprise)'
        
        dst_host = '1.1.1.1'  # Cloudflare DNS
        dst_subnet = 'External'
        
        event = {
            'timestamp': None,  # Will be assigned in Gap 4
            'src_host': src_host,
            'dst_host': dst_host,
            'src_subnet': src_subnet,
            'dst_subnet': dst_subnet,
            'proto': 'tcp',
            'sport': random.randint(49152, 65535),
            'dport': 53,  # DNS
            'service': 'dns',
            'duration': random.uniform(60, 300),  # Long session
            'bytes': random.randint(10000000, 100000000),  # 10–100 MB
            'packets': random.randint(2000, 10000),
            'attack_cat': 'Normal',
            'label': 'False Alarm',
            '_fa_type': 'high_volume_low_risk',
            '_fa_reason': 'Large DNS data transfer (possible benign tunneling)'
        }
        
        fa_events.append(event)
    
    return fa_events
```

**Step 2.3 – Type 3: Rare Duration + Benign Context**

```python
def generate_false_alarm_type3(scenario_name, count=1):
    """Failed/timed-out SSH connection."""
    
    fa_events = []
    
    for i in range(count):
        # User to Enterprise SSH service
        src_host = random.choice(['User1', 'User2', 'User3'])
        src_subnet = 'Subnet 1 (User)'
        
        dst_host = random.choice(['Enterprise0', 'Enterprise1'])
        dst_subnet = 'Subnet 2 (Enterprise)'
        
        event = {
            'timestamp': None,  # Will be assigned in Gap 4
            'src_host': src_host,
            'dst_host': dst_host,
            'src_subnet': src_subnet,
            'dst_subnet': dst_subnet,
            'proto': 'tcp',
            'sport': random.randint(49152, 65535),
            'dport': 22,  # SSH
            'service': 'ssh',
            'duration': random.uniform(0.01, 0.05),  # Very short (failed attempt)
            'bytes': random.randint(50, 500),
            'packets': random.randint(2, 10),  # Few packets
            'attack_cat': 'Normal',
            'label': 'False Alarm',
            '_fa_type': 'rare_duration_benign',
            '_fa_reason': 'Very brief SSH session (rejected login, timeout, or connection reset)'
        }
        
        fa_events.append(event)
    
    return fa_events
```

---

#### Phase 3: False Alarm Distribution Logic (Week 2)

**Step 3.1 – Distribute false alarm types across 5 scenarios**

```python
def distribute_false_alarms(scenario_name, target_count=5):
    """Generate 4–5 false alarms per scenario, mixed types."""
    
    fa_events = []
    
    # Strategy: Vary type distribution per scenario to avoid repetition
    if scenario_name == 'WannaCry':
        # 2x Type 1, 1x Type 2, 1x Type 3
        fa_events.extend(generate_false_alarm_type1(scenario_name, 2))
        fa_events.extend(generate_false_alarm_type2(scenario_name, 1))
        fa_events.extend(generate_false_alarm_type3(scenario_name, 1))
    
    elif scenario_name == 'Data_Theft':
        # Weighted toward Type 1 (admin activity)
        fa_events.extend(generate_false_alarm_type1(scenario_name, 2))
        fa_events.extend(generate_false_alarm_type3(scenario_name, 1))
    
    elif scenario_name == 'ShellShock':
        # Weighted toward Type 2 (web traffic anomalies)
        fa_events.extend(generate_false_alarm_type2(scenario_name, 2))
        fa_events.extend(generate_false_alarm_type1(scenario_name, 1))
    
    # ... etc for Netcat, passwd-gzip-scp
    
    # Ensure target count
    while len(fa_events) < target_count:
        fa_events.extend(generate_false_alarm_type1(scenario_name, 1))
    
    return fa_events[:target_count]
```

---

#### Phase 4: Validation and Documentation (Week 3)

**Step 4.1 – False alarm coherence checks**

```python
def validate_false_alarms(fa_events, scenario_name):
    """Verify false alarms are realistically generated."""
    
    for event in fa_events:
        # Check 1: Not part of attack chain
        # (Verified by temporal isolation in Gap 4)
        
        # Check 2: Service matches port
        port_to_service = {21: 'ftp', 22: 'ssh', 53: 'dns', 80: 'http', 443: 'https'}
        if event['dport'] in port_to_service:
            expected_service = port_to_service[event['dport']]
            if event['service'] != expected_service and event['service'] != '-':
                print(f"Warning: Port {event['dport']} should use service '{expected_service}', "
                      f"got '{event['service']}'")
        
        # Check 3: Feature ranges make sense
        if event['bytes'] < 0 or event['duration'] < 0:
            raise ValueError(f"Invalid event: bytes={event['bytes']}, duration={event['duration']}")
        
        # Check 4: Is it labeled 'Normal' in attack_cat?
        assert event['attack_cat'] == 'Normal', \
            f"False alarm should have attack_cat='Normal', got '{event['attack_cat']}'"
    
    print(f"✅ False alarms validated for {scenario_name}")
    
    # Summary
    type_counts = {}
    for event in fa_events:
        fa_type = event.get('_fa_type', 'unknown')
        type_counts[fa_type] = type_counts.get(fa_type, 0) + 1
    
    print(f"   Type distribution: {type_counts}")
```

**Step 4.2 – Document false alarms per scenario**

```yaml
WannaCry False Alarms (4 events):
  - Type 1a: Port 45678 from Enterprise0 → 8.8.8.8:dns (admin tool query)
  - Type 1b: Port 56789 from Defender → 8.8.8.4:dns (internal DNS request)
  - Type 2: Enterprise1 → 1.1.1.1:53 (53 MB DNS transfer, possible zone transfer)
  - Type 3: User2 → Enterprise1:22 (0.02s SSH, rejected login)
  
  Rationale: Types 1 & 3 are admin/user activity. Type 2 is benign tunneling.
             None are causally related to WannaCry attack chain.
```

---

### Risk Assessment

| Risk | Likelihood | Mitigation |
|------|-----------|-----------|
| False alarms too suspicious (misclassified as malicious) | Medium | Pre-test with pilot users; adjust feature ranges if > 20% misclassified |
| False alarms too benign (missed by NoDOZE) | Low | Ensure at least one "unusual port + benign service" per scenario |
| Repetitive false alarms across scenarios | Medium | Vary type distribution per scenario (documented in Step 3.1) |
| False alarms accidentally correlated with attack | Medium | Enforce temporal isolation via Gap 4 false_alarm_zones |

---

## GAP 6: Schema Mapping (UNSW → Output Format)

### Problem Statement

UNSW-NB15 features don't map directly to output schema:

| Output Schema Column | UNSW Equivalent | Gap |
|---|---|---|
| `src_host` | Not present (IPs only) | ❌ Must synthesize hostname |
| `src_subnet` | Not present | ❌ Must infer from topology |
| `dst_host` | Not present (IPs only) | ❌ Must synthesize hostname |
| `dst_subnet` | Not present | ❌ Must infer from topology |
| `bytes` | `sbytes + dbytes` | ✅ Sum |
| `proto` | `proto` | ✅ Direct |
| `service` | `service` | ✅ Direct (or infer from dport) |

**Why It Matters:**
- Output table must match schema for downstream processing
- Host/subnet labels critical for topology + attack narrative
- Feature loss or misalignment invalidates NoDOZE analysis

**Current Risk Level:** 🟡 **HIGH** — Structural requirement; no workaround

---

### Recommendation

Implement **deterministic IP→host mapping** preserving feature integrity:

1. Keep all UNSW features unchanged (bytes, packets, duration → realism)
2. Map IPs to hostnames deterministically
3. Infer subnets from hostname prefix

---

### Action Plan

#### Phase 1: Host Assignment Rules (Week 1)

**Step 1.1 – Define IP space allocation**

```python
# UNSW IPs are in range 192.168.x.x, 10.x.x.x, etc.
# Map to topology:

IP_TO_HOST_MAPPING = {
    # Subnet 1 (User)
    '192.168.1.0/26': ['User0', 'User1', 'User2', 'User3', 'User4'],
    
    # Subnet 2 (Enterprise)
    '192.168.2.0/26': ['Enterprise0', 'Enterprise1', 'Enterprise2', 'Defender'],
    
    # Subnet 3 (Operational)
    '192.168.3.0/26': ['OpHost0', 'OpHost1', 'OpHost2', 'OpServer0'],
    
    # External
    '0.0.0.0/0': ['*_external'],  # Any IP not in above ranges
}

SUBNET_LABELS = {
    'User': 'Subnet 1 (User)',
    'Enterprise': 'Subnet 2 (Enterprise)',
    'OpHost': 'Subnet 3 (Operational)',
    'OpServer': 'Subnet 3 (Operational)',
}
```

**Step 1.2 – IP→Host mapping deterministic hash**

```python
import hashlib

def map_ip_to_host(ip_address, scenario_name):
    """Deterministically map IP to host based on scenario + IP."""
    
    # Determine which pool this IP belongs to
    # (Use IP's last octet as pseudo-hash)
    last_octet = int(ip_address.split('.')[-1])
    
    # Consistency: Same IP always maps to same host within scenario
    hash_value = hashlib.md5(f"{scenario_name}:{ip_address}".encode()).hexdigest()
    hash_int = int(hash_value, 16)
    
    # Assign based on IP range
    if ip_address.startswith('192.168.1'):
        host_pool = ['User0', 'User1', 'User2', 'User3', 'User4']
    elif ip_address.startswith('192.168.2'):
        host_pool = ['Enterprise0', 'Enterprise1', 'Enterprise2', 'Defender']
    elif ip_address.startswith('192.168.3') or ip_address.startswith('10.0.3'):
        host_pool = ['OpHost0', 'OpHost1', 'OpHost2', 'OpServer0']
    else:
        # External IP
        return f"external_{last_octet}", 'External'
    
    # Deterministic selection from pool
    host_idx = hash_int % len(host_pool)
    host = host_pool[host_idx]
    
    # Infer subnet
    subnet_key = host.split('_')[0] if '_' in host else host.split('0')[0] if any(c.isdigit() for c in host) else host
    subnet = SUBNET_LABELS.get(subnet_key, 'Unknown')
    
    return host, subnet
```

---

#### Phase 2: Schema Transformation (Week 1–2)

**Step 2.1 – Transform UNSW row to output schema**

```python
def transform_unsw_row_to_output(unsw_row, scenario_name):
    """Map UNSW row to output CSV schema."""
    
    # Extract UNSW fields
    src_ip = unsw_row.get('src_ip')
    dst_ip = unsw_row.get('dst_ip')
    
    # Map IPs to hostnames
    src_host, src_subnet = map_ip_to_host(src_ip, scenario_name)
    dst_host, dst_subnet = map_ip_to_host(dst_ip, scenario_name)
    
    # Build output row
    output_row = {
        'timestamp': unsw_row.get('ts', 0),  # Use flow start time or assign later (Gap 4)
        'src_host': src_host,
        'dst_host': dst_host,
        'src_subnet': src_subnet,
        'dst_subnet': dst_subnet,
        'proto': unsw_row.get('proto', '-'),
        'sport': unsw_row.get('sprt', 0),
        'dport': unsw_row.get('dprt', 0),
        'service': unsw_row.get('service', infer_service_from_port(unsw_row.get('dprt'))),
        'duration': unsw_row.get('dur', 0),
        'bytes': unsw_row.get('sbytes', 0) + unsw_row.get('dbytes', 0),  # Total bytes
        'packets': unsw_row.get('spkts', 0) + unsw_row.get('dpkts', 0),  # Total packets
        'attack_cat': unsw_row.get('attack_cat', 'Normal'),
        'label': 'Benign',  # Placeholder; will be set by Gap 3 logic
    }
    
    return output_row

def infer_service_from_port(dport):
    """Infer service name from destination port."""
    port_to_service = {
        21: 'ftp',
        22: 'ssh',
        53: 'dns',
        80: 'http',
        443: 'https',
        25: 'smtp',
        110: 'pop3',
        143: 'imap',
        445: 'smb',
    }
    return port_to_service.get(dport, '-')
```

---

#### Phase 3: Batch Transformation (Week 2)

**Step 3.1 – Transform all events for a scenario**

```python
def batch_transform_scenario(scenario_name, unsw_df):
    """Transform all UNSW rows for scenario to output schema."""
    
    output_events = []
    
    for _, unsw_row in unsw_df.iterrows():
        output_row = transform_unsw_row_to_output(unsw_row, scenario_name)
        output_events.append(output_row)
    
    # Validation: Check for duplicates, null values
    assert len(output_events) == len(unsw_df), "Row count mismatch"
    
    # Check no null hosts
    for event in output_events:
        assert event['src_host'] is not None, "src_host is None"
        assert event['dst_host'] is not None, "dst_host is None"
    
    return output_events
```

---

#### Phase 4: Validation and Reconciliation (Week 2–3)

**Step 4.1 – Verify deterministic mapping consistency**

```python
def validate_schema_mapping(events, scenario_name):
    """Ensure IP→host mapping is consistent and complete."""
    
    ip_to_host_cache = {}
    
    for event in events:
        # Fetch source/dest IPs (if stored in original UNSW row)
        # Note: After transformation, raw IPs not stored; validate against mapping
        
        # Check 1: Hosts are in expected pools
        for host, subnet in [(event['src_host'], event['src_subnet']),
                             (event['dst_host'], event['dst_subnet'])]:
            
            if host.startswith('User'):
                assert subnet == 'Subnet 1 (User)', f"Hostname/subnet mismatch: {host} in {subnet}"
            elif host.startswith('Enterprise') or host == 'Defender':
                assert subnet == 'Subnet 2 (Enterprise)', f"Hostname/subnet mismatch: {host} in {subnet}"
            elif host.startswith('Op'):
                assert subnet == 'Subnet 3 (Operational)', f"Hostname/subnet mismatch: {host} in {subnet}"
            elif host.startswith('external'):
                assert subnet == 'External', f"Hostname/subnet mismatch: {host} in {subnet}"
    
    # Check 2: Service matches port
    for event in events:
        dport = event['dport']
        service = event['service']
        expected_service = infer_service_from_port(dport)
        
        if service != '-' and expected_service != '-':
            # Allow mismatch if service is explicitly set in UNSW
            pass  # (Some UNSW rows may have non-standard service labels)
    
    print(f"✅ Schema mapping validated for {scenario_name}")
```

**Step 4.2 – Preserve source IP metadata (for debugging)**

```python
# Optional: Add debug column to output CSV
def add_debug_columns(output_events, unsw_df):
    """For validation, store original IP addresses."""
    
    for i, event in enumerate(output_events):
        # Store original UNSW row for reconciliation
        event['_debug_original_src_ip'] = unsw_df.iloc[i].get('src_ip', 'N/A')
        event['_debug_original_dst_ip'] = unsw_df.iloc[i].get('dst_ip', 'N/A')
        event['_debug_scenario'] = scenario_name

# Strip debug columns before final output
def clean_debug_columns(events):
    """Remove debug columns from final CSV."""
    return [{k: v for k, v in e.items() if not k.startswith('_debug')} 
            for e in events]
```

---

### Risk Assessment

| Risk | Likelihood | Mitigation |
|------|-----------|-----------|
| IP→host mapping produces collisions (same IP → different hosts) | Low | Use deterministic hash; validate mapping is 1-to-1 per scenario |
| Subnet inferences incorrect | Low | Hardcode host→subnet mapping; validate all hosts assigned |
| Feature loss during transformation (bytes/packets/duration wrong) | Low | Unit test transformation; compare UNSW values pre/post |

---

## GAP 7: Per-Scenario Network Grounding

### Problem Statement

Benign and false alarm events should be scenario-tailored (vs. generic across all scenarios):

- **Problem**: If all scenarios use identical benign SSH traffic, realism suffers
- **Question**: Should benign events vary by scenario?

**Current Status from user input:** Benign events should be **generic across scenarios** (act as "noise" unaware of specific zero-day)

**Recommendation:** Accept generic benign events, but document why:

> "Benign events are deliberately generic because the IDS system has no prior knowledge of the specific zero-day scenario. Network traffic noise is indistinguishable across attack types."

---

### Implementation

**Step 1 – Generic benign event pool**

```python
GENERIC_BENIGN_EVENTS = [
    # Web browsing
    {'service': 'http', 'dport': 80, 'bytes': (1000, 100000), 'duration': (0.1, 30)},
    # SSH admin connections
    {'service': 'ssh', 'dport': 22, 'bytes': (100, 10000), 'duration': (5, 600)},
    # DNS queries
    {'service': 'dns', 'dport': 53, 'bytes': (100, 1000), 'duration': (0.05, 2)},
    # FTP transfers
    {'service': 'ftp', 'dport': 21, 'bytes': (10000, 10000000), 'duration': (5, 300)},
    # SMTP (email)
    {'service': 'smtp', 'dport': 25, 'bytes': (1000, 100000), 'duration': (2, 60)},
]
```

---

## GAP 8: Rarity Operationalization

### Problem Statement

NoDOZE uses **transition probability** to detect anomalies, but:

- Transition probability calculation requires event frequency database
- Current pipeline doesn't explicitly compute this
- Question: Simplify to heuristics, or implement full NoDoze scoring?

**Recommendation:** **SIMPLIFY to heuristics** (Option 1) for MVP:

Assume UNSW labels (`attack_cat`) encode rarity; no separate scoring needed in generation phase. Document that **post-generation, users can compute transition probabilities** for validation.

---

### Implementation

**Step 1 – Document simplification**

```yaml
Rarity Operationalization Strategy:

  Assumed: UNSW 'attack_cat' labels already capture rarity
    - Rows labeled 'Exploits', 'Worms', 'Backdoor' → high-anomaly transitions
    - Rows labeled 'Normal' → low-anomaly transitions

  Post-Generation:
    - No explicit transition matrix computed during generation
    - Users can post-hoc compute via: P(E_{i+1} | E_i) = freq / total
    - Expected: Malicious sequences have P < 0.01; benign > 0.1; false alarms 0.01–0.1

  Validation:
    - Run NoDOZE's network diffusion on final tables
    - Verify: Malicious chains score higher than benign/false alarm chains
```

---

## Implementation Roadmap

### Timeline Overview

```
Week 1: Gaps 1, 2, 3, 6 (Core foundations)
  - Verify UNSW temporal structure (Gap 1, Phase 1)
  - Define feature constraints (Gap 2, Phase 1)
  - Assess UNSW per-scenario counts (Gap 3, Phase 1)
  - Define schema mappings (Gap 6, Phase 1)

Week 2: Gaps 1, 2, 3, 4, 5 (Sequencing & generation)
  - Construct causal chains (Gap 1, Phases 2–3)
  - Validate feature realism (Gap 2, Phases 2–3)
  - Generate 30-event tables (Gap 3, Phases 2–3)
  - Timestamp all events (Gap 4, Phases 1–2)
  - Generate false alarms (Gap 5, Phases 2–3)

Week 3: All gaps (Integration & validation)
  - Complete schema transformation (Gap 6, Phases 3–4)
  - Validate all tables end-to-end (All gaps, Phase 4)
  - Generate final CSV outputs + documentation
  - Run pilot NoDOZE validation (Gap 8 post-generation)

Week 4 (Buffer): Refinement
  - Address any validation failures
  - Iterate on feature/temporal constraints
  - Prepare final tables for experiments
```

---

## Validation Checklist

Before finalizing outputs, run:

```markdown
## Pre-Release Validation

### Gap 1: Causal Chains ✓
- [ ] UNSW temporal ordering assessed
- [ ] Phase templates defined for all 5 scenarios
- [ ] Chains validated: progression from entry_point → target_asset
- [ ] Cross-subnet transitions verified

### Gap 2: Feature Realism ✓
- [ ] Per-scenario constraints applied
- [ ] Post-filter validation passed (>85% events in range)
- [ ] Remediation strategies applied if failures detected
- [ ] Feature correlations preserved (Corr(bytes, packets) valid)

### Gap 3: Event Count & Labels ✓
- [ ] All scenarios have exactly 30 events
- [ ] Label distribution: malicious ≈35%, benign ≈50%, false alarm ≈15%
- [ ] Tier assignment documented (TIER_1/2/3)
- [ ] Parameterized/synthetic events marked (_source column)

### Gap 4: Temporal Coherence ✓
- [ ] Timestamps strictly increasing
- [ ] Malicious events clustered (attack window ≤ 900s)
- [ ] Attack progression shows clear phases
- [ ] False alarms temporally isolated from attack chain
- [ ] Timeline diagrams generated + reviewed

### Gap 5: False Alarms ✓
- [ ] 4–5 false alarms per scenario
- [ ] Type distribution varied across scenarios
- [ ] All labeled as 'Normal' in attack_cat
- [ ] Temporally isolated (not causal to attack)
- [ ] _fa_type and _fa_reason columns populated

### Gap 6: Schema Mapping ✓
- [ ] All UNSW rows transformed to output schema
- [ ] src_host/dst_host/src_subnet/dst_subnet assigned
- [ ] Mapping is deterministic and consistent
- [ ] Service field correctly inferred from dport
- [ ] No null values in required columns

### Gap 7: Network Grounding ✓
- [ ] Benign events are generic (not scenario-specific)
- [ ] All hosts belong to defined topology (User/Enterprise/Operational/External)
- [ ] Cross-subnet flows follow topology rules

### Gap 8: Rarity Operationalization ✓
- [ ] Assumption documented: UNSW labels encode rarity
- [ ] No explicit transition matrix computed (post-gen only)
- [ ] Ready for downstream NoDOZE validation

### Final Outputs ✓
- [ ] 5 CSV files: `{scenario}_30events.csv`
- [ ] 1 metadata file: `generation_report.csv` (gap status per scenario)
- [ ] 5 timeline diagrams: `timeline_{scenario}.png`
- [ ] 1 implementation log: `implementation_notes.md`
```

---

## Risk Summary & Escalation

### Critical Risks (🔴 Red)

| Gap | Risk | Mitigation |
|-----|------|-----------|
| 1 | UNSW rows independent, not sequenced | Validate temporal structure; if failed, use synthetic sequencing (Phases 2–3) |
| 5 | False alarms too similar to malicious | Pre-test with pilot users; adjust feature ranges |
| 6 | Feature loss during transformation | Unit test; compare UNSW pre/post |

### High Risks (🟡 Yellow)

| Gap | Risk | Mitigation |
|-----|------|-----------|
| 2 | Filtered features atypical | Post-filter validation + remediation (Phases 2–3) |
| 3 | Event count insufficiency | Tier-based synthesis strategy (Phases 2–3) |
| 4 | Temporal coherence breaks | Staged architecture + validation plots |

### Resolved Risks (✅ Green)

- Gap 7: Network grounding (use generic benign)
- Gap 8: Rarity operationalization (post-hoc via NoDOZE)

---

## Conclusion

This document provides a **detailed, actionable remediation strategy** for all 8 gaps identified in the IDS generation pipeline. By following the phases outlined and validating against the checklist, you will produce **high-fidelity, realistic IDS tables** suitable for NoDoze-aligned alert triage research.

**Next Step:** Begin **Week 1 activities** (Gaps 1, 2, 3, 6) with Python scripts for data validation and transformation. Estimated completion: 4 weeks.

---

**Document Version:** 1.0  
**Last Updated:** April 2026  
**Prepared by:** Copilot Planning Agent
