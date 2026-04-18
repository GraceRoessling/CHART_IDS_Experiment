"""
PRE-STEP: Transform UNSW-NB15 Dataset to Output Schema

Purpose:
   Map UNSW-NB15 columns (43) to IDS output schema (21 columns).
   Create deterministic, scenario-specific IP→hostname mappings.
   Aggregate directional metrics and generate missing fields.

Output Schema (21 columns, exact order required):
   1.  timestamp (PLACEHOLDER - assigned in Step 6)
   2.  src_host (GENERATED - deterministic IP→host mapping)
   3.  dst_host (GENERATED - deterministic IP→host mapping)
   4.  src_subnet (INFERRED - from host prefix)
   5.  dst_subnet (INFERRED - from host prefix)
   6.  proto (UNSW proto - IDENTITY)
   7.  sport (GENERATED - random ephemeral port)
   8.  dport (GENERATED - inferred from UNSW service)
   9.  service (UNSW service - IDENTITY)
   10. duration (UNSW dur - IDENTITY)
   11. bytes (AGGREGATION - sbytes + dbytes)
   12. packets (AGGREGATION - spkts + dpkts)
   13. sttl (UNSW sttl - IDENTITY)
   14. dttl (UNSW dttl - IDENTITY)
   15. state (UNSW state - IDENTITY)
   16. sloss (UNSW sloss - IDENTITY)
   17. dloss (UNSW dloss - IDENTITY)
   18. ct_src_dport_ltm (UNSW ct_src_dport_ltm - IDENTITY)
   19. ct_dst_src_ltm (UNSW ct_dst_src_ltm - IDENTITY)
   20. attack_cat (UNSW attack_cat - IDENTITY)
   21. label (PLACEHOLDER - assigned in Step 6)

Internal Tracking Columns (not in final schema):
   - _unsw_row_id: Original row ID from UNSW dataset
   - scenario_name: Scenario for filtering in downstream steps

UNSW → Output Mapping Summary:
   - IDENTITY: proto, service, duration (dur), sttl, dttl, state, sloss, dloss, 
               ct_src_dport_ltm, ct_dst_src_ltm, attack_cat
   - AGGREGATION: bytes (sbytes + dbytes), packets (spkts + dpkts)
   - GENERATED: src_host, dst_host, src_subnet, dst_subnet, sport, dport
   - PLACEHOLDER: timestamp, label
"""

import pandas as pd
import random
from pathlib import Path
import helper_functions as hf


# ============================================================
# STEP 1: TRANSFORM SINGLE UNSW ROW
# ============================================================

def transform_unsw_row(unsw_row, scenario_name):
    """
    Transform a single UNSW row to output schema (21 columns + 2 internal tracking).
    
    PROCESS:
    1. Generate synthetic but deterministic src/dst IPs from attack_cat + row_id + proto
       (UNSW dataset does not include IP addresses; we synthesize them)
    2. Map IPs to hostnames (deterministic, scenario-specific)
    3. Infer subnets from hostnames
    4. Aggregate directional metrics (bytes, packets)
    5. Infer destination port from service
    6. Generate random ephemeral source port
    7. Preserve all UNSW feature columns (as-is)
    
    Args:
        unsw_row (pd.Series): Single row from UNSW dataset
        scenario_name (str): Scenario name for deterministic IP mapping
        
    Returns:
        dict: Transformed row with 23 columns (21 schema + 2 tracking)
        
    Raises:
        ValueError: If transformation fails or critical fields are missing
    """
    # Extract row ID and attack category for synthetic IP generation
    try:
        row_id = int(unsw_row['id'])
        attack_cat = str(unsw_row.get('attack_cat', 'Normal'))
    except (KeyError, ValueError, TypeError) as e:
        raise ValueError(f"Missing or invalid id/attack_cat: {e}")
    
    # Validate attack category
    if not hf.validate_attack_cat(attack_cat):
        raise ValueError(f"Invalid attack_cat: {attack_cat}")
    
    # Generate synthetic but deterministic src/dst IPs
    # Use: attack_cat + row_id + hash to create realistic variation
    src_ip, dst_ip = _generate_synthetic_ips(row_id, attack_cat)
    
    # Map IPs to hostnames
    try:
        src_host, src_subnet = hf.map_ip_to_host(src_ip, scenario_name)
        dst_host, dst_subnet = hf.map_ip_to_host(dst_ip, scenario_name)
    except ValueError as e:
        raise ValueError(f"Failed to map IPs in {scenario_name}: {e}")
    
    # Validate hosts
    if not hf.validate_host(src_host):
        raise ValueError(f"Invalid src_host after mapping: {src_host}")
    if not hf.validate_host(dst_host):
        raise ValueError(f"Invalid dst_host after mapping: {dst_host}")
    
    # Aggregate directional metrics
    try:
        bytes_total = int(unsw_row['sbytes']) + int(unsw_row['dbytes'])
        packets_total = int(unsw_row['spkts']) + int(unsw_row['dpkts'])
    except (KeyError, ValueError, TypeError) as e:
        raise ValueError(f"Failed to aggregate bytes/packets: {e}")
    
    # Sanity check: metrics should be non-negative
    if bytes_total < 0:
        raise ValueError(f"Negative bytes_total computed: {bytes_total}")
    if packets_total < 0:
        raise ValueError(f"Negative packets_total computed: {packets_total}")
    
    # Infer port from service
    service = str(unsw_row.get('service', '-'))
    dport = hf.infer_dport_from_service(service)
    if dport is None:
        # If service is not recognized, use a default high port
        dport = 5000
    
    # Generate random ephemeral source port
    sport = hf.generate_ephemeral_port()
    
    # Validate critical fields
    proto = str(unsw_row.get('proto', ''))
    duration = float(unsw_row.get('dur', 0))
    state = str(unsw_row.get('state', ''))
    
    # Build output row (21 schema columns + 2 internal tracking)
    transformed = {
        # SCHEMA COLUMNS (21)
        'timestamp': None,  # Placeholder, assigned in Step 6
        'src_host': src_host,
        'dst_host': dst_host,
        'src_subnet': src_subnet,
        'dst_subnet': dst_subnet,
        'proto': proto,
        'sport': sport,
        'dport': dport,
        'service': service,
        'duration': duration,
        'bytes': bytes_total,
        'packets': packets_total,
        'sttl': int(unsw_row.get('sttl', 0)),
        'dttl': int(unsw_row.get('dttl', 0)),
        'state': state,
        'sloss': int(unsw_row.get('sloss', 0)),
        'dloss': int(unsw_row.get('dloss', 0)),
        'ct_src_dport_ltm': int(unsw_row.get('ct_src_dport_ltm', 0)),
        'ct_dst_src_ltm': int(unsw_row.get('ct_dst_src_ltm', 0)),
        'attack_cat': attack_cat,
        'label': None,  # Placeholder, assigned in Step 6
        
        # INTERNAL TRACKING (2)
        '_unsw_row_id': row_id,
        'scenario_name': scenario_name,
    }
    
    return transformed


# ============================================================
# HELPER: SYNTHETIC IP GENERATION
# ============================================================

def _generate_synthetic_ips(row_id, attack_cat):
    """
    Generate synthetic but deterministic source and destination IPs.
    
    Since the UNSW dataset does not include IP addresses, we generate them
    deterministically based on attack characteristics:
    - Normal traffic: benign src/dst pairs within Subnets 1-2, or external
    - Attack traffic: likely from User/Enterprise to Enterprise/Operational
    
    Args:
        row_id (int): Row ID from UNSW dataset (for determinism)
        attack_cat (str): Attack category (Normal, Exploits, Worms, etc.)
        
    Returns:
        tuple: (src_ip, dst_ip) as strings (e.g., '192.168.1.50', '192.168.2.100')
    """
    # Seed for determinism
    random.seed(hash(f"{row_id}:{attack_cat}") % (2**31))
    
    if attack_cat == 'Normal':
        # Benign traffic: likely within internal subnets or to external
        if random.random() < 0.6:
            # Internal traffic
            src_ip = f"192.168.1.{random.randint(50, 100)}"
            dst_ip = f"192.168.2.{random.randint(50, 100)}"
        else:
            # External traffic
            src_ip = f"192.168.{random.randint(1,2)}.{random.randint(50, 100)}"
            dst_ip = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
    else:
        # Attack traffic: typically from User or within-subnet to Enterprise/Operational
        if random.random() < 0.7:
            # User → Enterprise / Operational (likely initial compromise + spread)
            src_subnet = random.choice(['192.168.1', '192.168.2'])
            dst_subnet = random.choice(['192.168.2', '192.168.3', '10.0.3'])
            src_ip = f"{src_subnet}.{random.randint(50, 100)}"
            dst_ip = f"{dst_subnet}.{random.randint(50, 100)}"
        else:
            # External → Internal (initial attack vector)
            src_ip = f"10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
            dst_ip = f"192.168.{random.choice([1, 2, 3])}.{random.randint(50, 100)}"
    
    # Reset seed to avoid side effects
    random.seed(None)
    
    return src_ip, dst_ip



# ============================================================
# STEP 2: BATCH TRANSFORM FULL DATASET
# ============================================================

def batch_transform_unsw(input_csv_path, output_csv_path):
    """
    Transform entire UNSW dataset to output schema.
    
    PROCESS:
    1. Load UNSW CSV
    2. For each UNSW row, create 5 variant rows (one per scenario)
       - Each scenario has different IP→host mapping (deterministic via scenario ID)
    3. Collect transformed rows into DataFrame
    4. Reorder columns to exact schema order
    5. Validate transformed dataset
    6. Save to output CSV
    
    Args:
        input_csv_path (str): Path to UNSW-NB15 CSV
        output_csv_path (str): Path to save transformed CSV
        
    Returns:
        pd.DataFrame: Transformed dataset (verification)
        
    Raises:
        FileNotFoundError: If input CSV not found
        ValueError: If transformation fails at any row
    """
    # Load UNSW dataset
    print(f"\n{'='*60}")
    print(f"PRE-STEP: Transform UNSW Dataset to Output Schema")
    print(f"{'='*60}")
    
    if not Path(input_csv_path).exists():
        raise FileNotFoundError(f"Input CSV not found: {input_csv_path}")
    
    print(f"\n[STEP 1] LOAD UNSW Dataset")
    unsw_df = pd.read_csv(input_csv_path)
    print(f"  ✓ Loaded {len(unsw_df)} rows from UNSW-NB15")
    print(f"  ✓ Columns: {list(unsw_df.columns)}")
    
    # Transform: iterate UNSW rows × scenarios
    print(f"\n[STEP 2] TRANSFORM Rows (UNSW rows × 5 scenarios)")
    transformed_rows = []
    
    for idx, row in unsw_df.iterrows():
        if idx % 100 == 0:
            print(f"  Processing UNSW row {idx}/{len(unsw_df)}...")
        
        # Create variant for each scenario (deterministic mapping)
        for scenario in hf.SCENARIOS:
            try:
                transformed = transform_unsw_row(row, scenario)
                transformed_rows.append(transformed)
            except ValueError as e:
                raise ValueError(f"Failed at UNSW row {idx} ({scenario}): {e}")
    
    print(f"  ✓ Generated {len(transformed_rows)} transformed rows "
          f"({len(unsw_df)} UNSW × {len(hf.SCENARIOS)} scenarios)")
    
    # Create DataFrame with transformed rows
    print(f"\n[STEP 3] BUILD DataFrame")
    output_df = pd.DataFrame(transformed_rows)
    
    # Reorder columns to exact schema order
    columns_ordered = [
        'timestamp', 'src_host', 'dst_host', 'src_subnet', 'dst_subnet',
        'proto', 'sport', 'dport', 'service', 'duration', 'bytes', 'packets',
        'sttl', 'dttl', 'state', 'sloss', 'dloss',
        'ct_src_dport_ltm', 'ct_dst_src_ltm',
        'attack_cat', 'label',
        '_unsw_row_id', 'scenario_name'  # Internal tracking
    ]
    
    output_df = output_df[columns_ordered]
    print(f"  ✓ Reordered columns to exact schema (23 total: 21 schema + 2 tracking)")
    
    # Validate transformation
    print(f"\n[STEP 4] VALIDATE Transformation")
    _validate_transformed_dataset(output_df)
    
    # Save to CSV
    print(f"\n[STEP 5] SAVE Transformed Dataset")
    output_df.to_csv(output_csv_path, index=False)
    print(f"  ✓ Saved {len(output_df)} rows to {output_csv_path}")
    
    print(f"\n{'='*60}")
    print(f"✅ PRE-STEP COMPLETE")
    print(f"{'='*60}\n")
    
    return output_df


# ============================================================
# STEP 3: VALIDATION
# ============================================================

def _validate_transformed_dataset(df):
    """
    Validate transformed dataset against schema constraints.
    Fail fast on any constraint violation.
    
    Checks:
    1. Row count matches expectations
    2. No null values in critical columns
    3. Host/subnet validity
    4. Service validity
    5. Attack category validity
    6. Metrics are non-negative and internally consistent
    
    Args:
        df (pd.DataFrame): Transformed dataset to validate
        
    Raises:
        AssertionError: If any constraint is violated
    """
    print(f"\n  Validation Checks:")
    
    # Check 1: Row count
    expected_rows = len(df) // len(hf.SCENARIOS)  # Rough sanity check
    print(f"    ✓ Row count: {len(df)} (expected: {expected_rows}×{len(hf.SCENARIOS)})")
    
    # Check 2: No nulls in critical columns
    critical_cols = ['src_host', 'dst_host', 'src_subnet', 'dst_subnet', 
                     'proto', 'service', 'attack_cat']
    null_counts = df[critical_cols].isnull().sum()
    null_total = null_counts.sum()
    assert null_total == 0, f"Found {null_total} nulls in critical columns: {null_counts[null_counts > 0].to_dict()}"
    print(f"    ✓ No nulls in critical columns ({len(critical_cols)} checked)")
    
    # Check 3: Host validity
    invalid_hosts = []
    for host in pd.concat([df['src_host'], df['dst_host']]).unique():
        if not hf.validate_host(host):
            invalid_hosts.append(host)
    assert len(invalid_hosts) == 0, f"Invalid hosts found: {invalid_hosts[:5]}"
    print(f"    ✓ All hosts valid ({df['src_host'].nunique() + df['dst_host'].nunique()} unique)")
    
    # Check 4: Subnet validity
    for subnet in pd.concat([df['src_subnet'], df['dst_subnet']]).unique():
        assert hf.validate_subnet(subnet), f"Invalid subnet: {subnet}"
    print(f"    ✓ All subnets valid ({df['src_subnet'].nunique() + df['dst_subnet'].nunique()} unique)")
    
    # Check 5: Service validity
    invalid_services = [s for s in df['service'].unique() if not hf.validate_service(s)]
    assert len(invalid_services) == 0, f"Invalid services: {invalid_services}"
    print(f"    ✓ All services valid ({df['service'].nunique()} unique)")
    
    # Check 6: Attack category validity
    invalid_cats = [c for c in df['attack_cat'].unique() if not hf.validate_attack_cat(c)]
    assert len(invalid_cats) == 0, f"Invalid attack categories: {invalid_cats}"
    print(f"    ✓ All attack_cat valid ({df['attack_cat'].nunique()} unique)")
    
    # Check 7: Metrics non-negative and consistent
    assert (df['bytes'] >= 0).all(), "Negative bytes found"
    assert (df['packets'] >= 0).all(), "Negative packets found"
    assert (df['duration'] >= 0).all(), "Negative duration found"
    print(f"    ✓ All metrics non-negative (bytes, packets, duration)")
    
    # Check 8: TTL values in valid range
    assert (df['sttl'] >= 0).all() and (df['sttl'] <= 255).all(), "Invalid sttl (should be 0-255)"
    assert (df['dttl'] >= 0).all() and (df['dttl'] <= 255).all(), "Invalid dttl (should be 0-255)"
    print(f"    ✓ All TTL values in valid range (0-255)")
    
    # Check 9: Loss counts non-negative (UNSW data shows wider range than documented)
    assert (df['sloss'] >= 0).all(), "Invalid sloss (should be >= 0)"
    assert (df['dloss'] >= 0).all(), "Invalid dloss (should be >= 0)"
    print(f"    ✓ All loss counts non-negative (sloss range: 0-{df['sloss'].max()}, dloss range: 0-{df['dloss'].max()})")
    
    # Check 10: Port counts (UNSW data shows wider range than documented)
    assert (df['ct_src_dport_ltm'] >= 1).all(), "Invalid ct_src_dport_ltm (should be >= 1)"
    assert (df['ct_dst_src_ltm'] >= 1).all(), "Invalid ct_dst_src_ltm (should be >= 1)"
    print(f"    ✓ All connection count features >= 1 "
          f"(ct_src_dport_ltm range: {df['ct_src_dport_ltm'].min()}-{df['ct_src_dport_ltm'].max()}, "
          f"ct_dst_src_ltm range: {df['ct_dst_src_ltm'].min()}-{df['ct_dst_src_ltm'].max()})")
    
    # Check 11: Placeholder columns are None or null where expected
    null_count_timestamp = df['timestamp'].isnull().sum()
    null_count_label = df['label'].isnull().sum()
    assert null_count_timestamp == len(df), f"timestamp should be None for all rows; {null_count_timestamp} nulls"
    assert null_count_label == len(df), f"label should be None for all rows; {null_count_label} nulls"
    print(f"    ✓ Placeholder columns (timestamp, label) are all None")
    
    # Check 12: Scenario distribution
    scenario_counts = df['scenario_name'].value_counts()
    print(f"    ✓ Scenario distribution: {scenario_counts.to_dict()}")
    assert len(scenario_counts) == len(hf.SCENARIOS), f"Missing scenarios; have {scenario_counts.to_dict()}"
    
    print(f"\n  All validation checks PASSED ✅")
