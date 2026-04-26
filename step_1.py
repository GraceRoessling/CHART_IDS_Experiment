"""
STEP 1: Structure and Validate Zero-Day Templates JSON

Objective:
    - Load zero_day_templates.json
    - Validate that all 5 scenarios have required fields with correct structure
    - Ensure JSON is well-formed and ready for Step 2
    - Generate validation report
    - Save validated templates

Inputs:
    - templates/zero_day_templates.json (5 scenarios with required fields)
    - templates/global_constraints.json (for cross-reference validation)

Outputs:
    - Validation report (console)
    - Updated templates/zero_day_templates.json (saved back)
"""

import json
from pathlib import Path
from helper_functions import (
    validate_all_templates,
    load_templates,
    save_templates,
    get_scenario_by_name,
    SCENARIOS
)


def validate_templates_step(templates_path, constraints_path, output_path=None):
    """
    Main Step 1 function: Load, validate, and save templates.
    
    Args:
        templates_path (str): Path to zero_day_templates.json
        constraints_path (str): Path to global_constraints.json (for reference)
        output_path (str, optional): Path to save validated templates. 
                                     If None, uses input templates_path
    
    Returns:
        dict: Validation result with 'success', 'total_scenarios', 'valid_scenarios', 
              'errors', 'warnings'
    """
    
    print("\n" + "="*70)
    print("STEP 1: VALIDATE ZERO-DAY TEMPLATES")
    print("="*70)
    
    output_path = output_path or templates_path
    result = {
        'success': False,
        'total_scenarios': 0,
        'valid_scenarios': 0,
        'errors': [],
        'warnings': []
    }
    
    # ============================================================
    # LOAD TEMPLATES
    # ============================================================
    print("\n[1/4] Loading templates...")
    try:
        templates = load_templates(templates_path)
        print(f"  [OK] Loaded {templates_path}")
    except FileNotFoundError as e:
        result['errors'].append(str(e))
        print(f"  ✗ {e}")
        return result
    except ValueError as e:
        result['errors'].append(str(e))
        print(f"  ✗ {e}")
        return result
    
    # ============================================================
    # LOAD GLOBAL CONSTRAINTS (for reference)
    # ============================================================
    print("\n[2/4] Loading global constraints...")
    try:
        with open(constraints_path, 'r') as f:
            constraints = json.load(f)
        print(f"  [OK] Loaded {constraints_path}")
    except FileNotFoundError as e:
        result['warnings'].append(f"Global constraints file not found: {constraints_path}")
        print(f"  ⚠ Global constraints not available for cross-validation")
        constraints = None
    except json.JSONDecodeError as e:
        result['warnings'].append(f"Global constraints JSON malformed: {e}")
        print(f"  ⚠ Global constraints not available for cross-validation")
        constraints = None
    
    # ============================================================
    # VALIDATE TEMPLATE STRUCTURE
    # ============================================================
    print("\n[3/4] Validating template structure...")
    validation = validate_all_templates(templates)
    
    result['total_scenarios'] = validation['total_scenarios']
    result['valid_scenarios'] = validation['valid_scenarios']
    result['errors'].extend(validation['errors'])
    
    if validation['valid']:
        print(f"  [OK] All {validation['total_scenarios']} scenarios have valid structure")
    else:
        print(f"  ✗ Validation failed: {len(validation['errors'])} error(s)")
        for error in validation['errors']:
            print(f"    {error}")
    
    # ============================================================
    # CROSS-REFERENCE VALIDATION (if global_constraints available)
    # ============================================================
    if constraints:
        print("\n[3.5/4] Cross-referencing with global constraints...")
        
        # Check network topology references
        if 'network_topology' in constraints and 'subnets' in constraints['network_topology']:
            constraint_subnets = set()
            for subnet_key, subnet_data in constraints['network_topology']['subnets'].items():
                if 'name' in subnet_data:
                    constraint_subnets.add(subnet_data['name'])
            
            # Expected subnets
            expected_subnets = {
                'Subnet 1 (User)',
                'Subnet 2 (Enterprise)',
                'Subnet 3 (Operational)',
                'External'
            }
            
            # Verify each scenario references valid entry/target subnets
            for scenario in templates.get('scenarios', []):
                scenario_name = scenario.get('scenario_name', 'Unknown')
                
                # Handle null entry_point/target_asset (for No_Attack scenario)
                entry_point = scenario.get('entry_point')
                target_asset = scenario.get('target_asset')
                entry_subnet = entry_point.get('subnet') if entry_point else None
                target_subnet = target_asset.get('subnet') if target_asset else None
                
                if entry_subnet and entry_subnet not in expected_subnets:
                    result['warnings'].append(
                        f"{scenario_name}: entry_point subnet '{entry_subnet}' may be invalid"
                    )
                
                if target_subnet and target_subnet not in expected_subnets:
                    result['warnings'].append(
                        f"{scenario_name}: target_asset subnet '{target_subnet}' may be invalid"
                    )
        
        # Check feature_constraints are null (to be filled in Step 2)
        for scenario in templates.get('scenarios', []):
            scenario_name = scenario.get('scenario_name', 'Unknown')
            fc = scenario.get('feature_constraints', {})
            
            # Warn if feature_constraints are already filled (should be done in Step 2)
            if fc.get('duration') is not None or fc.get('bytes') is not None:
                result['warnings'].append(
                    f"{scenario_name}: feature_constraints should be null (to be populated in Step 2)"
                )
    
    # ============================================================
    # SAVE VALIDATED TEMPLATES
    # ============================================================
    print("\n[4/4] Saving validated templates...")
    try:
        save_templates(templates, output_path)
        print(f"  [OK] Saved validated templates to {output_path}")
    except Exception as e:
        result['errors'].append(f"Failed to save templates: {e}")
        print(f"  ✗ {e}")
        return result
    
    # ============================================================
    # SUMMARY
    # ============================================================
    result['success'] = len(result['errors']) == 0
    
    print("\n" + "-"*70)
    print("STEP 1 VALIDATION SUMMARY")
    print("-"*70)
    print(f"Total Scenarios: {result['total_scenarios']}")
    print(f"Valid Scenarios: {result['valid_scenarios']}")
    print(f"Status: {'[PASS]' if result['success'] else '[FAIL]'}")
    
    if result['errors']:
        print(f"\nErrors ({len(result['errors'])}):")
        for error in result['errors']:
            print(f"  [ERROR] {error}")
    
    if result['warnings']:
        print(f"\nWarnings ({len(result['warnings'])}):")
        for warning in result['warnings']:
            print(f"  [WARN] {warning}")
    
    if result['success']:
        print("\n[OK] Templates validated successfully and ready for Step 2")
        print("   Next: Apply UNSW filtering and compute feature statistics")
    
    print("="*70 + "\n")
    
    return result


def get_scenario_templates(templates_path):
    """
    Utility: Load and return all scenario templates.
    
    Args:
        templates_path (str): Path to zero_day_templates.json
    
    Returns:
        dict: Parsed templates or None if load fails
    """
    try:
        return load_templates(templates_path)
    except Exception as e:
        print(f"Error loading templates: {e}")
        return None


if __name__ == "__main__":
    # Stand-alone execution for testing
    templates_path = Path("templates/zero_day_templates.json")
    constraints_path = Path("templates/global_constraints.json")
    
    result = validate_templates_step(
        str(templates_path),
        str(constraints_path)
    )
    
    # Exit with appropriate status
    exit(0 if result['success'] else 1)
