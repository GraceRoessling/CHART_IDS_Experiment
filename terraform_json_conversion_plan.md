# Terraform JSON Conversion Plan for Network Topology

## Purpose
This document defines a structured plan for converting an existing simulation-oriented JSON (e.g., `global_constraints.json`) into a Terraform-compliant JSON configuration. It is designed to guide an LLM in systematically transforming the input into valid Terraform syntax.

---

## Core Principle

**Separate concerns clearly:**
- KEEP: Infrastructure-relevant topology (subnets, hosts, routing intent)
- REMOVE: Simulation logic, IDS constraints, temporal/event-generation rules
- TRANSFORM: Abstract topology → concrete Terraform resources

---

## Step 1: Remove Non-Terraform Sections

Delete the following top-level fields entirely:

- `label_distribution`
- `unsw_grounding_principles`
- `tiered_synthesis_framework`
- `false_alarm_taxonomy`
- `temporal_architecture_principles`
- `validation_checkpoints`
- `output_schema`
- `unsw_dataset_reference`

These are not compatible with Terraform and belong to simulation or data pipelines.

---

## Step 2: Extract Network Topology

From the input JSON, retain only:

- `network_topology.subnets`
- `network_topology.routing_constraints`

Ignore all descriptive text fields except where needed for naming.

---

## Step 3: Introduce Terraform Top-Level Structure

Create the following required top-level blocks:

```json
{
  "terraform": {},
  "provider": {},
  "resource": {},
  "variable": {},
  "locals": {},
  "output": {}
}
```

At minimum, `terraform`, `provider`, and `resource` must be populated.

---

## Step 4: Add Provider Configuration

Insert a provider block (default to AWS unless specified otherwise):

```json
"provider": {
  "aws": {
    "region": "us-east-1"
  }
}
```

---

## Step 5: Create VPC Resource

Define a base VPC (required for subnet placement):

```json
"resource": {
  "aws_vpc": {
    "main": {
      "cidr_block": "10.0.0.0/16"
    }
  }
}
```

---

## Step 6: Convert Subnets

For each subnet in `network_topology.subnets`:

### Required Transformations:

1. Assign a CIDR block (deterministic mapping):
   - subnet_1 → 10.0.1.0/24
   - subnet_2 → 10.0.2.0/24
   - subnet_3 → 10.0.3.0/24

2. Create Terraform resource:

```json
"aws_subnet": {
  "subnet_name": {
    "vpc_id": "${aws_vpc.main.id}",
    "cidr_block": "<assigned_cidr>"
  }
}
```

---

## Step 7: Convert Hosts to Instances

For each host in each subnet:

### Transformation Rules:

- Normalize name: lowercase
- Replace invalid characters if needed
- Map to `aws_instance`

### Example:

```json
"aws_instance": {
  "user0": {
    "ami": "ami-123456",
    "instance_type": "t2.micro",
    "subnet_id": "${aws_subnet.subnet_user.id}"
  }
}
```

### Notes:
- AMI can be placeholder
- Instance type can default to `t2.micro`

---

## Step 8: Encode Routing Constraints

Convert routing rules into one or more of:

- `aws_route_table`
- `aws_route`
- `aws_security_group`

### Heuristic Mapping:

| Constraint Type | Terraform Representation |
|----------------|--------------------------|
| Gateway node | Route table + route |
| Restricted access | Security group rules |
| No direct subnet connection | Omit routes between subnets |

### Example (security group):

```json
"aws_security_group": {
  "allow_internal": {
    "ingress": [{
      "from_port": 0,
      "to_port": 0,
      "protocol": "-1",
      "cidr_blocks": ["10.0.0.0/16"]
    }]
  }
}
```

---

## Step 9: Introduce Variables (Optional but Recommended)

Move reusable values into variables:

- subnet CIDRs
- instance types
- AMI IDs

```json
"variable": {
  "instance_type": {
    "default": "t2.micro"
  }
}
```

---

## Step 10: Introduce Locals (Optional)

Use locals to store structured topology mappings:

```json
"locals": {
  "subnet_map": {
    "user": "10.0.1.0/24",
    "enterprise": "10.0.2.0/24"
  }
}
```

---

## Step 11: Add Outputs (Optional)

Expose useful values:

```json
"output": {
  "vpc_id": {
    "value": "${aws_vpc.main.id}"
  }
}
```

---

## Step 12: Validation Rules for Output JSON

The generated Terraform JSON must:

1. Contain valid top-level Terraform keys
2. Use only supported Terraform resource types
3. Ensure all references use interpolation syntax:
   - `${resource_type.name.attribute}`
4. Ensure no leftover simulation-only fields remain
5. Ensure all resources have required fields

---

## Step 13: Non-Goals (Explicitly Exclude)

Do NOT attempt to encode:

- IDS logic
- Event sequencing
- Temporal constraints
- Statistical distributions
- Dataset references

These belong outside Terraform.

---

## Final Output Expectation

The LLM should output:

- A single valid Terraform JSON file
- Fully self-contained
- Ready to run with `terraform init` and `terraform plan`

---

## Optional Extension (Advanced)

If desired, the LLM may also:

- Tag instances with roles (user, enterprise, operational)
- Add security group segmentation between subnets
- Introduce NAT gateways or internet gateways

---

## Summary

Transformation pipeline:

1. Strip simulation logic
2. Extract topology
3. Add Terraform structure
4. Map subnets → aws_subnet
5. Map hosts → aws_instance
6. Encode routing → networking resources
7. Validate Terraform compliance

---

End of specification.

