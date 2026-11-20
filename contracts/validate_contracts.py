import json
import re
import os
import sys

def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def validate_payload(payload, schema):
    errors = []
    
    # 1. additionalProperties false check at root
    schema_props = set(schema.get("properties", {}).keys())
    for k in payload.keys():
        if k not in schema_props:
            errors.append(f"Root object has unpermitted property: '{k}'")
            
    # 2. Required fields
    for req in schema.get("required", []):
        if req not in payload:
            errors.append(f"Missing required field: '{req}'")

    # 3. Pattern / type checks
    patterns = {
        "payload_id": schema["properties"]["payload_id"]["pattern"],
        "tenant_id": schema["properties"]["tenant_id"]["pattern"],
        "collector_id": schema["properties"]["collector_id"]["pattern"],
        "prev_hash": schema["properties"]["prev_hash"]["pattern"],
        "signature": schema["properties"]["signature"]["pattern"]
    }
    for field, pat in patterns.items():
        val = payload.get(field)
        if isinstance(val, str):
            if not re.match(pat, val):
                errors.append(f"Field '{field}' value '{val}' does not match pattern {pat}")
                
    # 4. Enums
    metric_names = schema["properties"]["metrics"]["items"]["properties"]["name"]["enum"]
    for i, m in enumerate(payload.get("metrics", [])):
        for k in m.keys():
            if k not in schema["properties"]["metrics"]["items"]["properties"]:
                errors.append(f"Metric[{i}] has unexpected field: '{k}'")
        if m.get("name") not in metric_names:
            errors.append(f"Metric[{i}] name '{m.get('name')}' is not in allowed enum")
            
    log_sevs = schema["properties"]["log_fingerprints"]["items"]["properties"]["sev"]["enum"]
    for i, lf in enumerate(payload.get("log_fingerprints", [])):
        for k in lf.keys():
            if k not in schema["properties"]["log_fingerprints"]["items"]["properties"]:
                errors.append(f"log_fingerprints[{i}] has unexpected field: '{k}'")
        if lf.get("sev") not in log_sevs:
            errors.append(f"log_fingerprints[{i}] sev '{lf.get('sev')}' not in allowed enum")
            
    health_states = schema["properties"]["health"]["properties"]["state"]["enum"]
    health_reasons = schema["properties"]["health"]["properties"]["reason_codes"]["items"]["enum"]
    health = payload.get("health", {})
    if health.get("state") not in health_states:
        errors.append(f"health.state '{health.get('state')}' not in allowed enum")
    for rc in health.get("reason_codes", []):
        if rc not in health_reasons:
            errors.append(f"health.reason_code '{rc}' not in allowed enum")

    return errors

def main():
    root_dir = os.path.dirname(os.path.abspath(__file__))
    schema_path = os.path.join(root_dir, "payload.schema.json")
    schema = load_json(schema_path)
    samples_dir = os.path.join(root_dir, "samples")
    
    print("=== Testing VeilOps Wire Schema (Contracts Verification) ===")
    
    # Test valid payloads
    valid_files = [f for f in os.listdir(samples_dir) if f.startswith("valid_")]
    all_passed = True
    for vf in sorted(valid_files):
        path = os.path.join(samples_dir, vf)
        data = load_json(path)
        errs = validate_payload(data, schema)
        if not errs:
            print(f" [PASS] {vf} is valid as expected.")
        else:
            print(f" [FAIL] {vf} failed validation: {errs}")
            all_passed = False

    # Test rejected payloads
    rejected_files = [f for f in os.listdir(samples_dir) if f.startswith("rejected_")]
    for rf in sorted(rejected_files):
        path = os.path.join(samples_dir, rf)
        data = load_json(path)
        errs = validate_payload(data, schema)
        if errs:
            print(f" [PASS] {rf} was correctly REJECTED with: {errs[0]}")
        else:
            print(f" [FAIL] {rf} was unexpectedly ACCEPTED!")
            all_passed = False
            
    if all_passed:
        print("\nAll schema contract tests PASSED successfully!")
        return 0
    else:
        print("\nSome schema tests FAILED!")
        return 1

if __name__ == "__main__":
    sys.exit(main())
