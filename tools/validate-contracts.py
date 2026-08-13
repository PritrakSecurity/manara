#!/usr/bin/env python3
"""Validate the frozen data contracts in docs/contracts against their
example fixtures. Exits non-zero on any failure.

Usage:
    python tools/validate-contracts.py

Requires: pip install jsonschema
"""
import json
import sys
from pathlib import Path

import jsonschema

ROOT = Path(__file__).resolve().parents[1]
CONTRACTS = ROOT / "docs" / "contracts"
EXAMPLES = CONTRACTS / "examples"


def load(path: Path):
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


CASES = [
    # (schema file, example files that MUST validate)
    ("enrollment.schema.json", ["enrollment-request.json", "enrollment-response.json"]),
    ("heartbeat.schema.json", ["heartbeat-request.json", "heartbeat-response.json"]),
    ("event.schema.json", ["event-request.json", "event-response.json"]),
    ("policy-bundle.schema.json", ["policy-bundle.json"]),
]

# Negative sanity checks: instances that MUST FAIL validation.
NEGATIVE = [
    ("heartbeat.schema.json", {"enforcement_mode": "BLOCK_EVERYTHING"}),
    ("enrollment.schema.json", {"enrollment_token": "pk_enr_short", "agent_version": "1.0.0"}),
    ("event.schema.json", {"events": [{"action": "NOT_AN_ACTION"}]}),
    ("policy-bundle.schema.json", {"bundle_version": 1, "enforcement_mode": "MONITOR_ONLY"}),
]


def main():
    failures = 0

    for schema_name, example_names in CASES:
        schema = load(CONTRACTS / schema_name)
        for example_name in example_names:
            instance = load(EXAMPLES / example_name)
            try:
                jsonschema.validate(instance, schema)
            except jsonschema.ValidationError as exc:
                failures += 1
                print(f"[FAIL] {schema_name} rejects {example_name}: {exc.message}")
            else:
                print(f"[ OK ] {schema_name} accepts {example_name}")

    for schema_name, instance in NEGATIVE:
        schema = load(CONTRACTS / schema_name)
        try:
            jsonschema.validate(instance, schema)
        except jsonschema.ValidationError:
            print(f"[ OK ] {schema_name} rejects invalid instance")
        else:
            failures += 1
            print(f"[FAIL] {schema_name} ACCEPTED an invalid instance")

    if failures:
        print(f"\n{len(CASES)} contract(s) validated. FAILURES: {failures}", file=sys.stderr)
        return 1

    print(f"\nAll {len(CASES)} contract(s) validated against Section 3 examples.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
