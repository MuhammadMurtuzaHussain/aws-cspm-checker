#!/usr/bin/env python3
"""A stand-in `aws` executable that answers from fixtures/demo-account.json.

Lets the tests exercise the real subprocess path (AwsRunner, error parsing, the bash wrapper)
without credentials.
"""
import json
import sys
from pathlib import Path

data = json.loads((Path(__file__).resolve().parent.parent / "fixtures" / "demo-account.json").read_text())
args = sys.argv[1:]
region = None
clean = []
i = 0
while i < len(args):
    a = args[i]
    if a in ("--region", "--profile", "--output", "--query"):
        if a == "--region":
            region = args[i + 1]
        i += 2
        continue
    if a == "--no-cli-pager":
        i += 1
        continue
    clean.append(a)
    i += 1

if "--query" in args and "text" in args:  # wrapper's preflight identity call
    print("123456789012\tarn:aws:iam::123456789012:user/demo-auditor")
    sys.exit(0)

key = f"{region or '*'}|{' '.join(clean)}"
if key not in data["responses"] and region:  # global calls may arrive with a region attached
    key = f"*|{' '.join(clean)}"
value = data["responses"].get(key, {"__error__": "AccessDenied"})
if isinstance(value, dict) and "__error__" in value:
    print(f"An error occurred ({value['__error__']}) when calling the {clean[1]} operation: fake",
          file=sys.stderr)
    sys.exit(254)
print(json.dumps(value))
