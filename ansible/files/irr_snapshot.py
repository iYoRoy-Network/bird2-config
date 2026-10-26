#!/usr/bin/env python3
"""Resolve public IRR AS-SETs into an explicit, reviewable JSON snapshot."""

import argparse
import json
from pathlib import Path
import subprocess


def resolve(queries):
    sets = {}
    for name, query in sorted(queries.items()):
        command = ["bgpq4", "-j", "-t", "-l", "asns"]
        if "::" in query:
            source, query = query.split("::", 1)
            command += ["-S", source]
        output = subprocess.run(command + [query], check=True, capture_output=True, text=True, timeout=60)
        values = json.loads(output.stdout)["asns"]
        if not values or any(type(asn) is not int or not 1 <= asn <= 4294967295 for asn in values):
            raise ValueError("Invalid/empty IRR response for " + name)
        sets[name] = sorted(set(values))
    return {"queries": queries, "sets": sets}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--queries", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    snapshot = resolve(json.loads(Path(args.queries).read_text()))
    target = Path(args.output)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix(".json.tmp")
    temporary.write_text(json.dumps(snapshot, indent=2, sort_keys=True) + "\n")
    temporary.replace(target)


if __name__ == "__main__":
    main()
