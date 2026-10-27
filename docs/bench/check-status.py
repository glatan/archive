#!/usr/bin/env python3
"""Inspect a benchmark result.json and reject failed or partial cases.

This is a local guard for full-reference runs. It is intentionally not
wired into CI; pass --allow-partial when some reference tools are known
to be absent.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("result", type=Path, help="result.json from the compare bench")
    parser.add_argument(
        "--allow-partial",
        action="store_true",
        help="treat partial as acceptable (for example when refs are not installed)",
    )
    args = parser.parse_args()

    try:
        payload = json.loads(args.result.read_text())
    except (OSError, json.JSONDecodeError) as error:
        print(f"error: cannot read {args.result}: {error}", file=sys.stderr)
        return 2

    results = payload.get("results")
    if not isinstance(results, list) or not results:
        print(f"error: {args.result} has no results", file=sys.stderr)
        return 2

    counts = Counter(result.get("status", "unknown") for result in results)
    print(f"cases: {len(results)}")
    for status in ("measured", "partial", "ours-only", "failed", "unavailable"):
        if counts[status]:
            print(f"  {status}: {counts[status]}")

    known = {"measured", "partial", "ours-only", "failed", "unavailable"}
    failures = [result for result in results if result.get("status") == "failed"]
    partials = [result for result in results if result.get("status") == "partial"]
    unavailable = [result for result in results if result.get("status") == "unavailable"]
    unexpected = [result for result in results if result.get("status") not in known]

    for label, rows in (
        ("failed", failures),
        ("partial", partials),
        ("unavailable", unavailable),
        ("unexpected", unexpected),
    ):
        if not rows or (label == "partial" and args.allow_partial):
            continue
        print(f"\n{label} cases:", file=sys.stderr)
        for result in rows:
            print(f"  {result.get('case')}", file=sys.stderr)
            for op in ("encode", "decode"):
                value = result.get(op)
                if not value:
                    continue
                note = value.get("note")
                if note:
                    print(f"    {op}: {note}", file=sys.stderr)

    if failures or unavailable or unexpected or (partials and not args.allow_partial):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
