#!/usr/bin/env python3
"""Fetch spec source documents from manifest.json."""

import json
import os
import sys
import urllib.request

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
MANIFEST_PATH = os.path.join(SCRIPT_DIR, "manifest.json")


def main():
    with open(MANIFEST_PATH) as f:
        manifest = json.load(f)

    fetched = 0
    skipped = 0
    failed = 0

    for source in manifest["sources"]:
        filename = source["filename"]
        url = source["url"]
        path = os.path.join(SCRIPT_DIR, filename)

        if os.path.exists(path):
            print(f"  skip {filename} (cached)")
            skipped += 1
            continue

        print(f"  fetch {filename} <- {url}")
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "Mozilla/5.0 (spec-source-fetch)"}
            )
            with urllib.request.urlopen(req) as r, open(path, "wb") as out:
                out.write(r.read())
            fetched += 1
        except Exception as e:
            print(f"  ERROR: {e}", file=sys.stderr)
            failed += 1

    print(f"\nDone: {fetched} fetched, {skipped} cached, {failed} failed")
    return 1 if failed > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
