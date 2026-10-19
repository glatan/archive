#!/usr/bin/env python3
"""Print archive features other than `default` and `std`, comma-separated.

The list is the package's own features. Merging every workspace member
would pass archive-cli's `json` feature to the archive crate.
"""

import json
import subprocess
import sys


def main() -> None:
    raw = subprocess.check_output(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        text=True,
    )
    metadata = json.loads(raw)
    for package in metadata["packages"]:
        if package["name"] != "archive":
            continue
        names = sorted(
            name for name in package["features"] if name not in ("default", "std")
        )
        sys.stdout.write(",".join(names))
        return
    sys.stderr.write("archive package not found in cargo metadata\n")
    sys.exit(1)


if __name__ == "__main__":
    main()
