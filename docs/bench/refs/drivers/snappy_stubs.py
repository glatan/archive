#!/usr/bin/env python3
"""Generate `snappy-stubs-public.h` from the upstream `.in` template.

The upstream tarball ships only the CMake template. The benchmark build
does not run CMake, so fill in the values used by Snappy 1.2.1.
"""

from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} SNAPPY_SOURCE_DIR", file=sys.stderr)
        return 2
    root = Path(sys.argv[1])
    source = root / "snappy-stubs-public.h.in"
    target = root / "snappy-stubs-public.h"
    text = source.read_text()
    text = text.replace("${HAVE_SYS_UIO_H_01}", "1")
    text = text.replace("${PROJECT_VERSION_MAJOR}", "1")
    text = text.replace("${PROJECT_VERSION_MINOR}", "2")
    text = text.replace("${PROJECT_VERSION_PATCH}", "1")
    target.write_text(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
