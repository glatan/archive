#!/usr/bin/env python3
"""Run the feature-matrix clippy checks on the host.

Each invocation uses its own CARGO_TARGET_DIR. Cargo locks one target
directory, so sharing it would serialize the matrix. The job count
defaults to min(cpu count, 4); set CHECK_FEATURES_JOBS to override.
"""

import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path


def feature_list() -> list[str]:
    script = Path(__file__).with_name("archive-features.py")
    raw = subprocess.check_output([sys.executable, str(script)], text=True)
    return [name for name in raw.strip().split(",") if name]


def jobs(features: list[str]) -> list[tuple[str, list[str]]]:
    clippy = ["cargo", "clippy", "--lib"]
    deny = ["--", "-D", "warnings"]
    planned: list[tuple[str, list[str]]] = [
        ("no-default-features", clippy + ["--no-default-features", *deny]),
    ]
    for name in features:
        planned.append(
            (
                name,
                clippy + ["--no-default-features", "--features", name, *deny],
            )
        )
    planned.append(
        (
            "all-except-std",
            clippy
            + ["--no-default-features", "--features", ",".join(features), *deny],
        )
    )
    planned.append(("default", clippy + deny))
    planned.append(
        (
            "archive-cli",
            ["cargo", "clippy", "-p", "archive-cli", *deny],
        )
    )
    return planned


def run_one(index: int, label: str, command: list[str], root: Path) -> tuple[str, int, str]:
    target = root / "target" / "check-features" / f"{index:03d}-{label}"
    env = os.environ.copy()
    env["CARGO_TARGET_DIR"] = str(target)
    result = subprocess.run(
        command,
        cwd=root,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    return label, result.returncode, result.stdout


def main() -> None:
    root = Path(__file__).resolve().parents[1]
    planned = jobs(feature_list())
    workers = int(os.environ.get("CHECK_FEATURES_JOBS") or min(os.cpu_count() or 1, 4))
    failures: list[tuple[str, str]] = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(run_one, index, label, command, root)
            for index, (label, command) in enumerate(planned)
        ]
        for future in as_completed(futures):
            label, code, output = future.result()
            if code == 0:
                print(f"ok {label}", flush=True)
                continue
            print(f"fail {label}", flush=True)
            failures.append((label, output))
    if failures:
        for label, output in failures:
            sys.stderr.write(f"\n===== {label} =====\n")
            sys.stderr.write(output)
        sys.stderr.write(f"\n{len(failures)} of {len(planned)} clippy jobs failed\n")
        sys.exit(1)
    print(f"{len(planned)} clippy jobs passed")


if __name__ == "__main__":
    main()
