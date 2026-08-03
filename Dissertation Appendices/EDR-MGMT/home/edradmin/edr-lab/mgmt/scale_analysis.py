#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
import math
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
import pandas as pd
import psutil
# Calculate the total byte size of a directory tree.
def directory_bytes(path: Path) -> int:
    """Calculate the total byte size of a directory tree."""
    return sum(item.stat().st_size for item in path.rglob("*") if item.is_file())
# Execute the dataset builder for one scale-test input size.
def run_builder(command: list[str]) -> tuple[int, float, int, str, str]:
    """Execute the dataset builder for one scale-test input size."""
    start = time.perf_counter()
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    peak_rss = 0
    ps_process = psutil.Process(process.pid)
    while process.poll() is None:
        try:
            rss = ps_process.memory_info().rss
            for child in ps_process.children(recursive=True):
                try:
                    rss += child.memory_info().rss
                except psutil.Error:
                    pass
            peak_rss = max(peak_rss, rss)
        except psutil.Error:
            pass
        time.sleep(0.1)
    stdout, stderr = process.communicate()
    return process.returncode, time.perf_counter() - start, peak_rss, stdout, stderr
# Parse command-line arguments and execute the file workflow.
def main() -> int:
    """Build each declared run subset, execute the dataset builder, and write scaling summaries."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--builder", type=Path, required=True)
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--mode", choices=["Pilot", "Formal", "Validation"], default="Formal")
    parser.add_argument("--window-seconds", type=int, default=30)
    parser.add_argument("--fractions", nargs="+", type=float, default=[0.25, 0.50, 0.75, 1.00])
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    run_dirs = sorted(path for path in args.evidence_root.iterdir() if path.is_dir())
    if not run_dirs:
        raise SystemExit("No run directories were found")
    rows = []
    for fraction in args.fractions:
        if not 0 < fraction <= 1:
            raise SystemExit("Fractions must be greater than 0 and no greater than 1")
        count = max(1, math.ceil(len(run_dirs) * fraction))
        selected = run_dirs[:count]
        subset_dir = args.output_dir / f"subset-{int(round(fraction * 100)):03d}pct"
        evidence_link_dir = subset_dir / "evidence"
        dataset_dir = subset_dir / "dataset"
        evidence_link_dir.mkdir(parents=True, exist_ok=True)
        dataset_dir.mkdir(parents=True, exist_ok=True)
        for run_dir in selected:
            link = evidence_link_dir / run_dir.name
            if not link.exists():
                os.symlink(run_dir.resolve(), link, target_is_directory=True)
        total_bytes = sum(directory_bytes(path) for path in selected)
        command = [
            sys.executable,
            str(args.builder),
            "--evidence-root",
            str(evidence_link_dir),
            "--output-dir",
            str(dataset_dir),
            "--window-seconds",
            str(args.window_seconds),
            "--include-mode",
            args.mode,
        ]
        exit_code, elapsed, peak_rss, stdout, stderr = run_builder(command)
        (subset_dir / "builder-stdout.txt").write_text(stdout, encoding="utf-8")
        (subset_dir / "builder-stderr.txt").write_text(stderr, encoding="utf-8")
        quality_files = list(dataset_dir.glob("dataset-quality-report-*.json"))
        quality = json.loads(quality_files[0].read_text(encoding="utf-8")) if quality_files else {}
        rows.append(
            {
                "fraction": fraction,
                "run_directories": count,
                "raw_evidence_bytes": total_bytes,
                "elapsed_seconds": elapsed,
                "peak_rss_bytes": peak_rss,
                "exit_code": exit_code,
                "valid_runs": quality.get("valid_runs"),
                "dataset_rows": quality.get("rows"),
                "rows_per_second": (quality.get("rows", 0) / elapsed) if elapsed > 0 else None,
                "megabytes_per_second": (total_bytes / 1024 / 1024 / elapsed) if elapsed > 0 else None,
            }
        )
        if exit_code != 0:
            raise SystemExit(f"Dataset builder failed for fraction {fraction}. Review {subset_dir}")
    frame = pd.DataFrame(rows)
    frame.to_csv(args.output_dir / "scale-analysis.csv", index=False)
    (args.output_dir / "scale-analysis.json").write_text(json.dumps(rows, indent=2), encoding="utf-8")
    print(frame.to_string(index=False))
    return 0
# Run the command-line entry point only when this file is executed directly.
if __name__ == "__main__":
    raise SystemExit(main())
