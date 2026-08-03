#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
from pathlib import Path
import pandas as pd
COLUMNS = [
    "cpu_load_percent",
    "memory_used_mb",
    "disk_bytes_per_sec",
    "network_bytes_per_sec",
    "free_system_disk_mb",
    "monitored_process_cpu_percent",
    "monitored_process_working_set_mb",
]
# Parse an input timestamp as UTC.
def parse_utc(value: str) -> pd.Timestamp:
    """Parse an input timestamp as UTC."""
    return pd.to_datetime(value, utc=True)
# Calculate descriptive statistics for one numeric series.
def describe_numeric(frame: pd.DataFrame, prefix: str = "") -> dict[str, float]:
    """Calculate descriptive statistics for one numeric series."""
    result: dict[str, float] = {}
    for column in COLUMNS:
        if column not in frame:
            continue
        numeric = pd.to_numeric(frame[column], errors="coerce")
        result[f"{prefix}{column}_median"] = float(numeric.median())
        result[f"{prefix}{column}_iqr"] = float(numeric.quantile(0.75) - numeric.quantile(0.25))
        result[f"{prefix}{column}_maximum"] = float(numeric.max())
    return result
# Parse command-line arguments and execute the file workflow.
def main() -> int:
    """Join resource measurements to run metadata and write all declared grouped summaries."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-root", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--mode", choices=["Pilot", "Formal", "Validation"], default="Formal")
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    rows = []
    phase_rows = []
    for run_dir in sorted(path for path in args.evidence_root.iterdir() if path.is_dir()):
        csv_path = run_dir / "resource-samples.csv"
        start_path = run_dir / "manifest-start.json"
        complete_path = run_dir / "manifest-complete.json"
        validation_path = run_dir / "run-validation-report.json"
        if not all(path.exists() for path in (csv_path, start_path, complete_path, validation_path)):
            continue
        validation = json.loads(validation_path.read_text(encoding="utf-8-sig"))
        if not validation.get("passed", False):
            continue
        start_manifest = json.loads(start_path.read_text(encoding="utf-8-sig"))
        complete_manifest = json.loads(complete_path.read_text(encoding="utf-8-sig"))
        if start_manifest.get("mode") != args.mode:
            continue
        frame = pd.read_csv(csv_path)
        if frame.empty:
            continue
        frame["timestamp_utc"] = pd.to_datetime(frame["timestamp_utc"], utc=True, errors="coerce")
        scenario_start = parse_utc(start_manifest["scenario_start_utc"])
        scenario_end = parse_utc(start_manifest["planned_scenario_end_utc"])
        collection_end = parse_utc(complete_manifest["collection_end_utc"])
        frame["phase"] = "baseline"
        frame.loc[(frame["timestamp_utc"] >= scenario_start) & (frame["timestamp_utc"] < scenario_end), "phase"] = "active"
        frame.loc[(frame["timestamp_utc"] >= scenario_end) & (frame["timestamp_utc"] <= collection_end), "phase"] = "grace"
        row = {
            "run_id": run_dir.name,
            "session_id": start_manifest.get("session_id"),
            "family_id": start_manifest.get("family_id"),
            "variant_id": start_manifest.get("variant_id"),
            "label": start_manifest.get("label"),
            "mode": start_manifest.get("mode"),
            "sample_count": len(frame),
            "evidence_directory_bytes": sum(path.stat().st_size for path in run_dir.iterdir() if path.is_file()),
        }
        row.update(describe_numeric(frame))
        rows.append(row)
        for phase, phase_frame in frame.groupby("phase"):
            phase_row = {
                "run_id": run_dir.name,
                "session_id": start_manifest.get("session_id"),
                "family_id": start_manifest.get("family_id"),
                "variant_id": start_manifest.get("variant_id"),
                "label": start_manifest.get("label"),
                "phase": phase,
                "sample_count": len(phase_frame),
            }
            phase_row.update(describe_numeric(phase_frame))
            phase_rows.append(phase_row)
    output = pd.DataFrame(rows)
    phases = pd.DataFrame(phase_rows)
    output.to_csv(args.output_dir / f"resource-summary-by-run-{args.mode.lower()}.csv", index=False)
    phases.to_csv(args.output_dir / f"resource-summary-by-run-phase-{args.mode.lower()}.csv", index=False)
    if not output.empty:
        output.groupby(["family_id", "label"], as_index=False).median(numeric_only=True).to_csv(
            args.output_dir / f"resource-summary-by-family-{args.mode.lower()}.csv", index=False
        )
        output.groupby(["session_id"], as_index=False).median(numeric_only=True).to_csv(
            args.output_dir / f"resource-summary-by-session-{args.mode.lower()}.csv", index=False
        )
    if not phases.empty:
        phases.groupby(["phase", "label"], as_index=False).median(numeric_only=True).to_csv(
            args.output_dir / f"resource-summary-by-phase-class-{args.mode.lower()}.csv", index=False
        )
    print(f"Summarised {len(output)} validated {args.mode} runs")
    return 0
# Run the command-line entry point only when this file is executed directly.
if __name__ == "__main__":
    raise SystemExit(main())
