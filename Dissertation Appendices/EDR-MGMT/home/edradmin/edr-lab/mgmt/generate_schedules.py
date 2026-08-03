#!/usr/bin/env python3
from __future__ import annotations
import argparse
import csv
import random
from pathlib import Path
FAMILIES = {
    "B1": 0,
    "B2": 0,
    "B3": 0,
    "S1": 1,
    "S2": 1,
    "S3": 1,
}
# Construct one balanced formal-session schedule.
def build_session(session_number: int, seed: int) -> list[dict[str, object]]:
    """Construct one balanced formal-session schedule."""
    session_id = f"S{session_number:02d}"
    rows: list[dict[str, object]] = []
    for family_id, label in FAMILIES.items():
        variants = ["V1", "V2"]
        for index, variant in enumerate(variants, start=1):
            rows.append(
                {
                    "session_id": session_id,
                    "family_id": family_id,
                    "variant_id": variant,
                    "label": label,
                    "family_repetition": index,
                }
            )
    rng = random.Random(seed)
    rng.shuffle(rows)
    for sequence, row in enumerate(rows, start=1):
        row["sequence_number"] = sequence
        row["planned_run_id"] = (
            f"{session_id}-{sequence:03d}-{row['family_id']}-{row['variant_id']}"
        )
        row["planned_start_utc"] = ""
        row["status"] = "planned"
        row["actual_start_utc"] = ""
        row["actual_end_utc"] = ""
        row["exit_code"] = ""
        row["evidence_root"] = ""
        row["error_message"] = ""
        row["central_status"] = ""
        row["central_completed_utc"] = ""
        row["central_error"] = ""
    return rows
# Parse command-line arguments and execute the file workflow.
def main() -> int:
    """Create the three deterministic 12-row Formal session schedules."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--seeds", nargs=3, type=int, default=[4201, 4202, 4203])
    args = parser.parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    fields = [
        "sequence_number",
        "session_id",
        "planned_run_id",
        "family_id",
        "variant_id",
        "label",
        "family_repetition",
        "planned_start_utc",
        "status",
        "actual_start_utc",
        "actual_end_utc",
        "exit_code",
        "evidence_root",
        "error_message",
        "central_status",
        "central_completed_utc",
        "central_error",
    ]
    for session_number, seed in enumerate(args.seeds, start=1):
        rows = build_session(session_number, seed)
        output = args.output_dir / f"collection-schedule-session-{session_number:02d}.csv"
        with output.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fields)
            writer.writeheader()
            writer.writerows(rows)
        print(f"Wrote {output} with {len(rows)} runs using seed {seed}")
    return 0
# Run the command-line entry point only when this file is executed directly.
if __name__ == "__main__":
    raise SystemExit(main())
