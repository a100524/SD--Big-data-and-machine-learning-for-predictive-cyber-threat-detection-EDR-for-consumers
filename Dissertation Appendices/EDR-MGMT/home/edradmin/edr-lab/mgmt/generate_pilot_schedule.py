#!/usr/bin/env python3
from __future__ import annotations
import argparse
import csv
import random
from pathlib import Path
FAMILIES = {"B1": 0, "B2": 0, "B3": 0, "S1": 1, "S2": 1, "S3": 1}
# Parse command-line arguments and execute the file workflow.
def main() -> int:
    """Create and write the deterministic 30-row Pilot schedule."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=4100)
    args = parser.parse_args()
    rows = []
    for family, label in FAMILIES.items():
        for repetition, variant in enumerate(["V1", "V2", "V1", "V2", "V1"], start=1):
            rows.append(
                {
                    "session_id": "PILOT",
                    "family_id": family,
                    "variant_id": variant,
                    "label": label,
                    "family_repetition": repetition,
                }
            )
    random.Random(args.seed).shuffle(rows)
    for sequence, row in enumerate(rows, start=1):
        row["sequence_number"] = sequence
        row["planned_run_id"] = f"PILOT-{sequence:03d}-{row['family_id']}-{row['variant_id']}"
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
    args.output.parent.mkdir(parents=True, exist_ok=True)
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
    with args.output.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {args.output} with {len(rows)} pilot runs using seed {args.seed}")
    return 0
# Run the command-line entry point only when this file is executed directly.
if __name__ == "__main__":
    raise SystemExit(main())
