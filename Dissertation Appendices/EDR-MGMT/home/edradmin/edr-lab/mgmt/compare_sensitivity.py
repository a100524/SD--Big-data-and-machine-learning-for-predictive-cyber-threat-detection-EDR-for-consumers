#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
from pathlib import Path
import pandas as pd
# Load one sensitivity result set and attach its label.
def load(path: Path, label: str) -> pd.DataFrame:
    """Load one sensitivity result set and attach its label."""
    records = json.loads(path.read_text(encoding="utf-8"))
    rows = []
    for record in records:
        if record.get("feature_set") not in {"telemetry_only", "hybrid"}:
            continue
        rows.append(
            {
                "window_design": label,
                "design": record.get("design"),
                "feature_set": record.get("feature_set"),
                "model": record.get("model"),
                "run_mcc": record.get("run_metrics_max", {}).get("mcc"),
                "run_recall": record.get("run_metrics_max", {}).get("recall"),
                "run_fpr": record.get("run_metrics_max", {}).get("false_positive_rate"),
                "window_false_alerts_per_benign_hour": record.get("window_metrics", {}).get(
                    "false_alerts_per_benign_hour"
                ),
            }
        )
    return pd.DataFrame(rows)
# Parse command-line arguments and execute the file workflow.
def main() -> int:
    """Load both sensitivity result sets and write the selected metric comparison table."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--results-30s", type=Path, required=True)
    parser.add_argument("--results-60s", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    output = pd.concat([load(args.results_30s, "30s"), load(args.results_60s, "60s")], ignore_index=True)
    output.to_csv(args.output, index=False)
    print(f"Wrote {args.output}")
    return 0
# Run the command-line entry point only when this file is executed directly.
if __name__ == "__main__":
    raise SystemExit(main())
