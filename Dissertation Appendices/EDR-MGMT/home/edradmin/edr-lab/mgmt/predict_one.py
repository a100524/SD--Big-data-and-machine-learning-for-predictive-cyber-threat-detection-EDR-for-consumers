#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
import joblib
import pandas as pd
# Convert the strongest feature contribution into a short explanation.
def feature_phrase(name: str) -> str:
    """Convert the strongest feature contribution into a short explanation."""
    mapping = {
        "sysmon_process_create_count": "process launches",
        "sysmon_unique_process_image_count": "distinct executable images",
        "sysmon_powershell_process_count": "PowerShell launches",
        "sysmon_cmd_process_count": "command-shell launches",
        "sysmon_unique_parent_child_pair_count": "distinct parent-child process relationships",
        "sysmon_network_connect_count": "network connections",
        "sysmon_unique_destination_count": "distinct network destinations",
        "sysmon_dns_query_count": "DNS queries",
        "sysmon_file_create_count": "file creations",
        "sysmon_file_delete_count": "file deletions",
        "sysmon_registry_event_count": "registry changes",
        "osquery_process_count_delta": "change in active process count",
    }
    return mapping.get(name, name.replace("_", " "))
# Parse command-line arguments and execute the file workflow.
def main() -> int:
    """Load one deployment bundle and feature vector, then write a scored and explained decision."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--metadata", type=Path, required=True)
    parser.add_argument("--benign-reference", type=Path, required=True)
    parser.add_argument("--input-json", type=Path, required=True)
    parser.add_argument("--output-json", type=Path, required=True)
    args = parser.parse_args()
    metadata = json.loads(args.metadata.read_text(encoding="utf-8"))
    reference = json.loads(args.benign_reference.read_text(encoding="utf-8"))
    features = metadata["features"]
    threshold = float(metadata["threshold"])
    record = json.loads(args.input_json.read_text(encoding="utf-8-sig"))
    missing = [name for name in features if name not in record]
    if missing:
        raise SystemExit(f"Input is missing features: {missing}")
    model = joblib.load(args.model)
    frame = pd.DataFrame([{name: record[name] for name in features}], columns=features)
    score = float(model.predict_proba(frame)[:, 1][0])
    prediction = int(score >= threshold)
    deviations = []
    for name in features:
        value = float(record[name])
        stats = reference.get("features", {}).get(name, {})
        mean = float(stats.get("mean", 0.0))
        std = float(stats.get("standard_deviation", 0.0))
        if std > 0:
            z = (value - mean) / std
        else:
            z = 0.0 if value == mean else (999.0 if value > mean else -999.0)
        deviations.append({"feature": name, "value": value, "benign_mean": mean, "benign_standard_deviation": std, "z_score": z, "absolute_z_score": abs(z)})
    ranked = sorted(deviations, key=lambda item: item["absolute_z_score"], reverse=True)[:3]
    phrases = [feature_phrase(item["feature"]) for item in ranked]
    if prediction:
        summary = "The model threshold was exceeded. The largest deviations from benign training windows involved " + ", ".join(phrases) + "."
        recommended = "Review the recorded processes, generated files, registry changes, and internal connections before any response action."
    else:
        summary = "The model threshold was not exceeded. The largest measured deviations involved " + ", ".join(phrases) + "."
        recommended = "Retain the event record for audit; no automated response is justified by this score alone."
    explanation = {
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "protocol_id": metadata.get("protocol_id"),
        "score": score,
        "threshold": threshold,
        "prediction": prediction,
        "top_benign_reference_deviations": ranked,
        "plain_language_summary": summary,
        "recommended_safe_action": recommended,
        "warning": "This is a controlled laboratory classification. It does not establish that malware caused the events.",
    }
    args.output_json.parent.mkdir(parents=True, exist_ok=True)
    args.output_json.write_text(json.dumps(explanation, indent=2), encoding="utf-8")
    print(json.dumps(explanation, indent=2))
    return 0
# Run the command-line entry point only when this file is executed directly.
if __name__ == "__main__":
    raise SystemExit(main())
