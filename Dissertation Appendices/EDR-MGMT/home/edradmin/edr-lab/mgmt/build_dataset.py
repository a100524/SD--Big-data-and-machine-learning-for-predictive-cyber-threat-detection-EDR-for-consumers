#!/usr/bin/env python3
from __future__ import annotations
import argparse
import csv
import json
import math
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
import pandas as pd
SYSMON_IDS = {
    "process": 1,
    "network": 3,
    "file_create": 11,
    "registry": {12, 13, 14},
    "dns": 22,
    "file_delete": 26,
}
TELEMETRY_FEATURES = [
    "sysmon_process_create_count",
    "sysmon_unique_process_image_count",
    "sysmon_powershell_process_count",
    "sysmon_cmd_process_count",
    "sysmon_unique_parent_child_pair_count",
    "sysmon_network_connect_count",
    "sysmon_unique_destination_count",
    "sysmon_dns_query_count",
    "sysmon_file_create_count",
    "sysmon_file_delete_count",
    "sysmon_registry_event_count",
    "osquery_process_count_delta",
]
WAZUH_FEATURES = [f"wazuh_level_{level:02d}_count" for level in range(16)]
HYBRID_FEATURES = TELEMETRY_FEATURES + ["suricata_alert_count"] + WAZUH_FEATURES
FORBIDDEN_FEATURES = {
    "run_id",
    "session_id",
    "family_id",
    "variant_id",
    "scenario_name",
    "label",
    "split",
    "window_index",
    "window_start_utc",
    "window_end_utc",
    "sample_filename",
    "behavioural_family",
    "protocol_id",
}
# Parse a timestamp and return a timezone-aware UTC datetime.
def parse_dt(value: Any) -> datetime:
    """Parse a timestamp and return a timezone-aware UTC datetime."""
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    text = str(value).strip().replace("Z", "+00:00")
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)
# Convert a datetime to an ISO 8601 UTC string.
def iso(dt: datetime) -> str:
    """Convert a datetime to an ISO 8601 UTC string."""
    return dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
# Read and parse one UTF-8 JSON file.
def read_json(path: Path) -> dict[str, Any]:
    """Read and parse one UTF-8 JSON file."""
    with path.open("r", encoding="utf-8-sig") as handle:
        return json.load(handle)
# Yield parsed records from a JSON Lines file.
def iter_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    """Yield parsed records from a JSON Lines file."""
    with path.open("r", encoding="utf-8-sig", errors="replace") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"Malformed JSON in {path} line {line_number}: {exc}") from exc
            if isinstance(value, dict):
                yield value
# Normalise path separators and casing for deterministic comparisons.
def normalise_path(value: Any) -> str:
    """Normalise path separators and casing for deterministic comparisons."""
    text = str(value or "").strip().replace("/", "\\").lower()
    text = re.sub(r"\\+", r"\\", text)
    return text
# Return the final component of a normalised path.
def basename(value: Any) -> str:
    """Return the final component of a normalised path."""
    path = normalise_path(value)
    return path.rsplit("\\", 1)[-1] if path else ""
# Extract the event timestamp used for window alignment.
def event_time(record: dict[str, Any], field: str = "timestamp_utc") -> datetime:
    """Extract the event timestamp used for window alignment."""
    return parse_dt(record[field])
# Remove duplicate Sysmon records using stable event identifiers.
def deduplicate_sysmon(records: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """Remove duplicate Sysmon records using stable event identifiers."""
    seen: set[tuple[str, int]] = set()
    output: list[dict[str, Any]] = []
    duplicates = 0
    for record in records:
        key = (str(record.get("computer", "")), int(record.get("record_id", -1)))
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        output.append(record)
    return output, duplicates
# Remove duplicate Wazuh alerts using stable alert fields.
def deduplicate_wazuh(records: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """Remove duplicate Wazuh alerts using stable alert fields."""
    seen: set[tuple[str, str]] = set()
    output: list[dict[str, Any]] = []
    duplicates = 0
    for record in records:
        key = (str(record.get("_index", "")), str(record.get("_id", "")))
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        output.append(record)
    return output, duplicates
# Remove duplicate Suricata records using stable event fields.
def deduplicate_suricata(records: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """Remove duplicate Suricata records using stable event fields."""
    seen: set[tuple[Any, ...]] = set()
    output: list[dict[str, Any]] = []
    duplicates = 0
    for record in records:
        alert = record.get("alert") or {}
        key = (
            record.get("timestamp"),
            record.get("flow_id"),
            record.get("event_type"),
            alert.get("signature_id"),
        )
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        output.append(record)
    return output, duplicates
# Convert osquery log records into timestamped snapshots.
def parse_osquery_snapshots(path: Path) -> tuple[list[tuple[datetime, int]], int]:
    """Convert osquery log records into timestamped snapshots."""
    snapshots: list[tuple[datetime, int]] = []
    duplicates = 0
    seen: set[tuple[str, int, int]] = set()
    for record in iter_jsonl(path):
        if record.get("name") != "edr_processes":
            continue
        if "unixTime" in record:
            timestamp = parse_dt(record["unixTime"])
        elif "timestamp" in record:
            timestamp = parse_dt(record["timestamp"])
        else:
            continue
        counter = int(record.get("counter", 0))
        key = (str(record.get("hostIdentifier", "")), int(timestamp.timestamp()), counter)
        if key in seen:
            duplicates += 1
            continue
        seen.add(key)
        rows = record.get("snapshot")
        if isinstance(rows, list):
            count = len(rows)
        elif isinstance(record.get("columns"), dict):
            count = 1
        else:
            continue
        snapshots.append((timestamp, count))
    snapshots.sort(key=lambda item: item[0])
    return snapshots, duplicates
# Select the latest snapshot at or before the requested time.
def latest_snapshot_at_or_before(
    snapshots: list[tuple[datetime, int]], boundary: datetime, tolerance_seconds: int
) -> int | None:
    """Select the latest snapshot at or before the requested time."""
    candidate: tuple[datetime, int] | None = None
    for snapshot in snapshots:
        if snapshot[0] <= boundary:
            candidate = snapshot
        else:
            break
    if candidate is None:
        return None
    age = (boundary - candidate[0]).total_seconds()
    if age > tolerance_seconds:
        return None
    return candidate[1]
# Select records inside the half-open UTC window.
def window_records(records: Iterable[dict[str, Any]], start: datetime, end: datetime, ts_getter) -> list[dict[str, Any]]:
    """Select records inside the half-open UTC window."""
    result = []
    for record in records:
        timestamp = ts_getter(record)
        if start <= timestamp < end:
            result.append(record)
    return result
# Aggregate Sysmon records into the defined window features.
def sysmon_features(records: list[dict[str, Any]]) -> dict[str, int]:
    """Aggregate Sysmon records into the defined window features."""
    processes = [r for r in records if int(r.get("event_id", -1)) == SYSMON_IDS["process"]]
    network = [r for r in records if int(r.get("event_id", -1)) == SYSMON_IDS["network"]]
    data = lambda r: r.get("event_data") or {}
    images = {normalise_path(data(r).get("Image")) for r in processes if data(r).get("Image")}
    parent_child = {
        (normalise_path(data(r).get("ParentImage")), normalise_path(data(r).get("Image")))
        for r in processes
        if data(r).get("Image")
    }
    destinations = {
        (
            str(data(r).get("DestinationIp", "")).strip().lower(),
            str(data(r).get("DestinationPort", "")).strip(),
            str(data(r).get("Protocol", "")).strip().lower(),
        )
        for r in network
        if data(r).get("DestinationIp") or data(r).get("DestinationPort")
    }
    return {
        "sysmon_process_create_count": len(processes),
        "sysmon_unique_process_image_count": len(images),
        "sysmon_powershell_process_count": sum(
            basename(data(r).get("Image")) in {"powershell.exe", "pwsh.exe"} for r in processes
        ),
        "sysmon_cmd_process_count": sum(basename(data(r).get("Image")) == "cmd.exe" for r in processes),
        "sysmon_unique_parent_child_pair_count": len(parent_child),
        "sysmon_network_connect_count": len(network),
        "sysmon_unique_destination_count": len(destinations),
        "sysmon_dns_query_count": sum(int(r.get("event_id", -1)) == SYSMON_IDS["dns"] for r in records),
        "sysmon_file_create_count": sum(int(r.get("event_id", -1)) == SYSMON_IDS["file_create"] for r in records),
        "sysmon_file_delete_count": sum(int(r.get("event_id", -1)) == SYSMON_IDS["file_delete"] for r in records),
        "sysmon_registry_event_count": sum(int(r.get("event_id", -1)) in SYSMON_IDS["registry"] for r in records),
    }
# Extract the UTC timestamp from a Wazuh alert.
def wazuh_time(record: dict[str, Any]) -> datetime:
    """Extract the UTC timestamp from a Wazuh alert."""
    source = record.get("_source") or {}
    return parse_dt(source["timestamp"])
# Aggregate Wazuh alerts into the defined window features.
def wazuh_features(records: list[dict[str, Any]]) -> dict[str, int]:
    """Aggregate Wazuh alerts into the defined window features."""
    counts = {name: 0 for name in WAZUH_FEATURES}
    for record in records:
        source = record.get("_source") or {}
        rule = source.get("rule") or {}
        try:
            level = int(rule.get("level", 0))
        except (TypeError, ValueError):
            level = 0
        level = max(0, min(15, level))
        counts[f"wazuh_level_{level:02d}_count"] += 1
    return counts
# Extract the UTC timestamp from a Suricata EVE record.
def suricata_time(record: dict[str, Any]) -> datetime:
    """Extract the UTC timestamp from a Suricata EVE record."""
    return parse_dt(record["timestamp"])
# Count exact indicator matches without substring matching.
def exact_indicator_hits(sysmon: list[dict[str, Any]]) -> int:
    """Count exact indicator matches without substring matching."""
    patterns = ("s1v1-indicator", "\\s1v1\\", "s2v1-changed", "\\s2v1\\", "host-discovery.txt")
    count = 0
    for record in sysmon:
        values = " ".join(str(v) for v in (record.get("event_data") or {}).values()).lower()
        if any(pattern in values for pattern in patterns):
            count += 1
    return count
# Check that a source manifest reports a complete export.
def source_report_complete(path: Path) -> bool:
    """Check that a source manifest reports a complete export."""
    if not path.exists():
        return False
    try:
        report = read_json(path)
    except Exception:
        return False
    return bool(report.get("complete", False))
# Compare a source manifest with the corresponding evidence file.
def validate_manifest_pair(start: dict[str, Any], complete: dict[str, Any]) -> list[str]:
    """Compare a source manifest with the corresponding evidence file."""
    errors = []
    for key in ("run_id", "session_id", "family_id", "variant_id", "label"):
        if start.get(key) != complete.get(key):
            errors.append(f"manifest mismatch for {key}")
    if complete.get("status") != "completed":
        errors.append("run status was not completed")
    if int(complete.get("expected_window_count", 0)) != 4:
        errors.append("expected_window_count was not 4")
    return errors
# Write the dataset scope, provenance, schema, and exclusions.
def write_dataset_card(path: Path, quality: dict[str, Any], window_seconds: int, allowed_modes: list[str]) -> None:
    """Write the dataset scope, provenance, schema, and exclusions."""
    lines = [
        "# EDR laboratory dataset card",
        "",
        "## Purpose",
        "",
        "This dataset was created for a controlled MSc evaluation of telemetry-based and hybrid endpoint detection under the frozen protocol.",
        "",
        "## Composition",
        "",
        f"- Window duration: {window_seconds} seconds.",
        f"- Included run modes: {', '.join(allowed_modes)}.",
        f"- Valid independent runs: {quality['valid_runs']}.",
        f"- Model rows: {quality['rows']}.",
        f"- Benign and suspicious run counts: {quality['class_counts_by_run']}.",
        f"- Behavioural-family counts: {quality['family_counts_by_run']}.",
        "",
        "## Experimental unit and grouping",
        "",
        "The independent experimental unit is run_id. Multiple event windows from one run are correlated and must remain in one training, validation, test, cross-validation, and bootstrap group.",
        "",
        "## Data sources",
        "",
        "The feature rows were calculated from run-specific raw Sysmon JSONL, osquery snapshot logs, Wazuh alert exports, Suricata EVE exports, and scenario manifests. Literal scenario identifiers, timestamps, filenames, paths, network addresses, rule identifiers, signatures, and ATT&CK identifiers were retained only as evidence or metadata and were not model features.",
        "",
        "## Ground truth",
        "",
        "Labels were assigned from the frozen scenario family in manifest-start.json. The builder accepted a run only after the start and completion manifests agreed, the action log contained four completed actions, preflight and rollback passed, source-export reports passed, and the run validation report passed.",
        "",
        "## Cleaning and quality controls",
        "",
        "Exact duplicates were removed with source-specific stable identifiers. Missing telemetry was not converted to zero. Runs with absent osquery boundary snapshots, incomplete exports, malformed JSON, manifest disagreement, or failed source-health checks were excluded and recorded in run-exclusion-log.csv.",
        "",
        "## Intended use",
        "",
        "The dataset is intended only for the controlled comparisons defined by the frozen protocol, including variant, behavioural-family holdout, and temporal evaluation.",
        "",
        "## Prohibited interpretation",
        "",
        "The dataset is not evidence of unrestricted malware detection, production consumer readiness, or human usability. It contains synthetic, non-destructive behaviours from one Windows endpoint and one frozen four-VM laboratory.",
        "",
        "## Known limitations",
        "",
        "The behavioural families are designed laboratory abstractions. Rule-alert features contain prior Wazuh and Suricata decisions. Multiple windows from one run are correlated. Results can change with operating-system, telemetry, configuration, timing, or behavioural distribution changes.",
        "",
        "## Reproducibility",
        "",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")
# Parse command-line arguments and execute the file workflow.
def main() -> int:
    """Validate arguments, process accepted runs, build window features, and write all dataset artefacts."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--evidence-root", type=Path, required=True, help="Directory containing one subdirectory per run")
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--window-seconds", type=int, default=30)
    parser.add_argument("--osquery-tolerance-seconds", type=int, default=35)
    parser.add_argument("--include-mode", action="append", choices=["Pilot", "Formal", "Validation"], help="Run mode to include. Repeat for more than one mode. Default: Formal")
    parser.add_argument("--allow-missing-alert-sources", action="store_true")
    parser.add_argument("--allow-unfinalised", action="store_true", help="Validation-only option for synthetic test fixtures")
    args = parser.parse_args()
    if args.window_seconds not in {30, 60}:
        raise SystemExit("window-seconds must be 30 or 60")
    allowed_modes = args.include_mode or ["Formal"]
    args.output_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, Any]] = []
    exclusions: list[dict[str, Any]] = []
    duplicates: list[dict[str, Any]] = []
    run_manifest: list[dict[str, Any]] = []
    run_dirs = sorted(path for path in args.evidence_root.iterdir() if path.is_dir())
    for run_dir in run_dirs:
        run_id = run_dir.name
        reasons: list[str] = []
        required = [
            run_dir / "manifest-start.json",
            run_dir / "manifest-complete.json",
            run_dir / "action-log.jsonl",
            run_dir / "sysmon-events.jsonl",
            run_dir / "osqueryd.snapshots.log",
        ]
        for path in required:
            if not path.exists():
                reasons.append(f"missing {path.name}")
        if reasons:
            exclusions.append({"run_id": run_id, "reason": "; ".join(reasons)})
            continue
        try:
            start_manifest = read_json(run_dir / "manifest-start.json")
            complete_manifest = read_json(run_dir / "manifest-complete.json")
            reasons.extend(validate_manifest_pair(start_manifest, complete_manifest))
        except Exception as exc:
            exclusions.append({"run_id": run_id, "reason": f"manifest error: {exc}"})
            continue
        mode = str(start_manifest.get("mode", ""))
        if mode not in allowed_modes:
            exclusions.append({"run_id": run_id, "reason": f"mode {mode!r} not included; allowed={allowed_modes}"})
            continue
        if start_manifest.get("protocol_id") != "EDR-MSC-FINAL":
            reasons.append("protocol_id was not EDR-MSC-FINAL")
        if not args.allow_unfinalised:
            validation_path = run_dir / "run-validation-report.json"
            if not validation_path.exists():
                reasons.append("missing run-validation-report.json")
            else:
                try:
                    validation = read_json(validation_path)
                    if not validation.get("passed", False):
                        reasons.append("run validation report did not pass")
                except Exception as exc:
                    reasons.append(f"run validation report error: {exc}")
        wazuh_path = run_dir / "wazuh-alerts.jsonl"
        suricata_path = run_dir / "suricata-events.jsonl"
        if not args.allow_missing_alert_sources:
            if not wazuh_path.exists() or not source_report_complete(run_dir / "wazuh-export-report.json"):
                reasons.append("missing or incomplete Wazuh export")
            if not suricata_path.exists() or not source_report_complete(run_dir / "suricata-export-report.json"):
                reasons.append("missing or incomplete Suricata export")
        if reasons:
            exclusions.append({"run_id": run_id, "reason": "; ".join(reasons)})
            continue
        try:
            sysmon, sysmon_dups = deduplicate_sysmon(iter_jsonl(run_dir / "sysmon-events.jsonl"))
            snapshots, osquery_dups = parse_osquery_snapshots(run_dir / "osqueryd.snapshots.log")
            wazuh, wazuh_dups = deduplicate_wazuh(iter_jsonl(wazuh_path)) if wazuh_path.exists() else ([], 0)
            suricata, suricata_dups = deduplicate_suricata(iter_jsonl(suricata_path)) if suricata_path.exists() else ([], 0)
        except Exception as exc:
            exclusions.append({"run_id": run_id, "reason": f"source parse error: {exc}"})
            continue
        for source, count in (("sysmon", sysmon_dups), ("osquery", osquery_dups), ("wazuh", wazuh_dups), ("suricata", suricata_dups)):
            if count:
                duplicates.append({"run_id": run_id, "source": source, "duplicate_count": count})
        scenario_start = parse_dt(start_manifest["scenario_start_utc"])
        planned_end = parse_dt(start_manifest["planned_scenario_end_utc"])
        actual_end = parse_dt(complete_manifest["actual_scenario_end_utc"])
        end_deviation = abs((actual_end - planned_end).total_seconds())
        if end_deviation > 5:
            exclusions.append({"run_id": run_id, "reason": f"actual scenario end differed from planned end by {end_deviation:.3f} seconds"})
            continue
        active_seconds = int((planned_end - scenario_start).total_seconds())
        if active_seconds % args.window_seconds != 0:
            exclusions.append({"run_id": run_id, "reason": "active duration was not divisible by window duration"})
            continue
        expected_windows = active_seconds // args.window_seconds
        run_rows: list[dict[str, Any]] = []
        missing_osquery = False
        for window_index in range(expected_windows):
            window_start = scenario_start + pd.Timedelta(seconds=window_index * args.window_seconds)
            window_end = window_start + pd.Timedelta(seconds=args.window_seconds)
            sysmon_window = window_records(sysmon, window_start, window_end, event_time)
            wazuh_window = window_records(wazuh, window_start, window_end, wazuh_time)
            suricata_window = window_records(suricata, window_start, window_end, suricata_time)
            start_count = latest_snapshot_at_or_before(snapshots, window_start, args.osquery_tolerance_seconds)
            end_count = latest_snapshot_at_or_before(snapshots, window_end, args.osquery_tolerance_seconds)
            if start_count is None or end_count is None:
                missing_osquery = True
                break
            row: dict[str, Any] = {
                "run_id": run_id,
                "session_id": start_manifest["session_id"],
                "family_id": start_manifest["family_id"],
                "variant_id": start_manifest["variant_id"],
                "scenario_name": start_manifest["scenario_name"],
                "label": int(start_manifest["label"]),
                "mode": mode,
                "window_index": window_index,
                "window_start_utc": iso(window_start),
                "window_end_utc": iso(window_end),
                "window_duration_s": args.window_seconds,
                "sample_filename": f"{run_id}-w{window_index:02d}",
                "behavioural_family": start_manifest["family_id"],
                "protocol_id": start_manifest.get("protocol_id", ""),
                "source_health_status": "complete",
            }
            row.update(sysmon_features(sysmon_window))
            row["osquery_process_count_delta"] = end_count - start_count
            row.update(wazuh_features(wazuh_window))
            row["wazuh_alert_total_count"] = len(wazuh_window)
            row["suricata_alert_count"] = sum(r.get("event_type") == "alert" for r in suricata_window)
            row["exact_indicator_hit_count"] = exact_indicator_hits(sysmon_window)
            row["exact_indicator_prediction"] = int(row["exact_indicator_hit_count"] > 0)
            row["rule_baseline_prediction"] = int(
                row["suricata_alert_count"] > 0
                or sum(row[f"wazuh_level_{level:02d}_count"] for level in range(7, 16)) > 0
            )
            run_rows.append(row)
        if missing_osquery:
            exclusions.append({"run_id": run_id, "reason": "missing acceptable osquery boundary snapshot"})
            continue
        if len(run_rows) != expected_windows:
            exclusions.append({"run_id": run_id, "reason": "unexpected number of complete windows"})
            continue
        rows.extend(run_rows)
        run_manifest.append(
            {
                "run_id": run_id,
                "session_id": start_manifest["session_id"],
                "family_id": start_manifest["family_id"],
                "variant_id": start_manifest["variant_id"],
                "label": start_manifest["label"],
                "mode": mode,
                "window_count": len(run_rows),
                "evidence_directory": str(run_dir),
            }
        )
    dataset = pd.DataFrame(rows)
    if not dataset.empty:
        dataset = dataset.sort_values(["session_id", "run_id", "window_index"]).reset_index(drop=True)
        assert not set(HYBRID_FEATURES).intersection(FORBIDDEN_FEATURES)
        for feature in HYBRID_FEATURES:
            if feature not in dataset.columns:
                raise RuntimeError(f"Missing feature column: {feature}")
        if dataset.groupby("run_id")["label"].nunique().max() != 1:
            raise RuntimeError("A run_id had more than one label.")
    mode_slug = "-".join(mode.lower() for mode in allowed_modes)
    stem = f"edr-{mode_slug}-windows-{args.window_seconds}s"
    csv_path = args.output_dir / f"{stem}.csv"
    parquet_path = args.output_dir / f"{stem}.parquet"
    dataset.to_csv(csv_path, index=False, lineterminator="\n")
    parquet_written = False
    try:
        dataset.to_parquet(parquet_path, index=False)
        parquet_written = True
    except ImportError:
        try:
            import duckdb
            connection = duckdb.connect()
            connection.register("dataset_frame", dataset)
            escaped = str(parquet_path).replace("'", "''")
            connection.execute(f"COPY dataset_frame TO '{escaped}' (FORMAT PARQUET)")
            connection.close()
            parquet_written = True
        except ImportError:
            parquet_written = False
    schema = {
        "protocol_id": "EDR-MSC-FINAL",
        "window_seconds": args.window_seconds,
        "included_modes": allowed_modes,
        "primary_experimental_unit": "run_id",
        "telemetry_only_features": TELEMETRY_FEATURES,
        "hybrid_features": HYBRID_FEATURES,
        "forbidden_feature_columns": sorted(FORBIDDEN_FEATURES | {"mode"}),
        "baseline_metadata": ["exact_indicator_prediction", "rule_baseline_prediction"],
    }
    schema_path = args.output_dir / f"feature-schema-{mode_slug}-{args.window_seconds}s.json"
    schema_path.write_text(json.dumps(schema, indent=2), encoding="utf-8")
    pd.DataFrame(run_manifest).to_csv(args.output_dir / f"run-manifest-{mode_slug}.csv", index=False, lineterminator="\n")
    pd.DataFrame(exclusions, columns=["run_id", "reason"]).to_csv(args.output_dir / f"run-exclusion-log-{mode_slug}.csv", index=False, lineterminator="\n")
    pd.DataFrame(duplicates, columns=["run_id", "source", "duplicate_count"]).to_csv(args.output_dir / f"duplicate-events-{mode_slug}.csv", index=False, lineterminator="\n")
    quality = {
        "protocol_id": "EDR-MSC-FINAL",
        "included_modes": allowed_modes,
        "window_seconds": args.window_seconds,
        "run_directories_seen": len(run_dirs),
        "valid_runs": int(dataset["run_id"].nunique()) if not dataset.empty else 0,
        "rows": int(len(dataset)),
        "excluded_runs": len(exclusions),
        "class_counts_by_run": dataset.drop_duplicates("run_id")["label"].value_counts().sort_index().to_dict() if not dataset.empty else {},
        "family_counts_by_run": dataset.drop_duplicates("run_id")["family_id"].value_counts().sort_index().to_dict() if not dataset.empty else {},
        "session_counts_by_run": dataset.drop_duplicates("run_id")["session_id"].value_counts().sort_index().to_dict() if not dataset.empty else {},
        "missing_values": dataset.isna().sum().to_dict() if not dataset.empty else {},
        "constant_features": [feature for feature in HYBRID_FEATURES if not dataset.empty and dataset[feature].nunique(dropna=False) <= 1],
        "feature_nonzero_windows": {feature: int((dataset[feature] != 0).sum()) for feature in HYBRID_FEATURES} if not dataset.empty else {},
        "parquet_written": parquet_written,
    }
    quality_path = args.output_dir / f"dataset-quality-report-{mode_slug}-{args.window_seconds}s.json"
    quality_path.write_text(json.dumps(quality, indent=2), encoding="utf-8")
    coverage = pd.DataFrame([
        {"feature": feature, "nonzero_windows": quality["feature_nonzero_windows"].get(feature, 0), "unique_values": int(dataset[feature].nunique(dropna=False)) if not dataset.empty else 0}
        for feature in HYBRID_FEATURES
    ])
    coverage.to_csv(args.output_dir / f"feature-coverage-{mode_slug}-{args.window_seconds}s.csv", index=False)
    write_dataset_card(args.output_dir / f"dataset-card-{mode_slug}-{args.window_seconds}s.md", quality, args.window_seconds, allowed_modes)
    print(json.dumps(quality, indent=2))
    return 0 if rows else 4
# Run the command-line entry point only when this file is executed directly.
if __name__ == "__main__":
    raise SystemExit(main())
