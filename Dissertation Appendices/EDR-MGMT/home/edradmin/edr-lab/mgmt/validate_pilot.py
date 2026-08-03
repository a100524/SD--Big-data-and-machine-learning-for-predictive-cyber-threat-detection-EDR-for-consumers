#!/usr/bin/env python3
from __future__ import annotations
import argparse, json
from pathlib import Path
import pandas as pd
REQUIRED_FAMILIES = {'B1','B2','B3','S1','S2','S3'}
PRIMARY_FEATURES = {
    'sysmon_process_create_count','sysmon_unique_process_image_count',
    'sysmon_powershell_process_count','sysmon_cmd_process_count',
    'sysmon_unique_parent_child_pair_count','sysmon_network_connect_count',
    'sysmon_unique_destination_count','sysmon_file_create_count',
    'sysmon_registry_event_count','osquery_process_count_delta'
}
# Parse command-line arguments and execute the file workflow.
def main() -> int:
    """Evaluate every Pilot acceptance condition and write the gate report."""
    p=argparse.ArgumentParser()
    p.add_argument('--quality-report', type=Path, required=True)
    p.add_argument('--run-manifest', type=Path, required=True)
    p.add_argument('--feature-coverage', type=Path, required=True)
    p.add_argument('--pytest-log', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    a=p.parse_args()
    quality=json.loads(a.quality_report.read_text(encoding='utf-8'))
    runs=pd.read_csv(a.run_manifest)
    coverage=pd.read_csv(a.feature_coverage)
    checks=[]
    # Append one named validation result to the report.
    def add(name, passed, details):
        """Append one named acceptance check to the report."""
        checks.append({'check':name,'passed':bool(passed),'details':details})
    unique=runs.drop_duplicates('run_id')
    add('pilot_mode_only', set(unique['mode'])=={'Pilot'}, str(sorted(set(unique['mode']))))
    add('minimum_30_valid_runs', len(unique)>=30, f'valid_runs={len(unique)}')
    counts=unique.groupby('family_id')['run_id'].nunique().to_dict()
    add('all_six_families', set(counts)==REQUIRED_FAMILIES, str(counts))
    add('minimum_five_per_family', all(counts.get(f,0)>=5 for f in REQUIRED_FAMILIES), str(counts))
    add('both_variants_present', all(unique[unique.family_id==f].variant_id.nunique()>=2 for f in REQUIRED_FAMILIES), 'V1 and V2 required per family')
    add('no_excluded_runs', int(quality.get('excluded_runs',-1))==0, f"excluded={quality.get('excluded_runs')}")
    add('no_missing_dataset_values', all(int(v)==0 for v in quality.get('missing_values',{}).values()), str({k:v for k,v in quality.get('missing_values',{}).items() if int(v)!=0}))
    nonzero=dict(zip(coverage['feature'],coverage['nonzero_windows']))
    add('primary_features_exercised', all(int(nonzero.get(f,0))>0 for f in PRIMARY_FEATURES), str({f:int(nonzero.get(f,0)) for f in sorted(PRIMARY_FEATURES)}))
    log=a.pytest_log.read_text(encoding='utf-8', errors='replace')
    add('automated_tests_passed', 'failed' not in log.lower() and 'passed' in log.lower(), log[-500:])
    passed=all(c['passed'] for c in checks)
    report={'protocol_id':'EDR-MSC-FINAL','passed':passed,'checks':checks,'required_action_before_formal': 'freeze protocol and package' if passed else 'correct failed checks and repeat affected pilot runs'}
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))
    return 0 if passed else 4
# Run the command-line entry point only when this file is executed directly.
if __name__=='__main__': raise SystemExit(main())
