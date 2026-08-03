#!/usr/bin/env python3
from __future__ import annotations
import argparse, json
from pathlib import Path
import pandas as pd
FAMILIES={'B1','B2','B3','S1','S2','S3'}
SESSIONS={'S01','S02','S03'}
# Parse command-line arguments and execute the file workflow.
def main() -> int:
    """Evaluate every Formal acceptance condition and write the gate report."""
    p=argparse.ArgumentParser()
    p.add_argument('--quality-report',type=Path,required=True)
    p.add_argument('--run-manifest',type=Path,required=True)
    p.add_argument('--output',type=Path,required=True)
    a=p.parse_args()
    q=json.loads(a.quality_report.read_text(encoding='utf-8'))
    runs=pd.read_csv(a.run_manifest).drop_duplicates('run_id')
    checks=[]
    # Append one named validation result to the report.
    def add(n, p, d):
        """Append one named acceptance check to the report."""
        checks.append({'check':n,'passed':bool(p),'details':d})
    add('formal_mode_only',set(runs['mode'])=={'Formal'},str(sorted(set(runs['mode']))))
    add('exactly_36_runs',len(runs)==36,f'runs={len(runs)}')
    fam=runs.groupby('family_id')['run_id'].nunique().to_dict()
    add('exactly_6_per_family',set(fam)==FAMILIES and all(fam.get(x)==6 for x in FAMILIES),str(fam))
    ses=runs.groupby('session_id')['run_id'].nunique().to_dict()
    add('exactly_12_per_session',set(ses)==SESSIONS and all(ses.get(x)==12 for x in SESSIONS),str(ses))
    cross=runs.groupby(['session_id','family_id'])['run_id'].nunique()
    add('two_per_family_per_session',len(cross)==18 and bool((cross==2).all()),str(cross.to_dict()))
    variants=runs.groupby(['session_id','family_id','variant_id'])['run_id'].nunique()
    expected_variant_cells={(session,family,variant) for session in SESSIONS for family in FAMILIES for variant in ['V1','V2']}
    add('one_variant_run_per_family_per_session',set(variants.index)==expected_variant_cells and bool((variants==1).all()),str(variants.to_dict()))
    add('no_excluded_runs',int(q.get('excluded_runs',-1))==0,f"excluded={q.get('excluded_runs')}")
    add('four_windows_per_run',int(q.get('rows',-1))==144,f"rows={q.get('rows')}")
    add('balanced_classes',q.get('class_counts_by_run') in ({'0':18,'1':18},{0:18,1:18}),str(q.get('class_counts_by_run')))
    add('no_missing_values',all(int(v)==0 for v in q.get('missing_values',{}).values()),str({k:v for k,v in q.get('missing_values',{}).items() if int(v)!=0}))
    passed=all(x['passed'] for x in checks)
    report={'protocol_id':'EDR-MSC-FINAL','passed':passed,'checks':checks}
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(report,indent=2),encoding='utf-8')
    print(json.dumps(report,indent=2))
    return 0 if passed else 4
# Run the command-line entry point only when this file is executed directly.
if __name__=='__main__': raise SystemExit(main())
