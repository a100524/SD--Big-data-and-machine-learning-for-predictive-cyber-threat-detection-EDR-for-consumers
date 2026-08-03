#!/usr/bin/env python3
from __future__ import annotations
import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
# Run one required validation command and return its result.
def run(command: list[str], *, capture: bool = False) -> subprocess.CompletedProcess[str]:
    """Run one required validation command and return its result."""
    completed = subprocess.run(command, text=True, capture_output=capture)
    if completed.returncode != 0:
        if capture:
            print(completed.stdout, file=sys.stderr)
            print(completed.stderr, file=sys.stderr)
        raise RuntimeError(f"Command failed ({completed.returncode}): {' '.join(command)}")
    return completed
# Read and parse one UTF-8 JSON file.
def read_json(path: Path) -> dict:
    """Read and parse one UTF-8 JSON file."""
    with path.open('r', encoding='utf-8-sig') as handle:
        value = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError(f'Expected object in {path}')
    return value
# Parse command-line arguments and execute the file workflow.
def main() -> int:
    """Export central evidence for one run and call finalisation after every export succeeds."""
    parser = argparse.ArgumentParser()
    parser.add_argument('--run-id', required=True)
    parser.add_argument('--endpoint-share-root', type=Path, default=Path.home() / 'edr-evidence' / 'VM-endpoint')
    parser.add_argument('--management-sensor-share-root', type=Path, default=Path.home() / 'edr-evidence' / 'VM-sensor')
    parser.add_argument('--final-root', type=Path, default=Path.home() / 'edr-evidence' / 'runs')
    parser.add_argument('--sensor-host', default='10.50.0.20')
    parser.add_argument('--sensor-user', default='edradmin')
    parser.add_argument('--sensor-script', default='/home/edradmin/edr-lab/sensor/export_suricata.py')
    parser.add_argument('--sensor-eve', default='/var/log/suricata/eve.json')
    parser.add_argument('--sensor-share-root', default='/mnt/edr-share/VM-sensor')
    parser.add_argument('--expected-mode', choices=['Pilot','Formal','Validation'], required=True)
    parser.add_argument('--wazuh-url', default=os.getenv('WAZUH_INDEXER_URL', 'https://127.0.0.1:9200'))
    parser.add_argument('--verify-wazuh-tls', action='store_true')
    args = parser.parse_args()
    if not args.run_id.replace('-', '').replace('_', '').replace('.', '').isalnum():
        raise SystemExit('Unsupported run identifier.')
    endpoint_run = (args.endpoint_share_root / args.run_id).resolve()
    final = (args.final_root / args.run_id).resolve()
    if not endpoint_run.is_dir():
        raise SystemExit(f'Endpoint run directory not found: {endpoint_run}')
    if final.exists():
        raise SystemExit(f'Final run directory already exists: {final}')
    start = read_json(endpoint_run / 'manifest-start.json')
    complete = read_json(endpoint_run / 'manifest-complete.json')
    if start.get('run_id') != args.run_id or complete.get('run_id') != args.run_id:
        raise SystemExit('Run identifier mismatch in manifests.')
    if start.get('mode') != args.expected_mode or complete.get('mode') != args.expected_mode:
        raise SystemExit('Run mode did not match --expected-mode.')
    start_utc = start['envelope_start_utc']
    end_utc = complete['collection_end_utc']
    args.final_root.mkdir(parents=True, exist_ok=True)
    temporary = args.final_root / f'.{args.run_id}.completing'
    if temporary.exists():
        shutil.rmtree(temporary)
    shutil.copytree(endpoint_run, temporary)
    root = Path(__file__).resolve().parents[1]
    wazuh_command = [
        sys.executable, str(root / 'mgmt' / 'export_wazuh_alerts.py'),
        '--start-utc', start_utc, '--end-utc', end_utc, '--run-id', args.run_id,
        '--output', str(temporary / 'wazuh-alerts.jsonl'),
        '--report', str(temporary / 'wazuh-export-report.json'),
        '--url', args.wazuh_url,
    ]
    if args.verify_wazuh_tls:
        wazuh_command.append('--verify-tls')
    run(wazuh_command)
    remote = f'{args.sensor_user}@{args.sensor_host}'
    remote_dir = f'{args.sensor_share_root}/{args.run_id}.partial'
    run(['ssh', remote, f"rm -rf '{remote_dir}' && mkdir -p '{remote_dir}'"])
    run(['ssh', remote, 'python3', args.sensor_script, '--source', args.sensor_eve, '--start-utc', start_utc, '--end-utc', end_utc, '--run-id', args.run_id, '--output', f'{remote_dir}/suricata-events.jsonl', '--report', f'{remote_dir}/suricata-export-report.json'])
    sensor_local = args.management_sensor_share_root / f'{args.run_id}.partial'
    shutil.copy2(sensor_local / 'suricata-events.jsonl', temporary / 'suricata-events.jsonl')
    shutil.copy2(sensor_local / 'suricata-export-report.json', temporary / 'suricata-export-report.json')
    shutil.rmtree(sensor_local)
    finaliser = root / 'mgmt' / 'finalise_run.py'
    run([sys.executable, str(finaliser), '--run-dir', str(temporary), '--expected-mode', args.expected_mode])
    validation = read_json(temporary / 'run-validation-report.json')
    if not validation.get('passed'):
        raise SystemExit('Run validation failed. The temporary evidence directory was retained for review.')
    temporary.rename(final)
    shutil.rmtree(endpoint_run)
    print(json.dumps({'run_id': args.run_id, 'status': 'sealed', 'final_directory': str(final)}, indent=2))
    return 0
# Run the command-line entry point only when this file is executed directly.
if __name__ == '__main__':
    raise SystemExit(main())
