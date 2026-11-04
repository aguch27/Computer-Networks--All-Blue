#!/usr/bin/env python3
"""Recover only an interrupted, recorded All Blue owner; never an active lab."""
import argparse
import json
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from all_blue.workspace import Workspace, local_lock
from all_blue.policy import Policy
from all_blue.lab_recovery import recover

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', required=True, help='Exact lab-* run name, not an arbitrary path')
    parser.add_argument('--confirm-interrupted', action='store_true', required=True)
    args = parser.parse_args()
    runtime = Workspace(ROOT).run_path(args.run)
    if not runtime.name.startswith('lab-'):
        parser.error('Select an interrupted lab run')
    policy = Policy(runtime / 'loaded-policy.json')
    with local_lock(ROOT / 'runtime/network.lock'):
        result = recover(runtime, policy, ROOT)
        for name in ('workspace.json',):
            os.chown(runtime / name, int(os.environ.get('SUDO_UID', 0)), int(os.environ.get('SUDO_GID', 0)))
        print(json.dumps(result, indent=2))
