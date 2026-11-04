#!/usr/bin/env python3
"""Attach a console client to the existing workspace; starts no network/services."""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from all_blue.lab_console import run_console
from all_blue.workspace import Workspace

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--runtime', type=Path, help='Existing workspace directory; defaults to latest lab')
    args = parser.parse_args()
    run_console(args.runtime or Workspace(ROOT).latest(ROOT / 'runtime'))
