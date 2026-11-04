#!/usr/bin/env bash
set -euo pipefail
cd /home/agasthya/all-blue
exec /home/agasthya/all-blue/.venv/bin/python /home/agasthya/all-blue/scripts/lab.py --test "$@"
