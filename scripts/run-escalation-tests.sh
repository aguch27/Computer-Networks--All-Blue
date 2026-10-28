#!/usr/bin/env bash
set -euo pipefail
cd /home/agasthya/all-blue
# Run the existing baseline first, then the same suite plus automatic-block checks.
.venv/bin/python scripts/lab.py --test "$@"
exec .venv/bin/python scripts/lab.py --test --escalation config/escalation-lab.json "$@"
