#!/usr/bin/env python3
"""Operator-invoked privileged handoff for fixed existing lab/test/benchmark jobs."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from all_blue.workspace import Conflict, Workspace, local_lock, read_json
from all_blue.storage import atomic_json


def command_for(job):
    python = str(ROOT / '.venv/bin/python')
    if job['kind'] == 'benchmark':
        return [python, '-u', str(ROOT / 'scripts/benchmark.py'), '--trials', str(job['trials'])]
    command = [python, '-u', str(ROOT / 'scripts/lab.py'), '--workspace' if job['kind'] == 'start' else '--test', '--verbose']
    if job['kind'] == 'start':
        command.append('--console')
    if job['profile'] == 'escalation':
        command += ['--escalation', str(ROOT / 'config/escalation-lab.json')]
    return command


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--job', required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit('Run this handoff with sudo in your terminal. The GUI never handles passwords.')
    workspace = Workspace(ROOT)
    path = workspace.job_path(args.job)
    uid, gid = int(os.environ.get('SUDO_UID', '0')), int(os.environ.get('SUDO_GID', '0'))
    with local_lock(ROOT / 'runtime/workflow.lock'):
        with local_lock(ROOT / 'runtime/job-plan.lock'):
            job = read_json(path, 8192)
            if job.get('id') != args.job:
                raise SystemExit('Job identity does not match its handoff; prepare a new workflow')
            workspace.validate_plan({key: job[key] for key in ('kind', 'profile', 'trials')})
            if job['status'] != 'awaiting_terminal':
                raise SystemExit('This handoff is no longer awaiting execution')
            config = workspace.configurations()
            if job['config_revisions'] != {key: config[key]['revision'] for key in ('policy', 'escalation')}:
                raise SystemExit('Configuration changed after preparation. Cancel this handoff and prepare another.')
            job.update(status='running', started_at=time.time(), pid=os.getpid())
            atomic_json(path, job)
            os.chown(path, uid, gid)
        process = None
        try:
            # Refuse active presentations BEFORE launching a benchmark or acceptance job.
            if subprocess.run(['ovs-vsctl', 'br-exists', 'ab-s1'], capture_output=True, timeout=5).returncode == 0:
                raise Conflict('ab-s1 is active. Shut down its existing lab first; this workflow never clears it.')
            from scripts.lab import check_management_ports
            check_management_ports()
            output = workspace.jobs / f'{job["id"]}.log'
            with output.open('xb') as log:
                os.chown(output, uid, gid)
                print('Running', job['kind'], 'with', job['profile'], 'profile. Progress is available in the observatory.', flush=True)
                # A console is an actual terminal reader, not a redirected prompt
                # or keystroke injection. Workspace snapshots retain its evidence.
                process = subprocess.Popen(command_for(job), cwd=ROOT,
                                           stdout=None if job['kind'] == 'start' else log, stderr=subprocess.STDOUT)
                previous = signal.signal(signal.SIGTERM, lambda *_: process.terminate())
                previous_hup = signal.signal(signal.SIGHUP, lambda *_: process.terminate())
                previous_int = signal.getsignal(signal.SIGINT)
                if job['kind'] == 'start':
                    signal.signal(signal.SIGINT, lambda *_: None)  # Foreground child receives Ctrl+C itself.
                try:
                    code = process.wait()
                except KeyboardInterrupt:
                    process.send_signal(signal.SIGINT)
                    code = process.wait(timeout=30)
                finally:
                    signal.signal(signal.SIGTERM, previous)
                    signal.signal(signal.SIGHUP, previous_hup)
                    signal.signal(signal.SIGINT, previous_int)
            job.update(status='completed' if code == 0 else 'failed', returncode=code)
        except Exception as error:
            job.update(status='failed', error=str(error))
        finally:
            if process and process.poll() is None:
                process.terminate()
                process.wait(timeout=30)
            job['finished_at'] = time.time()
            atomic_json(path, job)
            os.chown(path, uid, gid)
        print(json.dumps(job, indent=2), flush=True)
        return 0 if job['status'] == 'completed' else 1


if __name__ == '__main__':
    raise SystemExit(main())
