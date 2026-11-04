"""Bounded local presentation records, configuration and terminal job handoffs.

HTTP never starts a process. Privileged jobs run only when the operator invokes the
fixed workspace launcher in a terminal. Reads are restricted to known run records.
"""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
import time
import uuid

from .policy import Policy
from .escalation import EscalationConfig
from .storage import atomic_json, recent_events

ROOT = Path(__file__).resolve().parents[1]
REPORTS = {'acceptance.json', 'benchmark.json', 'environment.json', 'measurements.json',
           'RESULTS.md', 'measurements.csv', 'summary.csv', 'graphs.svg', 'workspace.json', 'events.json'}
RUN_NAME = re.compile(r'(?:lab|benchmark)-[0-9][0-9A-Za-z-]{1,90}')
LOG_NAME = re.compile(r'(?:controller|logger)-[0-9]+\.log(?:\.[1-5])?')


class Conflict(ValueError):
    pass


def read_bytes(path, limit=2_000_000):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise ValueError('Only regular local records are readable')
        with os.fdopen(fd, 'rb', closefd=False) as stream:
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError('Record exceeds the response limit')
        return data
    finally:
        os.close(fd)


def read_json(path, limit=2_000_000):
    def invalid_constant(value):
        raise ValueError(f'Non-finite JSON value: {value}')
    return json.loads(read_bytes(path, limit), parse_constant=invalid_constant)


def revision(data):
    return hashlib.sha256(data).hexdigest()


def entries(path, maximum=2048):
    try:
        with os.scandir(path) as iterator:
            return [item for _, item in zip(range(maximum), iterator)]
    except FileNotFoundError:
        return []


def modified(path):
    try:
        return path.stat().st_mtime
    except FileNotFoundError:
        return 0  # A diagnostic may rotate between discovery and opening.


@contextmanager
def local_lock(path):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise Conflict('Another lab workflow owns this resource; stop it before starting another') from None
        yield
    finally:
        os.close(fd)


class Workspace:
    def __init__(self, root=ROOT):
        self.root = Path(root).resolve()
        self.runs = self.root / 'runtime'
        self.jobs = self.runs / 'gui-jobs'

    def run_path(self, name):
        if not isinstance(name, str) or not RUN_NAME.fullmatch(name):
            raise ValueError('Select a known lab or benchmark run')
        path = self.runs / name
        if path.is_symlink() or not path.is_dir() or path.resolve().parent != self.runs.resolve():
            raise ValueError('Run unavailable')
        return path

    def latest(self, fallback):
        try:
            saved = read_json(self.runs / 'latest-lab.json', 2048)
            path = Path(saved['runtime'])
            selected = self.run_path(path.name)
            if selected.resolve() != path.resolve():
                raise ValueError('Latest run is outside this project')
            return selected
        except (OSError, ValueError, KeyError, TypeError):
            return Path(fallback)

    def configurations(self, controller=None):
        values = {}
        for kind, name in [('policy', 'lab.json'), ('escalation', 'escalation-lab.json')]:
            try:
                raw = read_bytes(self.root / 'config' / name, 32768)
                values[kind] = dict(data=json.loads(raw), revision=revision(raw), path=f'config/{name}')
            except (OSError, ValueError) as error:
                values[kind] = dict(error=str(error))
        values['loaded'] = dict(policy=(controller or {}).get('policy'),
                                policy_version=(controller or {}).get('policy_version'),
                                escalation=(controller or {}).get('escalation'))
        values['application'] = 'Saving changes files only. Policy, bindings and escalation thresholds require a controlled lab restart. Live mode uses the existing selector; a saved runtime mode override still takes precedence.'
        return values

    def save_configuration(self, command):
        if not isinstance(command, dict) or set(command) != {'kind', 'revision', 'data'}:
            raise ValueError('Configuration needs kind, revision and data')
        kind = command['kind']
        names = {'policy': 'lab.json', 'escalation': 'escalation-lab.json'}
        if kind not in names or not isinstance(command['revision'], str):
            raise ValueError('Unknown configuration')
        with local_lock(self.runs / 'config-edit.lock'):
            path = self.root / 'config' / names[kind]
            if revision(read_bytes(path, 32768)) != command['revision']:
                raise Conflict('Configuration changed since it was opened; reload before saving')
            if kind == 'policy':
                policy = Policy.from_data(command['data'])
                EscalationConfig.load(self.root / 'config/escalation-lab.json', policy)
            else:
                EscalationConfig.from_data(command['data'], Policy(self.root / 'config/lab.json'))
            atomic_json(path, command['data'])
        return dict(status='saved', applied=False, configuration=self.configurations())

    def catalog(self):
        paths = [Path(item.path) for item in entries(self.runs)
                 if RUN_NAME.fullmatch(item.name) and item.is_dir(follow_symlinks=False)]
        result = []
        for path in sorted(paths, key=lambda p: p.name, reverse=True)[:48]:
            files = [name for name in sorted(REPORTS) if (path / name).is_file() and not (path / name).is_symlink()]
            if (path / 'events.sqlite3').is_file() and not (path / 'events.sqlite3').is_symlink():
                files.append('events.json')
            row = dict(name=path.name, files=files, recorded_at=path.stat().st_mtime,
                       status='incomplete', checks=0, error=None)
            try:
                name = 'acceptance.json' if 'acceptance.json' in files else 'measurements.json'
                data = read_json(path / name)
                if isinstance(data, list):
                    row.update(status='measured' if data and all(r.get('valid') for r in data) else 'invalid',
                               checks=len(data), valid=sum(bool(r.get('valid')) for r in data))
                else:
                    row.update(status=data.get('status', 'recorded'), kind=data.get('kind', 'acceptance'), error=data.get('error'),
                               checks=len(data.get('combined_checks', []) if data.get('kind') == 'combined_acceptance' else data.get('passed', [])), recorded_at=data.get('finished_at', data.get('started_at', row['recorded_at'])))
            except FileNotFoundError:
                pass
            except (OSError, ValueError, TypeError, AttributeError) as error:
                row.update(status='invalid', error=str(error))
            result.append(row)
        return result

    def report(self, run, name):
        if name not in REPORTS:
            raise ValueError('Report is not allowlisted')
        if name == 'events.json':
            return json.dumps(dict(run=run, source='Retained SQLite security events; newest 100',
                                   events=self.audit_history(self.run_path(run))), allow_nan=False).encode()
        return read_bytes(self.run_path(run) / name, 4_000_000)

    def audit_history(self, runtime):
        database = Path(runtime) / 'events.sqlite3'
        if database.is_symlink() or not database.is_file():
            raise ValueError('Retained audit database unavailable')
        return recent_events(database)

    def diagnostics(self, runtime):
        result = dict(source='Transient process diagnostics, not persisted security events', records=[], files=[], errors=[])
        paths = [Path(item.path) for item in entries(runtime)
                 if LOG_NAME.fullmatch(item.name) and item.is_file(follow_symlinks=False)]
        selected = []
        for component in ('controller', 'logger'):
            selected.extend(sorted((p for p in paths if p.name.startswith(component)),
                                   key=modified, reverse=True)[:2])
        for path in selected:
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, 'rb') as stream:
                    info = os.fstat(stream.fileno())
                    if not stat.S_ISREG(info.st_mode):
                        raise ValueError('Only regular diagnostic files are readable')
                    offset = max(0, info.st_size - 65536)
                    stream.seek(offset)
                    data = stream.read(65536)
                lines = data.decode(errors='replace').splitlines()
                if offset:
                    lines = lines[1:]
                token = f'{path.name}:{info.st_ino}:{info.st_mtime_ns}:{info.st_size}'
                result['files'].append(dict(name=path.name, token=token, truncated=bool(offset or len(lines) > 64), modified_at=info.st_mtime))
                for line in lines[-64:]:
                    try:
                        record = json.loads(line)
                        if not isinstance(record, dict):
                            raise ValueError('Not a diagnostic object')
                    except ValueError:
                        record = dict(text=line[:2048])
                    result['records'].append(dict(file=path.name, record=record))
            except (OSError, ValueError) as error:
                result['errors'].append(f'{path.name}: {error}')
        result['available'] = bool(result['files'])
        return result

    def job_path(self, identity):
        if not isinstance(identity, str) or str(uuid.UUID(identity)) != identity:
            raise ValueError('Invalid job ID')
        return self.jobs / f'{identity}.json'

    def validate_plan(self, command):
        if not isinstance(command, dict) or set(command) != {'kind', 'profile', 'trials'}:
            raise ValueError('Job needs kind, profile and trials')
        if command['kind'] not in ('start', 'acceptance', 'benchmark') or command['profile'] not in ('baseline', 'escalation'):
            raise ValueError('Select an allowlisted lab workflow and explicit profile')
        if type(command['trials']) is not int or not 3 <= command['trials'] <= 10:
            raise ValueError('Benchmark repetitions must be 3–10')
        if command['kind'] == 'benchmark' and command['profile'] != 'baseline':
            raise ValueError('Benchmarks use their fixed comparison scenarios; a startup profile cannot override them')
        return command

    def plan(self, command):
        self.validate_plan(command)
        with local_lock(self.runs / 'job-plan.lock'):
            recent = self.job_records()
            if any(row.get('status') in ('awaiting_terminal', 'running') for row in recent):
                raise Conflict('A prepared or running workflow exists. Finish or cancel it first.')
            identity = str(uuid.uuid4())
            config = self.configurations()
            job = dict(id=identity, **command, status='awaiting_terminal', created_at=time.time(),
                       config_revisions={kind: config[kind]['revision'] for kind in ('policy', 'escalation')})
            atomic_json(self.job_path(identity), job)
        return dict(**job, terminal=f'sudo {self.root}/.venv/bin/python {self.root}/scripts/workspace.py --job {identity}',
                    note='Run this yourself in an Ubuntu terminal. The browser never handles administrator authentication. An active lab must be shut down first; existing networks are never cleared automatically.')

    def cancel_plan(self, command):
        if not isinstance(command, dict) or set(command) != {'id'}:
            raise ValueError('Cancellation requires a job ID')
        with local_lock(self.runs / 'job-plan.lock'):
            path = self.job_path(command['id'])
            job = read_json(path, 8192)
            if job['status'] != 'awaiting_terminal':
                raise Conflict('Only a handoff awaiting terminal execution can be cancelled. Use its terminal for a running job.')
            job.update(status='cancelled', finished_at=time.time())
            atomic_json(path, job)
        return job

    def job_records(self):
        records = []
        paths = [Path(item.path) for item in entries(self.jobs) if item.name.endswith('.json') and item.is_file(follow_symlinks=False)]
        for path in sorted(paths, key=modified, reverse=True)[:32]:
            try:
                job = read_json(path, 8192)
                identity = str(uuid.UUID(job['id']))
                job['terminal'] = f'sudo {self.root}/.venv/bin/python {self.root}/scripts/workspace.py --job {identity}'
                # No general filename endpoint: output always belongs to this validated job.
                output = self.jobs / (str(uuid.UUID(job['id'])) + '.log')
                try:
                    fd = os.open(output, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                    with os.fdopen(fd, 'rb') as stream:
                        info = os.fstat(stream.fileno())
                        if not stat.S_ISREG(info.st_mode):
                            raise ValueError('Only regular job output is readable')
                        stream.seek(max(0, info.st_size - 8192))
                        job['output'] = stream.read(8192).decode(errors='replace')
                except (OSError, ValueError):
                    job['output'] = ''
                if job.get('status') == 'running':
                    try:
                        command = Path(f'/proc/{int(job["pid"])}/cmdline').read_bytes().split(b'\0')
                        expected = str(self.root / 'scripts/workspace.py').encode()
                        if expected not in command or job['id'].encode() not in command:
                            raise ValueError('Launcher is no longer running')
                    except (OSError, ValueError, KeyError):
                        job.update(status='interrupted', error='The terminal launcher is no longer running. Inspect retained logs and the lab before starting another workflow.')
                records.append(job)
            except (OSError, ValueError, KeyError, TypeError):
                continue
        return records

    def status(self, runtime, controller=None):
        try:
            lab = read_json(Path(runtime) / 'workspace.json', 512000)
            if lab.get('status') in ('running', 'stopping') and not 0 <= time.time() - lab.get('collected_at', 0) < 5:
                lab['retained_status'] = lab['status']
                lab['status'] = 'interrupted'
                lab['reason'] = 'Runner heartbeat stale; cleanup is unverified. Inspect the owner terminal; guarded recovery requires an idle owner and administrator authentication.'
                for row in lab.get('operations', []):
                    if row['status'] in ('requested', 'pending'):
                        row.update(status='unknown', reason='Owner heartbeat lost before a final result; never replay into a different run')
                if (lab.get('demo') or {}).get('status') == 'running':
                    lab['demo'].update(status='interrupted', reason='Runner heartbeat lost; restoration and cleanup are unverified')
        except (OSError, ValueError):
            lab = dict(status='unavailable', reason='This run has no live workspace control channel. Start a presentation workspace to enable traffic and service actions. If an older interactive Mininet session is still running, exit it in its terminal first.')
        try:
            mode = read_json(Path(runtime) / 'escalation-mode.json', 1024)
            if not isinstance(mode, dict) or set(mode) != {'mode'} or mode['mode'] not in ('off', 'observe', 'enforce'):
                raise ValueError('Invalid saved mode override')
        except FileNotFoundError:
            mode = dict(mode=None, note='No override saved; startup configuration applies')
        except (OSError, ValueError) as error:
            mode = dict(error=str(error))
        try:
            history, audit_error = self.audit_history(runtime), None
        except (OSError, ValueError, sqlite3.Error) as error:
            history, audit_error = [], str(error)
        return dict(runtime=Path(runtime).name, served_at=time.time(), lab=lab,
                    saved_mode=mode, audit_history=history, audit_error=audit_error,
                    configurations=self.configurations(controller), runs=self.catalog(), jobs=self.job_records(),
                    diagnostics=self.diagnostics(runtime))
