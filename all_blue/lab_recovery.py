"""Exact-run ownership records and guarded, operator-invoked orphan recovery.

Never invoked by HTTP. A surviving owner or a different bridge/interface/process
identity is a hard refusal. Records are evidence to check, not permission to kill
an arbitrary PID.
"""
import os
import json
import stat
from pathlib import Path
import signal
import subprocess
import time

from .storage import atomic_json
from .workspace import Conflict, read_json


def process_identity(pid):
    try:
        base = Path('/proc') / str(pid)
        fields = (base / 'stat').read_text().rsplit(')', 1)[1].split()
        raw = (base / 'cmdline').read_bytes()
        if len(raw) > 4096:
            raise ValueError('Owned process argument list exceeds recovery budget')
        return dict(pid=int(pid), start=fields[19], parent=int(fields[1]),
                    namespace=os.stat(base / 'ns/net').st_ino,
                    argv=raw.decode(errors='replace').strip('\0').split('\0'))
    except (FileNotFoundError, ProcessLookupError):
        return None


def interface_index(name):
    try:
        return int((Path('/sys/class/net') / name / 'ifindex').read_text())
    except FileNotFoundError:
        return None


def ownership(interfaces):
    # The owner and its descendants are the only process family the lab creates.
    owner = process_identity(os.getpid())
    table = {}
    family, pending = set(), {owner['pid']}
    for _ in range(8):
        children = set()
        for pid in pending:
            try:
                children.update(map(int, Path(f'/proc/{pid}/task/{pid}/children').read_text().split()))
            except FileNotFoundError:
                pass
        pending = children - family
        for pid in pending:
            item = process_identity(pid)
            if item:
                table[pid] = item
        family |= set(table)
        if not pending:
            break
    if len(family) > 128:
        raise ValueError('Owned process family exceeds recovery budget')
    return dict(owner=owner, processes=[table[pid] for pid in sorted(family)], interfaces=interfaces,
                observed_at=time.time(), bridge='ab-s1')


def verify_process(record):
    now = process_identity(record['pid'])
    if now is not None and any(now[key] != record[key] for key in ('start', 'namespace', 'argv')):
        raise Conflict(f"PID {record['pid']} has a different identity; recovery refused")
    return now


def bridge_details():
    def ovs(*args):
        return subprocess.run(['ovs-vsctl', '--timeout=3', *args], text=True, capture_output=True, timeout=4)
    present = ovs('br-exists', 'ab-s1')
    if present.returncode == 2:
        return None
    if present.returncode:
        raise OSError('Cannot inspect ab-s1: ' + present.stderr[:512])
    values = {}
    for key, args in {'dpid': ('get', 'bridge', 'ab-s1', 'datapath_id'),
                      'ports': ('list-ports', 'ab-s1'), 'controller': ('get-controller', 'ab-s1')}.items():
        result = ovs(*args)
        if result.returncode:
            raise OSError('Cannot inspect bridge identity: ' + result.stderr[:512])
        values[key] = result.stdout.strip().strip('"')
    values['ports'] = values['ports'].splitlines()
    return values


def validate_recovery(record, policy, bridge, root):
    """Validate the entire target set before any signal or interface deletion."""
    if verify_process(record['owner']):
        raise Conflict('Lab owner still exists. Use its console/dashboard; recovery will not interrupt it.')
    script = str((Path(root) / 'scripts/lab.py').resolve())
    owner_args = record['owner']['argv']
    if not any(Path(arg).name == 'lab.py' for arg in owner_args) or record.get('bridge') != 'ab-s1':
        raise Conflict('Missing recognized lab owner record')
    for path in Path('/proc').iterdir():
        if path.name.isdigit():
            try:
                current = process_identity(int(path.name))
            except (OSError, ValueError):
                continue
            if current and (script in current['argv'] or 'scripts/lab.py' in current['argv']):
                raise Conflict('Another lab runner exists; recovery refused')
    expected = {f'ab-s1-eth{host.port}' for host in policy.hosts.values()}
    if bridge and (bridge['dpid'] != f'{policy.datapath_id:016x}' or
                   bridge['controller'] != 'tcp:127.0.0.1:16653' or not set(bridge['ports']) <= expected):
        raise Conflict('ab-s1 identity or ports do not match this lab')
    if not set(record['interfaces']) <= expected:
        raise Conflict('Unexpected interface in recovery record')
    for name, index in record['interfaces'].items():
        current = interface_index(name)
        if current is not None and current != index:
            raise Conflict('Interface identity changed; recovery refused: ' + name)
    family = {record['owner']['pid']}
    remaining = list(record['processes'])
    if len(remaining) > 128:
        raise Conflict('Too many recovery targets')
    for _ in range(8):
        attached = [item for item in remaining if item['parent'] in family]
        family.update(item['pid'] for item in attached)
        remaining = [item for item in remaining if item not in attached]
    if remaining:
        raise Conflict('Recovery record contains a process outside the owned family')
    return [item for item in record['processes'] if verify_process(item)]


def recover(runtime, policy, root):
    if os.geteuid() != 0:
        raise PermissionError('Recovery requires administrator authentication in your terminal')
    path = Path(runtime) / 'ownership.json'
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), 'rb') as stream:
        info = os.fstat(stream.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 512000:
            raise Conflict('Recovery requires the original root-owned, non-writable ownership record')
        record = json.load(stream)
    if record.get('runtime') != str(Path(runtime).resolve()):
        raise Conflict('Ownership record belongs to another runtime')
    bridge = bridge_details()
    processes = validate_recovery(record, policy, bridge, root)
    errors = []
    try:
        for item in reversed(processes):
            if verify_process(item):
                os.kill(item['pid'], signal.SIGTERM)
        deadline = time.monotonic() + 4
        while time.monotonic() < deadline and any(verify_process(item) for item in processes):
            time.sleep(.1)
        for item in reversed(processes):
            if verify_process(item):
                os.kill(item['pid'], signal.SIGKILL)
        from scripts.lab import check_management_ports
        check_management_ports()  # Unknown remaining services forbid bridge deletion.
        if bridge:
            subprocess.run(['ovs-vsctl', '--timeout=3', 'del-br', 'ab-s1'], check=True, timeout=4)
        for name, index in record['interfaces'].items():
            if interface_index(name) == index:
                subprocess.run(['ip', 'link', 'delete', 'dev', name], check=True, timeout=4)
        time.sleep(.2)
        if bridge_details() or any(interface_index(name) for name in record['interfaces']) or any(verify_process(item) for item in processes):
            raise RuntimeError('Owned resources remain or cannot be verified absent')
    except (OSError, ValueError, RuntimeError, subprocess.SubprocessError) as error:
        errors.append(str(error))
    state = read_json(Path(runtime) / 'workspace.json', 512000)
    state.update(status='cleanup_failed' if errors else 'stopped', cleanup_errors=errors,
                 collected_at=time.time(), recovery=dict(observed_at=time.time(), errors=errors,
                     note='Operator-invoked orphan cleanup; interrupted actions were not replayed'))
    for row in state.get('operations', []):
        if row['status'] in ('requested', 'pending'):
            row.update(status='unknown', reason='Owner died; action outcome unverified, never replayed')
    if state.get('demo'):
        state['demo'].update(status='interrupted', reason='Owner died; demonstration incomplete')
    state['components'] = {'evidence': 'Recovered cleanup' if not errors else 'Cleanup unverified'}
    atomic_json(Path(runtime) / 'workspace.json', state)
    if errors:
        raise RuntimeError('; '.join(errors))
    return state['recovery']
