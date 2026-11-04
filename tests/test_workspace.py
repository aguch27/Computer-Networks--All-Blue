"""Workspace boundaries and local integration; these tests are not Mininet evidence."""
import json
import os
from pathlib import Path
import queue
import threading
import time
import urllib.error
import urllib.request
import uuid

import pytest

from all_blue.dashboard import DashboardServer
from all_blue.lab_control import LabWorkspace, request_lab, validate_lab
from all_blue.policy import Policy
from all_blue.storage import atomic_json
from all_blue.workspace import Conflict, Workspace, local_lock
from scripts.workspace import command_for

ROOT = Path(__file__).resolve().parents[1]

@pytest.fixture
def workspace_root(tmp_path):
    (tmp_path / 'config').mkdir()
    for name in ('lab.json', 'escalation-lab.json'):
        (tmp_path / 'config' / name).write_bytes((ROOT / 'config' / name).read_bytes())
    (tmp_path / 'runtime/lab-20261030-test').mkdir(parents=True)
    return tmp_path

@pytest.fixture
def http_workspace(workspace_root):
    runtime = workspace_root / 'runtime/lab-20261030-test'
    server = DashboardServer(('127.0.0.1', 0), runtime, root=workspace_root)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    origin = f'http://127.0.0.1:{server.server_address[1]}'
    def request(path, body=None, headers=None):
        base = {'Origin': origin, 'Content-Type': 'application/json'}
        data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
        try:
            response = urllib.request.urlopen(urllib.request.Request(origin + path, data=data, headers={**base, **(headers or {})}), timeout=4)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, response.read(), response.headers
    yield request, server, runtime
    server.shutdown(); server.server_close(); thread.join(timeout=2)


def test_workspace_assets_and_offline_inspection_are_real_local_routes(http_workspace):
    request, _, _ = http_workspace
    for name in ('observatory', 'ob-style.css', 'ob-app.js', 'ob-scene.js', 'ob-view.js', 'ob-tools.js', 'ob-guide.js', 'ob-model.js', 'ob-art.svg', 'classic'):
        code, body, headers = request('/' + name)
        assert code == 200 and body
        assert "connect-src 'self'" in headers['Content-Security-Policy']
    code, body, _ = request('/workspace.json')
    data = json.loads(body)
    assert code == 200 and data['lab']['status'] == 'unavailable'
    assert data['configurations']['policy']['data']['hosts'][0]['name'] == 'h1'
    assert data['configurations']['loaded']['policy'] is None
    assert not data['diagnostics']['available']


@pytest.mark.parametrize('path', ['/workspace/config', '/workspace/plan', '/workspace/cancel', '/workspace/lab'])
def test_all_workspace_mutations_reject_cross_origin_and_bounds(http_workspace, path):
    request, _, _ = http_workspace
    assert request(path, {}, {'Origin': 'http://elsewhere.invalid'})[0] == 403
    assert request(path, {}, {'Sec-Fetch-Site': 'cross-site'})[0] == 403
    assert request(path, {}, {'Content-Type': 'text/plain'})[0] == 415
    assert request(path, b'x' * 32769)[0] == 413
    assert request(path, b'{')[0] == 400


def test_config_save_is_validated_atomic_conflict_checked_and_not_applied(http_workspace):
    request, server, runtime = http_workspace
    config = server.workspace.configurations()['policy']
    original = config['data']
    changed = {**original, 'permission_seconds': 42}
    payload = dict(kind='policy', revision=config['revision'], data=changed)
    code, body, _ = request('/workspace/config', payload)
    assert code == 200 and json.loads(body)['applied'] is False
    assert Policy(server.workspace.root / 'config/lab.json').permission_seconds == 42
    assert not (runtime / 'controller.json').exists()
    assert request('/workspace/config', payload)[0] == 409
    config = server.workspace.configurations()['policy']
    for invalid in ({**changed, 'allow': [{'source': 'h1', 'destination': 'h2', 'port': 0}]},
                    {**changed, 'permission_seconds': 121}, {**changed, 'unknown': 1},
                    {**changed, 'hosts': [changed['hosts'][0], changed['hosts'][0]]}):
        assert request('/workspace/config', dict(kind='policy', revision=config['revision'], data=invalid))[0] == 400
    assert server.workspace.configurations()['policy']['revision'] == config['revision']
    escalation = server.workspace.configurations()['escalation']
    invalid = {**escalation['data'], 'eligible_hosts': []}
    assert request('/workspace/config', dict(kind='escalation', revision=escalation['revision'], data=invalid))[0] == 400
    assert request('/workspace/config', dict(kind='escalation', revision=escalation['revision'], data={**invalid, 'mode': 'off'}))[0] == 200


def test_terminal_job_handoff_never_spawns_process_and_rejects_conflicts(http_workspace, monkeypatch):
    request, server, _ = http_workspace
    def forbidden(*args, **kwargs):
        raise AssertionError('HTTP attempted to spawn a process')
    monkeypatch.setattr('subprocess.Popen', forbidden)
    command = dict(kind='start', profile='baseline', trials=3)
    code, body, _ = request('/workspace/plan', command)
    job = json.loads(body)
    assert code == 200 and job['status'] == 'awaiting_terminal'
    assert job['terminal'].startswith('sudo ') and '--job ' + job['id'] in job['terminal']
    assert server.workspace.job_records()[0]['id'] == job['id']
    assert request('/workspace/plan', command)[0] == 409
    assert request('/workspace/cancel', {'id': job['id']})[0] == 200
    assert request('/workspace/plan', {**command, 'kind': 'shell'})[0] == 400
    assert request('/workspace/plan', {**command, 'profile': 'inferred-hosts'})[0] == 400
    assert request('/workspace/plan', {**command, 'trials': 100})[0] == 400
    assert request('/workspace/plan', {**command, 'kind': 'benchmark', 'profile': 'escalation'})[0] == 400
    assert request('/workspace/plan', {**command, 'path': '/etc/passwd'})[0] == 400
    assert '--workspace' in command_for(command)
    assert '--escalation' not in command_for(command)
    assert '--escalation' in command_for({**command, 'profile': 'escalation'})
    assert 'scripts/benchmark.py' in ' '.join(command_for({**command, 'kind': 'benchmark'}))


def test_config_and_job_disk_failures_are_reported_without_success(http_workspace, monkeypatch):
    request, server, _ = http_workspace
    config = server.workspace.configurations()['policy']
    def fail(*args): raise OSError('Simulated disk failure')
    monkeypatch.setattr('all_blue.workspace.atomic_json', fail)
    assert request('/workspace/config', dict(kind='policy', revision=config['revision'], data=config['data']))[0] == 503
    assert request('/workspace/plan', dict(kind='start', profile='baseline', trials=3))[0] == 503


def test_known_reports_only_and_incomplete_invalid_runs_remain_visible(http_workspace, workspace_root):
    request, server, runtime = http_workspace
    atomic_json(runtime / 'acceptance.json', {'status': 'failed', 'passed': [], 'error': '<script>bad()</script>', 'started_at': 1})
    invalid = workspace_root / 'runtime/lab-20261030-invalid'; invalid.mkdir()
    (invalid / 'acceptance.json').write_text('{')
    incomplete = workspace_root / 'runtime/lab-20261030-incomplete'; incomplete.mkdir()
    benchmark = workspace_root / 'runtime/benchmark-20261030-test'; benchmark.mkdir()
    atomic_json(benchmark / 'measurements.json', [{'mode': 'static', 'scenario': 'allow', 'valid': False, 'metrics': {}, 'error': 'no measurement'}])
    statuses = {row['name']: row['status'] for row in server.workspace.catalog()}
    assert statuses[runtime.name] == 'failed' and statuses[invalid.name] == 'invalid'
    assert statuses[incomplete.name] == 'incomplete' and statuses[benchmark.name] == 'invalid'
    code, body, headers = request('/workspace/report?run=' + runtime.name + '&file=acceptance.json&download=1')
    assert code == 200 and json.loads(body)['status'] == 'failed'
    assert 'attachment' in headers['Content-Disposition']
    for query in ('run=../../etc&file=passwd', f'run={runtime.name}&file=../controller.json', f'run={runtime.name}&file=events.sqlite3', f'run={runtime.name}&file=acceptance.json&file=other'):
        assert request('/workspace/report?' + query)[0] == 404
    (runtime / 'RESULTS.md').symlink_to(workspace_root / 'config/lab.json')
    assert request('/workspace/report?run=' + runtime.name + '&file=RESULTS.md')[0] == 404
    outside = workspace_root / 'runtime/lab-20261030-link'; outside.symlink_to('/etc')
    with pytest.raises(ValueError): server.workspace.run_path(outside.name)


def test_diagnostics_are_bounded_follow_rotation_and_do_not_read_arbitrary_files(workspace_root):
    workspace = Workspace(workspace_root); runtime = workspace_root / 'runtime/lab-20261030-test'
    (runtime / 'controller-1.log').write_text('x' * 100000 + '\n' + json.dumps({'kind': 'barrier_ack', 'text': '<img src=x>'}) + '\n')
    (runtime / 'secret.log').write_text('must not be served')
    (runtime / 'logger-2.log').symlink_to(workspace_root / 'config/lab.json')
    data = workspace.diagnostics(runtime)
    assert len(data['files']) == 1 and data['files'][0]['truncated']
    assert data['records'][-1]['record']['kind'] == 'barrier_ack'
    token = data['files'][0]['token']
    (runtime / 'controller-1.log').rename(runtime / 'controller-1.log.1')
    (runtime / 'controller-1.log').write_text('new process output\n')
    data = workspace.diagnostics(runtime)
    assert len(data['files']) == 2 and any(row['token'] != token for row in data['files'])
    assert any(row['record'].get('text') == 'new process output' for row in data['records'])


def test_follow_latest_rejects_outside_runtime_pointer(workspace_root):
    workspace = Workspace(workspace_root); fallback = workspace_root / 'fallback'
    atomic_json(workspace.runs / 'latest-lab.json', {'runtime': '/outside/lab-20261030-test'})
    assert workspace.latest(fallback) == fallback
    target = workspace.runs / 'lab-20261030-test'
    atomic_json(workspace.runs / 'latest-lab.json', {'runtime': str(target)})
    assert workspace.latest(fallback) == target


def test_lab_queue_request_status_dedup_stale_and_actual_local_results(workspace_root):
    runtime = workspace_root / 'runtime/lab-20261030-test'; policy = Policy(workspace_root / 'config/lab.json')
    executions = []
    def execute(command):
        executions.append(command)
        return {'sender': {'sent': 1, 'received': 1}, 'test_source': 'unit callback, not Mininet'}
    lab = LabWorkspace(runtime, os.getuid(), os.getgid(), policy, [{'host': 'h2', 'port': 9000}], execute, lambda: {})
    try:
        lab.publish()
        command = dict(action='traffic', id=str(uuid.uuid4()), run_id=lab.state['run_id'], source='h1', destination='h2', port=9000, count=1, interval=0)
        receipt = request_lab(runtime, command)
        assert receipt == dict(id=command['id'], status='requested') and not executions
        lab.handle(lab.commands.get(timeout=1))
        assert lab.operations[-1]['status'] == 'completed' and executions == [command]
        lab.handle(command)
        assert executions == [command]
        assert lab.submit({**command, 'id': str(uuid.uuid4()), 'run_id': str(uuid.uuid4())})['status'] == 'superseded'
        lab.handle({**command, 'id': str(uuid.uuid4()), 'port': 9999})
        assert lab.operations[-1]['status'] == 'failed' and len(executions) == 1
        lab.state['busy'] = True; lab.publish()
        # Identical retries still receive their original receipt during busy work.
        assert request_lab(runtime, command)['status'] == 'requested'
        with pytest.raises(Conflict): request_lab(runtime, {**command, 'id': str(uuid.uuid4())})
        lab.state['busy'] = False; lab.publish()
        with pytest.raises(Conflict): request_lab(runtime, {**command, 'run_id': str(uuid.uuid4())})
        saved = json.loads((runtime / 'workspace.json').read_text()); saved['collected_at'] = 0
        atomic_json(runtime / 'workspace.json', saved)
        with pytest.raises(Conflict): request_lab(runtime, command)
    finally:
        lab.admin.close()


@pytest.mark.parametrize('changes', [{'count': 0}, {'count': 101}, {'interval': float('nan')}, {'interval': 2}, {'count': 100, 'interval': 1}, {'source': []}, {'action': 'shell'}, {'path': '/etc/passwd'}])
def test_lab_command_budgets_and_allowlist(changes):
    command = dict(action='traffic', id=str(uuid.uuid4()), run_id=str(uuid.uuid4()), source='h1', destination='h2', port=9000, count=1, interval=.1)
    with pytest.raises(ValueError): validate_lab({**command, **changes})


def test_network_lock_rejects_conflicting_runner(workspace_root):
    path = workspace_root / 'runtime/network.lock'
    with local_lock(path):
        with pytest.raises(Conflict):
            with local_lock(path): pass


def test_retained_audit_history_crosses_controller_runs_and_exports_only_known_database(http_workspace):
    from all_blue.storage import connect_store, save_event
    request, server, runtime = http_workspace
    store = connect_store(runtime / 'events.sqlite3')
    event = dict(id=str(uuid.uuid4()), run_id=str(uuid.uuid4()), timestamp=1,
                 action='DENY', status='confirmed', reason='Prior controller decision')
    save_event(store, event); store.close()
    data = json.loads(request('/workspace.json')[1])
    assert data['audit_history'] == [event] and data['audit_error'] is None
    assert 'events.json' in data['runs'][0]['files']
    code, body, _ = request(f'/workspace/report?run={runtime.name}&file=events.json')
    assert code == 200 and json.loads(body)['events'] == [event]
    (runtime / 'events.sqlite3').unlink()
    (runtime / 'events.sqlite3').symlink_to(server.workspace.root / 'config/lab.json')
    assert request(f'/workspace/report?run={runtime.name}&file=events.json')[0] == 404


def test_saved_mode_errors_and_interrupted_jobs_are_visible(workspace_root):
    workspace = Workspace(workspace_root); runtime = workspace.runs / 'lab-20261030-test'
    atomic_json(runtime / 'escalation-mode.json', {'mode': 'observe'})
    assert workspace.status(runtime)['saved_mode'] == {'mode': 'observe'}
    (runtime / 'escalation-mode.json').write_text('{"mode": NaN}')
    assert 'error' in workspace.status(runtime)['saved_mode']
    job = workspace.plan(dict(kind='start', profile='baseline', trials=3))
    atomic_json(workspace.job_path(job['id']), {**job, 'status': 'running', 'pid': os.getpid()})
    output = workspace.jobs / f'{job["id"]}.log'
    os.mkfifo(output)
    observed = workspace.job_records()[0]
    assert observed['status'] == 'interrupted' and observed['output'] == ''
    assert workspace.plan(dict(kind='acceptance', profile='baseline', trials=3))['status'] == 'awaiting_terminal'


@pytest.mark.parametrize('problem', ['identity', 'configuration'])
def test_terminal_handoff_rejects_changed_job_or_configuration_before_launch(workspace_root, monkeypatch, problem):
    import scripts.workspace as runner
    workspace = Workspace(workspace_root)
    job = workspace.plan(dict(kind='start', profile='baseline', trials=3))
    if problem == 'identity':
        atomic_json(workspace.job_path(job['id']), {**job, 'id': '../../outside'})
    else:
        with (workspace_root / 'config/lab.json').open('a') as stream:
            stream.write('\n')
    monkeypatch.setattr(runner, 'ROOT', workspace_root)
    monkeypatch.setattr('sys.argv', ['workspace.py', '--job', job['id']])
    monkeypatch.setattr(runner.os, 'geteuid', lambda: 0)
    def forbidden(*args, **kwargs): raise AssertionError('Rejected handoff started a process')
    monkeypatch.setattr(runner.subprocess, 'Popen', forbidden)
    with pytest.raises(SystemExit, match='identity|Configuration changed'):
        runner.main()
    assert not list(workspace.jobs.glob('*.log'))


def test_lab_lost_ack_is_unknown_and_preserves_request_identity():
    import socket
    import tempfile
    with tempfile.TemporaryDirectory(prefix='ab-workspace-') as directory:
        runtime = Path(directory); run = str(uuid.uuid4())
        atomic_json(runtime / 'workspace.json', dict(run_id=run, status='running', collected_at=time.time(), busy=False))
        listener = socket.socket(socket.AF_UNIX); listener.bind(str(runtime / 'lab.sock')); listener.listen(1)
        accepted = []
        def lose_ack():
            with listener.accept()[0] as peer:
                accepted.append(json.loads(peer.makefile('rb').readline(1024)))
            listener.close()
        worker = threading.Thread(target=lose_ack); worker.start()
        command = dict(action='shutdown', id=str(uuid.uuid4()), run_id=run)
        result = request_lab(runtime, command); worker.join(timeout=3)
        assert accepted == [command] and result['status'] == 'unknown' and result['id'] == command['id']


@pytest.mark.parametrize('component', ['controller', 'logger', 'switch'])
def test_lab_lifecycle_requires_new_recovery_evidence_and_only_touches_owned_component(workspace_root, monkeypatch, component):
    """Adapter callbacks only; no privileged network or Mininet evidence."""
    from types import SimpleNamespace
    from unittest.mock import Mock
    import all_blue.lab_control as control
    runtime = workspace_root / 'runtime/lab-20261030-test'
    policy = Policy(workspace_root / 'config/lab.json')
    initial = dict(run_id='old', ready=True, switch_connected=True, switch_epoch=3,
                   collected_at=time.time(), statistics_at=time.time(), hosts=[])
    atomic_json(runtime / 'controller.json', initial)
    atomic_json(runtime / 'logger.json', dict(server_id='old', collected_at=time.time(), deliveries=[]))
    owned = {name: Mock(pid=index + 100) for index, name in enumerate(('controller', 'logger'))}
    for process in owned.values(): process.poll.return_value = None
    before = dict(owned); stopped = []
    def stop(process): stopped.append(process); process.poll.return_value = 0
    def replacement(_name):
        process = Mock(pid=200); process.poll.return_value = None
        return process
    launch = Mock(side_effect=replacement); switch = Mock(); net = SimpleNamespace(controllers=[object()], values=lambda: [], links=[])
    bridge = [True]
    switch.stop.side_effect = lambda **kwargs: bridge.__setitem__(0, False)
    switch.start.side_effect = lambda *_: bridge.__setitem__(0, True)
    monkeypatch.setattr(control, 'owned_bridge_present', lambda: bridge[0])
    captured = {}
    class Capture:
        def __init__(self, runtime, uid, gid, policy, services, execute, health):
            captured.update(execute=execute, health=health)
            self.state = {}; self.cancel = threading.Event()
        def publish(self): captured['published'] = True
        def serve(self): assert captured.get('verifier_started')
    monkeypatch.setattr(control, 'LabWorkspace', Capture)
    allow_fresh = [False]
    def wait(predicate, description, **kwargs):
        if description.startswith('owned ab-s1'):
            assert predicate()
            return True
        assert not predicate(), 'Previous run snapshot was incorrectly accepted as recovery'
        if not allow_fresh[0]: raise AssertionError('Fresh recovery evidence unavailable')
        now = time.time()
        atomic_json(runtime / 'controller.json', {**initial, 'run_id': 'new', 'switch_epoch': 4,
                    'collected_at': now, 'statistics_at': now})
        atomic_json(runtime / 'logger.json', dict(server_id='new', collected_at=now, deliveries=[{}] * 128))
        return predicate()
    listeners = []
    def listener(host, port):
        listeners.append((host, port))
        return runtime / f'{host}-{port}.json'
    def on_ready():
        assert len(listeners) == 6 and captured['published'] and net.all_blue_workspace
        captured['verifier_started'] = True
    control.serve_lab(runtime, os.getuid(), os.getgid(), policy, net, switch, owned, launch, Mock(),
                      listener, stop, wait, on_ready=on_ready)
    command = dict(action='service', component=component, operation='restart')
    with pytest.raises(AssertionError, match='Fresh recovery'):
        captured['execute'](command)
    allow_fresh[0] = True
    result = captured['execute'](command)
    assert result['interrupted'] == component
    if component == 'switch':
        assert not stopped and not launch.called
        switch.stop.assert_called_with(deleteIntfs=False); switch.start.assert_called_with(net.controllers)
        assert result['reconciled_controller']['switch_epoch'] == 4
    else:
        assert stopped[0] is before[component] and launch.call_args.args == (component,)
        assert owned['logger' if component == 'controller' else 'controller'] is before['logger' if component == 'controller' else 'controller']
        switch.stop.assert_not_called(); switch.start.assert_not_called()
        if component == 'logger': assert result['logger']['server_id'] == 'new' and 'deliveries' not in result['logger']
        else: assert result['reconciled_controller']['run_id'] == 'new'
