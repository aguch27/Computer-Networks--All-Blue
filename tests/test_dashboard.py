import json
from pathlib import Path
import threading
import time
import urllib.error
import urllib.request
import queue
import uuid
import pytest
from all_blue.admin import AdminServer
from all_blue.dashboard import DashboardServer,presentation
from all_blue.storage import atomic_json,connect_store,save_event

def test_missing_state_is_unknown_not_zero(tmp_path):
    result=presentation(tmp_path)
    assert result['controller'] is None and result['logger_server'] is None
    assert len(result['errors'])==2

def test_http_is_local_and_bounded(tmp_path):
    server=DashboardServer(('127.0.0.1',0),tmp_path)
    thread=threading.Thread(target=server.serve_forever,daemon=True); thread.start()
    base=f'http://127.0.0.1:{server.server_address[1]}'
    try:
        with urllib.request.urlopen(base+'/state.json') as response:
            assert json.load(response)['controller'] is None
            assert "default-src 'self'" in response.headers['Content-Security-Policy']
        for request,code in [(urllib.request.Request(base+'/state.json',headers={'Host':'evil.example'}),403),
                             (urllib.request.Request(base+'/block',data=b'{}'),403),
                             (urllib.request.Request(base+'/../config/lab.json'),404)]:
            try: urllib.request.urlopen(request)
            except urllib.error.HTTPError as error: assert error.code==code
            else: raise AssertionError('Invalid request accepted')
    finally:
        server.shutdown(); server.server_close(); thread.join()


def test_frontend_modules_and_artwork_are_local_allowlisted_assets(tmp_path):
    server = DashboardServer(('127.0.0.1', 0), tmp_path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f'http://127.0.0.1:{server.server_address[1]}'
    try:
        for path, content_type in [('/view.js', 'text/javascript'), ('/state.js', 'text/javascript'),
                                   ('/ocean.svg', 'image/svg+xml')]:
            with urllib.request.urlopen(base + path) as response:
                assert response.status == 200
                assert content_type in response.headers['Content-Type']
                assert response.read()
        for path in ('/storage.py', '/web/../storage.py', '/view.js?outside=1'):
            try:
                urllib.request.urlopen(base + path)
            except urllib.error.HTTPError as error:
                assert error.code == 404
            else:
                raise AssertionError('Non-allowlisted asset served')
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.fixture
def command_server(tmp_path):
    commands = queue.Queue(maxsize=2)
    admin = AdminServer(tmp_path/'admin.sock', commands)
    server = DashboardServer(('127.0.0.1', 0), tmp_path)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    origin = f'http://127.0.0.1:{server.server_address[1]}'
    state = dict(run_id=str(uuid.uuid4()), ready=True, switch_connected=True,
                 collected_at=time.time(), statistics_at=time.time(), hosts=[dict(name='h1')])
    atomic_json(tmp_path/'controller.json', state)
    body = dict(action='block', host='h1', id=str(uuid.uuid4()), run_id=state['run_id'])

    def post(payload=body, headers=None, path='/commands'):
        content = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        request = urllib.request.Request(origin+path, data=content,
            headers={'Origin': origin, 'Content-Type': 'application/json', **(headers or {})})
        try:
            response = urllib.request.urlopen(request, timeout=4)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            return response.status, json.load(response)

    try:
        yield post, body, commands, state, admin
    finally:
        admin.close()
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def test_http_forwards_only_receipt_and_operation_identity(command_server):
    post, body, commands, *_ = command_server
    status, response = post()
    assert status == 202
    assert response == dict(id=body['id'], status='requested')
    assert commands.get(timeout=1) == body
    # Filling the bounded queue produces an explicit failure, never a confirmed response.
    post(); post()
    status, response = post()
    assert status == 503 and response['status'] == 'failed'


@pytest.mark.parametrize('headers,code', [
    ({'Origin': 'http://evil.example'}, 403), ({'Origin': 'null'}, 403),
    ({'Origin': ''}, 403), ({'Host': 'evil.example'}, 403),
    ({'Sec-Fetch-Site': 'cross-site'}, 403),
    ({'Content-Type': 'text/plain'}, 415), ({'Transfer-Encoding': 'chunked'}, 400),
    ({'Content-Length': '999999999999999999999'}, 413),
])
def test_command_origin_and_framing(command_server, headers, code):
    post, _, commands, *_ = command_server
    assert post(headers=headers)[0] == code
    assert commands.empty()


@pytest.mark.parametrize('payload,code', [
    (b'x'*1025, 413), (b'', 413), (b'{', 400), ([], 400),
    ({'action': 'shell', 'host': 'h1'}, 400),
    ({'action': 'block', 'host': 'h1'}, 400),
    ({'action': 'block', 'host': ['h1']}, 400),
])
def test_invalid_commands_do_not_reach_writer(command_server, payload, code):
    post, _, commands, *_ = command_server
    assert post(payload)[0] == code
    assert commands.empty()


def test_unknown_host_invalid_id_and_extra_fields(command_server):
    post, body, commands, *_ = command_server
    for changes in (dict(host='not-a-host'), dict(id='no'), dict(run_id=[]), dict(extra=True)):
        assert post({**body, **changes})[0] == 400
    assert post(path='/block')[0] == 404
    assert commands.empty()


@pytest.mark.parametrize('changes', [dict(ready=False), dict(switch_connected=False),
    dict(collected_at=0), dict(statistics_at=0), dict(statistics_at=None)])
def test_controls_reject_unavailable_state(command_server, tmp_path, changes):
    post, _, commands, state, _ = command_server
    atomic_json(tmp_path/'controller.json', {**state, **changes})
    assert post()[0] == 503
    assert commands.empty()


def test_restart_and_lost_admin_ack_are_not_confirmation(command_server):
    post, body, commands, _, admin = command_server
    assert post({**body, 'run_id': str(uuid.uuid4())})[0] == 409
    assert commands.empty()
    admin.close()
    status, reply = post()
    assert status == 503 and reply['status'] == 'unknown'
    assert reply['id'] == body['id']


def test_dashboard_cannot_bind_to_external_interface(tmp_path):
    with pytest.raises(ValueError, match='loopback'):
        DashboardServer(('0.0.0.0', 0), tmp_path)


def test_existing_local_cli_request_remains_supported(command_server, tmp_path):
    from all_blue.admin import request
    _, _, commands, *_ = command_server
    reply = request(tmp_path, 'release', 'h1')
    assert reply['status'] == 'requested'
    command = commands.get(timeout=1)
    assert command == dict(action='release', host='h1', id=reply['id'])
    assert str(uuid.UUID(reply['id'])) == reply['id']


@pytest.mark.parametrize('mode', ['off', 'observe', 'enforce'])
def test_mode_http_is_a_queued_request_without_config_editing(command_server, tmp_path, mode):
    post, body, commands, state, _ = command_server
    state['escalation'] = dict(mode='observe', hosts={'h1': {}}, threshold=5, window_seconds=30)
    atomic_json(tmp_path/'controller.json', state)
    command = dict(action='mode', mode=mode, id=body['id'], run_id=body['run_id'])
    status, reply = post(command)
    assert status == 202 and reply == dict(id=body['id'], status='requested')
    assert commands.get(timeout=1) == command
    assert not (tmp_path/'escalation-mode.json').exists()
    for extra in ({'host': 'h1'}, {'eligible_hosts': ['h1']}, {'threshold': 3}, {'window_seconds': 10}):
        assert post({**command, **extra})[0] == 400
    assert commands.empty()


@pytest.mark.parametrize('mode', ['observe', 'enforce'])
def test_mode_http_cannot_choose_hosts_implicitly(command_server, tmp_path, mode):
    post, body, commands, state, _ = command_server
    state['escalation'] = dict(mode='off', hosts={})
    atomic_json(tmp_path/'controller.json', state)
    status, reply = post(dict(action='mode', mode=mode, id=body['id'], run_id=body['run_id']))
    assert status == 400 and 'No eligible hosts configured' in reply['error']
    assert commands.empty()
    assert post(dict(action='mode', mode='off', id=body['id'], run_id=body['run_id']))[0] == 202


def test_mode_http_invalid_offline_stale_run_and_origin(command_server, tmp_path):
    post, body, commands, state, _ = command_server
    command = dict(action='mode', mode='off', id=body['id'], run_id=body['run_id'])
    for mode in ('auto', '', None, [], True):
        assert post({**command, 'mode': mode})[0] == 400
    assert post(command, headers={'Origin': 'http://example.com'})[0] == 403
    assert post({**command, 'run_id': str(uuid.uuid4())})[0] == 409
    assert post(command, headers={'Content-Length': '²'})[0] == 400
    atomic_json(tmp_path/'controller.json', {**state, 'ready': False})
    assert post(command)[0] == 503
    assert commands.empty()
