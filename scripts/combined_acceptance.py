"""Opt-in real combined-mode checks; communicates only through shared interfaces.

Called exclusively by lab.py --combined-test after creating a fresh Mininet lab.
Does not type into a terminal, create networks, or mutate switch rules itself.
"""
import json
import time
import uuid
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from all_blue.lab_control import request_lab
from all_blue.workspace import Conflict, read_json
from scripts.lab import wait_for


def verify(runtime, report, save, origin='http://127.0.0.1:18080'):
    checks = report['combined_checks'] = []
    def state(): return read_json(runtime/'workspace.json', 512000)
    def controller(): return read_json(runtime/'controller.json')
    def get(path):
        with urlopen(origin+path, timeout=3) as response:
            return json.load(response)
    def post(path, command):
        with urlopen(Request(origin+path, data=json.dumps(command).encode(),
                     headers={'Content-Type':'application/json','Origin':origin}), timeout=3) as response:
            return json.load(response)
    def wait_result(identifier, status='completed'):
        def observed():
            row = next((r for r in state()['operations'] if r['id'] == identifier), None)
            if row and row['status'] in ('failed','superseded','unknown'):
                raise AssertionError(row)
            return row if row and row['status'] == status else None
        return wait_for(observed, 'combined action ' + identifier, timeout=35)
    def send(details, source='terminal', expected='completed'):
        body = dict(details, id=str(uuid.uuid4()), run_id=state()['run_id'])
        receipt = request_lab(runtime, dict(body, origin='terminal')) if source == 'terminal' else post('/workspace/lab', body)
        assert receipt['status'] == 'requested'
        return body, wait_result(body['id'], expected)
    def check(label, **evidence):
        checks.append(dict(check=label, time=time.time(), **evidence)); save()
        print('COMBINED PASS:', label, flush=True)
    def delivered(row):
        result = row['result']; sender = result['sender']; receiver = result['receiver_request']
        assert sender['request_id'] == row['id'] and sender['received'] == row['count'] and not sender['error']
        assert sorted(receiver['sequences']) == list(range(row['count']))
        assert receiver['source_port'] == sender['source_port']
        return dict(sender=sender, receiver=receiver)
    try:
        wait_for(lambda: (runtime/'workspace.json').exists(), 'combined workspace startup', timeout=25)
        for name in ('nodes','net','dump'):
            _, row = send(dict(action='inspect', command=name))
            assert row['result'] and row['origin'] == 'terminal'
        check('Console topology inspection shares the owned network')
        original_mode = controller()['escalation']['mode']
        if original_mode != 'off':
            send(dict(action='mode', mode='off'), expected='confirmed')
        first, row = send(dict(action='traffic', source='h1', destination='h2', port=9000, count=5, interval=.1))
        check('Terminal traffic has request-specific sender and receiver evidence', request=first, result=delivered(row))
        _, row = send(dict(action='traffic', source='h3', destination='h2', port=9000, count=5, interval=.1), 'dashboard')
        check('Dashboard traffic appears in shared terminal history', result=delivered(row), id=row['id'])
        assert request_lab(runtime, dict(first, origin='terminal'))['id'] == first['id']
        try:
            request_lab(runtime, dict(first, origin='terminal', count=6))
            raise AssertionError('Conflicting ID was accepted')
        except Conflict:
            pass
        check('Identical retry is retained and changed arguments rejected')
        block, row = send(dict(action='block', host='h1'), 'dashboard', 'confirmed')
        assert 'matching_readback' in [j['stage'] for j in row['result']['journey']]
        _, row = send(dict(action='traffic', source='h1', destination='h2', port=9000, count=1, interval=0))
        assert row['result']['sender']['received'] == 0 and row['result']['receiver_request'] is None
        check('Dashboard block confirmed by writer and terminal TCP denial', id=block['id'])
        send(dict(action='release', host='h1'), expected='confirmed')
        _, row = send(dict(action='traffic', source='h1', destination='h2', port=9000, count=2, interval=0), 'dashboard')
        check('Terminal release restores normal policy and dashboard delivery', result=delivered(row))
        if controller()['escalation']['hosts']:
            send(dict(action='mode', mode='observe'), expected='confirmed')
            before = controller()['run_id']
            send(dict(action='service', component='controller', operation='restart'), 'dashboard')
            def restarted():
                current = controller()
                return current if (current['run_id'] != before and current['ready']
                                   and current['escalation']['mode'] == 'observe') else None
            wait_for(restarted, 'new controller run with the saved Observe mode', timeout=25)
            check('Owned controller restart retains selected mode and reconciles')
            send(dict(action='mode', mode=original_mode), expected='confirmed')
        long = dict(action='traffic', source='h3', destination='h2', port=9000, count=40, interval=.4,
                    run_id=state()['run_id'], id=str(uuid.uuid4()), origin='terminal')
        request_lab(runtime, long)
        wait_for(lambda: any(r['id'] == long['id'] and r['status'] == 'pending' for r in state()['operations']), 'long traffic active')
        latencies = []
        for _ in range(4):
            began = time.monotonic(); assert get('/state.json')['controller']['ready']; get('/workspace.json')
            latencies.append(time.monotonic()-began)
        assert max(latencies) < 3
        check('Dashboard observations remain responsive during terminal traffic', seconds=latencies)
        # Shutdown must remain accessible while the long client is still active.
        shutdown = dict(action='shutdown', run_id=state()['run_id'], id=str(uuid.uuid4()))
        assert post('/workspace/lab', shutdown)['status'] == 'requested'
        wait_for(lambda: state()['status'] == 'stopping', 'shutdown stopping state')
        wait_result(long['id'], 'cancelled')
        check('Shutdown cancels the owned traffic process and remains pending cleanup', id=shutdown['id'])
        report['combined_valid'] = True
    except Exception as error:
        report.update(combined_valid=False, error=str(error))
        print('COMBINED FAILED:', error, flush=True)
    finally:
        save()
        try:
            if state()['status'] == 'running':
                request_lab(runtime, dict(action='shutdown', run_id=state()['run_id'], id=str(uuid.uuid4()), origin='terminal'))
        except (OSError, ValueError):
            pass
