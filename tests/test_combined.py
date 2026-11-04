"""Coordinated owner/console/HTTP tests. Synthetic enforcement, never Mininet."""
import copy
import json
import os
from pathlib import Path
import pty
import select
import signal
import subprocess
import threading
import time
import uuid
from collections import deque
from unittest.mock import Mock

import pytest
from playwright.sync_api import sync_playwright, expect

from all_blue.lab_actions import Cancelled, LabWorkspace, equivalent
from all_blue.lab_control import request_lab, validate_lab
from all_blue.lab_console import parse
from all_blue.storage import atomic_json
from all_blue.traffic import EchoServer, exchange
from all_blue.workspace import Conflict, Workspace
from all_blue.controller import AllBlue
from test_observatory_browser import observatory, demonstration_backend


def command(lab, **details):
    return dict(id=str(uuid.uuid4()), run_id=lab.state['run_id'], origin='terminal', **details)


def wait(predicate, timeout=8):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        result = predicate()
        if result:
            return result
        time.sleep(.03)
    raise AssertionError('Condition not observed within deadline')


def row(lab, identifier):
    return lab.ledger[identifier][1]


def test_simultaneous_clients_reserve_one_action_and_retries_survive_history_eviction(observatory, monkeypatch):
    lab = observatory['lab']; started = threading.Event(); release = threading.Event()
    original = lab.execute
    def hold(c):
        started.set(); release.wait(5); return original(c)
    lab.execute = hold
    first = command(lab, action='traffic', source='h1', destination='h2', port=9000, count=1, interval=0)
    threads = [threading.Thread(target=lambda: lab.submit(first)) for _ in range(8)]
    for thread in threads: thread.start()
    for thread in threads: thread.join()
    assert started.wait(2)
    assert lab.submit({**first, 'count': 2})['conflict']
    second = {**first, 'id': str(uuid.uuid4())}
    assert lab.submit(second)['conflict']
    assert len([r for r in lab.operations if r['id'] == first['id']]) == 1
    release.set(); wait(lambda: row(lab, first['id'])['status'] == 'completed')
    for _ in range(40):
        assert lab.submit(command(lab, action='inspect', command='nodes'))['status'] == 'requested'
    assert not any(r['id'] == first['id'] for r in lab.operations)
    assert lab.submit(first)['status'] == 'requested'
    assert len(observatory['executed']) == 1
    import all_blue.lab_actions as actions
    monkeypatch.setattr(actions, 'MAX_REQUESTS', len(lab.ledger) + 8)
    assert lab.submit(second)['conflict']  # Its original rejected outcome is immutable.
    assert lab.submit(command(lab, action='traffic', source='h3', destination='h2', port=9000, count=1, interval=0))['conflict']
    assert lab.submit(command(lab, action='cancel'))['status'] == 'requested'
    assert lab.submit({**first, 'run_id': str(uuid.uuid4())})['conflict']


def test_shutdown_cancels_long_action_keeps_reads_responsive_and_reports_cleanup_failure(observatory):
    lab = observatory['lab']; started = threading.Event()
    def long(c):
        started.set()
        if lab.cancel.wait(5): raise Cancelled('Owned client stopped')
        raise AssertionError('Cancellation did not arrive')
    lab.execute = long
    traffic = command(lab, action='traffic', source='h1', destination='h2', port=9000, count=40, interval=.5)
    lab.submit(traffic); assert started.wait(2)
    before = lab.state['started_at']; wait(lambda: json.loads((lab.runtime/'workspace.json').read_text())['collected_at'] > before + .5)
    inspection = command(lab, action='inspect', command='nodes')
    assert request_lab(lab.runtime, inspection)['status'] == 'requested'
    shutdown = command(lab, action='shutdown')
    assert request_lab(lab.runtime, shutdown)['status'] == 'requested'
    wait(lab.done.is_set)
    assert lab.state['status'] == 'stopping' and row(lab, shutdown['id'])['status'] == 'pending'
    assert row(lab, traffic['id'])['status'] == 'cancelled'
    assert lab.submit(command(lab, action='service', component='logger', operation='start'))['conflict']
    lab.close(dict(errors=['ab-s1 still present'], bridge_present=True, remaining_interfaces=['ab-s1-eth1'], remaining_processes=[]))
    final = json.loads((lab.runtime/'workspace.json').read_text())
    assert final['status'] == 'cleanup_failed'
    assert row(lab, shutdown['id'])['status'] == 'failed'
    assert final['components']['switch']['running'] is True


def test_terminal_command_allowlist_and_http_origin_cannot_be_spoofed(observatory):
    lab = observatory['lab']
    assert equivalent(parse('--override block h1', lab.state)) == '--override block h1'
    assert equivalent(parse('--override mode observe', lab.state)) == '--override mode observe'
    for line in ('nodes', 'net', 'dump', 'h1 traffic h2 9000 3 .1', 'h3 traffic h2 9001',
                 'block h1', 'release h3', 'mode observe', 'service logger restart',
                 '--override block h1', 'stop', 'shutdown'):
        validate_lab(parse(line, lab.state))
    for line in ('sh ovs-ofctl del-flows ab-s1', 'py net.stop()', 'h1 ip link set h1-eth0 down',
                 'h1 traffic h2 9000; rm anything', 'dpctl del-flows', 'source /tmp/script', 'link h1 ab-s1 down'):
        with pytest.raises(ValueError): parse(line, lab.state)
    with sync_playwright() as p:
        browser = p.chromium.launch(); page = browser.new_page()
        page.goto(observatory['origin']+'/observatory')
        result = page.evaluate("""async c => { const r = await fetch('/workspace/lab', {method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(c)}); return r.status }""", command(lab, action='shutdown'))
        assert result == 400  # Origin is assigned by HTTP, never a browser payload.
        assert not lab.done.is_set()
        browser.close()


def test_real_echo_correlates_simultaneous_clients_without_aggregate_counts(tmp_path):
    receiver = tmp_path/'receipts.json'
    server = EchoServer(('127.0.0.1', 0), receiver)
    worker = threading.Thread(target=server.serve_forever); worker.start()
    ids = [str(uuid.uuid4()) for _ in range(2)]; results = {}
    def send(index): results[index] = exchange('127.0.0.1', server.server_address[1], 45, .001, request_id=ids[index])
    clients = [threading.Thread(target=send, args=(i,)) for i in range(2)]
    try:
        for client in clients: client.start()
        for client in clients: client.join(timeout=8)
        receipts = json.loads(receiver.read_text())
        assert receipts['messages'] == 90 and len(receipts['recent']) == 32
        for i in range(2):
            assert results[i]['received'] == 45
            matching = receipts['requests'][ids[i]]
            assert sorted(matching['sequences']) == list(range(45))
            assert matching['source_port'] == results[i]['source_port']
        assert results[0]['source_port'] != results[1]['source_port']
    finally:
        server.shutdown(); server.server_close(); worker.join(timeout=2)


def test_writer_rejects_old_restoration_even_when_later_block_is_same_value():
    app = AllBlue.__new__(AllBlue); app.run_id = str(uuid.uuid4()); app.operations = deque(); app.audit = Mock()
    later, demo = str(uuid.uuid4()), str(uuid.uuid4())
    app.control_revisions = {'h1': later, '@mode': later}; app._host_action = Mock(); app._mode_action = Mock()
    for details in (dict(action='release', host='h1'), dict(action='mode', mode='off')):
        app._command(dict(details, id=str(uuid.uuid4()), run_id=app.run_id, if_revision=demo))
        assert app.operations[-1]['status'] == 'superseded'
    app._host_action.assert_not_called(); app._mode_action.assert_not_called()


@pytest.mark.parametrize('target', ['host', 'mode'])
def test_manual_override_preserves_later_choice_and_marks_restoration_attention(demonstration_backend, target):
    context = demonstration_backend; lab = context['lab']; state = context['source']['controller']
    execute = lab.execute; started = threading.Event(); release = threading.Event()
    def held(c):
        held_step = (target == 'host' and state['hosts'][0]['block_confirmed']) or (
            target == 'mode' and state['escalation']['mode'] == 'observe' and c['port'] == 9005)
        if held_step:
            started.set(); release.wait(5)
        return execute(c)
    lab.execute = held
    demo = command(lab, action='demo', kind='block' if target == 'host' else 'escalation', host='h1')
    lab.submit(demo); assert started.wait(8)
    manual = command(lab, action='block', host='h1', override=True) if target == 'host' else command(lab, action='mode', mode='enforce', override=True)
    assert request_lab(lab.runtime, manual)['status'] == 'requested'
    release.set()
    wait(lambda: row(lab, manual['id'])['status'] == 'confirmed', 10)
    assert 'Restoration requires attention' in row(lab, demo['id'])['reason']
    key = 'h1' if target == 'host' else '@mode'
    assert state['control_revisions'][key] == manual['id']
    assert state['hosts'][0]['block_confirmed'] if target == 'host' else state['escalation']['mode'] == 'enforce'


def test_two_browser_tabs_refresh_follow_backend_demo_and_shutdown_remains_available(demonstration_backend):
    context = demonstration_backend; lab = context['lab']; execute = lab.execute
    started = threading.Event(); release = threading.Event()
    def held(c):
        started.set(); release.wait(8); return execute(c)
    lab.execute = held
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(); first = browser.new_page(); second = browser.new_page()
            errors = []; first.on('pageerror', lambda e: errors.append(str(e))); second.on('pageerror', lambda e: errors.append(str(e)))
            for page in (first, second): page.goto(context['origin']+'/observatory')
            expect(first.locator('#run-demo')).to_be_enabled(); first.locator('#run-demo').click()
            assert started.wait(3)
            expect(second.locator('#run-demo')).to_be_disabled(timeout=5000)
            expect(second.locator('#shutdown-lab')).to_be_enabled()
            expect(second.locator('#stop-demo')).to_be_enabled()
            first.reload(); expect(first.locator('#demo-status')).to_contain_text('running')
            rival = command(lab, action='demo', kind='block', host='h3'); rival.pop('origin')
            response = second.request.post(context['origin']+'/workspace/lab',data=rival,headers={'Origin':context['origin']})
            assert response.status == 409
            second.locator('#stop-demo').click(); release.set()
            expect(first.locator('#demo-status')).to_contain_text('Demonstration stopped',timeout=10000)
            expect(second.locator('#demo-status')).to_contain_text('Demonstration stopped',timeout=10000)
            assert len(context['executed']) == 1 and not errors
            first.screenshot(path=str(context['runtime']/'combined-browser.png'), full_page=True)
            browser.close()
    finally: release.set()


def test_stale_runner_marks_interrupted_without_claiming_cleanup_and_rejects_retry(observatory):
    lab = observatory['lab']; lab.closed.set(); lab.publisher.join(timeout=2)
    lab.publish()
    path = lab.runtime/'workspace.json'; snapshot = json.loads(path.read_text())
    snapshot.update(collected_at=time.time()-20, status='running', demo=dict(status='running'))
    snapshot['operations'] = [dict(id=str(uuid.uuid4()), status='pending', action='shutdown')]
    atomic_json(path, snapshot)
    visible = Workspace(observatory['root']).status(lab.runtime)['lab']
    assert visible['status'] == 'interrupted' and visible['operations'][0]['status'] == 'unknown'
    assert visible['demo']['status'] == 'interrupted' and not visible.get('cleanup')
    with pytest.raises(Conflict): request_lab(lab.runtime, command(lab, action='shutdown'))


def test_attached_pty_console_shares_history_and_eof_detaches_without_shutdown(observatory):
    lab = observatory['lab']; lab.state['inspection']['nodes'] = 'ab-controller ab-s1 h1 h2 h3'; lab.publish()
    master, slave = pty.openpty()
    process = subprocess.Popen(['.venv/bin/python','scripts/console.py','--runtime',str(lab.runtime)], stdin=slave,stdout=slave,stderr=slave,start_new_session=True)
    os.close(slave); output = bytearray()
    def contains(text):
        if select.select([master],[],[],.1)[0]:
            try: output.extend(os.read(master,16384))
            except OSError: pass
        return text.encode() in output
    try:
        wait(lambda: contains('mininet>'))
        os.write(master,b'nodes\n'); wait(lambda: contains('ab-controller ab-s1 h1 h2 h3'))
        dashboard = command(lab, action='traffic', source='h3', destination='h2', port=9000, count=2, interval=0)
        dashboard['origin'] = 'dashboard'; request_lab(lab.runtime, dashboard)
        wait(lambda: contains(dashboard['id']) and contains('completed'))
        os.write(master,b'h1 traffic h2 9000 2 0\n')
        wait(lambda: len(observatory['executed']) == 2)
        assert observatory['executed'][-1]['origin'] == 'terminal'
        wait(lambda: any(r['origin'] == 'terminal' and r['action'] == 'traffic' and r['status'] == 'completed' for r in lab.operations))
        os.kill(process.pid, signal.SIGINT); wait(lambda: any(r['action'] == 'cancel' for r in lab.operations))
        os.write(master,b'\x04'); process.wait(timeout=3)
        assert process.returncode == 0 and not lab.done.is_set()
        assert lab.state['status'] == 'running'
    finally:
        if process.poll() is None: process.terminate(); process.wait(timeout=3)
        os.close(master)


def test_combined_acceptance_driver_records_real_http_results_with_explicit_synthetic_enforcement(demonstration_backend):
    """Test harness plumbing with loopback clients; not a Mininet acceptance run."""
    from scripts.combined_acceptance import verify
    context = demonstration_backend; lab = context['lab']; execute = lab.execute
    state = context['source']['controller']; report = {'kind': 'test_fixture_only'}
    lab.state['inspection'] = dict(nodes='synthetic nodes', net='synthetic links', dump='synthetic hosts')
    def lifecycle(c):
        if c['action'] == 'service':
            state['run_id'] = str(uuid.uuid4()); state['control_revisions'] = {}
            return {'test_source': 'synthetic restart'}
        if c['count'] == 40:
            assert lab.cancel.wait(5)
            raise Cancelled('Synthetic cancelled client')
        return execute(c)
    lab.execute = lifecycle
    verify(lab.runtime, report, lambda: None, origin=context['origin'])
    assert report['combined_valid'], report
    assert len(report['combined_checks']) == 9
    assert not any('cleanup' in c['check'] and 'verified absent' in c['check'] for c in report['combined_checks'])
    assert lab.state['status'] == 'stopping'  # Only the owner can certify cleanup later.


def test_both_dashboards_disable_controls_when_owner_is_stale_even_if_controller_is_fresh(observatory):
    lab = observatory['lab']; lab.closed.set(); lab.publisher.join(timeout=2)
    lab.publish(); path = lab.runtime/'workspace.json'; saved = json.loads(path.read_text())
    saved['collected_at'] = time.time()-30; atomic_json(path, saved)
    with sync_playwright() as p:
        browser = p.chromium.launch(); page = browser.new_page()
        page.goto(observatory['origin']+'/observatory')
        expect(page.locator('#connection')).to_have_text('Observing the lab')
        expect(page.locator('[data-host="h1"] button').first).to_be_disabled()
        expect(page.locator('#mode')).to_be_disabled()
        expect(page.locator('#lab-prerequisites')).to_contain_text('heartbeat stale')
        page.goto(observatory['origin']+'/classic')
        expect(page.locator('#connection')).to_have_text('Observing the lab')
        expect(page.locator('button[data-action="block"]').first).to_be_disabled()
        browser.close()


def test_new_owner_rejects_previous_runtime_requests_and_old_owner_cannot_be_adopted(observatory):
    lab = observatory['lab']; other = lab.runtime.parent/'lab-new'; other.mkdir()
    new = LabWorkspace(other, os.getuid(), os.getgid(), lab.policy, lab.state['services'], Mock(), lambda: {})
    try:
        old = command(lab, action='traffic', source='h1', destination='h2', port=9000, count=1, interval=0)
        assert new.submit(old)['status'] == 'superseded'
        new.execute.assert_not_called()
        with pytest.raises(RuntimeError, match='already listening'):
            LabWorkspace(lab.runtime, os.getuid(), os.getgid(), lab.policy, [], Mock(), lambda: {})
    finally:
        new.admin.close()


def test_shutdown_during_release_prevents_followup_demo_traffic(demonstration_backend):
    context = demonstration_backend; lab = context['lab']; original = lab.child
    def child(parent, details):
        result = original(parent, details)
        if details['action'] == 'release':
            lab.submit(command(lab, action='shutdown'))
        return result
    lab.child = child
    demo = command(lab, action='demo', kind='block', host='h1')
    lab.submit(demo); wait(lab.done.is_set, 12)
    assert len(context['executed']) == 1  # Initial ALLOW; synthetic BLOCK does not call the echo callback.
    assert len([r for r in lab.operations if r['action'] == 'traffic']) == 2
    assert row(lab, demo['id'])['status'] == 'failed'
    assert 'Restoration requires attention' in row(lab, demo['id'])['reason']
    assert lab.state['status'] == 'stopping' and lab.cancel.is_set()


def test_cancelled_sender_and_late_receipt_do_not_break_browser_monitoring(observatory):
    lab = observatory['lab']; started = threading.Event()
    def long(c):
        started.set()
        assert lab.cancel.wait(12)
        error = Cancelled('Owned client stopped')
        error.result = dict(sender=None, sender_status='Interrupted: exact sender totals unavailable',
                            receiver_request={'sequences': [0], 'source_port': 43000})
        raise error
    lab.execute = long
    with sync_playwright() as p:
        browser = p.chromium.launch(); page = browser.new_page()
        errors = []; page.on('pageerror', lambda error: errors.append(str(error)))
        page.goto(observatory['origin']+'/observatory')
        page.evaluate("""() => {
          const original = window.fetch;
          window.fetch = async (url, options) => {
            const response = await original(url, options);
            if (url === '/workspace/lab' && JSON.parse(options.body).action === 'traffic')
              return new Promise(resolve => { window.releaseTrafficReceipt = () => resolve(response); });
            return response;
          };
        }""")
        page.locator('#send-traffic').click(); assert started.wait(3)
        page.wait_for_function('typeof window.releaseTrafficReceipt === "function"')
        page.locator('#cancel-action').click()
        expect(page.locator('#service-result')).to_contain_text('cancel')
        page.evaluate('window.releaseTrafficReceipt()')
        expect(page.locator('#traffic-result')).to_contain_text('sender totals unavailable', timeout=7000)
        expect(page.locator('#service-result')).to_contain_text('cancel · completed', timeout=7000)
        page.reload()
        expect(page.locator('#traffic-evidence')).to_contain_text('"sender": null')
        expect(page.locator('#traffic-result')).to_contain_text('sender totals unavailable')
        expect(page.locator('#service-submit')).to_be_enabled()
        page.set_viewport_size({'width': 390, 'height': 844})
        page.locator('#cancel-action').scroll_into_view_if_needed()
        assert not page.evaluate('document.documentElement.scrollWidth > innerWidth')
        page.screenshot(path=str(observatory['runtime']/'combined-cancel-mobile.png'))
        assert not errors
        browser.close()
