import io
import json
import socket
import threading
import time
import uuid
from collections import deque
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from all_blue.audit import AuditClient, AuditServer, receive, send
from all_blue.controller import AllBlue, Phase
from all_blue.observability import TerminalLog
from all_blue.rules import Rule
from all_blue.storage import recent_events
from tests.test_audit import wait_for


def records(stream):
    return [json.loads(line) for line in stream.getvalue().splitlines()]


def test_slow_terminal_is_bounded_and_never_blocks_producer():
    entered, release = threading.Event(), threading.Event()
    class SlowTerminal:
        def write(self, _text):
            entered.set()
            release.wait()
        def flush(self):
            pass
    log = TerminalLog('test', True, SlowTerminal(), capacity=4)
    try:
        log.emit('first')
        assert entered.wait(1)
        started = time.monotonic()
        for index in range(10000):
            log.emit('busy', index=index)
        assert time.monotonic() - started < 1
        assert log.queue.qsize() == 4 and log.dropped == 9996
        finished = threading.Event()
        def close():
            log.close()
            finished.set()
        closer = threading.Thread(target=close, daemon=True)
        closer.start()
        # Check actual independence from the blocked sink. VM scheduling can
        # exceed the writer's join timeout, so do not time a subsecond deadline.
        assert finished.wait(3) and not release.is_set() and log.thread.is_alive()
        closer.join(1)
    finally:
        release.set()
        log.close()


def test_default_off_has_no_output_or_worker():
    stream = io.StringIO()
    log = TerminalLog('test', stream=stream)
    log.emit('operation', status='confirmed')
    assert log.thread is None and not stream.getvalue() and log.queue.empty()


def test_output_error_does_not_escape_into_caller():
    class BrokenTerminal:
        def write(self, _text):
            raise BrokenPipeError()
    log = TerminalLog('test', True, BrokenTerminal())
    try:
        log.emit('test')
        wait_for(lambda: log.error == 'BrokenPipeError')
        assert log.dropped == 1
    finally:
        log.close()


def test_tcp_verbose_correlates_commit_ack_and_client_receipt(tmp_path):
    stream = io.StringIO()
    log = TerminalLog('test', True, stream)
    server = AuditServer(('127.0.0.1', 0), tmp_path/'events.db', tmp_path/'health.json', log)
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .05})
    thread.start()
    client = AuditClient(server.server_address, str(uuid.uuid4()), trace=log)
    try:
        value = client.emit('DENY', 'confirmed', 'readback matched', operation_id='decision-1')
        wait_for(lambda: client.delivered == 1)
        wait_for(lambda: log.queue.empty())
        assert recent_events(tmp_path/'events.db') == [value]
        rows = [row for row in records(stream) if row.get('event_id') == value['id']]
        stages = [row.get('stage', row.get('delivery')) for row in rows]
        assert stages.index('validated') < stages.index('persist_pending') < stages.index('sqlite_commit_returned')
        # sendall returning and client receiving can race; both must follow commit.
        assert stages.index('sqlite_commit_returned') < stages.index('ack_sent')
        assert stages.index('sqlite_commit_returned') < stages.index('ack_received')
        assert any(row.get('operation_id') == 'decision-1' for row in rows)
        acknowledgements = client.health()['acknowledgements']
        assert acknowledgements == [dict(event_id=value['id'], operation_id='decision-1',
                                        stage='ack_received', timestamp=client.last_ack)]
        with server.health_lock:
            deliveries = list(server.deliveries)
        assert [row['stage'] for row in deliveries] == ['sqlite_commit_returned', 'ack_sent']
        assert all(row['event_id'] == value['id'] for row in deliveries)
        assert deliveries[0]['timestamp'] <= acknowledgements[0]['timestamp']
    finally:
        client.close(); server.shutdown(); thread.join(2); server.server_close(); log.close()


def test_invalid_concurrent_clients_and_failed_persistence_never_claim_ack(tmp_path, monkeypatch):
    import all_blue.audit as audit
    stream = io.StringIO(); log = TerminalLog('logger', True, stream)
    server = AuditServer(('127.0.0.1', 0), tmp_path/'events.db', tmp_path/'health.json', log)
    thread = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .05}); thread.start()
    try:
        with socket.create_connection(server.server_address, timeout=2) as first, \
                socket.create_connection(server.server_address, timeout=2) as second:
            wait_for(lambda: server.active == 2)
            send(first, {'invalid': True})
            assert first.recv(1) == b''
            import sqlite3
            monkeypatch.setattr(audit, 'save_event', Mock(side_effect=sqlite3.OperationalError('disk full')))
            value = dict(id=str(uuid.uuid4()), run_id=str(uuid.uuid4()), timestamp=time.time(),
                         action='ALLOW', status='pending', reason='test')
            send(second, value)
            assert second.recv(1) == b''
        wait_for(lambda: server.active == 0 and log.queue.empty())
        rows = records(stream)
        assert any(row.get('active') == 2 for row in rows)
        assert any(row.get('status') == 'invalid_or_io_error' for row in rows)
        assert any(row.get('stage') == 'persistence_failed' for row in rows)
        assert not any(row.get('stage') in ('sqlite_commit_returned', 'ack_sent') for row in rows)
    finally:
        server.shutdown(); thread.join(2); server.server_close(); log.close()


def test_barrier_and_mismatched_readback_never_log_confirmation():
    stream = io.StringIO(); log = TerminalLog('controller', True, stream)
    app = AllBlue.__new__(AllBlue); app.trace = log
    app.dp = SimpleNamespace(); app.operations = deque(); app.audit = Mock()
    app.active = dict(operation=app._operation('ALLOW', 'service permitted'), barrier=7,
                      phase=Phase([Rule(1, 0, 100, {})]))
    app._request_stats = Mock(); app._observe = Mock(); app._phase = Mock()
    app._fail = lambda reason: app._status(app.active['operation'], 'failed', reason)
    try:
        app.barrier(SimpleNamespace(msg=SimpleNamespace(datapath=app.dp, xid=7)))
        app._request_stats.assert_called_once_with(transaction=True)
        app.stats_pending = dict(xid=8, transaction=True, rows=[], parts=0)
        app.statistics(SimpleNamespace(msg=SimpleNamespace(datapath=app.dp, xid=8, body=[], flags=0)))
        log.close()
        assert app.operations[-1]['status'] == 'failed'
        assert [step['stage'] for step in app.operations[-1]['journey']] == ['requested', 'barrier_ack', 'failed']
        assert any(row['kind'] == 'barrier_ack' and row['status'] == 'pending' for row in records(stream))
        assert not any(row.get('status') == 'confirmed' for row in records(stream))
        app._phase.assert_not_called()
    finally:
        log.close()


def test_terminal_mode_command_uses_existing_admin_queue(monkeypatch, capsys):
    from all_blue.__main__ import main
    import all_blue.admin as admin
    request = Mock(return_value=dict(id='queued', status='requested'))
    monkeypatch.setattr(admin, 'request', request)
    monkeypatch.setattr('sys.argv', ['all_blue', '--runtime', 'local-run', 'mode', 'observe'])
    main()
    request.assert_called_once_with('local-run', 'mode', mode='observe')
    assert json.loads(capsys.readouterr().out)['status'] == 'requested'


def test_verbose_openflow_failure_uses_bounded_output_before_fail_closed():
    stream = io.StringIO(); log = TerminalLog('controller', True, stream)
    app = AllBlue.__new__(AllBlue); app.trace = log; app.dp = object()
    app.logger = Mock(); app._fail = Mock()
    try:
        app.openflow_error(SimpleNamespace(msg=SimpleNamespace(datapath=app.dp, type=3, code=2, xid=8, data=b'invalid')))
        app.logger.error.assert_not_called()
        app._fail.assert_called_once()
        log.close()
        assert any(row['kind'] == 'openflow_error' and row['status'] == 'failed' for row in records(stream))
    finally:
        log.close()
