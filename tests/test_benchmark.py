import json
from pathlib import Path
import subprocess
import threading
from unittest.mock import Mock

import pytest

from all_blue.policy import Policy
from all_blue.traffic import EchoServer, exchange
from scripts.benchmark import (allow_metrics, audit_drained, elapsed_ms, flow_rows, ovs_text, percentile,
                               static_rules, summarize, verify_receipts, write_results)
from scripts.lab import stop_process


def test_measured_workload_uses_real_tcp_and_independent_receipts(tmp_path):
    path = tmp_path/'receiver.json'
    server = EchoServer(('127.0.0.1', 0), path)
    worker = threading.Thread(target=server.serve_forever, kwargs={'poll_interval': .02}); worker.start()
    try:
        before = json.loads(path.read_text())
        result = exchange(*server.server_address, count=21, interval=0, measure=True)
        after = json.loads(path.read_text())
        verify_receipts(result, before, after, 21)
        metrics = allow_metrics(result, 21, 30)
        assert metrics['delivery_success_pct'] == 100
        assert result['first_flow_ms'] >= result['connect_ms'] > 0
        assert result['first_reply_ns'] > result['connect_started_ns']
        assert len(result['rtt_ms']) == 21 and metrics['steady_goodput_mbps'] > 0
        assert result['received_bytes'] == 21 * 1024
        assert metrics['steady_goodput_mbps'] == pytest.approx(
            20 * 1024 * 8000 / (result['last_reply_ns'] - result['first_reply_ns']))
    finally:
        server.shutdown(); worker.join(2); server.server_close()


@pytest.mark.parametrize('change', ['messages', 'bytes', 'token', 'client_count', 'client_error'])
def test_receiver_verification_rejects_inconsistent_evidence(change):
    before = dict(messages=4, bytes=100)
    after = dict(messages=5, bytes=1124, recent=[dict(text='abc:0:payload')])
    result = dict(received=1, sent=1, error=None, received_bytes=1024, token='abc')
    if change == 'messages': after['messages'] += 1
    if change == 'bytes': after['bytes'] += 1
    if change == 'token': after['recent'][0]['text'] = 'unrelated'
    if change == 'client_count': result['received'] = 0
    if change == 'client_error': result['error'] = 'incomplete'
    with pytest.raises(AssertionError):
        verify_receipts(result, before, after, 1)


def test_denial_requires_error_and_no_receiver_delivery():
    before = dict(messages=4, bytes=100)
    result = dict(received=0, sent=0, error='timed out')
    verify_receipts(result, before, before, 0)
    with pytest.raises(AssertionError):
        verify_receipts(result, before, dict(messages=5, bytes=100), 0)
    with pytest.raises(AssertionError):
        verify_receipts(dict(result, error=None), before, before, 0)


def test_calculations_separate_first_flow_from_steady_samples():
    result = dict(rtt_ms=[100, 1, 2, 3], connect_started_ns=0, completed_monotonic_ns=200_000_000,
                  connect_ms=90, first_flow_ms=190, steady_goodput_mbps=2, received=4)
    metrics = allow_metrics(result, 4, 30)
    assert metrics['steady_rtt_p50_ms'] == 2
    assert metrics['steady_rtt_p95_ms'] == pytest.approx(2.9)
    assert metrics['first_flow_ms'] == 190
    assert elapsed_ms(1000, 3_001_000) == 3
    with pytest.raises(ValueError): elapsed_ms(10, 9)
    with pytest.raises(ValueError): percentile([], 50)
    with pytest.raises(ValueError): percentile([float('nan')], 50)
    with pytest.raises(ValueError): allow_metrics(dict(result, completed_monotonic_ns=30_000_000_000), 4, 30)
    with pytest.raises(ValueError): allow_metrics(dict(result, steady_goodput_mbps=None), 4, 30)


def test_invalid_measurements_are_preserved_but_excluded_from_summary(tmp_path):
    rows = [dict(trial=1, mode='static', scenario='allow', valid=True, metrics=dict(first_flow_ms=2)),
            dict(trial=2, mode='static', scenario='allow', valid=False, metrics=dict(first_flow_ms=999), error='receiver mismatch')]
    summary = summarize(rows)
    assert len(summary) == 1 and summary[0]['n'] == 1 and summary[0]['mean'] == 2
    write_results(tmp_path, rows)
    assert 'receiver mismatch' in (tmp_path/'RESULTS.md').read_text()
    assert ',False,first_flow_ms,999,' in (tmp_path/'measurements.csv').read_text()
    assert '<svg' in (tmp_path/'graphs.svg').read_text()
    assert json.loads((tmp_path/'measurements.json').read_text()) == rows


def test_static_baseline_preserves_bindings_drop_and_ack_gate(tmp_path):
    rules = static_rules(Policy('config/lab.json'))
    assert len(rules) == 9
    assert sum(rule.goto == 1 for rule in rules) == 3
    assert sum(rule.priority == 0 and rule.output is None for rule in rules) == 2
    assert all(rule.hard_timeout == 0 and rule.output != 0xfffffffd for rule in rules)
    for rule in rules:
        if rule.output is None:
            continue
        assert {'in_port', 'eth_src', 'eth_dst', 'ipv4_src', 'ipv4_dst', 'ip_frag'} <= rule.fields.keys()
        if rule.fields['in_port'] == 2:
            assert rule.fields['tcp_flags'] == (16, 16) and 'tcp_dst' not in rule.fields
        else:
            assert rule.fields['tcp_dst'] == 9000 and 'tcp_src' not in rule.fields
    path = tmp_path/'flows.txt'; path.write_text('\n'.join(map(ovs_text, rules)))
    parsed = subprocess.run(['ovs-ofctl', '-O', 'OpenFlow13', 'diff-flows', str(path), str(path)],
                            capture_output=True, text=True, timeout=5)
    assert parsed.returncode == 0 and not parsed.stdout, parsed.stderr


def test_flow_parser_never_accepts_missing_switch_evidence():
    with pytest.raises(ValueError): flow_rows('')
    with pytest.raises(ValueError): flow_rows('cookie=0xab1, table=1')
    row = flow_rows(' cookie=0xab1, table=1, n_packets=12, n_bytes=500, priority=1000,tcp,tp_src=45000 actions=drop')[0]
    assert row['actions'] == 'drop' and row['n_packets'] == '12' and row['tp_src'] == '45000'


def test_empty_audit_queue_is_not_proof_of_acknowledgement():
    health = dict(backlog=0, error=None, generated=5, delivered=4, dropped=0)
    assert not audit_drained(health)
    assert audit_drained(dict(health, delivered=5))
    assert audit_drained(dict(health, dropped=1))
    assert not audit_drained(dict(health, delivered=5, backlog=1))
    assert not audit_drained(dict(health, delivered=5, error='outage'))


def test_cleanup_only_signals_owned_live_process_and_escalates_when_needed():
    done = Mock(); done.poll.return_value = 0
    stop_process(done)
    done.terminate.assert_not_called(); done.kill.assert_not_called()
    live = Mock(); live.poll.return_value = None
    live.wait.side_effect = [subprocess.TimeoutExpired('owned-child', 3), 0]
    stop_process(live)
    live.terminate.assert_called_once(); live.kill.assert_called_once()
    assert live.wait.call_count == 2


def test_benchmark_requires_privilege_and_static_is_not_a_normal_launcher_mode():
    import os
    if os.geteuid() == 0:
        pytest.skip('This rejection check needs an unprivileged account')
    for command, text in [(['scripts/benchmark.py'], 'Use sudo'), (['scripts/lab.py', '--static'], 'only valid with --benchmark')]:
        result = subprocess.run([str(Path('.venv/bin/python')), *command], capture_output=True, text=True, timeout=5)
        assert result.returncode != 0 and text in result.stderr
