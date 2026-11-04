import errno
from itertools import chain, repeat
import socket

import pytest

from scripts.lab import check_management_ports, wait_for_dashboard_counters, wait_for_permission_expiry


def test_port_check_allows_immediate_reuse_after_a_closed_connection():
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('127.0.0.1', 0))
        address = listener.getsockname()
        listener.listen()
        with socket.create_connection(address, timeout=2) as client:
            accepted, _ = listener.accept()
            accepted.close()  # Active close leaves this local port in TIME_WAIT.
            assert client.recv(1) == b''
    check_management_ports((address[1],))


def test_port_check_still_refuses_an_active_listener():
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
        listener.listen()
        with pytest.raises(OSError) as rejected:
            check_management_ports((port,))
        assert rejected.value.errno == errno.EADDRINUSE
        assert str(port) in str(rejected.value)


def counter_panel(counts=((15, 1176), (9, 788))):
    flow = dict(source_port=41000, source_ip='10.0.0.1',
                destination_ip='10.0.0.2', destination_port=9000)
    rows = [dict(cookie=123, flow=flow.copy(), match={'in_port': port}, packets=packets, bytes=byte_count)
            for port, (packets, byte_count) in enumerate(counts, start=1)]
    return dict(controller=dict(ready=True, run_id='one-run', switch_epoch=1,
                                statistics_at=20, flows=rows),
                events=[dict(action='ALLOW', status='confirmed', flow=flow.copy())])


def counter_dump(counts=((15, 1176), (9, 788))):
    return '\n'.join(f' cookie=0x7b, table=1, n_packets={packets}, n_bytes={byte_count}, '
                     f'priority=2000,tcp,in_port={port} actions=output:{3-port}'
                     for port, (packets, byte_count) in enumerate(counts, start=1))


def test_counter_comparison_waits_for_lagging_dashboard_sample():
    # Reproduce the reported 18-packet snapshot followed by the settled 24-packet one.
    old = counter_panel(((11, 881), (7, 625)))
    snapshots = iter([old, old, counter_panel()])
    result = wait_for_dashboard_counters(lambda: next(snapshots), counter_dump, 41000, 10)
    assert result['selected_tuple_totals'] == dict(packets=24, bytes=1964)
    assert result['comparison']['attempts'] == 2
    assert result['ovs_before'] == result['ovs']


def test_counter_comparison_retries_when_switch_changes_during_dashboard_read():
    old_counts = ((11, 881), (7, 625))
    old = counter_panel(old_counts)
    snapshots = iter([old, old, counter_panel()])
    switch = iter([counter_dump(old_counts), counter_dump(), counter_dump(), counter_dump()])
    result = wait_for_dashboard_counters(lambda: next(snapshots), lambda: next(switch), 41000, 10)
    assert result['comparison']['attempts'] == 2
    assert result['selected_tuple_totals']['packets'] == 24


def test_counter_comparison_rejects_persistent_per_direction_disagreement():
    # Equal aggregate totals must not conceal incorrect forward/reverse counters.
    panel = counter_panel(((9, 788), (15, 1176)))
    with pytest.raises(AssertionError, match='last comparison=') as failed:
        wait_for_dashboard_counters(lambda: panel, counter_dump, 41000, 10, timeout=.01)
    assert "'dashboard': {1: (9, 788)" in str(failed.value)
    assert "'ovs_after': {1: (15, 1176)" in str(failed.value)


@pytest.mark.parametrize('change', ['run', 'epoch', 'stale', 'missing', 'empty_switch', 'wrong_audit'])
def test_counter_comparison_cannot_pass_invalid_or_unrelated_evidence(change):
    initial, later = counter_panel(), counter_panel()
    if change == 'run': later['controller']['run_id'] = 'new-run'
    if change == 'epoch': later['controller']['switch_epoch'] = 2
    if change == 'stale': later['controller']['statistics_at'] = 10
    if change == 'missing': later['controller']['flows'].pop()
    if change == 'wrong_audit': later['events'][0]['flow']['source_port'] = 41001
    snapshots = iter(chain([initial], repeat(later)))
    switch = (lambda: '') if change == 'empty_switch' else counter_dump
    with pytest.raises(AssertionError, match='last comparison='):
        wait_for_dashboard_counters(lambda: next(snapshots), switch, 41000, 10, timeout=.01)


def expiry_clock():
    now = [100.0]
    return now, lambda: now[0], lambda delay: now.__setitem__(0, now[0] + delay)


def test_permission_expiry_measures_rule_removal_instead_of_client_completion():
    now, clock, pause = expiry_clock()
    snapshots = iter(['OFPST_FLOW reply (OF1.3):\n' + counter_dump(),
                      'OFPST_FLOW reply (OF1.3):\n table=1, priority=0 actions=drop'])
    samples = []
    result = wait_for_permission_expiry(lambda: next(snapshots), now[0], 35, samples, clock, pause)
    assert 0 < result['seconds_after_loss'] < 1
    assert [item['remaining_permissions'] for item in samples] == [2, 0]


@pytest.mark.parametrize('late_read', [False, True])
def test_permission_expiry_keeps_deadline_strict(late_read):
    now, clock, pause = expiry_clock()
    def switch():
        if late_read:
            now[0] += 36
            return 'OFPST_FLOW reply (OF1.3):\n table=1, priority=0 actions=drop'
        return 'OFPST_FLOW reply (OF1.3):\n' + counter_dump()
    samples = []
    with pytest.raises(AssertionError, match='not observed absent within 35s'):
        wait_for_permission_expiry(switch, now[0], 35, samples, clock, pause)
    assert samples  # Failure diagnostics must survive either kind of deadline miss.


def test_permission_expiry_rejects_missing_switch_response():
    now, clock, pause = expiry_clock()
    with pytest.raises(AssertionError, match='flow reply missing'):
        wait_for_permission_expiry(lambda: '', now[0], 35, [], clock, pause)


def test_live_follower_reads_new_logs_after_restart_without_starting_services(tmp_path, monkeypatch, capsys):
    import json
    from unittest.mock import Mock
    import scripts.lab as lab
    runtime = tmp_path/'runtime'/'lab-test'; runtime.mkdir(parents=True)
    (tmp_path/'runtime'/'latest-lab.json').write_text(json.dumps(dict(runtime=str(runtime))))
    first = runtime/'controller-1.log'; first.write_text('first live record\n')
    calls = []
    def advance(_seconds):
        if calls:
            raise KeyboardInterrupt
        with first.open('a') as stream: stream.write('later record\n')
        (runtime/'controller-4.log').write_text('new controller run\n')
        calls.append(True)
    spawn = Mock(side_effect=AssertionError('A viewer must not start services'))
    monkeypatch.setattr(lab, 'ROOT', tmp_path)
    monkeypatch.setattr(lab.time, 'sleep', advance)
    monkeypatch.setattr(lab.subprocess, 'Popen', spawn)
    assert lab.follow('controller') == 0
    output = capsys.readouterr().out
    assert all(output.count(text) == 1 for text in ('first live record', 'later record', 'new controller run'))
    spawn.assert_not_called()
