"""Recovery guards only. These tests do not perform privileged cleanup."""
import copy
from pathlib import Path

import pytest

from all_blue.policy import Policy
from all_blue.workspace import Conflict
import all_blue.lab_recovery as recovery

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def recovery_state(monkeypatch):
    owner = dict(pid=999900, start='1', namespace=10, argv=['python', str(ROOT/'scripts/lab.py'), '--console'], parent=1)
    child = dict(pid=999901, start='2', namespace=11, argv=['python','-m','all_blue.traffic'], parent=999900)
    record = dict(owner=owner, processes=[child], interfaces={'ab-s1-eth1': 22}, bridge='ab-s1')
    table = {child['pid']: copy.deepcopy(child)}
    monkeypatch.setattr(recovery, 'process_identity', lambda pid: table.get(pid))
    monkeypatch.setattr(recovery, 'interface_index', lambda name: 22)
    bridge = dict(dpid='0000000000000001', ports=['ab-s1-eth1','ab-s1-eth2','ab-s1-eth3'], controller='tcp:127.0.0.1:16653')
    return record, table, bridge


def test_guard_accepts_only_matching_interrupted_process_family(recovery_state):
    record, table, bridge = recovery_state
    assert recovery.validate_recovery(record, Policy(ROOT/'config/lab.json'), bridge, ROOT) == [record['processes'][0]]
    table.clear()
    assert recovery.validate_recovery(record, Policy(ROOT/'config/lab.json'), bridge, ROOT) == []


@pytest.mark.parametrize('problem', ['live_owner','pid_reused','namespace_changed','different_arguments','unknown_port','wrong_switch','wrong_controller','different_interface','outside_family'])
def test_guard_refuses_changed_ownership_before_mutation(recovery_state, monkeypatch, problem):
    record, table, bridge = recovery_state
    child = record['processes'][0]
    if problem == 'live_owner': table[record['owner']['pid']] = record['owner']
    if problem == 'pid_reused': table[child['pid']]['start'] = 'other'
    if problem == 'namespace_changed': table[child['pid']]['namespace'] = 99
    if problem == 'different_arguments': table[child['pid']]['argv'] = ['unrelated-service']
    if problem == 'unknown_port': bridge['ports'].append('unrelated-interface')
    if problem == 'wrong_switch': bridge['dpid'] = '0000000000000002'
    if problem == 'wrong_controller': bridge['controller'] = 'tcp:127.0.0.1:9999'
    if problem == 'different_interface': monkeypatch.setattr(recovery, 'interface_index', lambda name: 99)
    if problem == 'outside_family': child['parent'] = 123
    with pytest.raises(Conflict): recovery.validate_recovery(record, Policy(ROOT/'config/lab.json'), bridge, ROOT)


def test_recovery_rejects_user_editable_manifest_even_when_invoked_by_admin(tmp_path, monkeypatch):
    (tmp_path/'ownership.json').write_text('{}')
    monkeypatch.setattr(recovery.os, 'geteuid', lambda: 0)
    with pytest.raises(Conflict, match='root-owned'):
        recovery.recover(tmp_path, Policy(ROOT/'config/lab.json'), ROOT)
