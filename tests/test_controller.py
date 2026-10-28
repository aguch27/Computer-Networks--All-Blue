from collections import deque
from types import SimpleNamespace
from unittest.mock import Mock
import all_blue.controller as controller_module
from all_blue.controller import AllBlue, Phase
from all_blue.policy import Flow,Policy
from all_blue.rules import Rule

def test_newer_block_cancels_pending_first_packet():
    app=AllBlue.__new__(AllBlue)
    app.epoch=2; app.inflight={('flow',)}
    app.active=dict(kind='flow',epoch=1,key=('flow',),operation={},phases=deque([Phase()]))
    app._status=Mock(); app._next_job=Mock(); app.dp=Mock()
    app._phase()
    assert app.active is None and not app.inflight
    app.dp.send_msg.assert_not_called()
    assert app._status.call_args.args[1]=='superseded'

def test_newer_action_cancels_release_before_removing_block():
    app=AllBlue.__new__(AllBlue)
    app.epoch=2; app.inflight=set()
    app.active=dict(kind='release',epoch=1,operation={},phases=deque([Phase(deletions=[(123,0xffff)])]))
    app._status=Mock(); app._next_job=Mock(); app.dp=Mock()
    app._phase()
    app.dp.send_msg.assert_not_called()
    assert app.active is None

def test_readback_rejects_broadened_reverse_rule():
    rule=Rule(123,1,2000,dict(eth_type=0x0800,ip_proto=6,tcp_src=9000,tcp_dst=41000),output=1,hard_timeout=30)
    from os_ken.ofproto import ofproto_v1_3_parser as p
    from os_ken.ofproto import ofproto_v1_3 as o
    stat=SimpleNamespace(cookie=123,table_id=1,priority=2000,hard_timeout=30,
                         match=p.OFPMatch(eth_type=0x0800,ip_proto=6,tcp_src=9000),
                         instructions=[p.OFPInstructionActions(o.OFPIT_APPLY_ACTIONS,[p.OFPActionOutput(1)])])
    assert not rule.matches(stat)

def test_no_confirmation_on_missing_rule():
    app=AllBlue.__new__(AllBlue)
    dp=object(); app.dp=dp
    app.stats_pending=dict(xid=8,transaction=True,rows=[],parts=0)
    app.active=dict(phase=Phase([Rule(1,0,100,{})]))
    app._observe=Mock(); app._fail=Mock(); app._phase=Mock()
    app.statistics(SimpleNamespace(msg=SimpleNamespace(datapath=dp,xid=8,body=[],flags=0)))
    app._fail.assert_called_once()
    app._phase.assert_not_called()


def test_automatic_block_invalidates_stale_allow_and_uses_shared_writer(tmp_path):
    app=AllBlue.__new__(AllBlue)
    app.policy=SimpleNamespace(hosts={'h1':object()})
    app.ready=True; app.blocked=set(); app.epoch=3
    app.blocked_path=tmp_path/'blocked.json'
    app.jobs=deque(); app.operations=deque()
    app._next_job=Mock(); app.dp=Mock()
    evidence={'reason':'Five distinct prohibited services','distinct_services':5}
    app._host_action('block','h1','automatic-test',origin='automatic',evidence=evidence)
    assert app.epoch==4 and app.blocked=={'h1'}
    assert app.jobs[0]['kind']=='block' and app.jobs[0]['epoch']==4
    assert app.jobs[0]['operation']['origin']=='automatic'
    assert app.jobs[0]['operation']['evidence']==evidence
    app.dp.send_msg.assert_not_called()  # Only the existing writer may send flow changes.
    app._next_job.assert_called_once()


def test_failed_block_persistence_does_not_claim_or_queue_block(monkeypatch,tmp_path):
    app=AllBlue.__new__(AllBlue)
    app.policy=SimpleNamespace(hosts={'h1':object()})
    app.ready=True; app.blocked=set(); app.epoch=3
    app.blocked_path=tmp_path/'blocked.json'
    app.jobs=deque(); app.operations=deque()
    app._next_job=Mock(); app._status=Mock()
    def unavailable(*args): raise OSError('Simulated disk failure')
    monkeypatch.setattr(controller_module,'atomic_json',unavailable)
    app._host_action('block','h1','failed-test',origin='automatic',evidence={'reason':'Threshold'})
    assert app.epoch==3 and not app.blocked and not app.jobs
    assert app._status.call_args.args[1]=='failed'
    app._next_job.assert_not_called()


def test_failed_release_persistence_preserves_intent_and_fails_closed(monkeypatch,tmp_path):
    app=AllBlue.__new__(AllBlue)
    app.epoch=3; app.blocked={'h1'}; app.blocked_path=tmp_path/'blocked.json'
    app.active=dict(kind='release',host='h1',epoch=3,operation={})
    app.escalation=Mock(); app._fail=Mock(); app._next_job=Mock(); app._status=Mock()
    def unavailable(*args): raise OSError('Simulated disk failure')
    monkeypatch.setattr(controller_module,'atomic_json',unavailable)
    app._complete()
    assert app.blocked=={'h1'}
    app._fail.assert_called_once()
    app._status.assert_not_called()
    app.escalation.reset.assert_not_called()


def test_admin_command_uses_writer_once_and_rejects_previous_run():
    app = AllBlue.__new__(AllBlue)
    app.run_id = 'current-run'
    app.operations = deque()
    app._host_action = Mock()
    app.audit = Mock()
    command = dict(id='request-one', action='block', host='h1', run_id='previous-run')
    app._command(command)
    assert app.operations[-1]['status'] == 'superseded'
    app._host_action.assert_not_called()
    app._command(command)
    assert len(app.operations) == 1
    command = {**command, 'id': 'request-two', 'run_id': app.run_id}
    app._command(command)
    app._host_action.assert_called_once_with('block', 'h1', 'request-two')


def test_host_command_offline_has_failed_operation_without_switch_write():
    app = AllBlue.__new__(AllBlue)
    app.run_id = 'current-run'; app.operations = deque(); app.audit = Mock()
    app.policy = SimpleNamespace(hosts={'h1': object()})
    app.ready = False; app.jobs = deque(); app.dp = Mock(); app._next_job = Mock()
    app._command(dict(id='offline', action='release', host='h1'))
    assert app.operations[-1]['status'] == 'failed'
    assert not app.jobs
    app.dp.send_msg.assert_not_called()
    app._next_job.assert_not_called()


def test_repeated_request_id_does_not_enqueue_two_host_changes(tmp_path):
    app = AllBlue.__new__(AllBlue)
    app.run_id = 'run'; app.operations = deque(); app.audit = Mock()
    app.policy = SimpleNamespace(hosts={'h1': object()})
    app.ready = True; app.blocked = set(); app.epoch = 3
    app.blocked_path = tmp_path/'blocked.json'; app.jobs = deque(); app._next_job = Mock()
    command = dict(id='one-request', run_id='run', action='block', host='h1')
    app._command(command)
    app._command(command)
    assert len(app.jobs) == len(app.operations) == 1
    assert app.epoch == 4 and app.blocked == {'h1'}
    app._next_job.assert_called_once()


import json
import pytest
from all_blue.controller import load_mode_override
from all_blue.escalation import Escalation, EscalationConfig
from all_blue.storage import atomic_json


@pytest.fixture
def mode_app(tmp_path):
    app = AllBlue.__new__(AllBlue)
    app.run_id = 'run'; app.operations = deque(); app.audit = Mock()
    app.policy = Policy('config/lab.json')
    app.escalation = Escalation(app.policy, EscalationConfig('observe', 45, 6, ('h1',)))
    app.mode_path = tmp_path/'escalation-mode.json'; app.mode_error = None
    app.ready = True; app.epoch = 12; app.blocked = {'h3'}
    app.blocked_path = tmp_path/'blocked.json'; atomic_json(app.blocked_path, ['h3'])
    app.jobs = deque([{'kind': 'release', 'host': 'h3', 'epoch': 12}])
    app.active = {'kind': 'flow', 'action': 'ALLOW', 'epoch': 12}
    app.dp = Mock(); app._next_job = Mock()
    return app


def test_mode_change_persists_before_confirmation_without_touching_writer(mode_app, monkeypatch):
    app = mode_app
    app.escalation.observations['h1'][('10.0.0.2', 9001)] = app.escalation.clock()
    app.escalation.latched.add('h1')
    active = app.active; jobs = list(app.jobs); blocks = app.blocked_path.read_bytes()
    def save(path, value):
        assert app.operations[-1]['status'] == 'pending'
        assert app.escalation.config.mode == 'observe'
        atomic_json(path, value)
    monkeypatch.setattr(controller_module, 'atomic_json', save)
    app._command(dict(action='mode', mode='enforce', id='change', run_id='run'))
    assert app.operations[-1]['status'] == 'confirmed'
    assert app.operations[-1]['mode'] == 'enforce'
    assert 'saved and applied' in app.operations[-1]['reason']
    assert json.loads(app.mode_path.read_text()) == {'mode': 'enforce'}
    assert app.escalation.config == EscalationConfig('enforce', 45, 6, ('h1',))
    assert not app.escalation.latched and not any(app.escalation.observations.values())
    assert app.epoch == 12 and app.active is active and list(app.jobs) == jobs
    assert app.blocked == {'h3'} and app.blocked_path.read_bytes() == blocks
    app.dp.send_msg.assert_not_called(); app._next_job.assert_not_called()
    assert app.audit.emit.call_args.kwargs['mode'] == 'enforce'


@pytest.mark.parametrize('after_rename', [False, True])
def test_mode_persistence_failure_is_visible_and_preserves_live_state(mode_app, monkeypatch, after_rename):
    app = mode_app
    atomic_json(app.mode_path, {'mode': 'observe'})
    app.escalation.observations['h1'][('10.0.0.2', 9001)] = app.escalation.clock()
    def failure(path, value):
        if after_rename:
            atomic_json(path, value)
        raise OSError('simulated disk failure')
    monkeypatch.setattr(controller_module, 'atomic_json', failure)
    app._command(dict(action='mode', mode='enforce', id='fail'))
    assert app.operations[-1]['status'] == 'failed'
    assert 'Live mode unchanged' in app.mode_error and 'before restart' in app.mode_error
    assert app.escalation.config.mode == 'observe'
    assert app.escalation.snapshot()['hosts']['h1']['distinct_services'] == 1
    assert json.loads(app.mode_path.read_text()) == {'mode': 'enforce' if after_rename else 'observe'}
    assert app.blocked == {'h3'} and app.epoch == 12
    app.dp.send_msg.assert_not_called()


def test_mode_requests_offline_invalid_empty_hosts_and_old_run(mode_app):
    app = mode_app
    cases = [('off', False, 'run', 'failed'), ('other', True, 'run', 'failed'),
             ('off', True, 'old', 'superseded')]
    for index, (mode, ready, run, status) in enumerate(cases):
        app.ready = ready
        app._command(dict(action='mode', mode=mode, id=str(index), run_id=run))
        assert app.operations[-1]['status'] == status
    assert not app.mode_path.exists()
    app.escalation = Escalation(app.policy, EscalationConfig())
    for mode in ('observe', 'enforce'):
        app._command(dict(action='mode', mode=mode, id=mode))
        assert app.operations[-1]['status'] == 'failed'
        assert 'No eligible hosts configured' in app.operations[-1]['reason']
        assert not app.mode_path.exists()
    app._command(dict(action='mode', mode='off', id='valid-off'))
    assert app.operations[-1]['status'] == 'confirmed'
    assert json.loads(app.mode_path.read_text()) == {'mode': 'off'}
    app.dp.send_msg.assert_not_called()


@pytest.mark.parametrize('startup', ['off', 'observe', 'enforce'])
@pytest.mark.parametrize('saved', ['off', 'observe', 'enforce'])
def test_saved_mode_overrides_startup_and_preserves_config(tmp_path, startup, saved):
    path = tmp_path/'mode.json'
    config = EscalationConfig(startup, 45, 6, ('h1',))
    assert load_mode_override(config, path) == (config, None)
    atomic_json(path, {'mode': saved})
    restored, error = load_mode_override(config, path)
    assert error is None and restored == EscalationConfig(saved, 45, 6, ('h1',))
    assert json.loads(path.read_text()) == {'mode': saved}


@pytest.mark.parametrize('contents', ['{', '[]', '{"mode":"auto"}', '{"mode":null}',
    '{"mode":"enforce","eligible_hosts":["h2"]}', ' '*1025])
def test_bad_saved_mode_is_reported_without_silently_enforcing(tmp_path, contents):
    path = tmp_path/'mode.json'; path.write_text(contents)
    config = EscalationConfig('enforce', 45, 6, ('h1',))
    restored, error = load_mode_override(config, path)
    assert restored == EscalationConfig('off', 45, 6, ('h1',))
    assert error.startswith('Cannot load saved escalation mode')
    assert path.read_text() == contents


def test_saved_mode_cannot_select_hosts_or_hide_read_errors(tmp_path):
    path = tmp_path/'mode.json'
    atomic_json(path, {'mode': 'enforce'})
    restored, error = load_mode_override(EscalationConfig(), path)
    assert restored == EscalationConfig() and 'No eligible hosts' in error
    restored, error = load_mode_override(EscalationConfig(), tmp_path)
    assert restored == EscalationConfig() and 'Cannot load saved' in error
