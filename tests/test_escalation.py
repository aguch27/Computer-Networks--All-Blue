from dataclasses import replace
import json
from pathlib import Path

import pytest

from all_blue.escalation import Escalation, EscalationConfig
from all_blue.policy import Flow, Policy

ROOT = Path(__file__).parents[1]


@pytest.fixture
def setup():
    policy = Policy(ROOT / 'config/lab.json')
    now = [0.0]
    detector = Escalation(policy, EscalationConfig('observe', 30, 5, ('h1', 'h3')), lambda: now[0])
    flow = Flow(1, policy.hosts['h1'].mac, policy.hosts['h2'].mac,
                '10.0.0.1', '10.0.0.2', 41000, 9001)
    return detector, flow, now


def test_retries_and_client_port_changes_do_not_inflate_evidence(setup):
    detector, flow, _ = setup
    for source_port in range(41000, 41100):
        assert detector.observe(replace(flow, source_port=source_port), 2, set()) is None
    assert detector.snapshot()['hosts']['h1']['distinct_services'] == 1
    for port in (9002, 9003, 9004):
        assert detector.observe(replace(flow, destination_port=port), 2, set()) is None
    signal = detector.observe(replace(flow, destination_port=9005), 2, set())
    assert signal['distinct_services'] == 5
    assert {row['port'] for row in signal['services']} == set(range(9001, 9006))
    assert signal['policy_version'] == detector.policy.version
    assert detector.observe(replace(flow, destination_port=9006), 2, set()) is None
    assert detector.signals == 1


@pytest.mark.parametrize('flags', [0, 1, 4, 16, 18, 19, 6])
def test_only_initial_syn_can_contribute(setup, flags):
    detector, flow, _ = setup
    for port in range(9001, 9010):
        assert detector.observe(replace(flow, destination_port=port), flags, set()) is None
    assert detector.snapshot()['hosts']['h1']['distinct_services'] == 0


def test_allowed_invalid_exempt_and_blocked_sources_do_not_contribute(setup):
    detector, flow, _ = setup
    allowed = replace(flow, destination_port=9000)
    spoofed = replace(flow, source_mac='02:00:00:00:00:99')
    exempt = detector.policy.reverse(flow)
    for item, blocked in [(allowed, set()), (spoofed, set()), (exempt, set()),
                          (flow, {'h1'}), (flow, {'h2'})]:
        assert detector.observe(item, 2, blocked) is None
    assert all(row['distinct_services'] == 0 for row in detector.snapshot()['hosts'].values())


def test_expiry_and_reset_require_fresh_evidence(setup):
    detector, flow, now = setup
    for port in range(9001, 9006):
        detector.observe(replace(flow, destination_port=port), 2, set())
    now[0] = 30
    assert detector.snapshot()['hosts']['h1'] == dict(distinct_services=0, threshold_reached=False)
    assert detector.observe(flow, 2, set()) is None
    detector.reset('h1')
    assert detector.snapshot()['hosts']['h1']['distinct_services'] == 0
    detector.observe(flow, 2, set())
    detector.reset()
    assert detector.snapshot()['hosts']['h1']['distinct_services'] == 0


def test_per_host_isolation_and_bounded_storage(setup):
    detector, flow, _ = setup
    for port in range(10000, 11000):
        detector.observe(replace(flow, destination_port=port), 2, set())
    state = detector.snapshot()
    assert state['hosts']['h1']['distinct_services'] == 32
    assert state['hosts']['h3']['distinct_services'] == 0
    assert detector.signals == 1


def test_default_is_off_and_config_is_validated(tmp_path, setup):
    detector, flow, _ = setup
    disabled = Escalation(detector.policy, EscalationConfig.load(None, detector.policy))
    assert disabled.observe(flow, 2, set()) is None
    assert disabled.snapshot()['mode'] == 'off'
    config = json.loads((ROOT / 'config/escalation-lab.json').read_text())
    path = tmp_path / 'escalation.json'
    path.write_text(json.dumps(config))
    assert EscalationConfig.load(path, detector.policy).mode == 'enforce'
    for change in [{'mode': 'auto'}, {'window_seconds': True}, {'distinct_services': 33},
                   {'eligible_hosts': ['h99']}, {'eligible_hosts': []},
                   {'eligible_hosts': ['h1', 'h1']}, {'unknown_option': 1}]:
        path.write_text(json.dumps(config | change))
        with pytest.raises(ValueError):
            EscalationConfig.load(path, detector.policy)


@pytest.mark.parametrize('before,after', [('off', 'observe'), ('observe', 'enforce'),
    ('enforce', 'observe'), ('observe', 'off'), ('enforce', 'off'), ('off', 'enforce')])
def test_mode_transition_discards_partial_evidence_and_latches(setup, before, after):
    detector, flow, _ = setup
    detector.set_mode(before)
    detector.observations['h1'][('10.0.0.2', 9001)] = 0
    detector.latched.add('h1')
    original = detector.config
    detector.set_mode(after)
    assert detector.config == replace(original, mode=after)
    assert not detector.latched and not any(detector.observations.values())
    for port in range(9001, 9005):
        assert detector.observe(replace(flow, destination_port=port), 2, set()) is None
    signal = detector.observe(replace(flow, destination_port=9005), 2, set())
    assert bool(signal) == (after != 'off')
    if signal:
        assert signal['mode'] == after and signal['distinct_services'] == 5


def test_mode_cannot_infer_eligible_hosts(setup):
    detector, flow, _ = setup
    detector = Escalation(detector.policy, EscalationConfig())
    for mode in ('observe', 'enforce', 'invalid', None, []):
        with pytest.raises(ValueError):
            detector.set_mode(mode)
        assert detector.config == EscalationConfig()
        assert detector.observations == {}


def test_reselecting_current_mode_keeps_fresh_evidence(setup):
    detector, flow, _ = setup
    detector.observe(flow, 2, set())
    detector.set_mode('observe')
    assert detector.snapshot()['hosts']['h1']['distinct_services'] == 1
