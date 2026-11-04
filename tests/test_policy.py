from dataclasses import replace
import json
from pathlib import Path
import pytest
from all_blue.policy import Flow, Policy
from all_blue.rules import FULL_MASK, host_block, tuple_rules

@pytest.fixture
def policy():
    return Policy(Path(__file__).parents[1] / 'config/lab.json')

@pytest.fixture
def flow(policy):
    return Flow(1,policy.hosts['h1'].mac,policy.hosts['h2'].mac,'10.0.0.1','10.0.0.2',41000,9000)

def test_exact_service_and_block_precedence(policy,flow):
    assert policy.decide(flow,set())[0] == 'ALLOW'
    assert policy.decide(replace(flow,destination_port=9001),set())[0] == 'DENY'
    for blocked in ({'h1'},{'h2'},{'h1','h2'}):
        assert policy.decide(flow,blocked)[0] == 'BLOCK'

@pytest.mark.parametrize('change',[
    {'in_port':3},{'source_ip':'10.0.0.3'},{'source_mac':'02:00:00:00:00:03'},
    {'destination_mac':'02:00:00:00:00:03'},{'destination_ip':'10.0.0.99'},
    {'source_port':0},{'destination_port':65536}])
def test_spoofed_or_invalid_identity_denied(policy,flow,change):
    assert policy.decide(replace(flow,**change),set())[0] == 'DENY'

def test_precise_reverse_and_ingress(policy,flow):
    reverse=policy.reverse(flow)
    assert reverse.in_port == 2
    assert (reverse.source_ip,reverse.destination_ip,reverse.source_port,reverse.destination_port) == ('10.0.0.2','10.0.0.1',9000,41000)
    assert policy.decide(reverse,set())[0] == 'DENY'
    forward,back=tuple_rules(policy,flow,'ALLOW',123)
    assert back.fields['tcp_dst'] == 41000
    assert back.fields['tcp_src'] == 9000
    assert back.fields['tcp_flags'] == (16,16)
    assert back.fields['in_port'] == 2
    assert forward.hard_timeout == back.hard_timeout == policy.permission_seconds

def test_blocks_cover_ingress_and_egress_above_allow(policy,flow):
    blocks=host_block(policy.hosts['h1'])
    allow=tuple_rules(policy,flow,'ALLOW',123)
    assert all(rule.priority > allow[0].priority for rule in blocks)
    assert [r.fields for r in blocks] == [{'in_port':1},{'eth_dst':policy.hosts['h1'].mac}]

def test_reverse_syn_deny_does_not_shadow_approved_reverse_ack(policy,flow):
    reverse_allow=tuple_rules(policy,flow,'ALLOW',123)[1]
    reverse_deny=tuple_rules(policy,policy.reverse(flow),'DENY',124)[0]
    assert reverse_allow.priority > reverse_deny.priority

def test_duplicate_identity_rejected(tmp_path):
    raw=json.loads((Path(__file__).parents[1]/'config/lab.json').read_text())
    raw['hosts'][2]['mac']=raw['hosts'][0]['mac']
    path=tmp_path/'bad.json'; path.write_text(json.dumps(raw))
    with pytest.raises(ValueError,match='Duplicate'):
        Policy(path)
