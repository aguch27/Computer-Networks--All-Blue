"""Real OVS protocol tests with an unprivileged dummy datapath.

These exercise OpenFlow serialization/readback and packet injection. They do not
replace Mininet receiver tests, which need administrator-created namespaces.
"""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import time
import uuid
from urllib.request import Request, urlopen
from urllib.error import HTTPError

import pytest
from all_blue.dashboard import presentation
from all_blue.policy import Flow, Policy
from all_blue.rules import base_rules, tuple_rules
from all_blue.storage import recent_events
from os_ken.lib import pcaplib
from os_ken.lib.packet import ethernet, ipv4, packet, tcp
from os_ken.ofproto.ofproto_protocol import ProtocolDesc
from scripts.lab import wait_for_dashboard_counters, wait_for_permission_expiry

ROOT = Path(__file__).parents[1]


def wait_for(predicate, timeout=10):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        try:
            value=predicate()
            if value: return value
        except (OSError,ValueError,KeyError): pass
        time.sleep(.1)
    raise AssertionError('OVS protocol check timed out')


def test_ovs_decodes_rules_with_extension_prerequisites(tmp_path):
    if not shutil.which('ovs-ofctl'): pytest.skip('OVS tools not installed')
    policy=Policy(ROOT/'config/lab.json')
    flow=Flow(1,policy.hosts['h1'].mac,policy.hosts['h2'].mac,'10.0.0.1','10.0.0.2',41000,9000)
    datapath=ProtocolDesc(version=4)
    for index,rule in enumerate(base_rules(policy)+tuple_rules(policy,flow,'ALLOW',123)+tuple_rules(policy,flow,'DENY',124)):
        message=rule.message(datapath); message.serialize()
        path=tmp_path/f'rule-{index}.ofp'; path.write_bytes(message.buf)
        output=subprocess.check_output(['ovs-ofctl','ofp-parse',str(path)],text=True)
        assert 'decode error' not in output,output


@pytest.mark.parametrize('mode,verbose', [('off', False), ('observe', False), ('enforce', False),
                                         ('off', True), ('enforce', True)])
def test_real_ovs_handshake_rules_block_release_and_counters(tmp_path, mode, verbose):
    for binary in ('ovsdb-tool','ovsdb-server','ovs-vswitchd','ovs-vsctl','ovs-appctl','ovs-ofctl'):
        if not shutil.which(binary): pytest.skip('OVS protocol tools not installed')
    # UNIX paths must fit sockaddr_un even with long pytest directory names.
    import tempfile
    with tempfile.TemporaryDirectory(prefix='ab-of-',dir='/tmp') as short:
        work=Path(short); runtime=work/'runtime'; runtime.mkdir()
        env={**os.environ,'OVS_RUNDIR':str(work),'OVS_LOGDIR':str(work)}
        processes=[]; logs=[]
        def spawn(args,name):
            stream=(tmp_path/f'{name}.log').open('w'); logs.append(stream)
            process=subprocess.Popen(args,cwd=ROOT,env=env,stdout=stream,stderr=subprocess.STDOUT)
            processes.append(process); return process
        def run(args):
            return subprocess.check_output(args,env=env,text=True,stderr=subprocess.STDOUT,timeout=5)
        def free_port():
            with socket.socket() as probe:
                probe.bind(('127.0.0.1',0)); return probe.getsockname()[1]
        control_port,log_port,dashboard_port=free_port(),free_port(),free_port()
        def state(): return json.loads((runtime/'controller.json').read_text())
        vsctl=['ovs-vsctl','--db=unix:'+str(work/'db.sock'),'--timeout=3']
        appctl=['ovs-appctl','-t',str(work/'vswitch.ctl')]
        try:
            run(['ovsdb-tool','create',str(work/'conf.db'),'/usr/share/openvswitch/vswitch.ovsschema'])
            spawn(['ovsdb-server',str(work/'conf.db'),'--remote=punix:'+str(work/'db.sock'),
                   '--unixctl='+str(work/'db.ctl'),'--pidfile='+str(work/'db.pid')],'ovsdb')
            wait_for(lambda:(work/'db.sock').exists())
            spawn(['ovs-vswitchd','unix:'+str(work/'db.sock'),'--enable-dummy',
                   '--unixctl='+str(work/'vswitch.ctl'),'--pidfile='+str(work/'vswitch.pid')],'ovs')
            spawn([sys.executable,'-m','all_blue','--runtime',str(runtime),'logger','--port',str(log_port),
                   *(['--verbose'] if verbose else [])],'logger')
            spawn([sys.executable,'-m','all_blue','--runtime',str(runtime),'dashboard','--port',str(dashboard_port)],'dashboard')
            controller_args=[sys.executable,'-m','all_blue','--runtime',str(runtime),'controller',
                             '--port',str(control_port),'--log-port',str(log_port)]
            if verbose:
                controller_args.append('--verbose')
            if mode != 'off':
                escalation = work/'escalation.json'
                settings = json.loads((ROOT/'config/escalation-lab.json').read_text())
                settings['mode'] = mode
                escalation.write_text(json.dumps(settings))
                controller_args += ['--escalation', str(escalation)]
            controller=spawn(controller_args,'controller')
            wait_for(lambda:(runtime/'controller.json').exists())
            run(vsctl+['add-br','ab-check','--','set','Bridge','ab-check','datapath_type=dummy',
                       'fail_mode=secure','protocols=OpenFlow13','other_config:datapath-id=0000000000000001'])
            for port in (1,2,3):
                run(vsctl+['add-port','ab-check',f'p{port}','--','set','Interface',f'p{port}',
                           'type=dummy',f'ofport_request={port}',f'options:tx_pcap={work}/p{port}.pcap'])
            if mode == 'off':
                from scripts.benchmark import install_static
                install_static(Policy(ROOT/'config/lab.json'), runtime, f'unix:{work}/ab-check.mgmt', env)
                static_dump = run(['ovs-ofctl', '-O', 'OpenFlow13', 'dump-flows', f'unix:{work}/ab-check.mgmt'])
                assert 'CONTROLLER' not in static_dump and 'tcp_flags=+ack' in static_dump
                (tmp_path/'static-baseline-readback.txt').write_text(static_dump)
            run(vsctl+['set-controller','ab-check',f'tcp:127.0.0.1:{control_port}'])
            wait_for(lambda:state()['ready'])
            def inject(port=9000,source_port=41000,flags=2,source_host=1):
                frame=packet.Packet()
                frame.add_protocol(ethernet.ethernet(dst='02:00:00:00:00:02',src=f'02:00:00:00:00:0{source_host}',ethertype=0x0800))
                frame.add_protocol(ipv4.ipv4(src=f'10.0.0.{source_host}',dst='10.0.0.2',proto=6))
                frame.add_protocol(tcp.tcp(src_port=source_port,dst_port=port,bits=flags))
                frame.serialize()
                run(appctl+['netdev-dummy/receive',f'p{source_host}',bytes(frame.data).hex()])
                return bytes(frame.data)
            def delivered_frames():
                path=work/'p2.pcap'
                if not path.exists() or path.stat().st_size<24: return []
                with path.open('rb') as capture:
                    return [data for _,data in pcaplib.Reader(capture)]
            first_frame=inject()
            wait_for(lambda:any(op['action']=='ALLOW' and op['status']=='confirmed' for op in state()['operations']))
            next_frame=inject(flags=16)
            wait_for(lambda:any(row['packets']>0 and row['action']=='ALLOW' for row in state()['flows']))
            original_cookie=next(row['cookie'] for row in state()['flows'] if row['flow']['source_port']==41000)
            assert delivered_frames().count(first_frame)==1, 'First permitted packet duplicated or lost'
            assert delivered_frames().count(next_frame)==1
            reply=packet.Packet()
            reply.add_protocol(ethernet.ethernet(dst='02:00:00:00:00:01',src='02:00:00:00:00:02',ethertype=0x0800))
            reply.add_protocol(ipv4.ipv4(src='10.0.0.2',dst='10.0.0.1',proto=6))
            reply.add_protocol(tcp.tcp(src_port=9000,dst_port=41000,bits=16))
            reply.serialize()
            run(appctl+['netdev-dummy/receive','p2',bytes(reply.data).hex()])
            counters=wait_for_dashboard_counters(lambda:presentation(runtime),
                lambda:run(['ovs-ofctl','-O','OpenFlow13','dump-flows',f'unix:{work}/ab-check.mgmt']),
                41000,time.time())
            assert counters['selected_tuple_totals']['packets']==2
            (tmp_path/'dashboard-counter-evidence.json').write_text(json.dumps(counters,indent=2))
            denied_frame=inject(9001,41001)
            wait_for(lambda:any(op['action']=='DENY' and op['status']=='confirmed' for op in state()['operations']))
            def command(action, mode=None, expected='confirmed'):
                origin=f'http://127.0.0.1:{dashboard_port}'
                body=dict(action=action,id=str(uuid.uuid4()),run_id=state()['run_id'])
                body.update(dict(mode=mode) if action=='mode' else dict(host='h1'))
                try:
                    with urlopen(Request(origin+'/commands',data=json.dumps(body).encode(),
                                 headers={'Content-Type':'application/json','Origin':origin}),timeout=4) as response:
                        assert response.status==202
                        reply=json.load(response)
                except HTTPError as error:
                    with error:
                        detail=json.load(error)
                    assert expected=='rejected' and error.code==400 and 'No eligible hosts' in detail['error']
                    return
                assert reply==dict(id=body['id'],status='requested')
                return wait_for(lambda:next((op for op in state()['operations']
                    if op['id']==reply['id'] and op['status']==expected),None))
            command('block')
            assert any(h['name']=='h1' and h['block_confirmed'] for h in state()['hosts'])
            assert not state()['flows']
            blocked_frame=inject(9000,41999)
            command('release')
            assert not any(h['block_requested'] or h['block_confirmed'] for h in state()['hosts'])
            assert not state()['flows']
            inject(9000,41000)
            wait_for(lambda:any(row['flow']['source_port']==41000 for row in state()['flows']))
            assert all(row['cookie']!=original_cookie for row in state()['flows'])
            prior_run=state()['run_id']
            controller.terminate(); controller.wait(timeout=5)
            controller=spawn(controller_args,'controller-restarted')
            wait_for(lambda:state()['run_id']!=prior_run and state()['ready'])
            assert not state()['flows']
            inject(9000,41003)
            wait_for(lambda:any(row['flow']['source_port']==41003 for row in state()['flows']))
            command('block')
            prior_run=state()['run_id']
            controller.terminate(); controller.wait(timeout=5)
            controller=spawn(controller_args,'controller-block-restored')
            wait_for(lambda:state()['run_id']!=prior_run and state()['ready'])
            assert any(h['name']=='h1' and h['block_confirmed'] for h in state()['hosts'])
            assert not state()['flows']
            assert denied_frame not in delivered_frames(), 'A prohibited first packet reached the destination port'
            assert blocked_frame not in delivered_frames(), 'A blocked packet reached the destination port'

            command('release')
            for source_port in range(43000, 43007):
                inject(9011, source_port)
            wait_for(lambda:any(row['flow']['source_port']==43006 for row in state()['flows']))
            assert not any(h['block_requested'] for h in state()['hosts'])
            if mode != 'off':
                assert state()['escalation']['hosts']['h1']['distinct_services'] == 1
            inject(9012, 44000, flags=16)  # A denied ACK must not add evidence.
            allowed_before_escalation = inject(9000, 45000)
            wait_for(lambda:any(row['flow']['source_port']==45000 for row in state()['flows']))
            assert delivered_frames().count(allowed_before_escalation)==1
            for index, port in enumerate((9012, 9013, 9014, 9015)):
                inject(port, 46000+index)

            if mode == 'enforce':
                def automatic_block():
                    return next((op for op in state()['operations'] if op.get('origin')=='automatic'
                                 and op['action']=='BLOCK' and op['status']=='confirmed'), None)
                operation = wait_for(automatic_block)
                assert operation['evidence']['distinct_services']==5
                assert {item['port'] for item in operation['evidence']['services']} == set(range(9011,9016))
                assert any(h['name']=='h1' and h['block_confirmed'] for h in state()['hosts'])
                assert not state()['flows']
                blocked_existing = inject(9000, 45000, flags=16)
                blocked_new = inject(9000, 47000)
                inject(9000, 48000, source_host=3)
                wait_for(lambda:any(row['flow']['source_ip']=='10.0.0.3' for row in state()['flows']))
                assert blocked_existing not in delivered_frames()
                assert blocked_new not in delivered_frames()
                wait_for(lambda:any(event.get('operation_id')==operation['id'] and event['status']=='confirmed'
                                    and event.get('evidence',{}).get('distinct_services')==5
                                    for event in recent_events(runtime/'events.sqlite3')))
                assert json.loads((runtime/'blocked.json').read_text())==['h1']
                prior_run=state()['run_id']
                controller.terminate(); controller.wait(timeout=5)
                controller=spawn(controller_args,'controller-automatic-block-restored')
                wait_for(lambda:state()['run_id']!=prior_run and state()['ready'])
                assert any(h['name']=='h1' and h['block_confirmed'] for h in state()['hosts'])
                assert state()['escalation']['hosts']['h1']['distinct_services']==0
                command('release')
                inject(9020,49000)
                wait_for(lambda:state()['escalation']['hosts']['h1']['distinct_services']==1)
                inject(9000,49001)
                wait_for(lambda:any(row['flow']['source_port']==49001 for row in state()['flows']))
                assert not any(h['block_requested'] for h in state()['hosts'])
            else:
                wait_for(lambda:any(row['flow']['source_port']==46003 for row in state()['flows']))
                assert not any(h['block_requested'] or h['block_confirmed'] for h in state()['hosts'])
                still_allowed = inject(9000,45000,flags=16)
                wait_for(lambda:still_allowed in delivered_frames())
                if mode == 'observe':
                    assert state()['escalation']['signals']==1
                    wait_for(lambda:any(event['action']=='ESCALATION' and event['evidence']['mode']=='observe'
                                        for event in recent_events(runtime/'events.sqlite3')))
                else:
                    assert state()['escalation']['mode']=='off'
                    assert state()['escalation']['signals']==0
                assert not any(op.get('origin')=='automatic' for op in state()['operations'])
            if mode == 'off':
                command('mode', 'off')
                command('mode', 'observe', expected='rejected')
                command('mode', 'enforce', expected='rejected')
                assert json.loads((runtime/'escalation-mode.json').read_text())=={'mode':'off'}
                inject(9000,49902)
                wait_for(lambda:any(row['flow']['source_port']==49902 for row in state()['flows']))
                lost_at=time.monotonic()
                controller.terminate(); controller.wait(timeout=5)
                samples=[]
                expiry=wait_for_permission_expiry(
                    lambda:run(['ovs-ofctl','-O','OpenFlow13','dump-flows',f'unix:{work}/ab-check.mgmt']),
                    lost_at,35,samples)
                assert any(sample['remaining_permissions'] > 0 for sample in samples)
                assert expiry['seconds_after_loss'] <= 35
                after_loss=inject(9000,49903)
                assert after_loss not in delivered_frames()
                (tmp_path/'permission-expiry-evidence.json').write_text(json.dumps(
                    dict(samples=samples,expiry=expiry),indent=2))
            else:
                command('block')
                for target in ('off', 'observe', 'enforce'):
                    prior_run=state()['run_id']
                    operation=command('mode', target)
                    assert 'saved and applied' in operation['reason']
                    assert state()['run_id']==prior_run and state()['escalation']['mode']==target
                    assert any(host['name']=='h1' and host['block_confirmed'] for host in state()['hosts'])
                    assert json.loads((runtime/'escalation-mode.json').read_text())=={'mode':target}
                    controller.terminate(); controller.wait(timeout=5)
                    controller=spawn(controller_args,f'controller-saved-{target}')
                    wait_for(lambda:state()['run_id']!=prior_run and state()['ready'])
                    assert state()['escalation']['mode']==target
                    assert any(host['name']=='h1' and host['block_confirmed'] for host in state()['hosts'])
                    denied=inject(9000,51000)
                    assert denied not in delivered_frames()

                # Make only the mode destination unwritable; the controller/snapshot still run.
                mode_path=runtime/'escalation-mode.json'
                mode_path.unlink(); mode_path.mkdir()
                failure=command('mode','off',expected='failed')
                assert 'Cannot confirm saved mode' in failure['reason']
                assert state()['escalation']['mode']=='enforce'
                assert state()['escalation']['persistence_error']
                prior_run=state()['run_id']
                controller.terminate(); controller.wait(timeout=5)
                controller=spawn(controller_args,'controller-unreadable-mode')
                wait_for(lambda:state()['run_id']!=prior_run and state()['ready'])
                assert state()['escalation']['mode']=='off'
                assert 'Cannot load saved' in state()['escalation']['persistence_error']
                assert any(host['name']=='h1' and host['block_confirmed'] for host in state()['hosts'])
                mode_path.rmdir()
                command('mode','observe')
                assert state()['escalation']['persistence_error'] is None
                command('release')
                for index in range(5):
                    inject(9101+index,52000+index)
                wait_for(lambda:state()['escalation']['hosts']['h1']['threshold_reached'])
                assert not any(host['block_requested'] for host in state()['hosts'])
                command('mode','enforce')
                assert state()['escalation']['hosts']['h1']==dict(distinct_services=0,threshold_reached=False)
                for index in range(4):
                    inject(9101+index,53000+index)
                wait_for(lambda:state()['escalation']['hosts']['h1']['distinct_services']==4)
                assert not any(host['block_requested'] for host in state()['hosts'])
                inject(9105,53004)
                wait_for(lambda:any(host['name']=='h1' and host['block_confirmed'] for host in state()['hosts']))
                wait_for(lambda:any(event['action']=='MODE' and event['status']=='confirmed'
                                    and event.get('mode')=='enforce' for event in recent_events(runtime/'events.sqlite3')))
            shutil.copyfile(work/'p2.pcap',tmp_path/'destination-capture.pcap')
            (tmp_path/'final-controller.json').write_text(json.dumps(state(),indent=2))
            if verbose:
                def diagnostic_evidence():
                    def rows(paths):
                        result = []
                        for path in paths:
                            for line in path.read_text().splitlines():
                                if line.startswith('{'):
                                    try: result.append(json.loads(line))
                                    except ValueError: pass  # A writer may still be completing its last line.
                        return result
                    control = rows(tmp_path.glob('controller*.log'))
                    logged = rows([tmp_path/'logger.log'])
                    commits = {row['event_id']: row['monotonic_ns'] for row in logged if row.get('stage') == 'sqlite_commit_returned'}
                    acknowledgements = [row for row in control if row.get('delivery') == 'ack_received']
                    if not acknowledgements or not all(row['event_id'] in commits for row in acknowledgements):
                        return None
                    assert all(commits[row['event_id']] <= row['monotonic_ns'] for row in acknowledgements)
                    assert any(row['kind'] == 'barrier_ack' and row['status'] == 'pending' for row in control)
                    assert any(row['kind'] == 'phase_verified' for row in control)
                    assert not any(row['kind'] == 'openflow_error' for row in control)
                    return dict(acknowledged_event_ids=[row['event_id'] for row in acknowledgements],
                                commits_before_ack=True, verbose_records=len(control)+len(logged),
                                terminal_dropped=max(row.get('terminal_dropped',0) for row in control+logged))
                checked = wait_for(diagnostic_evidence)
                (tmp_path/'verbose-evidence.json').write_text(json.dumps(checked,indent=2))
        except BaseException:
            for path in tmp_path.glob('*.log'):
                print(path.name,path.read_text()[-6000:])
            if (runtime/'controller.json').exists(): print(state())
            raise
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
                    try: process.wait(timeout=4)
                    except subprocess.TimeoutExpired: process.kill();process.wait()
            for stream in logs:stream.close()
