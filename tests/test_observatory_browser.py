"""Synthetic controller/lab observations, real browser/HTTP/admin transport.

The optional echo callback is loopback TCP only, never Mininet evidence.
"""
import copy
import json
import os
from pathlib import Path
import queue
import threading
import time
import uuid

import pytest
from playwright.sync_api import sync_playwright, expect
from all_blue.admin import AdminServer
from all_blue.dashboard import DashboardServer
from all_blue.lab_control import LabWorkspace
from all_blue.policy import Policy
from all_blue.storage import atomic_json, connect_store, save_event
from all_blue.traffic import EchoServer, exchange

ROOT = Path(__file__).resolve().parents[1]

@pytest.fixture
def observatory(tmp_path):
    (tmp_path / 'config').mkdir()
    for name in ('lab.json', 'escalation-lab.json'):
        (tmp_path / 'config' / name).write_bytes((ROOT / 'config' / name).read_bytes())
    runtime = tmp_path / 'runtime/lab-20261030-browser'; runtime.mkdir(parents=True)
    policy = json.loads((tmp_path / 'config/lab.json').read_text())
    policy['hosts'][0]['label'] = '<img src=x onerror=window.injected=1> · client'
    run = str(uuid.uuid4()); event_id = str(uuid.uuid4()); operation_id = str(uuid.uuid4())
    clock = time.time()
    flow = dict(in_port=1, source_ip='10.0.0.1', destination_ip='10.0.0.2', source_port=41000, destination_port=9000)
    source = dict(freeze=False, controller=dict(run_id=run, started_at=clock, collected_at=clock,
        statistics_at=clock, switch_epoch=1, ready=True, switch_connected=True, error=None,
        policy=policy, policy_version='synthetic-browser-policy', permission_seconds=30, queue_depth=0,
        packet_ins=1, overload_drops=0, invalid_packets=0, flow_entries=9, tuple_episodes=1,
        terminal=dict(enabled=True, queued=0, dropped=0, error=None),
        hosts=[dict(**h, block_requested=False, block_confirmed=False) for h in policy['hosts']],
        flows=[dict(flow=flow, match=dict(ipv4_src='10.0.0.1', ipv4_dst='10.0.0.2', tcp_src=41000, tcp_dst=9000),
                    cookie=10, packets=10, bytes=800, action='ALLOW', direction='forward', hard_timeout=30, priority=2000)],
        observed_rules=[dict(cookie='0xa', table=1, priority=2000, match={'tcp_dst':9000}, actions=[{'output':2}], role='forward_or_controller', packets=10, bytes=800, hard_timeout=30, duration_seconds=2)],
        control_revisions={}, operations=[dict(id=operation_id, action='ALLOW', status='confirmed', reason='Synthetic readback fixture', timestamp=clock,
                         flow=flow, journey=[dict(stage='requested', timestamp=clock-.3), dict(stage='switch_updates', timestamp=clock-.2), dict(stage='barrier_ack', timestamp=clock-.1), dict(stage='matching_readback', timestamp=clock), dict(stage='confirmed', timestamp=clock)])],
        history=[dict(timestamp=clock-2, packets=4, bytes=320), dict(timestamp=clock, packets=10, bytes=800)],
        logger=dict(backlog=0, dropped=0, retries=0, delivered=1, error=None, acknowledgements=[dict(event_id=event_id, stage='ack_received', timestamp=clock)]),
        escalation=dict(mode='off', threshold=5, window_seconds=30, hosts={'h1':{'distinct_services':0,'threshold_reached':False}}, persistence_error=None)))
    event = dict(id=event_id, run_id=run, operation_id=operation_id, timestamp=clock, action='ALLOW', status='confirmed',
                 reason='<script>window.injected=1</script> synthetic event', host='h1', flow=flow)
    connection=connect_store(runtime/'events.sqlite3');save_event(connection,event);connection.close()
    atomic_json(runtime/'logger.json', dict(server_id='synthetic', collected_at=clock, received=1, error=None,
                deliveries=[dict(event_id=event_id, stage='ack_sent', timestamp=clock)], terminal=dict(enabled=True,dropped=0)))
    (runtime/'controller-1.log').write_text(json.dumps(dict(kind='audit_event', delivery='queued', event_id=event_id, text='<script>bad()</script>'))+'\n')
    atomic_json(runtime/'acceptance.json',dict(status='failed',passed=[],started_at=clock,error='Synthetic test report: not Mininet'))
    commands=queue.Queue(maxsize=8); admin=AdminServer(runtime/'admin.sock',commands)
    echo=EchoServer(('127.0.0.1',0),runtime/'test-receiver.json')
    echo_thread=threading.Thread(target=echo.serve_forever,daemon=True);echo_thread.start()
    executed=[]
    def execute(command):
        executed.append(command)
        if command['action']=='traffic':
            before=json.loads((runtime/'test-receiver.json').read_text())
            result=exchange('127.0.0.1',echo.server_address[1],command['count'],command['interval'],request_id=command['id'])
            after=json.loads((runtime/'test-receiver.json').read_text())
            matched = copy.deepcopy(after['requests'][command['id']])
            # Only namespace identity is synthetic: this server is loopback, not Mininet.
            matched['peer'] = next(h['ip'] for h in policy['hosts'] if h['name'] == command['source'])
            return dict(sender=result,receiver_request=matched,receiver_before=before,receiver_after=after,receiver_message_delta=after['messages']-before['messages'],test_source='loopback only')
        return dict(test_source='synthetic lifecycle callback',component=command.get('component'))
    lab=LabWorkspace(runtime,os.getuid(),os.getgid(),Policy(tmp_path/'config/lab.json'),[dict(host='h2',port=9000),dict(host='h2',port=9001)],execute,lambda:{})
    lab_thread=threading.Thread(target=lab.serve,daemon=True);lab_thread.start()
    stop=threading.Event()
    def heartbeat():
        while not stop.is_set():
            if not source['freeze']:
                source['controller']['collected_at']=time.time();source['controller']['statistics_at']=time.time()
            atomic_json(runtime/'controller.json',source['controller'])
            stop.wait(.25)
    writer=threading.Thread(target=heartbeat,daemon=True);writer.start()
    server=DashboardServer(('127.0.0.1',0),runtime,root=tmp_path)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    origin=f'http://127.0.0.1:{server.server_address[1]}'
    yield dict(origin=origin,source=source,runtime=runtime,root=tmp_path,commands=commands,lab=lab,executed=executed,event=event)
    stop.set();writer.join(timeout=2);lab.cancel.set();lab.done.set();lab_thread.join(timeout=17);lab.closed.set();lab.publisher.join(timeout=2)
    admin.close();echo.shutdown();echo.server_close();echo_thread.join(timeout=2)
    server.shutdown();server.server_close();thread.join(timeout=2)


def test_scene_observes_real_poll_changes_not_idle_replay_and_survives_stale_restart(observatory):
    context=observatory; state=context['source']['controller']
    with sync_playwright() as p:
        browser=p.chromium.launch();page=browser.new_page(viewport={'width':1440,'height':1000})
        errors=[];urls=[]
        page.on('pageerror',lambda e:errors.append(str(e)));page.on('request',lambda r:urls.append(r.url))
        page.goto(context['origin']+'/observatory')
        expect(page.locator('#connection')).to_have_text('Observing the lab')
        assert page.evaluate('window.injected') is None
        assert page.locator('#host-cards img').count()==0
        page.wait_for_timeout(2300)
        assert page.locator('#effects').locator('g').count()==0
        assert page.locator('#network-scene').get_attribute('data-effects-observed') is None
        page.evaluate("window.retainedHost=document.querySelector('.host-card'); window.retainedFlow=document.querySelector('#flow-rows tr')")
        page.wait_for_timeout(2300)
        assert page.evaluate("window.retainedHost===document.querySelector('.host-card') && window.retainedFlow===document.querySelector('#flow-rows tr')")
        state['flows'][0]['packets']=15
        expect(page.locator('#network-scene')).to_have_attribute('data-effects-observed','2',timeout=7000)
        page.locator('#motion').click()
        state['flows'][0]['packets']=20
        expect(page.locator('#flow-rows')).to_contain_text('20',timeout=7000)
        assert page.locator('#network-scene').get_attribute('data-effects-observed')=='2'
        assert page.locator('#effects').locator('g').count()==0
        page.locator('#motion').click()
        page.emulate_media(reduced_motion='reduce')
        state['flows'][0]['packets']=25
        expect(page.locator('#flow-rows')).to_contain_text('25',timeout=7000)
        assert page.locator('#network-scene').get_attribute('data-effects-observed')=='2'
        page.emulate_media(reduced_motion='no-preference')
        state['run_id']=str(uuid.uuid4());state['switch_epoch']=2;state['flows'][0]['packets']=100
        expect(page.locator('#identity-details')).to_contain_text(state['run_id'],timeout=7000)
        assert page.locator('#network-scene').get_attribute('data-effects-observed')=='2'
        context['source']['freeze']=True;state['collected_at']=time.time()-30;state['statistics_at']=time.time()-30
        expect(page.locator('#connection')).to_have_text('Controller snapshot stale',timeout=7000)
        expect(page.locator('#mode')).to_be_disabled()
        assert page.locator('#effects').locator('g').count()==0
        for width in (320,390,768,1024,1440):
            page.set_viewport_size({'width':width,'height':900})
            assert not page.evaluate('document.documentElement.scrollWidth>innerWidth'),width
        page.locator('[data-component="h1"]').focus();page.keyboard.press('Enter')
        expect(page.locator('#inspector-heading')).to_contain_text('h1')
        page.route('**/state.json',lambda route:route.abort())
        expect(page.locator('#connection')).to_have_text('Dashboard connection lost',timeout=7000)
        state['flows'][0]['packets']=500;context['source']['freeze']=False
        page.unroute('**/state.json')
        expect(page.locator('#connection')).to_have_text('Observing the lab',timeout=7000)
        assert page.locator('#network-scene').get_attribute('data-effects-observed')=='2'
        assert not errors and all(url.startswith(context['origin']) for url in urls)
        browser.close()


def test_pixel_sprites_animate_pause_and_react_only_to_observed_state(observatory):
    """Actual browser frame progression and status changes; no network/lab claim."""
    state = observatory['source']['controller']
    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page(viewport={'width': 1440, 'height': 1000})
        errors = []; page.on('pageerror', lambda error: errors.append(str(error)))
        page.goto(observatory['origin']+'/observatory')
        expect(page.locator('body')).to_have_attribute('data-sprite-motion', 'running')
        sprite = page.locator('[data-component="h3"] .sprite')
        assert sprite.locator('use').count() == 4
        assert sprite.locator('use').first.get_attribute('href').endswith('#submarine-0')
        visible = "el => [...el.querySelectorAll('.sprite-frame')].map(n => getComputedStyle(n).opacity)"
        before = sprite.evaluate(visible)
        assert before.count('1') == 1
        page.wait_for_timeout(450)
        after = sprite.evaluate(visible)
        assert after.count('1') == 1 and before != after
        # Decorative idle animation never creates observed traffic or a reaction.
        assert page.locator('#network-scene').get_attribute('data-effects-observed') is None
        assert page.locator('[data-sprite-reaction]').count() == 0
        page.locator('#motion').click()
        expect(page.locator('body')).to_have_attribute('data-sprite-motion', 'still')
        assert sprite.evaluate(visible) == ['1', '0', '0', '0']
        state['flows'][0]['packets'] = 16
        expect(page.locator('#flow-rows')).to_contain_text('16', timeout=7000)
        assert page.locator('[data-sprite-reaction]').count() == 0
        page.locator('#motion').click()
        page.emulate_media(reduced_motion='reduce')
        expect(page.locator('body')).to_have_attribute('data-sprite-motion', 'still')
        assert sprite.evaluate(visible) == ['1', '0', '0', '0']
        page.emulate_media(reduced_motion='no-preference')
        expect(page.locator('body')).to_have_attribute('data-sprite-motion', 'running')
        state['flows'][0]['packets'] = 22
        expect(page.locator('[data-component="h1"]')).to_have_attribute('data-sprite-reaction', 'allow', timeout=7000)
        state['hosts'][0]['block_requested'] = True
        expect(page.locator('[data-component="h1"]')).to_have_attribute('data-sprite-state', 'pending', timeout=7000)
        expect(page.locator('[data-component="h1"] .sprite-marker')).to_be_hidden()
        state['hosts'][0]['block_confirmed'] = True
        expect(page.locator('[data-component="h1"] .sprite-marker')).to_be_visible(timeout=7000)
        observatory['source']['freeze'] = True
        state['collected_at'] = time.time()-30; state['statistics_at'] = time.time()-30
        expect(page.locator('[data-component="h1"]')).to_have_attribute('data-sprite-state', 'unverified', timeout=7000)
        expect(page.locator('body')).to_have_attribute('data-sprite-motion', 'running')
        before = sprite.evaluate(visible)
        page.wait_for_timeout(450)
        assert before != sprite.evaluate(visible)
        assert page.locator('#effects g').count() == 0
        assert page.locator('[data-sprite-reaction]').count() == 0
        expect(page.locator('#scene-caption')).to_contain_text('character motion is decorative')
        expect(page.locator('[data-component="h1"] .sprite-marker')).to_be_hidden()
        assert not errors
        browser.close()


def test_control_confirmations_filtering_configuration_jobs_and_loopback_workbench(observatory):
    context=observatory;state=context['source']['controller']
    with sync_playwright() as p:
        browser=p.chromium.launch();page=browser.new_page(viewport={'width':1440,'height':1000},reduced_motion='reduce')
        errors=[];urls=[];page.on('pageerror',lambda e:errors.append(str(e)));page.on('request',lambda r:urls.append(r.url))
        page.goto(context['origin']+'/observatory')
        expect(page.locator('#connection')).to_have_text('Observing the lab')
        # Chapter navigation cannot enqueue any mutation.
        for index in range(8):page.locator('#chapter').select_option(str(index))
        assert context['commands'].empty() and not context['executed']
        page.locator('#chapter').select_option('2')
        card=page.locator('[data-host="h1"]')
        card.get_by_role('button',name='Block host',exact=True).click()
        command=context['commands'].get(timeout=2)
        expect(card.get_by_role('button',name='Block host',exact=True)).to_be_disabled()
        assert 'confirmed' not in card.locator('.command-result').inner_text()
        assert context['commands'].empty()
        op=dict(id=command['id'],action='BLOCK',host='h1',status='pending',reason='Awaiting readback',timestamp=time.time(),journey=[dict(stage='requested',timestamp=time.time())])
        state['operations'].insert(0,op);state['hosts'][0]['block_requested']=True
        expect(card.locator('.command-result')).to_contain_text('pending',timeout=7000)
        op.update(status='confirmed',reason='Barrier and switch rule readback matched');state['hosts'][0]['block_confirmed']=True
        op['journey'] += [dict(stage='barrier_ack',timestamp=time.time()),dict(stage='matching_readback',timestamp=time.time()),dict(stage='confirmed',timestamp=time.time())]
        expect(card.locator('.command-result')).to_contain_text('confirmed',timeout=7000)
        page.locator(f'[data-operation="{command["id"]}"]').click()
        expect(page.locator('#journey')).to_contain_text('matching readback')
        page.locator('#mode').select_option('observe')
        mode=context['commands'].get(timeout=2)
        expect(page.locator('#mode')).to_be_disabled()
        state['operations'].insert(0,dict(id=mode['id'],action='MODE',mode='observe',status='failed',reason='Synthetic disk failure',timestamp=time.time()))
        expect(page.locator('#mode-result')).to_contain_text('Synthetic disk failure',timeout=7000)
        expect(page.locator('#mode')).to_have_value('off')
        page.locator('#log-search').fill('<script>')
        expect(page.locator('#log-count')).to_contain_text('1 matching')
        page.locator('[data-event]').click()
        expect(page.locator('#delivery-path')).to_contain_text('Matched event ID received')
        assert page.evaluate('window.injected') is None
        page.locator('#log-search').fill('');page.locator('#log-status').select_option('failed')
        expect(page.locator('#event-list')).to_contain_text('Synthetic disk failure')
        # Real browser -> HTTP -> lab socket -> queue; callback uses local TCP only.
        page.locator('#traffic-count').fill('3');page.locator('#traffic-interval').fill('0')
        page.locator('#send-traffic').click()
        expect(page.locator('#traffic-evidence')).to_contain_text('"received": 3',timeout=7000)
        assert len(context['executed'])==1
        page.locator('#prepare-job').click()
        expect(page.locator('#terminal-command')).to_contain_text('sudo ')
        expect(page.locator('#prepare-job')).to_be_disabled()
        assert not list((context['root']/'runtime/gui-jobs').glob('*.log'))
        page.locator('#cancel-job').click();expect(page.locator('#job-result')).to_contain_text('cancelled')
        page.locator('#job-kind').select_option('benchmark')
        expect(page.locator('#job-profile')).to_be_disabled()
        expect(page.locator('#profile-note')).to_contain_text('static OpenFlow')
        config=json.loads(page.locator('#config-json').input_value());config['permission_seconds']=40
        page.locator('#config-json').fill(json.dumps(config));page.locator('#save-config').click()
        expect(page.locator('#config-result')).to_contain_text('Not applied')
        assert Policy(context['root']/'config/lab.json').permission_seconds==40
        assert state['policy']['permission_seconds']==30
        page.locator('#open-record').click()
        expect(page.locator('#record-content')).to_contain_text('Synthetic test report: not Mininet')
        assert page.locator('#download-record').get_attribute('href').endswith('download=1')
        page.locator('#presentation').click();expect(page.locator('body')).to_have_class('presentation')
        page.locator('#caption-toggle').click();expect(page.locator('#guide-caption')).to_be_hidden()
        page.locator('#caption-toggle').click();expect(page.locator('#guide-caption')).to_be_visible()
        assert page.locator('.guide').evaluate("el => getComputedStyle(el).position") != 'sticky'
        state['run_id']=str(uuid.uuid4());state['operations']=[]
        expect(page.locator('#mode-result')).to_contain_text('previous controller run',timeout=7000)
        page.locator('#log-status').select_option('');page.locator('#log-search').fill('<script>')
        expect(page.locator('#event-list')).to_contain_text('previous controller run',timeout=7000)
        assert not errors and all(url.startswith(context['origin']) for url in urls)
        browser.close()


def test_unavailable_destinations_explain_startup_then_populate_and_send(observatory):
    missing = {'value': True}
    def inspection(route):
        response = route.fetch(); data = response.json()
        if missing['value']:
            if route.request.url.endswith('/workspace.json'):
                data['lab'] = dict(status='unavailable', reason='No current workspace channel')
            else:
                data['controller'].pop('policy', None)
                data['controller']['collected_at'] = time.time()-30
                data['controller']['statistics_at'] = time.time()-30
        route.fulfill(response=response, json=data)
    with sync_playwright() as p:
        browser = p.chromium.launch(); page = browser.new_page()
        page.route('**/state.json', inspection); page.route('**/workspace.json', inspection)
        page.goto(observatory['origin']+'/observatory')
        expect(page.locator('#traffic-service')).to_be_disabled()
        expect(page.locator('#traffic-service')).to_contain_text('Start the workspace lab first')
        assert page.locator('#traffic-service').evaluate('el => el.selectedOptions[0]?.textContent') == 'Start the workspace lab first'
        expect(page.locator('#traffic-availability')).to_contain_text('destination services will appear automatically')
        expect(page.locator('#traffic-source')).to_be_disabled()
        expect(page.locator('#send-traffic')).to_be_disabled()
        expect(page.locator('body')).to_have_attribute('data-sprite-motion', 'running')
        assert not observatory['executed']
        missing['value'] = False
        expect(page.locator('#traffic-service')).to_be_enabled(timeout=7000)
        expect(page.locator('#traffic-service')).to_contain_text('h2 · TCP 9000')
        page.locator('#traffic-source').select_option('h2')
        expect(page.locator('#traffic-service')).to_have_value('')
        expect(page.locator('#traffic-service')).to_contain_text('No destination on another host')
        assert page.locator('#traffic-service').evaluate('el => el.selectedOptions[0]?.textContent') == 'No destination on another host'
        expect(page.locator('#traffic-availability')).to_contain_text('Choose a different client')
        page.locator('#traffic-source').select_option('h3')
        page.locator('#traffic-service').select_option('h2:9000')
        page.locator('#traffic-count').fill('3'); page.locator('#send-traffic').click()
        expect(page.locator('#traffic-evidence')).to_contain_text('"received": 3', timeout=7000)
        assert len(observatory['executed']) == 1
        assert observatory['executed'][0]['source'] == 'h3'
        browser.close()


def test_forwarded_local_browser_loads_assets_state_and_same_origin_controls(observatory):
    """A real local HTTP forwarder preserves a different Host/Origin port."""
    import http.client
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from urllib.parse import urlsplit
    backend = urlsplit(observatory['origin'])
    class Forward(BaseHTTPRequestHandler):
        def log_message(self, *_): pass
        def forward(self):
            connection = http.client.HTTPConnection(backend.hostname, backend.port, timeout=4)
            try:
                body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
                connection.request(self.command, self.path, body or None, dict(self.headers))
                response = connection.getresponse(); content = response.read()
                self.send_response(response.status)
                for name, value in response.getheaders():
                    if name.lower() not in ('server', 'date', 'connection'):
                        self.send_header(name, value)
                self.end_headers(); self.wfile.write(content)
            finally:
                connection.close()
        do_GET = forward
        do_POST = forward
    proxy = ThreadingHTTPServer(('127.0.0.1', 0), Forward)
    thread = threading.Thread(target=proxy.serve_forever, daemon=True); thread.start()
    origin = f'http://localhost:{proxy.server_address[1]}'
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(); page = browser.new_page(reduced_motion='reduce')
            errors=[]; urls=[]
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.on('request', lambda request: urls.append(request.url))
            assert page.goto(origin+'/observatory').status == 200
            expect(page.locator('#connection')).to_have_text('Observing the lab')
            assert page.locator('#components [data-component]').count() == 6
            page.locator('[data-host="h1"]').get_by_role('button', name='Block host', exact=True).click()
            command = observatory['commands'].get(timeout=2)
            assert command['action']=='block' and command['run_id']==observatory['source']['controller']['run_id']
            assert observatory['commands'].empty()
            result = page.evaluate("""async()=>{
                const response=await fetch('/workspace/config',{method:'POST',headers:{'Content-Type':'application/json'},body:'{}'});
                return {status:response.status,body:await response.json()};
            }""")
            assert result['status']==400 and 'Invalid request' in result['body']['error']
            assert page.goto(origin+'/classic').status == 200
            expect(page.locator('#connection')).to_have_text('Observing the lab')
            assert not errors and all(url.startswith(origin) for url in urls)
            browser.close()
    finally:
        proxy.shutdown(); proxy.server_close(); thread.join(timeout=2)


@pytest.fixture
def demonstration_backend(observatory):
    """Synthetic enforcement/mode results; allowed exchanges use real loopback TCP."""
    context = observatory; state = context['source']['controller']; base = context['lab'].execute
    state['escalation']['hosts']['h3'] = dict(distinct_services=0, threshold_reached=False)
    context['lab'].state['services'] = [dict(host='h2', port=port) for port in range(9000, 9006)]
    observed = set(); stop = threading.Event()
    def control_writer():
        while not stop.is_set():
            try: command = context['commands'].get(timeout=.1)
            except queue.Empty: continue
            key = '@mode' if command['action'] == 'mode' else command['host']
            if 'if_revision' in command and state['control_revisions'].get(key) != command['if_revision']:
                state['operations'].insert(0, dict(command, action=command['action'].upper(), status='superseded', timestamp=time.time(), reason='Later choice owns this state'))
                continue
            state['control_revisions'][key] = command['id']
            if command['action'] == 'mode':
                state['escalation']['mode'] = command['mode']; observed.clear()
                for host in state['escalation']['hosts'].values(): host.update(distinct_services=0, threshold_reached=False)
            else:
                host = next(h for h in state['hosts'] if h['name'] == command['host'])
                host['block_requested'] = host['block_confirmed'] = command['action'] == 'block'
            state['operations'].insert(0, dict(command, action=command['action'].upper(), status='confirmed', timestamp=time.time(), journey=[{'stage':'matching_readback','timestamp':time.time()}], reason='Synthetic writer confirmation for browser workflow test'))
    def execute(command):
        if command['action'] != 'traffic': return base(command)
        host = next(h for h in state['hosts'] if h['name'] == command['source'])
        if command['port'] == 9000 and not host['block_confirmed']: return base(command)
        config = state['escalation']
        if not host['block_confirmed']:
            state['operations'].insert(0, dict(id=str(uuid.uuid4()), action='DENY', status='confirmed', timestamp=time.time(),
                reason='Synthetic prohibited-service verdict', flow=dict(source_ip=host['ip'], destination_ip='10.0.0.2', source_port=41002, destination_port=command['port'])))
            if config['mode'] != 'off':
                observed.add(command['port']); evidence = config['hosts'][host['name']]
                evidence.update(distinct_services=len(observed), threshold_reached=len(observed) >= config['threshold'])
                if evidence['threshold_reached'] and config['mode'] == 'enforce':
                    host['block_requested'] = host['block_confirmed'] = True
                    block_id = str(uuid.uuid4()); state['control_revisions'][host['name']] = block_id
                    state['operations'].insert(0, dict(id=block_id, mode_revision=state['control_revisions'].get('@mode'), host=host['name'], action='BLOCK', status='confirmed', origin='automatic', timestamp=time.time(), reason='Synthetic automatic block'))
        return dict(sender=dict(sent=0, received=0, request_id=command['id'], source_port=41002, error='Synthetic timeout'), receiver_request=None, receiver_message_delta=0, test_source='Synthetic denial; not Mininet')
    context['lab'].execute = execute
    writer = threading.Thread(target=control_writer, daemon=True); writer.start()
    yield context
    stop.set(); writer.join(timeout=2)


@pytest.mark.parametrize('kind,steps', [('traffic', 2), ('block', 5), ('escalation', 18)])
def test_live_demo_sequences_require_evidence_and_restore_state(demonstration_backend, kind, steps):
    context = demonstration_backend
    with sync_playwright() as p:
        browser = p.chromium.launch(); page = browser.new_page(reduced_motion='reduce')
        errors = []; page.on('pageerror', lambda e: errors.append(str(e)))
        page.goto(context['origin']+'/observatory')
        expect(page.locator('#run-demo')).to_be_enabled()
        page.locator('#demo-kind').select_option(kind)
        page.locator('#demo-host').select_option('h3')
        page.locator('#run-demo').click()
        expect(page.locator('#demo-status')).to_contain_text('Demonstration complete.', timeout=45000)
        assert page.locator('#demo-steps .confirmed').count() == steps
        assert page.locator('#demo-steps .failed').count() == 0
        assert context['source']['controller']['escalation']['mode'] == 'off'
        assert not context['source']['controller']['hosts'][2]['block_confirmed']
        expect(page.locator('#send-traffic')).to_be_enabled()
        assert not errors
        browser.close()


def test_demo_does_not_claim_deny_when_receiver_observes_replies(observatory):
    """The test callback echoes all services; the demo must flag that mismatch."""
    with sync_playwright() as p:
        browser = p.chromium.launch(); page = browser.new_page(reduced_motion='reduce')
        page.goto(observatory['origin']+'/observatory')
        expect(page.locator('#run-demo')).to_be_enabled()
        page.locator('#run-demo').click()
        expect(page.locator('#demo-status')).to_contain_text('Unexpected delivery when denial was expected', timeout=15000)
        assert page.locator('#demo-steps .confirmed').count() == 1
        assert page.locator('#demo-steps .failed').count() == 1
        browser.close()


def test_flow_inspection_filters_and_expanded_readback_survive_refresh(observatory):
    context = observatory; state = context['source']['controller']
    with sync_playwright() as p:
        browser = p.chromium.launch(); page = browser.new_page(reduced_motion='reduce')
        errors = []; page.on('pageerror', lambda e: errors.append(str(e)))
        page.goto(context['origin']+'/observatory')
        expect(page.locator('#connection')).to_have_text('Observing the lab')
        page.locator('#flow-rows button').first.click()
        expect(page.locator('#inspector-heading')).to_contain_text('ALLOW · 10.0.0.1')
        assert page.locator('#routes .related').count() == 2
        page.locator('#inspector-content summary').click()
        state['flows'][0]['packets'] += 4
        expect(page.locator('#inspector-content')).to_contain_text('14', timeout=7000)
        expect(page.locator('#inspector-content details')).to_have_attribute('open', '')
        page.get_by_text('All observed switch rules and policy explanation', exact=True).click()
        page.locator('#rule-list summary').first.click()
        state['observed_rules'][0]['packets'] = 18
        expect(page.locator('#rule-list')).to_contain_text('18 packets', timeout=7000)
        expect(page.locator('#rule-list details').first).to_have_attribute('open', '')
        state['operations'].insert(0,dict(id=str(uuid.uuid4()),action='RELEASE',host='h3',status='confirmed',timestamp=time.time(),reason='Only host three'))
        page.locator('[data-component="h1"]').click()
        expect(page.locator('#log-host')).to_have_value('h1')
        page.locator('#log-host').select_option('h3')
        expect(page.locator('#event-list')).to_contain_text('Only host three', timeout=7000)
        page.locator('#clear-selection').click()
        expect(page.locator('#log-host')).to_have_value('')
        state['escalation']['hosts'] = {}
        expect(page.locator('#mode option[value="enforce"]')).to_be_disabled(timeout=7000)
        page.locator('#demo-kind').select_option('escalation')
        expect(page.locator('#demo-prerequisite')).to_contain_text('not eligible')
        expect(page.locator('#run-demo')).to_be_disabled()
        page.locator('#demo-setup').click()
        expect(page.locator('#job-profile')).to_have_value('escalation')
        page.locator('#traffic-source').select_option('h2')
        expect(page.locator('#send-traffic')).to_be_disabled()
        state['statistics_at'] = None; context['source']['freeze'] = True
        expect(page.locator('#metrics .metric strong').first).to_have_text('—', timeout=7000)
        for width in (320,390,768,1024,1440):
            page.set_viewport_size({'width':width,'height':900})
            assert not page.evaluate('document.documentElement.scrollWidth>innerWidth'),width
        assert not errors
        browser.close()


def test_new_rule_activity_is_animated_once_without_replaying_initial_history(observatory):
    state = observatory['source']['controller']
    with sync_playwright() as p:
        browser = p.chromium.launch(); page = browser.new_page()
        page.goto(observatory['origin']+'/observatory')
        expect(page.locator('#connection')).to_have_text('Observing the lab')
        assert page.locator('#network-scene').get_attribute('data-effects-observed') is None
        row = copy.deepcopy(state['flows'][0]); row.update(cookie=11, packets=3, installed_at=time.time(), action='DENY')
        row['match']['tcp_dst'] = 9001; row['flow']['destination_port'] = 9001
        state['flows'].append(row)
        expect(page.locator('#scene-evidence')).to_contain_text('DENY · +3 packets', timeout=7000)
        expect(page.locator('#network-scene')).to_have_attribute('data-effects-observed','2',timeout=7000)
        page.wait_for_timeout(2300)
        assert page.locator('#network-scene').get_attribute('data-effects-observed') == '2'
        browser.close()


def test_demo_restores_host_after_an_unexpected_traffic_result(demonstration_backend):
    context = demonstration_backend; execute = context['lab'].execute
    def contradictory(command):
        result = execute(command)
        if command['action'] == 'traffic' and command['port'] == 9000 and context['source']['controller']['hosts'][0]['block_confirmed']:
            result['sender']['received'] = 1
        return result
    context['lab'].execute = contradictory
    with sync_playwright() as p:
        browser = p.chromium.launch(); page = browser.new_page(reduced_motion='reduce')
        page.goto(context['origin']+'/observatory')
        expect(page.locator('#run-demo')).to_be_enabled()
        page.locator('#demo-kind').select_option('block'); page.locator('#run-demo').click()
        expect(page.locator('#demo-status')).to_contain_text('Demonstration incomplete:', timeout=20000)
        expect(page.locator('#demo-steps')).to_contain_text('Release back to normal policy · confirmed')
        expect(page.locator('#demo-steps')).to_contain_text('Verify delivery after release · confirmed')
        assert not context['source']['controller']['hosts'][0]['block_confirmed']
        browser.close()


@pytest.mark.parametrize('missing', ['receiver_request', 'sender_received'])
def test_demo_requires_both_sender_and_receiver_counts(observatory, missing):
    execute = observatory['lab'].execute
    def incomplete(command):
        result = execute(command)
        if missing == 'sender_received': result['sender'].pop('received')
        else: result.pop(missing)
        return result
    observatory['lab'].execute = incomplete
    with sync_playwright() as p:
        browser = p.chromium.launch(); page = browser.new_page(reduced_motion='reduce')
        page.goto(observatory['origin']+'/observatory')
        expect(page.locator('#run-demo')).to_be_enabled()
        page.locator('#run-demo').click()
        expect(page.locator('#demo-status')).to_contain_text('Demonstration incomplete:', timeout=15000)
        assert page.locator('#demo-steps .confirmed').count() == 0
        assert len(observatory['executed']) == 1
        browser.close()


def test_escalation_restores_mode_even_when_delivery_after_release_fails(demonstration_backend):
    context = demonstration_backend; state = context['source']['controller']; execute = context['lab'].execute
    def interrupted_receiver(command):
        if command['port'] == 9000 and any(op['action'] == 'RELEASE' for op in state['operations']):
            raise RuntimeError('Synthetic receiver unavailable after release')
        return execute(command)
    context['lab'].execute = interrupted_receiver
    with sync_playwright() as p:
        browser = p.chromium.launch(); page = browser.new_page(reduced_motion='reduce')
        page.goto(context['origin']+'/observatory')
        expect(page.locator('#run-demo')).to_be_enabled()
        page.locator('#demo-kind').select_option('escalation'); page.locator('#run-demo').click()
        expect(page.locator('#demo-status')).to_contain_text('Restoration requires attention:', timeout=45000)
        expect(page.locator('#demo-steps')).to_contain_text('Verify delivery after release · failed')
        expect(page.locator('#demo-steps')).to_contain_text('Restore starting mode: off · confirmed')
        assert state['escalation']['mode'] == 'off'
        assert not state['hosts'][0]['block_confirmed']
        browser.close()


@pytest.mark.parametrize('interruption', ['stop', 'switch_restart'])
def test_demo_stop_restores_but_changed_switch_prevents_further_commands(demonstration_backend, interruption):
    context = demonstration_backend; state = context['source']['controller']; execute = context['lab'].execute
    started = threading.Event(); resume = threading.Event()
    def hold_blocked_attempt(command):
        if command['port'] == 9000 and state['hosts'][0]['block_confirmed']:
            started.set()
            if not resume.wait(10): raise RuntimeError('Test did not release the held callback')
        return execute(command)
    context['lab'].execute = hold_blocked_attempt
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(); page = browser.new_page(reduced_motion='reduce')
            page.goto(context['origin']+'/observatory')
            expect(page.locator('#run-demo')).to_be_enabled()
            page.locator('#demo-kind').select_option('block'); page.locator('#run-demo').click()
            assert started.wait(10)
            if interruption == 'stop': page.locator('#stop-demo').click()
            else:
                state['switch_epoch'] += 1
                expect(page.locator('#notice')).to_contain_text('switch epoch changed', timeout=7000)
            resume.set()
            if interruption == 'stop':
                expect(page.locator('#demo-status')).to_contain_text('Demonstration stopped', timeout=20000)
                expect(page.locator('#demo-steps')).to_contain_text('Release back to normal policy · confirmed')
                expect(page.locator('#demo-steps')).to_contain_text('Verify delivery after release · confirmed')
                assert not state['hosts'][0]['block_confirmed']
            else:
                expect(page.locator('#demo-status')).to_contain_text('Restoration requires attention:', timeout=20000)
                expect(page.locator('#demo-status')).to_contain_text('switch epoch changed')
                assert not any(op['action'] == 'RELEASE' for op in state['operations'])
                assert state['hosts'][0]['block_confirmed']
            expect(page.locator('#stop-demo')).to_be_disabled()
            browser.close()
    finally:
        resume.set()


def test_terminal_handoff_tracks_external_cancellation_and_new_preparation(observatory):
    from all_blue.workspace import Workspace
    workspace = Workspace(observatory['root'])
    with sync_playwright() as p:
        browser = p.chromium.launch(); page = browser.new_page(reduced_motion='reduce')
        page.goto(observatory['origin']+'/observatory')
        expect(page.locator('#prepare-job')).to_be_enabled()
        page.locator('#prepare-job').click()
        expect(page.locator('#job-availability')).to_contain_text('already prepared')
        first = workspace.job_records()[0]
        workspace.cancel_plan({'id': first['id']})
        expect(page.locator('#copy-command')).to_be_disabled(timeout=7000)
        expect(page.locator('#prepare-job')).to_be_enabled()
        next_job = workspace.plan(dict(kind='start', profile='escalation', trials=3))
        expect(page.locator('#terminal-command')).to_contain_text(next_job['id'], timeout=7000)
        expect(page.locator('#cancel-job')).to_be_enabled()
        page.locator('#cancel-job').click()
        expect(page.locator('#job-result')).to_contain_text('cancelled')
        assert not list((observatory['root']/'runtime/gui-jobs').glob('*.log'))
        browser.close()


def test_stopping_at_observe_threshold_skips_remaining_demo_actions(demonstration_backend):
    context = demonstration_backend; state = context['source']['controller']; execute = context['lab'].execute
    started = threading.Event(); resume = threading.Event()
    def hold_last_observation(command):
        if command['port'] == 9005 and state['escalation']['mode'] == 'observe':
            started.set()
            if not resume.wait(10): raise RuntimeError('Test did not release the held observation')
        return execute(command)
    context['lab'].execute = hold_last_observation
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(); page = browser.new_page(reduced_motion='reduce')
            page.goto(context['origin']+'/observatory')
            expect(page.locator('#run-demo')).to_be_enabled()
            page.locator('#demo-kind').select_option('escalation'); page.locator('#run-demo').click()
            assert started.wait(15)
            page.locator('#stop-demo').click(); resume.set()
            expect(page.locator('#demo-status')).to_contain_text('Demonstration stopped', timeout=20000)
            expect(page.locator('#demo-steps')).to_contain_text('Restore starting mode: off · confirmed')
            expect(page.locator('#demo-steps')).not_to_contain_text('Threshold observed without a host block')
            assert state['escalation']['mode'] == 'off'
            assert not any(op.get('mode') == 'enforce' for op in state['operations'])
            assert len(context['executed']) == 1  # Only the initial loopback ALLOW exchange.
            browser.close()
    finally:
        resume.set()
