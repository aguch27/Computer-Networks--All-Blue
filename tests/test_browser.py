"""Browser checks use explicitly synthetic test state; never the live data path."""
import json
import threading
import time
import uuid
from pathlib import Path
import pytest
from playwright.sync_api import sync_playwright, expect
from all_blue.dashboard import DashboardServer


def test_browser_stale_empty_injection_resets_and_local_requests(tmp_path):
    server=DashboardServer(('127.0.0.1',0),tmp_path)
    worker=threading.Thread(target=server.serve_forever,daemon=True); worker.start()
    origin=f'http://127.0.0.1:{server.server_address[1]}'
    try:
        with sync_playwright() as playwright:
            browser=playwright.chromium.launch()
            page=browser.new_page(viewport={'width':1440,'height':1000},reduced_motion='reduce')
            errors=[]; urls=[]
            page.on('pageerror',lambda error:errors.append(str(error)))
            page.on('request',lambda request:urls.append(request.url))
            now=time.time()
            controller=dict(run_id='synthetic-browser-test',collected_at=now,statistics_at=now,
                            switch_connected=True,ready=True,error=None,permission_seconds=30,
                            flow_entries=9,tuple_episodes=1,policy_version='test-only',
                            logger=dict(backlog=0,dropped=0,delivered=1),
                            hosts=[dict(name='h1',label='<img src=x onerror=window.injected=1>',ip='10.0.0.1',
                                        mac='02:00:00:00:00:01',port=1,block_requested=False,block_confirmed=False)],
                            flows=[],operations=[],history=[dict(timestamp=now-2,bytes=2),dict(timestamp=now,bytes=9)])
            state=dict(controller=controller,logger_server=dict(collected_at=now,received=1),
                       events=[dict(id=str(uuid.uuid4()),timestamp=now,action='DENY',status='confirmed',
                                    reason='<script>window.injected=1</script>')])
            page.route('**/state.json',lambda route:route.fulfill(json=state))
            page.goto(origin)
            expect(page.locator('#connection')).to_have_text('Observing the lab')
            assert '<script>' in page.locator('#event-list').inner_text()
            assert page.evaluate('window.injected') is None
            assert page.locator('#host-grid img').count()==0
            assert page.locator('#metric-rules').inner_text()=='9'
            assert page.locator('#chart polyline').count()==1
            expect(page.locator('#escalation-status')).to_have_text('Automatic policy escalation is off.')
            controller['escalation']=dict(mode='observe',threshold=5,window_seconds=30,
                                          hosts={'h1':dict(distinct_services=4)})
            expect(page.locator('#escalation-status')).to_contain_text('Observation only',timeout=7000)
            expect(page.locator('#host-grid')).to_contain_text('4 recent prohibited services observed')
            controller['escalation']['mode']='enforce'
            controller['operations']=[dict(timestamp=now,action='BLOCK',host='h1',status='pending',
                                           origin='automatic',trigger_reason='<img src=x onerror=window.injected=1>',
                                           reason='Waiting for switch')]
            expect(page.locator('#operations')).to_contain_text('BLOCK · automatic',timeout=7000)
            expect(page.locator('#operations')).to_contain_text('pending')
            assert page.locator('#operations img').count()==0
            assert page.evaluate('window.injected') is None
            controller['collected_at']=now-30
            expect(page.locator('#connection')).to_have_text('Controller data stale',timeout=7000)
            controller.update(run_id='new-test-run',collected_at=time.time(),statistics_at=time.time(),history=[],flow_entries=0,tuple_episodes=0)
            expect(page.locator('#run-id')).to_contain_text('new-test-run',timeout=7000)
            assert page.locator('#chart polyline').count()==0
            assert page.locator('#metric-rules').inner_text()=='0'
            state['controller']=None
            expect(page.locator('#metric-rules')).to_have_text('—',timeout=7000)
            page.set_viewport_size({'width':390,'height':844})
            assert not page.evaluate('document.documentElement.scrollWidth > innerWidth')
            page.get_by_label('Filter security events').fill('no-matching-record')
            assert 'No events match' in page.locator('#event-list').inner_text()
            page.unroute('**/state.json')
            page.route('**/state.json',lambda route:route.abort())
            expect(page.locator('#connection')).to_have_text('Presentation offline',timeout=7000)
            assert not errors
            assert all(url.startswith(origin) for url in urls)
            browser.close()
    finally:
        server.shutdown(); server.server_close(); worker.join(timeout=2)


def test_unchanged_polls_preserve_dom_and_mobile_navigation(tmp_path):
    server = DashboardServer(('127.0.0.1', 0), tmp_path)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    origin = f'http://127.0.0.1:{server.server_address[1]}'
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            page = browser.new_page(viewport={'width': 1440, 'height': 1000}, reduced_motion='reduce')
            errors, urls, polls = [], [], []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.on('request', lambda request: urls.append(request.url))
            now = time.time()
            controller = dict(
                run_id='synthetic-render-test', switch_epoch=1, collected_at=now, statistics_at=now,
                switch_connected=True, ready=True, error=None, permission_seconds=30,
                flow_entries=15, tuple_episodes=1, policy_version='test-only',
                logger=dict(backlog=0, dropped=0, delivered=2),
                hosts=[dict(name=f'h{port}', label=label, ip=f'10.0.0.{port}',
                            mac=f'02:00:00:00:00:0{port}', port=port,
                            block_requested=False, block_confirmed=False)
                       for port, label in enumerate(('Harbor · client', 'Reef · services', 'Tide · client'), 1)],
                flows=[dict(match=dict(ipv4_src='10.0.0.1', ipv4_dst='10.0.0.2', tcp_src=41000,
                                       tcp_dst=9000), action='ALLOW', direction='forward', packets=8, bytes=640)],
                operations=[dict(timestamp=now, action='ALLOW', status='confirmed', reason='Rule readback matched')],
                history=[dict(timestamp=now-2, bytes=320), dict(timestamp=now, bytes=640)],
            )
            state = dict(controller=controller, logger_server=dict(collected_at=now, received=2),
                         events=[dict(id='one', timestamp=now, action='ALLOW', status='confirmed', reason='Service permitted')])

            def reply(route):
                controller['collected_at'] = time.time()
                state['logger_server']['collected_at'] = time.time()
                polls.append(time.monotonic())
                route.fulfill(json=state)

            page.route('**/state.json', reply)
            page.goto(origin)
            expect(page.locator('#flows')).to_contain_text('41000 → 9000')
            page.evaluate('''() => {
                window.renderChanges = 0;
                window.retainedFlow = document.querySelector('#flows tr');
                const observer = new MutationObserver(records => window.renderChanges += records.length);
                for (const id of ['flows', 'host-grid', 'operations', 'event-list', 'chart']) {
                    observer.observe(document.getElementById(id), {childList: true, subtree: true});
                }
            }''')
            start_polls = len(polls)
            deadline = time.monotonic() + 10
            while len(polls) < start_polls + 2 and time.monotonic() < deadline:
                page.wait_for_timeout(100)
            assert len(polls) >= start_polls + 2
            assert page.evaluate('window.renderChanges') == 0
            assert page.evaluate("window.retainedFlow === document.querySelector('#flows tr')")

            controller['flows'][0]['packets'] = 9
            expect(page.locator('#flows tr td').nth(4)).to_have_text('9', timeout=7000)
            assert not page.evaluate("window.retainedFlow === document.querySelector('#flows tr')")
            page.get_by_label('Filter security events').fill('missing')
            expect(page.locator('#event-list')).to_contain_text('No events match')
            page.get_by_label('Filter security events').fill('allow')
            expect(page.locator('#event-list')).to_contain_text('Service permitted')

            controller['statistics_at'] = time.time()
            expect(page.locator('#connection')).to_have_text('Observing the lab', timeout=7000)
            Path('artifacts').mkdir(exist_ok=True)
            page.locator('#event-filter').blur()
            page.evaluate('window.scrollTo(0, 0)')
            page.screenshot(path='artifacts/dashboard-desktop.png', full_page=True)
            for width in (320, 390, 768, 1024, 1440):
                page.set_viewport_size({'width': width, 'height': 844})
                assert not page.evaluate('document.documentElement.scrollWidth > innerWidth'), width
            page.set_viewport_size({'width': 390, 'height': 844})
            menu = page.get_by_role('button', name='Menu')
            menu.click()
            expect(menu).to_have_attribute('aria-expanded', 'true')
            page.keyboard.press('Escape')
            expect(menu).to_have_attribute('aria-expanded', 'false')
            expect(menu).to_be_focused()
            menu.click()
            page.get_by_role('navigation').get_by_role('link', name='Hosts').click()
            expect(menu).to_have_attribute('aria-expanded', 'false')
            expect(page.locator('#hosts')).to_be_in_viewport()
            assert page.evaluate("getComputedStyle(document.documentElement).scrollBehavior") == 'auto'
            page.evaluate('window.scrollTo(0, 0)')
            page.screenshot(path='artifacts/dashboard-mobile.png', full_page=True)
            assert not errors
            assert all(url.startswith(origin) for url in urls)
            browser.close()
    finally:
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def test_host_commands_track_controller_results_and_disable_duplicates(tmp_path):
    """Synthetic writer state, real browser → HTTP → local admin queue."""
    import queue
    from all_blue.admin import AdminServer
    from all_blue.storage import atomic_json
    commands = queue.Queue(maxsize=8)
    admin = AdminServer(tmp_path/'admin.sock', commands)
    server = DashboardServer(('127.0.0.1', 0), tmp_path)
    worker = threading.Thread(target=server.serve_forever, daemon=True)
    worker.start()
    origin = f'http://127.0.0.1:{server.server_address[1]}'
    controller = dict(run_id=str(uuid.uuid4()), switch_epoch=1, ready=True, switch_connected=True,
        collected_at=time.time(), statistics_at=time.time(), permission_seconds=30, error=None,
        flow_entries=4, tuple_episodes=0, policy_version='fixture', history=[], flows=[], operations=[],
        logger=dict(backlog=0, dropped=0, delivered=0),
        hosts=[dict(name='h1', label='Client', ip='10.0.0.1', mac='02:00:00:00:00:01',
                    port=1, block_requested=False, block_confirmed=False)])
    state = dict(controller=controller, events=[], logger_server=None)
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            page = browser.new_page()
            errors = []
            page.on('pageerror', lambda error: errors.append(str(error)))
            def snapshot(route):
                controller.update(collected_at=time.time(), statistics_at=time.time())
                atomic_json(tmp_path/'controller.json', controller)
                route.fulfill(json=state)
            page.route('**/state.json', snapshot)
            page.goto(origin)
            block = page.get_by_role('button', name='Block h1', exact=True)
            release = page.get_by_role('button', name='Release h1', exact=True)
            result = page.locator('[data-host="h1"] .command-result')
            expect(block).to_be_enabled()
            block.evaluate('(button) => { button.click(); button.click(); }')
            expect(result).to_contain_text('BLOCK pending')
            expect(block).to_be_disabled()
            expect(release).to_be_disabled()
            command = commands.get(timeout=2)
            assert commands.empty()
            assert command['run_id'] == controller['run_id']
            assert command['action'] == 'block'
            assert 'confirmed' not in result.inner_text().replace('confirmation', '')
            operation = dict(**command, timestamp=time.time(), status='pending', reason='Awaiting rule readback')
            controller['operations'] = [operation]
            expect(result).to_contain_text('Awaiting rule readback', timeout=7000)
            operation.update(status='confirmed', reason='Barrier and switch rule readback matched')
            controller['hosts'][0].update(block_requested=True, block_confirmed=True)
            expect(result).to_contain_text('BLOCK confirmed', timeout=7000)
            expect(release).to_be_enabled()
            for outcome, reason in [('superseded', 'A newer block superseded this release'),
                                    ('failed', 'Cannot persist release; reconciliation required')]:
                release.click()
                expect(result).to_contain_text('RELEASE pending')
                command = commands.get(timeout=2)
                controller['operations'].insert(0, dict(**command, timestamp=time.time(), status=outcome, reason=reason))
                expect(result).to_contain_text(f'RELEASE {outcome}', timeout=7000)
                expect(result).to_contain_text(reason)
            controller['ready'] = False
            expect(block).to_be_disabled(timeout=7000)
            expect(release).to_be_disabled()
            controller['ready'] = True
            expect(block).to_be_enabled(timeout=7000)
            uncertain = []
            def no_ack(route):
                uncertain.append(route.request.post_data_json)
                route.fulfill(status=503, json=dict(error='Controller acknowledgement unavailable', status='unknown'))
            page.route('**/commands', no_ack)
            block.click()
            expect(result).to_contain_text('BLOCK unknown')
            expect(result).to_contain_text('acknowledgement unavailable')
            block.click()
            expect(result).to_contain_text('BLOCK unknown')
            assert len(uncertain) == 2 and uncertain[0]['id'] == uncertain[1]['id']
            assert commands.empty()
            page.unroute('**/state.json')
            page.route('**/state.json', lambda route: route.abort())
            expect(block).to_be_disabled(timeout=7000)
            expect(release).to_be_disabled()
            assert not errors
            browser.close()
    finally:
        admin.close()
        server.shutdown()
        server.server_close()
        worker.join(timeout=2)


def test_mode_selector_tracks_apply_failure_restart_and_unavailable_state(tmp_path):
    """Synthetic mode application, real browser/HTTP/admin transport; no Mininet claim."""
    import queue
    from all_blue.admin import AdminServer
    from all_blue.storage import atomic_json
    commands = queue.Queue(maxsize=8)
    admin = AdminServer(tmp_path/'admin.sock', commands)
    server = DashboardServer(('127.0.0.1', 0), tmp_path)
    worker = threading.Thread(target=server.serve_forever, daemon=True); worker.start()
    origin = f'http://127.0.0.1:{server.server_address[1]}'
    controller = dict(run_id=str(uuid.uuid4()), switch_epoch=1, ready=True, switch_connected=True,
        collected_at=time.time(), statistics_at=time.time(), permission_seconds=30, error=None,
        flow_entries=4, tuple_episodes=0, policy_version='fixture', history=[], flows=[], operations=[],
        logger=dict(backlog=0, dropped=0, delivered=0),
        escalation=dict(mode='observe', hosts={'h1': dict(distinct_services=4)}, threshold=5, window_seconds=30),
        hosts=[dict(name='h1', label='Client', ip='10.0.0.1', mac='02:00:00:00:00:01',
                    port=1, block_requested=True, block_confirmed=True)])
    state = dict(controller=controller, events=[], logger_server=None)
    try:
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch()
            page = browser.new_page(viewport={'width': 390, 'height': 844})
            errors, urls = [], []
            page.on('pageerror', lambda error: errors.append(str(error)))
            page.on('request', lambda request: urls.append(request.url))
            def snapshot(route):
                controller.update(collected_at=time.time(), statistics_at=time.time())
                atomic_json(tmp_path/'controller.json', controller)
                route.fulfill(json=state)
            page.route('**/state.json', snapshot)
            page.goto(origin)
            mode = page.get_by_label('Escalation mode', exact=True)
            result = page.locator('#mode-result')
            expect(mode).to_have_value('observe')
            expect(mode).to_be_enabled()
            mode.select_option('enforce')
            expect(result).to_contain_text('MODE enforce pending')
            expect(mode).to_be_disabled()
            mode.dispatch_event('change')
            command = commands.get(timeout=2)
            assert commands.empty() and command['mode'] == 'enforce' and 'host' not in command
            expect(page.locator('#escalation-status')).to_contain_text('Observation only')
            operation = dict(**command, timestamp=time.time(), status='pending', reason='Saving mode')
            controller['operations'] = [operation]
            expect(result).to_contain_text('Saving mode', timeout=7000)
            operation.update(status='confirmed', reason='Escalation enforce saved and applied; existing host blocks retained')
            controller['escalation']['mode'] = 'enforce'
            controller['escalation']['hosts']['h1']['distinct_services'] = 0
            expect(result).to_contain_text('MODE enforce confirmed', timeout=7000)
            expect(mode).to_be_enabled()
            expect(page.locator('#host-grid')).to_contain_text('Block confirmed')
            expect(page.locator('#operations')).to_contain_text('Escalation → enforce')
            mode.select_option('off')
            expect(result).to_contain_text('MODE off pending')
            command = commands.get(timeout=2)
            controller['operations'].insert(0, dict(**command, timestamp=time.time(), status='failed', reason='Cannot confirm saved mode: disk full'))
            expect(result).to_contain_text('MODE off failed', timeout=7000)
            expect(result).to_contain_text('disk full')
            expect(mode).to_have_value('enforce')
            mode.select_option('observe')
            expect(result).to_contain_text('MODE observe pending')
            command = commands.get(timeout=2)
            controller['operations'].insert(0, dict(**command, timestamp=time.time(), status='superseded', reason='Controller run changed'))
            expect(result).to_contain_text('MODE observe superseded', timeout=7000)
            expect(mode).to_have_value('enforce')
            # A restarted controller supplies its persisted mode; no new POST is sent.
            controller.update(run_id=str(uuid.uuid4()), operations=[])
            controller['escalation']['mode'] = 'off'
            controller['escalation']['hosts'] = {}
            expect(mode).to_have_value('off', timeout=7000)
            mode.select_option('observe')
            expect(result).to_contain_text('No eligible hosts configured')
            expect(mode).to_have_value('off')
            assert commands.empty()
            controller['switch_connected'] = False
            expect(mode).to_be_disabled(timeout=7000)
            for width in (320, 390, 768, 1440):
                page.set_viewport_size({'width': width, 'height': 844})
                assert not page.evaluate('document.documentElement.scrollWidth > innerWidth'), width
            page.unroute('**/state.json'); page.route('**/state.json', lambda route: route.abort())
            expect(page.locator('#connection')).to_have_text('Presentation offline', timeout=7000)
            expect(mode).to_be_disabled()
            assert not errors and all(url.startswith(origin) for url in urls)
            browser.close()
    finally:
        admin.close(); server.shutdown(); server.server_close(); worker.join(timeout=2)
