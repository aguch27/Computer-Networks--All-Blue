#!/usr/bin/env python3
"""Real Mininet/OVS acceptance tests; operate only on the ab-s1 lab bridge.

Run with sudo. Controller/logger/dashboard and socket apps drop to the invoking
user. The only privileged responsibilities are isolated namespaces and OVS.
"""
import argparse
import hashlib
import json
import os
import pwd
from pathlib import Path
import re
import select
import shutil
import signal
import socket
import subprocess
import sys
import time
import traceback
import uuid
from urllib.request import Request, urlopen
from urllib.error import HTTPError

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from all_blue.policy import Policy
from all_blue.storage import atomic_json, recent_events
from all_blue.rules import BASE
from all_blue.escalation import EscalationConfig


def wait_for(predicate, description, timeout=12):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            last = predicate()
            if last:
                return last
        except (OSError, ValueError, KeyError):
            pass
        time.sleep(.2)
    raise AssertionError(f'Timed out: {description}; last result={last}')


def read(path):
    return json.loads(Path(path).read_text())


def follow(component):
    """Follow this run's real log files, including service restarts; start nothing."""
    runtime = Path(read(ROOT / 'runtime/latest-lab.json')['runtime'])
    print(f'Following {component} in {runtime}; Ctrl-C stops only this viewer.', flush=True)
    positions = {}
    try:
        while True:
            for path in sorted(runtime.glob(f'{component}-*.log'), key=lambda p: int(p.stem.rsplit('-', 1)[1])):
                with path.open() as stream:
                    stream.seek(positions.get(path, 0))
                    chunk = stream.read(65536)
                    positions[path] = stream.tell()
                if chunk:
                    print(chunk, end='', flush=True)
            time.sleep(.1)
    except KeyboardInterrupt:
        return 0


def stop_process(process, timeout=3):
    """Stop only a process created by this runner; preserve unrelated processes."""
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def check_management_ports(ports=(16653, 19020, 18080)):
    for port in ports:
        with socket.socket() as probe:
            # Match the services' bind behavior: permit prior TIME_WAIT connections,
            # while still refusing an active listener before any namespace mutation.
            probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                probe.bind(('127.0.0.1', port))
            except OSError as error:
                raise OSError(error.errno, f'Management port {port} unavailable: {error}') from error


def wait_for_dashboard_counters(dashboard_state, switch_flows, source_port, completed_at, timeout=12):
    """Compare one tuple across fresh dashboard and stable independent OVS samples."""
    target, last, attempts = None, {}, 0

    def ovs_counters(dump, cookie):
        lines = [line for line in dump.splitlines() if f'cookie=0x{cookie:x},' in line]
        if len(lines) != 2:
            return lines, None
        counts = {}
        for line in lines:
            port = int(re.search(r'\bin_port=(\d+)', line)[1])
            counts[port] = tuple(int(re.search(r'n_' + field + r'=(\d+)', line)[1])
                                 for field in ('packets', 'bytes'))
        return lines, counts if len(counts) == 2 else None

    def compare():
        nonlocal target, last, attempts
        attempts += 1
        if target is None:
            initial = dashboard_state().get('controller') or {}
            rows = [row for row in initial.get('flows', [])
                    if row['flow']['source_port'] == source_port]
            if not initial.get('ready') or len(rows) != 2 or rows[0]['cookie'] != rows[1]['cookie']:
                last = dict(reason='Awaiting the selected tuple', rows=len(rows))
                return None
            target = (initial['run_id'], initial['switch_epoch'], rows[0]['cookie'])
        before, before_counts = ovs_counters(switch_flows(), target[2])
        panel = dashboard_state()
        after, after_counts = ovs_counters(switch_flows(), target[2])
        current = panel.get('controller') or {}
        shown = [row for row in current.get('flows', [])
                 if row['cookie'] == target[2] and row['flow']['source_port'] == source_port]
        shown_counts = {row['match']['in_port']: (row['packets'], row['bytes']) for row in shown}
        same_run = (current.get('run_id'), current.get('switch_epoch')) == target[:2]
        fresh = (current.get('statistics_at') or 0) > completed_at
        audited = bool(shown) and any(event['action'] == 'ALLOW' and event['status'] == 'confirmed'
                                     and event.get('flow') == shown[0]['flow']
                                     for event in panel.get('events', []))
        last = dict(cookie=target[2], attempts=attempts, same_run=same_run, fresh=fresh,
                    statistics_at=current.get('statistics_at'), audited=audited,
                    dashboard=shown_counts, ovs_before=before_counts, ovs_after=after_counts)
        # Never accept an expired/missing pair or offsetting errors in aggregate totals.
        # Late TCP packets and asynchronous polling may require another fresh sample.
        if (current.get('ready') and same_run and fresh and audited and len(shown) == 2
                and before_counts and all(packets > 0 for packets, _ in before_counts.values())
                and before_counts == after_counts == shown_counts):
            totals = {field: sum(value[index] for value in after_counts.values())
                      for index, field in enumerate(('packets', 'bytes'))}
            return dict(presentation=panel, ovs=after, ovs_before=before,
                        selected_tuple_totals=totals, comparison=last)
        return None

    try:
        return wait_for(compare, 'fresh dashboard counters agree with stable OVS samples', timeout)
    except AssertionError as error:
        raise AssertionError(f'{error}; last comparison={last}') from error


def allow_permissions(dump):
    if not dump.startswith('OFPST_FLOW reply'):
        raise AssertionError('Independent OVS flow reply missing; cannot verify permission expiry')
    return [line for line in dump.splitlines()
            if 'table=1,' in line and re.search(r'\bpriority=2000,', line)]


def wait_for_permission_expiry(switch_flows, started_at, limit, samples,
                               clock=time.monotonic, pause=time.sleep):
    """Measure absence of forwarding permissions, separately from client shutdown."""
    while clock() - started_at <= limit:
        dump = switch_flows()
        remaining = allow_permissions(dump)
        elapsed = clock() - started_at
        samples.append(dict(seconds_after_loss=elapsed, remaining_permissions=len(remaining)))
        del samples[:-200]
        # A delayed read returning after the deadline cannot establish timely expiry.
        if elapsed <= limit and not remaining:
            return dict(seconds_after_loss=elapsed, ovs=dump)
        pause(.2)
    raise AssertionError(f'Forwarding permissions not observed absent within {limit}s; '
                         f'last sample={samples[-1] if samples else None}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--test', action='store_true', help='Run the complete acceptance suite and clean up')
    parser.add_argument('--preflight', action='store_true', help='Check imports and binaries without creating a network')
    parser.add_argument('--escalation', help='Opt-in local escalation config; also test its selected mode')
    parser.add_argument('--verbose', action='store_true', help='Live bounded controller/logger diagnostics in run logs')
    parser.add_argument('--follow', choices=('controller', 'logger'), help='Follow the latest lab logs without starting services')
    parser.add_argument('--benchmark', choices=('allow', 'deny', 'block', 'outage'), help='Run one isolated real-network measurement')
    parser.add_argument('--static', action='store_true', help='Static OpenFlow comparison, only with --benchmark')
    args = parser.parse_args()
    if args.follow:
        return follow(args.follow)
    if args.static and not args.benchmark:
        parser.error('--static is only valid with --benchmark')
    # Mininet is an Ubuntu system package; the controller remains in the venv.
    if '/usr/lib/python3/dist-packages' not in sys.path:
        sys.path.append('/usr/lib/python3/dist-packages')
    from mininet.net import Mininet
    from mininet.node import OVSSwitch, RemoteController
    from mininet.cli import CLI
    from mininet.log import setLogLevel
    for binary in ('ovs-vsctl', 'ovs-ofctl', 'ip', 'mn'):
        if not shutil.which(binary):
            raise SystemExit(f'Missing {binary}; run scripts/setup-system.sh')
    from all_blue.controller import AllBlue
    policy = Policy(ROOT / 'config/lab.json')
    escalation = EscalationConfig.load(args.escalation, policy)
    if escalation.eligible_hosts and (escalation.distinct_services != 5 or
            escalation.window_seconds < 20 or 'h1' not in escalation.eligible_hosts):
        raise SystemExit('This acceptance scenario needs h1 selected, threshold 5 and window >=20s.')
    if args.preflight:
        print('All Blue preflight passed: Mininet, OS-Ken and OVS tools available')
        return 0
    if os.geteuid() != 0:
        raise SystemExit('Use sudo for this isolated network test; no password is read by the project.')
    if subprocess.run(['ovs-vsctl', 'br-exists', 'ab-s1'], capture_output=True).returncode == 0:
        raise SystemExit('Bridge ab-s1 already exists. Stop that All Blue lab before starting another.')
    uid, gid = int(os.environ.get('SUDO_UID', '0')), int(os.environ.get('SUDO_GID', '0'))
    account = pwd.getpwuid(uid).pw_name
    stamp = time.strftime('%Y%m%d-%H%M%S')
    if args.benchmark:
        stamp += f'-{time.monotonic_ns()}'
    runtime = ROOT / 'runtime' / f'lab-{stamp}'
    runtime.mkdir(parents=True)
    os.chown(runtime, uid, gid)
    python = str(ROOT / '.venv/bin/python')
    sources = [*sorted((ROOT/'all_blue').glob('*.py')), *sorted((ROOT/'all_blue/web').glob('*')),
               ROOT/'scripts/lab.py', ROOT/'config/lab.json']
    if args.benchmark:
        sources.append(ROOT/'scripts/benchmark.py')
    if args.escalation:
        sources.append(Path(args.escalation).resolve())
    report = dict(started_at=time.time(), runtime=str(runtime), passed=[], exchanges=[], status='running', error=None,
                  escalation_mode=escalation.mode,
                  source_sha256={str(path.relative_to(ROOT) if path.is_relative_to(ROOT) else path):
                                 hashlib.sha256(path.read_bytes()).hexdigest() for path in sources})
    processes, outputs, net = [], [], None
    previous_term = signal.getsignal(signal.SIGTERM)
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt('Lab interrupted; cleaning up its own resources')
    signal.signal(signal.SIGTERM, interrupted)

    def evidence():
        atomic_json(runtime / 'acceptance.json', report)
        os.chown(runtime / 'acceptance.json', uid, gid)
        atomic_json(ROOT / 'runtime' / 'latest-lab.json', dict(runtime=str(runtime), status=report['status']))
        os.chown(ROOT / 'runtime' / 'latest-lab.json', uid, gid)

    def passed(label, **details):
        report['passed'].append(dict(check=label, time=time.time(), **details))
        print('PASS:', label, flush=True)
        evidence()

    def launch(command, **extra):
        log = (runtime / f'{command}-{len(processes)}.log').open('w')
        outputs.append(log)
        os.chown(log.name, uid, gid)
        ports = {'controller': ['--port', '16653', '--log-port', '19020'],
                 'logger': ['--port', '19020'], 'dashboard': ['--port', '18080']}
        if args.escalation:
            ports['controller'] += ['--escalation', str(Path(args.escalation).resolve())]
        if args.verbose and command in ('controller', 'logger'):
            ports[command].append('--verbose')
        process = subprocess.Popen([python, '-u', '-m', 'all_blue', '--runtime', str(runtime), command, *ports[command]],
                                   cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
                                   user=uid, group=gid, extra_groups=[], **extra)
        processes.append(process)
        return process

    def state():
        return read(runtime / 'controller.json')

    def network_state(host):
        node = net.get(host)
        return {kind: json.loads(node.cmd('ip', '-j', kind, 'show'))
                for kind in ('link', 'address', 'neighbor')}

    def restore_neighbors(host):
        # Linux flushes even permanent ARP entries when a device MAC changes.
        # Use the policy bindings, including while the source is deliberately spoofed.
        node = net.get(host)
        for peer in policy.hosts.values():
            if peer.name != host:
                out, err, code = node.pexec(['ip', 'neighbor', 'replace', peer.ip,
                    'lladdr', peer.mac, 'nud', 'permanent', 'dev', str(node.defaultIntf())])
                assert code == 0, (out, err)
        entries = network_state(host)['neighbor']
        for peer in policy.hosts.values():
            if peer.name != host:
                assert any(row.get('dst') == peer.ip and row.get('lladdr') == peer.mac
                           and 'PERMANENT' in row.get('state', []) for row in entries), entries

    def switch_flows():
        return subprocess.check_output(['ovs-ofctl', '-O', 'OpenFlow13', 'dump-flows', 'ab-s1'],
                                       text=True, timeout=5)

    def ingress_drop_packets():
        for line in switch_flows().splitlines():
            if f'cookie=0x{BASE:x},' in line and 'table=0,' in line:
                return int(re.search(r'n_packets=(\d+)', line)[1])
        raise AssertionError('Default ingress drop rule missing from OVS')

    def dashboard_state():
        with urlopen('http://127.0.0.1:18080/state.json', timeout=2) as response:
            return json.load(response)

    def admin(action, host=None, *, mode=None, rejected=False):
        origin = 'http://127.0.0.1:18080'
        command = dict(action=action, id=str(uuid.uuid4()), run_id=state()['run_id'])
        command.update(dict(mode=mode) if action == 'mode' else dict(host=host))
        try:
            with urlopen(Request(origin + '/commands', data=json.dumps(command).encode(),
                                headers={'Content-Type': 'application/json', 'Origin': origin}), timeout=4) as response:
                assert response.status == 202 and not rejected
                reply = json.load(response)
        except HTTPError as error:
            with error:
                detail = json.load(error)
            assert rejected and error.code == 400 and 'No eligible hosts configured' in detail['error'], detail
            return detail
        assert reply == dict(id=command['id'], status='requested'), reply
        if reply['status'] != 'requested':
            raise AssertionError(reply)
        def confirmed():
            for operation in state()['operations']:
                if operation['id'] == reply['id']:
                    if operation['status'] in ('failed', 'superseded'):
                        raise AssertionError(operation)
                    return operation['status'] == 'confirmed'
        wait_for(confirmed, f'{action} {host or mode} confirmation')
        operation = next(operation for operation in state()['operations'] if operation['id'] == reply['id'])
        report.setdefault('dashboard_commands', []).append(dict(request=command, receipt=reply, result=operation))
        return reply

    def client(host, destination='10.0.0.2', port=9000, count=1, interval=.1, background=False, measure=False):
        # Mininet's mnexec must enter the namespace before credentials are dropped.
        process = net.get(host).popen(['runuser', '-u', account, '--', python, '-m', 'all_blue.traffic', 'client', destination,
            '--port', str(port), '--count', str(count), '--interval', str(interval), *(['--measure'] if measure else [])],
            cwd=str(ROOT), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        processes.append(process)
        if background:
            return process
        stdout, stderr = process.communicate(timeout=max(8, count * interval + 6))
        if process.returncode:
            raise AssertionError(stderr)
        result = json.loads(stdout)
        report['exchanges'].append(dict(host=host, destination=destination, port=port, **result))
        report['exchanges'] = report['exchanges'][-64:]
        return result

    def server(host, port):
        path = runtime / f'received-{port}.json'
        process = net.get(host).popen(['runuser', '-u', account, '--', python, '-m', 'all_blue.traffic', 'server', '--port', str(port),
            '--evidence', str(path)], cwd=str(ROOT), stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True)
        processes.append(process)
        if not select.select([process.stdout], [], [], 5)[0] or not process.stdout.readline():
            raise AssertionError('Listener failed to start: ' + process.stderr.read())
        return path

    try:
        evidence()
        print(f'Runtime: {runtime}\nLive output: .venv/bin/python scripts/lab.py --follow controller (or logger)', flush=True)
        # Fail before any namespace mutation if a required management port is busy.
        check_management_ports()
        startup_ns = time.monotonic_ns()
        logger = controller = dashboard = None
        if not args.static:
            logger, controller, dashboard = launch('logger'), launch('controller'), launch('dashboard')
            wait_for(lambda: (runtime / 'controller.json').exists(), 'controller startup')
        setLogLevel('warning')
        net = Mininet(controller=None, switch=OVSSwitch, build=False, autoStaticArp=True)
        if not args.static:
            net.addController('ab-controller', controller=RemoteController, ip='127.0.0.1', port=16653)
        switch = net.addSwitch('ab-s1', dpid=f'{policy.datapath_id:016x}',
                               protocols='OpenFlow13', failMode='secure', inband=False)
        for host in policy.hosts.values():
            node = net.addHost(host.name, ip=host.ip + '/24', mac=host.mac)
            net.addLink(node, switch, port2=host.port)
        net.build()
        net.start()
        for host in net.hosts:
            host.cmd('sysctl -qw net.ipv6.conf.all.disable_ipv6=1')
        if args.static:
            from scripts.benchmark import install_static
            install_static(policy, runtime)
        else:
            wait_for(lambda: state()['ready'], 'OpenFlow compatibility and startup reconciliation', timeout=20)
        ready_ns = time.monotonic_ns()
        if args.benchmark:
            from scripts.benchmark import experiment
            report['benchmark'] = experiment(args, runtime, policy, startup_ns, ready_ns,
                client, server, state, switch_flows, launch, logger)
            report['status'] = 'passed'
            report['finished_at'] = time.time()
            evidence()
            print(f'Benchmark evidence: {runtime / "acceptance.json"}', flush=True)
            return 0
        passed('OS-Ken connects to OVS; default-deny rules verified by barrier and readback')
        allowed_receipts, forbidden_receipts = server('h2', 9000), server('h2', 9001)
        assert client('h2', '127.0.0.1', 9001)['received'] == 1
        forbidden_before = read(forbidden_receipts)['messages']
        denied = client('h1', port=9001)
        assert denied['received'] == 0 and denied['error']
        assert read(forbidden_receipts)['messages'] == forbidden_before
        passed('DENY prevents TCP payload delivery to an independently verified listening service', result=denied)
        allowed = client('h1', count=6)
        assert allowed['received'] == 6 and not allowed['error']
        passed('ALLOW exchanges actual TCP payloads with receiver evidence', result=allowed)

        comparison = wait_for_dashboard_counters(dashboard_state, switch_flows,
                                                 allowed['source_port'], allowed['completed_at'])
        atomic_json(runtime / 'dashboard-evidence.json', comparison)
        passed('Local dashboard counters equal independent OVS readings and include persisted audit events',
               selected_tuple_totals=comparison['selected_tuple_totals'],
               comparison_attempts=comparison['comparison']['attempts'])

        stream = client('h1', count=600, interval=.12, background=True)
        wait_for(lambda: read(allowed_receipts)['messages'] >= 12, 'ongoing TCP stream')
        wait_for(lambda: any(row['bytes'] > 0 for row in state()['flows']), 'ongoing flow counters')
        first = state()
        pre_block_cookies = {row['cookie'] for row in first['flows']}
        first_bytes = sum(row['bytes'] for row in first['flows'])
        wait_for(lambda: state()['statistics_at'] > first['statistics_at'] and
                 sum(row['bytes'] for row in state()['flows']) > first_bytes,
                 'counters increase after initial rule install')
        passed('Ongoing switch statistics increase after first-packet installation')
        admin('block', 'h1')
        # Allow already-in-flight receiver work to settle; do not claim retroactive delivery prevention.
        time.sleep(.4)
        settled = read(allowed_receipts)['messages']
        time.sleep(1)
        assert read(allowed_receipts)['messages'] == settled
        assert client('h1')['received'] == 0
        stream_result = json.loads(stream.communicate(timeout=5)[0])
        assert stream_result['received'] < 600 and stream_result['error']
        assert client('h3')['received'] == 1
        passed('BLOCK stops established and new h1 traffic; another host remains usable', stream=stream_result)
        dump = switch_flows()
        (runtime / 'blocked-flows.txt').write_text(dump)
        assert 'priority=50000' in dump
        obsolete_cookies = pre_block_cookies | {row['cookie'] for row in state()['flows']}
        release_reply = admin('release', 'h1')
        released = state()
        release_operation = next(op for op in released['operations'] if op['id'] == release_reply['id'])
        assert not any(row['cookie'] in obsolete_cookies for row in released['flows'])
        actual_after_release = switch_flows()
        assert not any(f'cookie=0x{cookie:x},' in actual_after_release for cookie in obsolete_cookies)
        # Kernel retransmissions may prompt a NEW policy decision on the same tuple.
        # Prove old permissions are gone rather than assuming no post-release traffic.
        assert all(row['installed_at'] >= release_operation['updated_at']
                   for row in released['flows'] if row['flow']['source_ip'] == '10.0.0.1')
        assert client('h1')['received'] == 1
        passed('Release clears old permissions before removing block; fresh authorization succeeds',
               retired_cookie_count=len(obsolete_cookies))

        h1 = net.get('h1')
        report['spoof_network'] = dict(before=network_state('h1'))
        h1.cmd('ip link set dev h1-eth0 address 02:00:00:00:00:99')
        try:
            report['spoof_network']['after_mac_change'] = network_state('h1')
            restore_neighbors('h1')
            dropped_before = ingress_drop_packets()
            spoofed = client('h1')
            assert spoofed['received'] == 0 and spoofed['error'], spoofed
            dropped_after = ingress_drop_packets()
            assert dropped_after > dropped_before, 'Spoofed traffic did not reach the switch ingress drop'
        finally:
            h1.cmd('ip link set dev h1-eth0 address 02:00:00:00:00:01')
            restore_neighbors('h1')
            report['spoof_network']['restored'] = network_state('h1')
        restored = client('h1')
        assert restored['received'] == 1, restored
        passed('Spoofed ingress MAC hits switch drop; restored identity exchanges fresh TCP payloads',
               dropped_packets=dropped_after-dropped_before)
        reverse_receipts = server('h1', 9100)
        assert client('h1', '127.0.0.1', 9100)['received'] == 1
        reverse_before = read(reverse_receipts)['messages']
        assert client('h2', '10.0.0.1', 9100)['received'] == 0
        assert read(reverse_receipts)['messages'] == reverse_before
        passed('Unsolicited reverse connection denied against a real listener')

        logger.terminate(); logger.wait(timeout=5)
        assert client('h3', count=3)['received'] == 3
        wait_for(lambda: state()['logger']['backlog'] > 0, 'visible audit backlog during outage')
        logger = launch('logger')
        wait_for(lambda: state()['logger']['backlog'] == 0 and not state()['logger']['error'], 'audit retry recovery')
        stored = recent_events(runtime / 'events.sqlite3', state()['run_id'])
        assert any(event['action'] == 'ALLOW' and event['status'] == 'confirmed' for event in stored)
        passed('TCP logger outage preserves enforcement; queued events persist after recovery')

        # Create a fresh, long-lived tuple immediately before controller loss.
        stream = client('h3', count=900, interval=.1, background=True)
        before = read(allowed_receipts)['messages']
        wait_for(lambda: read(allowed_receipts)['messages'] > before + 3, 'stream before controller loss')
        before_loss = switch_flows()
        assert allow_permissions(before_loss), 'No forwarding permissions before controller-loss test'
        (runtime / 'before-controller-loss-flows.txt').write_text(before_loss)
        lost_at = time.time()
        lost_monotonic = time.monotonic()
        loss = report['controller_loss'] = dict(lost_at=lost_at, deadline_seconds=policy.permission_seconds + 5,
                                                samples=[])
        controller.terminate(); controller.wait(timeout=5)
        loss['controller_exit_after_seconds'] = time.monotonic() - lost_monotonic
        expiry = wait_for_permission_expiry(switch_flows, lost_monotonic, loss['deadline_seconds'], loss['samples'])
        loss['permissions_absent_after_seconds'] = expiry['seconds_after_loss']
        (runtime / 'after-controller-loss-flows.txt').write_text(expiry['ovs'])
        stream_out, stream_err = stream.communicate(timeout=8)
        loss_result = json.loads(stream_out)
        loss['client'] = loss_result
        loss['client_observed_finished_after_seconds'] = time.monotonic() - lost_monotonic
        assert loss_result['error'] and loss_result['received'] < 900
        settled = read(allowed_receipts)['messages']
        time.sleep(1)
        assert read(allowed_receipts)['messages'] == settled, 'Receiver continued after permission expiry'
        assert client('h1')['received'] == 0
        passed('Controller loss expires existing permissions within documented bound and denies new traffic',
               permissions_absent_after_seconds=loss['permissions_absent_after_seconds'],
               client_observed_finished_after_seconds=loss['client_observed_finished_after_seconds'])
        prior_run = state()['run_id']
        controller = launch('controller')
        wait_for(lambda: state()['run_id'] != prior_run and state()['ready'], 'restart reconciliation', timeout=20)
        recovered = client('h1')
        assert recovered['received'] == 1, recovered
        passed('Controller restart reconciles rules and authorizes a fresh TCP exchange', result=recovered)
        admin('block', 'h1')
        blocked_run = state()['run_id']
        controller.terminate(); controller.wait(timeout=5)
        controller = launch('controller')
        wait_for(lambda: state()['run_id'] != blocked_run and state()['ready'], 'restore persisted block', timeout=20)
        assert client('h1')['received'] == 0
        assert any(host['name'] == 'h1' and host['block_confirmed'] for host in state()['hosts'])
        passed('Restart restores deliberate host blocks and uses a new run identifier')
        admin('release', 'h1')

        if escalation.mode != 'off':
            receipts = {9001: forbidden_receipts}
            for port in range(9002, 9006):
                receipts[port] = server('h2', port)
                listening = client('h2', '127.0.0.1', port)
                assert listening['received'] == 1, listening
            receipts_before = {port: read(path)['messages'] for port, path in receipts.items()}
            for _ in range(3):
                retry = client('h1', port=9001)
                assert retry['received'] == 0, retry
            wait_for(lambda: state()['escalation']['hosts']['h1']['distinct_services'] == 1,
                     'same-service retry deduplication')
            assert not any(host['block_requested'] for host in state()['hosts'])
            assert client('h1')['received'] == 1
            passed('Escalation counts repeated denied service attempts once; allowed traffic remains usable')

            stream = client('h1', count=600, interval=.1, background=True)
            before = read(allowed_receipts)['messages']
            wait_for(lambda: read(allowed_receipts)['messages'] > before + 3, 'stream before automatic escalation')
            for port in range(9002, 9005):
                below_threshold = client('h1', port=port)
                assert below_threshold['received'] == 0, below_threshold
            wait_for(lambda: state()['escalation']['hosts']['h1']['distinct_services'] == 4,
                     'four distinct prohibited services')
            assert not any(host['block_requested'] for host in state()['hosts'])
            passed('Below-threshold activity does not trigger a host block')

            if escalation.mode == 'enforce':
                logger.terminate(); logger.wait(timeout=5)
            trigger = client('h1', port=9005)
            assert trigger['received'] == 0, trigger
            assert all(read(path)['messages'] == receipts_before[port] for port, path in receipts.items())
            if escalation.mode == 'observe':
                wait_for(lambda: state()['escalation']['signals'] == 1, 'observation threshold notification')
                assert not any(host['block_requested'] or host['block_confirmed'] for host in state()['hosts'])
                assert client('h1')['received'] == 1
                stream.terminate(); stream.wait(timeout=5)
                passed('Observation-only threshold logs evidence without blocking permitted TCP traffic')
            else:
                def automatic_confirmation():
                    return next((operation for operation in state()['operations']
                                 if operation.get('origin') == 'automatic' and operation['action'] == 'BLOCK'
                                 and operation['status'] == 'confirmed'), None)
                operation = wait_for(automatic_confirmation, 'automatic block readback confirmation')
                assert operation['evidence']['distinct_services'] == 5, operation
                assert {row['port'] for row in operation['evidence']['services']} == set(range(9001, 9006))
                stream_result = json.loads(stream.communicate(timeout=5)[0])
                assert stream_result['received'] < 600 and stream_result['error'], stream_result
                assert client('h1')['received'] == 0
                assert client('h3')['received'] == 1
                assert read(runtime/'blocked.json') == ['h1']
                passed('Automatic BLOCK stops existing and new traffic with logger offline; h3 remains usable',
                       operation=operation, stream=stream_result)
                logger = launch('logger')
                wait_for(lambda: state()['logger']['backlog'] == 0 and not state()['logger']['error'],
                         'automatic evidence persistence after logger recovery')
                stored = recent_events(runtime/'events.sqlite3', state()['run_id'])
                assert any(event.get('operation_id') == operation['id'] and event['status'] == 'confirmed'
                           and event['evidence']['distinct_services'] == 5 for event in stored)
                panel = dashboard_state()
                assert panel['controller']['escalation']['mode'] == 'enforce'
                assert any(host['name'] == 'h1' and host['block_confirmed']
                           for host in panel['controller']['hosts'])
                assert any(event.get('operation_id') == operation['id'] for event in panel['events'])
                atomic_json(runtime/'escalation-evidence.json', dict(operation=operation, presentation=panel))
                passed('Automatic block evidence persists over TCP and agrees with the local dashboard')

                previous_run = state()['run_id']
                controller.terminate(); controller.wait(timeout=5)
                controller = launch('controller')
                wait_for(lambda: state()['run_id'] != previous_run and state()['ready'],
                         'automatic block restart reconciliation', timeout=20)
                assert client('h1')['received'] == 0
                assert any(host['name'] == 'h1' and host['block_confirmed'] for host in state()['hosts'])
                assert state()['escalation']['hosts']['h1']['distinct_services'] == 0
                passed('Restart preserves the automatic block and starts a fresh evidence window')
                admin('release', 'h1')
                assert client('h1')['received'] == 1
                assert client('h1', port=9001)['received'] == 0
                wait_for(lambda: state()['escalation']['hosts']['h1']['distinct_services'] == 1,
                         'fresh evidence after deliberate release')
                assert not any(host['block_requested'] for host in state()['hosts'])
                assert client('h1')['received'] == 1
                passed('Manual release restores permitted traffic without reusing old escalation evidence')

        # Live mode changes use the same HTTP/admin queue as the host controls.
        live_run = state()['run_id']
        admin('mode', mode='off')
        assert state()['escalation']['mode'] == 'off'
        assert all(row['distinct_services'] == 0 and not row['threshold_reached']
                   for row in state()['escalation']['hosts'].values())
        assert client('h1')['received'] == 1
        assert client('h1', port=9001)['received'] == 0
        if not escalation.eligible_hosts:
            for mode in ('observe', 'enforce'):
                admin('mode', mode=mode, rejected=True)
            assert state()['escalation']['mode'] == 'off'
            assert read(runtime/'escalation-mode.json') == {'mode': 'off'}
            passed('Dashboard rejects Observe/Enforce without configured hosts; Off preserves normal TCP policy')
        else:
            if escalation.mode == 'off':
                for port in range(9002, 9006):
                    server('h2', port)
                    assert client('h2', '127.0.0.1', port)['received'] == 1
            admin('block', 'h3')
            admin('mode', mode='observe')
            for port in range(9001, 9006):
                assert client('h1', port=port)['received'] == 0
            wait_for(lambda: state()['escalation']['hosts']['h1']['threshold_reached'], 'live Observe threshold')
            assert not next(host for host in state()['hosts'] if host['name'] == 'h1')['block_requested']
            assert client('h1')['received'] == 1 and client('h3')['received'] == 0
            passed('Live Observe collects threshold evidence without blocking; existing host block remains')

            admin('mode', mode='enforce')
            assert state()['run_id'] == live_run
            assert state()['escalation']['hosts']['h1'] == dict(distinct_services=0, threshold_reached=False)
            assert client('h1')['received'] == 1
            for port in range(9001, 9005):
                assert client('h1', port=port)['received'] == 0
            wait_for(lambda: state()['escalation']['hosts']['h1']['distinct_services'] == 4, 'fresh Enforce observations')
            assert not next(host for host in state()['hosts'] if host['name'] == 'h1')['block_requested']
            assert client('h1')['received'] == 1
            previous = {op['id'] for op in state()['operations']}
            assert client('h1', port=9005)['received'] == 0
            operation = wait_for(lambda: next((op for op in state()['operations'] if op['id'] not in previous
                and op.get('origin') == 'automatic' and op['status'] == 'confirmed'), None), 'fresh live Enforce block')
            assert operation['evidence']['distinct_services'] == 5
            assert client('h1')['received'] == 0
            passed('Entering Enforce requires fresh observations before a verified automatic block', operation=operation)

            admin('mode', mode='off')
            assert client('h1')['received'] == 0 and client('h3')['received'] == 0
            admin('release', 'h1')
            assert client('h1')['received'] == 1 and client('h1', port=9001)['received'] == 0
            assert read(runtime/'escalation-mode.json') == {'mode': 'off'}
            prior_run = state()['run_id']
            controller.terminate(); controller.wait(timeout=5)
            controller = launch('controller')
            wait_for(lambda: state()['run_id'] != prior_run and state()['ready'], 'saved mode restart', timeout=20)
            assert state()['escalation']['mode'] == 'off'
            assert client('h1')['received'] == 1 and client('h3')['received'] == 0
            assert next(host for host in state()['hosts'] if host['name'] == 'h3')['block_confirmed']
            passed('Saved Off overrides startup mode across restart; host blocks and normal policy persist')
            admin('release', 'h3')
            admin('mode', mode=escalation.mode)

        if not args.test:
            print('All Blue is running at http://127.0.0.1:18080. Exit the Mininet CLI to stop.', flush=True)
            CLI(net)
        report['status'] = 'passed'
        report['finished_at'] = time.time()
        evidence()
        print(f'Acceptance evidence: {runtime / "acceptance.json"}', flush=True)
        return 0
    except BaseException as error:
        report['status'], report['error'], report['traceback'] = 'failed', str(error), traceback.format_exc()
        try:
            report['controller_error'] = state().get('error')
            report['last_operation'] = next(iter(state().get('operations', [])), None)
        except (OSError, ValueError):
            pass
        if net:
            try:
                report['failure_network'] = {host.name: network_state(host.name) for host in net.hosts}
                (runtime / 'failure-flows.txt').write_text(switch_flows())
            except (OSError, ValueError, subprocess.SubprocessError) as diagnostic_error:
                report['diagnostic_error'] = str(diagnostic_error)
        evidence()
        print(report['traceback'], file=sys.stderr, flush=True)
        print('Controller detail:', report.get('controller_error'), report.get('last_operation'), file=sys.stderr, flush=True)
        print(f'Failure evidence: {runtime}', file=sys.stderr, flush=True)
        return 1
    finally:
        cleanup_errors = []
        for process in reversed(processes):
            try:
                stop_process(process)
            except (OSError, subprocess.SubprocessError) as error:
                cleanup_errors.append(str(error))
        if net:
            try:
                net.stop()
            except Exception as error:
                cleanup_errors.append(str(error))
        for output in outputs:
            output.close()
        for path in runtime.iterdir():
            if path.is_file() and not path.is_symlink():
                os.chown(path, uid, gid)
        signal.signal(signal.SIGTERM, previous_term)
        if cleanup_errors:
            report['status'] = 'failed'
            report['cleanup_errors'] = cleanup_errors
            evidence()
            raise RuntimeError('Lab cleanup failed: ' + '; '.join(cleanup_errors))


if __name__ == '__main__':
    raise SystemExit(main())
