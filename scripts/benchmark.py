#!/usr/bin/env python3
"""Repeat isolated experiments through the existing Mininet launcher; no synthetic fallback."""
import argparse
import csv
from dataclasses import replace
import html
import json
import math
import os
from pathlib import Path
import platform
import re
import signal
import statistics
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from all_blue.policy import Flow
from all_blue.rules import PREFIX, base_rules, tuple_rules
from all_blue.storage import atomic_json, recent_events
from scripts.lab import read, stop_process, wait_for


def percentile(values, percent):
    values = sorted(values)
    if not values or not all(math.isfinite(value) for value in values):
        raise ValueError('Finite measured samples required')
    position = (len(values) - 1) * percent / 100
    low, high = math.floor(position), math.ceil(position)
    return values[low] + (values[high] - values[low]) * (position - low)


def elapsed_ms(start, end):
    if not isinstance(start, int) or not isinstance(end, int) or end < start:
        raise ValueError('Invalid monotonic timing boundary')
    return (end - start) / 1e6


def audit_drained(health):
    # Queue.get() and setting the pending flag are separate operations. An empty
    # queue alone can briefly precede acknowledgement; require event accounting.
    return (health['backlog'] == 0 and not health['error']
            and health['generated'] == health['delivered'] + health['dropped'])


def flow_rows(dump):
    rows = []
    for line in dump.splitlines():
        if 'cookie=' not in line:
            continue
        if ' actions=' not in line:
            raise ValueError('Incomplete OVS flow dump')
        fields, actions = line.strip().split(' actions=', 1)
        values = dict(re.findall(r'(\w+)=([^, ]+)', fields))
        values['actions'] = actions
        rows.append(values)
    if not rows:
        raise ValueError('OVS returned no flow evidence')
    return rows


def static_rules(policy):
    # Same identity table and default drops. Static service rules deliberately
    # wildcard the client port, have no expiry, and never send to a controller.
    rules = [rule for rule in base_rules(policy) if rule.output is None]
    for index, (source, destination, port) in enumerate(sorted(policy.allowed)):
        src, dst = policy.hosts[source], policy.hosts[destination]
        flow = Flow(src.port, src.mac, dst.mac, src.ip, dst.ip, 40000, port)
        for direction, rule in enumerate(tuple_rules(policy, flow, 'ALLOW', PREFIX | 0x200000 | index)):
            fields = dict(rule.fields)
            fields.pop('tcp_src' if direction == 0 else 'tcp_dst')
            rules.append(replace(rule, fields=fields, hard_timeout=0))
    return rules


def ovs_text(rule):
    names = dict(eth_src='dl_src', eth_dst='dl_dst', eth_type='dl_type', ipv4_src='nw_src',
                 ipv4_dst='nw_dst', ip_proto='nw_proto', tcp_src='tp_src', tcp_dst='tp_dst')
    fields = [f'cookie=0x{rule.cookie:x}', f'table={rule.table}', f'priority={rule.priority}',
              f'hard_timeout={rule.hard_timeout}']
    for name, value in rule.fields.items():
        if name == 'ip_frag':
            if value != (0, 1):
                raise ValueError('Unsupported fragment match')
            fields.append('nw_frag=no')
        elif name == 'tcp_flags':
            if value != (0x10, 0x10):
                raise ValueError('Unsupported TCP flag match')
            fields.append('tcp_flags=+ack')
        else:
            fields.append(f'{names.get(name, name)}={hex(value) if name == "eth_type" else value}')
    actions = f'goto_table:{rule.goto}' if rule.goto is not None else f'output:{rule.output}' if rule.output else 'drop'
    return ','.join(fields) + ' actions=' + actions


def install_static(policy, runtime, target='ab-s1', env=None):
    path = runtime / 'static-flows.txt'
    path.write_text('\n'.join(ovs_text(rule) for rule in static_rules(policy)) + '\n')
    command = ['ovs-ofctl', '-O', 'OpenFlow13']
    subprocess.run(command + ['--bundle', 'add-flows', target, str(path)], check=True, timeout=10, env=env)
    # diff-flows reads the actual switch and ignores traffic counters/durations.
    result = subprocess.run(command + ['diff-flows', str(path), target],
                            capture_output=True, text=True, timeout=10, env=env)
    (runtime / 'static-readback.txt').write_text(result.stdout + result.stderr)
    if result.returncode or result.stdout.strip():
        raise AssertionError('Static rule readback differs: ' + result.stdout + result.stderr)


def verify_receipts(result, before, after, expected):
    if result['received'] != expected:
        raise AssertionError(f'TCP echo count {result["received"]} != {expected}: {result.get("error")}')
    if after['messages'] - before['messages'] != expected:
        raise AssertionError('Independent receiver count differs from client')
    if expected:
        if result['error'] or result['sent'] != expected:
            raise AssertionError('Incomplete TCP workload')
        if after['bytes'] - before['bytes'] != expected * 1024 or result['received_bytes'] != expected * 1024:
            raise AssertionError('Independent receiver byte count differs')
        if not all(row['text'].startswith(result['token'] + ':') for row in after['recent'][-min(32, expected):]):
            raise AssertionError('Receiver token does not match this workload')
    elif not result['error'] or after['bytes'] != before['bytes']:
        raise AssertionError('Denied attempt lacks timeout/receiver evidence')


def allow_metrics(result, expected, permission_seconds):
    if len(result['rtt_ms']) != expected or expected < 2:
        raise ValueError('Missing measured round trips')
    if elapsed_ms(result['connect_started_ns'], result['completed_monotonic_ns']) >= permission_seconds * 1000:
        raise ValueError('Workload exceeded permission lifetime; steady-state sample is invalid')
    for name in ('connect_ms', 'first_flow_ms', 'steady_goodput_mbps'):
        value = result[name]
        if not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
            raise ValueError(f'Missing or invalid measurement: {name}')
    return dict(connect_ms=result['connect_ms'], first_flow_ms=result['first_flow_ms'],
                steady_rtt_p50_ms=percentile(result['rtt_ms'][1:], 50),
                steady_rtt_p95_ms=percentile(result['rtt_ms'][1:], 95),
                steady_goodput_mbps=result['steady_goodput_mbps'], delivery_success_pct=100 * result['received'] / expected)


def experiment(args, runtime, policy, startup_ns, ready_ns, client, server, state, switch_flows, launch, logger):
    mode = 'static' if args.static else 'all-blue-verbose' if args.verbose else 'all-blue'
    result = dict(mode=mode, scenario=args.benchmark, valid=False, metrics={}, evidence={})
    metrics, evidence = result['metrics'], result['evidence']
    atomic_json(runtime / 'benchmark.json', result)

    def dump(label):
        actual = switch_flows()
        (runtime / f'benchmark-{label}-flows.txt').write_text(actual)
        return flow_rows(actual)

    def listener(port):
        path = server('h2', port)
        probe = client('h2', '127.0.0.1', port)
        if probe['received'] != 1 or read(path)['messages'] != 1:
            raise AssertionError(f'Service {port} was not independently verified listening')
        return path

    def measured(path, port=9000, count=1, host='h1', expected=None):
        before = read(path)
        value = client(host, port=port, count=count, interval=0, measure=True)
        after = read(path)
        verify_receipts(value, before, after, count if expected is None else expected)
        evidence.setdefault('transfers', []).append(dict(port=port, host=host, client=value,
            receiver_before={key: before[key] for key in ('messages', 'bytes')},
            receiver_after={key: after[key] for key in ('messages', 'bytes')},
            receiver_token=value.get('token')))
        return value

    def confirmation(action, source_port=None):
        def find():
            for op in state()['operations']:
                if op['action'] != action or (source_port is not None and op.get('flow', {}).get('source_port') != source_port):
                    continue
                if action == 'BLOCK' and op.get('origin') != 'automatic':
                    continue
                if op['status'] in ('failed', 'superseded'):
                    raise AssertionError(op)
                if op['status'] == 'confirmed':
                    return op
        op = wait_for(find, f'{action} barrier/readback confirmation')
        evidence.setdefault('operations', []).append(op)
        return op

    try:
        metrics['startup_ms'] = elapsed_ms(startup_ns, ready_ns)
        metrics['rules_ready'] = len(dump('ready'))
        allowed = listener(9000)
        if args.benchmark == 'allow':
            value = measured(allowed, count=201)
            metrics.update(allow_metrics(value, 201, policy.permission_seconds))
            rows = dump('allowed')
            if not args.static:
                confirmation('ALLOW', value['source_port'])
                selected = [row for row in rows if row.get('tp_src') == str(value['source_port']) or row.get('tp_dst') == str(value['source_port'])]
                if len(selected) != 2 or any('output:' not in row['actions'] or int(row['n_packets']) == 0 for row in selected):
                    raise AssertionError('Actual forward/reverse ALLOW rules or counters missing')
            elif not any('output:' in row['actions'] and int(row['n_packets']) > 0 for row in rows):
                raise AssertionError('No static forwarding counter evidence')
            metrics['rules_active'] = len(rows)
        elif args.benchmark == 'deny':
            forbidden = listener(9001)
            before_rows = dump('before-deny')
            value = measured(forbidden, 9001, expected=0)
            metrics['unauthorized_payloads'] = 0
            metrics['denied_probe_elapsed_ms'] = elapsed_ms(value['connect_started_ns'], value['completed_monotonic_ns'])
            if not args.static:
                op = confirmation('DENY', value['source_port'])
                metrics['deny_decision_confirm_ms'] = elapsed_ms(op['requested_monotonic_ns'], op['updated_monotonic_ns'])
                metrics['deny_attempt_confirm_ms'] = elapsed_ms(value['connect_started_ns'], op['updated_monotonic_ns'])
            rows = dump('denied')
            if args.static:
                dropped = lambda data: sum(int(row['n_packets']) for row in data if row.get('table') == '1' and row.get('priority') == '0')
                if dropped(rows) <= dropped(before_rows):
                    raise AssertionError('Static default-deny counter did not increase')
                evidence['deny_timing'] = 'Preinstalled default deny; reactive confirmation latency is not applicable'
            elif not any(row.get('tp_src') == str(value['source_port']) and row['actions'] == 'drop' and row.get('priority') == '1000' for row in rows):
                raise AssertionError('Independent OVS DENY rule missing')
            metrics['rules_active'] = len(rows)
        elif args.benchmark == 'block':
            forbidden = {port: listener(port) for port in range(9001, 9006)}
            stream = client('h1', count=1000, interval=.02, background=True)
            start_count = read(allowed)['messages']
            wait_for(lambda: read(allowed)['messages'] > start_count + 3, 'established stream before escalation')
            attempts = [measured(path, port, expected=0) for port, path in forbidden.items()]
            metrics['unauthorized_payloads'] = 0
            if args.static:
                if read(allowed)['messages'] <= start_count + 3:
                    raise AssertionError('Static baseline stream did not continue during violation campaign')
                evidence['stream_receipts_after_campaign'] = read(allowed)['messages']
                stop_process(stream)
                time.sleep(.3)
                measured(allowed)
                metrics['automatic_blocks'] = 0
                metrics['rules_active'] = len(dump('static-after-campaign'))
                evidence['block_timing'] = 'No automatic blocking in static baseline; permitted traffic remained usable'
            else:
                op = confirmation('BLOCK')
                if op['evidence']['distinct_services'] != 5:
                    raise AssertionError('Escalation evidence did not reach the configured threshold')
                metrics['automatic_blocks'] = 1
                metrics['block_trigger_request_ms'] = elapsed_ms(attempts[-1]['connect_started_ns'], op['requested_monotonic_ns'])
                metrics['block_trigger_confirm_ms'] = elapsed_ms(attempts[-1]['connect_started_ns'], op['updated_monotonic_ns'])
                metrics['block_decision_confirm_ms'] = elapsed_ms(op['requested_monotonic_ns'], op['updated_monotonic_ns'])
                metrics['block_campaign_confirm_ms'] = elapsed_ms(attempts[0]['connect_started_ns'], op['updated_monotonic_ns'])
                rows = dump('blocked')
                metrics['block_ovs_observed_ms'] = elapsed_ms(attempts[-1]['connect_started_ns'], time.monotonic_ns())
                blocks = [row for row in rows if row.get('priority') == '50000' and row['actions'] == 'drop']
                if len(blocks) != 2 or not any(row.get('in_port') == '1' for row in blocks) or not any(row.get('dl_dst') == policy.hosts['h1'].mac for row in blocks):
                    raise AssertionError('Independent ingress/egress host block rules missing')
                output, error = stream.communicate(timeout=8)
                evidence['established_stream'] = json.loads(output)
                if stream.returncode or not evidence['established_stream']['error'] or evidence['established_stream']['received'] >= 1000:
                    raise AssertionError('Established stream was not interrupted: ' + error)
                time.sleep(.3)
                settled = read(allowed)['messages']; time.sleep(.5)
                if read(allowed)['messages'] != settled:
                    raise AssertionError('Receiver still advanced after confirmed block')
                measured(allowed, expected=0)
                measured(allowed, host='h3')
                metrics['rules_active'] = len(rows)
        else:
            if args.static:
                raise ValueError('Static baseline has no audit logger; outage is not applicable')
            forbidden = listener(9001)
            wait_for(lambda: audit_drained(state()['logger']), 'audit idle before outage')
            before = state()['logger']
            stored_before = {event['id'] for event in recent_events(runtime/'events.sqlite3', state()['run_id'], limit=10000)}
            if logger.poll() is not None:
                raise AssertionError('Logger already exited before controlled outage')
            stop_process(logger)
            outage_ns = time.monotonic_ns()
            for _ in range(3):
                permitted = measured(allowed, count=3)
                confirmation('ALLOW', permitted['source_port'])
                value = measured(forbidden, 9001, expected=0)
                confirmation('DENY', value['source_port'])
            outage_rows = dump('logger-outage')
            if not any(row.get('tp_src') == str(value['source_port']) and row['actions'] == 'drop' for row in outage_rows):
                raise AssertionError('Independent DENY readback missing during logger outage')
            queued = wait_for(lambda: state()['logger'] if state()['logger']['backlog'] > 0 else None, 'audit queue during outage')
            restart_ns = time.monotonic_ns()
            launch('logger')
            wait_for(lambda: audit_drained(state()['logger']), 'all queued audit acknowledgements', timeout=20)
            after = state()['logger']
            stored = recent_events(runtime/'events.sqlite3', state()['run_id'], limit=10000)
            new_stored = [event for event in stored if event['id'] not in stored_before]
            generated = after['generated'] - before['generated']
            delivered = after['delivered'] - before['delivered']
            lost = after['dropped'] - before['dropped']
            if generated != delivered + lost or len(new_stored) != delivered:
                raise AssertionError('Generated, acknowledged, dropped and persisted event counts disagree')
            confirmed_ids = {op['id'] for op in evidence['operations']}
            if not confirmed_ids <= {event.get('operation_id') for event in new_stored if event['status'] == 'confirmed'}:
                raise AssertionError('Outage decisions missing from persisted logger records')
            metrics.update(outage_ms=elapsed_ms(outage_ns, restart_ns), queued_events=queued['backlog'],
                generated_events=generated, acknowledged_events=delivered, persisted_events=len(new_stored),
                lost_events=lost, recovery_ack_ms=elapsed_ms(restart_ns, after['last_ack_monotonic_ns']),
                recovery_observed_ms=elapsed_ms(restart_ns, time.monotonic_ns()), unauthorized_payloads=0,
                allowed_payloads=9, rules_active=len(dump('outage-recovered')))
            evidence['audit'] = dict(before=before, outage=queued, after=after, persisted_event_ids=[event['id'] for event in new_stored])
        if not args.static:
            wait_for(lambda: audit_drained(state()['logger']), 'final audit delivery')
            evidence['logger_final'] = state()['logger']
            evidence['terminal'] = state()['terminal']
            metrics['terminal_dropped'] = state()['terminal']['dropped']
        result['valid'] = True
        return result
    except BaseException as error:
        result['error'] = f'{type(error).__name__}: {error}'
        raise
    finally:
        atomic_json(runtime / 'benchmark.json', result)


def summarize(rows):
    groups = {}
    for row in rows:
        if not row['valid']:
            continue
        for name, value in row['metrics'].items():
            if isinstance(value, (int, float)) and math.isfinite(value):
                groups.setdefault((row['mode'], row['scenario'], name), []).append(value)
    return [dict(mode=mode, scenario=scenario, metric=metric, n=len(values), mean=statistics.mean(values),
                 median=statistics.median(values), p95=percentile(values, 95), minimum=min(values), maximum=max(values),
                 stdev=statistics.stdev(values) if len(values) > 1 else 0)
            for (mode, scenario, metric), values in sorted(groups.items())]


def write_results(directory, rows):
    atomic_json(directory / 'measurements.json', rows)
    with (directory/'measurements.csv').open('w', newline='') as stream:
        writer = csv.writer(stream)
        writer.writerow(('trial', 'mode', 'scenario', 'valid', 'metric', 'value', 'runtime', 'error'))
        for row in rows:
            for metric, value in (row['metrics'].items() or [('', '')]):
                writer.writerow((row['trial'], row['mode'], row['scenario'], row['valid'], metric, value, row.get('runtime', ''), row.get('error', '')))
    summary = summarize(rows)
    with (directory/'summary.csv').open('w', newline='') as stream:
        writer = csv.DictWriter(stream, fieldnames=('mode', 'scenario', 'metric', 'n', 'mean', 'median', 'p95', 'minimum', 'maximum', 'stdev'))
        writer.writeheader(); writer.writerows(summary)
    # Dependency-free SVG scatter panels of measured trial values, never example data.
    panels = [('allow', 'first_flow_ms'), ('allow', 'steady_goodput_mbps'), ('allow', 'steady_rtt_p50_ms'),
              ('allow', 'rules_active'), ('deny', 'deny_attempt_confirm_ms'), ('block', 'block_trigger_confirm_ms'),
              ('outage', 'recovery_ack_ms'), ('allow', 'startup_ms')]
    svg = ['<svg xmlns="http://www.w3.org/2000/svg" width="900" height="1520" viewBox="0 0 900 1520">',
           '<rect width="900" height="1520" fill="white"/>', '<g font-family="sans-serif" font-size="13" fill="#153c44">']
    for panel, (scenario, metric) in enumerate(panels):
        top = panel * 190 + 25
        svg.append(f'<text x="20" y="{top}">{html.escape(scenario + ": " + metric)}</text>')
        values = [row['metrics'][metric] for row in rows if row['valid'] and row['scenario'] == scenario and metric in row['metrics']]
        maximum = max(values, default=0) or 1
        for index, mode in enumerate(('static', 'all-blue', 'all-blue-verbose')):
            y = top + 35 + index * 42
            samples = [row['metrics'][metric] for row in rows if row['valid'] and row['mode'] == mode and row['scenario'] == scenario and metric in row['metrics']]
            svg.append(f'<text x="20" y="{y+4}">{mode}</text><line x1="170" x2="750" y1="{y}" y2="{y}" stroke="#d4e5e4"/>')
            for sample in samples:
                svg.append(f'<circle cx="{170+580*sample/maximum:.2f}" cy="{y}" r="4" fill="#087c86"><title>{sample:.6g}</title></circle>')
            label = f'median {statistics.median(samples):.3g}' if samples else 'no valid data'
            svg.append(f'<text x="760" y="{y+4}">{label}</text>')
        svg.append(f'<text x="170" y="{top+158}">0</text><text x="700" y="{top+158}">{maximum:.3g}</text>')
    svg.extend(['</g>', '</svg>']); (directory/'graphs.svg').write_text('\n'.join(svg))
    valid = sum(row['valid'] for row in rows)
    report = [f'# All Blue real TCP benchmark results\n\n{valid}/{len(rows)} attempted measurements valid. Invalid trials are excluded from summaries.',
        'Same three-host Mininet topology, policy identities, permanent neighbors, 1024-byte echo workload and host. '
        'Each scenario/trial creates a fresh switch, namespaces, controller, database and receiver evidence. '
        'Execution order rotates each trial. Local fsync per echo is included: goodput measures this application, not link capacity.',
        'Startup: service launch/network construction to verified readiness (includes polling). First flow: before connect to first verified echo. '
        'Steady RTT: subsequent 200 exchanges. Goodput: echoed payload bits after first reply divided by time to last reply; excludes startup and first flow. '
        'DENY: controller decision/attempt to barrier+readback confirmation, separately from TCP timeout. '
        'BLOCK: fifth service attempt to automatic request (includes network/detection), then decision and first campaign attempt to confirmation; independent OVS observation is an upper bound. '
        'Logger recovery: restart request to last received durable acknowledgement, with polling observation separately reported. All durations use monotonic clocks.',
        'Static baseline uses the same ingress bindings and default drops, with preinstalled service/ACK-return rules and wildcard client ports. '
        'It has no exact dynamic reverse authorization, finite permissions, automatic blocks or audit logger. Those latencies are not applicable, never zero-valued substitutes. '
        'Dynamic escalation is enabled only for the block experiment. Terminal logging remains off in the normal dynamic profile.',
        'Audit loss means observed in-process dropped events. Crashes can lose memory queues; no crash-durability or guaranteed-delivery claim. '
        'The raw run directory contains receiver records, exact client samples, OVS dumps, controller operations, SQLite events and source hashes.',
        '| Mode | Scenario | Metric | n | Mean | Median | p95 | Std dev |\n|---|---|---|---:|---:|---:|---:|---:|']
    visible = set(panels) | {('deny', 'unauthorized_payloads'), ('block', 'automatic_blocks'),
        ('outage', 'queued_events'), ('outage', 'acknowledged_events'), ('outage', 'persisted_events'), ('outage', 'lost_events')}
    report.extend(f'| {r["mode"]} | {r["scenario"]} | {r["metric"]} | {r["n"]} | {r["mean"]:.4g} | {r["median"]:.4g} | {r["p95"]:.4g} | {r["stdev"]:.4g} |'
                  for r in summary if (r['scenario'], r['metric']) in visible)
    report.append('\nFull measurements and summaries: `measurements.csv`, `summary.csv`. '
                  'Paired changes below are (comparison − reference) / reference × 100, averaged across valid matching trials.')
    report.append('| Comparison / reference | ALLOW metric | Pairs | Mean change |\n|---|---|---:|---:|')
    for reference, comparison in [('static', 'all-blue'), ('all-blue', 'all-blue-verbose')]:
        for metric in ('first_flow_ms', 'steady_rtt_p50_ms', 'steady_goodput_mbps', 'rules_active'):
            pairs = []
            for row in rows:
                if not row['valid'] or row['mode'] != reference or row['scenario'] != 'allow' or not row['metrics'].get(metric):
                    continue
                other = next((candidate for candidate in rows if candidate['valid'] and candidate['trial'] == row['trial']
                              and candidate['mode'] == comparison and candidate['scenario'] == 'allow' and metric in candidate['metrics']), None)
                if other:
                    pairs.append(100 * (other['metrics'][metric] / row['metrics'][metric] - 1))
            if pairs:
                report.append(f'| {comparison} / {reference} | {metric} | {len(pairs)} | {statistics.mean(pairs):+.3g}% |')
    report.append('\n![Measured trial values](graphs.svg)\n\nInvalid measurements:')
    report.extend(f'- Trial {r["trial"]} {r["mode"]}/{r["scenario"]}: {r.get("error", "unknown failure")} ({r.get("runtime", "no runtime")})' for r in rows if not r['valid'])
    if valid == len(rows):
        report.append('None.')
    (directory/'RESULTS.md').write_text('\n\n'.join(report) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--trials', type=int, default=3, help='Repeated trials per condition (3..30)')
    args = parser.parse_args()
    if not 3 <= args.trials <= 30:
        parser.error('--trials must be 3..30')
    if os.geteuid() != 0:
        raise SystemExit('Use sudo for actual Mininet benchmarks; no simulated fallback is available.')
    directory = ROOT/'runtime'/f'benchmark-{time.strftime("%Y%m%d-%H%M%S")}'
    directory.mkdir(parents=True)
    uid, gid = int(os.environ.get('SUDO_UID', '0')), int(os.environ.get('SUDO_GID', '0'))
    os.chown(directory, uid, gid)
    conditions = [(mode, scenario) for mode in ('static', 'all-blue', 'all-blue-verbose')
                  for scenario in ('allow', 'deny', 'block', 'outage') if (mode, scenario) != ('static', 'outage')]
    atomic_json(directory/'environment.json', dict(platform=platform.platform(), python=sys.version, cpu_count=os.cpu_count(),
        trials=args.trials, topology='config/lab.json', workload=dict(messages=201, bytes_per_message=1024, interval=0),
        ovs=subprocess.check_output(['ovs-ofctl', '--version'], text=True), conditions=conditions))
    rows = []
    previous_term = signal.getsignal(signal.SIGTERM)
    def interrupted(_signum, _frame):
        raise KeyboardInterrupt('Benchmark interrupted; cleaning up the current lab')
    signal.signal(signal.SIGTERM, interrupted)
    print(f'Benchmark artifacts: {directory}', flush=True)
    try:
        for trial in range(1, args.trials + 1):
            order = conditions[(trial-1) % len(conditions):] + conditions[:(trial-1) % len(conditions)]
            for mode, scenario in order:
                row = dict(trial=trial, mode=mode, scenario=scenario, valid=False, metrics={})
                rows.append(row)
                command = [str(ROOT/'.venv/bin/python'), str(ROOT/'scripts/lab.py'), '--test', '--benchmark', scenario]
                if mode == 'static': command.append('--static')
                if mode == 'all-blue-verbose': command.append('--verbose')
                if scenario == 'block' and mode != 'static': command += ['--escalation', str(ROOT/'config/escalation-lab.json')]
                print(f'Trial {trial}/{args.trials}: {mode} {scenario}', flush=True)
                with (directory/f'{trial}-{mode}-{scenario}.log').open('w') as output:
                    process = subprocess.Popen(command, cwd=ROOT, stdout=output, stderr=subprocess.STDOUT)
                    try:
                        code = process.wait(timeout=180)
                        text = Path(output.name).read_text()
                        match = re.search(r'^Runtime: (.+)$', text, re.MULTILINE)
                        if match:
                            runtime = Path(match[1]); row['runtime'] = str(runtime)
                            path = runtime/'benchmark.json'
                            if path.exists():
                                row.update(read(path))
                            acceptance = read(runtime/'acceptance.json')
                            if acceptance['status'] != 'passed':
                                row['valid'] = False
                                row['error'] = acceptance.get('error') or 'Lab acceptance failed'
                        if code or not match:
                            row['valid'] = False
                            row['error'] = row.get('error') or f'Launcher exited {code}; see {output.name}'
                    except BaseException as error:
                        row['error'] = f'{type(error).__name__}: {error}'
                        row['valid'] = False
                        if isinstance(error, KeyboardInterrupt):
                            raise
                    finally:
                        stop_process(process, timeout=30)
                write_results(directory, rows)
                print('VALID' if row['valid'] else 'INVALID: ' + row.get('error', 'missing evidence'), flush=True)
                # If cleanup failed, do not touch the existing switch or run another experiment.
                if subprocess.run(['ovs-vsctl', 'br-exists', 'ab-s1'], capture_output=True).returncode == 0:
                    raise RuntimeError('ab-s1 still exists after cleanup; stopping experiments')
    finally:
        signal.signal(signal.SIGTERM, previous_term)
        write_results(directory, rows)
        for path in directory.iterdir():
            if path.is_file() and not path.is_symlink(): os.chown(path, uid, gid)
    print(f'Results: {directory / "RESULTS.md"}', flush=True)
    return 0 if rows and all(row['valid'] for row in rows) else 1


if __name__ == '__main__':
    raise SystemExit(main())
