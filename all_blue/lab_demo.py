"""Evidence-based interactive demonstrations, executed by the sole lab owner.

These records are demonstrations, never acceptance or benchmark results.
"""
import copy
import time

from .lab_actions import Cancelled


def run_demo(lab, command):
    initial = lab.controller()
    identity = (initial['run_id'], initial['switch_epoch'])
    host, kind = command['host'], command['kind']
    source = next((h for h in initial['hosts'] if h['name'] == host), None)
    if not source or source['block_requested'] or source['block_confirmed'] is not False:
        raise ValueError('Choose a configured host with freshly confirmed normal policy')
    services = [s for s in lab.state['services'] if s['host'] != host]
    def allowed(service):
        return any(r['source'] == host and r['destination'] == service['host'] and r['port'] == service['port']
                   for r in initial['policy']['allow'])
    permitted = next((s for s in services if allowed(s)), None)
    prohibited = [s for s in services if not allowed(s)]
    escalation = initial['escalation']
    threshold = escalation['threshold']
    if not permitted or not prohibited:
        raise ValueError('Demonstration needs permitted and prohibited owned services')
    if any(o['status'] in ('requested', 'pending') for o in initial['operations']):
        raise ValueError('Wait for pending controller operations')
    if kind == 'escalation':
        if host not in escalation['hosts']:
            raise ValueError('Host is not eligible; explicitly start the configured escalation profile')
        if len(prohibited) < threshold or escalation['window_seconds'] < threshold * 2 + 3:
            raise ValueError('Not enough prohibited services or observation time for this demonstration')
    elif escalation['mode'] == 'enforce' and host in escalation['hosts']:
        raise ValueError('Select Off or Observe before a traffic/block demonstration')
    demo = dict(id=command['id'], kind=kind, host=host, origin=command.get('origin', 'dashboard'),
                run_id=lab.state['run_id'], controller_run_id=identity[0], switch_epoch=identity[1],
                status='running', reason='Demonstration running', steps=[], started_at=time.time(),
                evidence_kind='interactive_demonstration', stop_requested=False)
    with lab.lock:
        lab.state['demo'] = demo
    lab.publish()
    revisions = {'host': None, 'mode': None, 'enforce': None}
    failed = None
    restoring = False

    def current():
        return lab.controller(identity)

    def checkpoint():
        current()
        if lab.cancel.is_set() or lab.state['status'] != 'running':
            raise Cancelled('Stop requested; remaining demo actions skipped')
        state = current()
        if revisions['mode'] and state.get('control_revisions', {}).get('@mode') != revisions['mode']:
            raise RuntimeError('A later mode choice interrupted the demonstration')

    def step(title, action):
        row = dict(title=title, status='pending', detail='Waiting for actual backend evidence')
        with lab.lock:
            demo['steps'].append(row)
        lab.publish()
        try:
            result = action()
            with lab.lock:
                row.update(detail=result, status='confirmed')
        except Exception as error:
            with lab.lock:
                row.update(status='failed', detail=str(error))
            raise
        finally:
            lab.publish()

    def wait(predicate, description, timeout=10):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not restoring:
                checkpoint()
            result = predicate(current())
            if result:
                return result
            time.sleep(.15)
        raise RuntimeError('Timed out waiting for ' + description)

    def control(details, target=None):
        current()
        if lab.state['status'] != 'running':
            raise Cancelled('Lab shutdown interrupted restoration')
        key = '@mode' if details['action'] == 'mode' else details.get('host')
        if restoring and key in demo.get('override_targets', []):
            raise RuntimeError('Later manual choice queued; restoration skipped')
        row = lab.child(command['id'], dict(details, controller_run_id=identity[0]))
        if target:
            revisions[target] = row['id']
        return row['reason']

    def mode(value):
        if not restoring:
            checkpoint()
        result = control(dict(action='mode', mode=value), 'mode')
        if value == 'enforce':
            revisions['enforce'] = revisions['mode']
        return result

    def traffic(service, expected):
        current()
        count = 5 if expected == 'ALLOW' else 1
        row = lab.child(command['id'], dict(action='traffic', source=host, destination=service['host'],
                        port=service['port'], count=count, interval=.1))
        result = row['result']
        sender, receiver = result.get('sender', {}), result.get('receiver_request')
        if sender.get('request_id') != row['id'] or not all(type(sender.get(k)) is int and sender[k] >= 0 for k in ('sent', 'received')):
            raise RuntimeError('Correlated sender/receiver counters are missing or invalid')
        sequences = receiver.get('sequences', []) if receiver else []
        summary = f"{host} → {service['host']}:{service['port']} · sent {sender['sent']}, echoed {sender['received']}, matching receiver messages {len(sequences)} · request {row['id']}"
        if expected == 'ALLOW':
            if (sender['sent'] != count or sender['received'] != count or sender.get('error') or
                    sorted(sequences) != list(range(count)) or receiver.get('peer') != source['ip'] or
                    receiver.get('source_port') != sender.get('source_port')):
                raise RuntimeError(summary + '. Request-specific delivery evidence did not match.')
            return summary + '. Application delivery observed.'
        if sender['received'] or sequences:
            raise RuntimeError(summary + '. Unexpected delivery when denial was expected.')
        destination = next(h['ip'] for h in initial['hosts'] if h['name'] == service['host'])
        def verdict(c):
            if expected != 'DENY' and any(h['name'] == host and h['block_confirmed'] for h in c['hosts']):
                return 'BLOCK confirmed by fresh switch readback'
            if expected == 'BLOCK':
                return None
            return next((f"DENY confirmed · operation {op['id']}" for op in c['operations']
                if op['action'] == 'DENY' and op['status'] == 'confirmed'
                and op['timestamp'] >= row['timestamp'] and op.get('flow', {}).get('source_ip') == source['ip']
                and op['flow'].get('destination_ip') == destination and op['flow'].get('source_port') == sender.get('source_port')
                and op['flow'].get('destination_port') == service['port']), None)
        return summary + '. ' + wait(verdict, 'correlated DENY/BLOCK confirmation')

    try:
        checkpoint()
        step('Permitted service', lambda: traffic(permitted, 'ALLOW'))
        checkpoint()
        if kind == 'traffic':
            step('Prohibited service', lambda: traffic(prohibited[0], 'DENY'))
        elif kind == 'block':
            step('Install host block', lambda: control(dict(action='block', host=host), 'host'))
            checkpoint()
            step('Previously permitted service under BLOCK', lambda: traffic(permitted, 'BLOCK'))
        else:
            step('Start a fresh observation window', lambda: (mode('off'), mode('observe'))[-1])
            for service in prohibited[:threshold]:
                checkpoint()
                step(f"Observe service {service['port']}", lambda s=service: traffic(s, 'DENY'))
            checkpoint()
            def observed():
                wait(lambda c: c['escalation']['mode'] == 'observe' and
                     c['escalation']['hosts'][host]['threshold_reached'] and
                     next(h for h in c['hosts'] if h['name'] == host)['block_confirmed'] is False, 'Observe threshold')
                return traffic(permitted, 'ALLOW')
            step('Threshold observed without a host block', observed)
            checkpoint()
            step('Enter Enforce with fresh evidence', lambda: mode('enforce'))
            for service in prohibited[:threshold]:
                checkpoint()
                step(f"Enforce service {service['port']}", lambda s=service: traffic(s, 'DENY_OR_BLOCK'))
            checkpoint()
            def automatic():
                op = wait(lambda c: next((o for o in c['operations'] if o['action'] == 'BLOCK'
                    and o.get('host') == host and o.get('origin') == 'automatic' and o['status'] == 'confirmed'
                    and o.get('mode_revision') == revisions['enforce']), None), 'automatic block from this demonstration')
                revisions['host'] = op['id']
                return traffic(permitted, 'BLOCK')
            step('Automatic block takes precedence', automatic)
    except Exception as error:
        failed = str(error)
    finally:
        restoring = True
        errors = []
        # A submitted operation may have finished after a lost receipt. Discover
        # ownership by writer revision, never by a host's boolean block state.
        try:
            c = current()
            rev = c.get('control_revisions', {}).get(host)
            op = next((o for o in c['operations'] if o['id'] == rev), None)
            with lab.lock:
                own_ids = {r['id'] for _, r in lab.ledger.values() if r.get('parent_id') == command['id']}
            mode_revision = c.get('control_revisions', {}).get('@mode')
            if mode_revision in own_ids:
                revisions['mode'] = mode_revision
                if c['escalation']['mode'] == 'enforce':
                    revisions['enforce'] = mode_revision
            if rev in own_ids or (op and op.get('origin') == 'automatic' and revisions['enforce']
                                  and op.get('mode_revision') == revisions['enforce']):
                revisions['host'] = rev
        except Exception as error:
            if kind != 'traffic':
                errors.append(str(error))
        # Shutdown does not delay for restoration. It retains intent and reports
        # interruption; cancellation alone restores only still-owned state.
        with lab.lock:
            running = lab.state['status'] == 'running'
            if running:
                lab.cancel.clear()  # Allow bounded restoration, never clear a shutdown signal.
        if not running:
            errors.append('Lab shutdown interrupted restoration; retained intent requires inspection')
        else:
            override_targets = demo.get('override_targets', [])
            try:
                if revisions['host']:
                    if host in override_targets:
                        raise RuntimeError('Later manual host choice queued; demo host restoration skipped')
                    step('Release back to normal policy', lambda: control(dict(action='release', host=host,
                         if_revision=revisions['host'])))
                    step('Verify delivery after release', lambda: traffic(permitted, 'ALLOW'))
            except Exception as error:
                errors.append(str(error))
            try:
                if revisions['mode']:
                    if '@mode' in override_targets:
                        raise RuntimeError('Later manual mode choice queued; demo mode restoration skipped')
                    step('Restore starting mode: ' + escalation['mode'], lambda: control(dict(action='mode',
                        mode=escalation['mode'], if_revision=revisions['mode'])))
            except Exception as error:
                errors.append(str(error))
        if errors:
            failed = (failed + ' ' if failed else '') + 'Restoration requires attention: ' + '; '.join(errors)
        status = 'failed' if failed and not demo['stop_requested'] else 'cancelled' if demo['stop_requested'] else 'completed'
        if errors:
            status = 'failed'
        with lab.lock:
            demo.update(status=status, finished_at=time.time(), restoration_errors=errors,
                reason=('Demonstration stopped: ' if demo['stop_requested'] else 'Demonstration incomplete: ') + failed
                    if failed else 'Demonstration complete. Backend evidence is retained; this is not an acceptance suite.')
        lab.publish()
    with lab.lock:
        return copy.deepcopy(demo)
