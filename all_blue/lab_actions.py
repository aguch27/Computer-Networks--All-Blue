"""One lab executor with bounded, run-scoped receipts and out-of-band cancellation.

Socket/console threads only admit work or set cancellation flags. Mininet and
owned-process callbacks always run on the runner's main thread.
"""
from collections import deque
import copy
import json
import os
from pathlib import Path
import queue
import threading
import time
import uuid

from .admin import AdminServer, request
from .storage import atomic_json
from .workspace import read_json

FINAL = {'completed', 'confirmed', 'failed', 'superseded', 'cancelled', 'unknown'}
MAX_REQUESTS = 1024


class Cancelled(RuntimeError):
    result = None


def equivalent(command):
    action = command['action']
    if action == 'traffic':
        return f"{command['source']} traffic {command['destination']} {command['port']} {command['count']} {command['interval']}"
    if action in ('block', 'release'):
        return ('--override ' if command.get('override') else '') + f"{action} {command['host']}"
    if action == 'mode':
        return ('--override ' if command.get('override') else '') + 'mode ' + command['mode']
    if action == 'service':
        return f"service {command['component']} {command['operation']}"
    if action == 'demo':
        return f"demo {command['kind']} {command['host']}"
    if action == 'inspect':
        return command['command']
    return action


class LabWorkspace:
    def __init__(self, runtime, uid, gid, policy, services, execute, health):
        from .lab_control import validate_lab
        self.runtime, self.policy, self.execute, self.health = Path(runtime), policy, execute, health
        self.uid, self.gid = uid, gid
        self.commands = queue.Queue(maxsize=2)
        self.operations = deque(maxlen=32)
        self.ledger = {}  # Never evicted within a run: capacity exhaustion rejects new IDs.
        self.lock = threading.RLock()
        self.publish_lock = threading.Lock()
        self.done, self.closed, self.cancel = threading.Event(), threading.Event(), threading.Event()
        self.active = None
        self.ownership = None
        self.last_ownership = None
        self.state = dict(run_id=str(uuid.uuid4()), status='running', busy=False, services=services,
            started_at=time.time(), error=None, profile='coordinated lab workspace', demo=None,
            console='detached', inspection={}, deduplication=dict(capacity=MAX_REQUESTS,
                expiry='Entire lab run; no ID eviction. Restart uses a new run ID and rejects old requests.'))
        self.admin = AdminServer(self.runtime / 'lab.sock', self.commands, validate_lab, handler=self.submit)
        os.chown(self.admin.path, uid, gid)
        self.publisher = threading.Thread(target=self._heartbeat, daemon=True, name='lab-progress')

    def publish(self):
        with self.publish_lock:
            with self.lock:
                state = copy.deepcopy(dict(self.state, operations=list(self.operations),
                    collected_at=time.time(), components=self.health(), runtime=str(self.runtime)))
            if self.ownership:
                try:
                    owned = dict(self.ownership(), runtime=str(self.runtime.resolve()))
                    atomic_json(self.runtime / 'ownership.json', owned)
                    os.chmod(self.runtime / 'ownership.json', 0o600)
                    self.last_ownership = owned
                except (OSError, ValueError) as error:
                    state['recovery_error'] = f'Ownership record unavailable: {error}; automatic orphan recovery will refuse'
            try:
                atomic_json(self.runtime / 'workspace.json', state)
                os.chown(self.runtime / 'workspace.json', self.uid, self.gid)
            except OSError as error:
                with self.lock:
                    self.state['error'] = f'Lab progress persistence failed: {error}'

    def _heartbeat(self):
        while not self.closed.wait(.5):
            self.publish()

    def _record(self, command):
        row = dict(command, origin=command.get('origin', 'dashboard'), runtime=str(self.runtime),
                   timestamp=time.time(), status='requested', equivalent=equivalent(command),
                   reason='Received by the lab owner; execution and confirmation are pending')
        self.ledger[command['id']] = (json.dumps(command, sort_keys=True, allow_nan=False), row)
        self.operations.append(row)
        return row

    def submit(self, command):
        from .lab_control import validate_lab
        validate_lab(command)
        command = copy.deepcopy(command)
        with self.lock:
            old = self.ledger.get(command['id'])
            if old:
                if old[0] != json.dumps(command, sort_keys=True, allow_nan=False):
                    return dict(id=command['id'], status='failed', error='Request ID already belongs to different arguments or origin', conflict=True)
                if old[1].get('admission_error'):
                    return dict(id=command['id'], status='failed', error=old[1]['admission_error'], conflict=True)
                if not any(r['id'] == command['id'] for r in self.operations):
                    self.operations.append(old[1])  # Expose the retained outcome without executing again.
                # Receipt stays distinct from the retained execution result.
                return dict(id=command['id'], status='requested')
            if command['run_id'] != self.state['run_id']:
                return dict(id=command['id'], status='superseded', error='Lab run changed; old requests cannot be replayed', conflict=True)
            reserve = 0 if command['action'] == 'shutdown' else 1 if command['action'] == 'cancel' else 8
            if len(self.ledger) >= MAX_REQUESTS - reserve:
                return dict(id=command['id'], status='failed', error='Run request ledger full; no IDs were forgotten. Shut down and start a new run.', conflict=True)
            row = self._record(command)
            action = command['action']
            def reject(reason):
                row.update(status='failed', reason=reason, admission_error=reason, finished_at=time.time())
                return dict(id=row['id'], status='failed', error=reason, conflict=True)
            if self.state['status'] != 'running':
                return reject('Lab is stopping or unavailable; no new work accepted')
            if action == 'inspect':
                row.update(status='completed', result=self.state['inspection'].get(command['command'], 'Inspection unavailable'),
                           reason='Read-only topology captured by the owner at startup', finished_at=time.time())
            elif action in ('cancel', 'shutdown'):
                self.cancel.set()
                if self.state.get('demo') and self.state['demo']['status'] == 'running':
                    self.state['demo']['stop_requested'] = True
                if action == 'shutdown':
                    self.state['status'] = 'stopping'
                    self._discard_queue('Lab shutdown requested')
                    row.update(status='pending', reason='Stopping; waiting for action cancellation and verified cleanup')
                    self.commands.put_nowait(command)
                else:
                    row.update(status='completed', reason='Cancellation signalled; wait for the target result. Traffic stops; service/writer steps settle before restoration.',
                               result={'target': self.active}, finished_at=time.time())
            else:
                demo = self.state.get('demo')
                overriding = command.get('override') and action in ('block', 'release', 'mode')
                if self.state['busy']:
                    if not (demo and demo['status'] == 'running' and overriding and self.commands.empty()):
                        return reject('Lab action or demonstration active. Stop it, or explicitly override with a host/mode choice.')
                    demo['overridden'] = True
                    demo.setdefault('override_targets', []).append('@mode' if action == 'mode' else command['host'])
                    demo['stop_requested'] = True
                    self.cancel.set()
                else:
                    self.cancel.clear()
                self.state['busy'] = True  # Reserve at admission, not after dequeue.
                self.commands.put_nowait(command)
            return dict(id=command['id'], status='requested')

    def _discard_queue(self, reason):
        while True:
            try:
                queued = self.commands.get_nowait()
            except queue.Empty:
                return
            self.ledger[queued['id']][1].update(status='cancelled', reason=reason, finished_at=time.time())

    def controller(self, identity=None):
        state = read_json(self.runtime / 'controller.json')
        if identity and (state['run_id'], state['switch_epoch']) != identity:
            raise RuntimeError('Controller run or switch epoch changed; restoration requires attention')
        now = time.time()
        if not (state.get('ready') and state.get('switch_connected') and
                0 <= now - state.get('collected_at', 0) < 6 and 0 <= now - (state.get('statistics_at') or 0) < 7):
            raise RuntimeError('Controller/switch observations unavailable or stale')
        return state

    def control(self, command):
        state = self.controller()
        if command.get('controller_run_id', state['run_id']) != state['run_id']:
            raise RuntimeError('Controller restarted; request superseded')
        keys = ('action', 'host', 'mode', 'id', 'if_revision')
        payload = {k: command[k] for k in keys if k in command}
        payload['run_id'] = state['run_id']
        # Receipt loss is uncertain; keep the ID and still look for writer evidence.
        try:
            receipt = request(self.runtime, **payload)
            if receipt.get('status') != 'requested':
                raise RuntimeError(receipt.get('error', 'Controller rejected request'))
        except OSError:
            pass
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            current = read_json(self.runtime / 'controller.json')
            if current['run_id'] != state['run_id']:
                return dict(status='superseded', reason='Controller restarted before confirmation')
            operation = next((o for o in current.get('operations', []) if o['id'] == command['id']), None)
            if operation and operation['status'] in FINAL:
                return operation
            time.sleep(.1)  # Never interrupt a submitted writer transaction halfway.
        return dict(status='unknown', reason='Writer result not observed within 15 seconds; inspect this request ID before retrying')

    def child(self, parent, details):
        command = dict(details, id=str(uuid.uuid4()), run_id=self.state['run_id'], origin='demo', parent_id=parent)
        with self.lock:
            if self.state['status'] != 'running':
                raise Cancelled('Lab shutdown interrupted restoration; no new demo actions accepted')
            if len(self.ledger) >= MAX_REQUESTS - 8:
                raise RuntimeError('Run request ledger full; restoration requires attention')
            row = self._record(command)
        self._execute(command, row)
        if row['status'] not in ('confirmed', 'completed'):
            raise RuntimeError(row['reason'])
        return row

    def _execute(self, command, row):
        def update(**values):
            with self.lock:
                row.update(values)
        update(status='pending', reason='Executing in the owned lab runner')
        self.publish()
        try:
            if command['action'] in ('block', 'release', 'mode'):
                result = self.control(command)
                update(status=result['status'], result=result, reason=result['reason'])
            elif command['action'] == 'demo':
                from .lab_demo import run_demo
                result = run_demo(self, command)
                update(status=result['status'], result=result, reason=result['reason'])
            elif command['action'] == 'shutdown':
                self.done.set()
                return  # Remains pending until cleanup evidence is written.
            else:
                if command['action'] == 'traffic':
                    if command['source'] not in self.policy.hosts or command['source'] == command['destination']:
                        raise ValueError('Select distinct configured hosts')
                    if not any(s['host'] == command['destination'] and s['port'] == command['port'] for s in self.state['services']):
                        raise ValueError('Destination service is not an owned listening application')
                result = self.execute(command)
                update(status='completed', result=result, reason='Action completed; inspect actual evidence')
        except Cancelled as error:
            update(status='cancelled', reason=str(error), result=error.result)
        except Exception as error:
            update(status='failed', reason=str(error))
            if command['action'] == 'demo':
                with self.lock:
                    self.state['demo'] = dict(id=command['id'], status='failed', steps=[],
                                             reason='Demonstration incomplete: ' + str(error), evidence_kind='interactive_demonstration')
        finally:
            if command['action'] != 'shutdown':
                update(finished_at=time.time())
            self.publish()

    def handle(self, command):
        if command['id'] not in self.ledger:
            receipt = self.submit(command)
            if receipt.get('status') != 'requested':
                return
            # Convenience for direct owner tests, never used by the socket thread.
            if not self.commands.empty():
                self.commands.get_nowait()
        row = self.ledger[command['id']][1]
        if row['status'] in FINAL:
            return
        self.active = command['id']
        self._execute(command, row)
        with self.lock:
            self.active = None
            self.state['busy'] = not self.commands.empty()
            if self.state['status'] == 'running':
                self.cancel.clear()
        self.publish()

    def serve(self):
        self.publish()
        self.publisher.start()
        try:
            while not self.done.is_set():
                try:
                    self.handle(self.commands.get(timeout=.2))
                except queue.Empty:
                    continue
        finally:
            with self.lock:
                self.state['status'] = 'stopping'
                self._discard_queue('Runner exiting; queued work cancelled')
            self.publish()
            self.admin.close()

    def close(self, cleanup):
        """Called only after the runner independently checks its owned resources."""
        self.closed.set()
        if self.publisher.is_alive():
            self.publisher.join(timeout=2)
        with self.lock:
            self.ownership = None
            errors = cleanup['errors']
            self.state.update(status='cleanup_failed' if errors else 'stopped', busy=False,
                              cleanup=cleanup, cleanup_errors=errors)
            for _, row in self.ledger.values():
                if row['status'] not in FINAL:
                    row.update(status=('failed' if errors else 'completed') if row['action'] == 'shutdown' else 'cancelled', result=cleanup,
                               reason='Cleanup failed' if errors else 'Owned resources verified absent; unfinished work cancelled', finished_at=time.time())
            demo = self.state.get('demo')
            if demo and demo['status'] == 'running':
                demo.update(status='interrupted', reason='Lab stopped; inspect retained block/mode intent before restarting')
            self.health = lambda: {'cleanup': cleanup, 'controller': {'running': False if not errors else None},
                                  'logger': {'running': False if not errors else None},
                                  'switch': {'running': cleanup['bridge_present']}}
        self.publish()
