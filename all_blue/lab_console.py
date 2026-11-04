"""A restricted Mininet console client of the same local action broker as HTTP.

Never executes a string as a shell command and never owns a network lifecycle.
"""
import json
import os
from pathlib import Path
import select
import shlex
import sys
import threading
import uuid

from .lab_control import request_lab
from .workspace import read_json

HELP = '''nodes | net | dump                 native read-only topology inspection
h1 traffic h2 9000 [count] [interval]  real socket traffic (also h3)
traffic h3 h2 9000 [count] [interval]  same action as the dashboard
block h1 | release h1                return to normal policy on release
mode off|observe|enforce              save and apply the live mode
service controller|logger|switch start|stop|restart
demo traffic|block|escalation h1      backend-owned demonstration
--override block h1                  stop demo and queue a deliberate manual choice
cancel | stop                        cancel traffic/demo; service/writer step settles
shutdown                             cancel work, then verify owned cleanup
status | history | help              local observations (continue during long work)
exit / EOF                           detach console only; lab stays running
Ctrl+C                               request cancellation, not shutdown
Shell, sh, py, source, dpctl, link and arbitrary host commands are disabled.
Use the supported traffic command; run other local tools in another terminal.
Never mutate this lab with external Mininet/OVS commands while it owns ab-s1.'''


def parse(line, state):
    if len(line) > 1024:
        raise ValueError('Console input exceeds 1024 characters')
    words = shlex.split(line)
    if not words:
        return None
    override = words[0] == '--override'
    if override:
        words = words[1:]
    if len(words) >= 2 and words[1] == 'traffic':
        words = ['traffic', words[0], *words[2:]]
    action, *args = words
    details = {'action': action}
    if action in ('nodes', 'net', 'dump') and not args:
        details = dict(action='inspect', command=action)
    elif action == 'traffic' and 3 <= len(args) <= 5:
        details.update(source=args[0], destination=args[1], port=int(args[2]),
                       count=int(args[3]) if len(args) > 3 else 5,
                       interval=float(args[4]) if len(args) > 4 else .1)
    elif action in ('block', 'release') and len(args) == 1:
        details['host'] = args[0]
    elif action == 'mode' and len(args) == 1:
        details['mode'] = args[0]
    elif action == 'service' and len(args) == 2:
        details.update(component=args[0], operation=args[1])
    elif action == 'demo' and len(args) == 2:
        details.update(kind=args[0], host=args[1])
    elif action in ('cancel', 'stop', 'shutdown') and not args:
        details['action'] = 'cancel' if action == 'stop' else action
    else:
        raise ValueError('Unsupported command. Type help for coordinated commands; arbitrary shell execution is disabled.')
    if override:
        if action not in ('block', 'release', 'mode'):
            raise ValueError('--override applies only to manual host/mode choices')
        details['override'] = True
    return dict(details, id=str(uuid.uuid4()), run_id=state['run_id'], origin='terminal')


def run_console(runtime, stopped=None, stdin=None, stdout=None, owner=None):
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
    stopped = stopped or threading.Event()
    runtime = Path(runtime)
    seen = {}
    buffer = bytearray()
    discarding = False
    def output(value):
        print(value, file=stdout, flush=True)
    def read():
        return read_json(runtime / 'workspace.json', 512000)
    def cancel():
        try:
            state = read()
            output(request_lab(runtime, parse('cancel', state)))
        except (OSError, ValueError) as error:
            output(str(error))
    output('All Blue combined Mininet console. Type help. Commands are coordinated; no automatic terminal typing.')
    output('Runtime: ' + str(runtime))
    output('mininet> ')
    if owner:
        owner.state['console'] = 'attached'
    try:
        while not stopped.is_set():
            try:
                state = read()
                for row in state.get('operations', []):
                    version = row['status']
                    if seen.get(row['id']) == version:
                        continue
                    seen[row['id']] = version
                    output(f"[{row.get('origin', 'unknown')}] {row['id']} · {row.get('equivalent', row['action'])} · {version} · {row.get('reason', '')}")
                    if row.get('result') is not None:
                        output(json.dumps(row['result'], ensure_ascii=True)[:12000])
                # Bound terminal tracking to the snapshot, without replaying unchanged rows.
                seen = {r['id']: seen[r['id']] for r in state.get('operations', [])}
                if state['status'] in ('stopped', 'cleanup_failed'):
                    output('Lab ' + state['status'] + ': ' + json.dumps(state.get('cleanup', {})))
                    return
                if not select.select([stdin], [], [], .2)[0]:
                    continue
                chunk = os.read(stdin.fileno(), 4096)
                if not chunk:
                    output('Console detached at EOF. Lab remains available in the dashboard; shutdown is separate.')
                    return
                for byte in chunk:
                    if byte != 10:
                        if not discarding:
                            buffer.append(byte)
                            if len(buffer) > 1024:
                                buffer.clear(); discarding = True
                        continue
                    if discarding:
                        discarding = False
                        output('Rejected an overlong command; the entire line was discarded.')
                        continue
                    line = buffer.decode(errors='replace').strip(); buffer.clear()
                    if line in ('exit', 'quit'):
                        output('Console detached. Lab remains running; use dashboard shutdown or reattach scripts/console.py.')
                        return
                    if line == 'help':
                        output(HELP)
                    elif line in ('status', 'history'):
                        output(json.dumps(state if line == 'status' else state.get('operations', []), indent=2, ensure_ascii=True))
                    elif line:
                        try:
                            command = parse(line, state)
                            output(json.dumps(request_lab(runtime, command)))
                        except (ValueError, OSError, KeyError) as error:
                            output('Rejected: ' + str(error))
                    output('mininet> ')
            except KeyboardInterrupt:
                cancel()
                output('mininet> ')
            except (ValueError, OSError, KeyError) as error:
                output('Unavailable: ' + str(error))
                # Polling errors should not become a busy loop or claim cleanup.
                if stopped.wait(.5):
                    return
    finally:
        if owner:
            owner.state['console'] = 'detached'


def start_console(runtime, owner):
    thread = threading.Thread(target=run_console, args=(runtime, owner.closed),
                              kwargs={'owner': owner}, daemon=True, name='mininet-console-input')
    thread.start()
    return thread
