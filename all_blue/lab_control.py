"""Allowlisted lab actions owned by the existing Mininet runner, never HTTP.

The socket only queues requests. The runner's main thread executes them; its
heartbeat publishes bounded progress independently of a slow traffic exchange.
"""
import json
import math
import os
from pathlib import Path
import socket
import subprocess
import time
import uuid

from .storage import atomic_json
from .workspace import Conflict, read_json


def owned_bridge_present():
    """Read only the lab bridge, from the runner's lifecycle callback."""
    result = subprocess.run(['ovs-vsctl', '--timeout=3', 'br-exists', 'ab-s1'],
                            capture_output=True, text=True, timeout=4)
    if result.returncode not in (0, 2):
        raise OSError('Cannot observe ab-s1 lifecycle: ' + result.stderr.strip()[:512])
    return result.returncode == 0


def validate_lab(command):
    if not isinstance(command, dict):
        raise ValueError('Expected a lab command object')
    for key in ('id', 'run_id'):
        if not isinstance(command.get(key), str) or str(uuid.UUID(command[key])) != command[key]:
            raise ValueError('Lab request and run IDs must be UUIDs')
    action = command.get('action')
    fields = {'id', 'run_id', 'action'}
    if action == 'traffic':
        fields |= {'source', 'destination', 'port', 'count', 'interval'}
        if not all(isinstance(command.get(k), str) for k in ('source', 'destination')):
            raise ValueError('Select configured host names')
        if type(command.get('port')) is not int or not 1 <= command['port'] <= 65535:
            raise ValueError('Invalid TCP port')
        if type(command.get('count')) is not int or not 1 <= command['count'] <= 100:
            raise ValueError('Traffic count must be 1–100 application messages')
        interval = command.get('interval')
        if type(interval) not in (int, float) or not math.isfinite(interval) or not 0 <= interval <= 1 or interval * command['count'] > 20:
            raise ValueError('Interval must be 0–1 seconds; total scheduled traffic is limited to 20 seconds')
    elif action == 'service':
        fields |= {'component', 'operation'}
        if command.get('component') not in ('controller', 'logger', 'switch') or command.get('operation') not in ('start', 'stop', 'restart'):
            raise ValueError('Only owned controller/logger/switch lifecycle actions are supported')
    elif action in ('block', 'release', 'mode'):
        target = 'mode' if action == 'mode' else 'host'
        fields |= {target}
        if target == 'mode' and command.get(target) not in ('off', 'observe', 'enforce'):
            raise ValueError('Unknown escalation mode')
        if target == 'host' and (not isinstance(command.get(target), str) or not 1 <= len(command[target]) <= 16):
            raise ValueError('Select a configured host')
        for key in ('controller_run_id', 'if_revision'):
            if key in command:
                if not isinstance(command[key], str) or str(uuid.UUID(command[key])) != command[key]:
                    raise ValueError('Invalid controller identity/revision')
                fields.add(key)
        if 'override' in command:
            if type(command['override']) is not bool:
                raise ValueError('Override must be explicit true/false')
            fields.add('override')
    elif action == 'demo':
        fields |= {'kind', 'host'}
        if command.get('kind') not in ('traffic', 'block', 'escalation') or not isinstance(command.get('host'), str) or not 1 <= len(command['host']) <= 16:
            raise ValueError('Choose a supported demonstration and configured host')
    elif action == 'inspect':
        fields.add('command')
        if command.get('command') not in ('nodes', 'net', 'dump'):
            raise ValueError('Only nodes, net and dump are supported inspections')
    elif action not in ('shutdown', 'cancel'):
        raise ValueError('Unknown lab action')
    if 'origin' in command:
        fields.add('origin')
        if command['origin'] not in ('terminal', 'dashboard'):
            raise ValueError('Invalid interface origin')
    if set(command) != fields:
        raise ValueError('Unexpected or missing lab command fields')


def request_lab(runtime, command):
    validate_lab(command)
    state = read_json(Path(runtime) / 'workspace.json', 512000)
    if state.get('status') != 'running' or not 0 <= time.time() - state['collected_at'] < 5:
        raise Conflict('Workspace runner unavailable or stale; use the terminal launch workflow')
    if command['run_id'] != state['run_id']:
        raise Conflict('Lab run changed; refresh before submitting')
    try:
        with socket.socket(socket.AF_UNIX) as connection:
            connection.settimeout(2)
            connection.connect(str(Path(runtime) / 'lab.sock'))
            connection.sendall(json.dumps(command, allow_nan=False).encode() + b'\n')
            result = json.loads(connection.makefile('rb').readline(2048))
            if result.get('conflict'):
                raise Conflict(result['error'])
            return result
    except Conflict:
        raise
    except (OSError, ValueError):
        return dict(id=command['id'], status='unknown',
                    error='Lab acknowledgement unavailable. Inspect action history; retrying the same action retains its request ID.')


def coordinated_control(runtime, command, origin):
    """Route existing controls through an active workspace; never bypass a stale owner."""
    path = Path(runtime) / 'workspace.json'
    if not path.exists():
        return None
    lab = read_json(path, 512000)
    controller = read_json(Path(runtime) / 'controller.json')
    details = dict(command, id=command.get('id', str(uuid.uuid4())),
                   controller_run_id=command.get('run_id', controller['run_id']),
                   run_id=lab['run_id'], origin=origin)
    return request_lab(runtime, details)


from .lab_actions import LabWorkspace, Cancelled


def serve_lab(runtime, uid, gid, policy, net, switch, managed, launch, client, server, stop_process, wait_for, console=False, on_ready=None):
    """Use the existing runner's processes, traffic applications and cleanup lifecycle."""
    configured = {(destination, port) for _, destination, port in policy.allowed}
    if 'h2' in policy.hosts:
        configured.update(('h2', port) for port in range(9001, 9006))
    if len(configured) > 16:
        raise ValueError('The presentation lab supports at most 16 listening services')
    receivers = {}
    for host, port in sorted(configured):
        receivers[(host, port)] = server(host, port)
    switch_up = [True]
    switch_observed_at = [time.time()]

    def health():
        return {**{name: dict(running=process is not None and process.poll() is None,
                              pid=process.pid if process else None) for name, process in managed.items()},
                'switch': dict(running=switch_up[0], name='ab-s1', observed_at=switch_observed_at[0],
                               evidence='Last runner lifecycle observation; use current controller readback for connectivity')}

    def execute(command):
        action = command['action']
        if action == 'shutdown':
            return dict(request='Orderly shutdown of this runner and its own ab-s1; cleanup follows the runner exit')
        if action == 'traffic':
            if workspace.cancel.is_set():
                raise Cancelled('Traffic cancelled before starting a host process')
            destination, port = command['destination'], command['port']
            path = receivers[(destination, port)]
            before = read_json(path)
            try:
                result = client(command['source'], policy.hosts[destination].ip, port,
                                command['count'], command['interval'], request_id=command['id'], cancel=workspace.cancel)
            except Cancelled as error:
                after = read_json(path)
                error.result = dict(sender=None, sender_status='Interrupted: exact sender totals unavailable',
                                    receiver_request=after.get('requests', {}).get(command['id']))
                raise
            after = read_json(path)
            correlated = after.get('requests', {}).get(command['id'])
            before.pop('requests', None)
            after.pop('requests', None)
            before['recent'] = before.get('recent', [])[-4:]
            after['recent'] = after.get('recent', [])[-4:]
            return dict(sender=result, receiver_request=correlated, receiver_before=before, receiver_after=after,
                        receiver_message_delta=after['messages'] - before['messages'],
                        note='Receiver totals are independent observations during this request; other terminal traffic may also contribute. Sent/received are application messages, not switch packets.')
        if workspace.cancel.is_set():
            raise Cancelled('Action cancelled before service mutation')
        component, operation = command['component'], command['operation']
        before = health()
        began = time.time()
        prior = None
        prior_epoch = -1
        prior_logger = None
        try:
            previous = read_json(runtime / 'controller.json')
            prior, prior_epoch = previous['run_id'], previous['switch_epoch']
            prior_logger = read_json(runtime / 'logger.json')['server_id']
        except (OSError, ValueError, KeyError):
            pass
        if component == 'switch':
            if operation in ('stop', 'restart'):
                if not switch_up[0]:
                    raise ValueError('The owned switch is already stopped')
                switch.stop(deleteIntfs=False)
                wait_for(lambda: not owned_bridge_present(), 'owned ab-s1 bridge absent after stop', timeout=5)
                switch_up[0] = False
                switch_observed_at[0] = time.time()
            if operation in ('start', 'restart'):
                if switch_up[0]:
                    raise ValueError('The owned switch is already running')
                switch.start(net.controllers)
                wait_for(owned_bridge_present, 'owned ab-s1 bridge present after start', timeout=5)
                switch_up[0] = True
                switch_observed_at[0] = time.time()
        else:
            process = managed.get(component)
            running = process is not None and process.poll() is None
            if operation == 'start' and running:
                raise ValueError('This owned service is already running')
            if operation in ('stop', 'restart'):
                if not running and operation == 'stop':
                    raise ValueError('This owned service is already stopped')
                if running:
                    stop_process(process)
                managed[component] = None
            if operation in ('start', 'restart'):
                managed[component] = launch(component)
        evidence = dict(before=before, after=health(), interrupted=component if operation != 'start' else None)
        if operation != 'stop':
            if component in ('controller', 'switch'):
                def ready():
                    current = read_json(runtime / 'controller.json')
                    return current if (current['ready'] and current['switch_connected']
                        and time.time() - current['collected_at'] < 5 and current['statistics_at'] >= began
                        and (component != 'controller' or current['run_id'] != prior)
                        and (component != 'switch' or current['switch_epoch'] > prior_epoch)) else None
                verified = wait_for(ready, 'fresh verified reconciliation', timeout=25)
                evidence['reconciled_controller'] = {key: verified[key] for key in (
                    'run_id', 'switch_epoch', 'collected_at', 'ready', 'hosts')}
            else:
                def logger_ready():
                    current = read_json(runtime / 'logger.json')
                    return current if (time.time() - current['collected_at'] < 2
                                       and current['collected_at'] >= began and current['server_id'] != prior_logger) else None
                verified = wait_for(logger_ready, 'fresh logger state')
                evidence['logger'] = {key: verified.get(key) for key in (
                    'server_id', 'collected_at', 'received', 'last_received', 'error')}
        if workspace.cancel.is_set():
            evidence['cancellation'] = 'Service step settled before cancellation; no rollback claimed'
        return evidence

    services = [dict(host=host, port=port) for host, port in sorted(receivers)]
    workspace = LabWorkspace(runtime, uid, gid, policy, services, execute, health)
    from .lab_recovery import ownership, interface_index
    interfaces = {str(intf): interface_index(str(intf)) for node in net.values()
                  for intf in node.intfList() if str(intf) != 'lo' and interface_index(str(intf)) is not None}
    workspace.ownership = lambda: ownership(interfaces)
    # Only this owner reads Mininet's objects; console requests use cached inspection.
    workspace.state['inspection'] = {
        'nodes': ' '.join(sorted(node.name for node in net.values())),
        'net': '\n'.join(str(link) for link in net.links),
        'dump': '\n'.join(repr(node) for node in net.values()),
    }
    net.all_blue_workspace = workspace
    if console:
        from .lab_console import start_console
        start_console(runtime, workspace)
    if on_ready:
        workspace.publish()
        on_ready()  # Start the optional verifier only after listeners and owner state exist.
    print('Lab workspace ready. Dashboard and console share one owner; shutdown verifies cleanup.', flush=True)
    workspace.serve()
    return workspace
