"""A local, owner-only UNIX socket submits bounded requests to the writer."""
import json
import os
from pathlib import Path
import queue
import socket
import threading
import uuid


def validate_command(command):
    if not isinstance(command, dict):
        raise ValueError('Expected a command object')
    action = command.get('action')
    target = 'mode' if action == 'mode' else 'host'
    if (action not in ('block', 'release', 'mode') or not {'action', target} <= command.keys()
            or command.keys() - {'action', target, 'run_id', 'id'}):
        raise ValueError('Expected block/release with host, or mode with off/observe/enforce')
    if target == 'mode':
        if command['mode'] not in ('off', 'observe', 'enforce'):
            raise ValueError('Escalation mode must be off, observe or enforce')
    elif not isinstance(command['host'], str) or not 1 <= len(command['host']) <= 16:
        raise ValueError('Expected a configured host name')
    for key in ('run_id', 'id'):
        if key in command:
            if not isinstance(command[key], str) or str(uuid.UUID(command[key])) != command[key]:
                raise ValueError(f'Invalid {key}')


class AdminServer:
    def __init__(self, path, commands):
        self.path, self.commands = Path(path), commands
        self.stop = threading.Event()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        if self.path.exists():
            with socket.socket(socket.AF_UNIX) as probe:
                probe.settimeout(.2)
                try:
                    probe.connect(str(self.path))
                except (ConnectionRefusedError, FileNotFoundError):
                    self.path.unlink(missing_ok=True)
                else:
                    raise RuntimeError('An All Blue controller is already listening')
        self.socket = socket.socket(socket.AF_UNIX)
        self.socket.bind(str(self.path))
        os.chmod(self.path, 0o600)
        self.socket.listen(4)
        self.socket.settimeout(.5)
        self.thread = threading.Thread(target=self._serve, daemon=True, name='local-admin')
        self.thread.start()

    def _serve(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.socket.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            with connection:
                connection.settimeout(.5)
                try:
                    stream = connection.makefile('rb')
                    body = stream.readline(1025)
                    if len(body) > 1024 or not body.endswith(b'\n'):
                        raise ValueError('Invalid command frame')
                    request = json.loads(body)
                    validate_command(request)
                    request.setdefault('id', str(uuid.uuid4()))
                    self.commands.put_nowait(request)
                    reply = dict(id=request['id'], status='requested')
                except (ValueError, KeyError, TypeError, queue.Full, OSError):
                    reply = dict(status='failed', error='Invalid command or command queue full')
                try:
                    connection.sendall(json.dumps(reply).encode() + b'\n')
                except OSError:
                    pass

    def close(self):
        self.stop.set()
        self.socket.close()
        self.thread.join(timeout=1)
        self.path.unlink(missing_ok=True)


def request(runtime, action, host=None, **details):
    command = dict(action=action, **details)
    if host is not None:
        command['host'] = host
    validate_command(command)
    with socket.socket(socket.AF_UNIX) as connection:
        connection.settimeout(2)
        connection.connect(str(Path(runtime) / 'admin.sock'))
        connection.sendall(json.dumps(command).encode() + b'\n')
        return json.loads(connection.makefile('rb').readline(2048))
