"""Loopback dashboard; bounded commands go through the controller's local admin socket."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import sqlite3
import threading
import time
from urllib.parse import parse_qs, urlsplit

from .storage import recent_events
from .admin import request, validate_command
from .workspace import ROOT, Conflict, Workspace

WEB = Path(__file__).parent / 'web'
ASSETS = {
    '/': ('index.html', 'text/html; charset=utf-8'),
    '/style.css': ('style.css', 'text/css; charset=utf-8'),
    '/app.js': ('app.js', 'text/javascript; charset=utf-8'),
    '/view.js': ('view.js', 'text/javascript; charset=utf-8'),
    '/state.js': ('state.js', 'text/javascript; charset=utf-8'),
    '/favicon.svg': ('favicon.svg', 'image/svg+xml'),
    '/ocean.svg': ('ocean.svg', 'image/svg+xml'),
}
for name in ('observatory.html', 'ob-style.css', 'ob-app.js', 'ob-view.js', 'ob-scene.js',
             'ob-model.js', 'ob-tools.js', 'ob-guide.js', 'ob-demo.js', 'ob-art.svg'):
    suffix = Path(name).suffix
    ASSETS['/' + name] = (name, {'.html': 'text/html', '.css': 'text/css',
                               '.js': 'text/javascript', '.svg': 'image/svg+xml'}[suffix] + '; charset=utf-8')
ASSETS['/observatory'] = ASSETS['/observatory.html']
ASSETS['/classic'] = ASSETS['/']


def snapshot(path):
    with Path(path).open('rb') as stream:
        content = stream.read(2_000_001)
    if len(content) > 2_000_000:
        raise ValueError('Snapshot exceeds size budget')
    return json.loads(content)


def presentation(runtime):
    result = dict(served_at=time.time(), controller=None, logger_server=None, events=[], errors=[])
    for field, filename in [('controller', 'controller.json'), ('logger_server', 'logger.json')]:
        try:
            result[field] = snapshot(Path(runtime) / filename)
        except (OSError, ValueError):
            result['errors'].append(f'{field} data unavailable')
    # Queue-level failures can precede a controller operation. Both dashboards
    # must show that actual outcome rather than wait forever for writer evidence.
    try:
        lab = snapshot(Path(runtime) / 'workspace.json')
        current = 0 <= time.time() - lab.get('collected_at', 0) < 5
        result['lab_controls'] = dict(available=current and lab.get('status') == 'running',
                                      status=lab.get('status'), collected_at=lab.get('collected_at'))
        result['command_operations'] = [dict(
            {key: row[key] for key in ('id', 'host', 'mode', 'reason', 'timestamp', 'origin') if key in row},
            action=row['action'].upper(), status='unknown' if not current and row['status'] in ('requested', 'pending') else row['status'])
            for row in lab.get('operations', [])[-32:] if row['action'] in ('block', 'release', 'mode')]
    except (OSError, ValueError, KeyError, TypeError):
        result['command_operations'] = []
    try:
        if result['controller']:
            result['events'] = recent_events(Path(runtime) / 'events.sqlite3', result['controller']['run_id'])
    except (OSError, ValueError, sqlite3.Error, KeyError):
        result['errors'].append('Persisted audit events unavailable')
    return result


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 8

    def __init__(self, address, runtime, follow_lab=False, root=ROOT):
        if address[0] != '127.0.0.1':
            raise ValueError('The dashboard must bind to IPv4 loopback')
        self._runtime = Path(runtime)
        self.workspace = Workspace(root)
        self.follow_lab = follow_lab
        self.capacity = threading.BoundedSemaphore(8)
        super().__init__(address, DashboardHandler)

    @property
    def runtime(self):
        return self.workspace.latest(self._runtime) if self.follow_lab else self._runtime

    def process_request(self, request, address):
        if not self.capacity.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.capacity.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.capacity.release()


class DashboardHandler(BaseHTTPRequestHandler):
    def setup(self):
        super().setup()
        self.connection.settimeout(2)

    def log_message(self, *_args):
        pass

    def local_host(self):
        hosts = self.headers.get_all('Host', [])
        if len(hosts) != 1:
            return None
        # Local forwarding can preserve a browser port different from our listener.
        # Keep literal loopback hosts; POST still requires this exact Host as Origin.
        match = re.fullmatch(r'(?:127\.0\.0\.1|localhost)(?::([1-9][0-9]{0,4}))?', hosts[0])
        return hosts[0] if match and (not match[1] or int(match[1]) <= 65535) else None

    def json_reply(self, code, **body):
        self.reply(code, json.dumps(body, allow_nan=False).encode(), 'application/json')

    def do_POST(self):
        host = self.local_host()
        if (not host or self.headers.get_all('Origin', []) != [f'http://{host}']
                or self.headers.get('Sec-Fetch-Site', 'same-origin') != 'same-origin'):
            self.json_reply(403, error='Commands require the same local dashboard origin')
            return
        if self.path not in ('/commands', '/workspace/config', '/workspace/plan', '/workspace/cancel', '/workspace/lab'):
            self.json_reply(404, error='Unknown command endpoint')
            return
        if self.headers.get_content_type() != 'application/json':
            self.json_reply(415, error='Commands require application/json')
            return
        lengths = self.headers.get_all('Content-Length', [])
        if (self.headers.get('Transfer-Encoding') or len(lengths) != 1
                or not lengths[0].isascii() or not lengths[0].isdigit()):
            self.json_reply(400, error='A bounded Content-Length is required')
            return
        maximum = 32768 if self.path == '/workspace/config' else 1024
        length = int(lengths[0]) if len(lengths[0]) <= 5 else maximum + 1
        if not 1 <= length <= maximum:
            self.json_reply(413, error=f'Command must be between 1 and {maximum} bytes')
            return
        if self.path.startswith('/workspace/'):
            try:
                command = json.loads(self.rfile.read(length))
                workspace = self.server.workspace
                if self.path == '/workspace/config':
                    result = workspace.save_configuration(command)
                elif self.path == '/workspace/plan':
                    result = workspace.plan(command)
                elif self.path == '/workspace/cancel':
                    result = workspace.cancel_plan(command)
                else:
                    from .lab_control import request_lab
                    if isinstance(command, dict):
                        if 'origin' in command:
                            raise ValueError('Interface origin is assigned by the server')
                        command['origin'] = 'dashboard'
                    result = request_lab(self.server.runtime, command)
                code = 200
                if self.path == '/workspace/lab':
                    code = 202 if result.get('status') == 'requested' else 503
                self.json_reply(code, **result)
            except Conflict as error:
                self.json_reply(409, error=str(error))
            except (ValueError, TypeError, KeyError, AttributeError, RecursionError) as error:
                self.json_reply(400, error=f'Invalid request: {error}')
            except OSError as error:
                self.json_reply(503, error=f'Local workspace unavailable: {error}')
            return
        try:
            command = json.loads(self.rfile.read(length))
            if not isinstance(command, dict):
                raise ValueError('Expected a command object')
            if isinstance(command, dict) and 'override' in command and type(command['override']) is not bool:
                raise ValueError('Override must be explicit true/false')
            validate_command({k: v for k, v in command.items() if k != 'override'})
            if not {'id', 'run_id'} <= command.keys():
                raise ValueError('Request ID and controller run ID are required')
        except (ValueError, TypeError, OSError) as error:
            self.json_reply(400, error=f'Invalid command: {error}')
            return
        try:
            controller = snapshot(self.server.runtime / 'controller.json')
            now = time.time()
            if (not controller['ready'] or not controller['switch_connected']
                    or not 0 <= now - controller['collected_at'] < 6
                    or not 0 <= now - (controller['statistics_at'] or 0) < 7):
                raise ValueError('Controller or switch state unavailable; wait for fresh observations')
        except (OSError, ValueError, TypeError, KeyError) as error:
            self.json_reply(503, error=f'Controls unavailable: {error}')
            return
        if command['run_id'] != controller['run_id']:
            self.json_reply(409, error='Controller restarted; refresh before submitting')
            return
        if command['action'] == 'mode':
            if command['mode'] != 'off' and not controller.get('escalation', {}).get('hosts'):
                self.json_reply(400, error='No eligible hosts configured; select eligible_hosts in the loaded configuration before enabling Observe or Enforce')
                return
        elif command['host'] not in {host['name'] for host in controller['hosts']}:
            self.json_reply(400, error='Unknown configured host')
            return
        try:
            from .lab_control import coordinated_control
            result = coordinated_control(self.server.runtime, command, 'dashboard')
            if result is None:
                if 'override' in command:
                    raise ValueError('Manual demo override requires a workspace')
                result = request(self.server.runtime, **command)
        except Conflict as error:
            self.json_reply(409, error=str(error), id=command['id'], status='failed')
            return
        except (OSError, ValueError) as error:
            self.json_reply(503, error=f'Controller acknowledgement unavailable: {error}. Check action history before retrying.',
                            id=command['id'], status='unknown')
            return
        # A socket acknowledgement is receipt only, never switch enforcement.
        self.json_reply(202 if result.get('status') == 'requested' else 503, **result)

    def do_GET(self):
        if not self.local_host() or self.headers.get('Sec-Fetch-Site') == 'cross-site':
            self.send_error(403, 'Local presentation only')
            return
        if self.path == '/state.json':
            runtime = self.server.runtime
            content = json.dumps(dict(presentation(runtime), runtime=runtime.name), allow_nan=False).encode()
            content_type = 'application/json'
        elif self.path == '/workspace.json':
            try:
                runtime = self.server.runtime
                state = presentation(runtime)
                content = json.dumps(self.server.workspace.status(runtime, state['controller']), allow_nan=False).encode()
            except (OSError, ValueError, TypeError, KeyError, RecursionError) as error:
                self.json_reply(503, error=f'Workspace records unavailable: {error}')
                return
            content_type = 'application/json'
        elif self.path.startswith('/workspace/report?'):
            try:
                query = parse_qs(urlsplit(self.path).query, strict_parsing=True, max_num_fields=3)
                if set(query) - {'run', 'file', 'download'} or any(len(v) != 1 for v in query.values()):
                    raise ValueError('Invalid report selection')
                name = query['file'][0]
                content = self.server.workspace.report(query['run'][0], name)
                self.reply(200, content, 'application/octet-stream' if 'download' in query else 'text/plain; charset=utf-8',
                           attachment=name if 'download' in query else None)
            except (ValueError, OSError, KeyError, sqlite3.Error) as error:
                self.json_reply(404, error=str(error))
            return
        elif self.path in ASSETS:
            filename, content_type = ASSETS[self.path]
            content = (WEB / filename).read_bytes()
        else:
            self.send_error(404)
            return
        self.reply(200, content, content_type)

    def reply(self, status, content, content_type, attachment=None):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(content)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        if attachment:
            self.send_header('Content-Disposition', f'attachment; filename="{attachment}"')
        self.send_header('Content-Security-Policy', "default-src 'self'; connect-src 'self'; style-src 'self'; script-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(content)


def run_dashboard(runtime, port=8080, follow_lab=False):
    with DashboardServer(('127.0.0.1', port), runtime, follow_lab=follow_lab) as server:
        print(f'All Blue dashboard: http://127.0.0.1:{server.server_address[1]}', flush=True)
        server.serve_forever()
