"""Loopback dashboard; bounded commands go through the controller's local admin socket."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
import threading
import time

from .storage import recent_events
from .admin import request, validate_command

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
    try:
        if result['controller']:
            result['events'] = recent_events(Path(runtime) / 'events.sqlite3', result['controller']['run_id'])
    except (OSError, ValueError, sqlite3.Error, KeyError):
        result['errors'].append('Persisted audit events unavailable')
    return result


class DashboardServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 8

    def __init__(self, address, runtime):
        if address[0] != '127.0.0.1':
            raise ValueError('The dashboard must bind to IPv4 loopback')
        self.runtime = Path(runtime)
        self.capacity = threading.BoundedSemaphore(8)
        super().__init__(address, DashboardHandler)

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
        port = self.server.server_address[1]
        allowed = {f'127.0.0.1:{port}', f'localhost:{port}'}
        if port == 80:
            allowed.update(('127.0.0.1', 'localhost'))
        hosts = self.headers.get_all('Host', [])
        return hosts[0] if len(hosts) == 1 and hosts[0] in allowed else None

    def json_reply(self, code, **body):
        self.reply(code, json.dumps(body, allow_nan=False).encode(), 'application/json')

    def do_POST(self):
        host = self.local_host()
        if (not host or self.headers.get_all('Origin', []) != [f'http://{host}']
                or self.headers.get('Sec-Fetch-Site', 'same-origin') != 'same-origin'):
            self.json_reply(403, error='Commands require the same local dashboard origin')
            return
        if self.path != '/commands':
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
        length = int(lengths[0]) if len(lengths[0]) <= 4 else 1025
        if not 1 <= length <= 1024:
            self.json_reply(413, error='Command must be between 1 and 1024 bytes')
            return
        try:
            command = json.loads(self.rfile.read(length))
            validate_command(command)
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
            result = request(self.server.runtime, **command)
        except (OSError, ValueError) as error:
            self.json_reply(503, error=f'Controller acknowledgement unavailable: {error}. Check action history before retrying.',
                            id=command['id'], status='unknown')
            return
        # A socket acknowledgement is receipt only, never switch enforcement.
        self.json_reply(202 if result.get('status') == 'requested' else 503, **result)

    def do_GET(self):
        if not self.local_host():
            self.send_error(403, 'Local presentation only')
            return
        if self.path == '/state.json':
            content = json.dumps(presentation(self.server.runtime), allow_nan=False).encode()
            content_type = 'application/json'
        elif self.path in ASSETS:
            filename, content_type = ASSETS[self.path]
            content = (WEB / filename).read_bytes()
        else:
            self.send_error(404)
            return
        self.reply(200, content, content_type)

    def reply(self, status, content, content_type):
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(content)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Content-Security-Policy', "default-src 'self'; connect-src 'self'; style-src 'self'; script-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(content)


def run_dashboard(runtime, port=8080):
    with DashboardServer(('127.0.0.1', port), runtime) as server:
        print(f'All Blue dashboard: http://127.0.0.1:{server.server_address[1]}', flush=True)
        server.serve_forever()
