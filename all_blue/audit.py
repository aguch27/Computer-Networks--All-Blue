"""Length-prefixed JSON over TCP, durable acknowledgement, bounded retry."""
import json
from collections import deque
import math
from pathlib import Path
import queue
import socket
import socketserver
import sqlite3
import struct
import threading
import time
import uuid

from .storage import atomic_json, connect_store, save_event
from .observability import QUIET, TerminalLog

MAX_MESSAGE = 16384


def read_exact(sock, count, deadline=None):
    result = bytearray()
    while len(result) < count:
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError('Frame assembly deadline exceeded')
            sock.settimeout(remaining)
        chunk = sock.recv(count - len(result))
        if not chunk:
            raise EOFError('TCP stream ended within a frame')
        result.extend(chunk)
    return bytes(result)


def receive(sock, trace=QUIET):
    original_timeout = sock.gettimeout()
    deadline = time.monotonic() + (original_timeout or 2)
    try:
        length, = struct.unpack('!I', read_exact(sock, 4, deadline))
        trace.emit('tcp_frame', stage='header_received', bytes=length)
        if not 0 < length <= MAX_MESSAGE:
            raise ValueError('Frame exceeds 16 KiB limit')
        body = read_exact(sock, length, deadline)
        trace.emit('tcp_frame', stage='body_received', bytes=length)
        value = json.loads(body)
        trace.emit('tcp_frame', stage='json_decoded', bytes=length,
                   event_id=value.get('id', value.get('ack')) if isinstance(value, dict) else None)
        return value
    finally:
        sock.settimeout(original_timeout)


def send(sock, message):
    body = json.dumps(message, allow_nan=False, separators=(',', ':')).encode()
    if not 0 < len(body) <= MAX_MESSAGE:
        raise ValueError('Frame exceeds 16 KiB limit')
    sock.sendall(struct.pack('!I', len(body)) + body)


def validate_event(event):
    if not isinstance(event, dict):
        raise ValueError('Expected an event object')
    for key in ('id', 'run_id'):
        uuid.UUID(event[key])
    if (type(event['timestamp']) not in (float, int)
            or not math.isfinite(event['timestamp']) or event['timestamp'] < 0):
        raise ValueError('Invalid timestamp')
    for key in ('action', 'status', 'reason'):
        if not isinstance(event[key], str) or len(event[key]) > 1024:
            raise ValueError('Invalid event text')
    return event


class AuditClient:
    def __init__(self, address, run_id, capacity=256, trace=QUIET):
        self.address, self.run_id = address, run_id
        self.trace = trace
        self.queue = queue.Queue(maxsize=capacity)
        self.stop = threading.Event()
        self.dropped = 0
        self.generated = 0
        self.delivered = 0
        self.last_ack = None
        self.last_ack_monotonic_ns = None
        self.error = 'Not connected yet'
        self.pending = False
        self.retries = 0
        self.acknowledgements = deque(maxlen=128)
        self.thread = threading.Thread(target=self._worker, daemon=True, name='audit-delivery')
        self.thread.start()

    def emit(self, action, status, reason, **extra):
        event = dict(id=str(uuid.uuid4()), run_id=self.run_id, timestamp=time.time(),
                     action=action, status=status, reason=reason, **extra)
        self.generated += 1
        try:
            if len(json.dumps(event).encode()) > MAX_MESSAGE:
                raise ValueError('Oversize event')
            self.queue.put_nowait(event)
            self.trace.emit('audit_event', delivery='queued', event_id=event['id'], run_id=self.run_id,
                            action=action, status=status, reason=reason,
                            operation_id=extra.get('operation_id'), backlog=self.queue.qsize())
        except (queue.Full, ValueError):
            self.dropped += 1
            self.trace.emit('audit_event', delivery='dropped', event_id=event['id'],
                            reason='Audit queue full or event oversized', dropped=self.dropped)
        return event

    def health(self):
        return dict(backlog=self.queue.qsize() + int(self.pending), dropped=self.dropped,
                    generated=self.generated, delivered=self.delivered, last_ack=self.last_ack,
                    last_ack_monotonic_ns=self.last_ack_monotonic_ns, error=self.error,
                    retries=self.retries, acknowledgements=list(self.acknowledgements))

    def close(self):
        self.stop.set()
        self.thread.join(timeout=3)
        self.trace.emit('audit_client', status='stopped', **self.health())

    def _worker(self):
        connection, event, attempt = None, None, 0
        while not self.stop.is_set():
            if event is None:
                try:
                    event = self.queue.get(timeout=.2)
                    self.pending = True
                except queue.Empty:
                    continue
            try:
                attempt += 1
                if connection is None:
                    self.trace.emit('audit_connection', status='connecting', address=self.address, attempt=attempt)
                    connection = socket.create_connection(self.address, timeout=1)
                    self.trace.emit('audit_connection', status='connected', address=self.address)
                connection.settimeout(1)
                send(connection, event)
                self.trace.emit('audit_event', delivery='sent_awaiting_ack', event_id=event['id'], attempt=attempt)
                acknowledgement = receive(connection, self.trace)
                if acknowledgement != {'ack': event['id']}:
                    raise ValueError('Invalid logger acknowledgement')
                self.delivered += 1
                self.last_ack = time.time()
                self.last_ack_monotonic_ns = time.monotonic_ns()
                self.acknowledgements.append(dict(event_id=event['id'], timestamp=self.last_ack,
                                                 stage='ack_received', operation_id=event.get('operation_id')))
                self.error, self.pending = None, False
                self.trace.emit('audit_event', delivery='ack_received', event_id=event['id'],
                                delivered=self.delivered, backlog=self.queue.qsize(), attempt=attempt)
                event = None
                attempt = 0
                self.queue.task_done()
            except (OSError, EOFError, ValueError) as error:
                self.retries += 1
                self.error = 'Logger unavailable; bounded retry pending'
                self.trace.emit('audit_event', delivery='retry_pending', event_id=event['id'], attempt=attempt,
                                error=str(error), backlog=self.queue.qsize() + 1)
                if connection:
                    connection.close()
                connection = None
                self.stop.wait(.5)
        if connection:
            connection.close()


class AuditServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 8

    def __init__(self, address, database, health_path, trace=QUIET):
        self.database, self.health_path = Path(database), Path(health_path)
        self.trace = trace
        self.capacity = threading.BoundedSemaphore(8)
        self.health_lock = threading.Lock()
        self.received, self.rejected, self.active, self.last_received = 0, 0, 0, None
        self.last_error = None
        self.deliveries = deque(maxlen=128)
        self.server_id = str(uuid.uuid4())
        connect_store(database).close()
        super().__init__(address, AuditHandler)

    def process_request(self, request, address):
        if not self.capacity.acquire(blocking=False):
            self.shutdown_request(request)
            with self.health_lock:
                self.rejected += 1
            self.trace.emit('tcp_client', status='rejected', peer=address, reason='Eight-client capacity reached')
            return
        with self.health_lock:
            self.active += 1
            self.trace.emit('tcp_client', status='connected', peer=address, active=self.active)
        try:
            super().process_request(request, address)
        except BaseException:
            self.capacity.release()
            with self.health_lock:
                self.active -= 1
                self.trace.emit('tcp_client', status='disconnected', peer=address, active=self.active)
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            with self.health_lock:
                self.active -= 1
            self.capacity.release()

    def service_actions(self):
        with self.health_lock:
            state = dict(server_id=self.server_id, collected_at=time.time(), received=self.received,
                         rejected=self.rejected, active=self.active, last_received=self.last_received,
                         error=self.last_error, deliveries=list(self.deliveries))
        if self.trace.enabled:
            state['terminal'] = self.trace.health()
        atomic_json(self.health_path, state)


class AuditHandler(socketserver.BaseRequestHandler):
    def handle(self):
        trace = getattr(self.server, 'trace', QUIET)
        self.request.settimeout(2)
        connection = connect_store(self.server.database)
        try:
            while True:
                value = receive(self.request, trace) if trace.enabled else receive(self.request)
                event = validate_event(value)
                trace.emit('audit_event', stage='validated', event_id=event['id'], peer=self.client_address,
                           operation_id=event.get('operation_id'), action=event['action'], status=event['status'])
                trace.emit('audit_event', stage='persist_pending', event_id=event['id'])
                save_event(connection, event)
                trace.emit('audit_event', stage='sqlite_commit_returned', event_id=event['id'],
                           database=str(self.server.database), deduplication='INSERT OR IGNORE')
                with self.server.health_lock:
                    self.server.received += 1
                    self.server.last_received = time.time()
                    self.server.last_error = None
                    self.server.deliveries.append(dict(event_id=event['id'], stage='sqlite_commit_returned',
                                                       timestamp=time.time(), operation_id=event.get('operation_id')))
                send(self.request, {'ack': event['id']})
                with self.server.health_lock:
                    self.server.deliveries.append(dict(event_id=event['id'], stage='ack_sent', timestamp=time.time()))
                trace.emit('audit_event', stage='ack_sent', event_id=event['id'],
                           evidence='sendall returned; client receipt not observed by server')
        except EOFError as error:
            trace.emit('tcp_client', status='eof', peer=self.client_address, error=str(error))
        except sqlite3.Error as error:
            trace.emit('audit_event', stage='persistence_failed', error=str(error))
            with self.server.health_lock:
                self.server.last_error = f'Persistence failed: {type(error).__name__}'
        except (OSError, ValueError, KeyError, TypeError, RecursionError) as error:
            trace.emit('tcp_client', status='invalid_or_io_error', peer=self.client_address, error=str(error))
            with self.server.health_lock:
                self.server.rejected += 1
        finally:
            # Closing the final SQLite connection may checkpoint/fsync its WAL.
            # Signal transport closure before that disk work, so an invalid or
            # incomplete frame cannot hold its peer open during storage cleanup.
            try:
                self.request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()


def run_logger(runtime, port=9020, verbose=False):
    runtime = Path(runtime)
    trace = TerminalLog('logger', verbose)
    try:
        with AuditServer(('127.0.0.1', port), runtime / 'events.sqlite3', runtime / 'logger.json', trace) as server:
            print(f'All Blue TCP logger: 127.0.0.1:{server.server_address[1]}', flush=True)
            trace.emit('logger', status='listening', address=server.server_address, server_id=server.server_id)
            server.serve_forever(poll_interval=.5)
    finally:
        trace.close()
