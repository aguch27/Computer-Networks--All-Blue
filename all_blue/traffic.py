"""Real bounded TCP echo applications and receipt evidence for the lab."""
import argparse
import json
import socket
import socketserver
import threading
import time
import uuid
from pathlib import Path

from .storage import atomic_json


class EchoServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 16

    def __init__(self, address, evidence):
        self.evidence = Path(evidence)
        self.lock = threading.Lock()
        self.capacity = threading.BoundedSemaphore(16)
        self.receipts = dict(messages=0, bytes=0, last_received=None, recent=[])
        super().__init__(address, EchoHandler)
        atomic_json(self.evidence, self.receipts)

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


class EchoHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        try:
            while True:
                body = self.rfile.readline(1025)
                if not body or len(body) > 1024 or not body.endswith(b'\n'):
                    return
                with self.server.lock:
                    receipts = self.server.receipts
                    receipts['messages'] += 1
                    receipts['bytes'] += len(body)
                    receipts['last_received'] = time.time()
                    receipts['recent'].append(dict(timestamp=time.time(), peer=self.client_address[0],
                                                   text=body.decode(errors='replace').strip()))
                    receipts['recent'] = receipts['recent'][-32:]
                    atomic_json(self.server.evidence, receipts)
                self.wfile.write(body)
                self.wfile.flush()
        except (OSError, ValueError):
            return


def exchange(host, port, count=1, interval=.1, source_port=None, timeout=1.2, measure=False):
    result = dict(sent=0, received=0, error=None, started_at=time.time(), completed_at=None)
    if measure:
        if not 1 <= count <= 10000 or interval != 0:
            raise ValueError('Measurements need 1..10000 exchanges and zero interval')
        result.update(token=str(uuid.uuid4()), rtt_ms=[], received_bytes=0, connect_ms=None,
                      first_flow_ms=None, steady_goodput_mbps=None, first_reply_ns=None, last_reply_ns=None)
    try:
        with socket.socket() as connection:
            connection.settimeout(timeout)
            if source_port:
                connection.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                connection.bind(('0.0.0.0', source_port))
            elif measure:
                connection.bind(('0.0.0.0', 0))
            if measure:
                result['source_port'] = connection.getsockname()[1]
                result['connect_started_ns'] = time.monotonic_ns()
            connection.connect((host, port))
            if measure:
                result['connect_ms'] = (time.monotonic_ns() - result['connect_started_ns']) / 1e6
            result['source_port'] = connection.getsockname()[1]
            stream = connection.makefile('rb')
            for sequence in range(count):
                payload = f'all-blue:{sequence}:{time.time_ns()}\n'.encode()
                if measure:
                    payload = f'{result["token"]}:{sequence}:'.encode().ljust(1023, b'x') + b'\n'
                    sent_ns = time.monotonic_ns()
                connection.sendall(payload)
                result['sent'] += 1
                reply = stream.readline(1025)
                if reply != payload:
                    raise OSError('Echo differed from transmitted payload')
                result['received'] += 1
                if measure:
                    received_ns = time.monotonic_ns()
                    result['last_reply_ns'] = received_ns
                    result['rtt_ms'].append((received_ns - sent_ns) / 1e6)
                    result['received_bytes'] += len(reply)
                    if sequence == 0:
                        result['first_reply_ns'] = received_ns
                        result['first_flow_ms'] = (received_ns - result['connect_started_ns']) / 1e6
                    elif received_ns > result['first_reply_ns']:
                        result['steady_goodput_mbps'] = (result['received_bytes'] - 1024) * 8000 / (received_ns - result['first_reply_ns'])
                if sequence + 1 < count:
                    time.sleep(interval)
    except OSError as error:
        result['error'] = str(error)
    result['completed_at'] = time.time()
    if measure:
        result['completed_monotonic_ns'] = time.monotonic_ns()
    return result


def main():
    parser = argparse.ArgumentParser(description='All Blue lab socket applications')
    sub = parser.add_subparsers(dest='command', required=True)
    server = sub.add_parser('server')
    server.add_argument('--port', type=int, required=True)
    server.add_argument('--evidence', required=True)
    client = sub.add_parser('client')
    client.add_argument('host')
    client.add_argument('--port', type=int, required=True)
    client.add_argument('--count', type=int, default=1)
    client.add_argument('--interval', type=float, default=.1)
    client.add_argument('--source-port', type=int)
    client.add_argument('--measure', action='store_true', help='Monotonic timings for 1024-byte echo workloads; requires --interval 0')
    args = parser.parse_args()
    if args.command == 'server':
        with EchoServer(('0.0.0.0', args.port), args.evidence) as service:
            print(json.dumps(dict(listening=args.port)), flush=True)
            service.serve_forever()
    else:
        print(json.dumps(exchange(args.host, args.port, args.count, args.interval, args.source_port, measure=args.measure)), flush=True)


if __name__ == '__main__':
    main()
