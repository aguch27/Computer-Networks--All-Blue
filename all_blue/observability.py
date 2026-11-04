"""Optional bounded terminal diagnostics; never a delivery or enforcement channel."""
import json
import queue
import sys
import threading
import time


class TerminalLog:
    def __init__(self, component, enabled=False, stream=None, capacity=512):
        self.component, self.enabled = component, enabled
        self.stream = stream if stream is not None else sys.stdout
        self.queue = queue.Queue(maxsize=capacity)
        self.dropped = 0
        self.error = None
        self.stop = threading.Event()
        self.thread = None
        if enabled:
            self.thread = threading.Thread(target=self._write, name='terminal-output', daemon=True)
            self.thread.start()

    def emit(self, kind, **fields):
        if not self.enabled:
            return
        # Callers supply bounded metadata, never packet payloads. Formatting and all
        # potentially blocking output happen off the controller/socket threads.
        record = dict(time=time.time(), monotonic_ns=time.monotonic_ns(),
                      component=self.component, thread=threading.current_thread().name, kind=kind, **fields)
        try:
            self.queue.put_nowait(record)
        except queue.Full:
            self.dropped += 1

    def health(self):
        return dict(enabled=self.enabled, queued=self.queue.qsize(), dropped=self.dropped, error=self.error)

    def _write(self):
        while not self.stop.is_set() or not self.queue.empty():
            try:
                record = self.queue.get(timeout=.1)
            except queue.Empty:
                continue
            try:
                record['terminal_dropped'] = self.dropped
                self.stream.write(json.dumps(record, separators=(',', ':'), allow_nan=False) + '\n')
                self.stream.flush()
            except (OSError, ValueError, TypeError) as error:
                self.error = type(error).__name__
                self.dropped += 1
            finally:
                self.queue.task_done()

    def close(self):
        self.stop.set()
        if self.thread:
            # A full pipe or slow terminal must not delay enforcement/shutdown.
            self.thread.join(timeout=.25)


QUIET = TerminalLog('disabled')
