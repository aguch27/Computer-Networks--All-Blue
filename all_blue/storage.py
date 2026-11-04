"""Atomic local snapshots and bounded SQLite audit storage."""
from contextlib import closing
import copy
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import queue
import threading


def atomic_json(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(dir=path.parent, prefix='.' + path.name)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(data, stream, ensure_ascii=False, allow_nan=False)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


class SnapshotWriter:
    """UI disk work never blocks the controller; retain only the latest snapshot."""
    def __init__(self, path):
        self.path = Path(path)
        self.queue = queue.Queue(maxsize=1)
        self.stop = threading.Event()
        self.error = None
        self.thread = threading.Thread(target=self._run, daemon=True, name='snapshot-writer')
        self.thread.start()

    def publish(self, data):
        frozen = copy.deepcopy(data)
        try:
            self.queue.put_nowait(frozen)
        except queue.Full:
            try:
                self.queue.get_nowait()
            except queue.Empty:
                pass
            self.queue.put_nowait(frozen)

    def _run(self):
        while not self.stop.is_set():
            try:
                data = self.queue.get(timeout=.2)
            except queue.Empty:
                continue
            try:
                atomic_json(self.path, data)
                self.error = None
            except (OSError, ValueError) as error:
                self.error = f'Snapshot write failed: {type(error).__name__}'

    def close(self):
        self.stop.set()
        self.thread.join(timeout=1)


def connect_store(path):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(path, timeout=1)
    connection.execute('PRAGMA journal_mode=WAL')
    connection.execute('PRAGMA synchronous=FULL')
    connection.execute('''CREATE TABLE IF NOT EXISTS events (
        sequence INTEGER PRIMARY KEY, id TEXT UNIQUE NOT NULL,
        run_id TEXT NOT NULL, timestamp REAL NOT NULL, payload TEXT NOT NULL)''')
    connection.execute('CREATE INDEX IF NOT EXISTS events_run ON events(run_id, sequence)')
    return connection


def save_event(connection, event, limit=10000):
    with connection:
        connection.execute('INSERT OR IGNORE INTO events(id,run_id,timestamp,payload) VALUES (?,?,?,?)',
                           (event['id'], event['run_id'], event['timestamp'], json.dumps(event)))
        connection.execute('DELETE FROM events WHERE sequence <= COALESCE('
                           '(SELECT sequence FROM events ORDER BY sequence DESC LIMIT 1 OFFSET ?), -1)',
                           (limit,))


def recent_events(path, run_id=None, limit=100):
    path = Path(path).resolve()
    # SQLite's transaction context does not close the connection. Polling readers
    # must release their descriptors immediately, including on decode failures.
    with closing(sqlite3.connect(path.as_uri() + '?mode=ro', uri=True, timeout=.2)) as connection:
        if run_id:
            rows = connection.execute('SELECT payload FROM events WHERE run_id=? ORDER BY sequence DESC LIMIT ?',
                                      (run_id, min(limit, 100)))
        else:
            rows = connection.execute('SELECT payload FROM events ORDER BY sequence DESC LIMIT ?', (min(limit, 100),))
        return [json.loads(row[0]) for row in rows]
