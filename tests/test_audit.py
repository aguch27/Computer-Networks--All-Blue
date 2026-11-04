import json
from pathlib import Path
import select
import socket
import sqlite3
import struct
import subprocess
import sys
import time
import threading
import uuid
import pytest
from all_blue.audit import AuditClient, MAX_MESSAGE, receive, send
from all_blue.storage import connect_store, recent_events, save_event

def wait_for(predicate, timeout=6):
    deadline=time.monotonic()+timeout
    while time.monotonic()<deadline:
        if predicate(): return
        time.sleep(.05)
    raise AssertionError('Condition did not become true')

def event():
    return dict(id=str(uuid.uuid4()),run_id=str(uuid.uuid4()),timestamp=time.time(),
                action='DENY',status='confirmed',reason='<script>unsafe()</script>')

def start_logger(path,port=0):
    process=subprocess.Popen([sys.executable,'-m','all_blue','--runtime',str(path),'logger','--port',str(port)],
                             stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
    assert select.select([process.stdout],[],[],6)[0], 'Logger did not start'
    line=process.stdout.readline()
    if not line: raise AssertionError(process.stderr.read())
    return process,int(line.strip().split(':')[-1])

@pytest.fixture
def logger(tmp_path):
    process,port=start_logger(tmp_path)
    try: yield tmp_path,port
    finally:
        process.terminate(); process.wait(timeout=5)

def test_real_tcp_fragmented_frame_durable_ack_and_dedup(logger):
    path,port=logger; value=event()
    body=json.dumps(value).encode(); frame=struct.pack('!I',len(body))+body
    with socket.create_connection(('127.0.0.1',port),timeout=2) as client:
        for offset in range(0,len(frame),3): client.sendall(frame[offset:offset+3])
        assert receive(client) == {'ack':value['id']}
        send(client,value); assert receive(client) == {'ack':value['id']}
    stored=recent_events(path/'events.sqlite3')
    assert len(stored)==1 and stored[0]==value

def test_oversized_frame_and_partial_disconnect_do_not_break_logger(logger):
    path,port=logger
    with socket.create_connection(('127.0.0.1',port),timeout=2) as client:
        client.sendall(struct.pack('!I',MAX_MESSAGE+1)); assert client.recv(1)==b''
    with socket.create_connection(('127.0.0.1',port),timeout=2) as client:
        client.sendall(b'\x00\x00')
    value=event()
    with socket.create_connection(('127.0.0.1',port),timeout=2) as client:
        send(client,value); assert receive(client)['ack']==value['id']
    assert len(recent_events(path/'events.sqlite3'))==1

def test_outage_is_bounded_and_retry_recovers(tmp_path):
    with socket.socket() as reserve:
        reserve.bind(('127.0.0.1',0)); port=reserve.getsockname()[1]
    client=AuditClient(('127.0.0.1',port),str(uuid.uuid4()),capacity=4)
    process=None
    try:
        started=time.monotonic()
        for _ in range(100): client.emit('ALLOW','requested','outage test')
        assert time.monotonic()-started < .5
        assert client.health()['backlog']<=5 and client.dropped>=95
        process,_=start_logger(tmp_path,port)
        wait_for(lambda: client.delivered>0 and client.health()['backlog']==0)
        assert client.health()['error'] is None
        assert len(recent_events(tmp_path/'events.sqlite3'))==client.delivered
    finally:
        client.close()
        if process: process.terminate(); process.wait(timeout=5)

def test_retention_remains_bounded(tmp_path):
    connection=connect_store(tmp_path/'audit.db')
    for _ in range(14): save_event(connection,event(),limit=5)
    assert connection.execute('SELECT count(*) FROM events').fetchone()[0]==5
    connection.close()

def test_incomplete_frame_is_closed_and_logger_remains_usable(logger):
    path,port=logger
    with socket.create_connection(('127.0.0.1',port),timeout=4) as client:
        value=event(); send(client,value); assert receive(client)['ack']==value['id']
        client.sendall(struct.pack('!I',100))
        client.sendall(b'  ')
        assert client.recv(1)==b''
        # Socket timeout bounds this integration wait. Deterministic clock tests
        # below verify the absolute deadline without measuring VM scheduling lag.
    value=event()
    with socket.create_connection(('127.0.0.1',port),timeout=2) as client:
        send(client,value); assert receive(client)['ack']==value['id']

def test_lost_ack_retries_same_identifier_and_deduplicates(tmp_path):
    listener=socket.socket(); listener.bind(('127.0.0.1',0)); listener.listen(2); listener.settimeout(6)
    seen=[]
    def receiver():
        store=connect_store(tmp_path/'audit.db')
        try:
            for attempt in range(2):
                peer,_=listener.accept()
                with peer:
                    peer.settimeout(2)
                    value=receive(peer); seen.append(value['id']); save_event(store,value)
                    if attempt: send(peer,{'ack':value['id']})
        finally:
            store.close(); listener.close()
    worker=threading.Thread(target=receiver); worker.start()
    client=AuditClient(listener.getsockname(),str(uuid.uuid4()))
    try:
        client.emit('ALLOW','confirmed','Simulated lost acknowledgement')
        wait_for(lambda: client.delivered==1)
        assert len(seen)==2 and seen[0]==seen[1]
        assert len(recent_events(tmp_path/'audit.db'))==1
    finally:
        client.close(); worker.join(timeout=7)

def test_frame_activity_cannot_extend_absolute_deadline(monkeypatch):
    import all_blue.audit as audit
    ticks=[0.0]
    class TrickleSocket:
        timeout=2
        def gettimeout(self): return self.timeout
        def settimeout(self,value): self.timeout=value
        def recv(self,count):
            if count==4: return struct.pack('!I',100)
            ticks[0]+=.51
            return b' '
    monkeypatch.setattr(audit.time,'monotonic',lambda:ticks[0])
    peer=TrickleSocket()
    with pytest.raises(TimeoutError,match='deadline'):
        receive(peer)
    assert ticks[0] < 2.1
    assert peer.timeout == 2


def test_rejected_connection_closes_before_slow_database_cleanup(monkeypatch):
    import all_blue.audit as audit
    from types import SimpleNamespace
    entered=threading.Event(); release=threading.Event()
    class SlowStore:
        def close(self):
            entered.set()
            release.wait(timeout=5)
    def rejected(_peer): raise ValueError('Invalid frame')
    monkeypatch.setattr(audit,'connect_store',lambda _path:SlowStore())
    monkeypatch.setattr(audit,'receive',rejected)
    server=SimpleNamespace(database='unused',health_lock=threading.Lock(),rejected=0)
    client,peer=socket.socketpair()
    worker=threading.Thread(target=audit.AuditHandler,args=(peer,None,server))
    worker.start()
    try:
        assert entered.wait(timeout=2)
        client.settimeout(2)
        assert client.recv(1)==b''
        assert not release.is_set() and server.rejected==1
    finally:
        release.set(); worker.join(timeout=3)
        client.close(); peer.close()
