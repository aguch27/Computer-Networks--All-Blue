import threading
import time
import all_blue.storage as storage


def test_slow_ui_disk_work_does_not_block_producer_or_accumulate(monkeypatch,tmp_path):
    entered=threading.Event(); release=threading.Event(); written=[]
    def delayed_write(path,data):
        entered.set(); release.wait(timeout=3); written.append(data)
    monkeypatch.setattr(storage,'atomic_json',delayed_write)
    writer=storage.SnapshotWriter(tmp_path/'state.json')
    try:
        writer.publish({'sequence':0})
        assert entered.wait(timeout=1)
        started=time.monotonic()
        for sequence in range(1,100): writer.publish({'sequence':sequence})
        assert time.monotonic()-started<.5
        assert writer.queue.qsize()==1
        release.set()
        deadline=time.monotonic()+2
        while len(written)<2 and time.monotonic()<deadline: time.sleep(.01)
        assert written[-1]['sequence']==99
    finally:
        release.set(); writer.close()


def test_audit_reads_release_descriptors_even_when_payload_is_invalid(tmp_path):
    import gc
    import json
    import os
    import pytest

    if not os.path.isdir('/proc/self/fd'):
        pytest.skip('File-descriptor check requires Linux')
    path = tmp_path / 'events.sqlite3'
    connection = storage.connect_store(path)
    storage.save_event(connection, dict(id='one', run_id='test', timestamp=1, action='ALLOW'))
    connection.close()
    gc.collect()
    collecting = gc.isenabled()
    gc.disable()
    try:
        before = len(os.listdir('/proc/self/fd'))
        for _ in range(50):
            assert storage.recent_events(path, 'test')[0]['action'] == 'ALLOW'
        assert len(os.listdir('/proc/self/fd')) == before

        connection = storage.connect_store(path)
        with connection:
            connection.execute("UPDATE events SET payload='invalid json'")
        connection.close()
        before = len(os.listdir('/proc/self/fd'))
        for _ in range(50):
            with pytest.raises(json.JSONDecodeError):
                storage.recent_events(path, 'test')
        assert len(os.listdir('/proc/self/fd')) == before
    finally:
        if collecting:
            gc.enable()
        gc.collect()
