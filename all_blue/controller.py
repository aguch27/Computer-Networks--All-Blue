"""OS-Ken application. All rule writes occur in one application event queue.

A transaction is confirmed only after a barrier and matching flow-stat readback.
The native OS-Ken hub avoids eventlet monkey-patching on modern Python.
"""
from collections import deque
from dataclasses import dataclass, field
import json
import logging
import os
from pathlib import Path
import queue
import time
import uuid

from os_ken.base import app_manager
from os_ken.controller import event, ofp_event
from os_ken.controller.handler import CONFIG_DISPATCHER, DEAD_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from os_ken.lib import hub
from os_ken.lib.packet import ethernet, ipv4, packet, tcp
from os_ken.ofproto import ofproto_v1_3 as ofp
from os_ken.ofproto import ofproto_v1_3_parser as parser

from .admin import AdminServer
from .audit import AuditClient
from .escalation import Escalation, EscalationConfig
from .policy import Flow, Policy
from .observability import QUIET, TerminalLog
from .rules import (BASE, BLOCK_BASE, FULL_MASK, GUARD, PREFIX, PREFIX_MASK, TUPLE_BASE,
                    base_rules, delete_cookie, diagnostic, guard, host_block, tuple_rules)
from .storage import SnapshotWriter, atomic_json

TUPLE_MASK = 0xFFFFFFFFFFF00000


def load_mode_override(config, path):
    """A bad saved override is visible and disables escalation, never the firewall."""
    try:
        with Path(path).open('rb') as stream:
            raw = stream.read(1025)
        if len(raw) > 1024:
            raise ValueError('Saved mode exceeds size limit')
        saved = json.loads(raw)
        if not isinstance(saved, dict) or set(saved) != {'mode'}:
            raise ValueError('Saved override must contain only mode')
        return config.with_mode(saved['mode']), None
    except FileNotFoundError:
        return config, None
    except (OSError, ValueError) as error:
        return config.with_mode('off'), f'Cannot load saved escalation mode: {error}. Escalation is off; select a mode to save a new override.'


class Tick(event.EventBase):
    pass


@dataclass
class Phase:
    additions: list = field(default_factory=list)
    deletions: list = field(default_factory=list)
    clear_tables: list = field(default_factory=list)


class AllBlue(app_manager.OSKenApp):
    OFP_VERSIONS = [ofp.OFP_VERSION]
    trace = QUIET

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.policy = Policy(os.environ.get('ALL_BLUE_POLICY', 'config/lab.json'))
        self.runtime = Path(os.environ.get('ALL_BLUE_RUNTIME', 'runtime'))
        self.runtime.mkdir(parents=True, exist_ok=True)
        self.mode_path = self.runtime / 'escalation-mode.json'
        config, self.mode_error = load_mode_override(EscalationConfig.load(
            os.environ.get('ALL_BLUE_ESCALATION'), self.policy), self.mode_path)
        self.escalation = Escalation(self.policy, config)
        self.snapshot_writer = SnapshotWriter(self.runtime / 'controller.json')
        self.run_id = str(uuid.uuid4())
        self.trace = TerminalLog('controller', os.environ.get('ALL_BLUE_VERBOSE') == '1')
        self.started_at = time.time()
        self.blocked_path = self.runtime / 'blocked.json'
        self.blocked = set(json.loads(self.blocked_path.read_text())) if self.blocked_path.exists() else set()
        if not self.blocked <= self.policy.hosts.keys():
            raise ValueError('Saved block state contains unknown hosts')
        self.epoch = 0
        self.switch_epoch = 0
        self.commands = queue.Queue(maxsize=32)
        self.admin = AdminServer(self.runtime / 'admin.sock', self.commands)
        self.audit = AuditClient(('127.0.0.1', int(os.environ.get('ALL_BLUE_LOG_PORT', '9020'))),
                                 self.run_id, trace=self.trace)
        self.dp, self.ready, self.error = None, False, 'Waiting for the lab switch'
        self.jobs = deque()
        self.inflight = set()
        self.active = None
        self.records = {}
        self.operations = deque(maxlen=128)
        self.history = deque(maxlen=90)
        self.stats, self.stats_at, self.stats_pending = [], None, None
        self.poll_due, self.export_due = 0, 0
        self.counter = 0
        self.packet_ins, self.overload, self.invalid_packets = 0, 0, 0
        self.audit.emit('CONTROLLER', 'started', 'New controller run; switch reconciliation required')
        self.trace.emit('controller', status='started', run_id=self.run_id, restored_block_intent=sorted(self.blocked),
                        escalation_mode=self.escalation.config.mode, ready=False)
        if self.mode_error:
            self._status(self._operation('MODE', self.mode_error, mode='off', origin='startup'), 'failed')
        self.ticker = hub.spawn(self._clock)

    def _clock(self):
        while self.is_active:
            hub.sleep(.25)
            self.send_event(self.name, Tick())

    def close(self):
        self.admin.close()
        self.audit.close()
        self.snapshot_writer.close()
        self.trace.emit('controller', status='closing', run_id=self.run_id)
        self.trace.close()
        super().close()

    def _operation(self, action, reason, **details):
        result = dict(id=details.pop('id', str(uuid.uuid4())), action=action,
                      status='requested', reason=reason, timestamp=time.time(),
                      requested_monotonic_ns=time.monotonic_ns(), **details)
        self.operations.append(result)
        self.trace.emit('operation', operation_id=result['id'], action=action, status='requested',
                        reason=reason, **details)
        return result

    def _status(self, operation, status, reason=None):
        operation['status'] = status
        if reason:
            operation['reason'] = reason
        operation['updated_at'] = time.time()
        operation['updated_monotonic_ns'] = time.monotonic_ns()
        self.trace.emit('operation', operation_id=operation['id'], action=operation['action'],
                        status=status, reason=operation['reason'], host=operation.get('host'),
                        updated_monotonic_ns=operation['updated_monotonic_ns'])
        self.audit.emit(operation['action'], status, operation['reason'],
                        operation_id=operation['id'], host=operation.get('host'), flow=operation.get('flow'),
                        origin=operation.get('origin'), evidence=operation.get('evidence'),
                        trigger_reason=operation.get('trigger_reason'), mode=operation.get('mode'))

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features(self, ev):
        dp = ev.msg.datapath
        if dp.id != self.policy.datapath_id or ev.msg.n_tables < 2 or (self.dp and self.dp is not dp):
            dp.close()
            return
        self.dp, self.ready, self.error = dp, False, 'Reconciling switch rules'
        self.trace.emit('switch', status='connected_reconciling', datapath_id=dp.id, tables=ev.msg.n_tables)
        self.epoch += 1
        self.switch_epoch += 1
        self.escalation.reset()
        self.history.clear()
        self.records.clear()
        self.inflight.clear()
        self.jobs.clear()
        self.active, self.stats_pending, self.stats_at, self.stats = None, None, None, []
        dp.send_msg(parser.OFPSetConfig(dp, ofp.OFPC_FRAG_DROP, ofp.OFPCML_NO_BUFFER))
        operation = self._operation('RECONCILE', 'Install default deny and restore deliberate host blocks')
        rules = base_rules(self.policy)
        for name in sorted(self.blocked):
            rules.extend(host_block(self.policy.hosts[name]))
        self.jobs.append(dict(kind='boot', operation=operation,
                              phases=deque([Phase([guard()]),
                                            Phase([guard(), *rules], clear_tables=[1, 0]),
                                            Phase(deletions=[(GUARD, FULL_MASK)])])))
        self._next_job()

    @set_ev_cls(ofp_event.EventOFPStateChange, DEAD_DISPATCHER)
    def disconnected(self, ev):
        if ev.datapath is self.dp:
            self._fail('Switch disconnected; previous permissions may last until their hard timeout', close=False)
            self.dp = None
            self.stats_at = None

    def _fail(self, reason, close=True):
        self.ready, self.error = False, reason
        self.trace.emit('controller', status='failed', reason=reason)
        if self.active:
            self._status(self.active['operation'], 'failed', reason)
        for job in self.jobs:
            self._status(job['operation'], 'failed', reason)
        self.jobs.clear()
        self.inflight.clear()
        self.active, self.stats_pending = None, None
        self.audit.emit('CONTROLLER', 'degraded', reason)
        if close and self.dp:
            # Best-effort emergency drop; readback was unavailable so never label it confirmed.
            self.dp.send_msg(guard().message(self.dp))
            self.trace.emit('openflow_write', status='unverified', change='ADD',
                            reason='Emergency guard sent; no barrier/readback', **diagnostic(guard().message(self.dp)))
            self.dp.close()

    def _next_job(self):
        if self.active or not self.dp or not self.jobs:
            return
        job = self.jobs.popleft()
        if job['kind'] == 'flow' and job['epoch'] != self.epoch:
            self.inflight.discard(job['key'])
            self._status(job['operation'], 'superseded', 'A newer host action invalidated this permission')
            return self._next_job()
        if job['kind'] == 'release' and job['epoch'] != self.epoch:
            self._status(job['operation'], 'superseded', 'A newer host action superseded this release')
            return self._next_job()
        if job['kind'] in ('block', 'release'):
            host = self.policy.hosts[job['host']]
            cleanup = Phase(deletions=[(TUPLE_BASE, TUPLE_MASK)])
            if job['kind'] == 'block':
                job['phases'] = deque([Phase(host_block(host)), cleanup])
            else:
                job['phases'] = deque([cleanup, Phase(deletions=[(BLOCK_BASE + host.port, FULL_MASK)])])
        self.active = job
        self._status(job['operation'], 'pending')
        self._phase()

    def _phase(self):
        job = self.active
        if job['kind'] in ('flow', 'release') and job['epoch'] != self.epoch:
            self._status(job['operation'], 'superseded', 'Newer host action; no packet dispatched')
            self.inflight.discard(job.get('key'))
            self.active = None
            self._next_job()
            return
        if not job['phases']:
            self._complete()
            return
        phase = job['phases'].popleft()
        job['phase'], job['xids'], job['deadline'] = phase, set(), time.monotonic() + 4
        for table in phase.clear_tables:
            message = parser.OFPFlowMod(self.dp, table_id=table, command=ofp.OFPFC_DELETE,
                                       out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                                       match=parser.OFPMatch())
            self._send_tracked(message)
        for cookie, mask in phase.deletions:
            self._send_tracked(delete_cookie(self.dp, cookie, mask))
        for rule in phase.additions:
            self._send_tracked(rule.message(self.dp))
        barrier = parser.OFPBarrierRequest(self.dp)
        self._send_tracked(barrier)
        job['barrier'] = barrier.xid

    def _send_tracked(self, message):
        self.dp.set_xid(message)
        self.active['xids'].add(message.xid)
        self.dp.send_msg(message)
        if self.trace.enabled:
            fields = dict(xid=message.xid, operation_id=self.active['operation']['id'], status='pending')
            if isinstance(message, parser.OFPFlowMod):
                change = {ofp.OFPFC_ADD: 'ADD', ofp.OFPFC_MODIFY: 'MODIFY', ofp.OFPFC_MODIFY_STRICT: 'MODIFY_STRICT',
                          ofp.OFPFC_DELETE: 'DELETE', ofp.OFPFC_DELETE_STRICT: 'DELETE_STRICT'}.get(message.command)
                self.trace.emit('openflow_write', change=change, cookie_mask=f'0x{message.cookie_mask:x}',
                                **fields, **diagnostic(message))
            else:
                self.trace.emit('barrier_request', **fields)

    @set_ev_cls(ofp_event.EventOFPErrorMsg, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def openflow_error(self, ev):
        if ev.msg.datapath is self.dp:
            if self.trace.enabled:
                self.trace.emit('openflow_error', status='failed', error_type=ev.msg.type, code=ev.msg.code,
                                xid=ev.msg.xid, data=bytes(ev.msg.data[:256]).hex())
            else:
                self.logger.error('OpenFlow rejection type=%s code=%s xid=%s data=%s',
                                  ev.msg.type, ev.msg.code, ev.msg.xid, bytes(ev.msg.data[:256]).hex())
            self._fail(f'OpenFlow error type={ev.msg.type} code={ev.msg.code} xid={ev.msg.xid}')

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def barrier(self, ev):
        if ev.msg.datapath is self.dp and self.active and ev.msg.xid == self.active.get('barrier'):
            self.trace.emit('barrier_ack', xid=ev.msg.xid, operation_id=self.active['operation']['id'],
                            status='pending', reason='Barrier received; rule readback still required')
            self._request_stats(transaction=True)

    def _request_stats(self, transaction=False):
        # Cancel an older monitoring request rather than confusing it with a transaction readback.
        if self.stats_pending:
            self.trace.emit('readback_status', xid=self.stats_pending['xid'], status='superseded')
        message = parser.OFPFlowStatsRequest(self.dp, table_id=ofp.OFPTT_ALL,
                                             cookie=PREFIX, cookie_mask=PREFIX_MASK)
        self.dp.set_xid(message)
        self.stats_pending = dict(xid=message.xid, transaction=transaction, rows=[],
                                  parts=0, deadline=time.monotonic() + 3)
        self.dp.send_msg(message)
        self.trace.emit('readback_request', xid=message.xid, transaction=transaction, status='pending')

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def statistics(self, ev):
        pending = self.stats_pending
        if ev.msg.datapath is not self.dp or not pending or ev.msg.xid != pending['xid']:
            return
        pending['parts'] += 1
        if pending['parts'] > 16 or len(pending['rows']) + len(ev.msg.body) > 512:
            self._fail('Switch statistics exceeded the lab resource budget')
            return
        pending['rows'].extend(ev.msg.body)
        if ev.msg.flags & ofp.OFPMPF_REPLY_MORE:
            return
        self.stats_pending = None
        self._observe(pending['rows'])
        self.trace.emit('readback_received', xid=ev.msg.xid, rows=len(pending['rows']),
                        transaction=pending['transaction'], status='observed')
        if pending['transaction'] and self.active:
            phase = self.active['phase']
            for rule in phase.additions:
                if not any(rule.matches(row) for row in pending['rows']):
                    self._fail('Switch readback did not match a requested rule')
                    return
            for cookie, mask in phase.deletions:
                if any(row.cookie & mask == cookie & mask for row in pending['rows']):
                    self._fail('Switch readback still contains a rule requested for removal')
                    return
            self.trace.emit('phase_verified', status='confirmed',
                            operation_id=self.active.get('operation', {}).get('id'), xid=ev.msg.xid)
            self._phase()

    def _complete(self):
        job = self.active
        if job['kind'] == 'boot':
            self.ready, self.error = True, None
        elif job['kind'] == 'flow':
            self.inflight.discard(job['key'])
            if job['epoch'] == self.epoch and self.policy.decide(job['flow'], self.blocked)[0] == job['action']:
                self.records[job['cookie']] = dict(flow=job['flow'].json(), action=job['action'],
                                                  cookie=job['cookie'], installed_at=time.time())
                if job['action'] == 'ALLOW':
                    # NO_BUFFER is used for both FlowMod and PacketOut: dispatch exactly once here.
                    self.dp.send_msg(parser.OFPPacketOut(self.dp, buffer_id=ofp.OFP_NO_BUFFER,
                        in_port=job['flow'].in_port,
                        actions=[parser.OFPActionOutput(self.policy.by_ip[job['flow'].destination_ip].port)],
                        data=job['data']))
            else:
                self._status(job['operation'], 'superseded', 'Newer action prevented first-packet dispatch')
                self.active = None
                self._next_job()
                return
        elif job['kind'] == 'release' and job['epoch'] == self.epoch:
            remaining = self.blocked - {job['host']}
            try:
                atomic_json(self.blocked_path, sorted(remaining))
            except OSError:
                # The switch phase completed, but durable intent could not be updated.
                # Keep the saved intent and use the existing fail-closed error path.
                self._fail('Cannot persist release; reconciliation required')
                return
            self.blocked = remaining
            self.escalation.reset(job['host'])
        self._status(job['operation'], 'confirmed', 'Barrier and switch rule readback matched')
        self.active = None
        self._next_job()

    def _observe(self, rows):
        if self.trace.enabled:
            previous = {(row.cookie, row.table_id, row.priority, str(row.match)): (row.packet_count, row.byte_count)
                        for row in self.stats}
            for row in rows:
                if previous.get((row.cookie, row.table_id, row.priority, str(row.match))) != (row.packet_count, row.byte_count):
                    self.trace.emit('switch_rule', status='observed', **diagnostic(row))
        self.stats, self.stats_at = rows, time.time()
        if self.ready:
            self.error = None
        live = {row.cookie for row in rows}
        self.records = {key: value for key, value in self.records.items() if key in live}

    @set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
    def flow_removed(self, ev):
        if ev.msg.datapath is self.dp:
            # An expired permission must permit a new policy decision immediately,
            # rather than suppressing PacketIn until the next statistics poll.
            self.records.pop(ev.msg.cookie, None)
            self.trace.emit('flow_removed', status='observed', cookie=f'0x{ev.msg.cookie:x}',
                            reason=ev.msg.reason, packets=ev.msg.packet_count, bytes=ev.msg.byte_count)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        if ev.msg.datapath is not self.dp or not self.ready:
            return
        self.packet_ins += 1
        if len(self.jobs) >= 128 or len(self.records) + len(self.inflight) >= self.policy.max_tuples:
            self.overload += 1
            self._drop_note('Controller writer/tuple capacity reached')
            return
        try:
            decoded = packet.Packet(ev.msg.data)
            eth, ip, segment = (decoded.get_protocol(ethernet.ethernet),
                                decoded.get_protocol(ipv4.ipv4), decoded.get_protocol(tcp.tcp))
            if (not eth or not ip or not segment or ip.offset or ip.flags & 1
                    or eth.ethertype != 0x0800 or ip.proto != 6 or len(ev.msg.data) != ev.msg.total_len):
                self.invalid_packets += 1
                self._drop_note('Invalid, fragmented, non-TCP or truncated controller-visible frame')
                return
            flow = Flow(ev.msg.match['in_port'], eth.src, eth.dst, ip.src, ip.dst,
                        segment.src_port, segment.dst_port)
        except (ValueError, KeyError, TypeError, IndexError):
            self.invalid_packets += 1
            self._drop_note('Controller-visible frame decoding failed')
            return
        action, reason = self.policy.decide(flow, self.blocked)
        if action == 'BLOCK' or not self.policy.identities(flow):
            self.invalid_packets += 1
            self._drop_note(reason, action, flow)
            return
        signal = self.escalation.observe(flow, segment.bits, self.blocked)
        if signal:
            self.audit.emit('ESCALATION', 'observed', signal['reason'], host=signal['host'],
                            origin='automatic', evidence=signal)
            if self.escalation.config.mode == 'enforce':
                self._host_action('block', signal['host'], str(uuid.uuid4()),
                                  origin='automatic', evidence=signal)
                # The triggering packet is denied; it is never dispatched or buffered.
                return
        if flow.key() in self.inflight:
            return
        # A bare reverse SYN cannot replace or broaden an existing ACK-gated permission.
        for record in self.records.values():
            if record['flow'] == flow.json():
                return
        self.counter = self.counter % 0xFFFFF + 1
        cookie = TUPLE_BASE | self.counter
        operation = self._operation(action, reason, flow=flow.json())
        self.trace.emit('policy_evaluation', operation_id=operation['id'], action=action, reason=reason,
                        flow=flow.json(), tcp_flags=segment.bits, bytes=ev.msg.total_len,
                        status='requested', evidence='Controller-visible tuple; subsequent switch traffic is not traced')
        self.inflight.add(flow.key())
        self.jobs.append(dict(kind='flow', operation=operation, action=action,
                              flow=flow, key=flow.key(), epoch=self.epoch, cookie=cookie,
                              data=bytes(ev.msg.data),
                              phases=deque([Phase(tuple_rules(self.policy, flow, action, cookie))])))
        self._next_job()

    def _drop_note(self, reason, action='DENY', flow=None):
        # At most one sampled invalid-frame diagnostic/second; no packet tracing.
        if self.trace.enabled and time.monotonic() >= getattr(self, '_drop_log_due', 0):
            self._drop_log_due = time.monotonic() + 1
            self.trace.emit('controller_visible_drop', action=action, reason=reason,
                            flow=flow.json() if flow else None, sampled=True)

    def _command(self, command):
        # Browser retries keep their ID; never enqueue an already recorded action twice.
        if any(operation['id'] == command['id'] for operation in self.operations):
            return
        if command.get('run_id', self.run_id) != self.run_id:
            operation = self._operation(command['action'].upper(), 'Controller run changed',
                                        host=command.get('host'), mode=command.get('mode'), id=command['id'])
            self._status(operation, 'superseded', 'Controller restarted; submit from its current state')
            return
        if command['action'] == 'mode':
            self._mode_action(command['mode'], command['id'])
        else:
            self._host_action(command['action'], command['host'], command['id'])

    def _mode_action(self, mode, operation_id):
        operation = self._operation('MODE', 'Local escalation mode request', mode=mode, id=operation_id)
        if not self.ready:
            self._status(operation, 'failed', 'Switch not ready; mode unchanged')
            return
        try:
            self.escalation.config.with_mode(mode)
        except ValueError as error:
            self._status(operation, 'failed', str(error))
            return
        self._status(operation, 'pending', 'Saving escalation mode override')
        try:
            atomic_json(self.mode_path, dict(mode=mode))
        except OSError as error:
            # A directory-fsync failure can occur after rename: never promise rollback.
            self.mode_error = f'Cannot confirm saved mode: {error}. Live mode unchanged; saved state must be checked before restart.'
            self._status(operation, 'failed', self.mode_error)
            return
        self.escalation.set_mode(mode)
        self.mode_error = None
        self._status(operation, 'confirmed', f'Escalation {mode} saved and applied; existing host blocks retained')

    def _host_action(self, action, host, operation_id, origin='manual', evidence=None):
        reason = evidence['reason'] if evidence else 'Local administrative request'
        operation = self._operation(action.upper(), reason, host=host, id=operation_id,
                                    origin=origin, evidence=evidence, trigger_reason=reason)
        if host not in self.policy.hosts or not self.ready or len(self.jobs) >= 160:
            self._status(operation, 'failed', 'Unknown host, switch not ready, or writer queue full')
            return
        if action == 'block':
            desired = self.blocked | {host}
            try:
                atomic_json(self.blocked_path, sorted(desired))
            except OSError:
                self._status(operation, 'failed', 'Cannot persist block; no switch change queued')
                return
            self.blocked = desired
        self.epoch += 1
        self.jobs.append(dict(kind=action, host=host, operation=operation, epoch=self.epoch))
        self._next_job()

    @set_ev_cls(Tick)
    def tick(self, _ev):
        now = time.monotonic()
        for _ in range(8):
            try:
                self._command(self.commands.get_nowait())
            except queue.Empty:
                break
        if self.active and now > self.active.get('deadline', now + 1):
            self._fail('Rule confirmation timed out')
        elif self.stats_pending and now > self.stats_pending['deadline']:
            if self.stats_pending['transaction']:
                self._fail('Rule readback timed out')
            else:
                self.trace.emit('readback_status', xid=self.stats_pending['xid'], status='failed',
                                reason='Traffic statistics timed out')
                self.stats_pending = None
                self.error = 'Traffic statistics timed out'
        if self.dp and self.ready and not self.active and not self.stats_pending and now >= self.poll_due:
            self._request_stats()
            self.poll_due = now + self.policy.poll_seconds
        if now >= self.export_due:
            self._export()
            self.export_due = now + 1

    def _export(self):
        if self.trace.enabled:
            self.trace.emit('controller_counters', packet_ins=self.packet_ins, overload_drops=self.overload,
                            invalid_packets=self.invalid_packets, writer_queue=len(self.jobs), **self.trace.health())
        rows = []
        for stat in self.stats:
            record = self.records.get(stat.cookie)
            if record:
                rows.append(dict(**record, direction='forward' if dict(stat.match.items()).get('in_port') == record['flow']['in_port'] else 'reverse',
                                 packets=stat.packet_count, bytes=stat.byte_count, priority=stat.priority,
                                 hard_timeout=stat.hard_timeout, match=dict(stat.match.items())))
        total = sum(row['bytes'] for row in rows)
        if self.stats_at and (not self.history or self.history[-1]['timestamp'] != self.stats_at):
            self.history.append(dict(timestamp=self.stats_at, bytes=total,
                                     packets=sum(row['packets'] for row in rows), entries=len(rows)))
        hosts = []
        for host in self.policy.hosts.values():
            expected = host_block(host)
            fresh = self.stats_at is not None and time.time() - self.stats_at <= self.policy.poll_seconds * 3
            confirmed = (all(any(rule.matches(row) for row in self.stats) for rule in expected)
                         if self.dp and self.ready and fresh else None)
            hosts.append(dict(name=host.name, label=host.label, ip=host.ip, mac=host.mac, port=host.port,
                              block_requested=host.name in self.blocked, block_confirmed=confirmed))
        self.snapshot_writer.publish(dict(
            run_id=self.run_id, started_at=self.started_at, collected_at=time.time(),
            statistics_at=self.stats_at, policy_version=self.policy.version,
            switch_connected=self.dp is not None, ready=self.ready, error=self.error,
            permission_seconds=self.policy.permission_seconds,
            packet_ins=self.packet_ins, overload_drops=self.overload, invalid_packets=self.invalid_packets,
            flow_entries=len(self.stats) if self.stats_at else None, tuple_episodes=len(self.records),
            logger=self.audit.health(), hosts=hosts, flows=rows[:256],
            terminal=self.trace.health(),
            operations=list(reversed(self.operations)), history=list(self.history),
            queue_depth=len(self.jobs), generation=self.epoch, switch_epoch=self.switch_epoch,
            escalation=dict(self.escalation.snapshot(), persistence_error=self.mode_error),
            snapshot_error=self.snapshot_writer.error))


def run_controller(policy, runtime, port=6653, log_port=9020, escalation=None, verbose=False):
    logging.basicConfig(level=logging.INFO, format='%(asctime)s %(name)s %(levelname)s %(message)s')
    os.environ['ALL_BLUE_POLICY'] = str(Path(policy).resolve())
    os.environ['ALL_BLUE_RUNTIME'] = str(Path(runtime).resolve())
    os.environ['ALL_BLUE_LOG_PORT'] = str(log_port)
    os.environ['ALL_BLUE_VERBOSE'] = '1' if verbose else '0'
    if escalation:
        os.environ['ALL_BLUE_ESCALATION'] = str(Path(escalation).resolve())
    else:
        os.environ.pop('ALL_BLUE_ESCALATION', None)
    from os_ken import cfg
    from os_ken.controller import controller as _controller  # registers OpenFlow options
    cfg.CONF(['--ofp-listen-host', '127.0.0.1', '--ofp-tcp-listen-port', str(port)])
    cfg.CONF.set_override('echo_request_interval', 2)
    cfg.CONF.set_override('maximum_unreplied_echo_requests', 3)
    app_manager.AppManager.run_apps(['all_blue.controller'])
