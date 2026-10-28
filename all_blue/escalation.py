"""Bounded local evidence for optional policy-violation escalation.

Counts distinct prohibited destination services, not packets, connections or an
attack probability. Only validated, initial TCP SYN attempts can contribute.
"""
from dataclasses import dataclass, replace
import hashlib
import json
from pathlib import Path
import time


@dataclass(frozen=True)
class EscalationConfig:
    mode: str = 'off'
    window_seconds: int = 30
    distinct_services: int = 5
    eligible_hosts: tuple = ()

    @classmethod
    def load(cls, path, policy):
        if not path:
            return cls()
        raw = json.loads(Path(path).read_text())
        if not isinstance(raw, dict) or set(raw) != {
                'mode', 'window_seconds', 'distinct_services', 'eligible_hosts'}:
            raise ValueError('Escalation config needs mode, window_seconds, distinct_services and eligible_hosts')
        if raw['mode'] not in ('off', 'observe', 'enforce'):
            raise ValueError('Escalation mode must be off, observe or enforce')
        for key, low, high in [('window_seconds', 5, 300), ('distinct_services', 2, 32)]:
            if type(raw[key]) is not int or not low <= raw[key] <= high:
                raise ValueError(f'Escalation {key} must be {low}–{high}')
        hosts = raw['eligible_hosts']
        if (not isinstance(hosts, list) or not all(isinstance(host, str) for host in hosts)
                or len(hosts) != len(set(hosts)) or not set(hosts) <= policy.hosts.keys()
                or (raw['mode'] != 'off' and not hosts)):
            raise ValueError('Escalation eligible_hosts must explicitly select configured hosts')
        return cls(raw['mode'], raw['window_seconds'], raw['distinct_services'], tuple(hosts))

    @property
    def version(self):
        value = (self.mode, self.window_seconds, self.distinct_services, sorted(self.eligible_hosts))
        return hashlib.sha256(json.dumps(value).encode()).hexdigest()[:12]

    def with_mode(self, mode):
        if mode not in ('off', 'observe', 'enforce'):
            raise ValueError('Escalation mode must be off, observe or enforce')
        if mode != 'off' and not self.eligible_hosts:
            raise ValueError('No eligible hosts configured; select eligible_hosts in the loaded configuration before enabling Observe or Enforce')
        return replace(self, mode=mode)


class Escalation:
    """Owned exclusively by the controller event queue; no I/O or background work."""
    def __init__(self, policy, config, clock=time.monotonic):
        self.policy, self.config, self.clock = policy, config, clock
        self.observations = {host: {} for host in config.eligible_hosts}
        self.latched = set()
        self.signals = 0

    def reset(self, host=None):
        names = self.observations if host is None else (host,)
        for name in names:
            if name in self.observations:
                self.observations[name].clear()
            self.latched.discard(name)

    def set_mode(self, mode):
        config = self.config.with_mode(mode)
        if config.mode != self.config.mode:
            self.reset()
        self.config = config

    def _prune(self, host, now):
        entries = self.observations[host]
        for service, seen in list(entries.items()):
            if now - seen >= self.config.window_seconds:
                del entries[service]
        if len(entries) < self.config.distinct_services:
            self.latched.discard(host)
        return entries

    def observe(self, flow, tcp_flags, blocked):
        if self.config.mode == 'off':
            return None
        pair = self.policy.identities(flow)
        # Exclude replies, teardown, invalid bindings, authorized traffic and host blocks.
        if (not pair or tcp_flags & 0x17 != 0x02
                or self.policy.decide(flow, blocked)[0] != 'DENY'):
            return None
        host = pair[0].name
        if host not in self.observations:
            return None
        now = self.clock()
        entries = self._prune(host, now)
        service = (flow.destination_ip, flow.destination_port)
        # Retain at most 32 services per explicitly eligible host. Once at capacity,
        # old entries may be evicted; that is conservative evidence undercounting.
        if service not in entries and len(entries) >= 32:
            del entries[min(entries, key=entries.get)]
        entries[service] = now
        if len(entries) < self.config.distinct_services or host in self.latched:
            return None
        self.latched.add(host)
        self.signals += 1
        return dict(host=host, mode=self.config.mode, config_version=self.config.version,
                    policy_version=self.policy.version,
                    window_seconds=self.config.window_seconds, threshold=self.config.distinct_services,
                    distinct_services=len(entries),
                    services=[dict(ip=ip, port=port) for ip, port in sorted(entries)],
                    observation='Identity-validated initial SYN to a policy-denied service',
                    reason=f'{len(entries)} distinct prohibited services observed within '
                           f'{self.config.window_seconds}s; policy threshold {self.config.distinct_services}')

    def snapshot(self):
        now = self.clock()
        hosts = {host: dict(distinct_services=len(self._prune(host, now)),
                            threshold_reached=host in self.latched)
                 for host in self.observations}
        return dict(mode=self.config.mode, config_version=self.config.version,
                    window_seconds=self.config.window_seconds, threshold=self.config.distinct_services,
                    signals=self.signals, hosts=hosts)
