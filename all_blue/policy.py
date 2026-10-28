"""Pure policy logic. Bindings identify lab interfaces, never processes."""
from dataclasses import asdict, dataclass
import hashlib
from ipaddress import IPv4Address
import json
from pathlib import Path
import re


@dataclass(frozen=True)
class Host:
    name: str
    label: str
    port: int
    ip: str
    mac: str


@dataclass(frozen=True)
class Flow:
    in_port: int
    source_mac: str
    destination_mac: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int

    def key(self):
        return (self.in_port, self.source_ip, self.destination_ip,
                self.source_port, self.destination_port)

    def json(self):
        return asdict(self)


class Policy:
    def __init__(self, path):
        raw = json.loads(Path(path).read_text())
        self.version = hashlib.sha256(json.dumps(raw, sort_keys=True).encode()).hexdigest()[:12]
        self.datapath_id = raw['datapath_id']
        if type(self.datapath_id) is not int or not 0 < self.datapath_id < 2**64:
            raise ValueError('Invalid datapath ID')
        if not 1 <= len(raw['hosts']) <= 16:
            raise ValueError('The lab supports 1–16 explicitly bound hosts')
        self.hosts = {}
        for item in raw['hosts']:
            host = Host(**item)
            IPv4Address(host.ip)
            if not re.fullmatch(r'h[1-9][0-9]?', host.name):
                raise ValueError('Invalid host name')
            if not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', host.mac):
                raise ValueError('Invalid lowercase MAC address')
            if int(host.mac[:2], 16) & 1 or type(host.port) is not int or not 1 <= host.port <= 64:
                raise ValueError('Host needs a unicast MAC and a physical lab port')
            if not isinstance(host.label, str) or len(host.label) > 80:
                raise ValueError('Invalid host label')
            for old in self.hosts.values():
                if any(getattr(old, key) == getattr(host, key) for key in ('name', 'port', 'ip', 'mac')):
                    raise ValueError('Duplicate host binding')
            self.hosts[host.name] = host
        self.by_ip = {host.ip: host for host in self.hosts.values()}
        self.by_port = {host.port: host for host in self.hosts.values()}
        self.allowed = set()
        for rule in raw['allow']:
            source, destination, port = rule['source'], rule['destination'], rule['port']
            if source not in self.hosts or destination not in self.hosts or source == destination:
                raise ValueError('Invalid service host pair')
            if type(port) is not int or not 1 <= port <= 65535:
                raise ValueError('Invalid service port')
            self.allowed.add((source, destination, port))
        for key, low, high in [('permission_seconds', 5, 120), ('deny_seconds', 1, 30),
                               ('poll_seconds', 1, 10), ('max_tuples', 1, 128)]:
            value = raw[key]
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f'Invalid {key}; expected {low}–{high}')
            setattr(self, key, value)

    def identities(self, flow):
        source, destination = self.by_port.get(flow.in_port), self.by_ip.get(flow.destination_ip)
        if not source or not destination or source == destination:
            return None
        if (flow.source_ip != source.ip or flow.source_mac != source.mac
                or flow.destination_mac != destination.mac):
            return None
        if not all(type(port) is int and 1 <= port <= 65535
                   for port in (flow.source_port, flow.destination_port)):
            return None
        return source, destination

    def decide(self, flow, blocked):
        pair = self.identities(flow)
        if not pair:
            return 'DENY', 'Invalid ingress identity or destination binding'
        source, destination = pair
        if source.name in blocked or destination.name in blocked:
            return 'BLOCK', 'Host is administratively blocked'
        if (source.name, destination.name, flow.destination_port) in self.allowed:
            return 'ALLOW', 'Explicit TCP service policy'
        return 'DENY', 'No matching permission; default deny'

    def reverse(self, flow):
        source, destination = self.identities(flow)
        return Flow(destination.port, destination.mac, source.mac, destination.ip,
                    source.ip, flow.destination_port, flow.source_port)
