"""OpenFlow 1.3 rule construction, isolated from controller event handling."""
from dataclasses import dataclass
from os_ken.ofproto import ofproto_v1_3 as ofp
from os_ken.ofproto import ofproto_v1_3_parser as parser

PREFIX = 0xAB10000000000000
PREFIX_MASK = 0xFFFF000000000000
FULL_MASK = 0xFFFFFFFFFFFFFFFF
GUARD = PREFIX | 1
BASE = PREFIX | 0x100
BLOCK_BASE = PREFIX | 0x1000
TUPLE_BASE = PREFIX | 0x100000


def diagnostic(row):
    """Describe an actual FlowMod/readback, without treating a request as installed."""
    actions = []
    for instruction in row.instructions or []:
        if isinstance(instruction, parser.OFPInstructionGotoTable):
            actions.append(dict(goto=instruction.table_id))
        elif isinstance(instruction, parser.OFPInstructionActions):
            for action in instruction.actions:
                if isinstance(action, parser.OFPActionOutput):
                    actions.append(dict(output='CONTROLLER' if action.port == ofp.OFPP_CONTROLLER else action.port))
                else:
                    actions.append(dict(type=type(action).__name__))
        else:
            actions.append(dict(type=type(instruction).__name__))
    role = 'forward_or_controller'
    if not actions:
        role = ('reconciliation_or_emergency_guard' if row.cookie == GUARD else
                'host_block' if row.priority == 50000 else
                'default_deny_ingress_identity_or_non_ipv4' if row.table_id == 0 and row.priority == 0 else
                'default_deny_non_tcp_or_fragment' if row.priority == 0 else 'policy_deny')
    return dict(cookie=f'0x{row.cookie:x}', table=row.table_id, priority=row.priority,
                match=dict(row.match.items()), actions=actions or ['DROP'], role=role,
                hard_timeout=row.hard_timeout, packets=getattr(row, 'packet_count', None),
                bytes=getattr(row, 'byte_count', None))


def match_fields(fields):
    # Numeric sorting puts Nicira ip_frag before its required eth_type.
    # OVS rejects that order as OFPBMC_BAD_PREREQ. Retain normalization,
    # then put extension fields after their OpenFlow prerequisites.
    normalized = list(parser.OFPMatch(**fields).items())
    ordinary = [(name, value) for name, value in normalized if name not in ('ip_frag', 'tcp_flags')]
    extensions = [(name, value) for name, value in normalized if name in ('ip_frag', 'tcp_flags')]
    return parser.OFPMatch(_ordered_fields=ordinary + extensions)


@dataclass(frozen=True)
class Rule:
    cookie: int
    table: int
    priority: int
    fields: dict
    output: int | None = None
    goto: int | None = None
    hard_timeout: int = 0

    def message(self, datapath):
        instructions = []
        if self.goto is not None:
            instructions.append(parser.OFPInstructionGotoTable(self.goto))
        if self.output is not None:
            instructions.append(parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS,
                [parser.OFPActionOutput(self.output, ofp.OFPCML_NO_BUFFER)]))
        return parser.OFPFlowMod(datapath, cookie=self.cookie, table_id=self.table,
                                 priority=self.priority, match=match_fields(self.fields),
                                 instructions=instructions, hard_timeout=self.hard_timeout,
                                 buffer_id=ofp.OFP_NO_BUFFER, flags=ofp.OFPFF_SEND_FLOW_REM)

    def matches(self, stat):
        if (stat.cookie, stat.table_id, stat.priority) != (self.cookie, self.table, self.priority):
            return False
        expected = dict(parser.OFPMatch(**self.fields).items())
        actual = dict(stat.match.items())
        if expected != actual or stat.hard_timeout != self.hard_timeout:
            return False
        expected_instructions = []
        if self.goto is not None:
            expected_instructions.append(('goto', self.goto))
        if self.output is not None:
            expected_instructions.append(('output', self.output))
        actual_instructions = []
        for instruction in stat.instructions:
            if isinstance(instruction, parser.OFPInstructionGotoTable):
                actual_instructions.append(('goto', instruction.table_id))
            elif isinstance(instruction, parser.OFPInstructionActions):
                if instruction.type != ofp.OFPIT_APPLY_ACTIONS:
                    return False
                for action in instruction.actions:
                    if not isinstance(action, parser.OFPActionOutput):
                        return False
                    actual_instructions.append(('output', action.port))
            else:
                return False
        return expected_instructions == actual_instructions


def delete_cookie(datapath, cookie, mask=FULL_MASK):
    return parser.OFPFlowMod(datapath, cookie=cookie, cookie_mask=mask,
                             table_id=ofp.OFPTT_ALL, command=ofp.OFPFC_DELETE,
                             out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                             match=parser.OFPMatch())


def guard():
    return Rule(GUARD, 0, 65535, {})


def base_rules(policy):
    result = [Rule(BASE, 0, 0, {}), Rule(BASE + 1, 1, 0, {})]
    for host in policy.hosts.values():
        result.append(Rule(BASE + 10 + host.port, 0, 100,
                           dict(in_port=host.port, eth_src=host.mac,
                                eth_type=0x0800, ipv4_src=host.ip), goto=1))
    # The explicit punt is restricted to unfragmented IPv4/TCP. Everything else drops.
    result.append(Rule(BASE + 2, 1, 1,
                       dict(eth_type=0x0800, ip_proto=6, ip_frag=(0, 1)),
                       output=ofp.OFPP_CONTROLLER))
    return result


def host_block(host):
    cookie = BLOCK_BASE + host.port
    return [Rule(cookie, 0, 50000, dict(in_port=host.port)),
            Rule(cookie, 0, 50000, dict(eth_dst=host.mac))]


def tuple_rules(policy, flow, action, cookie):
    def fields(value):
        return dict(in_port=value.in_port, eth_type=0x0800, eth_src=value.source_mac,
                    eth_dst=value.destination_mac, ipv4_src=value.source_ip,
                    ipv4_dst=value.destination_ip, ip_proto=6, tcp_src=value.source_port,
                    tcp_dst=value.destination_port, ip_frag=(0, 1))
    seconds = policy.permission_seconds if action == 'ALLOW' else policy.deny_seconds
    forward = Rule(cookie, 1, 2000 if action == 'ALLOW' else 1000, fields(flow),
                   output=policy.by_ip[flow.destination_ip].port if action == 'ALLOW' else None,
                   hard_timeout=seconds)
    if action != 'ALLOW':
        return [forward]
    reverse = fields(policy.reverse(flow))
    # A server source-port alone never grants access; bare reverse SYN is excluded.
    # This is tuple authorization with ACK gating, not a complete TCP state tracker.
    reverse['tcp_flags'] = (0x10, 0x10)
    return [forward, Rule(cookie, 1, 2000, reverse, output=flow.in_port, hard_timeout=seconds)]
