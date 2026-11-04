import { $, available, fresh, hostState, hostRole, hostArt, node, text, badge, empty, details, character,
  related, flowKey, endpoints, StableDOM, number, clock, json, escalationSummary, commandText, MAX } from './ob-model.js';

const stamp = value => Number.isFinite(value) ? new Date(value * 1000).toLocaleString() : 'Unavailable';
const ruleNote = 'Rules enforce every matching packet; monitoring samples counters and logging records security events.';
function fields(values) {
  const list = node('dl');
  for (const [key, value] of Object.entries(values)) list.append(node('dt', key), node('dd', value == null ? 'Unavailable' : typeof value === 'object' ? json(value) : value));
  return list;
}
function recordButton(record, source, attribute, identity) {
  const button = node('button', undefined, 'record-row'); button.type = 'button'; button.dataset[attribute] = identity;
  const heading = node('span', undefined, 'row-heading'); heading.append(badge(record.action), badge(record.status), node('span', `${record.host || ''}${record.mode ? ` → ${record.mode}` : ''}`));
  button.append(heading, node('p', record.reason || record.trigger_reason || ''), node('small', `${source} · ${stamp(record.timestamp)} · ${record.id || 'No ID'}`));
  return button;
}

export class ObservatoryView {
  constructor(commands) { this.dom = new StableDOM(); this.commands = commands; this.selected = null; this.flowID = null; this.operationID = null; this.eventID = null; this.state = null; this.workspace = null; this.offline = true; this.demoBusy = false; }
  selectedFlow() { return this.state?.controller?.flows?.find(row => flowKey(row) === this.flowID); }
  render(state, workspace, offline, resetNote) {
    this.state = state; this.workspace = workspace; this.offline = offline;
    this.renderHealth(); this.renderInspector(); this.renderTraffic(resetNote); this.renderHosts();
    this.renderOperations(); this.renderLogs(); this.renderDiagnostics();
  }
  renderHealth() {
    const c = this.state?.controller, logger = this.state?.logger_server, live = available(this.state, this.offline);
    const freshController = !this.offline && fresh(c?.collected_at, 6), freshLogger = !this.offline && fresh(logger?.collected_at, 5);
    let label = this.offline ? 'Dashboard connection lost' : !c ? 'Waiting for the controller' : !freshController ? 'Controller snapshot stale'
      : !c.switch_connected ? 'Switch disconnected' : !c.ready ? 'Switch reconciliation pending' : !live ? 'Switch statistics stale' : 'Observing the lab';
    text('connection', label);
    text('connection-detail', live ? 'Actual switch observations and retained local records. Idle traffic stays quiet.' : 'Displayed values are retained observations. Current switch enforcement is not established.');
    text('runtime-label', `Runtime: ${this.state?.runtime || 'unavailable'}`);
    text('sample-time', `Switch sample ${stamp(c?.statistics_at)}${live ? '' : ' · historical / unavailable'}`);
    const health = [
      ['Controller', freshController ? c.ready ? 'Ready' : 'Reconciling' : 'Unavailable / stale', c?.error || `Writer queue ${number(c?.queue_depth)} · overload drops ${number(c?.overload_drops)}`],
      ['Switch', live ? 'Observed' : freshController && c?.switch_connected ? 'Connected · unverified' : 'Disconnected / unknown', `Epoch ${c?.switch_epoch ?? '—'} · ${number(c?.flow_entries)} observed entries`],
      ['TCP logger', freshLogger ? logger.error ? 'Error' : 'Snapshot current' : 'Unavailable / stale', `${number(c?.logger?.backlog)} pending · ${number(c?.logger?.retries)} retries · ${number(c?.logger?.dropped)} audit drops${logger?.error ? ` · ${logger.error}` : ''}`],
      ['Dashboard', this.offline ? 'Offline' : 'Connected', c?.snapshot_error || 'Local presentation; controller and logger run independently']
    ];
    this.dom.replace('health-grid', health, () => health.map(([name, status, detail]) => { const el = node('article', undefined, 'health-card'); el.append(node('strong', name), node('p', status), node('p', detail, 'subtle')); return el; }));
    this.dom.replace('identity-details', [c?.run_id, c?.switch_epoch, c?.started_at, c?.collected_at, c?.statistics_at, this.state?.served_at], () => [fields({
      'Controller run': c?.run_id, 'Switch epoch': c?.switch_epoch, 'Controller started': stamp(c?.started_at),
      'Controller sample': stamp(c?.collected_at), 'Switch sample': stamp(c?.statistics_at), 'Dashboard served': stamp(this.state?.served_at)
    })]);
  }
  renderInspector() {
    const c = this.state?.controller, host = c?.hosts?.find(h => h.name === this.selected), current = available(this.state, this.offline);
    if (this.flowID) {
      const row = this.selectedFlow(), pair = endpoints(row);
      text('inspector-heading', row ? `${row.action} · ${pair.source} → ${pair.destination}` : 'Selected flow expired or unavailable');
      this.dom.replace('inspector-content', [this.flowID, row, current], () => row ? [badge(row.action),
        node('p', current ? 'Current rule observation. Select a related controller action or audit event below for its evidence.' : 'Historical rule observation; current enforcement is unverified.'),
        fields({'Source port': pair.sourcePort, 'Destination port': pair.destinationPort, Direction: row.direction,
          Packets: row.packets, Bytes: row.bytes, Priority: row.priority, 'Hard timeout': `${row.hard_timeout}s`, Cookie: row.cookie}),
        details('Exact observed flow', row), node('p', ruleNote, 'subtle')]
        : [empty('This rule is no longer in the latest sample. It may have expired or been removed. Choose another flow or Show all components.')]);
      return;
    }
    const selection = this.selected || 'switch';
    const logger = this.state?.logger_server;
    const data = host ? [host, hostRole(host, c)] : selection === 'controller' ? [c?.ready, c?.queue_depth, c?.invalid_packets, c?.error, c?.terminal]
      : selection === 'logger' ? [c?.logger?.backlog, c?.logger?.delivered, c?.logger?.retries, c?.logger?.dropped, c?.logger?.error, logger?.error, logger?.terminal]
      : [c?.policy?.datapath_id, c?.switch_connected];
    text('inspector-heading', host ? `${host.name} · ${host.label}` : {switch: 'The reef checkpoint', controller: 'The policy controller', logger: 'The TCP logbook'}[selection] || 'Select a component');
    this.dom.replace('inspector-content', [selection, data, current], () => {
      if (host) return [character(hostArt(host, c, c.hosts.indexOf(host))), node('p', hostState(host, current)), fields({
        'Configured role': hostRole(host, c), Label: host.label, 'IPv4 address': host.ip, 'MAC address': host.mac, 'Switch port': host.port,
        'Saved block intent': host.block_requested ? 'Requested' : 'Not requested', 'Observed block rules': current ? host.block_confirmed === true ? 'Confirmed' : host.block_confirmed === false ? 'Absent in readback' : 'Unverified' : 'Unverified'
      }), node('p', 'A binding identifies a lab interface. A policy violation does not identify a malicious user.', 'subtle'), node('a', 'Manage this host ↓')].map(el => { if (el.tagName === 'A') el.href = '#management'; return el; });
      if (selection === 'controller') return [character('controller'), node('p', 'Chooses ALLOW / DENY policy and queues rule changes. One writer serializes switch mutations.'),
        fields({'Ready': current ? c?.ready : 'Unverified', 'Writer queue': c?.queue_depth, 'Invalid controller-visible frames': c?.invalid_packets, 'Last reported error': c?.error || 'None reported'}),
        details('Terminal diagnostics health', c?.terminal || {available: false})];
      if (selection === 'logger') return [character('logger'), node('p', 'Receives length-framed TCP security events, commits to SQLite, then transmits an acknowledgement. Client receipt is a separate observation.'),
        fields({'Backlog': c?.logger?.backlog, 'Delivered / ACK received': c?.logger?.delivered, Retries: c?.logger?.retries, 'Dropped audit records': c?.logger?.dropped,
          'Logger error': this.state?.logger_server?.error || c?.logger?.error || 'None reported'}), details('Logger diagnostics health', this.state?.logger_server?.terminal || {available: false})];
      return [character('gateway'), node('p', 'The lab switch enforces installed OpenFlow rules. Controller communication is separate from application forwarding.'),
        fields({'Switch': 'ab-s1', 'Datapath ID': c?.policy?.datapath_id, 'Connected': current ? c?.switch_connected : 'Unverified', 'Current readback': current ? 'Available' : 'Unverified',
          'Block priority': '50000 · table 0', 'Default behaviour': 'Drop unless explicitly permitted'}), node('p', ruleNote, 'subtle')];
    });
  }
  renderTraffic(resetNote) {
    const c = this.state?.controller, flows = (c?.flows || []).slice(0, MAX.flows), current = available(this.state, this.offline);
    const sampled = Boolean(c?.statistics_at);
    const metrics = [['Observed rule packets', sampled ? flows.reduce((n, r) => n + (r.packets || 0), 0) : null], ['Observed rule bytes', sampled ? flows.reduce((n, r) => n + (r.bytes || 0), 0) : null], ['Flow entries', c?.flow_entries], ['Observed tuple episodes', c?.tuple_episodes]];
    this.dom.replace('metrics', [metrics, current], () => metrics.map(([label, value]) => { const el = node('div', undefined, 'metric'); el.append(node('span', label), node('strong', number(value)), node('span', current ? 'Current sample' : 'Retained / unavailable')); return el; }));
    const history = (c?.history || []).slice(-MAX.samples);
    text('history-label', `${history.length} samples · ${resetNote || 'Within this controller run / switch epoch'}`);
    this.dom.replace('traffic-history', [c?.run_id, c?.switch_epoch, history], () => {
      if (history.length < 2) return [];
      const points = history.map((row, index) => `${index / (history.length - 1) * 900},${90 - (row.packets || 0) / Math.max(1, ...history.map(r => r.packets || 0)) * 80}`);
      const line = document.createElementNS('http://www.w3.org/2000/svg', 'polyline'); line.setAttribute('points', points.join(' ')); return [line];
    });
    const shown = flows.filter(row => related(row, this.selected, c));
    text('selection-note', this.flowID ? 'A flow is selected in the component inspector.' : this.selected && !['switch', 'controller', 'logger'].includes(this.selected) ? `Traffic and actions filtered to ${this.selected}. Use Show all components to clear.` : 'Select a tuple to inspect it and highlight its route.');
    this.dom.replace('flow-rows', [shown, current, this.flowID], () => shown.length ? shown.map(row => {
      const match = row.match || {}, flow = row.flow || {}, tr = node('tr');
      const action = node('td'); action.append(badge(row.action));
      const tuple = node('td'), button = node('button', `${match.ipv4_src || flow.source_ip}:${match.tcp_src ?? flow.source_port} → ${match.ipv4_dst || flow.destination_ip}:${match.tcp_dst ?? flow.destination_port}`, 'flow-select');
      button.dataset.flow = flowKey(row); button.setAttribute('aria-pressed', String(this.flowID === flowKey(row))); tuple.append(button);
      tuple.append(node('span', `Priority ${row.priority ?? '—'} · ${current ? 'observed' : 'retained'}`, 'subtle'));
      tr.append(action, tuple, node('td', row.direction || 'Unknown'), node('td', number(row.packets)), node('td', number(row.bytes)), node('td', `${row.hard_timeout ?? '—'}s hard timeout · no exact countdown`)); return tr;
    }) : [(() => { const tr = node('tr'), td = node('td', c ? 'No matching tuple entries in this sample. Absence of an entry does not prove absence of traffic.' : 'No controller observations available.'); td.colSpan = 6; tr.append(td); return tr; })()]);
    this.dom.replace('policy-explanation', c?.policy, () => {
      const policy = c?.policy;
      if (!policy) return [empty('Loaded policy details unavailable. This running controller may predate the observatory export; inspect its saved configuration separately.')];
      const list = node('ul');
      for (const rule of policy.allow || []) list.append(node('li', `${rule.source} → ${rule.destination} TCP ${rule.port}`));
      return [node('h3', 'Loaded policy · explanatory view'), node('p', `Policy version ${c.policy_version}. These explanations describe configured semantics; adjacent records are actual switch observations.`), list,
        fields({'Default deny': 'Table 0 binds ingress IP/MAC/port. Table 1 drops non-TCP/fragmented traffic and evaluates permitted tuples.',
          'Priority ordering': 'Emergency/reconciliation guard 65535; host blocks 50000; ingress binding 100. Table 1 ALLOW 2000; DENY 1000; controller punt 1; default drop 0.',
          'Exact forward & reverse': 'Exact addresses, MACs, ingress ports and TCP ports. Reverse permission requires ACK; a bare reverse SYN is excluded. This is not full TCP connection tracking.',
          'Permission expiry': `${policy.permission_seconds}s hard timeout`, 'Deny-rule expiry': `${policy.deny_seconds}s hard timeout`,
          'Controller loss': `Existing permissions can remain until their finite hard timeout (up to ${policy.permission_seconds}s from installation). New permissions cannot be authorized.`,
          'Release cleanup': 'Remove old tuple permissions and verify their absence before removing block rules. Release returns to normal policy.'})];
    });
    const rules = (c?.observed_rules || []).slice(0, 512);
    this.dom.replace('rule-list', rules, () => rules.length ? rules.map(rule => {
      const el = node('div', undefined, 'rule'); el.append(node('strong', `Table ${rule.table} · priority ${rule.priority} · ${rule.role}`),
        node('p', `${number(rule.packets)} packets · ${number(rule.bytes)} bytes · timeout ${rule.hard_timeout}s · observed age ${rule.duration_seconds ?? 'unavailable'}s`), details('Match, actions and cookie', rule, JSON.stringify([rule.cookie, rule.table, rule.priority, rule.match]))); return el;
    }) : [empty('Detailed switch readback is unavailable for this runtime.')]);
  }
  renderHosts() {
    const c = this.state?.controller, current = available(this.state, this.offline), config = c?.escalation;
    text('escalation-summary', escalationSummary(config) + ` Eligible hosts: ${Object.keys(config?.hosts || {}).join(', ') || 'none configured'}. Mode transitions clear partial evidence and latches; existing blocks stay until released.`);
    this.dom.replace('host-cards', [c?.hosts, config?.hosts, this.selected, current], () => (c?.hosts || []).slice(0, 16).map((host, index) => {
      const card = node('article', undefined, `host-card${host.name === this.selected ? ' selected' : ''}`); card.dataset.host = host.name;
      const top = node('div', undefined, 'top'), title = node('div'); title.append(node('h3', host.name), node('p', host.label)); top.append(character(hostArt(host, c, index)), title);
      const controls = node('div', undefined, 'button-row');
      for (const [action, label] of [['block', 'Block host'], ['release', 'Release to normal policy']]) { const button = node('button', label); button.dataset.action = action; controls.append(button); }
      const evidence = config?.hosts?.[host.name];
      card.append(top, node('p', `${host.ip} · ${host.mac} · switch port ${host.port}`, 'address'), node('p', hostState(host, current)),
        node('p', evidence ? `${evidence.distinct_services} distinct prohibited services · threshold ${evidence.threshold_reached ? 'reached' : 'not reached'}` : 'Not selected for automatic escalation.'), controls, node('p', '', 'command-result')); return card;
    }));
    this.updateControls();
  }
  updateControls() {
    const current = available(this.state, this.offline) && this.state?.lab_controls?.available !== false, c = this.state?.controller, config = c?.escalation;
    for (const card of $('host-cards').children) {
      const host = card.dataset.host;
      for (const button of card.querySelectorAll('button')) button.disabled = this.demoBusy || !current || this.commands.busy(host, this.state);
      const message = commandText(this.commands.result(host, this.state)) || (current ? 'Release returns this host to normal policy.' : 'Controls unavailable until controller and switch observations are current.');
      if (card.querySelector('.command-result').textContent !== message) card.querySelector('.command-result').textContent = message;
    }
    const modeResult = this.commands.result('@mode', this.state), busy = this.commands.busy('@mode', this.state);
    $('mode').disabled = this.demoBusy || !current || !config || busy;
    for (const option of $('mode').options) if (['observe', 'enforce'].includes(option.value)) option.disabled = !Object.keys(config?.hosts || {}).length;
    $('mode').value = busy && modeResult?.mode ? modeResult.mode : config?.mode || '';
    text('mode-result', [commandText(modeResult), config?.persistence_error,
      this.workspace?.saved_mode?.error || (this.workspace?.saved_mode?.mode ? `Saved runtime override: ${this.workspace.saved_mode.mode}.` : this.workspace?.saved_mode?.note),
      !Object.keys(config?.hosts || {}).length ? 'Observe / Enforce require explicitly configured eligible hosts.' : '',
      'Mode confirmation means saved and applied, not a switch-rule mutation.'].filter(Boolean).join(' '));
  }
  renderOperations() {
    const operations = (this.state?.controller?.operations || []).filter(op => related(op, this.selected, this.state?.controller)).slice(0, MAX.operations);
    this.dom.replace('operation-list', [operations, this.operationID], () => operations.length ? operations.map(op => { const button = recordButton(op, op.origin === 'automatic' ? 'Automatic controller action' : 'Controller action', 'operation', op.id); button.classList.toggle('selected', op.id === this.operationID); return button; }) : [empty('No related controller actions in the bounded history.')]);
    const operation = (this.state?.controller?.operations || []).find(op => op.id === this.operationID);
    text('operation-scope', operation ? `${operation.action} ${operation.status} · ${operation.id}` : 'Choose a controller action. Only recorded writer steps appear here.');
    text('operation-detail', operation ? json(operation) : 'No action selected.');
    this.dom.replace('journey', operation, () => {
      if (!operation) return [];
      if (!operation.journey?.length) return [node('li', 'Intermediate writer instrumentation is unavailable for this retained action. Final status remains as recorded.')];
      return operation.journey.slice(-24).map(step => { const item = node('li', step.stage.replaceAll('_', ' ')); item.append(node('span', `${stamp(step.timestamp)}${step.reason ? ` · ${step.reason}` : ''}${step.xid ? ` · xid ${step.xid}` : ''}`)); return item; });
    });
  }
  records() {
    const history = this.workspace?.audit_error ? this.state?.events : this.workspace?.audit_history ?? this.state?.events;
    return [...(history || []).slice(0, MAX.events).map(event => ({...event, source: 'SQLite security event', historical: event.run_id !== this.state?.controller?.run_id, key: `audit:${event.id}`})),
      ...(this.state?.controller?.operations || []).slice(0, MAX.operations).map(op => ({...op, source: 'Controller operation', key: `operation:${op.id}`}))];
  }
  renderLogs() {
    const c = this.state?.controller;
    this.dom.replace('log-host', (c?.hosts || []).map(h => h.name), () => [new Option('All hosts', ''), ...(c?.hosts || []).map(h => new Option(h.name, h.name))]);
    const query = $('log-search').value.toLowerCase(), host = $('log-host').value, action = $('log-action').value, status = $('log-status').value;
    const rows = this.records().filter(r => (!host || related(r, host, c)) && (!action || r.action === action)
      && (!status || r.status === status) && (!query || JSON.stringify(r).toLowerCase().includes(query))).sort((a,b) => b.timestamp - a.timestamp);
    text('log-count', `${rows.length} matching retained records · at most 100 persisted events and 128 controller operations. Previous controller runs are labelled; other runtimes have an events.json export below.${this.workspace?.audit_error ? ` Audit history: ${this.workspace.audit_error}` : ''}`);
    this.dom.replace('event-list', [rows, this.eventID], () => rows.length ? rows.map(row => { const button = recordButton(row, row.source + (row.historical ? ' · previous controller run' : ''), 'event', row.key); button.classList.toggle('selected', row.key === this.eventID); return button; }) : [empty('No records match these filters.')]);
    const selected = this.records().find(row => row.key === this.eventID);
    text('event-scope', selected ? `${selected.source} · ${selected.id}` : 'Select a record. Unavailable evidence never becomes an invented intermediate confirmation.');
    text('event-detail', selected ? json(selected) : 'No record selected.');
    const event = selected?.source === 'SQLite security event' ? selected : this.state?.events?.find(e => e.operation_id === selected?.id);
    const records = this.workspace?.diagnostics?.records || [];
    const queued = event && records.find(row => row.record.event_id === event.id && row.record.delivery === 'queued');
    const ackSent = event && this.state?.logger_server?.deliveries?.find(row => row.event_id === event.id && row.stage === 'ack_sent');
    const ackReceived = event && c?.logger?.acknowledgements?.find(row => row.event_id === event.id);
    const path = selected ? [
      ['Controller queue', queued ? `Observed in ${queued.file}` : 'Not retained in available diagnostics'],
      ['SQLite persistence', event ? `Persisted event ${event.id} · ${stamp(event.timestamp)} (event creation time)` : 'No correlated persisted event in this bounded view'],
      ['Server acknowledgement transmission', ackSent ? `sendall returned at ${stamp(ackSent.timestamp)}` : 'No correlated transmission observation retained'],
      ['Controller acknowledgement receipt', ackReceived ? `Matched event ID received at ${stamp(ackReceived.timestamp)}` : 'No correlated receipt observation retained']
    ] : [];
    this.dom.replace('delivery-path', path, () => path.map(([label, detail]) => { const el = node('li', label); el.append(node('span', detail)); return el; }));
  }
  renderDiagnostics() {
    const diagnostic = this.workspace?.diagnostics;
    const c = this.state?.controller, logger = this.state?.logger_server;
    text('diagnostic-health', `${diagnostic?.available ? 'Actual retained process output' : 'Diagnostic files unavailable'} · controller diagnostic drops ${number(c?.terminal?.dropped)} · logger diagnostic drops ${number(logger?.terminal?.dropped)}. ${diagnostic?.files?.some(f => f.truncated) ? 'Older output truncated to a bounded tail.' : ''} ${diagnostic?.errors?.join(' ') || ''}`);
    const query = $('diagnostic-filter').value.toLowerCase();
    text('diagnostics', (diagnostic?.records || []).filter(row => !query || JSON.stringify(row).toLowerCase().includes(query)).map(row => `${row.file} | ${JSON.stringify(row.record)}`).join('\n') || 'No diagnostic lines available for this selection.');
  }
}
