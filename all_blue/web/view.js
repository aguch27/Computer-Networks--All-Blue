import { clock, escalationSummary, health, limits, number } from './state.js';

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}

function badge(text, kind = 'neutral') {
  return element('span', text, `badge ${kind}`);
}

function emptyRow(columns, message) {
  const row = element('tr');
  const cell = element('td', message, 'empty');
  cell.colSpan = columns;
  row.append(cell);
  return row;
}

function tableRow(cells) {
  const row = element('tr');
  for (const value of cells) {
    const cell = element('td');
    cell.append(value instanceof Node ? value : document.createTextNode(value));
    row.append(cell);
  }
  return row;
}

function commandKey(command) {
  return command.action.toLowerCase() === 'mode' ? '@mode' : command.host;
}

function commandText(result) {
  if (!result) return '';
  const status = result.status === 'requested' ? 'pending' : result.status;
  return `${result.action.toUpperCase()}${result.mode ? ` ${result.mode}` : ''} ${status} · ${result.reason}`;
}

export class DashboardView {
  constructor() {
    this.nodes = new Map([...document.querySelectorAll('[id]')].map(node => [node.id, node]));
    this.previous = new Map();
    this.state = null;
    this.failed = false;
    this.requests = new Map();
  }

  text(id, value) {
    const node = this.nodes.get(id);
    if (node.textContent !== value) node.textContent = value;
  }

  // Store one bounded signature per section, so identical polls keep existing DOM nodes.
  replace(id, data, build) {
    const signature = JSON.stringify(data);
    if (this.previous.get(id) === signature) return;
    this.nodes.get(id).replaceChildren(...build());
    this.previous.set(id, signature);
  }

  updateHealth() {
    const controller = this.state?.controller;
    const status = health(this.state, this.failed);
    this.text('connection', status.label);
    this.nodes.get('connection').className = `badge ${status.kind}`;
    this.text('notice', status.message);
    this.nodes.get('notice').className = `notice ${status.kind}`;
    this.text('health-controller', !controller ? 'Waiting for controller' : !status.fresh
      ? 'Stale · state unknown' : controller.ready ? 'Connected · rules reconciled' : controller.error || 'Awaiting switch');
    this.text('health-telemetry', status.telemetry ? `Collected ${clock(controller.statistics_at)}` : 'No fresh switch sample');
    const logger = this.state?.logger_server;
    this.text('health-logger', status.logger
      ? logger.error || controller?.logger?.error || `${number(logger.received)} frames received · server online`
      : 'Logger offline or stale');
    this.text('sample-time', clock(controller?.statistics_at));
    this.updateControls();
  }

  controlsAvailable() {
    const status = health(this.state, this.failed);
    return status.fresh && status.telemetry && this.state.controller.ready
      && this.state.controller.switch_connected;
  }

  commandResult(host) {
    const controller = this.state?.controller;
    const local = this.requests.get(host);
    if (!local) return controller?.operations?.find(operation => commandKey(operation) === host);
    const operation = controller?.operations?.find(operation => operation.id === local.id)
      || this.state?.events?.find(event => event.operation_id === local.id);
    if (operation) Object.assign(local, { status: operation.status, reason: operation.reason });
    if (controller && controller.run_id !== local.run_id && ['requested', 'pending', 'unknown'].includes(local.status)) {
      local.status = 'unknown';
      local.reason = 'Controller restarted; previous result unavailable. Check the audit history.';
      local.sending = false;
    }
    return local;
  }

  commandBusy(host) {
    const result = this.commandResult(host);
    return result?.sending || ['requested', 'pending'].includes(result?.status)
      || this.state?.controller?.operations?.some(operation => commandKey(operation) === host
        && ['requested', 'pending'].includes(operation.status));
  }

  beginCommand(details) {
    const host = commandKey(details);
    if (!this.controlsAvailable() || this.commandBusy(host)) return null;
    const previous = this.requests.get(host);
    const run = this.state.controller.run_id;
    const retry = previous?.status === 'unknown' && previous.run_id === run
      && previous.action === details.action && previous.mode === details.mode;
    const command = { ...details, id: retry ? previous.id : crypto.randomUUID(), run_id: run };
    this.requests.set(host, { ...command, status: 'pending', sending: true,
      reason: 'Sending request; controller confirmation is pending.' });
    this.updateControls();
    return command;
  }

  commandReply(command, result) {
    const local = this.requests.get(commandKey(command));
    if (local?.id !== command.id) return;
    Object.assign(local, { sending: false, status: result.status,
      reason: result.error || 'Waiting for controller confirmation.' });
    this.updateControls();
  }

  updateControls() {
    const available = this.controlsAvailable();
    for (const card of this.nodes.get('host-grid').querySelectorAll('[data-host]')) {
      const host = card.dataset.host;
      const result = this.commandResult(host);
      for (const button of card.querySelectorAll('button')) button.disabled = !available || Boolean(this.commandBusy(host));
      const message = card.querySelector('.command-result');
      const text = result ? commandText(result)
        : available ? 'Block traffic or release this host to normal policy.' : 'Controls unavailable until controller and switch state are current.';
      if (message.textContent !== text) message.textContent = text;
    }
    const config = this.state?.controller?.escalation;
    const mode = this.nodes.get('escalation-mode');
    const result = this.commandResult('@mode');
    const busy = Boolean(this.commandBusy('@mode'));
    mode.disabled = !available || !config || busy;
    mode.value = busy && result?.mode ? result.mode : config?.mode || '';
    const message = commandText(result) || (!available ? 'Controls unavailable until controller and switch state are current.'
      : !Object.keys(config?.hosts || {}).length ? 'No eligible hosts configured. Observe and Enforce require an explicit selection in configuration.'
      : 'Mode changes start fresh observations and retain existing host blocks.');
    this.text('mode-result', config?.persistence_error && !message.includes(config.persistence_error)
      ? `${message} ${config.persistence_error}` : message);
  }

  offline() {
    this.failed = true;
    this.updateHealth();
  }

  render(state) {
    this.state = state;
    this.failed = false;
    this.updateHealth();
    const controller = state.controller;
    if (controller) {
      const hosts = new Set(controller.hosts.slice(0, limits.hosts).map(host => host.name));
      for (const host of this.requests.keys()) if (host !== '@mode' && !hosts.has(host)) this.requests.delete(host);
    }
    // A new run can reuse the same numbers; never keep its old section identity.
    const identity = controller ? `${controller.run_id}/${controller.switch_epoch}` : null;
    if (identity !== this.identity) this.previous.clear();
    this.identity = identity;
    this.renderMetrics(controller);
    this.renderFlows(controller);
    this.renderHosts(controller);
    this.updateControls();
    this.renderOperations(controller);
    this.renderChart(controller);
    this.renderEvents();
  }

  renderMetrics(controller) {
    const sampled = Boolean(controller?.statistics_at);
    const hosts = controller?.hosts || [];
    const blocks = sampled && hosts.every(host => host.block_confirmed !== null)
      ? hosts.filter(host => host.block_confirmed).length : null;
    this.text('metric-rules', number(controller?.flow_entries));
    this.text('metric-tuples', number(sampled ? controller.tuple_episodes : null));
    this.text('metric-blocks', number(blocks));
    this.text('metric-backlog', number(controller?.logger?.backlog));
    this.text('audit-detail', controller
      ? `${number(controller.logger.dropped)} dropped · ${number(controller.logger.delivered)} acknowledged`
      : 'Waiting for the TCP logger');
    this.text('policy-version', controller?.policy_version || '—');
    this.text('run-id', controller
      ? `Run ${controller.run_id} · switch epoch ${controller.switch_epoch ?? '—'}`
      : 'No controller run available');
    this.text('escalation-status', controller
      ? escalationSummary(controller.escalation) : 'Policy escalation status unavailable.');
  }

  renderFlows(controller) {
    const flows = (controller?.flows || []).slice(0, limits.flows);
    const sampled = Boolean(controller?.statistics_at);
    this.text('flow-count', sampled ? `${flows.length} tuple rules` : 'Awaiting data');
    this.replace('flows', [sampled, flows], () => flows.length ? flows.map(flow => {
      const match = flow.match;
      return tableRow([
        `${match.ipv4_src} → ${match.ipv4_dst}`, `${match.tcp_src} → ${match.tcp_dst}`,
        badge(flow.action, flow.action === 'ALLOW' ? 'good' : 'bad'), flow.direction,
        number(flow.packets), number(flow.bytes),
      ]);
    }) : [emptyRow(6, sampled
      ? 'No current tuple rules. Send traffic in the lab to see a decision.'
      : 'Waiting for the first switch counter sample.')]);
  }

  renderHosts(controller) {
    const hosts = (controller?.hosts || []).slice(0, limits.hosts);
    const config = controller?.escalation;
    this.replace('host-grid', [hosts, config], () => hosts.length ? hosts.map(host => {
      const card = element('article', undefined, 'host-card');
      card.dataset.host = host.name;
      const heading = element('div', undefined, 'host-heading');
      const verified = host.block_confirmed;
      const label = verified === null ? 'State unverified' : verified ? 'Block confirmed'
        : host.block_requested ? 'Block pending' : 'Policy governed';
      heading.append(element('span', host.name, 'host-name'),
        badge(label, verified ? 'bad' : host.block_requested ? 'warn' : 'neutral'));
      const details = element('dl', undefined, 'host-details');
      for (const [name, value] of [['Address', host.ip], ['Port', String(host.port)], ['MAC', host.mac]]) {
        const pair = element('div');
        pair.append(element('dt', name), element('dd', value));
        details.append(pair);
      }
      card.append(heading, element('h3', host.label), details);
      if (config && config.mode !== 'off') {
        const evidence = config.hosts?.[host.name];
        const message = evidence
          ? `${evidence.distinct_services >= 32 ? '≥' : ''}${number(evidence.distinct_services)} recent prohibited services observed`
          : 'Excluded from automatic escalation';
        card.append(element('p', message, 'escalation-detail'));
      }
      const controls = element('div', undefined, 'host-controls');
      for (const action of ['block', 'release']) {
        const button = element('button', action === 'block' ? 'Block' : 'Release', 'control-button');
        button.type = 'button';
        button.dataset.action = action;
        button.setAttribute('aria-label', `${button.textContent} ${host.name}`);
        button.disabled = true;
        controls.append(button);
      }
      const result = element('p', '', 'command-result');
      result.setAttribute('role', 'status');
      card.append(controls, result);
      return card;
    }) : [element('p', 'Host bindings will appear when the controller starts.', 'empty')]);
  }

  renderOperations(controller) {
    const operations = (controller?.operations || []).slice(0, limits.operations);
    this.replace('operations', operations, () => operations.length ? operations.map(operation => {
      const flow = operation.flow;
      const scope = operation.mode ? `Escalation → ${operation.mode}` : operation.host
        || (flow ? `${flow.source_ip} → ${flow.destination_ip}:${flow.destination_port}` : 'Lab switch');
      const automatic = operation.origin === 'automatic';
      const kind = operation.status === 'confirmed' ? 'good' : operation.status === 'failed' ? 'bad' : 'neutral';
      return tableRow([
        clock(operation.timestamp), `${operation.action}${automatic ? ' · automatic' : ''}`, scope,
        badge(operation.status, kind), automatic ? `${operation.trigger_reason}. ${operation.reason}` : operation.reason,
      ]);
    }) : [emptyRow(5, 'No actions recorded for this run.')]);
  }

  renderEvents() {
    const query = this.nodes.get('event-filter').value.trim().toLowerCase();
    const events = (this.state?.events || []).slice(0, limits.events).filter(event =>
      `${event.action} ${event.status} ${event.reason} ${event.origin || ''} ${event.trigger_reason || ''}`.toLowerCase().includes(query));
    this.replace('event-list', [query, events], () => events.length ? events.map(event => {
      const row = element('div', undefined, 'event');
      const automatic = event.origin === 'automatic';
      const detail = element('div', automatic && event.trigger_reason
        ? `${event.trigger_reason}. ${event.reason}` : event.reason);
      detail.append(element('small', `${event.status}${automatic ? ' · automatic' : ''} · ${event.id}`));
      row.append(element('time', clock(event.timestamp)), element('strong', event.action), detail);
      return row;
    }) : [element('p', query ? 'No events match this filter.' : 'No persisted events available for this run.', 'empty')]);
  }

  renderChart(controller) {
    const points = (controller?.history || []).slice(-limits.samples)
      .filter(point => Number.isFinite(point.bytes) && Number.isFinite(point.timestamp));
    this.text('chart-total', points.length ? number(points.at(-1).bytes) : '—');
    this.nodes.get('chart-empty').hidden = points.length > 1;
    this.replace('chart', points, () => {
      if (points.length < 2) return [];
      const max = Math.max(1, ...points.map(point => point.bytes));
      const start = points[0].timestamp;
      const span = Math.max(1, points.at(-1).timestamp - start);
      const segments = [[]];
      points.forEach((point, index) => {
        if (index && point.timestamp - points[index - 1].timestamp > 7) segments.push([]);
        const x = ((point.timestamp - start) / span * 700).toFixed(1);
        const y = (140 - point.bytes / max * 125).toFixed(1);
        segments.at(-1).push(`${x},${y}`);
      });
      return segments.filter(segment => segment.length > 1).map(segment => {
        const line = document.createElementNS('http://www.w3.org/2000/svg', 'polyline');
        line.setAttribute('points', segment.join(' '));
        return line;
      });
    });
  }
}
