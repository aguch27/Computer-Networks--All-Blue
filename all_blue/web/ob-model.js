// Presentation logic only. No synthetic observations enter this model.
export { number, clock, escalationSummary } from './state.js';
export const MAX = Object.freeze({ flows: 256, operations: 128, events: 100, effects: 8, samples: 90 });
export const $ = id => document.getElementById(id);
export const now = () => Date.now() / 1000;
export const json = value => JSON.stringify(value, null, 2);
export function fresh(timestamp, limit, at = now()) { return Number.isFinite(timestamp) && at >= timestamp && at - timestamp < limit; }
export function available(state, offline = false) {
  const c = state?.controller;
  return Boolean(!offline && c?.ready && c.switch_connected && fresh(c.collected_at, 6) && fresh(c.statistics_at, 7));
}
export function labAvailable(workspace, offline = false) { return !offline && workspace?.lab?.status === 'running' && fresh(workspace.lab.collected_at, 5); }
export function hostState(host, current) {
  if (!current) return host.block_requested ? 'Block intent saved · enforcement unverified' : 'Current enforcement unverified';
  if (host.block_confirmed === true) return '■ Block confirmed';
  if (host.block_requested) return '◷ Block requested · awaiting verification';
  if (host.block_confirmed === false) return '○ Normal policy';
  return 'Enforcement unverified';
}
export function kind(status) { return ['confirmed', 'completed', 'ALLOW'].includes(status) ? 'good' : ['failed', 'BLOCK', 'DENY'].includes(status) ? 'bad' : ['pending', 'requested', 'unknown'].includes(status) ? 'warn' : ''; }
export function node(tag, text, className) {
  const element = document.createElement(tag);
  if (text !== undefined) element.textContent = String(text);
  if (className) element.className = className;
  return element;
}
export function text(id, value) { const el = $(id); const next = value == null ? '—' : String(value); if (el.textContent !== next) el.textContent = next; }
export function badge(status) { return node('span', status, `badge ${kind(status)}`); }
export function empty(message) { return node('p', message, 'empty'); }
export function details(label, data, key = label) { const el = node('details'); el.dataset.detailKey = key; el.append(node('summary', label), node('pre', json(data))); return el; }
export function flowKey(row) { return JSON.stringify([row.cookie, row.direction, row.match]); }
export function endpoints(row) {
  const match = row?.match || {}, flow = row?.flow || {};
  return {source: match.ipv4_src || flow.source_ip, destination: match.ipv4_dst || flow.destination_ip,
    sourcePort: match.tcp_src ?? flow.source_port, destinationPort: match.tcp_dst ?? flow.destination_port};
}
export function svg(tag, attributes = {}) {
  const el = document.createElementNS('http://www.w3.org/2000/svg', tag);
  for (const [key, value] of Object.entries(attributes)) el.setAttribute(key, String(value));
  return el;
}
export function character(name) {
  const el = svg('svg', {viewBox: '0 0 32 28', 'aria-hidden': 'true', class: 'character sprite', 'shape-rendering': 'crispEdges'});
  for (let frame = 0; frame < 4; frame++) {
    const layer = svg('g', {class: `sprite-frame sprite-frame-${frame}`});
    layer.append(svg('use', {href: `/ob-art.svg#${name}-${frame}`})); el.append(layer);
  }
  return el;
}
export function related(row, selected, controller) {
  if (!selected || ['switch', 'controller', 'logger'].includes(selected)) return true;
  if (row.host === selected || row.evidence?.host === selected) return true;
  const host = controller?.hosts?.find(h => h.name === selected);
  const flow = row.flow || row.match;
  return Boolean(host && flow && [flow.source_ip, flow.destination_ip, flow.ipv4_src, flow.ipv4_dst].includes(host.ip));
}
export function hostRole(host, controller) {
  const rules = controller?.policy?.allow || [];
  return rules.some(r => r.destination === host.name) ? 'service host' : rules.some(r => r.source === host.name) ? 'configured client'
    : /server|service/i.test(host.label) ? 'service role from configured label' : /client/i.test(host.label) ? 'client role from configured label' : 'bound host';
}
export function hostArt(host, controller, index = 0) {
  if (hostRole(host, controller).startsWith('service')) return 'crab';
  const clientIndex = controller?.hosts?.filter(h => !hostRole(h, controller).startsWith('service')).findIndex(h => h.name === host.name);
  return (clientIndex >= 0 ? clientIndex : index) % 2 ? 'submarine' : 'turtle';
}
export class StableDOM {
  constructor() { this.keys = new Map(); }
  replace(id, value, render) {
    const key = JSON.stringify(value);
    if (this.keys.get(id) === key) return;
    const opened = new Set([...$(id).querySelectorAll('details[data-detail-key][open]')].map(el => el.dataset.detailKey));
    this.keys.set(id, key); $(id).replaceChildren(...render());
    for (const el of $(id).querySelectorAll('details[data-detail-key]')) el.open = opened.has(el.dataset.detailKey);
  }
}
export class Commands {
  constructor() { this.requests = new Map(); }
  key(details) { return details.action === 'mode' ? '@mode' : details.host; }
  result(key, state) {
    const local = this.requests.get(key), c = state?.controller;
    if (!local) return c?.operations?.find(op => key === '@mode' ? op.action === 'MODE' : op.host === key);
    const observed = c?.operations?.find(op => op.id === local.id) || state?.command_operations?.find(op => op.id === local.id) || state?.events?.find(e => e.operation_id === local.id);
    if (observed) Object.assign(local, {status: observed.status, reason: observed.reason});
    if (c && local.run_id !== c.run_id) {
      if (!['confirmed', 'failed', 'superseded'].includes(local.status)) Object.assign(local, {status: 'superseded', reason: 'Controller restarted before a result was observed; inspect current state before submitting again.'});
      local.historical = true;
      local.sending = false;
    }
    else if (!local.sending && ['pending', 'requested'].includes(local.status) && now() - local.started > 10)
      Object.assign(local, {status: 'unknown', reason: 'No matching controller result observed. Check action history before retrying.'});
    return local;
  }
  busy(key, state) {
    const result = this.result(key, state);
    return Boolean(result?.sending || ['requested', 'pending'].includes(result?.status)
      || state?.controller?.operations?.some(op => (key === '@mode' ? op.action === 'MODE' : op.host === key) && ['requested', 'pending'].includes(op.status)));
  }
  begin(details, state) {
    const key = this.key(details);
    if (!available(state) || state?.lab_controls?.available === false || this.busy(key, state)) return null;
    const previous = this.requests.get(key);
    const retry = previous?.status === 'unknown' && previous.run_id === state.controller.run_id && previous.action === details.action && previous.mode === details.mode;
    const command = {...details, id: retry ? previous.id : crypto.randomUUID(), run_id: state.controller.run_id};
    this.requests.set(key, {...command, status: 'pending', reason: 'Sending request; confirmation is pending.', sending: true, started: now()});
    // At most one retained request per configured host and the mode selector.
    for (const name of this.requests.keys()) if (name !== '@mode' && !state.controller.hosts.some(h => h.name === name)) this.requests.delete(name);
    return command;
  }
  reply(command, result) { const local = this.requests.get(this.key(command)); if (local?.id === command.id) Object.assign(local, result, {sending: false}); }
}
export function commandText(result) { return result ? `${result.action?.toUpperCase()}${result.mode ? ` ${result.mode}` : ''} · ${result.status}${result.historical ? ' (previous controller run)' : ''} · ${result.reason || ''}` : ''; }

export class Observations {
  constructor() { this.identity = null; this.flows = new Map(); this.events = new Set(); this.acks = new Set(); this.steps = new Set(); this.sample = null; this.reset = ''; this.wasCurrent = false; }
  consume(state, animate, connected = true) {
    const c = state?.controller, identity = c ? `${state.runtime || ''}/${c.run_id}/${c.switch_epoch}` : null;
    const reset = identity !== this.identity;
    const traffic = [], events = [], control = [], audit = [];
    const flows = new Map();
    const current = available(state, !connected);
    const continuous = !reset && this.wasCurrent && fresh(this.sample, 7);
    if (!continuous && this.identity) this.reset = 'Observation gap: the first fresh sample establishes a new activity baseline.';
    if (reset) this.reset = this.identity ? 'New controller run or switch epoch: activity comparison reset.' : 'First observation establishes the baseline.';
    for (const row of (c?.flows || []).slice(0, MAX.flows)) {
      const key = flowKey(row);
      const old = reset ? null : this.flows.get(key);
      const newlyInstalled = !old && row.installed_at >= this.sample && row.installed_at <= c.statistics_at;
      if (animate && current && continuous && c.statistics_at > this.sample &&
          ((old && row.packets > old.packets) || (newlyInstalled && row.packets > 0)))
        traffic.push({...row, delta: row.packets - (old?.packets || 0)});
      if (old && row.packets < old.packets) this.reset = 'A rule counter reset; the next observation establishes a new comparison.';
      flows.set(key, row);
    }
    const stored = (state?.events || []).slice(0, MAX.events);
    if (continuous && animate && current) for (const event of stored) {
      if (!this.events.has(event.id) && fresh(event.timestamp, 6)) events.push(event);
    }
    const steps = new Set();
    for (const op of (c?.operations || []).slice(0, MAX.operations)) for (const step of op.journey || []) {
      const key = `${op.id}/${step.stage}/${step.timestamp}`; steps.add(key);
      if (continuous && animate && current && !this.steps.has(key) && fresh(step.timestamp, 6) && ['barrier_ack', 'matching_readback'].includes(step.stage)) control.push(step);
    }
    const acknowledgements = c?.logger?.acknowledgements || [];
    if (continuous && animate && current) for (const ack of acknowledgements) if (!this.acks.has(ack.event_id) && fresh(ack.timestamp, 6)) audit.push(ack);
    this.identity = identity; this.flows = flows; this.events = new Set(stored.map(e => e.id));
    this.acks = new Set(acknowledgements.map(a => a.event_id)); this.steps = steps; this.sample = c?.statistics_at; this.wasCurrent = current;
    return {traffic: traffic.slice(0, MAX.effects), events: events.slice(0, 1), control: control.slice(0, 1), audit: audit.slice(0, 1), reset};
  }
}
