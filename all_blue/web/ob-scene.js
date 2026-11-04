import { $, svg, character, available, hostState, hostRole, hostArt, endpoints, number, clock, text, Observations, MAX } from './ob-model.js';

export class Scene {
  constructor(select) {
    this.select = select; this.bindingKey = ''; this.positions = new Map(); this.nodes = new Map(); this.effects = new Set();
    this.observations = new Observations(); this.reduced = matchMedia('(prefers-reduced-motion: reduce)'); this.paused = false;
    this.reactions = new Map();
    this.reduced.addEventListener('change', () => { this.clear(); this.syncMotion(); });
  }
  clear() {
    for (const effect of this.effects) effect.cancel(); this.effects.clear(); $('effects').replaceChildren();
    for (const timer of this.reactions.values()) clearTimeout(timer); this.reactions.clear();
    for (const group of this.nodes.values()) delete group.dataset.spriteReaction;
    this.syncMotion();
  }
  syncMotion() {
    // Idle character motion is decoration. Evidence-driven effects remain freshness-gated.
    document.body.dataset.spriteMotion = this.nodes.size && !document.hidden && !this.paused && !this.reduced.matches ? 'running' : 'still';
  }
  setPaused(value) { this.paused = value; if (value) this.clear(); this.syncMotion(); }
  react(id, action) {
    const group = this.nodes.get(id);
    if (!group || !available(this.state, this.offline) || document.body.dataset.spriteMotion !== 'running') return;
    clearTimeout(this.reactions.get(id)); group.dataset.spriteReaction = action === 'ALLOW' ? 'allow' : 'deny';
    this.reactions.set(id, setTimeout(() => { delete group.dataset.spriteReaction; this.reactions.delete(id); }, 1700));
  }
  build(controller) {
    const hosts = (controller?.hosts || []).slice(0, 16);
    const key = JSON.stringify(hosts.map(h => [h.name, h.label, h.ip, h.mac, h.port, hostRole(h, controller)]));
    if (key === this.bindingKey) return;
    this.bindingKey = key; this.clear(); this.nodes.clear(); this.positions.clear();
    $('components').replaceChildren(); $('routes').replaceChildren();
    const services = hosts.filter(h => hostRole(h, controller).startsWith('service'));
    const clients = hosts.filter(h => !services.includes(h));
    const height = Math.max(540, 160 + Math.max(clients.length, services.length) * 180);
    $('network-scene').setAttribute('viewBox', `0 0 1000 ${height}`);
    $('network-scene').querySelector('.halftone').setAttribute('height', height);
    $('network-scene').querySelector('.sea-floor').setAttribute('d', `M0 ${height-95} Q170 ${height-145} 340 ${height-80} T680 ${height-95} T1000 ${height-110} V${height} H0Z`);
    const sw = {x: 500, y: Math.max(305, height / 2 + 20)};
    this.add('switch', 'Reef checkpoint', 'ab-s1 · installed rules', 'gateway', sw.x, sw.y);
    this.add('controller', 'Controller', 'Policy choices · single writer', 'controller', 365, 95);
    this.add('logger', 'TCP logger', 'Security events → SQLite', 'logger', 680, 95);
    const connect = (id, from, to, type) => {
      const path = svg('path', {d: `M${from.x} ${from.y} Q${(from.x + to.x) / 2} ${from.y} ${to.x} ${to.y}`, class: `route ${type}`, 'data-related': id,
        tabindex: 0, role: 'button', 'aria-label': `Inspect ${id} route`});
      path.addEventListener('click', () => this.select(id));
      path.addEventListener('keydown', event => { if (['Enter', ' '].includes(event.key)) { event.preventDefault(); this.select(id); } });
      $('routes').append(path);
    };
    connect('controller', sw, this.positions.get('controller'), 'control');
    connect('logger', this.positions.get('controller'), this.positions.get('logger'), 'audit');
    for (const [group, x] of [[clients, 135], [services, 865]]) group.forEach((host, index) => {
      const y = group.length === 1 ? sw.y : 220 + index * (height - 325) / Math.max(1, group.length - 1);
      this.add(host.name, host.name, host.ip, hostArt(host, controller, hosts.indexOf(host)), x, y);
      connect(host.name, this.positions.get(host.name), sw, 'application');
    });
  }
  add(id, label, address, art, x, y) {
    this.positions.set(id, {x, y});
    const group = svg('g', {transform: `translate(${x},${y})`, class: 'component', tabindex: '0', role: 'button', 'aria-label': `Inspect ${label}`, 'data-component': id});
    const sprite = character(art); sprite.setAttribute('x', -64); sprite.setAttribute('y', -91);
    sprite.setAttribute('width', 128); sprite.setAttribute('height', 112);
    const marker = svg('g', {class: 'sprite-marker', 'aria-hidden': 'true', transform: 'translate(33,-79)', 'shape-rendering': 'crispEdges'});
    marker.append(svg('path', {d: 'M0 8V0H16V8H20V24H-4V8ZM4 8H12V4H4Z', class: 'sprite-lock'}),
      svg('rect', {x: 6, y: 13, width: 4, height: 6, fill: '#fff5de'}));
    group.append(sprite, marker, svg('rect', {x: -105, y: 19, width: 210, height: 63, rx: 10, class: 'plaque'}));
    for (const [value, offset, cls] of [[label, 38, 'name'], [address, 55, 'address'], ['', 71, 'state']]) {
      const text = svg('text', {x: 0, y: offset, class: cls}); text.textContent = value; group.append(text);
    }
    group.addEventListener('click', () => this.select(id));
    group.addEventListener('keydown', event => { if (['Enter', ' '].includes(event.key)) { event.preventDefault(); this.select(id); } });
    $('components').append(group); this.nodes.set(id, group);
  }
  pulse(from, to, label, type, arrival) {
    if (this.effects.size >= MAX.effects || !from || !to || this.paused || this.reduced.matches) return;
    const element = svg('g', {class: `effect ${type}`});
    const width = Math.max(58, Math.min(116, label.length * 7 + 16));
    element.append(svg('rect', {x: -width / 2, y: -12, width, height: 24, rx: 5}));
    const caption = svg('text', {'text-anchor': 'middle', x: 0, y: 4}); caption.textContent = label; element.append(caption);
    $('effects').append(element);
    const effect = element.animate([{transform: `translate(${from.x}px,${from.y}px)`, opacity: 0.2},
      {opacity: 1, offset: .2}, {transform: `translate(${to.x}px,${to.y}px)`, opacity: 0.9}], {duration: 1050, easing: 'ease-in-out'});
    this.effects.add(effect);
    const cleanup = () => { element.remove(); this.effects.delete(effect); };
    effect.onfinish = () => { cleanup(); arrival?.(); }; effect.oncancel = cleanup;
    $('network-scene').dataset.effectsObserved = String(Number($('network-scene').dataset.effectsObserved || 0) + 1);
  }
  render(state, selected, offline, focusFlow) {
    this.state = state; this.offline = offline;
    const controller = state?.controller;
    this.build(controller);
    const current = available(state, offline);
    if (!current || document.hidden) this.clear();
    for (const [id, group] of this.nodes) {
      group.classList.toggle('selected', id === selected);
      group.setAttribute('aria-pressed', String(id === selected));
      const host = controller?.hosts?.find(h => h.name === id);
      group.dataset.spriteState = !current ? 'unverified' : host?.block_confirmed === true ? 'blocked' : host?.block_requested ? 'pending' : 'normal';
      const label = host ? hostState(host, current) : id === 'switch' ? current ? '✓ Current switch observations' : '◷ State unverified'
        : id === 'controller' ? 'Chooses policy; switch enforces' : 'ACK sent ≠ ACK received';
      group.querySelector('.state').textContent = label;
    }
    const pair = endpoints(focusFlow);
    const focusedHosts = new Set((controller?.hosts || []).filter(h => [pair.source, pair.destination].includes(h.ip)).map(h => h.name));
    for (const path of $('routes').children) path.classList.toggle('related', focusFlow ? focusedHosts.has(path.dataset.related) : path.dataset.related === selected || selected === 'switch');
    this.syncMotion();
    const changes = this.observations.consume(state, current && !offline && !this.paused && !this.reduced.matches && !document.hidden, !offline);
    if (changes.reset) this.lastEvidence = null;
    for (const flow of changes.traffic) {
      const match = flow.match || {}, source = controller.hosts.find(h => h.ip === (match.ipv4_src || flow.flow?.source_ip));
      const destination = controller.hosts.find(h => h.ip === (match.ipv4_dst || flow.flow?.destination_ip));
      const sw = this.positions.get('switch');
      this.react(source?.name, flow.action);
      this.pulse(this.positions.get(source?.name), sw, `+${number(flow.delta)} packets`, flow.action === 'ALLOW' ? 'application' : 'deny', () => {
        this.react('switch', flow.action);
        if (flow.action === 'ALLOW') {
          this.pulse(sw, this.positions.get(destination?.name), 'ALLOW', 'application', () => this.react(destination?.name, flow.action));
        } else this.pulse(sw, sw, 'DENY · DROP', 'deny');
      });
      const pair = endpoints(flow);
      this.lastEvidence = `${clock(controller.statistics_at)} · ${source?.name || pair.source}:${pair.sourcePort} → ${destination?.name || pair.destination}:${pair.destinationPort} · ${flow.action} · +${number(flow.delta)} packets in the observed ${flow.direction || 'tuple'} rule. ${flow.action === 'ALLOW' ? 'Forwarding rule matched; application replies are reported separately below.' : 'Drop rule matched; no delivery is inferred.'}`;
    }
    if (changes.control.length) this.pulse(this.positions.get('switch'), this.positions.get('controller'), 'reply', 'control');
    if (changes.audit.length) this.pulse(this.positions.get('logger'), this.positions.get('controller'), 'ACK', 'audit');
    text('scene-evidence', this.lastEvidence ? `${current ? 'Latest observed change: ' : 'Historical observation: '}${this.lastEvidence}` : 'Send a demonstration to see its route, decision and counter change here. The first sample establishes a baseline.');
    if (changes.events.length) $('scene-caption').textContent = `${changes.events[0].action} ${changes.events[0].status} · persisted security event`;
    else if (!current) $('scene-caption').textContent = 'No live traffic observations · character motion is decorative';
    else if (changes.traffic.length) $('scene-caption').textContent = 'Counter changes observed · capsules summarize aggregate activity';
    else $('scene-caption').textContent = 'Current observations · select a component to inspect it';
    if (this.reduced.matches) $('scene-caption').textContent += ' · System reduced motion is on';
    else if (this.paused) $('scene-caption').textContent += ' · Animation paused';
  }
}
