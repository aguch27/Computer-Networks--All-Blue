import { $, node, text, labAvailable, available, StableDOM } from './ob-model.js';
import { post } from './ob-tools.js';

// The runner owns the workflow. Refreshing/closing this view never repeats it.
export class Demonstration {
  constructor(read, refresh) {
    Object.assign(this, {read, refresh}); this.dom = new StableDOM(); this.sending = false;
    $('run-demo').addEventListener('click', () => this.submit('demo'));
    $('stop-demo').addEventListener('click', () => this.submit('cancel'));
    for (const id of ['demo-kind', 'demo-host']) $(id).addEventListener('change', () => this.render());
    $('demo-setup').addEventListener('click', () => {
      $('job-kind').value = 'start'; $('job-profile').value = $('demo-kind').value === 'escalation' ? 'escalation' : 'baseline';
      $('job-profile').dispatchEvent(new Event('change'));
    });
  }
  configuration() {
    const {state, workspace, offline} = this.read(), c = state?.controller;
    const host = $('demo-host').value, kind = $('demo-kind').value;
    const owned = (workspace?.lab?.services || []).filter(s => s.host !== host);
    const allowed = service => c?.policy?.allow?.some(r => r.source === host && r.destination === service.host && r.port === service.port);
    return {state, workspace, offline, c, host, kind, permitted: owned.find(allowed), prohibited: owned.filter(s => !allowed(s))};
  }
  prerequisite() {
    const {state, workspace, offline, c, host, kind, permitted, prohibited} = this.configuration();
    if (!labAvailable(workspace, offline)) return 'A presentation workspace lab is required. Use Prepare workspace below, then run its terminal handoff. A saved or legacy run cannot generate traffic through the GUI.';
    if (!available(state, offline)) return 'Waiting for fresh controller and switch observations.';
    if (!c.policy) return 'Restart into the current workspace version to expose the loaded policy.';
    if (workspace.lab.busy || c.operations?.some(op => ['requested', 'pending'].includes(op.status))) return 'Wait for the current lab or controller action to finish.';
    const source = c.hosts.find(h => h.name === host);
    if (!source || !permitted || !prohibited.length) return 'Choose a host with both a permitted service and an owned prohibited service.';
    if (source.block_requested || source.block_confirmed !== false) return 'Release this host and wait for confirmed normal policy before starting a demonstration.';
    if (kind === 'escalation') {
      if (!c.escalation?.hosts?.[host]) return 'This host is not eligible for escalation. Prepare a new workspace with the configured escalation profile; selecting Enforce alone cannot add eligible hosts.';
      if (prohibited.length < c.escalation.threshold) return `This profile needs ${c.escalation.threshold} distinct prohibited services; the lab exposes ${prohibited.length}.`;
      if (c.escalation.window_seconds < c.escalation.threshold * 2 + 3) return 'The configured observation window is too short for this sequential demonstration. Use a longer window in a new lab or demonstrate it manually.';
    } else if (c.escalation?.mode === 'enforce' && c.escalation.hosts?.[host]) return 'Select Observe or Off before this demonstration so automatic escalation cannot change its host-block test.';
    return '';
  }
  render() {
    const {state, workspace, offline} = this.read(), demo = workspace?.lab?.demo;
    this.running = demo?.status === 'running';
    const names = (state?.controller?.hosts || []).map(h => h.name);
    if (JSON.stringify(names) !== this.hostNames) {
      const selected = $('demo-host').value;
      $('demo-host').replaceChildren(...names.map(name => new Option(name, name)));
      if (names.includes(selected)) $('demo-host').value = selected;
      this.hostNames = JSON.stringify(names);
    }
    const requirement = this.prerequisite();
    $('demo-kind').disabled = this.running || this.sending; $('demo-host').disabled = this.running || this.sending;
    $('run-demo').disabled = this.sending || this.running || Boolean(requirement);
    $('stop-demo').disabled = this.sending || !this.running || !labAvailable(workspace, offline) || demo?.stop_requested;
    text('demo-prerequisite', this.running ? 'The lab runner coordinates this demonstration across consoles and browser tabs. Stop cancels current traffic; submitted controller/service work settles before conditional restoration.' : requirement || 'Ready. Real actions run in the lab owner. Only still-owned host/mode changes are restored.');
    text('demo-status', this.error || demo?.reason || (requirement ? 'Waiting for prerequisites' : 'Ready'));
    const steps = demo?.steps || [];
    this.dom.replace('demo-steps', steps, () => steps.map(step => {
      const item = node('li', undefined, `demo-step ${step.status}`);
      item.append(node('strong', `${step.title} · ${step.status}`), node('span', step.detail)); return item;
    }));
  }
  async submit(action) {
    if (this.sending) return;
    const {workspace} = this.read();
    if (!workspace?.lab?.run_id) return;
    const details = action === 'demo' ? {kind: $('demo-kind').value, host: $('demo-host').value} : {};
    // An uncertain receipt retains exactly the same ID and arguments.
    const signature = JSON.stringify({action, ...details, run_id: workspace.lab.run_id});
    if (this.pending?.signature !== signature) this.pending = {signature, command: {action, ...details, run_id: workspace.lab.run_id, id: crypto.randomUUID()}};
    this.sending = true; this.error = ''; this.render();
    try { await post('/workspace/lab', this.pending.command); this.pending = null; }
    catch (error) { this.error = error.message; if (error.result) this.pending = null; }
    finally { this.sending = false; this.render(); this.refresh(); }
  }
}
