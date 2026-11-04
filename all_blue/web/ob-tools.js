import { $, node, text, json, fresh, labAvailable, StableDOM, commandText, number } from './ob-model.js';

export async function get(url, signal) {
  const response = await fetch(url, {cache: 'no-store', signal});
  if (!response.ok) throw new Error(`Local request failed (${response.status})`);
  return response.json();
}
export async function post(url, body) {
  const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 4000);
  try {
    const response = await fetch(url, {method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify(body), signal: controller.signal});
    const result = await response.json();
    if (!response.ok) { const error = new Error(result.error || 'Request failed'); error.result = result; throw error; }
    return result;
  } finally { clearTimeout(timer); }
}
function options(id, rows, selected, emptyLabel) {
  const key = JSON.stringify([rows, emptyLabel]), el = $(id);
  if (el.dataset.options === key) return;
  const previous = selected ?? el.value;
  el.replaceChildren(...rows.map(([value, label]) => new Option(label, value)));
  if (!rows.length && emptyLabel) { const placeholder = new Option(emptyLabel, '', true, true); placeholder.disabled = true; el.append(placeholder); }
  if (rows.some(([value]) => value === previous)) el.value = previous;
  el.dataset.options = key;
}
export class Workbench {
  constructor(refresh, notify, acted) {
    this.refresh = refresh; this.notify = notify; this.acted = acted; this.dom = new StableDOM();
    this.workspace = null; this.pending = null; this.dirty = false; this.configKind = null; this.configRevision = null; this.prepared = null;
    this.preparing = false; this.saving = false; this.reportRequest = null; this.recordSelection = null;
    $('traffic-form').addEventListener('submit', event => { event.preventDefault(); this.traffic(); });
    $('service-form').addEventListener('submit', event => { event.preventDefault(); this.lab({action: 'service', component: $('service-component').value, operation: $('service-operation').value}); });
    $('cancel-action').addEventListener('click', () => this.lab({action: 'cancel'}));
    $('shutdown-lab').addEventListener('click', () => { if (confirm('Shut down this workspace lab and its owned services? The independent observatory will remain available.')) this.lab({action: 'shutdown'}); });
    $('job-form').addEventListener('submit', event => { event.preventDefault(); this.prepare(); });
    $('cancel-job').addEventListener('click', () => this.cancel());
    $('copy-command').addEventListener('click', async () => { try { await navigator.clipboard.writeText($('terminal-command').textContent); this.notify('Terminal command copied.'); } catch { this.notify('Select and copy the displayed command manually.'); } });
    $('config-json').addEventListener('input', () => { this.dirty = true; });
    $('config-kind').addEventListener('change', () => { if (this.dirty && !confirm('Discard the unsaved editor text and open the other configuration?')) { $('config-kind').value = this.configKind; return; } this.loadConfig(); });
    $('reload-config').addEventListener('click', () => { if (!this.dirty || confirm('Reload the saved file and discard unsaved editor text?')) this.loadConfig(); });
    $('save-config').addEventListener('click', () => this.saveConfig());
    $('record-run').addEventListener('change', () => this.recordFiles());
    $('record-file').addEventListener('change', () => this.recordLink());
    $('open-record').addEventListener('click', () => this.openRecord());
    $('job-profile').addEventListener('change', () => this.profileNote());
    $('job-kind').addEventListener('change', () => this.profileNote());
    $('traffic-source').addEventListener('change', () => this.render(this.workspace, this.state, this.offline));
    $('traffic-count').addEventListener('input', () => this.trafficValidation());
    $('traffic-interval').addEventListener('input', () => this.trafficValidation());
  }
  render(workspace, state, offline) {
    this.workspace = workspace; this.state = state; this.offline = offline;
    const lab = workspace?.lab, available = labAvailable(workspace, offline), freshWorkspace = fresh(workspace?.served_at, 7) && !offline;
    let pending = this.pending;
    if (pending) {
      const actual = lab?.operations?.find(op => op.id === pending.id);
      if (actual) { pending = this.pending = {...pending, ...actual, sending: false}; }
      else if (lab?.run_id && lab.run_id !== pending.run_id) {
        pending.historical = true;
        if (!['completed', 'failed', 'superseded'].includes(pending.status)) pending.status = 'superseded';
      }
      else if (!pending.sending && !lab?.busy && ['requested', 'pending'].includes(pending.status) && Date.now() - pending.started > 10000) pending.status = 'unknown';
    }
    const busy = lab?.busy || pending?.sending || ['pending', 'requested'].includes(pending?.status);
    text('lab-status', lab?.status === 'stopping' ? 'LAB STOPPING · CLEANUP PENDING' : lab?.status === 'cleanup_failed' ? 'LAB CLEANUP FAILED' : available ? busy ? 'LAB ACTION RUNNING' : 'WORKSPACE LAB CONNECTED' : 'WORKSPACE CONTROL UNAVAILABLE');
    text('lab-prerequisites', available ? `Owned run ${lab.run_id}. Traffic uses real socket applications inside configured Mininet hosts. Whole-lab configuration changes require shutdown, then a new explicit startup handoff.`
      : lab?.reason || 'The lab workspace heartbeat is missing or stale. Prepare a terminal startup below. An active legacy Mininet session must first be exited in its own terminal; the GUI does not adopt or destroy it.');
    const hosts = (state?.controller?.hosts || []).map(h => [h.name, `${h.name} · ${h.label}`]);
    options('traffic-source', hosts, undefined, 'Waiting for configured hosts');
    const services = lab?.services || (state?.controller?.policy?.allow || []).map(r => ({host: r.destination, port: r.port}));
    const unique = [...new Map(services.filter(s => s.host !== $('traffic-source').value).map(s => [`${s.host}:${s.port}`, [`${s.host}:${s.port}`, `${s.host} · TCP ${s.port}`]])).values()];
    options('traffic-service', unique, undefined, available ? 'No destination on another host' : 'Start the workspace lab first');
    const trafficLocked = this.demoBusy || !available || Boolean(busy);
    for (const id of ['traffic-source', 'traffic-count', 'traffic-interval']) $(id).disabled = trafficLocked;
    $('traffic-source').disabled ||= !hosts.length;
    $('traffic-service').disabled = trafficLocked || !unique.length;
    text('traffic-availability', !available ? 'Traffic generation needs a running presentation workspace. Start the lab in its terminal; destination services will appear automatically when it is ready.'
      : !unique.length ? 'This client has no listening destination on another host. Choose a different client.'
      : this.demoBusy ? 'A live demonstration is using the traffic generator. Its results appear in the demonstration panel.'
      : busy ? 'Waiting for the current lab action to finish.' : 'Choose a client and destination, then Send real traffic. The result below shows sent messages, replies and receiver counts.');
    for (const id of ['send-traffic', 'service-submit']) $(id).disabled = this.demoBusy || !available || Boolean(busy);
    $('send-traffic').disabled ||= !hosts.length || !unique.length;
    $('prepare-job').disabled = this.preparing || !freshWorkspace || (workspace?.jobs || []).some(j => ['awaiting_terminal', 'running'].includes(j.status));
    $('save-config').disabled = this.saving || !freshWorkspace || !this.configRevision;
    for (const id of ['config-kind', 'config-json', 'reload-config']) $(id).disabled = this.saving;
    if (pending) {
      const message = `${pending.action} · ${pending.status}${pending.historical ? ' (previous lab run)' : ''} · ${pending.reason || 'Request receipt only; waiting for runner evidence.'}`;
      text(pending.action === 'traffic' ? 'traffic-result' : 'service-result', message);
    }
    $('shutdown-lab').disabled = !available;
    $('cancel-action').disabled = !available || !busy;
    const traffic = (lab?.operations || []).slice().reverse().find(op => op.action === 'traffic' && op.result);
    if (traffic) {
      text('traffic-evidence', json(traffic));
      const result = traffic.result, sender = result.sender;
      if (!pending || pending.action !== 'traffic') text('traffic-result', `Recorded ${new Date(traffic.finished_at * 1000).toLocaleString()} · ${traffic.status} · ` + (sender
        ? `sent ${sender.sent}, echoed ${sender.received}, receiver delta ${result.receiver_message_delta}. ${sender.error || ''}`
        : `${result.sender_status || 'Sender totals unavailable after interruption'}. Inspect retained request-specific receiver evidence below.`));
    } else text('traffic-evidence', 'No sender/receiver result is retained for the selected lab runtime.');
    text('lab-actions', json({console: lab?.console, demo: lab?.demo, cleanup: lab?.cleanup, components: lab?.components, operations: lab?.operations || [], error: lab?.error}));
    if (!this.configKind && workspace?.configurations) this.loadConfig();
    text('loaded-config', json(workspace?.configurations?.loaded || {available: false}));
    const saved = workspace?.configurations?.[this.configKind];
    text('config-revision', `Saved revision ${saved?.revision?.slice(0, 12) || 'unavailable'} · editor revision ${this.configRevision?.slice(0, 12) || 'unavailable'}${saved?.revision && this.configRevision && saved.revision !== this.configRevision ? ' · file changed: reload before saving' : ''}. Saved does not mean applied.`);
    this.profileNote();
    const jobs = workspace?.jobs || [];
    this.dom.replace('job-list', jobs, () => {
      const opened = new Set([...$('job-list').querySelectorAll('details[open]')].map(el => el.dataset.job));
      return jobs.length ? jobs.map(job => {
        const el = node('details'); el.dataset.job = job.id; el.open = opened.has(job.id);
        el.append(node('summary', `${job.kind} · ${job.kind === 'benchmark' ? 'fixed comparisons' : job.profile} · ${job.status}`), node('p', `${job.id} · ${new Date(job.created_at * 1000).toLocaleString()}`), node('pre', [job.error, job.output].filter(Boolean).join('\n') || 'No terminal output retained.'));
        return el;
      }) : [node('p', 'No prepared workflows. Privileged validation remains pending until explicitly run in a terminal.')];
    });
    const awaiting = jobs.find(job => job.status === 'awaiting_terminal');
    if (awaiting) {
      this.prepared = awaiting; text('terminal-command', awaiting.terminal);
      $('copy-command').disabled = false; $('cancel-job').disabled = !freshWorkspace;
    } else if (this.prepared && jobs.some(job => job.id === this.prepared.id)) {
      const completed = jobs.find(job => job.id === this.prepared.id);
      this.prepared = null; text('terminal-command', ''); $('copy-command').disabled = true; $('cancel-job').disabled = true;
      text('job-result', `Workflow ${completed.status}. Inspect its retained output below.`);
    }
    text('job-availability', awaiting ? 'A command is already prepared below. Run it in your terminal, or cancel it before preparing another.'
      : jobs.some(job => job.status === 'running') ? 'A terminal workflow is running. Inspect its progress below.'
      : !freshWorkspace ? 'Waiting for the dashboard to read the local workspace.' : 'Preparation creates a terminal handoff. It does not start the network by itself.');
    const runs = workspace?.runs || [];
    options('record-run', runs.map(run => [run.name, `${run.name} · ${run.status} · ${run.checks} checks / measurements`]));
    this.recordFiles();
  }
  profileNote() {
    const config = this.workspace?.configurations?.escalation?.data;
    const benchmark = $('job-kind').value === 'benchmark';
    $('job-profile').disabled = benchmark;
    $('job-trials').disabled = !benchmark;
    text('profile-note', benchmark
      ? 'Benchmark compares static OpenFlow, ordinary All Blue and verbose All Blue using its existing fixed scenarios. The block experiment explicitly enables its eligible configuration. Trials can take several minutes; results preserve invalid measurements.'
      : $('job-profile').value === 'baseline' ? 'Baseline omits escalation configuration: automatic escalation starts off with no eligible hosts.'
      : `Explicit opt-in: startup mode ${config?.mode || 'unavailable'}, hosts ${config?.eligible_hosts?.join(', ') || 'none'}, threshold ${config?.distinct_services ?? '—'}, window ${config?.window_seconds ?? '—'}s. A new runtime is used.`);
  }
  async traffic() {
    this.trafficValidation();
    if (!$('traffic-form').reportValidity()) return;
    const [destination, port] = $('traffic-service').value.split(':');
    await this.lab({action: 'traffic', source: $('traffic-source').value, destination, port: Number(port), count: Number($('traffic-count').value), interval: Number($('traffic-interval').value)});
  }
  async lab(details) {
    const urgent = ['shutdown', 'cancel'].includes(details.action);
    if (!labAvailable(this.workspace, this.offline) || (!urgent && (this.demoBusy || this.workspace.lab.busy || this.pending?.sending || ['requested', 'pending'].includes(this.pending?.status)))) return;
    const run = this.workspace.lab.run_id;
    const same = this.pending?.status === 'unknown' && this.pending.run_id === run && JSON.stringify(this.pending.details) === JSON.stringify(details);
    const command = {...details, id: same ? this.pending.id : crypto.randomUUID(), run_id: run};
    this.pending = {...command, details, started: Date.now(), sending: true, status: 'pending'};
    this.acted({kind: 'lab', ...command}); this.render(this.workspace, this.state, this.offline);
    try { const response = await post('/workspace/lab', command); if (this.pending?.id === command.id) Object.assign(this.pending, {status: response.status, reason: response.error || 'Runner received the request.'}); }
    catch (error) { if (this.pending?.id === command.id) Object.assign(this.pending, {status: error.result?.status || (error.result ? 'failed' : 'unknown'), reason: error.message}); }
    finally { if (this.pending?.id === command.id) this.pending.sending = false; this.render(this.workspace, this.state, this.offline); this.refresh(); }
  }
  async prepare() {
    if (this.preparing) return;
    this.preparing = true;
    $('prepare-job').disabled = true;
    try {
      const result = await post('/workspace/plan', {kind: $('job-kind').value, profile: $('job-kind').value === 'benchmark' ? 'baseline' : $('job-profile').value, trials: Number($('job-trials').value)});
      this.prepared = result; text('terminal-command', result.terminal); text('job-result', result.note);
      $('copy-command').disabled = false; $('cancel-job').disabled = false;
      this.acted({kind: 'workflow', id: result.id, action: result.kind});
    } catch (error) { text('job-result', error.message); }
    finally { this.preparing = false; this.refresh(); }
  }
  async cancel() {
    if (!this.prepared) return;
    try { await post('/workspace/cancel', {id: this.prepared.id}); this.prepared = null; text('job-result', 'Prepared terminal handoff cancelled.'); text('terminal-command', ''); $('cancel-job').disabled = true; $('copy-command').disabled = true; }
    catch (error) { text('job-result', error.message); }
    this.refresh();
  }
  loadConfig() {
    this.configKind = $('config-kind').value;
    const config = this.workspace?.configurations?.[this.configKind];
    this.configRevision = config?.revision || null;
    $('config-json').value = config?.data ? json(config.data) : '';
    this.dirty = false; text('config-result', config?.error || 'Loaded saved file into editor. Running policy has not changed.');
  }
  trafficValidation() {
    const duration = Number($('traffic-count').value) * Number($('traffic-interval').value);
    $('traffic-interval').setCustomValidity(duration > 20 ? 'Use fewer messages or a shorter interval: scheduled spacing must total at most 20 seconds.' : '');
  }
  async saveConfig() {
    if (this.saving) return;
    this.saving = true;
    this.render(this.workspace, this.state, this.offline);
    try {
      const result = await post('/workspace/config', {kind: this.configKind, revision: this.configRevision, data: JSON.parse($('config-json').value)});
      this.workspace.configurations = result.configuration; this.loadConfig();
      text('config-result', 'Validated and atomically saved. Not applied: shut down and restart the lab to load these settings. Existing runtime mode overrides still take precedence.');
    } catch (error) { text('config-result', error.message); }
    finally { this.saving = false; this.render(this.workspace, this.state, this.offline); this.refresh(); }
  }
  recordFiles() {
    const run = this.workspace?.runs?.find(row => row.name === $('record-run').value);
    options('record-file', (run?.files || []).map(name => [name, name]));
    text('record-summary', run ? `${run.name} · ${run.kind || 'benchmark'} · ${run.status} · recorded ${new Date(run.recorded_at * 1000).toLocaleString()}${run.error ? ` · ${run.error}` : ''}. This selection is historical evidence, never live animation.` : 'No retained run reports available.');
    this.recordLink();
  }
  reportURL() { return `/workspace/report?${new URLSearchParams({run: $('record-run').value, file: $('record-file').value})}`; }
  recordLink() {
    const usable = Boolean($('record-run').value && $('record-file').value);
    const selection = this.reportURL();
    if (selection !== this.recordSelection) {
      this.reportRequest?.abort(); this.recordSelection = selection;
      text('record-content', 'Select Inspect report to load this historical record.');
      $('report-metrics').replaceChildren();
    }
    $('open-record').disabled = !usable || Boolean(this.reportRequest);
    if (usable) $('download-record').href = this.reportURL() + '&download=1'; else $('download-record').removeAttribute('href');
  }
  async openRecord() {
    if (this.reportRequest) return;
    $('open-record').disabled = true;
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 5000);
    this.reportRequest = controller;
    const run = $('record-run').value, file = $('record-file').value;
    try {
      const response = await fetch(this.reportURL(), {cache: 'no-store', signal: controller.signal});
      if (!response.ok) throw new Error('Recorded report unavailable');
      const body = await response.text();
      if (run !== $('record-run').value || file !== $('record-file').value) return;
      text('record-content', `Recorded ${run}/${file}\n\n${body}`); $('record-content').dataset.run = run;
      const data = file.endsWith('.json') ? JSON.parse(body) : null;
      const rows = Array.isArray(data) ? data : data?.metrics ? [data] : [];
      $('report-metrics').replaceChildren(...rows.slice(0, 100).map(row => node('p', `${row.mode || ''} / ${row.scenario || ''} · ${row.valid === false ? 'INVALID' : row.valid ? 'valid measurement' : 'recorded'} · ${JSON.stringify(row.metrics || row.error || {})}`, 'subtle')));
      this.acted({kind: 'record', action: 'inspect', id: run, file});
    } catch (error) { if (run === $('record-run').value && file === $('record-file').value) text('record-content', error.message); }
    finally { clearTimeout(timer); this.reportRequest = null; this.recordLink(); }
  }
}
