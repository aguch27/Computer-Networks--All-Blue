import { $, available, text, flowKey, Commands } from './ob-model.js';
import { Scene } from './ob-scene.js';
import { ObservatoryView } from './ob-view.js';
import { Guide } from './ob-guide.js';
import { Workbench, get, post } from './ob-tools.js';
import { Demonstration } from './ob-demo.js';

const commands = new Commands(), view = new ObservatoryView(commands), guide = new Guide();
let state = null, workspace = null, offline = true, request = null, timer = null, stopped = false, identity = null, noticeTimer;
function notify(message) { text('notice', message); $('notice').hidden = false; clearTimeout(noticeTimer); noticeTimer = setTimeout(() => $('notice').hidden = true, 7000); }
function select(component) {
  view.selected = component; view.flowID = null; render();
  $('log-host').value = state?.controller?.hosts?.some(host => host.name === component) ? component : '';
  view.renderLogs();
}
const scene = new Scene(select), tools = new Workbench(refresh, notify, action => guide.acted(action));
const demo = new Demonstration(() => ({state, workspace, offline}), refresh);
function render() {
  scene.render(state, view.selected, offline, state?.controller?.flows?.find(row => flowKey(row) === view.flowID));
  view.render(state, workspace, offline, scene.observations.reset);
  tools.demoBusy = workspace?.lab?.demo?.status === 'running';
  tools.render(workspace, state, offline);
  guide.render(state, workspace, offline);
  demo.render();
}
async function refresh() {
  if (request || stopped) return;
  clearTimeout(timer); request = new AbortController();
  const timeout = setTimeout(() => request?.abort(), 1800);
  try {
    const results = await Promise.allSettled([get('/state.json', request.signal), get('/workspace.json', request.signal)]);
    if (results[0].status === 'rejected') throw results[0].reason;
    state = results[0].value; offline = false;
    if (results[1].status === 'fulfilled' && results[1].value.runtime === state.runtime) workspace = results[1].value;
    else { workspace = null; text('lab-prerequisites', 'Workspace inspection unavailable; live controller observations remain independent.'); }
    const next = `${state.runtime}/${state.controller?.run_id}/${state.controller?.switch_epoch}`;
    if (identity !== null && next !== identity) { view.operationID = null; view.eventID = null; view.flowID = null; notify('Runtime, controller run or switch epoch changed. Activity comparisons have reset.'); }
    identity = next; render();
  } catch { offline = true; render(); }
  finally { clearTimeout(timeout); request = null; if (!stopped) timer = setTimeout(refresh, document.hidden ? 5000 : 2000); }
}
async function control(details) {
  if (!available(state, offline)) return;
  if (workspace?.lab?.demo?.status === 'running') {
    if (!confirm('Stop the active demonstration and apply this manual choice? Demo restoration will preserve this choice.')) return;
    details = {...details, override: true};
  }
  const command = commands.begin(details, state); if (!command) return;
  guide.acted({kind: 'controller', ...command}); view.updateControls();
  try { const response = await post('/commands', command); commands.reply(command, {status: response.status || 'requested', reason: 'HTTP request receipt only; waiting for controller result.'}); }
  catch (error) { commands.reply(command, {status: error.result?.status || (error.result ? 'failed' : 'unknown'), reason: error.message}); }
  finally { view.updateControls(); refresh(); }
  return command;
}
$('host-cards').addEventListener('click', event => { const button = event.target.closest('button[data-action]'); if (button && !button.disabled) control({action: button.dataset.action, host: button.closest('[data-host]').dataset.host}); });
$('mode').addEventListener('change', () => { if (!$('mode').disabled) control({action: 'mode', mode: $('mode').value}); });
$('clear-selection').addEventListener('click', () => select(null));
$('flow-rows').addEventListener('click', event => {
  const button = event.target.closest('button[data-flow]');
  if (!button) return;
  view.flowID = button.dataset.flow; view.selected = null; render();
  $('inspector').scrollIntoView({block: 'nearest'});
});
$('operation-list').addEventListener('click', event => { const button = event.target.closest('[data-operation]'); if (button) { view.operationID = button.dataset.operation; view.renderOperations(); } });
$('event-list').addEventListener('click', event => { const button = event.target.closest('[data-event]'); if (button) { view.eventID = button.dataset.event; view.renderLogs(); } });
$('log-filters').addEventListener('submit', event => event.preventDefault());
for (const id of ['log-search', 'log-host', 'log-action', 'log-status']) $(id).addEventListener('input', () => view.renderLogs());
$('diagnostic-filter').addEventListener('input', () => view.renderDiagnostics());
$('motion').addEventListener('click', () => { scene.setPaused(!scene.paused); $('motion').setAttribute('aria-pressed', String(scene.paused)); text('motion', scene.paused ? 'Resume animation' : 'Pause animation'); });
$('presentation').addEventListener('click', () => { const enabled = document.body.classList.toggle('presentation'); $('presentation').setAttribute('aria-pressed', String(enabled)); });
const freshness = setInterval(() => { if (!document.hidden) { view.renderHealth(); view.updateControls(); tools.render(workspace, state, offline); guide.render(state, workspace, offline); demo.render(); if (!available(state, offline)) scene.clear(); } }, 1000);
document.addEventListener('visibilitychange', () => { if (document.hidden) scene.clear(); else refresh(); });
window.addEventListener('pagehide', () => { stopped = true; clearTimeout(timer); clearInterval(freshness); request?.abort(); scene.clear(); });
window.addEventListener('pageshow', event => { if (event.persisted) location.reload(); });
refresh();
