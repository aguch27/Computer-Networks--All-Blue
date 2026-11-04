import { DashboardView } from './view.js';

const view = new DashboardView();
const refreshDelay = 2000;
const hiddenDelay = 5000;
const requestTimeout = 1800;
let pollTimer;
let healthTimer;
let request;
let stopped = false;

async function refresh() {
  if (request || stopped) return;
  clearTimeout(pollTimer);
  request = new AbortController();
  const timeout = setTimeout(() => request?.abort(), requestTimeout);
  try {
    const response = await fetch('/state.json', { cache: 'no-store', signal: request.signal });
    if (!response.ok) throw new Error('Presentation unavailable');
    const state = await response.json();
    if (!stopped) view.render(state);
  } catch {
    if (!stopped) view.offline();
  } finally {
    clearTimeout(timeout);
    request = null;
    if (!stopped) pollTimer = setTimeout(refresh, document.hidden ? hiddenDelay : refreshDelay);
  }
}

function start() {
  stopped = false;
  clearInterval(healthTimer);
  healthTimer = setInterval(() => {
    if (!document.hidden) view.updateHealth();
  }, 1000);
  refresh();
}

function stop() {
  stopped = true;
  clearTimeout(pollTimer);
  clearInterval(healthTimer);
  request?.abort();
}

async function submit(details) {
  const command = view.beginCommand(details);
  if (!command) return;
  const abort = new AbortController();
  const timeout = setTimeout(() => abort.abort(), 4000);
  try {
    const response = await fetch('/commands', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(command), signal: abort.signal });
    const result = await response.json();
    // HTTP acceptance means queued only. Confirmation comes from the polled operation ID.
    view.commandReply(command, response.ok
      ? { status: 'requested' } : { status: result.status || 'failed', error: result.error });
  } catch {
    view.commandReply(command, { status: 'unknown', error: 'No acknowledgement received. Check action history before retrying.' });
  } finally {
    clearTimeout(timeout);
    refresh();
  }
}

document.getElementById('host-grid').addEventListener('click', event => {
  const button = event.target.closest('button[data-action]');
  if (!button || button.disabled) return;
  submit({ action: button.dataset.action, host: button.closest('[data-host]').dataset.host });
});
document.getElementById('escalation-mode').addEventListener('change', event => {
  if (!event.target.disabled) submit({ action: 'mode', mode: event.target.value });
});

const navigation = document.querySelector('nav');
const menu = document.getElementById('menu-toggle');
function closeMenu() {
  menu.setAttribute('aria-expanded', 'false');
  navigation.classList.remove('open');
}
menu.addEventListener('click', () => {
  const expanded = menu.getAttribute('aria-expanded') !== 'true';
  menu.setAttribute('aria-expanded', String(expanded));
  navigation.classList.toggle('open', expanded);
});
navigation.addEventListener('click', event => {
  if (event.target.closest('a')) closeMenu();
});
document.addEventListener('keydown', event => {
  if (event.key === 'Escape' && menu.getAttribute('aria-expanded') === 'true') {
    closeMenu();
    menu.focus();
  }
});

const links = [...navigation.querySelectorAll('a')];
const sections = links.map(link => document.querySelector(link.getAttribute('href')));
const visible = new Set();
const observer = new IntersectionObserver(entries => {
  for (const entry of entries) {
    if (entry.isIntersecting) visible.add(entry.target.id);
    else visible.delete(entry.target.id);
  }
  const current = sections.find(section => visible.has(section.id));
  if (!current) return;
  for (const link of links) {
    if (link.hash === `#${current.id}`) link.setAttribute('aria-current', 'location');
    else link.removeAttribute('aria-current');
  }
}, { rootMargin: '-90px 0px -40% 0px' });
sections.forEach(section => observer.observe(section));

document.getElementById('event-filter').addEventListener('input', () => view.renderEvents());
document.addEventListener('visibilitychange', () => {
  if (!document.hidden) refresh();
});
window.addEventListener('pagehide', stop);
window.addEventListener('pageshow', event => {
  if (event.persisted) start();
});
start();
