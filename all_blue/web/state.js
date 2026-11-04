// Display rules shared by the dashboard views. All times come from local snapshots.
export const limits = Object.freeze({ flows: 256, events: 100, operations: 100, hosts: 16, samples: 90 });

const numbers = new Intl.NumberFormat(undefined, { maximumFractionDigits: 0 });
const times = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });

export function number(value) {
  return Number.isFinite(value) ? numbers.format(value) : '—';
}

export function clock(value) {
  const date = new Date(value * 1000);
  return Number.isFinite(value) && Number.isFinite(date.getTime()) ? times.format(date) : '—';
}

export function health(state, failed, now = Date.now() / 1000) {
  const controller = state?.controller;
  const fresh = Boolean(controller && now - controller.collected_at < 6 && !failed);
  const telemetry = Boolean(fresh && controller.statistics_at && now - controller.statistics_at < 7);
  const logger = Boolean(state?.logger_server && now - state.logger_server.collected_at < 5 && !failed);
  let label = 'Controller offline';
  let kind = 'neutral';
  let message = 'Waiting for the local controller. Traffic and enforcement data are unavailable.';

  if (failed) {
    label = 'Presentation offline';
    kind = 'bad';
    message = 'The dashboard cannot reach the local service. Values shown are the last received observations.';
  } else if (controller && !fresh) {
    label = 'Controller data stale';
    kind = 'warn';
    message = 'Controller updates have stopped. Displayed values are historical; current enforcement is unknown.';
  } else if (controller && !controller.switch_connected) {
    label = 'Switch disconnected';
    kind = 'warn';
    message = `No switch is connected. After controller loss, existing permissions may last up to ${controller.permission_seconds} seconds.`;
  } else if (controller && !controller.ready) {
    label = 'Enforcement pending';
    kind = 'warn';
    message = controller.error || 'Reconciling switch rules. Confirmation is pending.';
  } else if (controller && !telemetry) {
    label = 'Traffic data stale';
    kind = 'warn';
    message = 'No recent switch sample. Displayed counters do not establish current traffic.';
  } else if (controller) {
    label = 'Observing the lab';
    kind = 'good';
    message = 'Switch state and persisted audit events are current. Traffic is denied unless the policy permits it.';
  }
  return { label, kind, message, fresh, telemetry, logger };
}

export function escalationSummary(config) {
  if (!config || config.mode === 'off') return 'Automatic policy escalation is off.';
  const mode = config.mode === 'observe'
    ? 'Observation only · no automatic blocks'
    : 'Automatic blocking enabled · release remains manual';
  return `${mode}. Threshold: ${number(config.threshold)} distinct prohibited services within ${number(config.window_seconds)} seconds. These observations do not prove malicious intent.`;
}
