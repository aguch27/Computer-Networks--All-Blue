import { $, text, available, labAvailable, fresh, clock } from './ob-model.js';

const chapters = [
  ['Meet the network', 'The controller chooses policy. The switch enforces installed rules. Hosts run socket applications; the separate TCP logger persists security events.', 'A fresh controller snapshot and configured host bindings.', 'Select each component. The inspector shows its real role, addresses and current observations.', '#network', 'Explore components →'],
  ['Permitted & prohibited traffic', 'Send traffic deliberately. A policy DENY is a decision about a requested service, not a claim about the person or application behind it.', 'A workspace lab, owned listening destination and current switch observations.', 'Run Allow → Deny. Compare actual replies, independent receiver deltas, rule counters and decisions at each step.', '#demonstrations', 'Open the live demonstrations →'],
  ['Manual Block & Release', 'A host block takes precedence over permissions. Release clears old tuple rules before removing the block, then returns the host to normal policy.', 'A fresh ready controller and switch. Choose a host deliberately.', 'Block is confirmed only after switch readback. Release must retain cleanup verification. A successful echo is separate application-delivery evidence.', '#management', 'Open host controls →'],
  ['Off, Observe & Enforce', 'Observe records distinct prohibited services without automatically blocking. Enforce needs fresh observations after a mode transition. Existing blocks stay until released.', 'An explicitly selected escalation profile with eligible hosts. Baseline leaves escalation off.', 'Run Observe → Enforce → Release to see the actual evidence, automatic block and restoration. Manual mode controls remain below.', '#demonstrations', 'Open the escalation demonstration →'],
  ['Follow a real decision', 'Follow one operation through observed writer steps and one correlated security event through persistence and acknowledgements.', 'Controller operation records; persisted events. Intermediate steps require retained instrumentation.', 'HTTP receipt, queuing, switch updates, barrier reply and matching readback are distinct. A server ACK transmission is not proof that the controller received it.', '#logbook', 'Inspect the logbook →'],
  ['Why the policy holds', 'Identity bindings, default deny, exact reverse rules, finite permissions and cleanup before release define the firewall behaviour.', 'Loaded policy details and available switch readback.', 'Expand policy inspection. Compare the explanation with actual rule priorities and matches. Rule lifetime is shown as configured timeout and observed age, not an exact countdown.', '#traffic', 'Inspect policy and rules →'],
  ['Failures & recovery (optional)', 'Interrupt only a component owned by the isolated workspace. Keep the observatory open to inspect stale state, retries, retained block intent and verified recovery.', 'A workspace lab. Explicit intent to interrupt a component; this chapter itself performs no action.', 'Stop or restart the logger, controller or switch with the service controls. Inspect actual interruption/recovery results. Saved intent alone never establishes restored enforcement.', '#workbench', 'Open service controls →'],
  ['Validation & measurements', 'Review retained acceptance and benchmark evidence with its real run and time. Missing or invalid measurements stay visible.', 'Retained local reports, or an idle lab and an explicitly executed terminal workflow.', 'Static OpenFlow, ordinary All Blue and verbose All Blue remain separate conditions. Pending privileged validation and incomplete runs are not passing results.', '#records', 'Review recorded evidence →']
];
export class Guide {
  constructor() {
    this.index = 0; this.since = Date.now() / 1000; this.last = null;
    $('chapter').replaceChildren(...chapters.map((c, i) => new Option(`${i + 1}. ${c[0]}`, String(i))));
    $('chapter').addEventListener('change', () => this.select(Number($('chapter').value)));
    $('previous-chapter').addEventListener('click', () => this.select(Math.max(0, this.index - 1)));
    $('next-chapter').addEventListener('click', () => this.select(Math.min(chapters.length - 1, this.index + 1)));
    $('caption-toggle').addEventListener('click', () => {
      $('guide-caption').hidden = !$('guide-caption').hidden;
      $('caption-toggle').setAttribute('aria-expanded', String(!$('guide-caption').hidden));
      text('caption-toggle', $('guide-caption').hidden ? 'Show caption' : 'Hide caption');
    });
    this.select(0);
  }
  select(index) {
    this.index = index; this.since = Date.now() / 1000; this.last = null;
    const [title, caption, requirements, expected, link, action] = chapters[index];
    $('chapter').value = String(index); text('guide-heading', title); text('guide-caption', caption);
    text('guide-prerequisites', requirements); text('guide-expected', expected);
    $('guide-action').href = link; text('guide-action', action);
    $('previous-chapter').disabled = index === 0; $('next-chapter').disabled = index === chapters.length - 1;
    text('guide-actual', 'No demonstration action has been taken in this chapter.');
    if (this.state) this.render(this.state, this.workspace, this.offline);
  }
  acted(action) { this.last = {...action, at: Date.now() / 1000}; }
  render(state, workspace, offline) {
    this.state = state; this.workspace = workspace; this.offline = offline;
    const c = state?.controller, current = available(state, offline);
    let evidence = 'No demonstration action has been taken in this chapter.';
    if (this.index === 0) evidence = c ? `${c.hosts?.length || 0} configured hosts · switch ${c.switch_connected ? 'connected' : 'disconnected'} · ${current ? 'observations current' : 'observations unverified or stale'}.` : 'Unavailable: no controller snapshot.';
    else if ([1,6].includes(this.index) && !labAvailable(workspace, offline)) evidence = 'Unavailable prerequisite: this run has no current workspace control channel. Use the explicit terminal startup workflow.';
    else if (this.index === 3 && !Object.keys(c?.escalation?.hosts || {}).length) evidence = 'Unavailable prerequisite: no eligible hosts in the loaded configuration. Select the escalation profile explicitly for a new lab run.';
    else if (this.index === 5) evidence = c?.policy ? `Loaded policy ${c.policy_version}; ${c.observed_rules?.length || 0} retained switch rules. ${current ? 'Current readback.' : 'Readback is not current.'}` : 'Loaded policy inspection unavailable for this controller version.';
    else if (this.index === 4) evidence = `${state?.events?.length || 0} retained SQLite events; ${c?.operations?.length || 0} controller operations. Select a record to inspect actual correlated evidence.`;
    else if (this.index === 7) evidence = `${workspace?.runs?.length || 0} retained runs. Review their recorded status and time; none is relabelled as a live validation.`;
    else if (!current && this.index !== 6) evidence = 'Unavailable prerequisite: current controller/switch confirmation is missing.';
    if (this.last) {
      if (this.last.kind === 'controller') {
        const result = c?.operations?.find(op => op.id === this.last.id);
        evidence = result ? `Action ${result.action} · ${result.status}: ${result.reason}` : this.last.run_id !== c?.run_id
          ? 'This request belongs to a previous controller run. Inspect retained audit evidence and current enforcement.' : 'Request sent; no matching controller confirmation observed yet.';
      } else if (this.last.kind === 'lab') {
        const result = workspace?.lab?.operations?.find(op => op.id === this.last.id);
        evidence = result ? `${result.action} · ${result.status}${result.result?.sender ? ` · sent ${result.result.sender.sent}, echoed ${result.result.sender.received}, receiver delta ${result.result.receiver_message_delta}` : ` · ${result.reason}`}` : this.last.run_id !== workspace?.lab?.run_id
          ? 'The lab run changed or is unavailable. Inspect the retained run before retrying this action.' : 'Lab request sent; waiting for the runner result.';
      } else if (this.last.kind === 'workflow') {
        const job = workspace?.jobs?.find(j => j.id === this.last.id);
        evidence = `Prepared ${this.last.action} · ${job?.status || 'awaiting terminal'}. No networking result is implied by preparing a command.`;
      } else evidence = `Inspected recorded ${this.last.id}/${this.last.file}. Historical evidence remains separate from live observations.`;
    }
    text('guide-actual', evidence);
  }
}
