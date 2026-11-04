# All Blue

Local SDN firewall laboratory with real TCP traffic, an OS-Ken controller, Open vSwitch,
a TCP/SQLite audit logger and original ocean-teal dashboard assets. Runtime services,
artwork and browser modules stay local. Initial dependency installation needs internet.

## Setup on Ubuntu

Merge all three contributions into one repository before setup or testing.

```bash
sudo bash scripts/setup-system.sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m playwright install chromium
.venv/bin/python scripts/lab.py --preflight
```

The controller uses the pinned OS-Ken 4.2 native hub. No frontend build is required.
Administrator authentication stays in the operator terminal.

## Dashboard and coordinated console

Start the independent dashboard in one terminal. Reuse an existing instance on 8081.

```bash
.venv/bin/python -m all_blue --runtime runtime dashboard --port 8081 --follow-lab
```

Open [the observatory](http://127.0.0.1:8081/observatory) or
[the classic dashboard](http://127.0.0.1:8081/classic).
In a separate visible terminal, choose one startup command:

```bash
# Baseline: escalation off.
sudo .venv/bin/python scripts/lab.py --console --verbose

# Alternative: explicit escalation profile.
sudo .venv/bin/python scripts/lab.py --console --verbose --escalation config/escalation-lab.json
```

--console implies --workspace: one Mininet owner and one coordinated mininet> prompt,
with working dashboard controls. These modes do not automatically run acceptance tests.
Do not start both commands or a second network. An existing ab-s1 or busy management port
refuses startup. The profile explicitly starts Enforce for eligible h1/h3; select Off or
Observe before a traffic/block demo on an eligible host.

Attach another console without creating a network:

```bash
.venv/bin/python scripts/console.py
# Optional: select the exact runtime printed by the launcher.
.venv/bin/python scripts/console.py --runtime runtime/lab-YYYYMMDD-HHMMSS
```

Each console stays pinned to its selected run; the independent dashboard follows new runs.
At mininet>, enter supported commands individually:

```text
nodes
net
dump
h1 traffic h2 9000 5 0.1
h3 traffic h2 9001 1 0
block h1
release h1
mode observe
service logger restart
demo traffic h3
history
status
stop
exit
```

This is a restricted coordinated console, not the unrestricted native Mininet CLI.
Arbitrary shell/OpenFlow commands are refused. Topology inspection reflects the owner's
startup capture; use status and current observations for health. Traffic accepts configured
hosts/listeners, 1-100 messages, intervals 0-1 second and at most 20 seconds scheduled spacing.
The baseline allows h1/h3 to h2 TCP 9000 and denies prohibited services. A refused or timed-out
connection alone does not prove policy enforcement; inspect controller and receiver evidence.

Actions from either interface have shared request IDs, origin, status and history. HTTP or
socket receipt means queued, not enforced. Controller confirmation still requires barrier
and matching switch readback. Retries retain their request IDs; inspect unknown outcomes.
Competing actions are coordinated by the backend, and deliberate manual overrides interrupt
a demo with conditional restoration. Changing run/epoch identities invalidates stale work.

## Stop, detach and shutdown

Stop demo / stop cancels owned traffic and skips remaining demo actions; submitted writer
or lifecycle steps settle before conditional restoration. Inspect the final result.
exit or EOF detaches the coordinated console and leaves the owner running.
Use shutdown at the prompt or Workbench's Shut down this lab to stop the owner and its
resources. Shutdown remains stopping until cleanup is checked; failures remain visible.
Ctrl+C requests cancellation, not shutdown; exit/EOF detaches without stopping the owner.
The independent dashboard stays open and explains stopped/stale state.

The legacy command without --console/--workspace remains separate: it runs its acceptance
scenario before opening the native CLI. Its exit behavior differs from console detachment.
Do not mix legacy shell examples with the restricted coordinated console.

## Configuration, failures and recovery

Workbench configuration saves do not change the running network. Prepare a new terminal
workflow and explicitly shut down/restart when applying configuration changes. Eligible hosts,
thresholds and observation windows are configuration settings. Saved mode-only overrides
apply to restarts in the same run; a new run starts from its loaded configuration.

After an unexpected owner death, inspect status and the exact run. Only if it is interrupted,
use the explicit guarded recovery command in a visible terminal:

```bash
sudo .venv/bin/python scripts/recover-workspace.py --run lab-YYYYMMDD-HHMMSS --confirm-interrupted
```

Replace the run name with the actual interrupted run. Recovery verifies recorded ownership
and refuses a live owner or mismatched resources. It does not automatically start a new lab.
Never use global mn -c or broad process-kill commands. Only ab-s1 and this lab's owned
processes/interfaces may be managed.

## Logs, tests and acceptance

View logs without starting duplicate services:

```bash
.venv/bin/python scripts/lab.py --follow controller
.venv/bin/python scripts/lab.py --follow logger
```

Run ordinary tests after setup. Playwright checks need installed Chromium.
Stop a live lab before starting separate privileged acceptance or benchmark networks.

```bash
.venv/bin/python -m pytest -q
sudo bash scripts/run-lab-tests.sh --verbose
sudo bash scripts/run-escalation-tests.sh --verbose
sudo .venv/bin/python scripts/lab.py --combined-test --verbose
sudo .venv/bin/python scripts/lab.py --combined-test --verbose --escalation config/escalation-lab.json
sudo .venv/bin/python scripts/benchmark.py --trials 3
```

Unit, browser and loopback results are not Mininet evidence; isolated OVS checks have a
separate scope. The new combined-mode privileged acceptance, current baseline/escalation
regression, privileged orphan recovery and Mininet performance measurements remain pending.
Do not infer they passed from code availability or older reports. Inspect each actual run's
acceptance.json, controller logs and independently correlated receiver/switch evidence.
An interactive demonstration is not an acceptance suite. Report status, errors, cleanup
results and source_sha256 identify what was actually completed and which source was tested.

Benchmarks compare static OpenFlow, normal All Blue and verbose All Blue across ALLOW,
DENY, automatic BLOCK and logger outage: 11 applicable conditions, default three trials
(33 fresh networks). Metrics cover startup, first connection/echo, subsequent round trips,
application goodput, enforcement and audit recovery. Static rules have different guarantees.
Invalid trials stay in raw results and are excluded from summaries. Generated CSV/SVG/JSON/
Markdown results live under runtime/ and are not included in this source upload.

Packaging verification: the extracted combined copy recorded 105 passes and one shutdown
cleanup-state assertion failure in a 106-test focused run (49.28s). That test passed unchanged
in isolation (1.75s). The cause is unresolved; this is not a clean full-regression claim.

## Three-person upload allocation

Shared repository setup: README.md, .gitignore, pyproject.toml and requirements.lock.
Person 1: network/lab/console/benchmarks/recovery.
Person 2: controller/policy/escalation, both dashboards and workbench backend.
Person 3: audit/storage/terminal observability. Tests follow their related components.

Extract each ZIP and upload its contents to the same repository, preserving paths.
Upload the shared setup files first, including the hidden .gitignore. Do not upload ZIPs, outer folders or verification
artifacts. The per-person Markdown explanations are supplied separately for study/reference.
No environment, runtime records, private state, automation or historical report is included.
The original source handoff is preserved outside this reduced export.
