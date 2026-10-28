# All Blue

A local SDN firewall with traffic monitoring and an ocean-teal dashboard. TCP applications
send traffic through Open vSwitch; OS-Ken applies ALLOW, DENY and host-wide BLOCK decisions.
A separate TCP logger stores audit events in SQLite.

The local dashboard can block/release configured hosts and change escalation mode.
All runtime services, fonts and artwork are local. Initial setup requires internet access
to install dependencies.

## Setup on Ubuntu

From the project directory:

```bash
sudo bash scripts/setup-system.sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.lock
.venv/bin/python -m playwright install chromium
```

Setup installs Mininet and Open vSwitch and starts OVS. Administrative authentication remains
with the user. The controller uses the pinned OS-Ken 4.2 native hub in the virtual environment.

## Run the lab

```bash
sudo .venv/bin/python scripts/lab.py
```

The runner creates the isolated `ab-s1` switch and three hosts, runs acceptance checks, and
leaves the Mininet console open. The dashboard is at [localhost:18080](http://127.0.0.1:18080).
Exit the console to clean up. An existing `ab-s1` bridge is never overwritten.

The baseline permits h1/h3 → h2 TCP port 9000 and denies port 9001, where a real listener
also runs. Use the printed runtime directory for administrative commands in another terminal:

```bash
.venv/bin/python -m all_blue --runtime runtime/lab-<timestamp> block h1
.venv/bin/python -m all_blue --runtime runtime/lab-<timestamp> status
.venv/bin/python -m all_blue --runtime runtime/lab-<timestamp> release h1
```

A command starts as **requested**. The matching action becomes **confirmed** only after the
switch barrier and rule readback match. Failed and superseded actions remain visible.
Release removes old permissions before clearing the block.

The same actions are available on host cards. Controls require fresh controller/switch
state and are disabled while a request is pending. HTTP acceptance is only a queued request;
the card and action history show the controller's verified result. A missing acknowledgement
means the outcome is unknown: inspect action history before retrying. Commands require the
same local origin and pass through the existing owner-only administrative socket.

To send additional traffic, enter this at the Mininet prompt (adjust the path/user if moved):

```text
h1 runuser -u agasthya -- /home/agasthya/all-blue/.venv/bin/python -m all_blue.traffic client 10.0.0.2 --port 9000 --count 50 --interval 0.2
```

## Automatic blocking

Optional escalation observes repeated attempts to reach distinct prohibited services.
It is off by default. The lab profile enables a threshold of five services in 30 seconds
for h1/h3. Blocks use the same writer as manual commands and require manual release.

To run an interactive lab with automatic blocking explicitly enabled:

```bash
sudo .venv/bin/python scripts/lab.py --escalation config/escalation-lab.json
```

Use the **Off / Observe / Enforce** selector beside escalation status to change mode live.
Changes start fresh evidence and retain existing host blocks. Observe/Enforce require hosts
explicitly selected in the loaded configuration; the dashboard does not select them for you.
Thresholds, windows and host selection remain configuration settings.

A confirmed mode request has been saved and applied by the controller. Its mode-only
override in `runtime/<run>/escalation-mode.json` wins over the startup mode when the controller
restarts in that same directory. A new lab directory starts from configuration again.
Persistence errors are shown explicitly; a failed save leaves the live mode unchanged.

## Dashboard preview

For the UI without a Mininet network, run these in separate terminals:

```bash
.venv/bin/python -m all_blue logger
.venv/bin/python -m all_blue controller
.venv/bin/python -m all_blue dashboard
```

Open [localhost:8080](http://127.0.0.1:8080). The preview shows that no switch is connected;
it does not generate traffic data. From another computer, forward the loopback port through
SSH: `ssh -L 8080:127.0.0.1:8080 all-blue-ubuntu`.

The layout takes visual inspiration from
[Bedimcode's travel website](https://github.com/bedimcode/responsive-travel-website), using
original local artwork and components. There is no frontend build step.

## Verify and develop

```bash
.venv/bin/python -m pytest -q
.venv/bin/python scripts/lab.py --preflight
sudo bash scripts/run-escalation-tests.sh
```

The privileged runner checks both the baseline and automatic blocking using real TCP traffic.
It saves reports under `runtime/lab-<timestamp>/`.

Current validation: 154 distinct regression tests passed across full and focused runs,
including browser, loopback TCP/SQLite and isolated OVS checks. New privileged Mininet
acceptance and performance benchmarks remain unverified; no measured performance result
is claimed. Run the commands below on Ubuntu to collect actual network evidence.

The wrapper scripts and demonstration commands currently assume `/home/agasthya/all-blue`
and the `agasthya` account. Adjust these paths/account if you clone somewhere else.

## Live terminal demonstration and diagnostics

Run from `/home/agasthya/all-blue`. Start the existing lab once; it runs its real TCP
acceptance checks, then opens Mininet. `--verbose` is optional and off by default:

```bash
sudo .venv/bin/python scripts/lab.py --verbose
```

For the full automatic-block/observation demonstration, use this startup command instead.
It explicitly opts into the existing escalation profile and starts listeners on 9001–9005:

```bash
sudo .venv/bin/python scripts/lab.py --verbose --escalation config/escalation-lab.json
```

After the launcher prints its runtime path, open separate terminals for controller,
logger and actual OVS state. Following logs starts no services, follows controller/logger
restarts in this lab directory, and does not interfere with the dashboard:

```bash
.venv/bin/python scripts/lab.py --follow controller
.venv/bin/python scripts/lab.py --follow logger
sudo watch -n 1 'ovs-ofctl -O OpenFlow13 dump-flows ab-s1'
```

Verbose records are JSON lines with wall and monotonic timestamps, operation/event IDs,
thread identity and actual state. `requested`/`pending` are not confirmation. A barrier
acknowledgement still requires matching rule readback; failures and superseded work remain
visible. Readback includes cookies, priorities, matches, actions and packet/byte counters.
`sqlite_commit_returned` precedes acknowledgement transmission. `ack_sent` only records the
server's successful `sendall`; `ack_received` records the controller's receipt of that ID.
`retry_pending`, queue depth and audit drops describe outages without promising delivery.

The 512-record terminal queue drops diagnostics if its output cannot keep up, and reports
`terminal_dropped`. Audit records still use their separate existing retry queue. This is
tuple/operation observability: it adds no PacketIn rules, packet mirroring or per-packet
tracing. Invalid controller-visible frames are sampled at most once per second. Most
spoofed frames drop in the switch's identity table: its default-drop counter alone cannot
distinguish spoofing from other invalid/non-IPv4 ingress. A readback is an observation at
that time, not a promise that a rule remains installed forever.

At the Mininet prompt, send real permitted and prohibited application traffic:

```text
h1 runuser -u agasthya -- /home/agasthya/all-blue/.venv/bin/python -m all_blue.traffic client 10.0.0.2 --port 9000 --count 20 --interval 0.1
h1 runuser -u agasthya -- /home/agasthya/all-blue/.venv/bin/python -m all_blue.traffic client 10.0.0.2 --port 9001
```

In another terminal, select that run and request manual BLOCK/RELEASE. After each request,
wait for its matching ID to become `confirmed` in the controller output or `status` before
testing port 9000 again. BLOCK must prevent delivery; RELEASE permits fresh authorization:

```bash
export AB_RUN="$(.venv/bin/python -c 'import json; print(json.load(open("runtime/latest-lab.json"))["runtime"])')"
.venv/bin/python -m all_blue --runtime "$AB_RUN" block h1
.venv/bin/python -m all_blue --runtime "$AB_RUN" status
.venv/bin/python -m all_blue --runtime "$AB_RUN" release h1
```

With the escalation profile loaded, demonstrate observation without a block, then repeat
with enforcement. Confirm each mode request before sending the five distinct attempts:

```bash
.venv/bin/python -m all_blue --runtime "$AB_RUN" mode observe
```

```text
h1 bash -c 'for p in 9001 9002 9003 9004 9005; do runuser -u agasthya -- /home/agasthya/all-blue/.venv/bin/python -m all_blue.traffic client 10.0.0.2 --port "$p"; done'
```

Observation logs the threshold and still permits 9000. Set `mode enforce` with the same
CLI command, then repeat the five attempts: fresh evidence triggers a verified automatic
block, including on 9000. `release h1` restores permitted traffic and clears that host's
evidence. `mode off` disables escalation without releasing existing blocks. Observe and
Enforce cannot be selected without configured eligible hosts.

Independent captures and rule inspection (read only):

```bash
sudo ovs-ofctl -O OpenFlow13 dump-flows ab-s1
sudo ovs-ofctl -O OpenFlow13 dump-ports ab-s1
sudo tcpdump -i ab-s1-eth2 -nn -s 0 'tcp port 9000 or tcp portrange 9001-9005'
sudo tcpdump -i lo -nn -s 0 -A 'tcp port 19020'
```

Switch priorities are 65535 for the reconciliation/emergency guard, 50000 for host blocks,
2000 for exact ALLOW tuples, 1000 for DENY tuples, 100 for ingress identity bindings,
1 for the restricted TCP controller rule, and 0 for default drops. Counters exclude the
first packet sent through PacketOut and do not equal application payload counts.

Query the actual SQLite store without installing a SQLite CLI:

```bash
.venv/bin/python - <<'PY'
import os, sqlite3
from pathlib import Path
database = (Path(os.environ['AB_RUN']) / 'events.sqlite3').resolve()
with sqlite3.connect(database.as_uri() + '?mode=ro', uri=True) as db:
    for row in db.execute("SELECT id, json_extract(payload,'$.operation_id'), "
                          "json_extract(payload,'$.action'), json_extract(payload,'$.status') "
                          "FROM events ORDER BY sequence DESC LIMIT 20"):
        print(row)
PY
```

For standalone diagnostics when **no lab is running**, the existing service commands are:

```bash
.venv/bin/python -m all_blue --runtime runtime/manual logger --verbose
.venv/bin/python -m all_blue --runtime runtime/manual controller --verbose
```

These use the existing default ports 9020/6653 and do not create a Mininet network. The lab
uses 19020/16653. Do not start a second logger/controller to view an existing lab.
To shut down the lab, enter `exit` at Mininet (or Ctrl-C the launcher); its own processes
and `ab-s1` are cleaned up. Ctrl-C each follower/capture/watch terminal separately. Never
use global `mn -c` or broad process-kill commands.

## Reproducible benchmarks

Stop the interactive lab first. These commands preserve the existing acceptance suites,
including controller loss/restart, saved blocks, logger recovery and dashboard checks:

```bash
.venv/bin/python -m pytest -q
.venv/bin/python scripts/lab.py --preflight
sudo bash scripts/run-lab-tests.sh --verbose
sudo bash scripts/run-escalation-tests.sh --verbose
sudo .venv/bin/python scripts/benchmark.py --trials 3
```

The benchmark runs 33 fresh Mininet experiments (11 conditions × 3 trials), rotating order:
static OpenFlow, All Blue with verbose off, and All Blue with verbose on, across ALLOW,
DENY, automatic BLOCK and logger outage. Static has no logger, so its outage case is not
applicable. Only dynamic BLOCK experiments load the opt-in escalation profile. Every
experiment uses the existing launcher, same topology and socket applications, a new runtime,
fresh namespaces/rules and independent receiver evidence. There is no simulated fallback.

ALLOW uses 201 exchanges of 1024 bytes, with no deliberate inter-message delay. Startup,
connect/first echo and subsequent 200 round trips are separate. Application goodput includes
the existing receiver's durable per-message receipt write; it is not link capacity. DENY
and BLOCK timings use monotonic controller decision/verification boundaries and client
attempt timestamps. TCP timeout and independent OVS observation are separately labeled.
Outage results reconcile generated, queued, dropped, acknowledged and SQLite-persisted
events, plus restart-to-ack recovery time. No crash-loss guarantee is inferred.

Static comparison rules retain ingress identity checks and default deny, but preauthorize
service traffic and ACK returns with wildcard client ports and no expiry. They have no
dynamic exact reverse authorization, automatic blocks or audit trail. The report explicitly
records these differences; absent dynamic behavior is not represented as zero latency.

Artifacts are printed under `runtime/benchmark-<timestamp>/`: `measurements.csv`,
`summary.csv`, `measurements.json`, `graphs.svg`, `environment.json` and `RESULTS.md`.
Reports include paired static/dynamic and verbose-off/on comparisons. Invalid trials remain
in raw files and are excluded from summaries; the command exits nonzero if any trial is
invalid. Individual `runtime/lab-*/` directories preserve raw samples, receiver records,
OVS dumps, audit databases/logs, source hashes and acceptance/benchmark JSON. All generated
artifacts stay out of Git. Inspect actual acceptance and benchmark reports before interpreting results.
