# Sandbox runner: a design memo (M33)

Written 2026-09-02. Status: design only. Decides nothing about spend.

## What it is

mcp_vet today is a static reader. The badge says which checks ran on which
bytes, and the verify page lists what that cannot prove; first on that list is
"nothing was run." The MCP08 audit-record check infers from source that a call
record gets written. The runner would turn that inference into an observation:

1. start the server as a subprocess over stdio,
2. send `initialize`, `notifications/initialized`, `tools/list`, and ONE
   `tools/call` with harmless arguments,
3. read the server's call record back from disk and check that a row naming
   that call appeared after the call and was not there before,
4. write the result into the grade's `record_dynamic` field through
   `grade.dynamic_record()`, the only constructor for that field. The static
   field is untouched; the badge draws the two on separate rows (M35).

The probe in `scripts/own_five_probe.py` is this loop with the target list
hard-wired to our own five servers. It exists to prove the loop works and to
give this memo real numbers, not to be the runner: the runner's whole problem
is running code we did not write, and the probe refuses to do that by
construction.

## The problem, in one line

The runner launches a stranger's server. A static scan of a hostile server
costs nothing but a bad grade; a launch of one costs whatever the process can
reach. So every design question here is really "what can the child reach."

## Isolation model

Three options, against what this box actually has (Windows 11, Python 3.14,
WSL2 with Ubuntu 22.04 installed, no Docker CLI on PATH, Hyper-V present).

### A. Bare subprocess (what the probe does)

`subprocess.Popen` with cwd set to the target tree, stdio piped, a scrubbed
environment, and a 30 s deadline. This is the right tool for OUR servers and
the wrong tool for anyone else's: the child runs as the same Windows user, sees
the whole filesystem, every credential in `~`, and the network. A timeout is a
liveness bound, not a containment bound. Windows Job Objects can cap CPU,
memory, and process count and kill the tree on close, but they do not restrict
filesystem or network. Windows has no seccomp and no unprivileged user
namespaces; the honest options for a per-run restricted user are AppContainer
(a real sandbox, but fiddly to drive from Python and undocumented for this
use) or a Sandboxie-class tool (third party, out).

Verdict: fine for own_five, unacceptable for third-party code on this machine.

### B. Container or VM on this box

WSL2 is here, so a Linux VM is one `wsl` call away, and a distro can run
rootless Podman or Docker with `--network none`, a read-only bind mount of the
target tree, tmpfs for the record file, and cgroup limits. That gives real
filesystem and network containment at zero dollars. Costs that are not
dollars: the runner then depends on a WSL distro being installed and updated,
Docker Desktop is not installed and its licence terms would need reading before
it is, and a Linux container cannot exercise a server that only starts on
Windows (rare for MCP servers, worth listing). Windows Sandbox is the other
local option: a fresh throwaway Windows VM per run, but it needs the Pro SKU
feature enabled, boots in tens of seconds, and is driven through a `.wsb` file
and a GUI window, which makes it a poor fit for an unattended loop.

Verdict: the cheapest containment that would let us run other people's code,
if the runner lives on this box. Setup work, not spend.

### C. Hosted sandbox service

A hosted microVM per run (E2B, Modal, Fly Machines, and the like). The
isolation is somebody else's problem and their whole product; the target never
touches our disk or our network. What it buys beyond B: no dependence on this
laptop being on, a clean image every run, and the ability to grade at a rate
this box cannot. What it costs: dollars per run (below), a network dependency,
an API key that becomes a secret to guard, and the target's code leaving our
control to a vendor's VM, which for a stranger's public repo is nothing and for
a customer's private server may be a contract question.

Verdict: the right shape for a service; the wrong first step while the runner
is unproven.

## Network policy

The runner's own traffic is stdio only; the probe opens no socket, and a
runner would not either. The CHILD's network is the policy question. Default
must be **no network**: a server that phones home during `initialize` is
exactly the kind of thing the runner exists to notice, and an outbound
connection from a sandbox we started is our connection. Under A there is no
clean way to enforce that on Windows without a firewall rule per run. Under B
it is `--network none`. Under C it is a flag on the vendor's API. A second
mode, allow-listed egress for servers that legitimately need one host, is a
later decision and should be a per-run declaration that lands in the receipt.

## Timeout

30 s for the whole conversation (initialize through the one call and the
readback), as in the probe. Our five completed in 0.2 to 3.0 s (the connector
is the slow one at 3.0 s: it imports the MCP SDK and mcp_vet on start). A
server that needs more than 30 s to answer three requests is either doing
work we did not ask for or waiting on something we denied it, and both are a
finding, not a reason to wait longer. Kill the process tree on expiry; report
"launched, no reply within 30 s" as `record_dynamic.observed = False` with the
detail string saying why, never as "no record."

## Cost per server, three currencies

Numbers from the 2026-09-02 probe run and from `COST_PER_CHECK.md`.

**Seconds.** Static grade: 0.31 s median, 1.11 s p95 (warm, n=42). Dynamic
probe, our five: 0.21, 0.30, 0.31, 0.40, 3.02 s wall (subprocess start to
readback). Under B add container start, roughly 1 to 3 s for a warm image.
Under C add the vendor's VM boot, typically a few hundred milliseconds to a few
seconds, plus installing the target's dependencies, which for a Python server
with a lockfile is 10 to 60 s and dominates everything else.

**Bytes.** The runner's own traffic is under 5 KB (three requests, three
replies, one notification). The bytes that matter are the target tree: our
five packages are 90 KB to 457 KB on disk; a clone with history is larger.
Under C the tree is uploaded once per run.

**Dollars.** Zero under A and B. Under C, E2B's published rates
(https://e2b.dev/pricing, read 2026-09-02): "1 vCPU: $0.000014/s",
"2 [Default]: $0.000028/s", RAM "$0.0000045/GiB/s"; the Hobby plan carries a
"One-time $100 of usage in credits." At the default 2 vCPU with 1 GiB, a
sandbox costs $0.0000325 per second. A run that boots, installs deps, and
finishes inside the 30 s budget, call it 60 s of sandbox life, is about
$0.002. A pessimistic 3 minute run with a slow dependency install is about
$0.006. One thousand servers a month at the 60 s figure is about $2; the
pessimistic case is about $6. Storage and egress are free at these sizes on
the same page. These are the vendor's list prices for one vendor on one day;
they are a scale, not a quote.

## What a dynamic confirmation would change about the grade

Less than it sounds like, and the memo should say so before anyone sells it.

- It changes exactly one field: `record_dynamic` goes from `None` to a dict
  with `observed` true or false. The verdict does not move. The static gates
  do not move. The badge grows a second record row that says "record observed
  by runner" or "no record observed by runner"; the static row stays what the
  bytes said. A reader who sees both rows learns whether the write the scanner
  found actually fired for one call under one configuration.
- What it proves: this server, started this way, with this environment,
  wrote a row for this one call. That closes the optional-import blind spot
  (the write exists in source but is skipped when a dependency is absent) for
  that configuration, and it catches the "recorder is wired but never
  called" case the static check cannot see.
- What it does not prove: that every tool records, that recording survives a
  different config or a failed call, that the row is complete or
  tamper-evident (those are still the static gates), or anything about the
  other checks. One call is one sample. A server that records the first call
  and drops the rest passes.
- A DISAGREE (static says presence, runner sees nothing, or the reverse) is
  the interesting outcome and should be surfaced as its own finding rather
  than folded into either row: the static read was wrong about these bytes,
  and that is a scanner bug or a blind spot with a name.

The probe found five agrees and zero disagrees on our own servers (appendix).
That is the expected result for code written to pass this exact check; it is
not evidence about the ecosystem.

## The question for Daniel

Do you want the runner built at all before there is a paying user asking for
runtime evidence, and if so, on this box behind WSL2 for zero dollars or on a
hosted sandbox at roughly $0.002 to $0.006 per server?

## Appendix: own_five probe, 2026-09-02

Run: `py projects/mcp_vet/scripts/own_five_probe.py` at 16:32 PDT, mcp_vet
0.0.17, Python 3.14.3, stdio only, 30 s budget per server, every record file
pointed at a scratch directory. All grades are of the WORKING TREE, UNPUBLISHED.
"yes" means a row naming the called tool was readable from the record file
after the call and was not there before it.

| server (working tree, unpublished) | static gate (record_static) | dynamic record observed | agree |
|---|---|---|---|
| arcaeon-ledger | 4/4 gates, presence=True | yes (verify_peer_ledger) | agree |
| arcaeon-distill | 4/4 gates, presence=True | yes (distill_tool_output) | agree |
| arcaeon-once | 4/4 gates, presence=True | yes (guard_side_effect) | agree |
| arcaeon-continuity | 4/4 gates, presence=True | yes (continuity_snapshot) | agree |
| arcaeon_connector | 4/4 gates, presence=True | yes (arcaeon_status) | agree |

All five launched headless. Wall time, launch to readback: ledger 0.31 s,
distill 0.21 s, once 0.40 s, continuity 0.30 s, connector 3.02 s. Record
locations used: ledger's `--log` sidecar (`<log>.calls.jsonl`); distill, once,
continuity, and the connector via `$ARCAEON_CALL_RECORD`. The connector's
`arcaeon_status` handler records because of the same-day K34/K37/K38 work
that put `_record_call` at the end of every handler; before that change the
probe would have had to call `vet_scan` to see a row.
