# The mandate gate

    arcaeon-adapter --ledger seam.jsonl --mandate mandate.json -- <server command...>

A reader asked whether the proxy captures approvals or only calls. Until this
gate, only calls: the seam log said what the agent did, and nothing on the
tape said what the agent was allowed to do. The mandate gate joins the two. It
loads a mandate file (the same body the deal lane writes with
`arcaeon deal mandate`, or the tool-shaped form below), checks every
`tools/call` that crosses the proxy against it, and writes a ledger row when a
call falls outside.

**The default is record-only.** A call outside the mandate is still forwarded
to the server, exactly as the agent sent it. The gate is the first feature in
this package that could stop a customer's agent from working, so stopping is
something you turn on, never something you get.

## Where the gate runs

Three surfaces take `--mandate PATH`, and all three judge calls with the same
code (`_MandateWatch` in `arcaeon.record.adapter.proxy`), so the rows are the
same on each:

| surface | how to start it | where the mandate rows go |
|---|---|---|
| stdio proxy | `arcaeon proxy --ledger seam.jsonl --mandate mandate.json -- <server command...>` | the seam ledger, `--ledger` |
| HTTP forward proxy | `arcaeon proxy --ledger seam.jsonl --mandate mandate.json --http-forward URL --listen 127.0.0.1:PORT` | the seam ledger, `--ledger` |
| call_proxy (receipts) | `python -m arcaeon.record.receipt.call_proxy --upstream URL --mandate mandate.json` | a seam-format log of its own, `--mandate-log` (default `<ledger>.mandate.jsonl`); the receipt ledger is untouched |

Every surface is record-only unless `--mandate-enforce` is passed.
`tests/test_mandate_default_record_only.py` finds each surface by reading the
source for `--mandate`, and fails if one forwards nothing, writes no row, or
has no entry in its list.

## The mandate

One JSON object. Every field is optional; a field left out constrains nothing.

```json
{
  "who": "purchasing-agent@acme",
  "allowed_acts": ["search_*", "get_quote", "place_order"],
  "forbidden_acts": ["delete_*", "refund"],
  "spend_cap": {"amount": "60.00", "currency": "USD", "merchant": "acme-store"},
  "not_before": "2026-09-01T00:00:00Z",
  "not_after": "2026-12-31T23:59:59Z"
}
```

| field | what it means |
|---|---|
| `who` | the principal this mandate speaks for. Recorded in every mandate row. The gate does not check it: the proxy cannot see who is behind the agent. |
| `allowed_acts` | tool names the agent may call. Shell-style patterns (`search_*`). Absent or empty: any tool not forbidden. |
| `forbidden_acts` | tool names the agent may not call. Checked first; a forbidden name is outside even when it is also allowed. |
| `spend_cap` | `amount` (a string, the most one call may spend), `currency`, and optionally `merchant` and `total`. |
| `spend_cap.total` | optional: the most the whole session may spend (a string). See "The session total" below. |
| `not_before`, `not_after` | the time window, ISO 8601. A call outside it is outside. |

A **deal-lane mandate** works as-is. `{merchant, cap, currency, not_before,
not_after, may, may_not}` reads as `spend_cap = {amount: cap, currency,
merchant}`, `allowed_acts = may`, `forbidden_acts = may_not`. The sealed
sidecar `arcaeon deal mandate --sealed` writes (`{"deal", "mandate_digest",
"mandate": {...}}`) is unwrapped too, so the file that proves what the buyer
authorized is the file the proxy checks against.

### Which calls are spends

A call spends when its arguments carry an amount under one of the names in
`spend_cap.amount_args` (default `total`, `amount`). Its currency and merchant
are read from `currency_args` (default `currency`) and `merchant_args`
(default `seller`, `merchant`). A spend is judged by the deal lane's own
`check_mandate`, imported, not copied: merchant, currency, cap and window, in
that order, and the first rule broken is the reason. A call that carries no
amount is not a spend and is checked against names and the window only.

### The session total

`spend_cap.total` (optional) caps the whole session, not one call:

```json
{"spend_cap": {"amount": "60.00", "total": "100.00", "currency": "USD"}}
```

The gate keeps a running total of the spends that were forwarded. A spend
that is inside on its own terms but would take the total past `total` is
outside, rule `spend_cap.total`, and is written as a `mandate_cap_exceeded`
row carrying `amount`, `session_spent_before`, `session_spent` and
`session_total_cap`. Record-only, the call is still forwarded and its amount
still counts, so every later spend in the session is over too and gets its
own row. Under `--mandate-enforce` it is blocked, and a blocked spend adds
nothing to the total. The per-call `amount` check is unchanged and runs first;
with `total` and no `amount`, one call may spend up to the total.
`session_end` carries `mandate_cap_exceeded` (a count) and `mandate_spent`.

## The three answers

Every `tools/call` gets one of:

- **inside**: nothing in the mandate says no. No row of its own; the count
  rides in `session_end` as `mandate_inside`.
- **outside**: a rule says no. One `mandate_outside` row, naming the rule.
- **could not look**: something needed to decide could not be read (the
  mandate file, an amount, a time). One `mandate_could_not_look` row with
  `looked_for`, `where` and `reason_word`, the same keys every Arcaeon
  COULD NOT LOOK carries. Never counted as inside.

## The five outcomes

The verdict says what the gate answered. Every gate row also carries
`outcome`, which says what happened to the call, in exactly one word:

- `inside`: the gate looked and nothing said no; the call went through.
  Counted, not rowed.
- `outside_forwarded`: record-only. The gate said no and the call went
  through anyway.
- `blocked`: enforce. The gate ran and said no, and the call was withheld.
- `never_attempted`: the call never reached the gate's judgment. Either it
  was refused before the gate (a frame too big to judge, or a request that is
  not JSON, under enforce), and `reason` starts `refused before the gate:`;
  or the gate could not run because the mandate file could not be read (at
  start, or because it vanished mid-run), and `reason` starts `the gate
  could not run:`.
- `could_not_look`: the gate ran, but something it needed (an amount, a time,
  the call's name) could not be read. `action` says whether the call went
  through.

`verdict` and `action` stay on every row as before; `outcome` is the one word
a reader can count without combining them. `arcaeon mandate explain` prints
the five words with one line each.

### Calls no rule matched (`no_matching_mandate`)

A call no rule of the mandate matched at all is drift, and it is counted
apart from a call a rule matched and refused. It is either outside because
its tool name matches no `allowed_acts` pattern, or inside by default because
the mandate has no `allowed_acts` list and no `forbidden_acts` or
`spend_cap` rule applied to it. A rowed one carries `no_matching_mandate:
true`; the session total rides in `session_end` as
`mandate_no_matching_mandate`, and the evidence pack's `mandate_rows.json`
carries the window's total as `no_matching_mandate` (with `outcomes`, the
outcome words of its rowed calls). A call refused by `forbidden_acts`, a
spend cap or the window is not in it: a rule matched it.

## Record-only and block

| | record-only (default) | `--mandate-enforce` |
|---|---|---|
| outside call | forwarded; `mandate_outside` row, `action: forwarded` | not forwarded; the agent gets a JSON-RPC error (code -32001); `mandate_outside` row, `action: blocked` |
| could-not-look call | forwarded; `mandate_could_not_look` row | not forwarded; JSON-RPC error; row, `action: blocked` |
| request that is not JSON (HTTP surfaces) | forwarded; `mandate_could_not_look` row, `judged_reason: unparsed` | not forwarded; JSON-RPC error with id null; row, `action: blocked` |
| line that is not JSON (stdio) | forwarded; row, `judged_reason: unparsed` | forwarded byte-identical (nothing in it is a call); row, `action: forwarded` |
| mandate file missing or unreadable | the proxy starts; every call gets a `mandate_could_not_look` row, `outcome: never_attempted`; nothing is ever blocked | the proxy refuses to start and exits 3 (COULD NOT LOOK) |
| mandate file vanishes mid-run | each later call gets a `mandate_could_not_look` row, rule `mandate_file`, `outcome: never_attempted`; forwarded | the same row; the call is withheld |

### Before you turn on `--mandate-enforce`

Enforce stops your agent. A pattern that is one character wrong, a spend
field under a name the gate does not read, or a window that closed yesterday
turns into refused calls in the middle of real work, and the agent sees a
JSON-RPC error it may not handle. So:

1. Run record-only first, on real traffic, and read the `mandate_outside`
   and `mandate_could_not_look` rows. Every one of them is a call enforce
   would have refused.
2. `arcaeon mandate lint` and `arcaeon mandate explain` the file, and
   `arcaeon mandate check` the calls you expect.
3. Only then add `--mandate-enforce`. With a mandate it cannot read, enforce
   refuses to start (exit 3) rather than run with nothing to enforce.

Enforce blocks only on the seam it sits on, and a changed mandate file is not
picked up until the session restarts (the `mandate_changed` row says so).

Enforce mode holds each client frame until its newline arrives, so it can look
before it forwards. Record-only never holds anything: bytes go first and the
check reads a copy, the same fidelity rule as the rest of the proxy.

A blocked call still leaves its `tool_call` row, paired with the error the
proxy sent back, so the seam log shows the attempt and the answer. On a
two-sided tape the tool side never saw the call, and reconcile says MISSING
there, which is what happened.

## The rows it writes

The session's first row, `session_begin`, pins the mandate in force:

    "mandate": "mandate.json",
    "mandate_mode": "record-only",
    "mandate_status": "loaded",
    "mandate_file_sha256": "<hex>",
    "mandate_file_digest": "sha256:raw-bytes:v1:<hex>",
    "mandate_body_digest": "sha256:json-c14n:v1:<hex>"

`mandate_file_sha256` is the sha256 of the file's bytes. `mandate_body_digest`
is the digest the deal lane uses for the same body, so a proxy session can be
matched to the deal row that recorded the authorization. `--policy FILE`
(repeatable) adds `policy_pins` beside it: path, byte count and sha256 of each
system prompt or policy file. Hashes only; the contents never reach the ledger.

Each outside call:

    {"evt": "mandate_outside", "verdict": "outside", "rule": "forbidden_acts",
     "reason": "tool 'refund' matches forbidden_acts pattern 'refund'",
     "tool": "refund", "rpc_id": "7", "args_digest": "sha256:json-c14n:v1:...",
     "who": "purchasing-agent@acme", "mandate_file_sha256": "<hex>",
     "mandate_mode": "record-only", "action": "forwarded", ...seam fields}

Right after `session_begin`, when a mandate loaded, a `mandate_loaded` row
names the file (`mandate`, `mandate_status`, `mandate_file_sha256`,
`mandate_body_digest`, `who`, `mandate_mode`). Before each judged call the file
is hashed again; if its bytes moved, a `mandate_changed` row carries
`from_sha256`, `to_sha256`, `file_status` and `judged_against_sha256`. The gate
keeps judging against the mandate it loaded at start: the row says the file
moved, it does not reload it. Restart the session to judge against the new
file. A file that is gone or unreadable is different: the gate will not judge
against a mandate nobody can show, so every call after that is
could_not_look, rule `mandate_file`, `outcome: never_attempted`.

A request the gate cannot parse gets a `mandate_could_not_look` row with
`judged_reason: "unparsed"`, never a silent pass.

`session_end` carries `mandate_inside`, `mandate_outside`,
`mandate_could_not_look` and `mandate_blocked` counts when a mandate was given,
plus `mandate_cap_exceeded`, `mandate_changes`, `mandate_no_matching_mandate`
and `mandate_spent` when there was any.

## Check a mandate before an agent runs under it

`arcaeon mandate` reads the same file the gate reads and forwards, blocks and
writes nothing. With the example above saved as `mandate.json`:

```console
$ arcaeon mandate lint mandate.json
mandate.json: valid (tool shape, 0 problem(s), 0 warning(s))
(exit 0)
$ arcaeon mandate explain mandate.json
This mandate speaks for purchasing-agent@acme. The gate records that name on every row; it does not check it, because it cannot see who is behind the agent.
This agent may call search_*, get_quote and place_order.
It may not call delete_* or refund, even where an allowed pattern also matches.
One call may spend at most 60.00 USD, and only with acme-store.
A call counts as a spend when its arguments carry total or amount.
It holds from 2026-09-01T00:00:00Z until 2026-12-31T23:59:59Z.
Record-only unless the proxy is started with --mandate-enforce: a call outside this mandate is still forwarded, and the ledger gets a row naming it.
Each call the gate sees ends as one of five outcomes (the row's `outcome`):
inside: the gate looked and nothing in the mandate said no; the call went through.
outside_forwarded: record-only: the gate said no and the call went through anyway.
blocked: enforce: the gate ran and said no, and the call was withheld from the tool.
never_attempted: the call never reached the gate's judgment: it was refused before the gate, or the mandate file could not be read (`reason` says which).
could_not_look: the gate ran but something it needed to decide (an amount, a time, the call itself) could not be read; never counted as inside.
(exit 0)
$ arcaeon mandate check mandate.json --field name=place_order --field total=19.00 --field currency=USD --field seller=acme-store --at 2026-10-01T12:00:00Z
inside: spend: seller, currency, cap and window are inside the mandate
(exit 0)
$ arcaeon mandate check mandate.json --field name=refund --at 2026-10-01T12:00:00Z
outside: tool 'refund' matches forbidden_acts pattern 'refund'
(exit 1)
$ arcaeon mandate check mandate.json --field name=place_order --field total=75.00 --field currency=USD --field seller=acme-store --at 2026-10-01T12:00:00Z
outside: spend: total 75.00 is over the mandate's cap 60.00
(exit 1)
$ arcaeon mandate check mandate.json --field name=get_quote --at 2027-01-05T00:00:00Z
outside: call at 2027-01-05T00:00:00Z is after the mandate's not_after 2026-12-31T23:59:59Z
(exit 1)
$ arcaeon mandate check missing.json --field name=get_quote
could not look: the mandate could not be read: no file at missing.json
(exit 3)
```

`(exit N)` is the exit code, not output. `lint` exits 2 on an invalid mandate
and names each unknown key or bad type. `check` answers the gate's word:
inside 0, outside 1, could_not_look 3. `--field KEY=VALUE` needs no JSON
quoting (so it survives PowerShell); `KEY:=JSON` keeps a type. `--spent A`
says what the session already spent, for `spend_cap.total`. `--json` prints
the answer as one object.

The same check over HTTP (`arcaeon serve`) and MCP answers the same object
plus an integer `exit`:

```http
POST /v1/mandate/check
{"mandate": "mandate.json", "fields": {"name": "refund"}, "at": "2026-10-01T12:00:00Z"}
```

```mcp
mandate_check
{"mandate": "mandate.json", "fields": {"name": "refund"}, "at": "2026-10-01T12:00:00Z"}
```

Both answer `"verdict": "outside"`, `"rule": "forbidden_acts"`, `"exit": 1`.
A verdict never rides in the HTTP status: inside, outside and could not look
all come back as 200. The MCP tool `mandate_check` is free and, like every
connector tool, leaves one row in the connector's call record.

## Counts in `arcaeon status`

When a gated session ends, on any of the three surfaces, it adds one line to
`~/.arcaeon/mandate_sessions.jsonl` (or under `$ARCAEON_HOME`; off with
`ARCAEON_JOURNAL=0`): the session id, the mode, the mandate file's sha256 and
the counts, never a path, a tool name or an argument. `arcaeon status` adds
them up (`status --json` under `mandate`: `sessions`, `inside`, `outside`,
`could_not_look`, `blocked`, `cap_exceeded`, `changes`). The seam ledger stays
the record; the session id in each line is the one in that ledger's rows.

## What it does not prove

- It does not prove the person behind `who` wrote or approved the mandate. It
  proves which file was in force (by hash) and what each call was checked
  against. Pair it with a deal mandate row, pinned by a witness, for when.
- `arcaeon mandate check`, `POST /v1/mandate/check` and the MCP tool
  `mandate_check` judge the call you describe to them. They do not see what an
  agent actually sends; only a proxy on the seam does.
- Without `spend_cap.total` the spend cap is per call, so ten calls at the cap
  each read inside. The total counts only what crossed this seam, in the one
  session: a new session starts at zero. Under `--mandate-enforce`, calls
  sent together in one batch frame are each judged against the total as it
  stood before that frame.
- It reads tool names and arguments. A tool whose name says `get` and whose
  server spends money anyway is inside by name; the gate cannot see what a
  server does.
- It covers the one seam it sits on. A call that goes around the proxy is not
  checked and leaves no row, the same limit the adapter has always stated.
- Record-only is a record, not a control: an outside call was forwarded and
  ran. Only `--mandate-enforce` stops anything, and only on this seam.
- The ledger it writes is tamper-evident (the hash chain shows a changed row),
  which is not the same as true: a writer who controls the machine can write a
  different ledger from the start.
