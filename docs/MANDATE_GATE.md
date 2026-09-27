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

## Record-only and block

| | record-only (default) | `--mandate-enforce` |
|---|---|---|
| outside call | forwarded; `mandate_outside` row, `action: forwarded` | not forwarded; the agent gets a JSON-RPC error (code -32001); `mandate_outside` row, `action: blocked` |
| could-not-look call | forwarded; `mandate_could_not_look` row | not forwarded; JSON-RPC error; row, `action: blocked` |
| mandate file missing or unreadable | the proxy starts; every call gets a `mandate_could_not_look` row; nothing is ever blocked | the proxy refuses to start and exits 3 (COULD NOT LOOK) |

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

`session_end` carries `mandate_inside`, `mandate_outside`,
`mandate_could_not_look` and `mandate_blocked` counts when a mandate was given.

## What it does not prove

- It does not prove the person behind `who` wrote or approved the mandate. It
  proves which file was in force (by hash) and what each call was checked
  against. Pair it with a deal mandate row, pinned by a witness, for when.
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
