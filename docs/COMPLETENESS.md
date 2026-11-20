# Did everything get written?

`arcaeon verify` tells you nothing in a record was changed after it was
written. It cannot tell you the record is complete, because whoever writes a
record decides what goes in it. For tool calls there is a way to check: a call
has two ends, so keep a tape at each end and line the two tapes up.

## 1. Run the proxy in front of the server

Wrap the MCP server's command in `arcaeon proxy`. The agent talks to the proxy
exactly as it talked to the server; the proxy passes every byte through and
writes one tape row per `tools/call`.

```bash
arcaeon proxy --ledger seam.jsonl --tape agent.tape.jsonl -- <your server command>
```

In an MCP client config, that means putting `arcaeon proxy --ledger ...
--tape ... --` in front of the server's own command.

## 2. Keep the server's own tape

The other tape is written at the server, by the server's side, about the
calls it received. Two ways:

- The server writes it. One object, two calls:

  ```python
  from arcaeon.record.adapter.tape import TapeWriter

  tape = TapeWriter("tool.tape.jsonl", side="tool")
  idx = tape.open_call(params, rpc_id)   # when a tools/call arrives
  tape.close_call(idx, response)         # with the response you send
  tape.flush()                           # at shutdown
  ```

- Or wrap the server where it runs with a second proxy:
  `arcaeon proxy --side tool --ledger tool.seam.jsonl --tape tool.tape.jsonl -- <server command>`.

Both tapes hold digests of each request and response, not the payloads.

## 3. Run reconcile

```bash
arcaeon reconcile agent.tape.jsonl tool.tape.jsonl
```

It prints JSON and exits with a code you can script on.

## What each answer means

| Answer | Exit | Means |
|---|---|---|
| MATCHED n of n | 0 | Every call on either tape is on the other, with the same request and the same response. |
| MISSING | 1 | A call is on one tape and not the other. `at` is the call number, `index_side` says whose numbering that is, and `side` names the tape that is short. A call sent straight to the server, around the proxy, shows up here: it is on the server's tape and not the proxy's. |
| ALTERED | 1 | Both tapes have the call and disagree about it, or a tape does not check out against itself (for example, a row edited after it was written). `at` is the call. |
| COULD NOT LOOK | 3 | A tape is not there, cannot be opened, or cannot be read without guessing. The reason says which file and why. It is never a pass. |

Any finding beats COULD NOT LOOK: if reconcile could look at enough to see a
MISSING or ALTERED call, it says so.

## The one limit

A call that neither tape saw is invisible here. If the agent reaches the tool
by a route that has no proxy in front of it and the server keeps no tape for
it, both tapes are silent about that call and they still agree. Reconcile can
only compare what was written down at the two ends.

For a record that was written down, chain pinning closes the gap at the other
end: run the proxy with `--pin-witness URL` (key in `ARCAEON_WITNESS_KEY`) and
the tape's head is pinned at the witness when the session ends. Every pin
carries a sequence number at the witness, so a record dropped later leaves a
gap. `arcaeon reconcile ... --pin PIN` holds a tape against its pin: fewer
rows than pinned is MISSING, a different head is ALTERED.

The proof of all four answers, end to end through the real `arcaeon proxy`
and `arcaeon reconcile`, is `tests/completeness/test_proxy_reconcile_e2e.py`.
