# The verify-before-act gate behind OPA

If your agent stack already asks [Open Policy Agent](https://www.openpolicyagent.org/)
whether to do something, the arcaeon gate can be one more policy there. The
policy is [`policies/opa/arcaeon_gate.rego`](../policies/opa/arcaeon_gate.rego):
about twenty lines of Rego, package `arcaeon.gate`, deny by default. It reads
the JSON report `arcaeon envelope verify` prints ([ENVELOPE.md](ENVELOPE.md))
and the action the agent is about to take, and answers `allow` and `reason`.

arcaeon does not ship or run OPA. You run `envelope verify` yourself, hand its
report to OPA, and OPA applies the table below.

## The rule table

| verdict in the report | `read` | `act` | `pay` | `irreversible` |
|---|---|---|---|---|
| VERIFIED | allow | allow | allow | allow |
| COULD NOT LOOK | allow | refuse | refuse | refuse |
| BROKEN | refuse | refuse | refuse | refuse |
| anything else, or no verdict | refuse | refuse | refuse | refuse |

An action outside the four is refused. The verdict words are matched exactly
as the verifier prints them (`COULD NOT LOOK` with its spaces, upper case); a
lower-case `verified` is not VERIFIED.

## The input document

```json
{
 "report": { "...": "the whole JSON object `arcaeon envelope verify` printed on stdout" },
 "action": "read"
}
```

The policy reads only `input.report.verdict` and `input.action`. Pass the whole
report anyway: its `findings`, `not_checked` and `does_not_prove` are what a
person reads when they ask why.

## Wiring it

```console
$ arcaeon envelope verify grades.csv --audience instructor-1 --signer did:key:z6Mk... > report.json
$ python -c "import json; print(json.dumps({'report': json.load(open('report.json')), 'action': 'pay'}))" > input.json
$ opa eval --format pretty --data policies/opa/arcaeon_gate.rego --input input.json data.arcaeon.gate
```

`envelope verify` always prints the JSON report on stdout (there is no
separate `--json` flag) and its word and reason on stderr; its exit code (0, 1
or 3) is the same verdict and is not needed here. Query `data.arcaeon.gate.allow`
for the boolean alone.

## What it answers for each verdict

VERIFIED, action `pay`:

```json
{"allow": true, "reason": "allowed: VERIFIED permits pay"}
```

COULD NOT LOOK (for example signed, but no `--signer` named), action `read`
and then `pay`:

```json
{"allow": true, "reason": "allowed: COULD NOT LOOK permits read"}
{"allow": false, "reason": "refused: COULD NOT LOOK allows read only, not pay"}
```

BROKEN (for example the file's bytes changed after sealing), any action:

```json
{"allow": false, "reason": "refused: BROKEN refuses every action"}
```

No verdict, or a word the gate does not know:

```json
{"allow": false, "reason": "refused: the report has no verdict this gate knows (missing or unknown)"}
```

An action outside the four, say `delete`: `refused: unknown action delete`.

## Syntax

The policy is written for OPA v1 Rego: rule bodies open with `if`, `in` is a
keyword with no import, `default allow := false`, and `reason` is one rule with
an `else` chain over a `default`. Checked against the OPA policy-language
reference, <https://www.openpolicyagent.org/docs/policy-language> (fetched
2026-10-04). It has no `import rego.v1` line; it targets OPA 1.x, and an
older 0.x release would need its v1-compatible mode to read it.

## Honest limits

- **allow means unchanged and labeled, never true.** VERIFIED says the bytes
  are the bytes the key you named sealed, for this receiver, in date. It says
  nothing about whether the content is true or safe; a sealed file can carry a
  lie or a prompt injection. See
  [What VERIFIED does not prove](ENVELOPE.md#what-verified-does-not-prove).
- **The policy trusts the report it is handed.** OPA does not run the
  verifier and cannot tell a real report from a typed one. Whatever builds the
  input must run `envelope verify` itself, on the same file the action will use,
  right before the action; a report saved earlier, or for another file, gates
  nothing.
- **The report is only as strict as the verify call.** Without `--deal` or
  `--purpose` a report can still read VERIFIED (they are listed under
  `not_checked`). The policy does not look at `not_checked`; pass them to
  `verify` if the action depends on them.
- **COULD NOT LOOK allows `read`.** That is reading the file, not acting on
  it. If your `read` itself has side effects, map it to `act`.
- **One action, one decision.** The policy does not remember what was already
  acted on; replay inside one envelope's binding is the receiver's to stop.
- **No OPA binary is tested here by default.** The test suite holds the policy
  text to its shape and runs a Python mirror of the table over real verify
  reports for all twelve cells; it runs `opa eval` and compares only when an
  `opa` binary is on PATH.
