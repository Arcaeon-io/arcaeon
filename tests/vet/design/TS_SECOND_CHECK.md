# TS second check: `secret-in-code` vs `unsafe-exec` (M14 memo, 2026-09-02)

Status: memo only. Nothing here is implemented. The 0.0.17 TypeScript front end
runs exactly one check (`audit-record`); this note decides which of the two
obvious candidates should be the second tree-sitter port, or whether to hold.

The task named the exec candidate `exec-sink`; the registered check name in
`mcp_vet/checks.py` is `unsafe-exec`. Same thing; the memo uses the real name.

## What the two checks are, in Python today

`secret-in-code` (MCP01). Walks every string constant. Three classes:
(1) vendor-shaped literals (`_VENDOR_SHAPES`: AWS `AKIA`/`ASIA`, Stripe
`sk_live_`/`rk_live_`/`whsec_`, OpenAI `sk-`/`sk-proj-`/`sk-svcacct-`, GitHub
`gh?_`/`github_pat_`), (2) a high-entropy literal bound to a secret-looking name
(`_named_string_constants` maps the constant to its assignment target, dict key,
or keyword-argument name; `_is_secret_name` + `_looks_like_a_live_secret` gate
on length 16, no whitespace, letters and digits, placeholder vocabulary, Shannon
entropy 3.5), (3) `NAME=value` env-shaped lines quoted inside multi-line
literals and comments (`_env_line_findings`, `_comments` via `tokenize`).
Public shapes (`sk_test_`, `pk_live_`, ...) are never flagged. Redaction on
output is mandatory.

`unsafe-exec`. Resolves every call through the file's import map
(`_import_bindings` + `_canon_call`, so `from os import system` and
`import os as o` both land on `os.system`), then matches: builtin `eval`/`exec`,
the `os.system/popen/exec*/spawn*` family, `pty.spawn`, any `subprocess.*` with
`shell=True` or a `[sh, -c, ...]` first argument, and the dynamic-import dodge
(`__import__("os").system`). Severity is high on sight; there is no taint gate
(the check does not ask whether the argument came from tool input; that is a
known precision cost, documented in FALSE_POSITIVES.md).

## Effort to port each

### `secret-in-code` to tree-sitter

Node types needed: `string` / `template_string` (with `string_fragment`
children; a template with `template_substitution` children is not a literal and
should be skipped or treated as prose), `comment`, and for the name binding:
`variable_declarator` (name + value), `pair` inside `object` (key
`property_identifier` or `string`), `assignment_expression` with a
`member_expression` left side (`config.apiKey = "..."`), and `property_signature`
/ `public_field_definition` for class fields. There are no keyword arguments in
JS; the nearest equivalent is the object-literal `pair`, already covered.

What ports unchanged: everything that is a function of the string value.
`_VENDOR_SHAPES`, `_PUBLIC_PREFIXES`, `_entropy`, `_looks_like_a_live_secret`,
`_is_secret_name`, `_AWS_*`, `_ENV_LINE_RE`, `_env_line_findings`, `_redact`.
That is roughly 80 percent of the check by line count and 100 percent of the
precision logic. The only new code is the tree-sitter equivalent of
`_named_string_constants` (maybe 40 lines) and a comment collector (tree-sitter
hands us `comment` nodes directly, so the `tokenize` workaround goes away; a
`#` inside a string is not a problem the TS grammar has).

Effort: small. One afternoon, one fixture set (vendor literal, named entropy
literal, env line in a template string, env line in a `//` comment, the
`sk_test_` non-finding, a placeholder non-finding).

Line numbers: tree-sitter gives `start_point` per node, so `_offset_line` maps
directly for multi-line template strings.

### `unsafe-exec` to tree-sitter

Node types needed: `call_expression` with `identifier` or `member_expression`
callee, `new_expression` (for `new Function(...)`), `import_statement`
(`import { exec } from "child_process"`, `import cp from "node:child_process"`,
`import * as cp`), `require` destructuring (`const { execSync } = require(...)`,
`variable_declarator` + `object_pattern`), `arguments` + `object` + `pair` for
`{ shell: true }`, `array` first-argument for the `["sh", "-c", cmd]` shape,
plus `await_expression` and `promisify(exec)` wrapping.

The sink table is entirely new and larger than Python's: `eval`, `new Function`,
`setTimeout`/`setInterval` with a STRING first argument, `vm.runInThisContext` /
`vm.runInNewContext` / `vm.Script`, `child_process.exec` / `execSync` (always a
shell), `spawn` / `spawnSync` / `execFile` / `execFileSync` / `fork` with
`shell: true` or a shell binary as the file, `worker_threads.Worker` with
`eval: true`, and `Deno.Command` / `Bun.spawn` if we count non-Node runtimes.
The `node:` prefix has to be normalized (`node:child_process` and
`child_process` are one module). `shelljs` and `execa` are popular wrappers that
would want their own rows or a documented blind spot.

What ports: the SHAPE of `_import_bindings` + `_canon_call` (resolve the callee
through the import map, then table-match), and the `_first_arg_is_shell_list`
idea. 0.0.17 already has `_imports(root)` in `ts_checks.py` for the audit-record
sibling resolver, so the import map exists; it would need to learn bare
`require("child_process")` module aliasing on top of destructuring. None of the
Python sink strings port; every row is re-derived for Node.

Effort: medium. Two to three sittings if the goal is precision parity with the
Python check, because the Node sink surface is wider and the wrapper ecosystem
(`execa`, `shelljs`, `zx`) is where real servers actually shell out. A
narrow first cut (eval / new Function / child_process.exec* / spawn with
shell: true) is one sitting but ships with a bigger blind-spot list.

## What a stranger learns from each

`secret-in-code` on TS: "does this server ship a credential in its source." The
answer is the same kind of fact in both languages, the false-positive story is
already written (FALSE_POSITIVES.md, the public-prefix and placeholder gates),
and the finding is five-second verifiable by anyone: open the file, look at the
line. It is also the check every other scanner already does, so it does not
differentiate us; a stranger learns something true but not something new.

`unsafe-exec` on TS: "can a tool call reach a shell." This is the check a
skeptic actually cares about for an MCP server, and the TS ecosystem is where
most public MCP servers live (the 2026-09-02T2142Z bench summary's
`gate_by_lang` graded 22 TS targets against 13 Python; the Python battery has
never looked at the 22). A stranger learns
something they cannot get from a Python-only grader and cannot get from the
audit-record check. The cost is that without a taint gate it fires on every
`execSync("git status")`, which in TS servers is common and mostly benign; the
Python check carries the same cost and we accepted it there, but a TS port
doubles the surface it lands on.

## Decision

Port `secret-in-code` second, and hold `unsafe-exec` for a cut that ships WITH
a handler-parameter taint gate (the Python check does not have one; the TS port
should not inherit that debt onto a larger surface).

One line: `secret-in-code` first, because ~80 percent of it ports unchanged and
its false-positive story is already paid for, while `unsafe-exec` on Node is a
new sink table plus a wrapper ecosystem and is only worth shipping once the
walk can say whether the command came from tool input.

Not decided here: whether the taint gate for TS `unsafe-exec` reuses the
`_reachable` walk from `ts_checks.py` (handler params to call arguments). It
probably should; that is a separate memo when the port is scheduled.
