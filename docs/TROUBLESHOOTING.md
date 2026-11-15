# Troubleshooting

Every message arcaeon can show you when something goes wrong or is refused,
what it means in plain words, and what to do next. It is written from the
code: each message below is what the code prints, with the parts that change
from run to run shown in angle brackets, like `<path>`.

If a message is not here, run the same command with `--help`, or `arcaeon
doctor`, and see the section "If nothing here fits" at the end.

## How to read any answer

**The exit code** is the same table for every verb:

| Exit | Means | What to do |
|---|---|---|
| 0 | Done, and nothing wrong was found. | Nothing. |
| 1 | A check found something wrong (BROKEN, MISSING, ALTERED), or a refusal that is about your data. | Read the message: it names the line, the row or the field. |
| 2 | Bad usage: a missing argument, an unknown option, a value of the wrong kind. Nothing was checked or written. | Fix the command as the message says; `arcaeon <verb> --help` shows the usage. |
| 3 | COULD NOT LOOK: nothing wrong was found, but not everything could be checked. It is never a pass. | Read `reason_word` and `reason`, fix what stopped the look, and run it again. |

**The verdict words** (VERIFIED, BROKEN, COULD NOT LOOK, MATCHED, MISSING,
ALTERED, NO GRADEABLE FILES, COMPARED) are explained in docs/WORDS.md.

**A COULD NOT LOOK answer** in JSON carries four fields that say what stopped it:

```json
{"ok": false, "verdict": "COULD NOT LOOK", "looked_for": "...", "where": "...", "reason_word": "...", "reason": "..."}
```

`looked_for` is what the check wanted, `where` is where it looked, and
`reason_word` is one of these:

| reason_word | Means | What to do |
|---|---|---|
| `missing` | It was not there at all. | Check the path or name. |
| `unreadable` | It was there but could not be read: permissions, not text, not valid JSON, or not the kind of file expected. | Check the file; `reason` says what was wrong with it. |
| `empty` | It was there and held nothing to check. | Add rows first, or point at the right file. |
| `name_not_found` | It was read, but the name the check needed (a namespace, a key) was not in it. | Pass the right name, often with `--ns`. |
| `bounded` | Only part of it could be checked, for example rows that carry no chain. | `reason` says which part; a pin can cover rows the chain cannot. |
| `network` | A request never completed. | Check the network, then run it again. |
| `redirect_refused` | An address redirected elsewhere and arcaeon did not follow it. | Use the final address directly. |

Many verbs also print the same thing as one line on stderr:
`looked for: <looked_for>; where: <where>; reason_word: <reason_word>`.

## Messages any verb can show

| Message | What it means | What to do |
|---|---|---|
| `arcaeon: unknown verb '<verb>'` and the help text | The first word is not a verb arcaeon knows. Exit 2. | Pick a verb from the list printed under it. |
| `arcaeon: <message>` | A usage refusal; the message says what is wrong. Exit 2. | Fix the arguments as it says. |
| `arcaeon <verb>: could not finish: <ExceptionName> [internal_error]` | Something inside the verb failed in a way it did not expect. Only the kind of failure is shown, never a traceback, so no path or value leaks. Exit 3: it is never read as a pass. | Run it again; if it repeats, run `arcaeon doctor` and report the line, the verb and the arguments. |
| `arcaeon <verb>: not built in this checkout` | That verb's code is not in this install. Exit 2. | Install or upgrade to a version that has the verb (`arcaeon version`). |
| `arcaeon: no verb and stdin is not a terminal, so starting the MCP server (the pre-0.9 behaviour). Use `arcaeon mcp`; this fallback is removed in 1.0.0.` | A program ran plain `arcaeon` with no verb and a pipe, the way old MCP client settings did, so arcaeon started the MCP server for it. This is a notice, not a failure. | Change that client's settings to run `arcaeon mcp`. |
| A verb that answers with an old tool's exit code | You passed `--legacy-exit`, which keeps the exit codes of the separate tools arcaeon replaced. | Move your checks to the 0, 1, 2, 3 table before 1.0.0, then drop the flag. |

## log

| Message | What it means | What to do |
|---|---|---|
| `usage: arcaeon log <ledger.jsonl> '<json object>' \| - \| --field KEY=VALUE ...` | No ledger was named, or no row was given. Exit 2. | Name a ledger file and give the row as JSON, as `-` for stdin, or as `--field KEY=VALUE`. |
| `arcaeon: log: --field needs KEY=VALUE` | `--field` came last with nothing after it. Exit 2. | Add `KEY=VALUE` after it. |
| `arcaeon: log: unknown option <option>` | An option `log` does not take. Exit 2. | Remove it; `log` takes only `--field` and `-`. |
| `arcaeon: log: --field wants KEY=VALUE or KEY:=JSON, got '<text>'` | A `--field` value has no `=`, or no key before it. Exit 2. | Write `KEY=VALUE` for text, `KEY:=JSON` for a number, true, null or a list. |
| `arcaeon: log: --field <key>:= is not JSON (<detail>)` | The value after `:=` is not valid JSON. Exit 2. | Use `=` for a plain text value, or fix the JSON. |
| `arcaeon: log: the row is not JSON (<detail>)` | The row you gave as an argument or on stdin does not parse. Exit 2. | Fix the JSON, or build the row with `--field` only. |
| `arcaeon: log: the row is not a JSON object` | The row parses, but it is a list or a single value, not `{...}`. Exit 2. | Pass an object. |
| `bad JSON: <detail>` | The row you gave (without `--field`) does not parse. Exit 1. | Fix the JSON. |
| `record must be a JSON object` | The row (without `--field`) is a list or a single value. Exit 1. | Pass an object. |
| `arcaeon log: could not finish: UnicodeEncodeError [internal_error]` | The row holds a broken character (a lone surrogate, such as `"\ud800"`), which cannot be written as UTF-8. Exit 3. | Remove that character from the row. |
| `arcaeon: log: cannot append to <ledger>: it is a directory, not a ledger file` | The path you gave is a folder. Exit 2. | Name a file inside it, for example `<folder>/agent.jsonl`. |
| `arcaeon: log: cannot write <ledger>: <reason>` | The operating system refused the write: permissions, a full disk, a read only folder. Exit 2. | Fix what the reason names. |
| `COULD NOT LOOK: refusing to append to <ledger>: <problem>; nothing was written` | The ledger's last line cannot be chained from, so a new row would break the chain. Nothing was written. Exit 3. | See the problems below. |

The `<problem>` in that last message is one of:

| Problem | What it means | What to do |
|---|---|---|
| `cannot read it (<reason>)` | The file could not be opened. | Check its permissions. |
| `its last line is not UTF-8 text (a binary file?)` | The file is not a ledger, or its end was damaged. | Check you named the right file. |
| `its last line does not parse as one JSON row (<detail>)` | The last line is cut short or is not valid JSON, often from a crash mid write. | Look at the last line; repair it or start a new ledger. Run `arcaeon verify` to see where it breaks. |
| `its last line is nested deeper than <n> levels [nesting_too_deep]` | The last line is a JSON value nested too deep to read safely. | Check what wrote that line. |
| `its last line is not a chained ledger row` | The last line is JSON but has no chain value: this file is not an arcaeon ledger. | Use another file name for your ledger. |

`log` also leaves an empty `<ledger>.lock` file beside the ledger, readable
only by you. It is how two writers avoid writing at once; it is safe to keep.

## verify

| Message | What it means | What to do |
|---|---|---|
| `usage: arcaeon verify <ledger.jsonl> [--strict] [--witness PINS [--ns NS]]` | More or fewer than one ledger, an unknown option, or `--ns` without `--witness`. Exit 2. | Fix the arguments. |
| `arcaeon: verify: --witness needs a value` (or `--ns`) | The option came last with no value. Exit 2. | Give the value. |
| `COULD NOT LOOK (missing): looked for a ledger file in <path>: ...` (or `(unreadable)`) | The ledger is not there, cannot be read, or is a folder. Exit 3. | Check the path. |
| `COULD NOT LOOK (empty): looked for chained rows in <path>: the ledger has no rows` | The file is there but empty. Exit 3. | Log rows first, or check the path. |
| `COULD NOT LOOK (bounded): looked for a chain value on every row in <path>: <n> row(s) carry no chain, so the chain cannot speak for them (<scope>)` | Some rows were written without a chain value (rows from before the chain, or after a declared break). The rest checked out, but those rows cannot be vouched for by the chain. Exit 3. | Pin the ledger with a witness so those rows are covered, and verify with `--witness`. |
| JSON with `"verdict": "BROKEN"` and `first_break` | A row no longer matches the chain: something changed the record after it was written. `first_break` names the line. Exit 1. | Look at that line and what wrote it; treat everything after it as unconfirmed. |

With `--witness PINS`, `verify` also compares the ledger with its pins:

| Message | What it means | What to do |
|---|---|---|
| `BROKEN: the ledger holds <n> fewer row(s) than its last pin (<ns>, <rows> rows)` | Rows were cut off the end since the last pin. Exit 1. | Find out what removed them; the pin shows how many there were. |
| `BROKEN: the ledger's chain at the pinned row <row> (<chain>) differs from its last pin (<ns>, <chain>): history at or before that row was rewritten` | The ledger is as long as the pin says, but the rows up to it were changed. Exit 1. | The ledger was rewritten; compare it with a copy you trust. |
| `BROKEN: the ledger holds <n> fewer row(s) than an earlier pin (<ns>, <rows> rows)` | An older pin counted more rows than the ledger has now. Exit 1. | As above. |
| `BROKEN: the ledger's chain at row <row> (<chain>) differs from an earlier pin (<ns>, <chain>): history at or before that row was rewritten (the latest pin agrees: it was taken after the rewrite)` | An older pin disagrees with the ledger, and the newest pin was taken after the change. Exit 1. | The rewrite happened between those two pins. |
| `BROKEN: the pin file holds two different chains at row <row> (<ns>: <chain> and <chain>): this pin file holds two heads at one height; a local WitnessStore refuses that` | The pin file itself names two different heads for one row count, which an honest pin file never does. Exit 1. | Do not trust this pin file; find out who wrote it. |
| `no pin compared: <reason>` | Informational, on stderr: no pin could be lined up with the ledger. | See the COULD NOT LOOK line that follows. |
| `chain not compared with the pin: the ledger's row <row> carries no chain, ...` | Informational: the pinned row has no chain value, so row counts were compared but chains were not. | Re-pin after the ledger has chained rows. |
| `COULD NOT LOOK (<reason_word>): looked for <what> in <where>: --witness was given but no pin was compared, so the ledger's own VERIFIED does not stand: <why>` | You asked for a pin check and none could be made, so the plain chain check alone is not reported as a pass. Exit 3. | Fix the cause in `<why>`, below. |

The `<why>` in that last message is one of:

| Why | reason_word | What to do |
|---|---|---|
| `no pin file at <pins>` | `missing` | Check the `--witness` path. |
| `the pin file cannot be read: <problem>` | `unreadable` | The problem says which line is wrong: not a regular file, not UTF-8, a line that does not parse, a line that is not a pin (a pin carries namespace, rows, chain), a line that breaks the strict pin rules, or a pin chain that does not verify. Repair it, or use the right file. |
| `the pin file holds <n> namespaces; pass --ns` | `name_not_found` | Pass `--ns` with the namespace you pinned under. |
| `the pin file holds no pins` | `empty` | Pin the ledger first (`arcaeon pin`). |
| `no pin for <ns> in <pins>` | `name_not_found` | Check the `--ns` spelling. |
| `the latest pin for <ns> in <pins> was taken over an empty log (0 rows): it constrains nothing, ...; re-pin against a non-empty ledger` | `empty` | Pin again now that the ledger has rows. |
| `the ledger's rows could not be counted: <detail>` | `unreadable` | Check the ledger file. |
| `the ledger could not be read, so nothing was compared with the pin` | `missing` or `unreadable` | Check the ledger path. |
| `this install has no witness.rows_since_pin` | `missing` | Reinstall or upgrade arcaeon. |

## pin

| Message | What it means | What to do |
|---|---|---|
| `arcaeon pin: error: one of the arguments --witness --remote is required` (and other argument errors) | The command needs a ledger and exactly one of `--witness FILE` or `--remote`. Exit 2. | Add one. |
| `arcaeon: pin: --ns is required with --witness` | A local pin needs a namespace name. Exit 2. | Add `--ns <name>`. |
| `COULD NOT LOOK: refusing to pin a ledger verify cannot vouch for (<scope>; <n> unchained row(s)); run `arcaeon verify` for the detail` | Some rows carry no chain, so the head would not speak for them. Nothing was pinned. Exit 3. | Run `arcaeon verify` on the ledger to see which rows. |
| `COULD NOT LOOK: refusing to write to <pinfile>: <problem>; nothing was written` | The `--witness` file is not a valid pin file (the problems are those listed under verify). Exit 3. | Fix it or use another file. |
| `refusing to publish a head for namespace '<ns>': the log does not verify (<first_break>). ...` | The ledger is BROKEN, and a pin is a record outside your control that cannot be taken back. Exit 1. | Repair the ledger, or record the break with the declare break tool, then pin. |
| `refusing to pin an empty log: a zero-row pin constrains nothing ...` | The ledger has no rows. Exit 1. | Log at least one row first. |
| `monotonic violation: a witness never goes backward ... high-water is <h> rows, submitted <r>. ...` | The ledger is shorter than it was when last pinned. Exit 1. | Find out what removed rows; after a real reset, pin under a new namespace. |
| `equivocation: a witness never holds two heads at one height ... already pinned at row <r> with chain <c>; ...` | The ledger has the same row count as the last pin but a different chain: it was rewritten. Exit 1. | Find out what changed it; after a real reset, use a new namespace. |
| `refusing to pin namespace '<ns>': its pin #<i> in <path> fails the strict pin rules (<detail>); ...` | An earlier pin in the file is malformed. Exit 1. | Repair the pin file. |
| `cannot confirm the pin landed in <path>: <detail>`, or `wrote <n> bytes to <path> but the file holds <m> ...` | The write did not land as written, so the pin was not counted. Exit 1. | Check the disk and the path, then pin again. |
| `{"ok": false, "error": "refusing to pin a ledger that does not verify: <first_break>"}` | `--remote` with a BROKEN ledger. Exit 1. | Repair the ledger first. |
| `refused before sending: no ARCAEON_KEY. ...` | `--remote` needs your witness key and none is set (or it is blank). Nothing was sent. Exit 1. | Set `ARCAEON_KEY`. |
| `{"ok": false, "status": 0, "error": "witness unreachable: <reason>"}` | The hosted witness could not be reached. Exit 1. | Check the network and run it again. |
| `{"ok": false, "status": <code>, "error": "<the witness's words>"}` | The hosted witness refused. A refusal that names a namespace prefix means your key may pin only under that prefix; arcaeon retries once under it when you gave no `--ns`. Exit 1. | Read the witness's words; pass the printed `namespace` as `--ns` next time. |

## seal

| Message | What it means | What to do |
|---|---|---|
| `usage: arcaeon seal <path-to-mcp-server> [--ns NAMESPACE]` | No server path, or more than one. Exit 2. | Give one path. |
| `arcaeon: seal: --ns needs a value` | `--ns` came last. Exit 2. | Give the namespace. |
| `sealed scan is a paid Arcaeon tool and no ARCAEON_KEY is set, so nothing was sent. ...` | `seal` needs a witness key. Nothing was written. You still get the free badge on stdout. Exit 3. | Set `ARCAEON_KEY` and run it again. |
| `sealed scan refused: the record could not be committed to the connector's ledger (<detail>). No credit was spent ...` | The sealed scan ledger could not be written, so no pin was asked for. Exit 3. | Fix the path or permissions of that ledger (`ARCAEON_SEALED_SCAN_LOG`, else beside `ARCAEON_LEDGER_LOG`). |
| `sealed scan refused: credit balance is zero. The badge record above was appended to the ledger (true, but unwitnessed); ...` | The key has nothing left to spend. The record was kept, but not witnessed. Exit 3. | Add credits (`arcaeon buy` lists the plans), then run `seal` again. |
| `sealed scan refused: this ARCAEON_KEY may not pin namespace '<ns>'. The witness says this key pins only under prefix '<prefix>'; pass --ns <prefix>-sealed-scans. No credit was spent. ...` | The key may pin only names that start with its prefix. Exit 3. | Pass the `--ns` it suggests. |
| `sealed scan refused: this ARCAEON_KEY may not pin namespace '<ns>'. A key pins only under its own prefix; pass --ns <your-prefix>-sealed-scans. ...` | The same, when the witness did not say the prefix. Exit 3. | Pass `--ns` with your key's prefix. |
| `sealed scan refused: the witness did not accept the pin (<status>). No credit was spent. <detail>` | Any other refusal or failure: a key it does not know, too many requests, the witness down, or no network. Exit 3. | Read the detail; see the pin rows above for each kind. |
| `sealed scan refused: the arcaeon connector is not installed (<detail>). ...` | The part of arcaeon that pins is missing from this install. Exit 3. | Reinstall arcaeon. |

A seal that finds high severity problems in the server exits 1, refused or
not. The grading part of `seal` prints the same messages as `badge`; see "vet
and badge" below.

## stamp

| Message | What it means | What to do |
|---|---|---|
| `usage: arcaeon stamp <file>` | No file, or more than one. Exit 2. | Give one file. |
| `COULD NOT LOOK (missing): looked for the file to stamp at <file>: it does not exist; nothing was sent` (or `it is a directory`, or `(unreadable)` with the reason) | The file could not be read. Nothing was sent. Exit 3. | Check the path. |
| COULD NOT LOOK with `reason_word` `network` and `witness unreachable: <reason>` | The request never completed. Exit 3. | Check the network and run it again. |
| `{"ok": false, "status": <code>, "error": "<the witness's words>"}` | The hosted witness refused, for example because the free daily allowance without a key is used up. Exit 1. | Read the words; set `ARCAEON_KEY` to stamp past the free allowance. |

## credits

| Message | What it means | What to do |
|---|---|---|
| `usage: arcaeon credits [--json]` | An argument other than `--json`. Exit 2. | Use no argument or `--json`. |
| `refused before sending: no ARCAEON_KEY. The witness key was empty or whitespace, ...` | No key is set, or it is blank. Nothing was sent. Exit 2. | Set `ARCAEON_KEY`. |
| `COULD NOT LOOK (network): looked for your balance at <address>: witness unreachable: <reason>` | The request never completed. Exit 3. | Check the network and run it again. |
| `the witness did not answer with a balance: <detail>` | The witness answered but refused, most often because the key is not one it knows. Exit 1. | Check the key. |
| `balance read, but it carried no credit count` | The witness answered without a number. Exit 0. | Run it again later; if it stays, ask for help with the key. |

## buy

| Message | What it means | What to do |
|---|---|---|
| `arcaeon: no plan named '<plan>'; plans: <plans>` | The plan name is not in the list. Exit 2. | Use one of the names it prints. |
| `arcaeon: could not read offers.json: <detail>` | The price list file named by `--offers` or `ARCAEON_OFFERS_FILE` could not be read. Exit 2. | Fix the path, or unset `ARCAEON_OFFERS_FILE`. |
| `arcaeon: could not read the evidence-pack offer: <detail>` | `buy evidence-pack` could not find that entry in the price list. Exit 2. | Check the price list file. |

## receipt

`receipt` answers its own usage refusals with exit 1, not 2; argument errors
the option parser catches are still exit 2.

| Message | What it means | What to do |
|---|---|---|
| `error: verify needs a receipt path (or --batch for a whole class)` | Exit 1. | Give a receipt file. |
| `error: --batch takes its own target list; drop the single receipt path` | Exit 1. | Pick one. |
| `error: <detail>` from reading a receipt (no such file, not JSON, `duplicate key '<key>'`, nested too deep, not UTF-8) | The receipt file could not be read as one JSON object. Exit 1. | Fix the path or the file. |
| JSON with `"ok": false` and `notes` such as `body digest mismatch: a body field was altered after issue`, `witness block is inconsistent: ...`, `attestation signature does not belong to this receipt: ...`, `anchor was asked for and not proven (status <status>)` | A check of the receipt failed: something in it was changed after it was issued, or a proof it claims is not there. Exit 1. | Treat the receipt as altered; get a fresh one from whoever issued it. |
| `ledger.status` of `chain_broken`, `row_not_found` or `head_mismatch`, with `first_break` | The receipt's ledger does not back it up. A mistyped `--ledger` path shows up here too, as `chain_broken` with `first_break` `unreadable: ...`. Exit 1. | Check the `--ledger` path first; if it is right, the ledger or the receipt was changed. |
| `error: refusing this batch: <n> receipts, cap is 20 per pass. Nothing was verified. ...` | `--batch` checks at most 20 at once. Exit 1. | Split the batch, or use `roster-report`. |
| `error: no receipts matched: a batch target must be a directory holding *.receipt.json files, a glob, or one or more receipt paths` | Exit 1. | Fix the target. |
| A batch row `<id>  BROKEN  ...  -- <reason>` | That receipt failed a check (reasons as above, or a duplicate key that two readers would read differently). Exit 1. | Look at that receipt. |
| A batch row `<id>  COULD NOT LOOK  ...  -- <reason>`, such as `unreadable file: ...`, `not readable JSON: ...`, `... the receipt carries no ledger claim ...`, or `... <name> was not found beside the receipt: its ledger sequence claim is unchecked` | That receipt could not be fully checked. Exit 3. | Put its ledger beside it, or pass `--ledger`. |
| `error: <token variable> not set; the citation-lookup API requires a token ...` (`receipt cite`) | Looking citations up online needs a token for that service. Exit 1. | Set the variable the message names, or use `--fixture` for an offline run. |
| `error: text is <n> chars; the API caps a request at <max>. Split on paragraph boundaries first.` | Exit 1. | Split the text. |
| `error: HTTP Error <n>: ...`, or `error: <urlopen error ...>` (`receipt cite`) | The citation service could not be reached or refused. Exit 1. | Check the token and the network. |
| `!!` lines in the exhibit, and exit 1 | Some citations were not found or not recognised. | Check the flagged citations by hand. |
| `error: roster ...` or `error: roster row <n>: ...` (`receipt ballot --roster`) | One row of the class list is wrong (empty trainee, missing or unreadable ballot file, no scenario, two rows writing the same file). Nothing was issued. Exit 1. | Fix the row it names. |
| `error: a single ballot needs the ballot JSON path, --trainee and --scenario ...`, or `error: --roster mints a whole class; drop the single-ballot path/--trainee arguments` | Exit 1. | Give one or the other. |
| `error: archive contents do not match the manifest ...`, `error: <path> is not byte-identical to its source <source>: ...`, `error: two different files would both be archived as <name> ...` | The archive check found a file changed, missing or clashing. Exit 1. | Do not use that archive; build it again. |
| `arcaeon receipt: could not finish: <ExceptionName> [internal_error]` | Seen when the text or `--fixture` file for `cite` is missing, when `roster-report --out` cannot be written, or when `exhibit` is given JSON that is not an object. Exit 3. | Check those paths and files. |

## once

`once` answers its refusals with exit 1.

| Message | What it means | What to do |
|---|---|---|
| The command's help text | No subcommand, or an unknown one. Exit 1. | See the help. |
| `receipt needs a key argument`, or `reclaim needs a key argument` | Exit 1. | Add the key. |
| receipt JSON with `ledger_ok` false or null and `ledger_first_break` | The ledger behind it is missing, BROKEN or only partly checkable. Exit 1. | Run `arcaeon verify` on it. |
| reclaim `refusal` `HolderAlive`: `refusing to reclaim key '<key>': its holder (pid <pid>, ...) is ALIVE on this host ...` | Another process still holds the claim. Exit 1. | Stop that process first. |
| reclaim `refusal` `LivenessUnknown`: `cannot reclaim key '<key>': <reason>. Refusing (indeterminate = refuse). ...` | arcaeon cannot prove the holder stopped (no lease, another host, or the index lost). Exit 1. | Stop all work against this ledger, run `once rebuild-index`, then retry as the message says. |
| reclaim `refusal` `ValueError`: `nothing to reclaim: key '<key>' already executed ...`, or `... has never been claimed` | Exit 1. | Use `once receipt` to see it. |
| `arcaeon: once rebuild-index: cannot index <path>: the ledger does not exist` (or `is a directory`) | Exit 2. | Fix the path. |
| `COULD NOT LOOK: once rebuild-index: cannot index <path>: <problem>; nothing was created` | The ledger is not readable text. Exit 3. | Check the file. |
| `UserWarning: rebuild_index() is downgrading <n> in-flight-looking claim(s) ...` | Some claims looked as if work was still running; they were reset so they can be reclaimed. Exit 0. | Make sure nothing was running; if it was, it could run twice. |
| `arcaeon once: could not finish: IndexUnavailable [internal_error]` | The claim index beside the ledger could not be opened or locked. Exit 3. | Check that the folder is writable, and try again. |

## proxy

`proxy` exits with the wrapped server's own exit code, except for these:

| Message | What it means | What to do |
|---|---|---|
| `arcaeon proxy: error: <detail>` (for example `no server command given; usage: --ledger PATH -- <server command...>`, `--access-names needs --tape PATH`, `--mandate-enforce needs --mandate PATH`, `--http-forward wants an http:// or https:// URL, not '<url>'`) | Exit 2. | Fix the options as it says. |
| `arcaeon-adapter: cannot start server [<command>]: <reason>` | The command after `--` is not there or cannot run. Exit 127. | Check the command. |
| `arcaeon-adapter: refusing to start: --mandate-enforce and the mandate <missing or unreadable>: <detail>` | Enforcing a mandate needs one it can read. Exit 3. | Run `arcaeon mandate lint <file>`. |
| `arcaeon-adapter: cannot listen on <address>: <detail>` | Exit 1. | Use another port. |
| `arcaeon-adapter: WARNING the listener is not on loopback; anyone who can reach it can call the upstream through it.` | A warning, not a refusal. | Listen on 127.0.0.1 unless you mean it. |
| `arcaeon-adapter: WARNING <variable>=<value> is set; this process is DELIBERATELY CORRUPTING relayed bytes. Test harness only.` | A test setting is on. | Unset that variable. |
| `arcaeon proxy: could not finish: ValueError [internal_error]` | Seen when `--listen` is not `HOST:PORT`. Exit 3. | Write it as `127.0.0.1:<port>`. |
| `arcaeon proxy: could not finish: <ExceptionName> [internal_error]` | Seen when `--ledger` cannot be written. Exit 3. | Fix the `--ledger` path. |
| An error reply to the agent: `blocked by mandate (<outside or could not look>): <why>` | With `--mandate-enforce`, a call outside the mandate, or one that could not be judged, was not passed on. | See `mandate check` below. |

`--pin-witness` reads `ARCAEON_WITNESS_KEY`, not `ARCAEON_KEY`. A pin it
could not make is written into the tape's last row, not printed.

## deal

| Message | What it means | What to do |
|---|---|---|
| `arcaeon deal: unknown step '<step>'` | Exit 2. | See `arcaeon deal --help`. |
| `arcaeon deal <step>: <detail>` | The step refused: an empty deal id, a seller writing a mandate, a bad `--item SKU:QTY:PRICE`, a file it cannot read or write. Exit 2. | Fix what it names. |
| `COULD NOT LOOK: ledger not found: <path>` (or `is a directory`, `is not UTF-8 text`, `cannot be read`) | `deal show` could not read the ledger. Exit 3. | Fix the path. |
| `COULD NOT LOOK: <ledger> holds no row for deal <id>` | Exit 3. | Check the deal id. |
| `COULD NOT LOOK: <reason>` from `deal dispute` or `deal pack`, such as `<side> tape not found: <path>`, `... tape does not verify (<first_break>); ...`, `neither tape holds a row for deal <id>`, `pin unreadable: <detail>` | One of the two tapes or the pin could not be read or trusted. Exit 3. | Fix the tape or pin it names. |
| `ALTERED at <step>#<k> (<side> tape): ...` | The two sides recorded the same step differently, or a row was edited after it was written, or a tape changed after it was pinned. Exit 1. | Compare the two tapes; this is evidence of an edit. |
| `MISSING at <step>#<k> (<side> tape): ...`, or `MISSING at row#<n>: ... rows <a>..<b> were removed after the pin` | One tape holds a step the other does not, or rows were removed. Exit 1. | Find out which side left it out or removed it. |
| `arcaeon deal dispute: --claim needs --by buyer\|seller` | Exit 2. | Add `--by`. |
| `hosted deal verdict not yet available; local verdict above` | `--remote` was asked for; only the local verdict is given. | Use the local verdict. |
| `arcaeon deal: could not finish: <ExceptionName> [internal_error]` | Seen when `deal pack -o` cannot be written. Exit 3. | Fix the `-o` folder. |

`deal handshake` refuses a bad offer with exit 2 and a line naming the
problem (`cannot read the terms file`, `the proposal is to '<to>', not
'<agent>'`, `the proposal's terms_digest does not match its terms: it was
changed after it was proposed; nothing was countersigned`). Its `verify`
answers `DIFFERENT TERMS: ...` or `MISSING: ...` with exit 1, and
`COULD NOT LOOK: <reason>` with exit 3.

## mandate

| Message | What it means | What to do |
|---|---|---|
| `COULD NOT LOOK: no file at <path>`, or `COULD NOT LOOK: <ExceptionName>: <detail>` | `lint` or `explain` could not read the mandate. Exit 3. | Fix the path. |
| `problem: <problem>` lines, then `<file>: invalid (...)` | The mandate has errors: not JSON, not an object, a key that is not a mandate field, a value of the wrong kind, or something the gate cannot read. Exit 2. | Fix each key it names. |
| `warning: ...spend_cap has no amount and no total: every spend will be COULD NOT LOOK`, or `warning: both <a> and <b> are given; ...` | Valid, but probably not what you meant. Exit 0. | Remove the duplicate field, or add the amount. |
| `<file>: invalid; run `arcaeon mandate lint` for the list` | `explain` will not explain an invalid mandate. Exit 2. | Run `lint`. |
| `arcaeon mandate check: needs --field name=<tool name>`, or a `--field` format message | Exit 2. | Give the call's tool name and fields. |
| `outside: <reason>` | The call is outside the mandate: a forbidden tool, a tool no pattern allows, too much spend, or outside the time window. Exit 1. | Do not make that call under this mandate. |
| `could not look: <reason>` | The call could not be judged: an unreadable mandate, no tool name, an amount or time it cannot read. Exit 3. | Fix the mandate, the fields or `--at`. |

## status

| Message | What it means | What to do |
|---|---|---|
| `usage: arcaeon status [--json]` | An argument other than `--json`. Exit 2. | Use no argument or `--json`. |
| `balance: not checked, no key` | No `ARCAEON_KEY`, so the balance was not asked for. | Set the key to see the balance. |
| `balance: COULD NOT LOOK (network): <detail>` | The balance request never completed. `status` still exits 0: it reports, it does not check. | Check the network. |
| `balance: the witness said no (<detail>)` | The witness refused the key. | Check the key. |
| `open COULD NOT LOOKs: <n>` and a line per target | Checks whose newest run on a file ended in COULD NOT LOOK. A target is shown as the start of its sha256, never its path. | Fix what stopped them and run those checks again. |
| `OFF: ARCAEON_JOURNAL=0` | The activity journal is turned off, so nothing new is recorded. | Unset `ARCAEON_JOURNAL` to record again. |
| `UNKNOWN` or `EXIT <n>` as a verb's last word | A journal line has an exit code arcaeon does not know. | Usually harmless; run that verb again. |

## selftest, version and demo

| Message | What it means | What to do |
|---|---|---|
| `usage: arcaeon selftest [ledger adapter once compact continuity baseline distill]` | An unknown self check name. Exit 2. | Use a listed name, or none for all. |
| JSON with `"failed": [<names>]` | Those bundled self checks failed: this install is not working as built. Exit 1. | Run `arcaeon selftest <name>` alone to see its output; reinstall arcaeon. |
| `  <part> moved from <old name> import failed: <ExceptionName>` in `arcaeon version` | One part of the package could not be loaded. Exit 0. | Reinstall arcaeon. |
| `arcaeon demo: takes no arguments, got '<arg>'` | Exit 2. | Run `arcaeon demo` alone. |
| `arcaeon demo` ends with exit 1 | The demo's own checks did not come out as they must (VERIFIED, then BROKEN at line 1). The last line `BROKEN: line 1: ...` is expected and is not this. | Run `arcaeon selftest`; reinstall arcaeon. |

## doctor

`arcaeon doctor` prints one row per check. A status of `no` is a reading and
keeps exit 0. A status of `COULD NOT LOOK` makes it exit 3, and the last line
says `COULD NOT LOOK: <n> check(s) could not be looked at (exit 3)`.

| Row says | What it means | What to do |
|---|---|---|
| `arcaeon doctor: unknown argument '<arg>'` | Exit 2. | Use no argument or `--json`. |
| python `no`: `<version> is older than 3.10` | arcaeon needs Python 3.10 or newer. | Use a newer Python. |
| extra `no`: `not installed (pip install "arcaeon[<name>]")` | An optional part is not installed. | Install it only if you need it. |
| key `no`: `ARCAEON_KEY is not set (the free verbs do not need it)` | | Set it only for the hosted verbs. |
| serve `no`: `not running (no serve.json; start it with arcaeon serve)` | | Start `arcaeon serve` if you want the local API. |
| serve `no`: `nothing answers at <url> (serve.json is left over; run arcaeon serve)` | A server ran before and has stopped. | Start it again. |
| serve `no`: `<url> answered /health with HTTP <code>` | Something answered, but not as arcaeon's server does. | Check what holds that port. |
| serve `COULD NOT LOOK`: `serve.json could not be read (<ExceptionName>)`, or `serve.json has no url` | The file a running server leaves is damaged. | Restart `arcaeon serve`; it writes the file again. |
| serve `COULD NOT LOOK`: `serve.json names '<host>', off this machine; doctor only asks loopback` | The file names another machine; doctor does not ask it. | Restart `arcaeon serve` on this machine. |
| serve `COULD NOT LOOK`: `<url> neither answered nor refused (<detail>)` | The request hung or failed. | Restart `arcaeon serve`. |
| client `COULD NOT LOOK`: `<file> is not JSON arcaeon can read: <detail>`, or `could not be read (<reason>)` | An AI client's settings file is damaged or unreadable. | Fix that file by hand. |
| client: `absent: <path> has no arcaeon entry`, or `absent: <path> is not there` | That client is not set up to use arcaeon. | `arcaeon connect <client> --write`. |
| client: `stale: <path> names '<command>', which does not resolve here` | The client's entry points at a command that is not on this machine any more. | `arcaeon connect <client> --write` again. |
| journal `no`: `<home> is not there and <parent> is not writable`, `<home> is a file, not a directory`, or `<home> is not writable (<reason>)` | arcaeon cannot keep its activity journal there. | Fix the permissions, or set `ARCAEON_HOME` to a folder you own. |

## distill and dedup

| Message | What it means | What to do |
|---|---|---|
| `arcaeon distill: cannot read <path>: not UTF-8 text (a binary file?)` (or `it is a directory`, or the reason) | The input could not be read as text. Exit 2. The same for `dedup`. | Pass a text file, or `-` for stdin. |
| COULD NOT LOOK with `reason` `budget must be a positive integer (tokens)` | Exit 3. | Pass a `--budget` above 0. |
| COULD NOT LOOK with `reason` `schema_hint='json' but tool_output is not valid JSON text` | Exit 3. | Drop `--schema-hint json`, or fix the input. |
| COULD NOT LOOK with `reason` `<path>: NaN/Infinity is not JSON and has no stable serialization; ...` | The input holds a value JSON does not allow. Exit 3. | Replace it with null or a string. |
| COULD NOT LOOK with `reason` `<path>: str contains a lone surrogate ...` | The input holds a broken character. Exit 3. | Clean the source text. |
| COULD NOT LOOK with `reason` `input nests deeper than this process can distill ...` | Exit 3. | Flatten the input. |
| `arcaeon distill: could not finish: TypeError [internal_error]` | Seen with `--schema-hint tabular` on a JSON object: that hint needs a list of rows. The plain reason is not shown. Exit 3. | Use a list of rows, or another hint. |
| `arcaeon dedup: could not finish: ValueError [internal_error]` | Seen with `--keep last`, which the command lists but does not accept (use `first`), with `--max-hamming` outside 0 to 64, or with `--min-overlap` outside 0.0 to 1.0. The plain reason is not shown. Exit 3. | Use `--keep first`, and keep the numbers in range. |

`distill serve` answers bad MCP requests with errors such as `parse error`,
`method not found: <method>`, `tool_output is required` and `unknown tool
<name>`, and keeps running.

## meter

Every refusal is printed as `error: <message>` on stderr, exit 1.

| Message | What it means | What to do |
|---|---|---|
| `error: monthly_cap must be None (unlimited), a non-negative int, or 'plan' ...` | A negative `--cap`. | Use 0 or more, or `--unlimited`. |
| `error: <path>: not an arcaeon_meter keys file` (or `nested too deep to parse`, or `contains the non-JSON literal 'NaN'`) | The keys file is not one the meter wrote, or was edited by hand. | Point `--keys` at the right file, or fix it. |
| `error: 'unknown key ...'`, `"no key with id '<id>'"`, `"key id '<id>' is too short to be unambiguous (need at least 6 hex chars)"`, `"key id '<id>' is ambiguous (<n> matches)"` | The key you named could not be found, or matches more than one. | Copy the id from `arcaeon meter keys list`, at least 6 characters. |
| `error: month must be 'YYYY-MM' (as written by the meter itself), got '<month>'. ...` | `--month` is not in that form. | Write the year in four digits, a hyphen, then the month in two. |
| `warning: <n> pre-0.1.2 usage row(s) totaling <t> call(s) could not be attributed to a single key ...` | Old usage rows that cannot be tied to one key are left out of the export. Exit 0. | Look at them with `Meter.legacy_usage()` in Python. |
| `<key_id>  MALFORMED ENTRY (not a JSON object; denied as unknown_key until fixed)` | A hand edited entry in the keys file is broken, and that key is refused until it is fixed. | Fix the entry. |
| `arcaeon meter: could not finish: TimeoutError [internal_error]` | The keys file stayed locked for more than 10 seconds. Exit 3. | Run it again; if another meter is not running, remove the stale `.lock` file beside the keys file. |
| `arcaeon meter: could not finish: PermissionError [internal_error]` (or `OSError`, `RuntimeError`) | The keys file or usage store could not be read. Exit 3. | Check the permissions on those files. |
| HTTP 401 or 429 `{"error": "metering_denied", "reason": "<word>", ...}` | From the meter in front of your own service: 429 is `over_cap`; 401 is a missing, unknown, revoked or malformed key, or a keys file it could not read. | 401: send a valid key. 429: wait for the next month, or raise the cap. |

## connect

Usage refusals print `arcaeon connect: <message>` and the usage, exit 2:
`--list takes no '<arg>'`, `--path takes a file`, `--os takes one of
windows, macos, linux`, `unknown option '<option>'`, `name one client`,
`name one client, not several`, `no client '<name>'` (see `arcaeon connect
--list`), `<a> and <b> do not go together`, `--path goes with --write,
--undo or --check`, and `--<action> acts on this machine (<os>) only; --os is
for previews`.

| Message | What it means | What to do |
|---|---|---|
| `arcaeon connect: chatgpt has no local config to change. ... It needs a public URL, which is a deploy decision; nothing written` | That client reaches tools only through a public address, and arcaeon's server is local only. Exit 2. | Nothing to write on this machine. |
| ``arcaeon connect: generic-http has no config file to write: point the framework at GET /openapi.json on a running `arcaeon serve` `` | Exit 2. | Do that. |
| `confirmed: NO, the client's docs did not state this path; check it before --write` | A preview: the settings file path is arcaeon's best guess. Exit 0. | Check where that client keeps its settings. |
| `COULD NOT LOOK (path_unconfirmed): <client>'s docs did not state <file>; check where it keeps its config and pass --path FILE` | `--write` will not guess the path. Nothing written. Exit 3. | Pass `--path` with the real file. |
| `COULD NOT LOOK (unreadable): <file> is not JSON arcaeon can read: <detail>` (not valid JSON, the top level is not an object, a key holds the wrong kind of value, or the change could not be made without touching other keys), or `<file> could not be read (<reason>)` | The settings file could not be read safely, so it was not changed. Exit 3. | Fix the file by hand, then run it again. |
| `COULD NOT LOOK (unreadable): <file> changed while it was being backed up; nothing written` | Another program changed it at the same moment. Exit 3. | Run it again. |
| `COULD NOT LOOK (target_vanished): <file> disappeared while arcaeon was writing it ...; nothing written` | Exit 3. | Run it again. |
| `COULD NOT LOOK (unwritable): <file> could not be written (<reason>); nothing changed`, or `could not be restored (<reason>)` | The operating system refused. Exit 3. | Fix the permissions. |
| `the 'arcaeon' entry is already there, the same; nothing written` | Exit 0. | Nothing to do. |
| `COULD NOT LOOK (no_backup): no arcaeon backup of <file> to restore; nothing changed` | `--undo` found nothing arcaeon wrote. Exit 3. | Nothing to undo. |
| `COULD NOT LOOK (changed_since_write): <file> is not what arcaeon wrote (...); ... remove the arcaeon entry by hand` | The file was edited after arcaeon wrote it, so undo will not overwrite those edits. Exit 3. | Follow the sentence; it names the backup to compare with. |
| `state: absent  (no arcaeon entry)`, or `(the file is not there)` | `--check`: the client is not set up. Exit 1. | `--write`. |
| `state: stale  (command '<command>' does not resolve here)` | `--check`: the entry points at a command that is not on this machine. Exit 1. | `--write` again. |
| `state: present (...; differs from what --write would put there now)` | Exit 0. | `--write` again to bring it up to date. |

## mcp

| Message | What it means | What to do |
|---|---|---|
| `arcaeon mcp needs the MCP Python SDK: pip install 'arcaeon[mcp]'` | The MCP server needs an extra that is not installed. Exit 2. | Run `pip install "arcaeon[mcp]"`. |
| `COULD NOT LOOK: arcaeon mcp --http needs the [mcp] extra ...: pip install 'arcaeon[mcp]' (cannot import <module>)` | The HTTP mode needs the same extra. Exit 3. | Install it. |
| `arcaeon mcp: error: --port goes with --http` | `--port` without `--http`. Exit 2. | Add `--http`, or drop `--port`. |
| `arcaeon mcp: --port <n> is not a port (0 to 65535)` | Exit 2. | Use a number from 0 to 65535. |
| `arcaeon mcp: COULD NOT LOOK: cannot read or create <home>/serve.token (<reason>)` | The token file in arcaeon's home folder could not be read or made. Exit 3. | Fix the permissions on that folder (`ARCAEON_HOME`, else `~/.arcaeon`). |
| `arcaeon mcp: COULD NOT LOOK: cannot listen on 127.0.0.1:<port> (<reason>)` | Another program holds that port. Exit 3. | Pick another port, or 0 for any free one. |
| `arcaeon needs the MCP Python SDK: pip install 'mcp>=1.0'` (with a traceback) | Started through `python -m arcaeon.mcp` without the extra. | Install `arcaeon[mcp]`, and start it with `arcaeon mcp`. |

### What an agent sees from the MCP tools

A tool that fails answers with an error text of the form `<ExceptionName>:
<message>`. The ones a caller can cause:

| Text | What it means | What to do |
|---|---|---|
| `ValueError: namespace must be 1-64 chars of [A-Za-z0-9._-] starting alphanumeric ...` | The namespace is not a plain name. | Use letters, digits, dot, underscore and hyphen only. |
| `ValueError: strict must be a JSON boolean (true/false), got <type> <value>` | `strict` was sent as text or a number. | Send `true` or `false`. |
| `ValueError: jsonl_text must be a string of JSONL, got <type>` | The peer ledger was not sent as text. | Send the ledger's lines as one string. |
| `ValueError: events must be a list of strings (one line per action), got <type>`, or `events[<i>] is not valid UTF-8 text ...`, or `namespace <ns> has no ledger yet and events is empty ...` | The events to record are not a list of plain text lines, or there is nothing to record or check. | Send a list of strings. |
| `ValueError: reason must be a non-empty explanation ...`, `no ledger for namespace <ns>`, or `no break to declare in <ns> ...` | A break can only be declared, with a reason, in a ledger whose check found one. | Run the verify tool first; declare only a break it reports. |
| `ValueError: record must be a JSON object` | The row to append is not `{...}`. | Send an object. |
| `FileNotFoundError: not a readable file: <path>` | The vet tools were given a path that is not there. | Fix the path. |
| `PermissionError: refused: <path> is outside <variable> (<root>). This server only reads inside its configured root.` | The vet tools read only inside a set folder. | Use a path inside it, or change that variable where the server starts. |
| ``ValueError: `fields` must be a JSON object`` or ``... needs "name": the tool name of the call to check`` | The mandate check was not given the call to check. | Send `fields` as an object with `name`. |
| ``ValueError: `<name>` must be a string``, ``... `keep_text` must be true or false``, ``... `formats` must be a list of format names``, ``... `zip` must be true or false``, ``... `remote` must be true or false`` | A field was sent as the wrong kind of value. | Fix the field it names. |
| `RuntimeError: <tool> ran but its call record could not be written to <path>: <detail>` | The tool did its work, but its own record of the call could not be saved. | Make that path writable, or set `ARCAEON_CALL_RECORD` to a writable file. |

The two witness tools answer a refusal as normal text, not as an error:

| Text | What it means | What to do |
|---|---|---|
| `<tool> is a paid Arcaeon tool and no ARCAEON_KEY is set, so nothing was sent. ...` | The tool needs a witness key. It also lists the tools that are free in the same install. | Set `ARCAEON_KEY` where the MCP server starts. |
| `<tool> is refused: LICENSE_GATE_REQUIRED=1 is set on this machine but no license gate module is installed, ...` | Someone turned on the optional license gate, and the part that checks licenses is not installed. | Install that part, or unset `LICENSE_GATE_REQUIRED`. |
| `<tool> is refused by the license gate [<reason>], so nothing was sent. ... Set ARCAEON_LICENSE_KEY=<your license key>, or unset LICENSE_GATE_REQUIRED ...` | The license gate is on and did not accept this copy. | Set `ARCAEON_LICENSE_KEY`, or unset the gate if it should not be on. |
| `{"ok": false, "status": 0, ..., "error": "witness unreachable: <reason>"}` | The hosted witness could not be reached. | Check the network. |
| `{"ok": false, "status": <code>, ..., "error": "<the witness's words>"}` | The witness refused, for example a renew whose head does not match. | Read the words. |

## serve

| Message | What it means | What to do |
|---|---|---|
| `arcaeon serve: refusing --host <host>: exposing the server is a deploy decision; arcaeon serve binds 127.0.0.1 only` | The local API only listens on this machine. Exit 2. | Leave `--host` out; reach it from elsewhere only through a tunnel you set up yourself. |
| `arcaeon serve: --port <n> is not a port (0 to 65535)` | Exit 2. | Use 0 to 65535; 0 picks a free port. |
| `arcaeon serve: --root <dir> is not a directory` | Exit 2. | Point `--root` at a folder that exists. |
| `arcaeon serve: cannot read or create <home>/serve.token (<reason>)` | The token file could not be read or made. Exit 3. | Fix the permissions on arcaeon's home folder. |
| `arcaeon serve: cannot listen on 127.0.0.1:<port> (<reason>)` | Another program holds the port. Exit 3. | Stop it, or use `--port 0`. |
| `arcaeon serve: <METHOD> <path> <status>` | One line per request, failures included. | Informational. |

### What an HTTP client gets back

A check always comes back with status 200 and its own `exit` in the body.
These are the refusals:

| Status and body | What it means | What to do |
|---|---|---|
| 401 `{"error": "no token: send `Authorization: Bearer <token>` or `X-Arcaeon-Token: <token>` ..."}` | Every route but `/health` and `/openapi.json` needs the token. | Send the token that `arcaeon serve --print-token` shows. |
| 401 `{"error": "wrong token"}` | The token does not match. | Read it again; another `ARCAEON_HOME` has another token. |
| 400 `{"error": "this server answers only on its loopback address", "exit": 2}` | The request's Host is not `127.0.0.1` or `localhost`. | Call `http://127.0.0.1:<port>`; a tunnel must pass that Host on. |
| 404 `{"error": "no route <path>"}` | No such address. | Check it against `GET /openapi.json`. |
| 404 `{"error": "<path> is declared but not built in this checkout"}` | The route's code is not in this install. | Upgrade arcaeon. |
| 405 `{"error": "<METHOD> is not allowed on <path>", "allow": [...]}` | Wrong method. | Use one in `allow`. |
| 413 `{"error": "the body is over 10 MB", ...}` | The body is too large. | Send a path inside the served folder instead of the content. |
| 400 `{"error": "send the body with a Content-Length, not chunked", "exit": 2}`, or `Content-Length is not a length`, or `the body is not UTF-8 JSON`, or `the request body must be a JSON object` | The body could not be read as one JSON object. | Send a JSON object with a Content-Length. |
| 400 `missing required field '<name>' ...`, `<where> must be <type>, got <type>`, `<where> must be one of <values>, got <value>`, `<where> is <n> characters, over the limit of <max>` | A field is missing, of the wrong kind, not an allowed value, or too long. | Fix the field it names; `GET /openapi.json` lists every field. |
| 400 `` `<field>` is outside the served root `` | A path points outside the folder the server answers for. | Use a path inside it, or restart with another `--root`. |
| 400 ``send `<one>` or `<other>`, not both``, `` `<field>` must be a string ``, `` `<field>` is not base64 `` | A content field was sent wrong. | Send either a path or the content, once, as the kind it names. |
| 400 with the verb's own words in `error` | The command behind the route refused, the same way it does on the command line. | Read the message under that verb in this page. |
| 200 `{"verdict": "COULD NOT LOOK", "exit": 3, "error": "could not finish: <ExceptionName> [internal_error]"}` | The route failed unexpectedly. It is never shown as a pass. | Run it again; if it repeats, report it. |
| 200 `{"verdict": "COULD NOT LOOK", "exit": 3, "refused": true, "reason": "<tool> is a paid Arcaeon tool and no ARCAEON_KEY is set, ..."}` | `/v1/seal`, or `/v1/pin` with `"remote": true`, needs a witness key. | Set `ARCAEON_KEY` and restart the server. |
| 200 the same, with `reason` `this server was started without --allow-paid, so the paid lane does not spend even with ARCAEON_KEY set; ...` | The key is set, but the server was not started to allow spending it. | Restart with `arcaeon serve --allow-paid`. |

A few routes have their own refusals, all status 400: `log needs `row` or
`fields``; ``a pin is for tapes; kind "readings" takes two ledgers only``;
`` `path` is a directory with no records.jsonl (not an exported bundle) ``;
``missing required field 'provider' ...`` on `/v1/readings`; ``field name
<key> cannot be passed as --field`` on `/v1/mandate/check`; ``send `witness`
(a local pin) or `remote`, not both`` on `/v1/pin`; and `` `readings` not
taken over HTTP ... (use `receipt` for the second-read receipt) `` on
`/v1/evidence-pack`. Each names the field to fix.

## open, and the dashboard

| Message | What it means | What to do |
|---|---|---|
| `arcaeon open: could not open a browser; open this link (it works once):` and a link | No browser could be started. Exit 0. | Open the link yourself, soon: it works once. |
| `arcaeon open: COULD NOT LOOK: cannot read the token in <home>/serve.token (<reason>)` | A server is running but its token file cannot be read. Exit 3. | Fix the permissions on arcaeon's home folder. |
| `arcaeon open: COULD NOT LOOK: the running server does not answer the dashboard; stop it and run `arcaeon open` again ...` | The server already running is an older one without the dashboard. Exit 3. | Stop it, then run `arcaeon open`. |
| `arcaeon open: COULD NOT LOOK: the running server did not accept this machine's token (serve.token changed since it started)` | Exit 3. | Restart `arcaeon serve`. |
| `arcaeon open: COULD NOT LOOK: the running server answered <code> ...`, `... did not answer (<ExceptionName>)`, or `... gave no sign-in code` | The running server did not hand out a sign-in link. Exit 3. | Restart `arcaeon serve`, then `arcaeon open`. |
| `arcaeon open: COULD NOT LOOK: cannot start a server on 127.0.0.1:<port> (<reason>)` | No server was running and a new one could not start. The same line appears when the token file cannot be made. Exit 3. | Free the port or use `--port 0`; check the home folder's permissions. |
| `arcaeon open: --port <n> is not a port (0 to 65535)`, or `--root <dir> is not a directory` | Exit 2. | Fix the option. |

On the dashboard pages:

| Page shows | What it means | What to do |
|---|---|---|
| "This page needs a sign-in. Run `arcaeon open` for a fresh link." | The page was opened without a valid sign-in. | Run `arcaeon open`. |
| "That sign-in link was already used or has expired." | Each link works once, for a short while. | Run `arcaeon open` again. |
| "this form did not come from this dashboard's own page, so it was not read" | A form was sent from somewhere else. | Open the page from `arcaeon open` and send it from there. |
| "That path (`<field>`) is outside the folder this server answers for, so it was not opened." | The file you picked is outside the served folder. | Pick one inside it. |
| "Pick a file or paste a ledger, not both." and the other "Choose ... first." lines | The form was sent empty or with two inputs. | Do one of them. |
| "This mandate is not valid, so it was not explained." with problems listed | The mandate file has errors. | Fix them; `arcaeon mandate lint` lists them too. |
| "The page could not finish (<ExceptionName>). Nothing was shown as a pass." | A page failed unexpectedly. | Reload; if it repeats, report it. |
| A check shown as COULD NOT LOOK with an "error" line | The check refused its input. | Read the error line. |

## Framework adapters and the Python client

| Message | What it means | What to do |
|---|---|---|
| `ModuleNotFoundError: arcaeon.adapters.<adapter> needs <package>, which is not installed: pip install <package> ...` | The adapter for that agent framework needs the framework installed. | Run the `pip install` it names. |
| A tool answer `{"verdict": "bad usage", "exit": 2, "reason_word": "usage", "reason": "the tool arguments are not JSON"}` (or `not a JSON object`) | The model sent tool arguments that are not a JSON object. | The model should call again with an object. |
| `no server found: serve.json is absent (start `arcaeon serve`, or pass url=)` | The client looks for a running local API and found none. Exit 3. | Start `arcaeon serve`, or pass the address. |
| `not an http:// server url: '<url>'` | The address is not an `http://` address. Exit 3. | Pass `http://127.0.0.1:<port>`. |
| `refusing plain http:// to a non-loopback host '<host>': pass allow_insecure=True to send anyway` | The client will not send your token unencrypted to another machine. Exit 2. | Use the local address, or pass `allow_insecure=True` if you mean it. |
| `could not reach the server (<ExceptionName>)` | Nothing answered. Exit 3. | Check that `arcaeon serve` is running and the port is right. |
| `the server's answer (HTTP <status>) is not a JSON object` | Something other than arcaeon answered on that port. Exit 3. | Check the address. |
| The server's own refusal with `http_status` added | See "What an HTTP client gets back" above. | As there. |
