# Changelog

Reverse-chronological. One line per item; the commit id or ids that carry it
follow the item id. MIGRATION.md holds the field-by-field detail for anything
that adds a JSON field or a verb.

## Unreleased

Not in any release yet. These are committed on a local branch and are not in
any version on PyPI; `pip install arcaeon` does not have them.

### Plug-in batch (branch plugin-2026-09-27)

- **OA5.** The pack README no longer says the records were "not changed after it was written": without a pin it shows every row hashes to the next; with a pin, that the rows up to the pinned head existed at pin time.
- **OA4.** `connect --write` on a config removed by another program mid-write answers COULD NOT LOOK, exit 3, new reason word `target_vanished`, and leaves nothing behind; it raised FileNotFoundError before.
- **OA3.** The dashboard's origin guard drops a default port both ways, so on `--port 80` the `Origin: http://127.0.0.1` a browser sends is its own; every non-default port still needs the exact port.
- **OA2.** A reader whose endpoint redirects to a malformed Location (a bad port, a bad IPv6 host) is refused like any redirect: COULD NOT LOOK `redirect_refused`, reason "redirect refused: ...", the run continues and the key is not sent.
- **OA1.** Pack verify: a file the manifest lists that is gone from the pack is BROKEN, exit 1, naming the file (was COULD NOT LOOK, exit 3), and deleting could_not_look.json no longer hides "manifest incomplete".
- **K021R (aa69d47).** `arcaeon connect --undo` refuses a config changed since the write: COULD NOT LOOK, exit 3, new reason word `changed_since_write`, nothing touched, and the reason names the backup to compare against. `--write` now leaves a `<backup>.written` sidecar beside each backup holding the sha256 of the bytes it wrote; undo consumes it with the backup. A backup with no sidecar (made before this change) is restored as before.
- **KH8 (61b9aa6).** `arcaeon mcp --http` serves the stdio server's same 19 tools over streamable HTTP on 127.0.0.1 with the serve token; fails closed (COULD NOT LOOK, exit 3) without the `[mcp]` extra.
- **K14xR (c290700).** The test suite points ARCAEON_HOME and MCP_VET_AUDIT_LEDGER away from the real home for every test and fails the session if the real ~/.arcaeon or ~/.mcp_vet changed.
- **K143 (a44ff9f).** A socket guard in the test suite: loopback only unless a test is marked `live`; the `live` marker is registered and skipped by default.
- **K142 (1aa4818, eaac34d).** `py tools/release_check.py --offline` prints one PASS or named FAIL line per plug-in surface check.
- **K141 (a69d628).** A test holds MIGRATION.md to naming every new JSON field.
- **K140 (1515137, 1f927ff).** This file.
- **K107 (c352778, 579c6cb).** `arcaeon open` opens the local dashboard with a one-time sign-in code, starting a loopback server when none is running.
- **K100 to K109 (950e6c5 to bf79d9e).** The local dashboard: pages `/`, `/status`, `/verify`, `/packs`, `/readings`, `/mandate`, `POST /session/code`, a one-time code exchanged for an HttpOnly SameSite=Strict cookie, an origin guard on form posts, `Content-Security-Policy: default-src 'self'`, pages that read without JavaScript, and the new module `arcaeon.words`.
- **K020 to K025 (f54f2ba, 7dc64ff, a7cf939, 4a22674, 1e3f2c3, 3d7a5b0).** `arcaeon connect --write`, `--undo`, `--check` and `--path`, entries for all eight clients, and a launch line that uses uvx when present; new reason words `unreadable`, `path_unconfirmed`, `no_backup`, `unwritable`.
- **K016R (1ea6ed1).** The Python and JS clients send the home serve token only to loopback; plain http to another host exits 2 (`insecure`) unless `allow_insecure` is set.
- **K015b (083f75e).** Journal rows may carry an optional `reason_word`.
- **KH7R (bdca088).** A handshake acceptance is bound to the proposal row it cites (`proposer_chain`, `proposer_row`); verify answers DIFFERENT TERMS on `proposal_hash`, or MISSING when the cited row does not exist.
- **KH7 (4514b6b, edb7f9d, 2e99fa6).** Agent-to-agent handshake: `arcaeon deal handshake propose|accept|verify` and `POST /v1/handshake/propose`, `/accept`, `/verify`, with two new words, AGREED TERMS and DIFFERENT TERMS.
- **KH5 (95c2f05, 901c719).** A heavy test runs one six-call script through the stdio proxy, the HTTP forward and call_proxy, record-only and enforce, and checks the three ledgers agree row for row.
- **K093 (062014a).** docs/ADAPTERS.md gains an "Any OpenAPI-capable framework" section.
- **K092 (2e23a45).** New docs/ADAPTERS.md; its examples run in the suite.
- **K091 (0f0ad57).** A test holds the HTTP routes and the MCP tools to the same answers.
- **K090 (40a9884).** tests/test_import_weight.py covers the new serve, client, connect, readings and adapter modules.
- **K089 (2cea6e0).** AutoGen adapter, `arcaeon.adapters.autogen.arcaeon_tools(client=None)`; AutoGen is imported inside the function.
- **K088 (7016cc1).** CrewAI adapter, `arcaeon.adapters.crewai.arcaeon_tools(client=None)`; CrewAI is imported inside the function.
- **K087 (8863c24).** LlamaIndex adapter, `arcaeon.adapters.llamaindex.arcaeon_tools(client=None)`; LlamaIndex is imported inside the function.
- **K086 (a0ef7c4).** LangChain and LangGraph adapter, `arcaeon.adapters.langchain.arcaeon_tools(client=None)`; LangChain is imported inside the function.
- **K085 (e5ccf58).** OpenAI Agents SDK adapter, `arcaeon.adapters.openai_agents.arcaeon_tools(client=None)`, one `FunctionTool` per free check route.
- **K084 (d5d08ce).** `arcaeon schema --format gpt-action`: the OpenAPI document cut to the free check routes, committed as docs/schemas/gpt_action_openapi.json.
- **K083 (c968392).** `arcaeon schema --format gemini`: Gemini function declarations, committed as docs/schemas/gemini_functions.json.
- **K082 (961f8c1).** `arcaeon schema --format openai`: OpenAI function tools, committed as docs/schemas/openai_functions.json.
- **K081 (d023bb0).** `arcaeon schema --format claude`: Claude tool-use definitions, committed as docs/schemas/claude_tools.json.
- **K080 (ef956f1).** `arcaeon.adapters.tool_specs`: one tool list, generated from the OpenAPI document, for every adapter.
- **K079 (45fe686).** docs/MANDATE_GATE.md covers the HTTP forward and call_proxy surfaces, the session total cap and the enforce warning.
- **K078 (6046f53).** MCP tool `mandate_check`, free; it writes one call-record row and blocks nothing.
- **K077 (b7994c7).** `arcaeon status` shows mandate counts, read from the new file `~/.arcaeon/mandate_sessions.jsonl`.
- **K076 (ae25c28).** New rows `mandate_loaded` and `mandate_changed`; `session_end` gains `mandate_changes`.
- **K075 (b5f61af).** `arcaeon mandate check` and `POST /v1/mandate/check` judge one call against a mandate and write nothing.
- **K074 (ffc4bae, d05f4d3).** `arcaeon mandate lint` and `arcaeon mandate explain`, with a mandate section in docs/VERBS.md.
- **K073 (c4ab792).** Optional mandate field `spend_cap.total` and the new row `mandate_cap_exceeded`.
- **K072 (c151dff).** The mandate gate in call_proxy: record-only by default, `--mandate-enforce` opts in to refusing.
- **K071R (5588b57).** A request the gate cannot parse gets a `mandate_could_not_look` row with `judged_reason: "unparsed"`.
- **K071 (b562006).** The mandate gate in the HTTP forward proxy: record-only by default, enforce is opt-in.
- **K070R (fa07fc2).** The record-only guard test derives its surface list from the source.
- **K070 (fe19049).** A guard test holds record-only as the default on every mandate surface.
- **K069b (09919d4).** The evidence routes name every field they take, and the path fence adds `buyer`, `seller` and `readings_ledger`.
- **K069 (183df37, 9f53dac).** HTTP handlers for the evidence pack, and MCP tools `evidence_pack_build` and `evidence_pack_verify`.
- **K068 (9d864fd).** `evidence-pack --zip [--built-at TS]`: a deterministic zip that `evidence-pack verify` takes.
- **K067 (3acda11).** `evidence-pack --readings RECEIPT` includes a second-read comparison receipt, checked on every verify.
- **K066 (e93d599).** `evidence-pack --mandate FILE` adds the mandate rows section, rebuilt on verify.
- **K065 (ef5a276, 0c2dd15).** `evidence-pack --deal ID` folds the deal pack in.
- **K064 (ec401d4).** `evidence-pack --format aat` puts the AAT export inside the pack, checked on verify.
- **K06xR2 (0acee96).** `evidence-pack verify --witness` with no pin listed searches the pin file; a pin beyond the head is BROKEN.
- **K06xR1 (7a46836).** Pack verify re-derives the build findings; a manifest without `checks` or `counts` is BROKEN; every pack writes `manifest.sha256`.
- **K063 (cf81832).** The AAT export writes `<name>_gaps.json` and the which-chain line.
- **K062 (dd06239).** AAT records gain `prev_hash`, SHA-256 over the RFC 8785 JCS of the previous record; new stdlib module `arcaeon.prove.jcs`.
- **K061 (119a733).** `arcaeon export --format agent-audit-trail`: the field mapping from ledger rows.
- **K060 (db079bf).** `evidence-pack verify` step 4 checks the pins.
- **K059R (85b69db).** Pack verify reads could_not_look.json and the manifest counts; a build COULD NOT LOOK never exits 0.
- **K059 (fd028ae).** A missing-files test, and the spec's section 7 test as one file.
- **K058R (125df9f).** The window step is proven byte-exact; a tail cut with the head rewritten is BROKEN.
- **K058 (d26f633).** `evidence-pack verify` step 3: window rows equal their records lines.
- **K057 (c733c96).** `evidence-pack verify` step 2: the chain and its head.
- **K056R (2821207).** Pack verify walks the whole pack folder; a nested unlisted file is BROKEN.
- **K056 (60229f1).** `evidence-pack verify` step 1: rehash every file the manifest lists.
- **K055R (e841b57).** The pack README spells out the internal references in its does-not-show bullets.
- **K055 (5a979a0, 6f6df31).** A one-page README.md inside every pack, with the does-not-show bullets from the spec.
- **K054 (4096c97).** Every pack holds could_not_look.json.
- **K053 (561ae66).** The pack's manifest.json with file hashes, `operator_at_t` and the other fields the spec names.
- **K052R (88ae4e8).** Window rows keep their raw line bytes on a CRLF ledger.
- **K052 (b6ad1e6).** Agent and time-window filter into window.jsonl.
- **K051 (d2814de).** New module `arcaeon.prove.evidence_pack` over the audit export.
- **K050 (9bc63ac).** The Article 12 citations name 12(3)(a) to (c) for periods of use, the reference database and input data.
- **K046 (de2b257).** A test holds that a second-read request is a dry run until `--send`.
- **K045 (7f87f9a).** New docs/SECOND_READER.md.
- **K044 (7c95a13).** MCP tools `second_read_submit` and `second_read_compare`, both free.
- **K043 (10502e0).** `second-read compare --receipt` and `run --receipt` issue the comparison as a local, free receipt.
- **K042 (0942959).** `arcaeon second-read run`: two readers, two ledgers, one compare.
- **K041 (7ff4a5b, 4c28b78).** `arcaeon second-read ask` batches a claims file through one reader; nothing is sent without `--send`.
- **K040 (06c78eb, a966c0f).** `arcaeon second-read submit` and `POST /v1/readings`, with route schemas naming every field.
- **K039 (4ed2358).** Reader presets, including `ollama:<model>`, and a live test marked `live`.
- **K038 (7367ea0).** Gemini reader backend.
- **K037 (8c5d145).** Anthropic reader backend.
- **K036R (8afaeac).** Readers follow no redirect and use no proxy; new reason word `redirect_refused`.
- **K036 (c57221b).** Reader backend for any OpenAI-compatible endpoint.
- **K035 (bf9f687).** `arcaeon reconcile --kind readings`.
- **K034 (54a5fad, e20af26).** `arcaeon second-read compare A B` and the new verdict word COMPARED.
- **K033R (9442a2e).** Reader ids are compared in one canonical form.
- **K033 (5c5d336).** The `independence` field on compare results.
- **K032 (0e1dd52).** The readings compare core, with `disagreed` and `read` as two integers and `not_yet_informative` under 20 read.
- **K031 (060ea67).** Criterion rows; a reading needs its criterion frozen earlier in the ledger.
- **K030 (cf82cdd).** The reading row format, `arcaeon-reading/1`.
- **K019c (1d16e27).** Connect tests use a fake POSIX home, /fake/u, so no real user home folder is named in the tree.
- **K019 (2ee0c9e, 8716d8a).** `arcaeon connect <client>` prints the plan and writes nothing.
- **K018 (f79e3ad).** `arcaeon connect --list` and the eight-client catalog.
- **K017 (5aed605).** Zero-dependency JavaScript client, clients/js/arcaeon.mjs, not published to any registry.
- **K016 (34f448f).** Stdlib Python client, `arcaeon.client`.
- **K015 (cb1c244).** `arcaeon serve` journals every HTTP call that reaches a handler.
- **K014 (54c617f).** docs/openapi.json committed with a drift test.
- **K013 (eb86e9f, a1c2078).** OpenAPI 3.1 generated from the route table, and `arcaeon schema --format openapi`.
- **K012 (e868546, e8bac51).** `POST /v1/pin` (free, local) and the paid lane (`/v1/seal`, remote pin), which needs ARCAEON_KEY and `arcaeon serve --allow-paid` both.
- **K011 (db03ccb).** `POST /v1/receipt/verify` and `GET /v1/status`.
- **K010b (50c86af).** `arcaeon audit verify <directory>` reads the bundle's records.jsonl.
- **K010 (88abbc3).** `POST /v1/audit/verify` and `POST /v1/audit/export`.
- **K009b (0fb4055).** A subprocess smoke test for the token and the path fence.
- **K009 (ff10b30).** `POST /v1/reconcile`, tapes and kind readings.
- **K008 (f801dfd).** `POST /v1/log` and `POST /v1/verify`.
- **K007 (f6f123c).** Content-in mode: every path field also takes `content` or `content_b64`.
- **K006 (6fc757e).** Path fence: `arcaeon serve --root DIR`; a path outside it is 400.
- **K005 (f9a118e).** Token auth for `arcaeon serve`, with `~/.arcaeon/serve.token` and `--print-token`.
- **K004b (85a6ff3).** The parity fixture path passes the private-paths fence.
- **K004 (a2809e6).** `arcaeon serve`: the local HTTP/JSON API on 127.0.0.1 only.
- **K003 (21ef5b2).** The handler core, one function per route, with no HTTP in it.
- **K002b (102120e).** The evidence-pack verify route takes `witness` and `remote`; `export/aat` needs `out`.
- **K002 (9c3d58a).** The route table, `arcaeon.serve.routes`, declaring every HTTP route.
- **K001 (0cc7b44).** Ten verbs registered ahead of their code: `serve`, `connect`, `schema`, `second-read`, `evidence-pack`, `export`, `mandate`, `doctor`, `demo`, `open`.

### Before the plug-in batch (committed after 0.9.1)

- **Additive COULD NOT LOOK keys.** `looked_for`, `where` and `reason_word` beside the old `reason`, and `arcaeon.verdict.REASON_WORDS`.
- **The `status` verb.** `arcaeon status [--json]`.
- **The activity journal.** One line per verb run in `~/.arcaeon/activity.jsonl`; `ARCAEON_JOURNAL=0` turns it off.
- **`stamp` and `credits` exit codes.** A request that never completes is COULD NOT LOOK, exit 3.
- **`verify --witness`.** Compares a ledger with its last pin in a local pin file.
- **`log --field` and stdin.** A row with no JSON quoting on the command line.
- **The mandate gate.** `arcaeon proxy --mandate PATH`, record-only by default.
- **Deal tools over MCP.** `deal_mandate`, `deal_commit` and `deal_dispute`.
