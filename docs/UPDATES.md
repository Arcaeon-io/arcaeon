# Updates: the version check-in and the support schedule

This page is the draft of the published schedule page. The source of truth is
the signed file `https://arcaeon.io/latest.json`, not this page: where the two
disagree, the signed file wins, and this page is corrected.

## What the check-in does

Once a day at most, the `arcaeon` command line asks arcaeon.io which version
is current. The MCP server (`arcaeon mcp`) asks once at start, under the same
once-a-day limit, without making the server wait. The answer is checked,
cached, and turned into at most one line for you.

It runs after these verbs only: `log`, `pin`, `deal`, `escrow`, `mandate`,
`badge`, `seal`, `distill`, `dedup`, `meter`, `export`, `stamp`, `credits`,
`buy`, `connect`, `schema`, `open`, `status`, `version`, `doctor`, `demo`.
No checking verb asks: `arcaeon verify`, `receipt`, `envelope`, `gate`,
`audit`, `reconcile`, `compact`, `evidence-pack`, `exchange` and `tally`
never fetch anything.

## What it sends

One plain HTTPS GET of `https://arcaeon.io/latest.json` with two headers:

```text
User-Agent: arcaeon/<your installed version>
Accept: application/json
```

Nothing else: no id, no account, no key, no file path, no host name, no
cookie, no query string. The server sees your IP address, as any web request
does.

If arcaeon.io cannot be reached at all, the same request shape goes to PyPI's
public JSON for the project (`https://pypi.org/pypi/arcaeon/json`).

## How to turn it off

```text
ARCAEON_NO_CHECKIN=1
```

With that set there is no fetch, no line, and no cache file. Offline, the
check-in prints nothing and fails nothing: a verb's output and exit code are
the same with it on, off, or unreachable.

The cache is one file: `checkin.json` in `$ARCAEON_HOME`, else `~/.arcaeon`.
Deleting it is safe.

## The two lines

A person sees exactly one of these, or nothing:

| line | what it means |
|---|---|
| `Update to the latest version.` | a newer version than yours is out |
| `This version is no longer supported.` | your version is older than the oldest supported one |

When both are true, only the second is shown. The line never carries dates,
version numbers or a schedule; those are below and in the signed file.

Where you see it:

- the command line, on stderr, once a day at most;
- the top of `arcaeon verify`'s stderr, every run, read from the cache (verify
  never fetches; with no cache or with the check-in off, verify's output is
  unchanged);
- the MCP server's instructions text, from the cache at start.

To update: `pip install -U arcaeon`.

## What an agent sees

The MCP status tool (`arcaeon_status`) and the `arcaeon verify` JSON report
carry a `checkin` block with the full detail:

```json
{"installed": "0.10.0", "latest": "...", "minimum_supported": "...",
 "block_after": {"version": "...", "date": "..."}, "notice": "...",
 "upgrade_command": "pip install -U arcaeon", "signature": "VERIFIED",
 "source": "https://arcaeon.io/latest.json", "fetched_at": "...Z",
 "line": "Update to the latest version.", "ignored_because": null}
```

`signature` is one of:

| word | meaning |
|---|---|
| VERIFIED | signed by a key this version of arcaeon trusts, and unedited |
| BROKEN | the file was edited, malformed, or signed by a key this version does not trust: ignored, `ignored_because` says why |
| COULD NOT LOOK | no answer could be checked (offline, or no trusted key in this version): ignored |
| unsigned | the PyPI fallback: it can only ever say `Update to the latest version.` and never overrides a signed answer |

The verify report's `checkin` block is present only when the check-in is on
and something is cached. The MCP status tool says `{"off": true, ...}` when
it is off.

## The signed file

```json
{"payload": {"kind": "arcaeon.latest", "schema": 1,
             "latest": "...", "minimum_supported": "...",
             "block_after": {"version": "...", "date": "YYYY-MM-DD"},
             "notice": "...", "issued_at": "YYYY-MM-DDTHH:MM:SSZ"},
 "signatures": [{"keyid": "did:key:z6Mk...", "sig": "<base64>"}]}
```

The signature is Ed25519 over the JCS (RFC 8785) canonical bytes of
`payload`. The trusted signer ids are a constant inside the package
(`arcaeon.checkin.CHECKIN_KEYS`); no environment variable or config file can
add or replace one. A file signed by any other key, or edited after signing,
is ignored. An answer older (by `issued_at`) than the signed one already
cached does not replace it. The file is written with
`tools/make_latest_json.py`.

## The warn-to-block schedule

The plan: receiving surfaces start in warn-only mode and begin refusing
unverified files at a published cutoff. The cutoff is set in the signed file's
`block_after`; this table mirrors it.

| stage | version | date | what changes |
|---|---|---|---|
| warn only | set by the release owner | set by the release owner | receivers warn on an unverified file and still act |
| minimum supported | set by the release owner | set by the release owner | older versions see `This version is no longer supported.` |
| block after | set by the release owner | set by the release owner | receivers refuse to act on an unverified file unless opted out by flag |

## Limits

- The check-in is a nudge, not an enforcement: nothing stops an old version
  from running, and the line never changes an exit code.
- Until the release owner's key is in `CHECKIN_KEYS`, every signed answer
  reads COULD NOT LOOK and no signed line is shown; only the unsigned PyPI
  fallback (when arcaeon.io is unreachable) can say `Update to the latest
  version.`
- Someone who controls your network can block the check-in or replay an old
  signed file. They cannot forge a new answer without the key, and an older
  file does not replace a newer cached one, but a blocked or replayed check-in
  can keep the line from showing.
- PyPI's answer is unsigned. It is used only when arcaeon.io cannot be
  reached, can only ever say `Update to the latest version.`, and is labelled
  `unsigned` for agents.
- The server sees that a request came from your IP address with your version
  string. That is all it sees.
