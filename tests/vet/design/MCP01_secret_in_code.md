# MCP01 — Secret In Code

Design only (F4, 2026-08-30). **Not implemented here** — `mcp_vet/checks.py`
is being edited by another agent concurrently; this document is the spec to
implement against once that lands, plus a planted fixture
(`tests/fixtures/secret_in_code_server.py`) to develop and test it with. No
code in `mcp_vet/` was touched writing this.

## Why this class, and why it's numbered

Every check shipped so far (`unsafe-exec`, `ssrf`, `path-traversal`,
`zero-auth`) asks "can this server be made to do something dangerous."
Secret-in-code asks a different question: "is this server, right now, at
rest, handing out a credential to anyone who reads the source" — the MCP
equivalent of committing `.env` to git. It maps to OWASP's own catalog
(A05:2021 — Security Misconfiguration / CWE-798 Use of Hard-coded
Credentials), which is the reasoning behind giving it a catalog-style id
(`MCP01`) rather than the bare-name convention the first four checks use —
`grade.py`'s honesty contract (blind spots carried IN the grade) reads
better against a catalog than a private label, and it leaves room to number
future classes the same way instead of retrofitting IDs later.

## What it catches

Three independent pattern families, each cheap and precision-first (the
project's own stated bias: "a check would rather miss than cry a false
red" — `checks.py` module docstring):

### 1. Known-vendor key SHAPES (string-constant regex, no context needed)

These prefixes are effectively unique fingerprints — matching one is strong
evidence on its own, independent of variable name:

| vendor | pattern | notes |
|---|---|---|
| AWS access key ID | `\bAKIA[0-9A-Z]{16}\b` | also `\bASIA[0-9A-Z]{16}\b` for STS temp creds |
| AWS secret access key | `\b[A-Za-z0-9/+=]{40}\b` **and** appears as the value of a name matching `aws_secret`/`secret_access_key` (case-insensitive) | the bare 40-char shape alone is too common (base64 of anything); gate it on the assignment target name to keep this precision-first |
| Stripe secret/restricted key | `\bsk_live_[0-9a-zA-Z]{24,}\b`, `\brk_live_[0-9a-zA-Z]{24,}\b` | `_test_` variants are intentionally NOT flagged — see "What it deliberately does not catch" |
| Stripe webhook signing secret | `\bwhsec_[0-9a-zA-Z]{24,}\b` | |
| OpenAI key | `\bsk-[A-Za-z0-9]{20,}\b`, `\bsk-proj-[A-Za-z0-9_-]{20,}\b`, `\bsk-svcacct-[A-Za-z0-9_-]{20,}\b` | the bare `sk-` shape overlaps Stripe's restricted-key prefix (`rk_`) in spirit only, not string form, so no collision |
| GitHub token | `\bghp_[A-Za-z0-9]{36}\b`, `\bgho_[A-Za-z0-9]{36}\b`, `\bghu_[A-Za-z0-9]{36}\b`, `\bghs_[A-Za-z0-9]{36}\b`, `\bghr_[A-Za-z0-9]{36}\b`, `\bgithub_pat_[A-Za-z0-9_]{22,}\b` | fine-grained PAT uses the `github_pat_` form |

Each is checked against `ast.Constant` string nodes only (never against
comments or arbitrary source text) so a match always has a concrete AST
location — same evidence discipline as the existing checks (`file` + `line`
on every `Finding`).

### 2. High-entropy string assigned to a `*_KEY` / `*_TOKEN` / `*_SECRET` name

Catches the vendor-agnostic case: an assignment (`ast.Assign` /
`ast.AnnAssign`, module-level or in a class body — NOT inside a function
whose body is loading from `os.environ`, see below) where:

- the target name matches `(?i)(_KEY|_TOKEN|_SECRET|_CREDENTIAL|APIKEY)$` (or
  a dict/kwarg key of the same shape — `headers = {"Authorization": "..."}`
  is a realistic MCP-server leak site and should not require a bare
  variable),
- the value is an `ast.Constant` string, length >= 16,
- and the string's Shannon entropy is above a threshold (~3.5 bits/char is
  the common industry cutoff — high enough that `"changeme"`,
  `"your_key_here"`, `"REPLACE_ME"`, `"xxxxxxxxxxxxxxxx"`, `"test"`,
  `"<KEY>"`, `"${API_KEY}"` and empty-string defaults all fall below it and
  are never flagged; this is the single biggest lever for keeping this class
  precision-first, since it is also the class most exposed to noise).

Severity `"medium"` when only the entropy heuristic fires (vendor-shape
matches are `"high"` — they're a fingerprint, not a guess).

### 3. `.env`-shaped literal embedded in source

A string literal (docstring, triple-quoted block, or an f-string used as a
"here's the config" comment-substitute — all three show up in real MCP
servers as inline setup instructions) containing a line matching
`^[A-Z][A-Z0-9_]*=\S{8,}$` where the value half also clears the entropy bar
from class 2, OR matches a vendor shape from class 1. This is the case R5's
adjacent finding (F12, secret scrubber extended to server-code context) is
really about: a real key doesn't have to be *assigned* to leak, it can be
*quoted* — in a README block pasted into the module docstring, in a
"here's a working example" comment. Scope note: this class reads string
literals already inside the parsed `.py` AST; it does NOT open sibling
`.env` files on disk. Scanning actual `.env` files sitting next to a vetted
server is a real and useful extension but is a different I/O shape (line
scanner over a non-Python file, not an AST walk) — flagged here as a
follow-up, not folded in, so this class stays true to "AST-based, no code
execution" scope as written in the `checks.py` module docstring.

## What it deliberately does not catch (goes in `BLIND_SPOTS`, honestly)

- `sk_test_...` / `pk_test_...` / `pk_live_...` (Stripe publishable and test
  keys) — publishable keys are meant to be client-visible by design; test
  keys are the recommended thing to hardcode in fixtures and examples. Not
  flagging them is a choice about signal, not an oversight, but it means a
  test key rotated-to-prod without renaming stays invisible to MCP01.
- A secret loaded through `os.environ["STRIPE_KEY"]` / `os.getenv(...)` /
  `dotenv.load_dotenv()` is the CORRECT pattern and must never be flagged —
  the check only fires on a literal string constant as the value, never on
  a `Call` or `Subscript` node, so this is true by construction rather than
  requiring an allowlist.
- Secrets built at runtime by concatenation or `base64.b64decode(...)` of an
  otherwise-innocuous-looking split string is a known evasion (same family
  as the dynamic-import-around-os.system dodge that closed a blind spot in
  `unsafe-exec` on 2026-08-30) and is out of scope for a first pass.
- Entropy-based detection cannot tell a real leaked key from a
  well-formed-looking placeholder that happens to clear the entropy bar
  (e.g. a hash used as a non-secret cache key). This is why class 2 is
  `"medium"` severity, not `"high"` — same severity-reflects-confidence
  pattern the `ssrf` check already uses (tainted target = `"high"`,
  untainted = `"medium"`).

## Proposed shape (for whoever implements)

```python
def check_secret_in_code(tree: ast.AST, rel: str, source: str) -> list[Finding]:
    ...
```

Signature matches `check_zero_auth`'s pattern (needs `source` for the
docstring/literal-scan class, not just the AST) rather than `check_ssrf`'s
tree-only signature. `Finding.check` value: `"secret-in-code"`. Integration
touch points once implemented — none edited by this pass:

- `scan_source()` — add to the concatenated check list.
- `grade.py: CHECK_CLASSES` — append `"secret-in-code"`.
- `grade.py: BLIND_SPOTS` — remove nothing (this closes a gap, doesn't open
  one), but the four "what it deliberately does not catch" bullets above
  belong there as new entries so the grade stays honest about the new
  check's own edges, the same way the existing four blind spots document
  the first four checks' edges.

## Fixture

`tests/fixtures/secret_in_code_server.py` — a planted MCP-server-shaped file
with 3 fake keys, one per vendor-shape class (AWS, Stripe, GitHub), each
loud-marked `FAKE` in an adjacent comment so nothing downstream (secret
scrubbers, this repo's own anonymization tooling, a future contributor
grepping the codebase) mistakes it for a real leak. Also includes one
negative control — a key loaded correctly from `os.environ` — so a future
test can assert the check does NOT fire on it, matching the "false-negative
found, false-positive avoided" discipline the existing test suite already
holds unsafe-exec and ssrf to (`test_checks.py`).
