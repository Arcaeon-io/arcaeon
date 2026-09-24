"""The sealed-scan credit debit (board item 84, 2026-09-05).

WHAT A SEALED SCAN IS. mcp-vet's badge is free and stays free, unsigned. A
SEALED scan is the same badge appended to THIS connector's ledger and that
ledger's head pinned with the hosted witness, so the scan is tamper-evident --
a stranger can be handed the ledger row and the public pin and confirm neither
was altered after the fact. The pin is the seal: the witness's /api/pin takes
{namespace, rows, chain} and verifies no client signature (seal-for-strangers,
2026-09-24; evidence in MIGRATION.md, "seal"). A badge the caller also signed
with their own MCP_VET_RECEIPT_KEY carries that receipt as SIGNED in addition;
without one the row says UNSIGNED and is sealed all the same. That is the whole thing a stranger
is paying for: not a better grade, not a human review, just a grade that
cannot be quietly edited after it shipped.

NO NEW BILLING RAIL. This module spends credit through the EXACT mechanism
`witness_pin` / `witness_renew` already spend it through: one HTTP POST to the
hosted witness's `/api/pin`, gated on `ARCAEON_KEY`, over the SAME balance
those two tools already draw from (arcaeon-witness's `_balance.js`,
`decrementCredit` -- one pin, once the free monthly cap is spent). No pack, no
price, no Stripe product is created here. `offers.SEALED_SCAN_PACK` documents
the storefront framing for a future dedicated $5-for-50 page; nothing in this
module reads or trusts it, and it has no live checkout to point at yet.

THE DEBIT IS THE PIN, AND IT RUNS LAST. `seal()` does, in order:
  1. refuse before touching anything if there is no usable ARCAEON_KEY;
  2. append `record` to the ledger (free -- this is the tamper-evidence);
  3. read the ledger's new head (rows, chain);
  4. spend ONE credit witnessing that head (`witness.pin`) -- this is the paid
     step. It can SPEND at most once per `seal()` call. With no --ns it may
     be called twice: a 403 on the default namespace (which the witness
     answers before any metering, so it spends nothing) that names the key's
     prefix is retried once under `<prefix>-sealed-scans`.
Steps 2-3 failing means step 4 never runs: a seal that never became a
tamper-evident row can never spend a credit on a claim that isn't backed by
one. Step 4 failing (no key reaches this point -- that is step 1 -- but a
network error, a revoked key, or an exhausted balance can) means the scan is
refused exactly like any other paid-lane refusal: a plain sentence, never a
crash, and the earlier ledger row stands (a true row: the badge really was
computed and really was appended) even though `sealed` comes back False.

`ledger_factory` and `pin` are seams for tests -- a stubbed ledger object and a
stubbed network call, per the item's own test list. Production code never
passes them.
"""
from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path
from typing import Any, Callable

from arcaeon.record.ledger import Ledger

from . import witness
from .offers import upgrade_message

#: Where sealed-scan records live by default: beside the connector's ordinary
#: ledger log (same directory convention `server.ns_dir()` / `call_record_path()`
#: use), in their own file -- this is mcp-vet's own record, not the caller's
#: general agent-conduct ledger, and not the connector's own call record
#: either. Read at CALL time, never cached: same rule as every other path in
#: this package (server.py's block comment states why).
SEALED_SCAN_LOG_ENV = "ARCAEON_SEALED_SCAN_LOG"

#: The namespace a seal tries first when no --ns is given: the original fixed
#: one, kept so a key whose prefix already covers it (the operator's own) keeps
#: pinning into the same history it always has.
NAMESPACE = "mcp-vet-sealed-scans"

#: What a key's own prefix is joined to for its derived default namespace.
SUFFIX = "sealed-scans"

# NAMESPACE FROM THE KEY (branch ns-from-key, 2026-09-24). A key pins only
# under its own namespace prefix, so for a stranger's key NAMESPACE is a 403.
# The witness names the prefix in exactly one JSON place the client can read:
# the 403 body of POST /api/pin, `this key may only pin namespaces starting
# with "<prefix>"` (arcaeon-witness api/pin.js, the startsWith check that runs
# BEFORE the rate limiter and before any metering, so the refusal spends no
# credit). /api/balance's JSON carries no prefix; the key string (wk_ + random
# hex) encodes none. So with no --ns, a seal tries NAMESPACE; on a 403 that
# names a prefix it remembers that prefix for this process and retries ONCE
# under <prefix>-sealed-scans. Later seals in the same process go straight to
# the derived namespace. An explicit --ns is never second-guessed.
_PREFIX_RE = re.compile(r'starting with "([a-z0-9-]{1,64})"')
_NS_RE = re.compile(r"^[a-z0-9-]{1,64}$")
#: sha256(key) -> the prefix the witness named for it, this process only.
_prefix_cache: dict[str, str] = {}


def _key_id(key: str) -> str:
    return hashlib.sha256(key.encode("utf-8")).hexdigest()


def _reset_prefix_cache() -> None:
    """Forget every learned prefix (tests; a long-lived process after a key swap)."""
    _prefix_cache.clear()


def prefix_from_refusal(pin_result: dict) -> str | None:
    """The namespace prefix a 403 from /api/pin names, or None if it names none."""
    if pin_result.get("status") != 403:
        return None
    m = _PREFIX_RE.search(str(pin_result.get("error") or ""))
    return m.group(1) if m else None


def namespace_for_prefix(prefix: str) -> str:
    """`<prefix>-sealed-scans`, without doubling the dash an auto-minted
    `wk-...-` prefix already ends in."""
    return prefix + SUFFIX if prefix.endswith("-") else prefix + "-" + SUFFIX


def default_namespace(key: str | None = None) -> str:
    """The namespace a seal with no --ns tries first: the derived one if this
    process already learned the key's prefix, else NAMESPACE. Makes no request."""
    key = key if key is not None else _key()
    prefix = _prefix_cache.get(_key_id(key)) if key else None
    return namespace_for_prefix(prefix) if prefix else NAMESPACE


def sealed_scan_log_path() -> Path:
    override = os.environ.get(SEALED_SCAN_LOG_ENV)
    if override:
        return Path(override)
    base = Path(os.environ.get("ARCAEON_LEDGER_LOG", "agent.log.jsonl")).resolve()
    return base.parent / "sealed_scans.jsonl"


def _key() -> str | None:
    """Same blank-is-unset semantics as `server._key()`, duplicated on purpose:
    importing `server` here would pull in `mcp_vet.server` (server.py's own
    import), and with it the optional `mcp` SDK, just to read one env var. A
    plain `mcp_vet badge --sealed` with no MCP extras installed must still be
    able to ask this question."""
    return os.environ.get("ARCAEON_KEY", "").strip() or None


def sealed_scan_refusal(key: str | None = None) -> str | None:
    """`None` when a sealed scan may proceed; a plain sentence when it may
    not. Checked BEFORE any ledger write, so a missing or blank key never
    leaves a row behind for a scan that was never going to be witnessed."""
    if key is None:
        key = _key()
    if key:
        return None
    return upgrade_message("sealed scan", free_tools=["the unsigned free badge"])


def _insufficient_credit(pin_result: dict) -> bool:
    return (pin_result.get("reason") == "credit_exhausted"
            or pin_result.get("status") == 402)


def seal(record: dict[str, Any], *, key: str | None = None,
         namespace: str | None = None,
         ledger_path: str | Path | None = None,
         ledger_factory: Callable[[Path], Any] = Ledger,
         pin: Callable[[str, int, str, str], dict] = witness.pin) -> dict[str, Any]:
    """Seal `record` (mcp-vet hands in the signed badge/receipt). Returns:

      {"sealed": True,  "namespace": "...", "ledger_head": {...}, "pin": {...}}
      {"sealed": False, "reason": "..."}                         (no key)
      {"sealed": False, "reason": "...", "append_error": "..."}  (ledger append
                                                                   failed; the
                                                                   pin never ran)
      {"sealed": False, "reason": "...", "ledger_head": {...}, "pin": {...}}
                                                                  (pin refused --
                                                                   no credit was
                                                                   spent; the
                                                                   ledger row
                                                                   still stands)
    """
    refused = sealed_scan_refusal(key)
    if refused:
        return {"sealed": False, "reason": refused}
    resolved_key = key if key is not None else _key()

    path = Path(ledger_path) if ledger_path else sealed_scan_log_path()
    ledger = ledger_factory(path)

    try:
        ledger.append(dict(record))
        head = ledger.head()
    except Exception as exc:  # noqa: BLE001 - a refusal must never be a traceback
        return {
            "sealed": False,
            "reason": (
                "sealed scan refused: the record could not be committed to "
                "the connector's ledger (%s). No credit was spent -- the "
                "witness pin only runs after a successful ledger append."
                % exc),
            "append_error": str(exc),
        }

    explicit = namespace is not None
    ns = namespace if explicit else default_namespace(resolved_key)
    result = pin(ns, head.rows, head.chain, resolved_key)
    prefix = prefix_from_refusal(result) if not result.get("ok") else None
    if prefix:
        _prefix_cache[_key_id(resolved_key)] = prefix
        derived = namespace_for_prefix(prefix)
        # One retry, only for the default, only when the witness named a
        # prefix and the derived name is one the witness would accept. The
        # 403 spent nothing, so this is still at most one credit per seal.
        if not explicit and derived != ns and _NS_RE.match(derived):
            ns = derived
            result = pin(ns, head.rows, head.chain, resolved_key)
            prefix = prefix_from_refusal(result) if not result.get("ok") else None
    ledger_head = {"rows": head.rows, "chain": head.chain}
    if not result.get("ok"):
        if _insufficient_credit(result):
            reason = (
                "sealed scan refused: credit balance is zero. The badge "
                "record above was appended to the ledger (true, but "
                "unwitnessed); top up at the connector's existing $5 pack "
                "and re-run --sealed to witness it. %s"
                % (result.get("error") or ""))
        elif result.get("status") == 403:
            if prefix:
                hint = ("The witness says this key pins only under prefix %r; "
                        "pass --ns %s." % (prefix, namespace_for_prefix(prefix)))
            else:
                hint = ("A key pins only under its own prefix; pass --ns "
                        "<your-prefix>-sealed-scans.")
            reason = (
                "sealed scan refused: this ARCAEON_KEY may not pin namespace "
                "%r. %s No credit was spent. %s"
                % (ns, hint, result.get("error") or ""))
        else:
            reason = (
                "sealed scan refused: the witness did not accept the pin "
                "(%s). No credit was spent. %s"
                % (result.get("status"), result.get("error") or ""))
        return {"sealed": False, "reason": reason.strip(), "namespace": ns,
                "ledger_head": ledger_head, "pin": result}

    return {
        "sealed": True,
        "namespace": ns,
        "ledger_head": ledger_head,
        "pin": result,
    }
