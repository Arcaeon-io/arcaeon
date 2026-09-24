"""arcaeon_connector.sealed_scan -- the paid sealed-scan credit debit (board
item 84, 2026-09-05, item_84_sealed_scan_2026-09-05.md).

No MCP round-trip here on purpose: `seal()` is a plain library call mcp-vet's
CLI invokes directly (`mcp_vet.badge_cli.seal_badge`), never an MCP tool of
its own, so these tests call it the same way its one real caller does.

MUST-HIT: no key refuses before any ledger write; a failed ledger append
never reaches the witness (debit is zero); a successful seal debits (calls
the witness) EXACTLY ONCE; a zero/insufficient credit balance refuses with a
plain message and the ledger row still stands.

MUST-MISS: a real key with a healthy balance still seals, end to end, against
a real (tmp) `Ledger` -- proving the must-hit arms are not just "everything
refuses".

Ledger and network are both stubbed, per the item's own instruction: the real
`arcaeon_ledger.Ledger` is used but always against a `tmp_path` file (never a
real one), and the one function that ever touches a socket
(`witness._http_post`) is monkeypatched in every test, the same seam
`test_empty_key.py` already uses.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from arcaeon.record.ledger import Ledger  # noqa: E402

from arcaeon.remote import offers, sealed_scan, witness  # noqa: E402

RECORD = {"op": "mcp_vet_sealed_scan", "target": "acme-server", "verdict": "clean"}


def _isolate(monkeypatch, tmp_path):
    monkeypatch.setenv("ARCAEON_LEDGER_LOG", str(tmp_path / "agent.log.jsonl"))
    monkeypatch.delenv(sealed_scan.SEALED_SCAN_LOG_ENV, raising=False)
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    monkeypatch.delenv(offers.SEALED_SCAN_PACK["checkout_env"], raising=False)


def _count_posts(monkeypatch, response=(201, {"ok": True})):
    """Same seam `test_empty_key.py` uses: replace the one function that ever
    talks to the witness with a counter, so 'the network happened' is a
    countable fact rather than an assumption."""
    posted = []

    def fake(url, body, key, timeout=20.0):
        posted.append({"url": url, "body": dict(body), "key": key})
        return response

    monkeypatch.setattr(witness, "_http_post", fake)
    return posted


class _NeverCalledLedger:
    """A ledger stub that fails the test if it is ever constructed. Used to
    prove the no-key refusal happens before any ledger write is attempted."""

    def __init__(self, path):  # pragma: no cover - the assertion IS the point
        raise AssertionError(f"ledger must not be touched: {path}")


class _AppendFailsLedger:
    """A ledger stub whose append() raises. Used to prove a failed append
    never reaches the witness."""

    def __init__(self, path):
        self.path = path

    def append(self, record):
        raise OSError("disk is full (simulated)")

    def head(self):  # pragma: no cover - append() always raises first
        raise AssertionError("head() must not be called after a failed append")


# --- MUST-HIT: no key refuses before any ledger write -----------------------

def test_no_key_refuses_before_touching_the_ledger(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    posted = _count_posts(monkeypatch)

    out = sealed_scan.seal(RECORD, ledger_factory=_NeverCalledLedger)

    assert out["sealed"] is False
    assert "ARCAEON_KEY" in out["reason"]
    assert posted == [], "no key must never reach the witness"


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_blank_key_refuses_the_same_way_as_unset(monkeypatch, tmp_path, value):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("ARCAEON_KEY", value)
    posted = _count_posts(monkeypatch)

    out = sealed_scan.seal(RECORD, ledger_factory=_NeverCalledLedger)

    assert out["sealed"] is False
    assert "ARCAEON_KEY" in out["reason"]
    assert posted == []


# --- MUST-HIT: a failed ledger append never debits --------------------------

def test_failed_ledger_append_never_calls_the_witness(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("ARCAEON_KEY", "dummy-key-not-real")
    posted = _count_posts(monkeypatch)

    out = sealed_scan.seal(RECORD, ledger_factory=_AppendFailsLedger)

    assert out["sealed"] is False
    assert "disk is full" in out["reason"] or "disk is full" in out.get("append_error", "")
    assert posted == [], "a failed append must never reach the witness (zero debit)"


# --- MUST-HIT: a successful seal debits EXACTLY ONCE -------------------------

def test_successful_seal_calls_the_witness_exactly_once(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("ARCAEON_KEY", "dummy-key-not-real")
    posted = _count_posts(monkeypatch)

    out = sealed_scan.seal(RECORD, ledger_path=tmp_path / "sealed.jsonl")

    assert out["sealed"] is True, out
    assert len(posted) == 1, posted
    assert posted[0]["key"] == "dummy-key-not-real"
    assert posted[0]["url"].endswith("/api/pin")
    assert out["pin"]["ok"] is True
    assert out["ledger_head"]["rows"] == 1
    assert isinstance(out["ledger_head"]["chain"], str) and out["ledger_head"]["chain"]


def test_two_sealed_scans_debit_twice_not_once(monkeypatch, tmp_path):
    """Guards the OTHER direction of 'exactly once': a caching or memoized
    seam that quietly reused the first pin would make a second paid scan
    free. Two calls, two posts, two distinct heads."""
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("ARCAEON_KEY", "dummy-key-not-real")
    posted = _count_posts(monkeypatch)
    path = tmp_path / "sealed.jsonl"

    first = sealed_scan.seal(RECORD, ledger_path=path)
    second = sealed_scan.seal(RECORD, ledger_path=path)

    assert len(posted) == 2, posted
    assert first["sealed"] is True and second["sealed"] is True
    assert first["ledger_head"]["rows"] == 1
    assert second["ledger_head"]["rows"] == 2
    assert first["ledger_head"]["chain"] != second["ledger_head"]["chain"]


def test_the_ledger_row_really_lands_on_disk(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("ARCAEON_KEY", "dummy-key-not-real")
    _count_posts(monkeypatch)
    path = tmp_path / "sealed.jsonl"

    sealed_scan.seal(RECORD, ledger_path=path)

    v = Ledger(path).verify(strict=True)
    assert v.ok is True and v.rows == 1, v


# --- MUST-HIT: zero/insufficient credit balance refuses ---------------------

def test_zero_balance_refuses_with_a_plain_message_and_no_traceback(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("ARCAEON_KEY", "dummy-key-not-real")
    posted = _count_posts(monkeypatch, response=(402, {
        "error": "credit balance exhausted -- top up to continue",
        "reason": "credit_exhausted",
        "credit_balance": 0,
    }))

    out = sealed_scan.seal(RECORD, ledger_path=tmp_path / "sealed.jsonl")

    assert out["sealed"] is False
    assert "credit balance is zero" in out["reason"]
    assert len(posted) == 1, "the pin is still attempted once; it is refused, not skipped"
    for leak in ("Traceback", 'File "', "Exception"):
        assert leak not in out["reason"], out["reason"]
    # the free ledger row still stands even though nothing was witnessed
    assert out["ledger_head"]["rows"] == 1


def test_a_generic_witness_refusal_also_refuses_cleanly(monkeypatch, tmp_path):
    """Not every non-2xx is a balance problem (a revoked key, a network
    blip). All of them must refuse the same clean way -- never a crash."""
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("ARCAEON_KEY", "dummy-key-not-real")
    _count_posts(monkeypatch, response=(401, {"error": "revoked"}))

    out = sealed_scan.seal(RECORD, ledger_path=tmp_path / "sealed.jsonl")

    assert out["sealed"] is False
    assert "witness did not accept the pin" in out["reason"]
    assert "credit balance is zero" not in out["reason"]


# --- MUST-MISS: a real key with a healthy balance seals end to end ---------

def test_must_miss_a_healthy_key_seals_end_to_end(monkeypatch, tmp_path):
    """Without this arm, a `seal()` that refused unconditionally would pass
    every test above."""
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("ARCAEON_KEY", "  dummy-key-not-real  ")
    _count_posts(monkeypatch)

    out = sealed_scan.seal(RECORD, ledger_path=tmp_path / "sealed.jsonl")

    assert out["sealed"] is True
    assert "reason" not in out


# --- sealed_scan_refusal(), unit-level --------------------------------------

def test_sealed_scan_refusal_names_the_free_badge_as_still_free(monkeypatch):
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    msg = sealed_scan.sealed_scan_refusal()
    assert msg is not None
    assert "unsigned free badge" in msg
    assert "ARCAEON_KEY" in msg


def test_sealed_scan_refusal_is_none_for_a_real_key():
    assert sealed_scan.sealed_scan_refusal(key="a-real-key") is None


# --- offers.SEALED_SCAN_PACK: documented SKU, never a live grant ------------

def test_sealed_scan_pack_has_no_live_checkout_unlike_mini_pack():
    """MINI_PACK is real and carries a `checkout` URL. SEALED_SCAN_PACK is
    documentation for a page that does not exist yet and must not pretend
    otherwise."""
    assert "checkout" not in offers.SEALED_SCAN_PACK
    assert offers.SEALED_SCAN_PACK["checkout_env"] == "STRIPE_PAYMENT_LINK_SEALED_SCAN_50"
    assert "checkout" in offers.MINI_PACK


def test_resolve_sealed_scan_sku_is_none_with_no_purchase(monkeypatch):
    monkeypatch.delenv(offers.SEALED_SCAN_PACK["checkout_env"], raising=False)
    assert offers.resolve_sealed_scan_sku(None) is None
    assert offers.sealed_scan_sku_unconfigured(None) is False


def test_resolve_sealed_scan_sku_never_grants_off_a_missing_var(monkeypatch):
    """The missing-var case ascenvo's webhook answers with 503-and-park: it
    must never be readable as a resolved purchase."""
    monkeypatch.delenv(offers.SEALED_SCAN_PACK["checkout_env"], raising=False)
    assert offers.resolve_sealed_scan_sku("plink_someone_paid_for_something") is None
    assert offers.sealed_scan_sku_unconfigured("plink_someone_paid_for_something") is True


def test_resolve_sealed_scan_sku_resolves_once_configured(monkeypatch):
    monkeypatch.setenv(offers.SEALED_SCAN_PACK["checkout_env"], "plink_the_real_one")
    assert offers.resolve_sealed_scan_sku("plink_the_real_one") == "sealed_scan_50"
    assert offers.sealed_scan_sku_unconfigured("plink_the_real_one") is False


def test_resolve_sealed_scan_sku_an_unmatched_link_is_an_unknown_price_not_missing_var(monkeypatch):
    """Every mapping var present and the link still doesn't match: a product
    we do not sell, per ascenvo's own distinction -- NOT the missing-var
    finding."""
    monkeypatch.setenv(offers.SEALED_SCAN_PACK["checkout_env"], "plink_the_real_one")
    assert offers.resolve_sealed_scan_sku("plink_something_else") is None
    assert offers.sealed_scan_sku_unconfigured("plink_something_else") is False


# --- ns-from-key (2026-09-24): the default namespace follows the key's prefix --
# The witness names a key's prefix only in the 403 body of /api/pin
# (`this key may only pin namespaces starting with "<prefix>"`), which it sends
# before any metering. Mocked at witness._http_post; no real call.

def _witness_with_prefix(monkeypatch, prefix):
    """A fake witness that behaves like api/pin.js: 403 naming the prefix for
    any namespace outside it, 201 inside it."""
    posted = []

    def fake(url, body, key, timeout=20.0):
        posted.append({"url": url, "body": dict(body)})
        if body["namespace"].startswith(prefix):
            return 201, {"ok": True}
        return 403, {"error": f'this key may only pin namespaces starting with "{prefix}"'}

    monkeypatch.setattr(witness, "_http_post", fake)
    return posted


def test_default_namespace_is_derived_from_the_403_and_retried_once(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("ARCAEON_KEY", "dummy-key-not-real")
    posted = _witness_with_prefix(monkeypatch, "wk-0a1b2c3d4e5f-")

    out = sealed_scan.seal(RECORD, ledger_path=tmp_path / "sealed.jsonl")

    assert out["sealed"] is True, out
    assert out["namespace"] == "wk-0a1b2c3d4e5f-sealed-scans"
    assert [p["body"]["namespace"] for p in posted] == [
        "mcp-vet-sealed-scans", "wk-0a1b2c3d4e5f-sealed-scans"]


def test_the_learned_prefix_is_cached_so_the_next_seal_is_one_request(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("ARCAEON_KEY", "dummy-key-not-real")
    posted = _witness_with_prefix(monkeypatch, "acme")

    sealed_scan.seal(RECORD, ledger_path=tmp_path / "sealed.jsonl")
    del posted[:]
    out = sealed_scan.seal(RECORD, ledger_path=tmp_path / "sealed.jsonl")

    assert out["sealed"] is True
    assert [p["body"]["namespace"] for p in posted] == ["acme-sealed-scans"]
    assert sealed_scan.default_namespace("dummy-key-not-real") == "acme-sealed-scans"
    # a different key learned nothing
    assert sealed_scan.default_namespace("another-key-not-real") == sealed_scan.NAMESPACE


def test_a_key_that_covers_the_old_namespace_still_pins_there_in_one_request(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("ARCAEON_KEY", "dummy-key-not-real")
    posted = _witness_with_prefix(monkeypatch, "mcp-vet-")

    out = sealed_scan.seal(RECORD, ledger_path=tmp_path / "sealed.jsonl")

    assert out["sealed"] is True and out["namespace"] == "mcp-vet-sealed-scans"
    assert len(posted) == 1


def test_an_explicit_ns_is_never_retried_and_the_403_names_the_exact_ns(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("ARCAEON_KEY", "dummy-key-not-real")
    posted = _witness_with_prefix(monkeypatch, "wk-0a1b2c3d4e5f-")

    out = sealed_scan.seal(RECORD, namespace="someone-else",
                           ledger_path=tmp_path / "sealed.jsonl")

    assert out["sealed"] is False and len(posted) == 1
    assert "'someone-else'" in out["reason"]
    assert "--ns wk-0a1b2c3d4e5f-sealed-scans" in out["reason"]
    assert "No credit was spent" in out["reason"]


def test_a_403_that_names_no_prefix_gets_the_generic_line_and_no_retry(monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("ARCAEON_KEY", "dummy-key-not-real")
    posted = _count_posts(monkeypatch, response=(403, {"error": "forbidden"}))

    out = sealed_scan.seal(RECORD, ledger_path=tmp_path / "sealed.jsonl")

    assert out["sealed"] is False and len(posted) == 1
    assert "'mcp-vet-sealed-scans'" in out["reason"]
    assert "--ns <your-prefix>-sealed-scans" in out["reason"]


def test_prefix_parsing_and_joining():
    ok = {"status": 403, "error": 'this key may only pin namespaces starting with "wk-ab-"'}
    assert sealed_scan.prefix_from_refusal(ok) == "wk-ab-"
    assert sealed_scan.prefix_from_refusal({**ok, "status": 401}) is None
    assert sealed_scan.prefix_from_refusal({"status": 403}) is None
    assert sealed_scan.namespace_for_prefix("wk-ab-") == "wk-ab-sealed-scans"
    assert sealed_scan.namespace_for_prefix("acme") == "acme-sealed-scans"
