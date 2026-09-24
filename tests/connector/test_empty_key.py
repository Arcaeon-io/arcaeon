"""An empty ARCAEON_KEY is refused, and is never sent as a credential.

Board item 39 (BATCH_100_2026-09-05_PROPOSED.md): "Prove
`arcaeon_connector/server.py:123` refuses on an empty ARCAEON_KEY; defaulting a
key to `""` is the fail-open-to-unauthenticated shape until the gate is shown to
reject it."

WHAT THE PROOF FOUND. It already refuses. `_key()` is
`os.environ.get("ARCAEON_KEY", "").strip() or None`, where the `""` is a
sentinel for `.strip()` and not a default credential: both `""` and `"   "`
collapse to None, which is the same value an unset variable produces, so the
paid-lane handler returns the upgrade message and nothing reaches the wire. The
fail-open shape the item was right to suspect looks like
`os.environ.get("ARCAEON_KEY", "")` returned bare, which would put
`Authorization: Bearer ` on the wire and let the witness decide what an
unauthenticated caller is.

So the gap was not behaviour, it was EVIDENCE: the existing suite covered unset
and set, and nothing covered empty or whitespace-only, which is the state a
half-written `.env`, a shell `export ARCAEON_KEY=`, or a secrets manager that
resolved to nothing actually produces. This file is that missing half.

MUST-HIT arms: empty and whitespace-only refuse, on both paid tools, with a
message naming the variable, and with the HTTP hop counted and proven unused.
MUST-MISS arm: a real key still passes through untouched. A gate that refused
everything would pass every must-hit test here and be worthless.
"""
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

pytest.importorskip("mcp", reason="the connector IS an MCP server")

from arcaeon.remote import witness  # noqa: E402
from arcaeon.mcp.server import _key  # noqa: E402

# Reused rather than copied: `_isolate` is the fixture that guarantees a real
# key in the developer's own shell cannot leak into a gating assertion, and a
# second copy of it here would be a second thing to keep in step.
from test_connector import _call, _isolate  # noqa: E402

BLANK_VALUES = [("", "empty string"), ("   ", "spaces"), ("\t\n", "tab and newline")]
HEAD = {"namespace": "acme-ledger", "rows": 7, "chain": "a1b2c3d4"}


def _count_posts(monkeypatch):
    """Replace the one function that talks to the witness with a counter. The
    seam is named in witness.py's own docstring for exactly this reason: it is
    the line between 'our gate let it through' and 'the network happened'."""
    posted = []
    monkeypatch.setattr(
        "arcaeon.remote.witness._http_post",
        lambda url, body, key, timeout=20.0: (
            posted.append({"url": url, "key": key}) or (201, {"ok": True})),
    )
    return posted


def _text(out):
    return out if isinstance(out, str) else json.dumps(out)


# --- the resolver itself ---------------------------------------------------

def test_key_resolver_treats_blank_exactly_like_unset(monkeypatch):
    """The unit-level table. `""` is a sentinel for strip, not a credential."""
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    assert _key() is None, "unset must be None"

    for value, label in BLANK_VALUES:
        monkeypatch.setenv("ARCAEON_KEY", value)
        assert _key() is None, f"{label} must resolve to None, got {_key()!r}"

    monkeypatch.setenv("ARCAEON_KEY", "  padded-key  ")
    assert _key() == "padded-key", "a real key must be normalised, not rejected"


# --- MUST-HIT: a blank key refuses, and never leaves the process ------------

@pytest.mark.parametrize("value,label", BLANK_VALUES)
def test_blank_key_refuses_witness_pin_and_names_the_env_var(
        value, label, monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("ARCAEON_KEY", value)
    posted = _count_posts(monkeypatch)

    text = _text(_call("witness_pin", HEAD))

    assert "ARCAEON_KEY" in text, f"{label}: the refusal must name the variable: {text}"
    assert posted == [], f"{label}: a blank key reached the witness: {posted}"


@pytest.mark.parametrize("value,label", BLANK_VALUES)
def test_blank_key_refuses_witness_renew_too(value, label, monkeypatch, tmp_path):
    """Two paid tools, one gate. The second must not be a copy that forgot it."""
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("ARCAEON_KEY", value)
    posted = _count_posts(monkeypatch)

    text = _text(_call("witness_renew", HEAD))

    assert "ARCAEON_KEY" in text, f"{label}: {text}"
    assert posted == [], f"{label}: a blank key reached the witness: {posted}"


def test_the_blank_key_refusal_is_the_same_product_surface_as_the_unset_one(
        monkeypatch, tmp_path):
    """A blank key is not a lesser state than an unset one. It gets the same
    complete answer: what it costs, where the free door is, what to set."""
    _isolate(monkeypatch, tmp_path)
    _count_posts(monkeypatch)

    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    unset = _text(_call("witness_pin", HEAD))
    monkeypatch.setenv("ARCAEON_KEY", "   ")
    blank = _text(_call("witness_pin", HEAD))

    assert blank == unset, "a blank key must not get a different answer than unset"
    assert "buy.stripe.com" in blank and "ARCAEON_KEY" in blank, blank
    for leak in ("Traceback", 'File "', "urllib", "Exception"):
        assert leak not in blank, f"stack-trace leak in the refusal: {blank}"


@pytest.mark.parametrize("value,label", BLANK_VALUES)
def test_status_reports_key_present_false_for_a_blank_key(
        value, label, monkeypatch, tmp_path):
    """The status tool is what a stuck caller is told to run first. If it said
    a key was present while the gate refused, the refusal would read like a bug
    and the caller would go looking in the wrong place."""
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("ARCAEON_KEY", value)

    st = _call("arcaeon_status")

    assert st["key_present"] is False, f"{label}: {st['key_present']!r}"
    assert st["key_env_var"] == "ARCAEON_KEY"


# --- MUST-MISS: a real key still works -------------------------------------

def test_must_miss_a_set_key_still_passes_through_to_the_witness(
        monkeypatch, tmp_path):
    """THE must-miss. Without this arm, a gate that refused every call would
    pass every test above. The HTTP hop is stubbed so no live pin is spent, and
    the stub asserts on exactly what the gate handed it."""
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("ARCAEON_KEY", "dummy-key-not-real")
    posted = _count_posts(monkeypatch)

    out = _call("witness_pin", HEAD)

    assert len(posted) == 1, posted
    assert posted[0]["key"] == "dummy-key-not-real", posted
    assert posted[0]["url"].endswith("/api/pin"), posted
    assert out["ok"] is True and out["status"] == 201, out


def test_must_miss_a_padded_key_is_stripped_and_still_works(monkeypatch, tmp_path):
    """Surrounding whitespace is a normalisation, not a rejection. A key pasted
    from a console with a trailing newline is a real key."""
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("ARCAEON_KEY", "  dummy-key-not-real\n")
    posted = _count_posts(monkeypatch)

    _call("witness_pin", HEAD)

    assert len(posted) == 1 and posted[0]["key"] == "dummy-key-not-real", posted


def test_must_miss_status_reports_key_present_true_for_a_real_key(
        monkeypatch, tmp_path):
    _isolate(monkeypatch, tmp_path)
    monkeypatch.setenv("ARCAEON_KEY", "dummy-key-not-real")
    assert _call("arcaeon_status")["key_present"] is True


# --- the second gate, at the layer that owns the credential ----------------

@pytest.mark.parametrize("value,label", BLANK_VALUES + [(None, "None")])
def test_the_transport_refuses_a_blank_key_even_called_directly(
        value, label, monkeypatch):
    """`witness` is an importable module. Through the MCP server this branch is
    unreachable because the handler refuses first, but a direct
    `witness.pin(ns, rows, chain, "")` from Python would otherwise put
    `Authorization: Bearer ` on the wire."""
    posted = _count_posts(monkeypatch)

    out = witness.pin("acme-ledger", 7, "a1b2c3d4", value)

    assert out["ok"] is False, out
    assert "ARCAEON_KEY" in out["error"], out
    assert posted == [], f"{label}: a blank key reached the witness: {posted}"


def test_the_transport_still_sends_a_real_key(monkeypatch):
    """Must-miss for the second gate, same reason as the first."""
    posted = _count_posts(monkeypatch)

    out = witness.renew("acme-ledger", 7, "a1b2c3d4", "dummy-key-not-real")

    assert out["ok"] is True, out
    assert len(posted) == 1 and posted[0]["key"] == "dummy-key-not-real", posted
    assert posted[0]["url"].endswith("/api/renew"), posted
