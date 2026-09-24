"""Tests for the Ed25519 grade receipt (C-agent-04, 2026-08-30).

The three that were named red-before-green in the board item are
`test_sign_then_verify_round_trips`, `test_tampered_payload_fails_verification`
and `test_wrong_key_fails_verification` — signature, tamper, substitution. The
rest exist because a receipt makes a claim about a FORMAT as much as about a
signature, and an unasserted format claim is the thing this project keeps
finding in other people's servers.
"""
import base64
import copy
import hashlib
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from arcaeon.prove.vet import __version__, receipts
from arcaeon.prove.vet.grade import grade_source

pytestmark = pytest.mark.skipif(
    not receipts.RECEIPTS_AVAILABLE,
    reason="no Ed25519 backend installed (pip install 'arcaeon[sign]')")

SRC = ("from mcp.server.fastmcp import FastMCP\n"
       "mcp = FastMCP('x')\n\n"
       "@mcp.tool()\n"
       "def show(path):\n"
       "    return open(path).read()\n")


@pytest.fixture
def graded():
    return json.loads(grade_source(SRC, "sample_server.py").to_json())


@pytest.fixture
def seed():
    # Fixed seed, so a failure is reproducible rather than "it went red once".
    return bytes(range(32))


# --- the three named cases ---------------------------------------------------

def test_sign_then_verify_round_trips(graded, seed):
    receipt = receipts.sign_grade(graded, seed)
    assert receipts.verify_receipt(receipt) is True
    # ...and bound to the grade it was made from, which is the stronger claim.
    assert receipts.verify_receipt(receipt, graded) is True
    detail = receipts.verify_receipt_detail(receipt, graded)
    assert detail["reasons"] == [], detail
    assert detail["bound_to_grade"] is True


def test_tampered_payload_fails_verification(graded, seed):
    """Flip the verdict in the signed payload. Everything else — signature,
    key, format — is untouched, so only the signature check can catch it."""
    receipt = receipts.sign_grade(graded, seed)
    assert receipts.verify_receipt(receipt) is True

    tampered = copy.deepcopy(receipt)
    tampered["payload"]["verdict"] = "no findings in checked classes"
    assert receipts.verify_receipt(tampered) is False
    assert any("signature does not verify" in r
               for r in receipts.verify_receipt_detail(tampered)["reasons"])


def test_wrong_key_fails_verification(graded, seed):
    """Same payload, same signature, a different public key in the envelope.
    Two things must catch this: the signature, and the iss/pubkey binding."""
    receipt = receipts.sign_grade(graded, seed)
    other = receipts.public_key_from_seed(bytes(range(1, 33)))

    swapped = copy.deepcopy(receipt)
    swapped["pubkey_b64"] = base64.b64encode(other).decode("ascii")
    assert receipts.verify_receipt(swapped) is False

    reasons = receipts.verify_receipt_detail(swapped)["reasons"]
    assert any("does not match the key in pubkey_b64" in r for r in reasons), reasons
    assert any("signature does not verify" in r for r in reasons), reasons


# --- substitution attacks the round-trip alone would not catch ---------------

def test_a_receipt_for_a_different_grade_is_not_bound_to_this_one(seed):
    """The whole point of `responseHash`: a perfectly valid signature over
    SOME grade must not read as a valid receipt for the grade in your hand."""
    a = json.loads(grade_source(SRC, "a.py").to_json())
    b = json.loads(grade_source(SRC.replace("open(path)", "print(path)"),
                                "b.py").to_json())
    receipt = receipts.sign_grade(a, seed)

    assert receipts.verify_receipt(receipt) is True          # signature is fine
    assert receipts.verify_receipt(receipt, b) is False      # binding is not
    detail = receipts.verify_receipt_detail(receipt, b)
    assert detail["bound_to_grade"] is False
    assert any("responseHash does not match" in r for r in detail["reasons"])


def test_verification_without_a_grade_is_bounded_and_says_so(graded, seed):
    """`bound_to_grade` is None, not True, when no grade was supplied. A
    verifier that reported True here would be answering a question it was never
    asked — the same false-green shape `verify_audit_ledger` refuses."""
    detail = receipts.verify_receipt_detail(receipts.sign_grade(graded, seed))
    assert detail["verified"] is True
    assert detail["bound_to_grade"] is None


def test_expected_key_and_audience_are_enforced_when_given(graded, seed):
    pub = base64.b64encode(receipts.public_key_from_seed(seed)).decode("ascii")
    receipt = receipts.sign_grade(graded, seed, audience="did:key:zSomeGateway")

    assert receipts.verify_receipt(receipt, expected_pubkey_b64=pub) is True
    assert receipts.verify_receipt(receipt, expected_pubkey_b64="AAAA") is False
    assert receipts.verify_receipt(
        receipt, expected_audience="did:key:zSomeGateway") is True
    assert receipts.verify_receipt(receipt, expected_audience="someone-else") is False


def test_an_alg_other_than_eddsa_is_refused_not_silently_verified(graded, seed):
    """`alg` rides outside the signature. It must not be able to change the
    verification path — and a receipt claiming RS256 must not verify as Ed25519
    just because the bytes happen to check out."""
    receipt = receipts.sign_grade(graded, seed)
    receipt["alg"] = "RS256"
    assert receipts.verify_receipt(receipt) is False


@pytest.mark.parametrize("field", ["payload", "signature_b64", "pubkey_b64"])
def test_a_missing_field_is_a_red_not_an_exception(graded, seed, field):
    receipt = receipts.sign_grade(graded, seed)
    receipt.pop(field)
    assert receipts.verify_receipt(receipt) is False


def test_garbage_input_is_a_red_not_an_exception():
    for junk in (None, "receipt", 7, [], {}, {"payload": "x"}):
        assert receipts.verify_receipt(junk) is False


# --- the format claims, asserted rather than asserted-in-a-docstring ---------

def test_the_envelope_declares_what_the_board_item_asked_for(graded, seed):
    receipt = receipts.sign_grade(graded, seed)
    assert set(receipt) >= {"payload", "signature_b64", "pubkey_b64", "format"}
    assert receipt["format"] == "checkpoint-kya-v1-compatible"
    assert receipt["alg"] == "EdDSA"
    assert receipt["canonicalization"] == "RFC8785"


def test_the_payload_carries_the_five_grade_fields(graded, seed):
    p = receipts.sign_grade(graded, seed)["payload"]
    assert p["source_sha256"] == hashlib.sha256(SRC.encode()).hexdigest()
    assert p["verdict"] == graded["verdict"]
    assert p["checks_run"] == graded["checks_run"]
    assert p["tool_version"] == __version__
    assert isinstance(p["ts"], int)          # KYA: Unix epoch seconds


def test_the_payload_uses_kya_claim_names(graded, seed):
    """Fetched from decentralized-identity/kya-os-mcp SPEC.md on 2026-08-30.
    If we ever rename one of these to something more comfortable, the
    'compatible' in the format string stops being true and this fails."""
    p = receipts.sign_grade(graded, seed)["payload"]
    for claim in ("aud", "iss", "sub", "nonce", "ts", "requestHash",
                  "responseHash", "outcome", "prf"):
        assert claim in p, claim
    assert p["outcome"] == "allowed"
    assert p["prf"] == "mcp-vet-grade-v1"
    assert p["iss"] == p["sub"]
    assert p["iss"].startswith("did:key:z")
    for h in (p["requestHash"], p["responseHash"]):
        assert h.startswith("sha256:")
        assert len(h) == len("sha256:") + 64
        assert h[7:] == h[7:].lower()
        int(h[7:], 16)   # hex, or this raises


def test_the_receipt_confesses_its_divergences_in_band(graded, seed):
    """Same rule the grade lives under. A conformance gap documented only in a
    README is a gap nobody reads, and this one is emitted with every receipt."""
    receipt = receipts.sign_grade(graded, seed)
    assert receipt["divergences"] == receipts.DIVERGENCES
    joined = " ".join(receipt["divergences"])
    for expected in ("detached compact JWS", "sessionId", "DID document"):
        assert expected in joined, expected


def test_the_format_string_does_not_claim_conformance():
    """One word of drift here turns an honest 'shaped like' into a false
    'conforms to'. The envelope is NOT a KYA detached JWS and the string must
    keep saying so."""
    assert receipts.RECEIPT_FORMAT.endswith("-compatible")
    assert receipts.RECEIPT_FORMAT != "checkpoint-kya-v1"


# --- did:key, canonicalization ----------------------------------------------

def test_did_key_matches_the_multicodec_encoding(seed):
    """The multicodec prefix for an Ed25519 public key is 0xed01, and z6Mk is
    what base58btc makes of it for every 32-byte key. A did:key that does not
    start z6Mk is not an Ed25519 did:key."""
    did = receipts.did_key(receipts.public_key_from_seed(seed))
    assert did.startswith("did:key:z6Mk"), did


def test_canonical_json_is_sorted_and_tight():
    assert receipts._canonical({"b": 1, "a": [2, 3]}) == b'{"a":[2,3],"b":1}'


def test_floats_are_refused_rather_than_approximated():
    """RFC 8785 pins number serialization to ECMAScript's algorithm, which
    `json.dumps` does not implement. Emitting a hash over almost-canonical
    bytes would make the RFC8785 label false in exactly the cases nobody
    tests, so it raises."""
    with pytest.raises(ValueError, match="RFC 8785"):
        receipts.canonical_sha256({"score": 0.1})


def test_hashing_is_key_order_independent(graded, seed):
    """Canonicalization earns its keep here: a grade round-tripped through a
    different key order must hash the same, or every receipt would be bound to
    one particular JSON serialization rather than to the artifact."""
    shuffled = dict(reversed(list(graded.items())))
    assert receipts.canonical_sha256(shuffled) == receipts.canonical_sha256(graded)
    receipt = receipts.sign_grade(graded, seed)
    assert receipts.verify_receipt(receipt, shuffled) is True


# --- refusals ----------------------------------------------------------------

def test_a_non_grade_is_refused(seed):
    with pytest.raises(ValueError, match="missing"):
        receipts.sign_grade({"hello": "world"}, seed)


def test_a_grade_dataclass_works_as_well_as_a_dict(seed):
    grade = grade_source(SRC, "sample_server.py")
    receipt = receipts.sign_grade(grade, seed)
    assert receipts.verify_receipt(receipt, grade) is True


def test_a_bad_env_key_is_a_loud_error_not_a_silent_ephemeral_key(monkeypatch):
    """Falling back to a fresh key when the operator's key fails to load would
    produce receipts that verify and attribute to nobody — a green that means
    nothing, which is the failure this project is a complaint about."""
    monkeypatch.setenv(receipts.RECEIPT_KEY_ENV, "not base64 at all!!")
    with pytest.raises(ValueError, match="valid base64"):
        receipts.load_seed()
    monkeypatch.setenv(receipts.RECEIPT_KEY_ENV,
                       base64.b64encode(b"too short").decode())
    with pytest.raises(ValueError, match="32 bytes"):
        receipts.load_seed()


def test_load_seed_falls_back_to_the_persistent_file_when_env_is_unset(
        monkeypatch, tmp_path, seed):
    """Batch-100 item 121, 2026-09-05: before this, an unset env var meant
    EVERY receipt was ephemeral -- verifies fine, attributes to nobody. The
    persistent file is what makes attribution the default rather than an
    opt-in nobody remembers to set."""
    monkeypatch.delenv(receipts.RECEIPT_KEY_ENV, raising=False)
    key_file = tmp_path / "planted.key"
    key_file.write_text(base64.b64encode(seed).decode("ascii") + "\n", encoding="ascii")
    monkeypatch.setattr(receipts, "RECEIPT_KEY_FILE", key_file)
    assert receipts.load_seed() == seed


def test_load_seed_env_var_wins_over_the_file(monkeypatch, tmp_path, seed):
    """The launching operator's env var must not be silently overridden by a
    file sitting on disk -- same precedence the module docstring already
    promises for the env var over ephemeral, extended to the new source."""
    env_seed = bytes(range(1, 33))
    monkeypatch.setenv(receipts.RECEIPT_KEY_ENV, base64.b64encode(env_seed).decode("ascii"))
    key_file = tmp_path / "planted.key"
    key_file.write_text(base64.b64encode(seed).decode("ascii") + "\n", encoding="ascii")
    monkeypatch.setattr(receipts, "RECEIPT_KEY_FILE", key_file)
    assert receipts.load_seed() == env_seed
    assert receipts.load_seed() != seed


def test_load_seed_is_ephemeral_when_neither_env_nor_file_exist(monkeypatch, tmp_path):
    """The ordinary state on a machine that has never provisioned the file --
    must fall through to ephemeral exactly as it always did, not raise."""
    monkeypatch.delenv(receipts.RECEIPT_KEY_ENV, raising=False)
    monkeypatch.setattr(receipts, "RECEIPT_KEY_FILE", tmp_path / "does_not_exist.key")
    a = receipts.load_seed()
    b = receipts.load_seed()
    assert len(a) == 32 and len(b) == 32 and a != b  # fresh every call, never persisted


def test_load_seed_refuses_a_malformed_persistent_file_rather_than_downgrading(
        monkeypatch, tmp_path):
    """A provisioned-but-corrupt file must be a loud error, not a silent slide
    back to ephemeral -- the same discipline
    `test_a_bad_env_key_is_a_loud_error_not_a_silent_ephemeral_key` already
    holds the env var to."""
    monkeypatch.delenv(receipts.RECEIPT_KEY_ENV, raising=False)
    key_file = tmp_path / "corrupt.key"
    key_file.write_text("not base64 at all!!", encoding="ascii")
    monkeypatch.setattr(receipts, "RECEIPT_KEY_FILE", key_file)
    with pytest.raises(ValueError, match="valid base64"):
        receipts.load_seed()


def test_env_key_is_read_at_call_time(monkeypatch, seed):
    monkeypatch.setenv(receipts.RECEIPT_KEY_ENV,
                       base64.b64encode(seed).decode("ascii"))
    assert receipts.load_seed() == seed


def test_status_line_says_on_or_off_and_names_the_extra():
    line = receipts.receipts_status_line()
    assert line.startswith("grade receipts: ")
    if receipts.RECEIPTS_AVAILABLE:
        assert "ON" in line and receipts.BACKEND in line
    else:
        assert "arcaeon[sign]" in line
