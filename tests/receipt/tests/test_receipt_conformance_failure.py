"""FAILURE conformance for the receipt verifiers: does the verifier FAIL when
handed a bad receipt?

Why this file is phrased as failures and not as happy paths: the Sigstore peer
study (private monorepo projects/online_business/PEER_STUDY_SIGSTORE_2026-09.md, s.6)
found every high-impact public Sigstore failure was a VERIFIER saying
"verified" when it should have said no, and one such bug came back through a
refactor. A suite of green paths cannot tell a working checker from one that
returns ok unconditionally. So every case below hands the verifier something
bad and asserts it is NOT accepted, and the BREAK-ARM tests at the bottom swap
in a verifier that always says ok and assert this suite would catch it.

Entry points under test:
  arcaeon_receipt.core.verify_receipt(receipt, ledger_path=, ots=)  -> {"ok": ...}
  arcaeon_receipt.verify_batch.verify_one(path, ledger_path=, ots=) -> ok / FAIL / undetermined
  arcaeon_receipt.verify_batch.verify_batch(targets, ...)           -> counts, cap refusal

"Accepted" means core ok is True, or a batch verdict of OK. A FAIL or an
UNDETERMINED is a rejection; the three-valued contract only requires that a
bad input never earns the green.

KNOWN FINDINGS are xfail(strict=True): the verifier accepts the bad input
today. They are kept, not deleted, and strict so that the day the behaviour
changes the xfail turns into an XPASS failure and forces this file to be
updated. Verifier code is NOT modified here.

As of 2026-09-22 (receipt-fix-round2) the three xfails that remain each need a
receipt FORMAT change, written up in FORMAT_CHANGE_PROPOSAL.md; for each, the
part that did not need one (reporting the field as CLAIMED or COULD NOT LOOK
rather than beside a PASS) is fixed and asserted by a passing test next to it.

Run:  py -m pytest tests/test_conformance_failure.py -v      (from the repo root)
"""
from __future__ import annotations

import copy
import json
import math
from pathlib import Path

import pytest

from arcaeon.record.receipt import core, verify_batch
from arcaeon.record.receipt.verify_batch import FAIL, OK, UNDETERMINED


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _no_hosted_witness(monkeypatch):
    # Never POST anywhere from a test: the local-file witness path only.
    monkeypatch.delenv("ARCAEON_WITNESS_URL", raising=False)
    monkeypatch.delenv("ARCAEON_WITNESS_KEY", raising=False)


def _issue(tmp: Path, *, name="a", witness=False, n_before=0, n_after=0):
    """An honest receipt, issued by the real build_receipt, plus its ledger."""
    led = tmp / "shared.ledger.jsonl"
    from arcaeon.record.ledger import Ledger
    for i in range(n_before):
        Ledger(led).append({"evt": "filler", "i": i})
    rc = core.build_receipt(
        "conformance", {"trainee": "t. " + name, "scenario": "s1"},
        [{"name": "c1", "score": 88, "verdict": "PASS"},
         {"name": "c2", "score": 71, "verdict": "PASS"}],
        {"proves": ["the grader returned these scores"],
         "does_not_prove": ["the scores are correct"]},
        ledger_path=led, namespace="conf", witness=witness, anchor=False,
        issued_at="2026-09-22T12:00:00Z")
    for i in range(n_after):
        Ledger(led).append({"evt": "filler-after", "i": i})
    return rc, led


def _honest_ok(tmp: Path):
    """Control: the honest receipt must verify, or every rejection below is
    meaningless (a verifier that rejects everything also passes a failure suite)."""
    rc, led = _issue(tmp)
    assert core.verify_receipt(rc)["ok"] is True
    assert core.verify_receipt(rc, ledger_path=led)["ok"] is True
    return rc, led


def _rewrite_lines(path: Path, fn):
    lines = [l for l in path.read_text(encoding="utf-8").split("\n") if l.strip()]
    lines = fn(lines)
    path.write_text("".join(l + "\n" for l in lines), encoding="utf-8")


# --------------------------------------------------------------------------
# core.verify_receipt: bad-input cases. Each returns (receipt, kwargs).
# --------------------------------------------------------------------------

def c_tamper_subject(tmp):
    rc, _ = _honest_ok(tmp); rc["subject"]["trainee"] = "someone else"; return rc, {}

def c_tamper_check_score(tmp):
    rc, _ = _honest_ok(tmp); rc["checks"][1]["score"] = 99; return rc, {}

def c_tamper_score_type(tmp):
    # 88 -> 88.0 is the same number to a human and a different canonical form.
    rc, _ = _honest_ok(tmp); rc["checks"][0]["score"] = 88.0; return rc, {}

def c_tamper_issued_at(tmp):
    rc, _ = _honest_ok(tmp); rc["issued_at"] = "2026-01-01T00:00:00Z"; return rc, {}

def c_tamper_version(tmp):
    rc, _ = _honest_ok(tmp); rc["receipt_version"] = "arcaeon-receipt/9.9"; return rc, {}

def c_tamper_scope_limits(tmp):
    rc, _ = _honest_ok(tmp); rc["scope"]["does_not_prove"] = []; return rc, {}

def c_tamper_extra(tmp):
    rc, _ = _honest_ok(tmp); rc["extra"] = {"attestation": {"statement": "forged"}}; return rc, {}

def c_delete_body_field(tmp):
    rc, _ = _honest_ok(tmp); del rc["checks"]; return rc, {}

def c_reorder_checks(tmp):
    rc, _ = _honest_ok(tmp); rc["checks"].reverse(); return rc, {}

def c_duplicate_check(tmp):
    rc, _ = _honest_ok(tmp); rc["checks"].append(copy.deepcopy(rc["checks"][0])); return rc, {}

def c_missing_digest(tmp):
    rc, _ = _honest_ok(tmp); del rc["body_digest"]; return rc, {}

def c_empty_digest(tmp):
    rc, _ = _honest_ok(tmp); rc["body_digest"] = ""; return rc, {}

def c_null_digest(tmp):
    rc, _ = _honest_ok(tmp); rc["body_digest"] = None; return rc, {}

def c_wrong_recipe_prefix(tmp):
    rc, _ = _honest_ok(tmp)
    rc["body_digest"] = rc["body_digest"].replace("json-c14n:v1", "json-c14n:v2"); return rc, {}

def c_uppercase_digest(tmp):
    rc, _ = _honest_ok(tmp)
    pre, hexpart = rc["body_digest"].rsplit(":", 1)
    rc["body_digest"] = pre + ":" + hexpart.upper(); return rc, {}

def c_truncated_digest(tmp):
    rc, _ = _honest_ok(tmp); rc["body_digest"] = rc["body_digest"][:-1]; return rc, {}

def c_bare_hex_digest(tmp):
    rc, _ = _honest_ok(tmp); rc["body_digest"] = rc["body_digest"].rsplit(":", 1)[1]; return rc, {}

def c_nan_in_body(tmp):
    rc, _ = _honest_ok(tmp); rc["checks"][0]["score"] = math.nan; return rc, {}

def c_empty_object(tmp):
    return {}, {}

def c_none(tmp):
    return None, {}

def c_list(tmp):
    return [], {}

def c_string(tmp):
    return "not a receipt", {}

def c_int(tmp):
    return 42, {}

# ---- with the ledger in hand -------------------------------------------------

def c_forged_receipt_vs_ledger(tmp):
    """A receipt minted by hand, digest recomputed so the body verifies: only
    the ledger can say no, and it must."""
    rc, led = _honest_ok(tmp)
    rc["subject"]["trainee"] = "forged"
    rc["body_digest"] = core.digest_json(core._body_of(rc))
    return rc, {"ledger_path": led}

def c_ledger_row_tampered(tmp):
    rc, led = _issue(tmp, n_before=2, n_after=1)
    def edit(lines):
        o = json.loads(lines[0]); o["i"] = 999; lines[0] = json.dumps(o); return lines
    _rewrite_lines(led, edit); return rc, {"ledger_path": led}

def c_ledger_rows_reordered(tmp):
    rc, led = _issue(tmp, n_before=2, n_after=1)
    _rewrite_lines(led, lambda ls: [ls[1], ls[0]] + ls[2:]); return rc, {"ledger_path": led}

def c_ledger_row_duplicated(tmp):
    rc, led = _issue(tmp, n_before=2, n_after=1)
    _rewrite_lines(led, lambda ls: ls[:2] + [ls[1]] + ls[2:]); return rc, {"ledger_path": led}

def c_ledger_truncated_before_row(tmp):
    rc, led = _issue(tmp, n_before=2)
    _rewrite_lines(led, lambda ls: ls[:2]); return rc, {"ledger_path": led}

def c_ledger_torn_last_line(tmp):
    rc, led = _issue(tmp, n_before=1)
    raw = led.read_bytes().rstrip(b"\n")
    led.write_bytes(raw[:-7]); return rc, {"ledger_path": led}

def c_ledger_empty_file(tmp):
    rc, led = _issue(tmp); led.write_text("", encoding="utf-8"); return rc, {"ledger_path": led}

def c_ledger_missing_file(tmp):
    rc, led = _issue(tmp); return rc, {"ledger_path": tmp / "no-such.ledger.jsonl"}

def c_ledger_other_log(tmp):
    rc, _ = _issue(tmp)
    other = tmp / "other"; other.mkdir()
    _, led2 = _issue(other, name="b")
    return rc, {"ledger_path": led2}

def c_receipt_rows_edited(tmp):
    rc, led = _issue(tmp, n_before=1, n_after=1)
    rc["ledger"]["rows"] = rc["ledger"]["rows"] + 1; return rc, {"ledger_path": led}

def c_receipt_rows_non_int(tmp):
    rc, led = _issue(tmp); rc["ledger"]["rows"] = "2"; return rc, {"ledger_path": led}

def c_receipt_chain_edited(tmp):
    rc, led = _issue(tmp); rc["ledger"]["chain"] = "0" * 32; return rc, {"ledger_path": led}

def c_receipt_ledger_block_removed_with_ledger(tmp):
    rc, led = _issue(tmp); del rc["ledger"]; return rc, {"ledger_path": led}

def c_ledger_bounded_prechain(tmp):
    # An unchained "legacy" row in front: verify_file is bounded (ok=None), not True.
    rc, led = _issue(tmp)
    _rewrite_lines(led, lambda ls: [json.dumps({"evt": "legacy"})] + ls)
    return rc, {"ledger_path": led}


# ---- attachments outside the digest that contradict the receipt -------------

def c_witness_rows_edited(tmp):
    rc, led = _issue(tmp, witness=True); rc["witness"]["rows"] += 5
    return rc, {"ledger_path": led}

def c_witness_pin_self_broken(tmp):
    rc, led = _issue(tmp, witness=True); rc["witness"]["pin"]["as_of"] = "2020-01-01T00:00:00Z"
    return rc, {"ledger_path": led}

def c_attestation_sig_other_digest(tmp):
    rc, _ = _honest_ok(tmp)
    core.attach_attestation_signature(rc, "sig")
    rc["attestation_signature"]["body_digest"] = "sha256:json-c14n:v1:" + "1" * 64
    return rc, {}

def c_attestation_sig_not_object(tmp):
    rc, _ = _honest_ok(tmp); rc["attestation_signature"] = "sig"; return rc, {}


CORE_CASES = [
    c_witness_rows_edited, c_witness_pin_self_broken, c_attestation_sig_other_digest,
    c_attestation_sig_not_object,
    c_tamper_subject, c_tamper_check_score, c_tamper_score_type, c_tamper_issued_at,
    c_tamper_version, c_tamper_scope_limits, c_tamper_extra, c_delete_body_field,
    c_reorder_checks, c_duplicate_check, c_missing_digest, c_empty_digest,
    c_null_digest, c_wrong_recipe_prefix, c_uppercase_digest, c_truncated_digest,
    c_bare_hex_digest, c_nan_in_body, c_empty_object, c_none, c_list, c_string, c_int,
    c_forged_receipt_vs_ledger, c_ledger_row_tampered, c_ledger_rows_reordered,
    c_ledger_row_duplicated, c_ledger_truncated_before_row, c_ledger_torn_last_line,
    c_ledger_empty_file, c_ledger_missing_file, c_ledger_other_log,
    c_receipt_rows_edited, c_receipt_rows_non_int, c_receipt_chain_edited,
    c_receipt_ledger_block_removed_with_ledger, c_ledger_bounded_prechain,
]


def _core_rejects(fn, tmp, verifier=None) -> bool:
    verifier = verifier or core.verify_receipt
    rc, kw = fn(tmp)
    res = verifier(rc, **kw)
    return res.get("ok") is not True


@pytest.mark.parametrize("case", CORE_CASES, ids=lambda f: f.__name__[2:])
def test_core_rejects_bad_input(case, tmp_path):
    assert _core_rejects(case, tmp_path), f"verify_receipt said ok on bad input: {case.__name__}"


def test_core_never_raises_on_bad_input(tmp_path):
    for i, case in enumerate(CORE_CASES):
        d = tmp_path / str(i); d.mkdir()
        rc, kw = case(d)
        core.verify_receipt(rc, **kw)       # typed, never raises: a crash is not a verdict


# --------------------------------------------------------------------------
# KNOWN FINDINGS: the verifier accepts these today. xfail(strict) keeps them
# visible and forces an update the day the behaviour changes.
# --------------------------------------------------------------------------

@pytest.mark.xfail(strict=True, reason=(
    "FORMAT CHANGE NEEDED (FORMAT_CHANGE_PROPOSAL.md s.1): body_digest is a "
    "hash, not a signature, and format arcaeon-receipt/0.1 carries no issuer "
    "signature, so without ledger_path nothing can tell a re-minted receipt "
    "from an honest one. Only the ledger check (c_forged_receipt_vs_ledger) "
    "catches it. Since 2026-09-22 the verdict no longer implies otherwise: "
    "issuer is reported CLAIMED (test_reminted_receipt_issuer_is_reported_claimed)."))
def test_finding_reminted_receipt_without_ledger(tmp_path):
    rc, kw = c_forged_receipt_vs_ledger(tmp_path)
    assert core.verify_receipt(rc)["ok"] is not True


def test_reminted_receipt_issuer_is_reported_claimed(tmp_path):
    """What CAN be fixed without a format change: the result says, every time,
    that authorship is the issuer's claim and the ledger was not walked."""
    rc, kw = c_forged_receipt_vs_ledger(tmp_path)
    res = core.verify_receipt(rc)
    assert res["issuer"]["verdict"] == core.ATTACH_CLAIMED
    assert any(c.startswith("issuer") for c in res["claimed"])
    assert any(c.startswith("ledger") for c in res["claimed"])
    # and with the ledger in hand, the same forgery fails (unchanged)
    assert core.verify_receipt(rc, **kw)["ok"] is not True


def _relabelled(tmp_path):
    rc, led = _issue(tmp_path, witness=True)
    assert rc["witness"]["kind"] == "local-file"
    rc["witness"]["kind"] = "hosted"
    rc["witness"]["independence"] = "third-party-timestamped public commits"
    rc["witness"]["url"] = "https://witness.example"
    return rc, led


@pytest.mark.xfail(strict=True, reason=(
    "FORMAT CHANGE NEEDED (FORMAT_CHANGE_PROPOSAL.md s.2): kind/independence/url "
    "are the issuer's words and nothing in format 0.1 lets an offline verifier "
    "check them (the pin carries no signature by the witness's own key). "
    "Relabelling a local pin as hosted therefore still leaves ok=True. The "
    "other half of the finding is FIXED 2026-09-22: the block is reported and "
    "rendered as CLAIMED, never as checked (test_witness_relabel_is_reported_claimed)."))
def test_finding_witness_block_relabelled(tmp_path):
    rc, led = _relabelled(tmp_path)
    assert core.verify_receipt(rc, ledger_path=led)["ok"] is not True


def test_witness_relabel_is_reported_claimed(tmp_path):
    rc, led = _relabelled(tmp_path)
    res = core.verify_receipt(rc, ledger_path=led)
    w = res["witness"]
    assert w["verdict"] == core.ATTACH_CLAIMED, w
    assert w["claimed"]["kind"] == "hosted"
    assert "not checked" in w["note"] and "CLAIMED" in w["note"]
    assert "witness.kind / independence / url / status" in res["claimed"]
    ex = core.render_exhibit(rc)
    assert "witness (claimed, not verified): hosted" in ex
    # the old line, printed as if it were a fact, is gone
    assert "  witness: hosted" not in ex
    # batch: the row shows the witness as claimed, not as a checked field
    p = tmp_path / "a.receipt.json"
    core.save_receipt(rc, p)
    row = verify_batch.verify_one(p, ledger_path=led)
    assert row["witness"] == core.ATTACH_CLAIMED
    assert "witness=claimed" in verify_batch.render({"rows": [row], "verified": 1,
                                                     "failed": 0, "undetermined": 0})


# FIXED 2026-09-22 (receipt-fix-round2); formerly a strict xfail:
#   @pytest.mark.xfail(strict=True, reason=(
#       "FINDING (field outside the preimage): witness rows/chain can be edited "
#       "freely; verify_receipt compares ledger.rows/chain, never witness.rows/chain "
#       "or the embedded pin's self-digest."))
# The witness block must now agree with the ledger block and with its own pin,
# and a WitnessStore pin must still hash to its own `self`.
def test_finding_witness_pin_values_edited(tmp_path):
    rc, led = _issue(tmp_path, witness=True)
    rc["witness"]["rows"] = 9999
    rc["witness"]["chain"] = "f" * 32
    rc["witness"]["pin"]["rows"] = 9999
    res = core.verify_receipt(rc, ledger_path=led)
    assert res["ok"] is not True
    assert res["witness"]["verdict"] == core.ATTACH_INCONSISTENT
    # and without the ledger file: the block contradicts the receipt itself
    assert core.verify_receipt(rc)["ok"] is not True


@pytest.mark.parametrize("edit", [
    "pin_rows_only", "pin_as_of_only", "witness_chain_only", "pin_self_only",
])
def test_witness_pin_single_edits_are_caught(tmp_path, edit):
    rc, led = _issue(tmp_path, witness=True)
    assert core.verify_receipt(rc, ledger_path=led)["witness"]["pin_self_digest"] == "checked"
    w = rc["witness"]
    if edit == "pin_rows_only":
        w["pin"]["rows"] += 1
    elif edit == "pin_as_of_only":
        w["pin"]["as_of"] = "2020-01-01T00:00:00Z"      # only the self-digest sees this
    elif edit == "witness_chain_only":
        w["chain"] = "0" * 32
    else:
        w["pin"]["self"] = "0" * 32
    assert core.verify_receipt(rc, ledger_path=led)["ok"] is not True
    assert core.verify_receipt(rc)["ok"] is not True


# FIXED 2026-09-22 (fix-false-yes-2026-09-22); formerly a strict xfail:
#   @pytest.mark.xfail(strict=True, reason=(
#       "FINDING (fail-open anchor): with ots=True, an anchor block that was "
#       "stripped reads as status no_anchor and ok stays True. The caller asked for "
#       "the anchor to be checked and nothing was checked; that is UNDETERMINED, "
#       "not ok."))
def test_finding_anchor_stripped_with_ots_requested(tmp_path):
    rc, _ = _honest_ok(tmp_path)
    rc["anchor"] = {}
    assert core.verify_receipt(rc, ots=True)["ok"] is not True


# FIXED 2026-09-22 (fix-false-yes-2026-09-22); formerly a strict xfail:
#   @pytest.mark.xfail(strict=True, reason=(
#       "FINDING (fail-open anchor): a corrupt ots_b64 that makes the ots tool "
#       "error out gives anchor status 'error' (or 'unknown' on unrecognised "
#       "output), and ok stays True. Only the literal status 'failed' blocks."))
@pytest.mark.parametrize("mode", ["error", "unknown"])
def test_finding_anchor_error_counts_as_ok(tmp_path, monkeypatch, mode):
    rc, _ = _honest_ok(tmp_path)
    rc["anchor"] = {"kind": "opentimestamps", "status": "pending-calendar",
                    "ots_b64": "AAAA-not-a-proof"}
    monkeypatch.setattr(core, "ots_exe", lambda: Path("ots.exe"))
    if mode == "error":
        def boom(*a, **k): raise OSError("ots could not run")
        monkeypatch.setattr(core, "_run_ots", boom)
    else:
        class R: stdout, stderr, returncode = "something unrecognised", "", 0
        monkeypatch.setattr(core, "_run_ots", lambda *a, **k: R())
    assert core.verify_receipt(rc, ots=True)["ok"] is not True


# FIXED 2026-09-22 (receipt-fix-round2) for the case as written; formerly a
# strict xfail:
#   @pytest.mark.xfail(strict=True, reason=(
#       "FINDING (documented in attach_attestation_signature): the detached "
#       "attestation signature sits outside the body digest and is never checked, "
#       "so an edited signature value leaves ok=True."))
# A signature that says it was made over a different body digest does not
# belong to this receipt, and that is determined offline. The VALUE alone is
# not checkable in format 0.1: see test_finding_attestation_signature_value_only.
def test_finding_attestation_signature_edited(tmp_path):
    rc, _ = _honest_ok(tmp_path)
    core.attach_attestation_signature(rc, "real-signature")
    rc["attestation_signature"]["value"] = "forged"
    rc["attestation_signature"]["body_digest"] = "sha256:json-c14n:v1:" + "0" * 64
    res = core.verify_receipt(rc)
    assert res["ok"] is not True
    assert res["attestation_signature"]["verdict"] == core.ATTACH_MISMATCH


def _sig_value_only(tmp_path):
    rc, _ = _honest_ok(tmp_path)
    core.attach_attestation_signature(rc, "real-signature", algorithm="ed25519")
    rc["attestation_signature"]["value"] = "forged"
    return rc


@pytest.mark.xfail(strict=True, reason=(
    "FORMAT CHANGE NEEDED (FORMAT_CHANGE_PROPOSAL.md s.3): the receipt carries "
    "no public key, `algorithm` is free text, and the signed bytes are not "
    "fixed, so an edited signature VALUE cannot be checked by anyone holding "
    "only the receipt. The verdict for the value is COULD NOT LOOK, reported "
    "and rendered (test_attestation_signature_value_is_could_not_look)."))
def test_finding_attestation_signature_value_only(tmp_path):
    assert core.verify_receipt(_sig_value_only(tmp_path))["ok"] is not True


def test_attestation_signature_value_is_could_not_look(tmp_path):
    rc = _sig_value_only(tmp_path)
    res = core.verify_receipt(rc)
    a = res["attestation_signature"]
    assert a["verdict"] == core.ATTACH_COULD_NOT_LOOK
    assert "NOT checked" in a["note"] and "no public" in a["note"]
    assert any(c.startswith("attestation_signature.value") for c in res["claimed"])


# --------------------------------------------------------------------------
# verify_batch.verify_one: bad FILES. Each returns (path, kwargs).
# --------------------------------------------------------------------------

def _export(tmp: Path, **kw):
    """An honest export directory: receipt file beside its ledger."""
    rc, led = _issue(tmp, **kw)
    p = tmp / "a.receipt.json"
    core.save_receipt(rc, p)
    assert verify_batch.verify_one(p)["verdict"] == OK
    return rc, led, p


def b_missing_file(tmp):
    return tmp / "nope.receipt.json", {}

def b_empty_file(tmp):
    p = tmp / "e.receipt.json"; p.write_text("", encoding="utf-8"); return p, {}

def b_whitespace_file(tmp):
    p = tmp / "w.receipt.json"; p.write_text("  \n\t\n", encoding="utf-8"); return p, {}

def b_truncated_json(tmp):
    _, _, p = _export(tmp)
    t = p.read_text(encoding="utf-8"); p.write_text(t[: len(t) // 2], encoding="utf-8"); return p, {}

def b_non_object(tmp):
    p = tmp / "l.receipt.json"; p.write_text("[1, 2, 3]", encoding="utf-8"); return p, {}

def b_json_null(tmp):
    p = tmp / "n.receipt.json"; p.write_text("null", encoding="utf-8"); return p, {}

def b_not_utf8(tmp):
    p = tmp / "b.receipt.json"; p.write_bytes(b"\xff\xfe{\x00}"); return p, {}

def b_tampered_body(tmp):
    rc, _, p = _export(tmp); rc["checks"][0]["score"] = 100; core.save_receipt(rc, p); return p, {}

def b_missing_digest(tmp):
    rc, _, p = _export(tmp); del rc["body_digest"]; core.save_receipt(rc, p); return p, {}

def b_dup_key_last_tampered(tmp):
    rc, _, p = _export(tmp)
    t = p.read_text(encoding="utf-8").rstrip().rstrip("}")
    p.write_text(t + ', "kind": "tampered"}\n', encoding="utf-8"); return p, {}

def b_nan_token(tmp):
    rc, _, p = _export(tmp)
    t = p.read_text(encoding="utf-8").replace('"score": 88', '"score": NaN', 1)
    p.write_text(t, encoding="utf-8"); return p, {}

def b_ledger_absent(tmp):
    rc, led, p = _export(tmp); led.unlink(); return p, {}

def b_ledger_tampered(tmp):
    rc, led, p = _export(tmp, n_before=1)
    def edit(lines):
        o = json.loads(lines[0]); o["i"] = 7; lines[0] = json.dumps(o); return lines
    _rewrite_lines(led, edit); return p, {}

def b_ledger_truncated(tmp):
    rc, led, p = _export(tmp, n_before=1)
    _rewrite_lines(led, lambda ls: ls[:1]); return p, {}

def b_explicit_ledger_missing(tmp):
    rc, led, p = _export(tmp); return p, {"ledger_path": tmp / "missing.jsonl"}

def b_ledger_path_traversal(tmp):
    # ledger.path pointing elsewhere: only the basename is used; an honest ledger
    # of the same name elsewhere must not be reached.
    rc, led, p = _export(tmp)
    sub = tmp / "sub"; sub.mkdir()
    p2 = sub / "a.receipt.json"
    rc["ledger"]["path"] = "../" + led.name
    core.save_receipt(rc, p2)
    return p2, {}


BATCH_CASES = [
    b_missing_file, b_empty_file, b_whitespace_file, b_truncated_json, b_non_object,
    b_json_null, b_tampered_body, b_missing_digest, b_dup_key_last_tampered,
    b_nan_token, b_ledger_absent, b_ledger_tampered, b_ledger_truncated,
    b_explicit_ledger_missing, b_ledger_path_traversal,
]

#: The verdict each case must get. Never OK; the split between FAIL and
#: UNDETERMINED is part of the contract (a determined negative is a FAIL).
BATCH_EXPECT = {
    "b_missing_file": UNDETERMINED, "b_empty_file": UNDETERMINED,
    "b_whitespace_file": UNDETERMINED, "b_truncated_json": UNDETERMINED,
    "b_non_object": UNDETERMINED, "b_json_null": UNDETERMINED,
    "b_tampered_body": FAIL, "b_missing_digest": FAIL,
    "b_dup_key_last_tampered": FAIL, "b_nan_token": FAIL,
    "b_ledger_absent": UNDETERMINED, "b_ledger_tampered": FAIL,
    "b_ledger_truncated": FAIL, "b_explicit_ledger_missing": UNDETERMINED,
    "b_ledger_path_traversal": UNDETERMINED,
}


def _batch_verdict(fn, tmp, verifier=None):
    verifier = verifier or verify_batch.verify_one
    p, kw = fn(tmp)
    return verifier(p, **kw)["verdict"]


@pytest.mark.parametrize("case", BATCH_CASES, ids=lambda f: f.__name__[2:])
def test_batch_rejects_bad_file(case, tmp_path):
    got = _batch_verdict(case, tmp_path)
    assert got != OK, f"verify_one said ok on bad input: {case.__name__}"
    assert got == BATCH_EXPECT[case.__name__], (case.__name__, got)


_CRASH = ("FINDING (crash, not a verdict): verify_one's docstring says 'Typed, "
          "never raises', but a non-UTF-8 receipt file raises UnicodeDecodeError out "
          "of path.read_text (it is a ValueError, and only OSError is caught). In "
          "verify_batch there is no per-row guard, so ONE such file kills the whole "
          "pass and the other nineteen get no verdict. Not an accept, but a hostile "
          "file silencing the verifier is the failure class the ledger fixed in 0.5.3.")


# FIXED 2026-09-22 (fix-false-yes-2026-09-22); formerly a strict xfail:
#   @pytest.mark.xfail(strict=True, raises=UnicodeDecodeError, reason=_CRASH)
def test_finding_non_utf8_file_crashes_verify_one(tmp_path):
    assert _batch_verdict(b_not_utf8, tmp_path) == UNDETERMINED


# FIXED 2026-09-22 (fix-false-yes-2026-09-22); formerly a strict xfail:
#   @pytest.mark.xfail(strict=True, raises=UnicodeDecodeError, reason=_CRASH)
def test_finding_non_utf8_file_kills_the_batch(tmp_path):
    _, _, p = _export(tmp_path)
    b_not_utf8(tmp_path)
    res = verify_batch.verify_batch([tmp_path])
    assert res["verified"] == 1 and res["undetermined"] == 1


def test_batch_counts_one_bad_among_good(tmp_path):
    good = []
    for n in "abc":
        d = tmp_path / n; d.mkdir()
        _, _, p = _export(d)
        good.append(p)
    rc = json.loads(good[1].read_text(encoding="utf-8"))
    rc["subject"]["trainee"] = "swapped"
    good[1].write_text(json.dumps(rc), encoding="utf-8")
    res = verify_batch.verify_batch(good)
    assert (res["verified"], res["failed"], res["undetermined"]) == (2, 1, 0)
    assert verify_batch.exit_code(res) == 2


def test_batch_over_cap_verifies_nothing(tmp_path):
    for i in range(verify_batch.CAP + 1):
        (tmp_path / f"{i:02}.receipt.json").write_text("{}", encoding="utf-8")
    with pytest.raises(verify_batch.CapExceeded):
        verify_batch.verify_batch([tmp_path])


def test_batch_empty_target_is_not_a_pass(tmp_path):
    with pytest.raises(verify_batch.NoReceiptsFound):
        verify_batch.verify_batch([tmp_path])


# FIXED 2026-09-22 (fix-false-yes-2026-09-22); formerly a strict xfail:
#   @pytest.mark.xfail(strict=True, reason=(
#       "FINDING (verdict upgrade by deletion): a receipt whose ledger is missing is "
#       "UNDETERMINED (b_ledger_absent). Delete the receipt's own `ledger` block -- "
#       "which is outside the body digest -- and resolve_ledger sees no claim, so the "
#       "same receipt is upgraded to OK. Removing evidence must never raise a verdict."))
@pytest.mark.parametrize("how", ["delete_block", "null_chain"])
def test_finding_strip_ledger_claim_upgrades_to_ok(tmp_path, how):
    rc, led, p = _export(tmp_path)
    led.unlink()
    assert verify_batch.verify_one(p)["verdict"] == UNDETERMINED
    if how == "delete_block":
        del rc["ledger"]
    else:
        rc["ledger"]["chain"] = None
    core.save_receipt(rc, p)
    assert verify_batch.verify_one(p)["verdict"] != OK


# FIXED 2026-09-22 (fix-false-yes-2026-09-22); formerly a strict xfail:
#   @pytest.mark.xfail(strict=True, reason=(
#       "FINDING (fail-open anchor, batch): with ots=True an anchor the tool could "
#       "not check ('error') is reported OK, not UNDETERMINED."))
def test_finding_batch_anchor_error_is_ok(tmp_path, monkeypatch):
    rc, _, p = _export(tmp_path)
    rc["anchor"] = {"kind": "opentimestamps", "status": "pending-calendar", "ots_b64": "AAAA"}
    core.save_receipt(rc, p)
    monkeypatch.setattr(core, "ots_exe", lambda: Path("ots.exe"))
    def boom(*a, **k): raise OSError("ots could not run")
    monkeypatch.setattr(core, "_run_ots", boom)
    assert verify_batch.verify_one(p, ots=True)["verdict"] != OK


# FIXED 2026-09-22 (fix-false-yes-2026-09-22); formerly a strict xfail:
#   @pytest.mark.xfail(strict=True, reason=(
#       "FINDING (duplicate JSON keys): json.loads keeps the LAST occurrence, so a "
#       "file whose FIRST `kind` is tampered and whose last is honest verifies OK. "
#       "A human or a first-wins parser reads the tampered value under a green. The "
#       "browser verifier makes the same last-wins choice, so they agree with each "
#       "other and not with the reader."))
def test_finding_dup_key_first_tampered_is_ok(tmp_path):
    rc, _, p = _export(tmp_path)
    t = p.read_text(encoding="utf-8").lstrip().lstrip("{")
    p.write_text('{"kind": "tampered", ' + t, encoding="utf-8")
    assert verify_batch.verify_one(p)["verdict"] != OK


# --------------------------------------------------------------------------
# BREAK-ARMS: swap in a verifier that always says ok. The suite must go red on
# every case, or it is not testing the verifier at all.
# --------------------------------------------------------------------------

def _liar_core(receipt, **kw):
    return {"ok": True, "body_digest_ok": True, "ledger": {"status": "consistent"},
            "anchor": {"status": "not_checked"}, "notes": []}


def test_break_arm_core_liar_is_caught(tmp_path):
    caught = []
    for i, case in enumerate(CORE_CASES):
        d = tmp_path / str(i); d.mkdir()
        if _core_rejects(case, d, verifier=_liar_core):
            caught.append(case.__name__)
    # A liar that says ok to everything must be rejected by NONE of the cases,
    # i.e. every parametrized test above would fail against it.
    assert caught == [], f"cases that did not notice the liar: {caught}"


def test_break_arm_core_liar_via_monkeypatch(tmp_path, monkeypatch):
    """Same arm, through the module attribute the batch path imports, so the
    batch suite is also shown to depend on the real core verdict."""
    monkeypatch.setattr(verify_batch, "verify_receipt", _liar_core)
    accepted = 0
    for i, case in enumerate([b_tampered_body, b_missing_digest, b_ledger_tampered,
                              b_ledger_truncated, b_dup_key_last_tampered]):
        d = tmp_path / str(i); d.mkdir()
        if _batch_verdict(case, d) == OK:
            accepted += 1
    assert accepted == 5, "the batch FAIL cases must all flip to OK against a lying core"


def test_break_arm_batch_liar_is_caught(tmp_path):
    def liar(path, **kw):
        return {"id": Path(path).name, "verdict": OK, "ledger": "consistent",
                "anchor": None, "reason": ""}
    for i, case in enumerate(BATCH_CASES):
        d = tmp_path / str(i); d.mkdir()
        assert _batch_verdict(case, d, verifier=liar) == OK   # every case would go red
