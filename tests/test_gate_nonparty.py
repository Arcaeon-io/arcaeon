"""The non-party check rule (D061 / TE-35): over a cap, act / pay / irreversible
need one signed, verified check by a key that is neither the envelope's signer
nor the audience, on the same sha256, saying VERIFIED. Throwaway seeds in
tmp_path only; nothing reaches the network."""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
from pathlib import Path

import pytest

from arcaeon import cli
from arcaeon import verdict as V
from arcaeon.prove import envelope as E
from arcaeon.prove import gate as G

pytest.importorskip("cryptography", reason="signing needs the [sign] extra")

AUD, DEAL = "instructor-1", "d-7f3a"
BIND = {"label": "week 3 grades", "audience": AUD, "deal": DEAL, "purpose": "grading",
        "not_after": "7d"}
BODY = b"name,grade\nunit-a,pass\n"
SHA = hashlib.sha256(BODY).hexdigest()


@pytest.fixture(autouse=True)
def _cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)


def _key(tmp_path: Path, name: str) -> Path:
    k = tmp_path / f"{name}.key"
    k.write_text(base64.b64encode(secrets.token_bytes(32)).decode("ascii"), encoding="ascii")
    return k


def _handed(tmp_path: Path):
    f = tmp_path / "in" / "grades.csv"
    f.parent.mkdir(exist_ok=True)
    f.write_bytes(BODY)
    key = _key(tmp_path, "sender")
    env = E.seal(f, key_file=key, **BIND)
    return f, env["dsseEnvelope"]["signatures"][0]["keyid"], key


def _row(sha: str = SHA, word: str = V.VERIFIED) -> dict:
    """A check.verdict.relayed row in the TE-31 shape (arcaeon.connector)."""
    return {"kind": G.CHECK_KIND, "relayed": True, "checked_by_us": False,
            "vendor": {"name": "mockscan", "adapter_version": "1"}, "vendor_id": "scan-1",
            "vendor_word": "pass", "relayed_verdict": word, "mapping": {"rule": "table"},
            "subject": {"name": "grades.csv", "sha256": sha},
            "attestation": {"status": "CLAIMED", "checked_by_us": False,
                            "claimed": {"alg": "ed25519"}},
            "vendor_payload_digest": "sha256:raw-bytes:v1:" + "0" * 64,
            "vendor_payload_bytes": 10, "received_at": "2026-10-04T00:00:00Z"}


def _check(tmp_path: Path, name: str, key: Path | None, row: dict | None = None,
           audience: str = AUD) -> tuple[Path, str | None]:
    """A check file, sealed (signed by `key`) for the receiver, or unsigned with key=None."""
    c = tmp_path / "checks" / f"{name}.json"
    c.parent.mkdir(exist_ok=True)
    c.write_text(json.dumps(row or _row()), encoding="utf-8")
    if key is None:
        return c, None
    env = E.seal(c, key_file=key, label="independent check", audience=audience, deal=DEAL,
                 purpose="check", not_after="7d")
    return c, env["dsseEnvelope"]["signatures"][0]["keyid"]


def _decide(f, did, action="pay", **kw):
    kw.setdefault("record_dir", f.parent.parent / "rec")
    if action in G.NEEDS_EXCHANGE:                 # F2/R3: act, pay, irreversible name the exchange
        kw.setdefault("deal", DEAL)
        kw.setdefault("purpose", "grading")
    if kw.get("deal") is not None:                # D066: a deal id needs the party's ledger
        kw.setdefault("ledger", f.parent.parent / "ledger.jsonl")
    return G.decide(f, action=action, audience=AUD, signers=[did], **kw)


# --- the cases the item names ----------------------------------------------------------

def test_over_cap_with_a_good_nonparty_check_allows(tmp_path):
    f, did, _ = _handed(tmp_path)
    c, checker = _check(tmp_path, "good", _key(tmp_path, "checker"))
    for action in ("act", "pay", "irreversible"):
        d = _decide(f, did, action, require_nonparty_check_above="1000", amount="5000",
                    check_files=[c])
        assert d.decision == "allow" and d.exit_code == 0, d.reason
        assert d.reason.startswith(f"allow {action}: VERIFIED")
        assert "over the cap 1000" in d.reason and checker in d.reason
        np = d.to_dict()["nonparty_check"]
        assert np["applies"] is True and np["satisfied"] is True
        assert np["amount"] == "5000" and np["amount_source"] == "--amount"
        assert np["checks"][0]["counts"] is True and np["checks"][0]["nonparty"] == [checker]
        assert "does not prove the checker is independent" in np["limit"]


def test_over_cap_with_a_party_signed_check_refuses(tmp_path):
    f, did, sender_key = _handed(tmp_path)
    c, _ = _check(tmp_path, "self", sender_key)              # the sender vouches for itself
    d = _decide(f, did, require_nonparty_check_above="1000", amount="5000", check_files=[c])
    assert d.decision == "refuse" and d.verdict == V.VERIFIED and d.exit_code == 3
    assert d.reason.startswith("refuse pay: VERIFIED, but the non-party check rule refuses it")
    assert "signed only by a party" in d.reason
    assert d.could_not_check["looked_for"].startswith("a signed non-party check")


def test_over_cap_with_a_check_signed_by_the_audience_refuses(tmp_path):
    from arcaeon.prove.vet import receipts as R
    rk = _key(tmp_path, "receiver")
    me = R.did_key(R.public_key_from_seed(base64.b64decode(rk.read_text(encoding="ascii"))))
    f = tmp_path / "in" / "grades.csv"
    f.parent.mkdir(exist_ok=True)
    f.write_bytes(BODY)
    env = E.seal(f, key_file=_key(tmp_path, "sender"), **{**BIND, "audience": me})
    did = env["dsseEnvelope"]["signatures"][0]["keyid"]
    c, signer = _check(tmp_path, "mine", rk, audience=me)     # the receiver vouches itself
    assert signer == me
    d = G.decide(f, action="act", audience=me, signers=[did], record_dir=tmp_path / "rec",
                 deal=DEAL, purpose="grading", ledger=tmp_path / "ledger.jsonl",
                 require_nonparty_check_above=1, amount=2, check_files=[c])
    assert d.verdict == V.VERIFIED and d.decision == "refuse" and d.exit_code == 3
    assert "signed only by a party" in d.reason


def test_unsigned_vendor_row_refuses(tmp_path):
    f, did, _ = _handed(tmp_path)
    c, _ = _check(tmp_path, "unsigned", None)                # attestation CLAIMED, no sidecar
    d = _decide(f, did, require_nonparty_check_above="1000", amount="5000", check_files=[c])
    assert d.decision == "refuse" and d.exit_code == 3
    assert "unsigned" in d.reason and "reported by the sender" in d.reason


def test_wrong_file_hash_refuses(tmp_path):
    f, did, _ = _handed(tmp_path)
    c, _ = _check(tmp_path, "other", _key(tmp_path, "checker"), _row(sha="ab" * 32))
    d = _decide(f, did, require_nonparty_check_above="1000", amount="5000", check_files=[c])
    assert d.decision == "refuse" and d.exit_code == 3
    assert f"names sha256 {SHA}" in d.reason


@pytest.mark.parametrize("written", ["sha256:" + SHA, "SHA256:" + SHA.upper(), SHA.upper()])
def test_check_sha256_is_normalised_like_the_checks_veto(tmp_path, written):
    """F8: a `sha256:` prefix or upper case names the same digest, as `--checks` reads it."""
    f, did, _ = _handed(tmp_path)
    c, _ = _check(tmp_path, "prefixed", _key(tmp_path, "checker"), _row(sha=written))
    d = _decide(f, did, require_nonparty_check_above="10", amount="11", check_files=[c])
    assert d.decision == "allow" and d.exit_code == 0, d.reason
    assert d.nonparty_check["checks"][0]["counts"] is True


def test_check_that_says_broken_or_could_not_look_does_not_count(tmp_path):
    f, did, _ = _handed(tmp_path)
    k = _key(tmp_path, "checker")
    cnl, _ = _check(tmp_path, "cnl", k, _row(word=V.COULD_NOT_LOOK))
    d = _decide(f, did, require_nonparty_check_above="10", amount="11", check_files=[cnl])
    assert d.decision == "refuse" and "not VERIFIED" in d.reason
    good, _ = _check(tmp_path, "good", k)
    bad, _ = _check(tmp_path, "bad", _key(tmp_path, "checker2"), _row(word=V.BROKEN))
    d = _decide(f, did, require_nonparty_check_above="10", amount="11", check_files=[good, bad])
    assert d.decision == "refuse" and "says BROKEN" in d.reason        # a veto


def test_checker_pin_narrows_which_nonparty_keys_count(tmp_path):
    f, did, _ = _handed(tmp_path)
    c, checker = _check(tmp_path, "good", _key(tmp_path, "checker"))
    kw = dict(require_nonparty_check_above="10", amount="11", check_files=[c])
    assert _decide(f, did, checkers=[checker], **kw).decision == "allow"
    d = _decide(f, did, checkers=["did:key:z6MkOther"], **kw)
    assert d.decision == "refuse" and "--checker" in d.reason


def test_under_or_at_cap_is_unchanged(tmp_path):
    f, did, _ = _handed(tmp_path)
    plain = _decide(f, did)
    for amt in ("1000", "999.99", 0):
        d = _decide(f, did, require_nonparty_check_above="1000", amount=amt)
        assert d.decision == plain.decision == "allow" and d.exit_code == 0
        assert d.reason == plain.reason
        assert d.to_dict()["nonparty_check"]["applies"] is False
    assert "nonparty_check" not in plain.to_dict()             # rule absent: same keys as before


def test_amount_missing_refuses_guarded_actions_could_not_look(tmp_path):
    f, did, _ = _handed(tmp_path)
    c, _ = _check(tmp_path, "good", _key(tmp_path, "checker"))
    for action in ("act", "pay", "irreversible"):
        d = _decide(f, did, action, require_nonparty_check_above="1000", check_files=[c],
                    deal=DEAL)
        assert d.decision == "refuse" and d.verdict == V.VERIFIED and d.exit_code == 3
        assert "could not look" in d.reason and "(missing)" in d.reason
        assert d.could_not_check["reason_word"] == "missing"
        assert "amount" in d.could_not_check["looked_for"]
    r = _decide(f, did, "read", require_nonparty_check_above="1000")
    assert r.decision == "allow" and r.exit_code == 0         # read: the table, unchanged


def test_unreadable_amount_is_missing(tmp_path):
    f, did, _ = _handed(tmp_path)
    d = _decide(f, did, require_nonparty_check_above="1", amount="lots")
    assert d.decision == "refuse" and d.exit_code == 3
    assert "not a readable amount" in " ".join(d.nonparty_check["amount_notes"])


def test_deal_record_amount_is_read_and_the_larger_wins(tmp_path):
    f, did, _ = _handed(tmp_path)
    rec = tmp_path / "rec" / f"DEAL-{DEAL}"
    rec.mkdir(parents=True)
    rows = [{"kind": "deal.commit", "deal": DEAL, "shared": {"terms": {"total": "5000.00"}}},
            {"kind": "deal.pay", "deal": "d-other", "shared": {"amount": "999999"}}]
    (rec / "buyer.deal.jsonl").write_text(
        "\n".join(r if isinstance(r, str) else json.dumps(r) for r in rows) + "\n",
        encoding="utf-8")
    kw = dict(require_nonparty_check_above="1000", deal=DEAL, record_dir=tmp_path / "rec")
    d = _decide(f, did, amount="10", **kw)                   # the record's 5000 wins over 10
    assert d.decision == "refuse"
    assert d.nonparty_check["amount"] == "5000.00"
    assert d.nonparty_check["amount_source"] == "deal record"
    d = _decide(f, did, amount="20000", **kw)                # --amount wins when larger
    assert d.nonparty_check["amount"] == "20000"
    assert d.nonparty_check["amount_source"] == "--amount"
    d = _decide(f, did, **kw)                                # no --amount: the record alone
    assert d.nonparty_check["amount"] == "5000.00" and d.decision == "refuse"


@pytest.mark.parametrize("bad", ["not json {", '{"kind": "deal.pay", "kind": "x"}',
                                 '{"kind": "deal.pay", "shared": {"amount": "999999"'],
                         ids=["garbage", "dup-key", "cut-off-amount"])
def test_deal_record_line_not_json_refuses_could_not_look(tmp_path, bad):
    """R3 lead decision (reverses the old skip-as-a-note): a deal-record line
    that is not valid JSON could hide an amount over the cap, so the rule
    refuses (exit 3) and names the line, even with every readable amount under
    the cap and a counting check given."""
    f, did, _ = _handed(tmp_path)
    c, _ = _check(tmp_path, "good", _key(tmp_path, "checker"))
    rec = tmp_path / "rec" / f"DEAL-{DEAL}"
    rec.mkdir(parents=True)
    good = json.dumps({"kind": "deal.commit", "deal": DEAL,
                       "shared": {"terms": {"total": "50"}}})
    (rec / "seller.deal.jsonl").write_text(f"{good}\n{bad}\n", encoding="utf-8")
    for checks in ([], [c]):
        d = _decide(f, did, "act", require_nonparty_check_above="1000", amount="10",
                    deal=DEAL, record_dir=tmp_path / "rec", check_files=checks)
        assert d.verdict == V.VERIFIED and d.decision == "refuse" and d.exit_code == 3
        assert d.nonparty_check["applies"] is None
        assert d.nonparty_check["veto"] == G.NONPARTY_VETO
        assert "seller.deal.jsonl line 2" in d.reason
        assert d.could_not_check["reason_word"] == "unreadable"
    (rec / "seller.deal.jsonl").write_text(f"{good}\n\n", encoding="utf-8")   # blank: fine
    d = _decide(f, did, "act", require_nonparty_check_above="1000", amount="10",
                deal=DEAL, record_dir=tmp_path / "rec")
    assert d.decision == "allow" and d.nonparty_check["applies"] is False


@pytest.mark.parametrize("content", [
    b"", b"\xff\xfe garbage", b"[" * 100000, b'{"kind": "a", "kind": "b"}', b"[1, 2, 3]",
    b"null", b'"just a string"', b"{}\n{bad\n", b"x" * (G.MAX_CHECK_BYTES + 1)],
    ids=["empty", "not-utf8", "deep", "dup-key", "list-of-ints", "null", "string",
         "bad-jsonl", "too-big"])
def test_hostile_check_file_is_an_answer_not_a_traceback(tmp_path, content):
    f, did, _ = _handed(tmp_path)
    c = tmp_path / "checks" / "hostile.json"
    c.parent.mkdir(exist_ok=True)
    c.write_bytes(content)
    d = _decide(f, did, require_nonparty_check_above="1", amount="2", check_files=[c])
    assert d.decision == "refuse" and d.exit_code == 3
    assert d.nonparty_check["checks"][0]["counts"] is False


def test_hostile_check_paths_and_sidecars(tmp_path):
    f, did, _ = _handed(tmp_path)
    c, _ = _check(tmp_path, "good", _key(tmp_path, "checker"))
    E.envelope_path(c).write_text("{not an envelope", encoding="utf-8")
    d = _decide(f, did, require_nonparty_check_above="1", amount="2",
                check_files=[c, tmp_path / "nope.json", tmp_path, "\x00bad"])
    assert d.decision == "refuse" and d.exit_code == 3
    assert len(d.nonparty_check["checks"]) == 4
    assert not any(j["counts"] for j in d.nonparty_check["checks"])


def test_rule_does_not_change_broken_or_could_not_look(tmp_path):
    f, did, _ = _handed(tmp_path)
    c, _ = _check(tmp_path, "good", _key(tmp_path, "checker"))
    kw = dict(require_nonparty_check_above="1", amount="2", check_files=[c])
    cnl = G.decide(f, action="pay", audience=AUD, signers=[], **kw)
    assert cnl.verdict == V.COULD_NOT_LOOK and cnl.decision == "refuse"
    assert cnl.reason == G.decide(f, action="pay", audience=AUD, signers=[]).reason
    f.write_bytes(BODY + b"x")
    broken = G.decide(f, action="pay", audience=AUD, signers=[did], **kw)
    assert broken.verdict == V.BROKEN and broken.exit_code == 1


# --- the non-party rule beside the checker veto (F9, D067) ------------------------------

def _veto_file(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / "veto" / name
    p.parent.mkdir(exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return p


@pytest.mark.parametrize("veto", ["broken", "unreadable"])
def test_nonparty_refusal_keeps_its_reason_and_exit_3_beside_a_checker_veto(tmp_path, veto):
    f, did, _ = _handed(tmp_path)
    u, _ = _check(tmp_path, "unsigned", None)
    content = json.dumps(_row(word=V.BROKEN)) if veto == "broken" else "{not json\n"
    v = _veto_file(tmp_path, "veto.jsonl", content)
    d = _decide(f, did, require_nonparty_check_above="10", amount="11", check_files=[u, v])
    assert d.decision == "refuse" and d.verdict == V.VERIFIED
    assert d.reason.startswith("refuse pay: VERIFIED, but the non-party check rule refuses it")
    assert d.exit_code == 3, d.reason
    assert d.veto == G.NONPARTY_VETO and d.checks["veto"] is None
    assert d.checks["would_veto"] == (G.CHECKER_BROKEN if veto == "broken"
                                      else G.CHECKS_UNREADABLE)
    assert d.could_not_check["looked_for"].startswith("a signed non-party check")


def test_nonparty_refusal_row_carries_its_veto(tmp_path):
    f, did, _ = _handed(tmp_path)
    u, _ = _check(tmp_path, "unsigned", None)
    d = _decide(f, did, require_nonparty_check_above="10", amount="11", check_files=[u])
    assert d.decision == "refuse" and d.evidence and d.chain_row
    assert d.chain_row["verdict"] == V.VERIFIED and d.chain_row["veto"] == "nonparty-check"
    assert d.to_dict()["nonparty_check"]["veto"] == "nonparty-check"
    ok = _decide(f, did, require_nonparty_check_above="10", amount="5")      # under the cap
    assert ok.decision == "allow" and ok.veto is None


def test_under_cap_checker_veto_is_unchanged(tmp_path):
    f, did, _ = _handed(tmp_path)
    v = _veto_file(tmp_path, "veto.jsonl", json.dumps(_row(word=V.BROKEN)))
    d = _decide(f, did, require_nonparty_check_above="10", amount="5", check_files=[v])
    assert d.decision == "refuse" and d.veto == G.CHECKER_BROKEN and d.exit_code == 1
    assert d.chain_row["veto"] == G.CHECKER_BROKEN


def test_bad_cap_raises_in_the_library(tmp_path):
    f, did, _ = _handed(tmp_path)
    for cap in ("ten", "-1", "NaN", True):
        with pytest.raises(ValueError):
            _decide(f, did, require_nonparty_check_above=cap)


# --- the CLI ---------------------------------------------------------------------------

def _cli(f, did, *extra):
    return cli.main(["gate", "decide", "--envelope", str(E.envelope_path(f)),
                     "--audience", AUD, "--signer", did, *extra])


def test_cli_flags(tmp_path, capsys):
    f, did, _ = _handed(tmp_path)
    c, _ = _check(tmp_path, "good", _key(tmp_path, "checker"))
    u, _ = _check(tmp_path, "unsigned", None)
    rule = ["--action", "pay", "--require-nonparty-check-above", "1000",
            "--deal", DEAL, "--purpose", "grading", "--ledger", str(tmp_path / "ledger.jsonl"),
            "--record-dir", str(tmp_path / "rec")]
    assert _cli(f, did, *rule, "--amount", "5000", "--checks", str(c)) == 0
    assert capsys.readouterr().out.startswith("allow pay: VERIFIED")
    assert _cli(f, did, *rule, "--amount", "5000", "--checks", str(u), "--json") == 3
    j = json.loads(capsys.readouterr().out)
    assert j["decision"] == "refuse" and j["nonparty_check"]["satisfied"] is False
    assert _cli(f, did, *rule) == 3                                   # no amount
    assert "could not look" in capsys.readouterr().out
    assert _cli(f, did, *rule, "--amount", "1000") == 0               # at the cap
    assert _cli(f, did, "--action", "read", "--require-nonparty-check-above", "1") == 0
    capsys.readouterr()
    assert _cli(f, did, "--action", "pay", "--checker", "did:key:z6MkX") == 2   # no rule: usage
    assert _cli(f, did, "--action", "pay", "--amount", "5") == 2
    assert _cli(f, did, *rule[:2], "--require-nonparty-check-above", "x") == 2
    assert _cli(f, did, *rule, "--amount", "-3") == 2
    assert "--require-nonparty-check-above" in capsys.readouterr().err


# --- one flag: --checks FILE feeds the checker veto and the non-party rule ---------------

def test_check_flag_is_gone_and_points_at_checks(tmp_path, capsys):
    f, did, _ = _handed(tmp_path)
    c, _ = _check(tmp_path, "good", _key(tmp_path, "checker"))
    rule = ["--action", "act", "--require-nonparty-check-above", "1", "--amount", "2"]
    assert _cli(f, did, *rule, "--check", str(c)) == 2
    assert "--checks FILE" in capsys.readouterr().err
    assert "--check FILE" not in G.USAGE and "[--checks FILE ...]" in G.USAGE


def test_checks_flag_counts_for_the_nonparty_rule_with_checker_pins(tmp_path, capsys):
    f, did, _ = _handed(tmp_path)
    c, checker = _check(tmp_path, "good", _key(tmp_path, "checker"))
    rule = ["--action", "act", "--require-nonparty-check-above", "1", "--amount", "2",
            "--checks", str(c), "--deal", DEAL, "--purpose", "grading",
            "--ledger", str(tmp_path / "ledger.jsonl"), "--record-dir", str(tmp_path / "rec")]
    assert _cli(f, did, *rule) == 0
    assert _cli(f, did, *rule, "--checker", "did:key:z6MkOther", "--checker", checker) == 0
    assert _cli(f, did, *rule, "--checker", "did:key:z6MkOther") == 3
    assert "--checker" in capsys.readouterr().out


@pytest.mark.parametrize("shape", ["object", "pretty", "list"])
def test_checks_file_in_any_rule_shape_is_readable_by_the_veto(tmp_path, shape):
    """A check file the non-party rule reads (one object, a list, JSON lines) is
    not checks-unreadable to the checker veto under the cap."""
    f, did, _ = _handed(tmp_path)
    row = _row()
    text = {"object": json.dumps(row), "pretty": json.dumps(row, indent=2),
            "list": json.dumps([row, _row(sha="ab" * 32)], indent=1)}[shape]
    c, _ = _check(tmp_path, "good", _key(tmp_path, "checker"))
    c.write_text(text, encoding="utf-8")
    d = _decide(f, did, require_nonparty_check_above="10", amount="5", check_files=[c])
    assert d.decision == "allow" and d.checks["problems"] == [] and d.checks["rows"] >= 1
    broken = _veto_file(tmp_path, "b.json", json.dumps([_row(word=V.BROKEN)], indent=2))
    d = _decide(f, did, check_files=[broken])
    assert d.decision == "refuse" and d.veto == G.CHECKER_BROKEN and d.exit_code == 1


def test_unreadable_checks_file_still_refuses(tmp_path):
    f, did, _ = _handed(tmp_path)
    bad = _veto_file(tmp_path, "bad.jsonl", "{not json\n")
    d = _decide(f, did, check_files=[bad])
    assert d.decision == "refuse" and d.veto == G.CHECKS_UNREADABLE and d.exit_code == 3
    d = _decide(f, did, check_files=[tmp_path / "missing.jsonl", "\x00bad"])
    assert d.decision == "refuse" and d.veto == G.CHECKS_UNREADABLE and d.exit_code == 3
    assert _decide(f, did, "read", check_files=[bad]).decision == "allow"


def test_checks_keyword_is_an_alias_of_check_files(tmp_path):
    f, did, _ = _handed(tmp_path)
    c, _ = _check(tmp_path, "good", _key(tmp_path, "checker"))
    kw = dict(require_nonparty_check_above="1", amount="2")
    a = _decide(f, did, "act", checks=[c], **kw)
    b = _decide(f, did, "act", check_files=[c], **kw)
    assert a.decision == b.decision == "allow" and a.checks["files"] == b.checks["files"]


# --- R3-3: a record amount the rule cannot read is never skipped -------------------

def _record(tmp_path, *rows):
    rec = tmp_path / "rec" / f"DEAL-{DEAL}"
    rec.mkdir(parents=True, exist_ok=True)
    (rec / "buyer.deal.jsonl").write_text("".join(json.dumps(r) + "\n" for r in rows),
                                          encoding="utf-8")


def test_record_amount_as_a_json_number_counts(tmp_path):
    """Outside red team round 3 (R3-3, Gemini #1): a JSON number amount was not a
    str/int/Decimal, so the record's 1000000.5 was skipped with no note and
    --amount 10 put the deal under the cap: pay allowed, no non-party check."""
    f, did, _ = _handed(tmp_path)
    _record(tmp_path, {"kind": "deal.pay", "deal": DEAL, "shared": {"amount": 1000000.5}})
    d = _decide(f, did, require_nonparty_check_above="100", amount="10")
    assert d.decision == "refuse"
    assert d.nonparty_check["amount"] == "1000000.5"
    assert d.nonparty_check["amount_source"] == "deal record"


@pytest.mark.parametrize("bad", ["lots", -5, True, None, {"v": 1}, "NaN"])
def test_unreadable_record_amount_refuses_could_not_look(tmp_path, bad):
    f, did, _ = _handed(tmp_path)
    _record(tmp_path, {"kind": "deal.commit", "deal": DEAL, "shared": {"terms": {"total": bad}}})
    d = _decide(f, did, require_nonparty_check_above="100", amount="10")
    assert d.decision == "refuse" and d.exit_code == 3
    assert d.nonparty_check["applies"] is None
    assert any("not a readable amount" in n for n in d.nonparty_check["amount_notes"])
