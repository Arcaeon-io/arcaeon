"""The gate's evidence row (D056): a refusal with an evidence pack appends one
`gate.evidence` row to a hash-chained ledger, carrying the pack's digest, so a
later edit of the pack no longer matches the chain. `deal dispute` ignores the
row. Every key here is a throwaway seed written to tmp_path; no network."""
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
from arcaeon.record.deal import Deal, dispute
from arcaeon.record.ledger import Ledger, verify_file

pytest.importorskip("cryptography", reason="signing needs the [sign] extra")

BIND = {"label": "week 3 grades", "audience": "instructor-1", "deal": "d-7f3a",
        "purpose": "grading", "not_after": "7d"}
BODY = b"name,grade\nunit-a,pass\n"
ITEMS = [{"sku": "pens-12", "qty": 2, "unit_price": "9.50"}]
WINDOW = dict(not_before="2026-01-01T00:00:00Z", not_after="2099-12-31T00:00:00Z")


def _make(tmp_path: Path, verdict: str):
    """A handed file whose envelope verifies to `verdict`, and the signer's DID."""
    f = tmp_path / "in" / "grades.csv"
    f.parent.mkdir(exist_ok=True)
    f.write_bytes(BODY)
    key = None
    if verdict != V.COULD_NOT_LOOK:
        key = tmp_path / "seal.key"
        key.write_text(base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
                       encoding="ascii")
    env = E.seal(f, key_file=key, **BIND)
    sigs = env["dsseEnvelope"]["signatures"]
    did = sigs[0]["keyid"] if sigs else "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    if verdict == V.BROKEN:
        f.write_bytes(BODY + b"unit-b,pass\n")
    return f, did


def _rows(path: Path) -> list[dict]:
    return [r for r in Ledger(path) if isinstance(r, dict)]


def _gate_rows(path: Path) -> list[dict]:
    return [r for r in _rows(path) if r.get("kind") == G.CHAIN_KIND]


@pytest.fixture(autouse=True)
def _cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)


def _refuse(tmp_path, **kw):
    f, did = _make(tmp_path, V.BROKEN)
    kw.setdefault("record_dir", tmp_path / "rec")
    d = G.decide(f, action="pay", audience="instructor-1", signers=[did], deal="d-7f3a", **kw)
    return f, d


# --- one row on refusal, none on allow ----------------------------------------------

def test_refusal_with_deal_appends_exactly_one_gate_evidence_row(tmp_path):
    f, d = _refuse(tmp_path)
    assert d.decision == "refuse" and d.verdict == V.BROKEN and d.chain_error is None
    pack = Path(d.evidence)
    ledger = pack.parent / G.LEDGER_NAME
    rows = _rows(ledger)
    assert len(rows) == 1 and rows == _gate_rows(ledger)
    row = rows[0]
    assert row == d.chain_row
    assert row["kind"] == "gate.evidence" and row["deal"] == "d-7f3a"
    assert row["file_sha256"] == hashlib.sha256(f.read_bytes()).hexdigest()
    assert row["verdict"] == V.BROKEN
    ev = json.loads((pack / "evidence.json").read_text(encoding="utf-8"))
    assert row["reason"] == ev["reason"] and row["at"] == ev["at"] == d.at
    assert row["pack"] == pack.name and row["pack_digest_of"] == G.PACK_DIGEST_OF
    assert row["pack_digest"] == G.pack_digest(pack)
    assert verify_file(ledger).ok is True
    assert d.to_dict()["chain_row"] == row


def test_pack_digest_is_the_documented_rule(tmp_path):
    _, d = _refuse(tmp_path)
    pack = Path(d.evidence)
    lines = sorted((p.relative_to(pack).as_posix(), hashlib.sha256(p.read_bytes()).hexdigest())
                   for p in pack.rglob("*") if p.is_file())
    assert [r for r, _ in lines] == ["bundle/grades.csv", "bundle/grades.csv.envelope.json",
                                     "evidence.json"]
    text = "".join(f"{h}  {r}\n" for r, h in lines)
    assert G.pack_digest(pack) == hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_second_refusal_chains_a_second_row(tmp_path):
    f, a = _refuse(tmp_path)
    did = a.signers[0]
    b = G.decide(f, action="act", audience="instructor-1", signers=[did], deal="d-7f3a",
                 record_dir=tmp_path / "rec")
    ledger = Path(a.evidence).parent / G.LEDGER_NAME
    rows = _gate_rows(ledger)
    assert [r["pack"] for r in rows] == [Path(a.evidence).name, Path(b.evidence).name]
    assert verify_file(ledger).ok is True


def test_allow_writes_no_row(tmp_path):
    f, did = _make(tmp_path, V.VERIFIED)
    led = tmp_path / "tape.jsonl"
    d = G.decide(f, action="pay", audience="instructor-1", signers=[did], deal="d-7f3a",
                 record_dir=tmp_path / "rec", ledger=led)
    assert d.decision == "allow" and d.chain_row is None
    assert not led.exists() and not (tmp_path / "rec").exists()


def test_could_not_look_refusal_writes_no_pack_and_no_row(tmp_path):
    f, did = _make(tmp_path, V.COULD_NOT_LOOK)
    led = tmp_path / "tape.jsonl"
    d = G.decide(f, action="pay", audience="instructor-1", signers=[did], deal="d-7f3a",
                 record_dir=tmp_path / "rec", ledger=led)
    assert d.decision == "refuse" and d.evidence is None and d.chain_row is None
    assert not led.exists()


def test_no_deal_id_no_row_no_crash(tmp_path):
    f, did = _make(tmp_path, V.BROKEN)
    led = tmp_path / "tape.jsonl"
    d = G.decide(f, action="pay", audience="instructor-1", signers=[did],
                 record_dir=tmp_path / "rec", ledger=led)
    assert d.decision == "refuse" and d.exit_code == 1
    assert d.evidence is None and d.chain_row is None and d.chain_error is None
    assert not led.exists() and not (tmp_path / "rec").exists()


def test_unwritable_ledger_keeps_the_refusal(tmp_path):
    blocker = tmp_path / "a-file"
    blocker.write_text("x", encoding="utf-8")
    _, d = _refuse(tmp_path, ledger=blocker / "sub" / "tape.jsonl")
    assert d.decision == "refuse" and d.exit_code == 1 and d.evidence
    assert d.chain_row is None and d.chain_error.startswith("gate.evidence row not appended")
    assert "row could not be appended" in d.reason


# --- tamper evidence ------------------------------------------------------------------

def test_untouched_pack_verifies(tmp_path):
    _, d = _refuse(tmp_path)
    r = G.verify_evidence_pack(d.evidence, d.chain_row)
    assert r["verdict"] == V.VERIFIED and r["now"] == r["recorded"]


@pytest.mark.parametrize("edit", ["copy", "evidence", "add", "remove", "rename"])
def test_editing_the_pack_after_the_fact_is_broken(tmp_path, edit):
    _, d = _refuse(tmp_path)
    pack, row = Path(d.evidence), d.chain_row
    copy = pack / "bundle" / "grades.csv"
    if edit == "copy":
        copy.write_bytes(BODY)                         # put the sealed bytes back
    elif edit == "evidence":
        ev = json.loads((pack / "evidence.json").read_text(encoding="utf-8"))
        ev["verdict"] = V.VERIFIED
        (pack / "evidence.json").write_text(json.dumps(ev), encoding="utf-8")
    elif edit == "add":
        (pack / "note.txt").write_text("added later", encoding="utf-8")
    elif edit == "remove":
        (pack / "bundle" / "grades.csv.envelope.json").unlink()
    else:
        copy.rename(pack / "bundle" / "grades-old.csv")
    assert G.pack_digest(pack) != row["pack_digest"]
    r = G.verify_evidence_pack(pack, row)
    assert r["verdict"] == V.BROKEN and "changed after the row was written" in r["reason"]


def test_verify_could_not_look(tmp_path):
    _, d = _refuse(tmp_path)
    assert G.verify_evidence_pack(tmp_path / "gone", d.chain_row)["verdict"] == V.COULD_NOT_LOOK
    assert G.verify_evidence_pack(d.evidence, {"kind": "deal.pay"})["verdict"] == V.COULD_NOT_LOOK
    no_digest = dict(d.chain_row, pack_digest="xyz")
    assert G.verify_evidence_pack(d.evidence, no_digest)["verdict"] == V.COULD_NOT_LOOK
    assert G.verify_evidence_pack(d.evidence, None)["verdict"] == V.COULD_NOT_LOOK


# --- deal dispute ignores the new kind ----------------------------------------------

def _honest(tmp: Path, deal="d-7f3a"):
    b, s = tmp / "buyer.jsonl", tmp / "seller.jsonl"
    buyer, seller = Deal(b, "buyer", deal), Deal(s, "seller", deal)
    buyer.mandate(merchant="acme", cap="60.00", currency="USD", **WINDOW)
    bc = buyer.commit(items=ITEMS, total="19.00", currency="USD", seller="acme",
                      ship_to="1 Main St", buyer_ref="po-1")
    seller.commit(items=ITEMS, total="19.00", currency="USD", seller="acme",
                  ship_to="1 Main St", buyer_ref="po-1",
                  mandate_digest=bc["shared"]["mandate_digest"])
    for d in (buyer, seller):
        d.pay(rail="card", reference="ch_1", amount="19.00", currency="USD")
    return b, s


def test_deal_dispute_ignores_gate_evidence_rows(tmp_path, capsys):
    b, s = _honest(tmp_path)
    before = dispute("d-7f3a", b, s).to_dict()
    assert before["verdict"] == V.MATCHED
    _, d = _refuse(tmp_path, ledger=b)                 # the row lands on the buyer's tape
    assert d.chain_row is not None and len(_gate_rows(b)) == 1
    assert verify_file(b).ok is True
    after = dispute("d-7f3a", b, s).to_dict()
    assert after["verdict"] == V.MATCHED and after["matched"] == before["matched"]
    assert after["counts"] == before["counts"] and after["findings"] == []
    assert [e["step"] for e in after["timeline"]] == [e["step"] for e in before["timeline"]]
    assert cli.main(["deal", "dispute", "d-7f3a", "--buyer", str(b), "--seller", str(s)]) == 0
    assert capsys.readouterr().out.startswith("MATCHED")
    assert cli.main(["deal", "show", str(b), "--deal", "d-7f3a"]) == 0
    assert "gate.evidence" not in capsys.readouterr().out


# --- CLI --------------------------------------------------------------------------------

def test_cli_ledger_flag(tmp_path, capsys):
    f, did = _make(tmp_path, V.BROKEN)
    led = tmp_path / "tape.jsonl"
    rc = cli.main(["gate", "decide", "--envelope", str(E.envelope_path(f)), "--audience",
                   "instructor-1", "--signer", did, "--action", "read", "--deal", "d-7f3a",
                   "--record-dir", str(tmp_path / "rec"), "--ledger", str(led), "--json"])
    assert rc == 1
    j = json.loads(capsys.readouterr().out)
    assert j["chain_row"]["kind"] == "gate.evidence" and _gate_rows(led) == [j["chain_row"]]
