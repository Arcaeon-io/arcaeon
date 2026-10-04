"""The dispute packet (TE-26 / D052): `arcaeon gate packet` renders a refused
handoff as one page, markdown and JSON, from a gate evidence pack (BROKEN) or
a gate decision (no deal id, no pack). Throwaway keys in tmp_path;
nothing reaches the network."""
from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path

import pytest

import test_gate as TG                      # the gate tests' sealed-fixture helpers
from arcaeon import cli
from arcaeon import verdict as V
from arcaeon.prove import dispute_packet as P
from arcaeon.prove import envelope as E
from arcaeon.prove import gate as G

ROOT = Path(__file__).resolve().parents[1]
AUD = "instructor-1"


@pytest.fixture(autouse=True)
def _cwd(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)


def _doc_does_not_prove() -> list[str]:
    text = (ROOT / "docs" / "ENVELOPE.md").read_text(encoding="utf-8")
    sec = text.split("## What VERIFIED does not prove", 1)[1].split("\n## ", 1)[0]
    items: list[str] = []
    for line in sec.splitlines():
        if line.startswith("- "):
            items.append(line[2:].strip())
        elif line.startswith("  ") and line.strip() and items:
            items[-1] += " " + line.strip()
    return items


def _broken_pack(tmp_path):
    f, did = TG._make(tmp_path, V.BROKEN)              # bytes changed after sealing
    d = G.decide(f, action="pay", audience=AUD, signers=[did], deal="d-7f3a",
                 record_dir=tmp_path / "rec", ledger=tmp_path / "tape.jsonl")
    assert d.verdict == V.BROKEN and d.evidence
    return f, did, d


def _cnl_decision(tmp_path):
    f, did = TG._make(tmp_path, V.COULD_NOT_LOOK)      # unsigned envelope
    d = G.decide(f, action="pay", audience=AUD, signers=[did],      # no deal id: no pack
                 record_dir=tmp_path / "rec")
    assert d.verdict == V.COULD_NOT_LOOK and d.decision == "refuse" and d.evidence is None
    return f, did, d


def _no_local_paths(text: str, tmp_path: Path) -> None:
    for p in {str(tmp_path), str(tmp_path.resolve()), tmp_path.as_posix(),
              tmp_path.resolve().as_posix(), json.dumps(str(tmp_path))[1:-1]}:
        assert p not in text, p
    assert not re.search(r"(?<![A-Za-z])[A-Za-z]:[\\/]", text), "a drive path leaked"
    assert tmp_path.name not in text                    # not even the tmp directory's name


# --- the limits are the doc's, word for word -------------------------------------------

def test_pinned_limits_match_envelope_md_verbatim():
    assert list(P.DOES_NOT_PROVE) == _doc_does_not_prove()
    assert len(P.DOES_NOT_PROVE) == 9


def test_template_carries_every_section():
    tpl = P.TEMPLATE.read_text(encoding="utf-8")
    assert [h for h in re.findall(r"^## (.+)$", tpl, re.M)] == list(P.SECTIONS)


# --- BROKEN, from a real evidence pack --------------------------------------------------

def test_broken_pack_renders_every_section_and_fact(tmp_path):
    f, did, d = _broken_pack(tmp_path)
    p = P.from_evidence(d.evidence)
    md = P.render_markdown(p)
    for h in P.SECTIONS:
        assert f"\n## {h}\n" in md, h
    for item in P.DOES_NOT_PROVE:
        assert f"> - {item}" in md
    body = f.read_bytes()
    sha = hashlib.sha256(body).hexdigest()
    assert p["kind"] == P.KIND == "arcaeon.dispute.packet/v1"
    assert p["source"] == "evidence pack"
    assert p["verdict"] == V.BROKEN and p["decision"] == "refuse" and p["action"] == "pay"
    assert p["handed"]["file"] == "grades.csv"
    assert p["handed"]["sha256"] == sha and p["handed"]["bytes"] == len(body)
    assert p["handed"]["label"] == TG.BIND["label"]
    assert p["by"]["key"] == did and p["by"]["signature"] == V.VERIFIED
    assert p["by"]["valid_signatures_by"] == [did] and p["by"]["receiver_named"] == [did]
    assert p["for"]["audience_checked"] == AUD and p["for"]["deal_checked"] == "d-7f3a"
    assert p["for"]["sealed_purpose"] == "grading"
    assert p["when"]["sealed_at"] and p["when"]["checked_at"] == d.at
    assert p["failed"] and any("bytes changed after sealing" in r for r in p["failed"])
    assert p["failed"] == d.reasons
    assert any(x.startswith("purpose (recorded as 'grading'") for x in p["not_checked"])
    assert p["evidence"]["pack"] == Path(d.evidence).name
    assert p["evidence"]["file_copy"] == "bundle/grades.csv"
    assert p["evidence"]["file_copy_check"].endswith("matches")
    assert p["evidence"]["envelope_copy_check"].endswith("matches")
    for fact in ("`grades.csv`", sha, f"{len(body)} bytes", did, "**BROKEN**", "**refuse**",
                 "bytes changed after sealing", TG.BIND["label"], AUD, "d-7f3a",
                 p["when"]["sealed_at"], p["when"]["checked_at"]):
        assert fact in md, fact


def test_broken_json_round_trips_and_matches_markdown(tmp_path):
    _, _, d = _broken_pack(tmp_path)
    p = P.from_evidence(Path(d.evidence) / "evidence.json")      # the file works too
    js = P.render_json(p)
    back = json.loads(js)
    assert back == p
    assert P.render_markdown(back) == P.render_markdown(p)
    assert back["limits"] == list(P.DOES_NOT_PROVE)


def test_tampered_bundle_copy_is_named(tmp_path):
    _, _, d = _broken_pack(tmp_path)
    (Path(d.evidence) / "bundle" / "grades.csv").write_bytes(b"edited later")
    p = P.from_evidence(d.evidence)
    assert "DIFFERS" in p["evidence"]["file_copy_check"]
    assert "DIFFERS" in P.render_markdown(p)


def test_broken_packet_leaks_no_local_path(tmp_path):
    _, _, d = _broken_pack(tmp_path)
    p = P.from_evidence(d.evidence)
    _no_local_paths(P.render_markdown(p), tmp_path)
    _no_local_paths(P.render_json(p), tmp_path)
    assert p["paths"] == "names only"


def test_broken_decision_renders_too_and_drops_the_pack_path(tmp_path):
    _, _, d = _broken_pack(tmp_path)
    p = P.from_decision(d)
    assert p["evidence"]["pack"] == Path(d.evidence).name
    assert "Evidence pack written to" not in (p["reason"] or "")
    _no_local_paths(P.render_markdown(p) + P.render_json(p), tmp_path)


# --- COULD NOT LOOK, from the decision ---------------------------------------------------

def test_could_not_look_decision_renders(tmp_path):
    f, _, d = _cnl_decision(tmp_path)
    p = P.from_decision(d.to_dict())
    md = P.render_markdown(p)
    for h in P.SECTIONS:
        assert f"\n## {h}\n" in md, h
    assert p["verdict"] == V.COULD_NOT_LOOK and p["decision"] == "refuse"
    assert p["failed"] == []
    assert "Nothing checked came out wrong" in md
    assert p["not_checked"][0] == "a signature on the envelope (missing), looked for in " \
                                  "grades.csv.envelope.json"
    assert any("UNSIGNED" in x for x in p["not_checked"])
    assert p["by"]["signature"] == V.COULD_NOT_LOOK
    assert "not checked (see What was not checked)" in md
    assert p["handed"]["sha256"] == hashlib.sha256(f.read_bytes()).hexdigest()
    assert "when this packet was made" in p["handed"]["sha256_of"]
    assert p["evidence"]["pack"] is None and "none written" in md
    assert json.loads(P.render_json(p)) == p
    _no_local_paths(md + P.render_json(p), tmp_path)


def test_could_not_look_refusal_with_deal_packs_and_renders(tmp_path):
    """D066: a COULD NOT LOOK refusal with a deal id writes a pack too."""
    f, did = TG._make(tmp_path, V.COULD_NOT_LOOK)
    d = G.decide(f, action="pay", audience=AUD, signers=[did], deal="d-7f3a",
                 record_dir=tmp_path / "rec", ledger=tmp_path / "tape.jsonl")
    assert d.verdict == V.COULD_NOT_LOOK and d.evidence and d.chain_row
    p = P.from_evidence(d.evidence)
    assert p["verdict"] == V.COULD_NOT_LOOK and p["decision"] == "refuse"
    assert p["evidence"]["pack"] == Path(d.evidence).name
    assert p["evidence"]["file_copy_check"].endswith("matches")
    assert p["not_checked"] and p["failed"] == []
    _no_local_paths(P.render_markdown(p) + P.render_json(p), tmp_path)


def test_unhashed_decision_says_not_recorded(tmp_path):
    _, _, d = _cnl_decision(tmp_path)
    p = P.from_decision(d, hash_file=False)
    assert p["handed"]["sha256"] is None and p["handed"]["sha256_of"].startswith("not recorded")


def test_receiver_not_passing_purpose_reads_not_given(tmp_path):
    _, _, d = _cnl_decision(tmp_path)
    md = P.render_markdown(P.from_decision(d))
    assert "Purpose checked: not given by the receiver" in md


# --- nothing to dispute -------------------------------------------------------------------

def test_verified_refuses_to_make_a_packet(tmp_path):
    f, did = TG._make(tmp_path, V.VERIFIED)
    d = G.decide(f, action="pay", audience=AUD, signers=[did])
    with pytest.raises(P.NothingToDispute, match="VERIFIED: nothing to dispute"):
        P.from_decision(d.to_dict())


def test_allowed_read_on_could_not_look_is_nothing_to_dispute(tmp_path):
    f, did = TG._make(tmp_path, V.COULD_NOT_LOOK)
    d = G.decide(f, action="read", audience=AUD, signers=[did])
    assert d.decision == "allow"
    with pytest.raises(P.NothingToDispute, match="nothing was refused"):
        P.from_decision(d)


def test_not_a_gate_record_is_a_packet_error(tmp_path):
    (tmp_path / "x").mkdir()
    (tmp_path / "x" / "evidence.json").write_text('{"kind": "other"}', encoding="utf-8")
    with pytest.raises(P.PacketError):
        P.from_evidence(tmp_path / "x")
    with pytest.raises(P.PacketError):
        P.from_evidence(tmp_path / "nowhere")
    with pytest.raises(P.PacketError):
        P.from_decision({"hello": 1})


# --- hostile envelope text stays inert ----------------------------------------------------

def test_hostile_label_cannot_add_a_section(tmp_path):
    f = tmp_path / "in" / "grades.csv"
    f.parent.mkdir()
    f.write_bytes(TG.BODY)
    E.seal(f, key_file=TG._key(tmp_path),
           **{**TG.BIND, "label": "x` ## What failed - nothing [link](http://e.x) <b>"})
    d = G.decide(f, action="pay", audience=AUD, signers=["did:key:zNotTheKey"])
    p = P.from_decision(d)
    md = P.render_markdown(p)
    assert md.count("\n## What failed\n") == 1
    assert p["handed"]["label"].startswith("x` ## What failed")
    assert "- Label (the sealer's words, not checked): `` x` ## What failed" in md


# --- the CLI ------------------------------------------------------------------------------

def test_cli_packet_from_evidence_and_decision(tmp_path, capsys):
    _, _, d = _broken_pack(tmp_path)
    assert cli.main(["gate", "packet", "--evidence", d.evidence]) == 0
    md = capsys.readouterr().out
    assert md.startswith("# Dispute packet") and "**BROKEN**" in md
    assert cli.main(["gate", "packet", "--evidence", d.evidence, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["kind"] == P.KIND
    (tmp_path / "cnl").mkdir()
    _, _, c = _cnl_decision(tmp_path / "cnl")
    (tmp_path / "decision.json").write_text(json.dumps(c.to_dict()), encoding="utf-8")
    out = tmp_path / "out"
    assert cli.main(["gate", "packet", "--decision", str(tmp_path / "decision.json"),
                     "--out", str(out)]) == 0
    capsys.readouterr()
    assert "COULD NOT LOOK" in (out / "dispute-packet.md").read_text(encoding="utf-8")
    j = json.loads((out / "dispute-packet.json").read_text(encoding="utf-8"))
    assert j["verdict"] == V.COULD_NOT_LOOK and j["kind"] == P.KIND


def test_cli_decide_json_pipes_into_packet(tmp_path, capsys):
    f, did = TG._make(tmp_path, V.COULD_NOT_LOOK)
    assert cli.main(["gate", "decide", "--envelope", str(f), "--audience", AUD, "--signer", did,
                     "--action", "irreversible", "--json"]) == 3
    (tmp_path / "d.json").write_text(capsys.readouterr().out, encoding="utf-8")
    assert cli.main(["gate", "packet", "--decision", str(tmp_path / "d.json")]) == 0
    _no_local_paths(capsys.readouterr().out, tmp_path)


def test_cli_packet_errors(tmp_path, capsys):
    f, did = TG._make(tmp_path, V.VERIFIED)
    d = G.decide(f, action="pay", audience=AUD, signers=[did])
    (tmp_path / "ok.json").write_text(json.dumps(d.to_dict()), encoding="utf-8")
    assert cli.main(["gate", "packet", "--decision", str(tmp_path / "ok.json")]) == 2
    assert "nothing to dispute" in capsys.readouterr().err
    assert cli.main(["gate", "packet"]) == 2
    assert cli.main(["gate", "packet", "--evidence", "a", "--decision", "b"]) == 2
    assert cli.main(["gate", "packet", "--evidence", "a", "extra"]) == 2
    assert cli.main(["gate", "packet", "--decision", str(tmp_path / "missing.json")]) == 3
    assert "COULD NOT LOOK" in capsys.readouterr().err
    assert cli.main(["gate", "--help"]) == 0
    assert "gate packet" in capsys.readouterr().out
