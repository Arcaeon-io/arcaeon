"""Bearer classes on page one: every sentence of the pack's README.md ends in
[bytes], [order] or [asserted], README.json is its machine-readable twin, and
verify breaks on an untagged or misclassed sentence, naming the sentence id."""
import hashlib
import json
import re

import pytest

from arcaeon import verdict as V
from arcaeon.prove.evidence_pack import (BEARER_ALLOWED, BEARER_CLASSES,
                                         BEARER_FALSIFIER, BEARER_FILE, build_pack,
                                         falsifier_files)
from arcaeon.prove.evidence_pack_verify import main, verify_pack

CHAIN = "It shows what was written and that every row hashes to the next."
TAG = re.compile(r".* \[(bytes|order|asserted; falsifier: [^\]]+)\]")


def _m(out):
    return json.loads((out / "manifest.json").read_text(encoding="utf-8"))


def _seal(out, *fixed):
    """Rehash the named files and the manifest, so only the bearer check is left."""
    m = _m(out)
    for name in fixed:
        m["files"][name] = hashlib.sha256((out / name).read_bytes()).hexdigest()
    (out / "manifest.json").write_text(json.dumps(m, indent=2), encoding="utf-8")
    h = hashlib.sha256((out / "manifest.json").read_bytes()).hexdigest()
    (out / "manifest.sha256").write_bytes(f"{h}  manifest.json\n".encode("ascii"))


def _sentence_lines(text):
    out, fence = [], False
    for line in text.split("\n"):
        if line.startswith("```"):
            fence = not fence
            continue
        if fence or not line.strip() or line.startswith("#"):
            continue
        out.append(line)
    return out


@pytest.fixture
def pack(ledger, tmp_path):
    out = tmp_path / "pack"
    build_pack(ledger, out, agent="agent-a", since="2026-09-01", until="2026-09-30",
               system_id="sys-a", provider="Acme")
    return out


def _bearer(res):
    return next(c for c in res["checks"] if c["check"] == "bearer classes")


def test_every_sentence_is_tagged(pack):
    text = (pack / "README.md").read_text(encoding="utf-8")
    lines = _sentence_lines(text)
    assert lines and all(TAG.fullmatch(l) for l in lines), \
        [l for l in lines if not TAG.fullmatch(l)]
    assert f"{CHAIN} [bytes]" in text
    assert "With a pin, it also shows the rows up to the pinned head are the ones " \
           "that existed at pin time. [order]" in text
    assert ("- System id given at build: `sys-a` [asserted; falsifier: none derivable; "
            "compare with the operator's own records]") in text


def test_twin_lists_each_sentence_and_the_counts(pack):
    twin = json.loads((pack / BEARER_FILE).read_text(encoding="utf-8"))
    assert twin["classes"] == list(BEARER_CLASSES)
    ids = [s["id"] for s in twin["sentences"]]
    assert len(ids) == len(set(ids)) == len(_sentence_lines(
        (pack / "README.md").read_text(encoding="utf-8")))
    for s in twin["sentences"]:
        assert s["class"] in BEARER_ALLOWED[s["id"]]
    chain = next(s for s in twin["sentences"] if s["id"] == "intro.chain")
    assert chain["class"] == "bytes"
    assert chain["sha256"] == hashlib.sha256(CHAIN.encode("utf-8")).hexdigest()
    assert twin["counts"] == {"bytes": 6, "order": 2, "asserted": 13}
    assert _m(pack)["files"][BEARER_FILE] == \
        hashlib.sha256((pack / BEARER_FILE).read_bytes()).hexdigest()


def test_no_bytes_sentence_names_a_pin_or_an_operator():
    for sid in ("intro.pin", "intro.no_pin", "window.from", "window.to",
                "agent.system_id", "agent.provider", "dns.operator"):
        assert "bytes" not in BEARER_ALLOWED[sid], sid


def test_verify_counts_the_classes(pack, capsys):
    res = verify_pack(pack)
    assert res["exit"] == 0, res.get("finding")
    assert res["bearer"] == {"bytes": 6, "order": 2, "asserted": 13}
    assert _bearer(res)["verdict"] == V.VERIFIED
    assert main([str(pack), "--json"]) == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["bearer"] == {"bytes": 6, "order": 2, "asserted": 13}


def test_chain_sentence_retagged_order_is_broken_naming_it(pack):
    p = pack / "README.md"
    text = p.read_text(encoding="utf-8")
    p.write_bytes(text.replace(f"{CHAIN} [bytes]", f"{CHAIN} [order]").encode("utf-8"))
    _seal(pack, "README.md")
    res = verify_pack(pack)
    assert res["verdict"] == V.BROKEN and res["exit"] == 1
    b = _bearer(res)
    assert b["verdict"] == V.BROKEN
    assert "sentence intro.chain" in b["finding"]
    assert "tagged [order], README.json says [bytes]" in b["finding"]
    assert "cannot bear" in b["finding"]


def test_twin_and_page_both_retagged_still_broken_by_the_map(pack):
    """The holder moves both the page and its twin: the fixed map in the code
    still names the sentence."""
    p = pack / "README.md"
    p.write_bytes(p.read_text(encoding="utf-8").replace(
        f"{CHAIN} [bytes]", f"{CHAIN} [order]").encode("utf-8"))
    tp = pack / BEARER_FILE
    twin = json.loads(tp.read_text(encoding="utf-8"))
    for s in twin["sentences"]:
        if s["id"] == "intro.chain":
            s["class"] = "order"
    twin["counts"] = {"bytes": 5, "order": 3, "asserted": 13}
    tp.write_text(json.dumps(twin, indent=2) + "\n", encoding="utf-8")
    _seal(pack, "README.md", BEARER_FILE)
    b = _bearer(verify_pack(pack))
    assert b["verdict"] == V.BROKEN
    assert "sentence intro.chain (line 4) is tagged [order], which it cannot bear" \
        in b["finding"]


def test_removed_tag_is_broken_naming_it(pack):
    p = pack / "README.md"
    p.write_bytes(p.read_text(encoding="utf-8").replace(
        f"{CHAIN} [bytes]", CHAIN).encode("utf-8"))
    _seal(pack, "README.md")
    res = verify_pack(pack)
    assert res["verdict"] == V.BROKEN
    assert "sentence intro.chain (line 4) carries no bearer class" in _bearer(res)["finding"]


def test_a_fourth_word_is_broken(pack):
    p = pack / "README.md"
    p.write_bytes(p.read_text(encoding="utf-8").replace(
        f"{CHAIN} [bytes]", f"{CHAIN} [proof]").encode("utf-8"))
    _seal(pack, "README.md")
    f = _bearer(verify_pack(pack))["finding"]
    assert "sentence intro.chain" in f and "[proof], not one of bytes, order, asserted" in f


def test_missing_twin_is_broken(pack):
    (pack / BEARER_FILE).unlink()
    m = _m(pack)
    del m["files"][BEARER_FILE]
    (pack / "manifest.json").write_text(json.dumps(m, indent=2), encoding="utf-8")
    _seal(pack)
    b = _bearer(verify_pack(pack))
    assert b["verdict"] == V.BROKEN and "README.json is missing" in b["finding"]


def test_deal_mandate_readings_sections_are_mapped():
    for sid in ("deal.tapes", "deal.dispute", "deal.files", "mandate.file",
                "mandate.counts", "mandate.rows", "readings.receipt", "readings.verify",
                "readings.caveat", "window.unplaced"):
        assert BEARER_ALLOWED[sid][0] in BEARER_CLASSES


# --- falsifiers: an [asserted] sentence names the check a stranger runs ---

WINDOW_F = ("could_not_look.json, and `arcaeon evidence-pack verify .` re-deriving the "
            "window from records.jsonl")


def _twin(pack):
    return json.loads((pack / BEARER_FILE).read_text(encoding="utf-8"))


def _write_twin(pack, twin):
    (pack / BEARER_FILE).write_text(json.dumps(twin, indent=2) + "\n", encoding="utf-8")


def test_every_asserted_sentence_has_a_falsifier(pack):
    assert {k for k, v in BEARER_ALLOWED.items() if "asserted" in v} == set(BEARER_FALSIFIER)
    assert all(f.strip() and "]" not in f for f in BEARER_FALSIFIER.values())
    text = (pack / "README.md").read_text(encoding="utf-8")
    for s in _twin(pack)["sentences"]:
        if s["class"] == "asserted":
            assert s["falsifier"] == BEARER_FALSIFIER[s["id"]], s["id"]
            assert f"[asserted; falsifier: {s['falsifier']}]" in text
            for fn in falsifier_files(s["falsifier"]):
                assert (pack / fn).is_file(), (s["id"], fn)
        else:
            assert "falsifier" not in s, s["id"]
    assert BEARER_FALSIFIER["window.from"] == BEARER_FALSIFIER["window.to"] == WINDOW_F
    assert falsifier_files(WINDOW_F) == ["could_not_look.json", "records.jsonl"]
    from_line = next(l for l in text.split("\n") if l.startswith("- From: "))
    assert from_line.endswith(f" [asserted; falsifier: {WINDOW_F}]")
    for sid in ("agent.system_id", "agent.provider"):
        assert BEARER_FALSIFIER[sid] == \
            "none derivable; compare with the operator's own records"
        assert falsifier_files(BEARER_FALSIFIER[sid]) == []


def test_twin_with_a_falsifier_removed_is_broken_naming_it(pack):
    twin = _twin(pack)
    for s in twin["sentences"]:
        if s["id"] == "agent.system_id":
            del s["falsifier"]
    _write_twin(pack, twin)
    _seal(pack, BEARER_FILE)
    res = verify_pack(pack)
    assert res["verdict"] == V.BROKEN and res["exit"] == 1
    b = _bearer(res)
    assert b["verdict"] == V.BROKEN
    assert "sentence agent.system_id" in b["finding"]
    assert "is [asserted] with no falsifier in README.json" in b["finding"]


def test_falsifier_naming_a_file_not_in_the_pack_is_broken(pack):
    ghost = "ghost.json, and `arcaeon evidence-pack verify .`"
    twin = _twin(pack)
    for s in twin["sentences"]:
        if s["id"] == "window.from":
            s["falsifier"] = ghost
    _write_twin(pack, twin)
    p = pack / "README.md"
    lines = p.read_text(encoding="utf-8").split("\n")
    lines = [l.replace(WINDOW_F, ghost) if l.startswith("- From: ") else l for l in lines]
    p.write_bytes("\n".join(lines).encode("utf-8"))
    _seal(pack, BEARER_FILE, "README.md")
    b = _bearer(verify_pack(pack))
    assert b["verdict"] == V.BROKEN
    assert "sentence window.from" in b["finding"]
    assert "falsifier naming ghost.json, which is not in the pack" in b["finding"]


def test_falsifier_file_deleted_from_the_pack_is_broken(pack):
    (pack / "could_not_look.json").unlink()
    b = _bearer(verify_pack(pack))
    assert b["verdict"] == V.BROKEN
    for sid in ("intro.scope", "agent.selected", "window.from", "window.to"):
        assert f"sentence {sid} " in b["finding"], sid
    assert "falsifier naming could_not_look.json, which is not in the pack" in b["finding"]


def test_asserted_line_without_its_falsifier_is_broken(pack):
    p = pack / "README.md"
    p.write_bytes(p.read_text(encoding="utf-8").replace(
        "[asserted; falsifier: none derivable; compare with the operator's own records]",
        "[asserted]").encode("utf-8"))
    _seal(pack, "README.md")
    f = _bearer(verify_pack(pack))["finding"]
    assert "sentence agent.provider" in f and "names no falsifier on its line" in f
