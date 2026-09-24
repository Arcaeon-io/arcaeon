"""The whole product, in order, on one sample. Runs on every commit; no network.

    1. RECORD   three tool calls cross the adapter's seam observer: each lands as
                one chained row in the seam ledger, and each side (agent, tool)
                keeps its own tape of the same calls.
    2. VERIFY   the seam ledger verifies: VERIFIED, exit 0.
    3. PIN      the ledger head and both tape heads are pinned with a LOCAL
                witness store (a fake of the hosted witness: same record shape,
                a file on disk); the ledger checks out against its pin.
    4. PROVE    reconcile the agent tape against the tool tape:
                  MATCHED            the honest pair
                  ALTERED            one tool-side row's response digest changed
                                     (the forger re-chains, so the tape still
                                     verifies on its own)
                  MISSING            the tool tape lost its last row
                  COULD NOT LOOK     an unreadable tape (a directory): exit 3 (2 under
                                     --legacy-exit, 0.9.x only)
                  ALTERED vs the pin a tape rewritten after it was pinned
    5. RECEIPT  a receipt is issued for one tool_call row of the ledger and
                checked with the keyless verifier (recompute the body digest,
                find the row in the receipt ledger; no key, no network); a
                tampered copy fails.
    6. AUDIT    the regulator bundle is built from the SAME seam ledger, with the
                local witness, and says PASS with truncation checked.

Every step asserts. Nothing here is skipped: every link wires without network
or a private piece. The hosted witness itself (Node on Vercel) is out of scope
by design; arcaeon.remote's calls to it are covered with a stubbed seam in
tests/test_cli.py.
"""
import json
import shutil

import pytest

import _arcaeon_chain as C
from arcaeon import cli
from arcaeon import verdict as V
from arcaeon.prove import audit
from arcaeon.prove import reconcile as R
from arcaeon.record.ledger import Ledger, chain_at, verify_file
from arcaeon.record.ledger.tape_pin import pin_tape
from arcaeon.record.ledger.witness import WitnessStore, publish_head, verify_against_witness
from arcaeon.record.receipt.core import build_receipt, load_receipt, save_receipt, verify_receipt


@pytest.fixture()
def world(tmp_path, monkeypatch):
    # no hosted witness, no OTS: every pin in this file is local
    for var in ("ARCAEON_WITNESS_URL", "ARCAEON_WITNESS_KEY", "ARCAEON_KEY"):
        monkeypatch.delenv(var, raising=False)
    paths = C.record_session(tmp_path / "session", texts=("alpha", "bravo", "charlie"))
    return tmp_path, paths


def test_the_whole_chain(world, capsys):
    tmp, p = world

    # 1. RECORD: one chained row per tool call went through the adapter
    seam = C.rows(p["seam"])
    calls = [r for r in seam if r.get("evt") == "tool_call"]
    assert [c["tool"] for c in calls] == ["echo", "echo", "echo"]
    assert all(c["status"] == "ok" for c in calls)
    assert all(c["args_digest"].startswith("sha256:json-c14n:v1:") for c in calls)
    assert len(C.rows(p["agent_tape"])) == len(C.rows(p["tool_tape"])) == 3

    # 2. VERIFY
    vr = verify_file(p["seam"])
    assert vr.ok is True and vr.rows == len(seam) and vr.verified_scope == "full"
    assert cli.main(["verify", str(p["seam"])]) == V.EXIT_GOOD

    # 3. PIN, against a local fake witness store
    store = WitnessStore(tmp / "witness.jsonl")
    pin = publish_head(store, "demo-seam", Ledger(p["seam"]))
    assert pin["rows"] == len(seam) and pin["chain"] == seam[-1]["chain"]
    wv = verify_against_witness(store, "demo-seam", Ledger(p["seam"]))
    assert wv.verdict == "consistent" and bool(wv)
    agent_pin = pin_tape(p["agent_tape"], store, namespace="demo")
    assert agent_pin["rows"] == 3 and agent_pin["side"] == "agent"

    # 4. PROVE: MATCHED
    r = R.reconcile(p["agent_tape"], p["tool_tape"])
    assert r.verdict == R.MATCHED and r.exit_code == V.EXIT_GOOD, r.to_dict()

    # ... ALTERED: one tool-side response digest changed, tape re-chained so it
    # still verifies on its own
    tool_rows = C.rows(p["tool_tape"])
    altered = tmp / "tool.altered.jsonl"
    forged = [dict(x) for x in tool_rows]
    forged[1]["resp"] = "sha256:json-c14n:v1:" + "0" * 64
    C.write_rechained(altered, forged)
    assert verify_file(altered).ok is True, "the forgery must verify alone, or this proves nothing"
    r = R.reconcile(p["agent_tape"], altered)
    assert r.verdict == R.ALTERED and r.exit_code == V.EXIT_BAD, r.to_dict()
    assert cli.main(["reconcile", str(p["agent_tape"]), str(altered)]) == V.EXIT_BAD

    # ... MISSING: the tool tape lost its last call
    short = tmp / "tool.short.jsonl"
    C.write_rechained(short, [dict(x) for x in tool_rows[:-1]])
    r = R.reconcile(p["agent_tape"], short)
    assert r.verdict == R.MISSING and r.exit_code == V.EXIT_BAD, r.to_dict()

    # ... COULD NOT LOOK: an unreadable tape (the path is a directory, so there
    # is no tape to read at all)
    unreadable = tmp / "tool.tape.is.a.directory"
    unreadable.mkdir()
    r = R.reconcile(p["agent_tape"], unreadable)
    assert r.verdict == R.COULD_NOT_LOOK and r.exit_code == V.EXIT_COULD_NOT_LOOK, r.to_dict()
    assert cli.main(["reconcile", str(p["agent_tape"]), str(unreadable)]) == 3
    assert cli.main(["reconcile", str(p["agent_tape"]), str(unreadable), "--legacy-exit"]) == 2
    # (a tape whose bytes are garbage is NOT could-not-look: it was readable and
    # does not verify, so reconcile says ALTERED, by design)
    garbage = tmp / "tool.garbage.jsonl"
    garbage.write_bytes(b"\x00\x01 this is not a tape \xff\n")
    assert R.reconcile(p["agent_tape"], garbage).verdict == R.ALTERED

    # ... ALTERED against the pin: the agent tape rewritten AFTER it was pinned,
    # in agreement with a rewritten tool tape, so the pair alone still matches
    rewritten_agent = tmp / "agent.rewritten.jsonl"
    rewritten_tool = tmp / "tool.rewritten.jsonl"
    a_rows = [dict(x) for x in C.rows(p["agent_tape"])]
    t_rows = [dict(x) for x in tool_rows]
    for rs in (a_rows, t_rows):
        rs[0]["resp"] = "sha256:json-c14n:v1:" + "1" * 64
    C.write_rechained(rewritten_agent, a_rows)
    C.write_rechained(rewritten_tool, t_rows)
    assert R.reconcile(rewritten_agent, rewritten_tool).verdict == R.MATCHED
    pin_file = tmp / "agent.pin.json"
    pin_file.write_text(json.dumps(agent_pin), encoding="utf-8")
    r = R.reconcile(rewritten_agent, rewritten_tool, pin_path=pin_file)
    assert r.verdict == R.ALTERED, r.to_dict()

    # 5. RECEIPT for one ledger row, verified keyless
    n = next(i for i, x in enumerate(seam, start=1) if x.get("evt") == "tool_call")
    row = seam[n - 1]
    assert chain_at(p["seam"], n) == row["chain"]
    receipts = tmp / "receipts.jsonl"
    rec = build_receipt(
        "ledger-row",
        {"ledger": p["seam"].name, "row": n, "row_chain": row["chain"],
         "tool": row["tool"], "args_digest": row["args_digest"]},
        [{"name": "row_in_ledger", "result": "found",
          "chain_at_row": chain_at(p["seam"], n)}],
        {"proves": ["This ledger row, with this chain value, was at this position when issued."],
         "does_not_prove": ["That the tool's answer was correct."]},
        ledger_path=receipts, namespace="demo-receipts", witness=True, anchor=False,
        issued_at="2026-09-23T00:00:00Z")
    assert rec["witness"]["kind"] == "local-file", "no network: the receipt pin must be local"
    saved = save_receipt(rec, tmp / "receipt.json")
    res = verify_receipt(load_receipt(saved), ledger_path=receipts,
                         source_text=saved.read_text(encoding="utf-8"))
    assert res["ok"] is True and res["body_digest_ok"] is True, res
    assert res["ledger"]["status"] == "consistent", res["ledger"]
    assert cli.main(["receipt", "verify", str(saved), "--ledger", str(receipts)]) == V.EXIT_GOOD
    tampered = dict(rec, subject=dict(rec["subject"], row=n + 1))
    bad = save_receipt(tampered, tmp / "receipt.tampered.json")
    assert verify_receipt(load_receipt(bad), ledger_path=receipts)["ok"] is False
    assert cli.main(["receipt", "verify", str(bad), "--ledger", str(receipts)]) == V.EXIT_BAD

    # 6. AUDIT bundle from the same seam ledger, witness-checked
    out = audit.export_bundle(p["seam"], tmp / "bundle", system_id="chain-test",
                              witness=str(tmp / "witness.jsonl"),
                              witness_namespace="demo-seam")
    integ = json.loads((out / "integrity.json").read_text(encoding="utf-8"))
    assert integ["finding"] == "PASS" and integ["verdict"] == V.VERIFIED, integ
    assert integ["chain_ok"] is True and integ["truncation_checked"] is True
    for name in ("records.jsonl", "integrity.json", "manifest.json", "ARTICLE_12_SUMMARY.md"):
        assert (out / name).exists(), name
    assert cli.main(["audit", "verify", str(p["seam"])]) == V.EXIT_GOOD

    # ... and the same bundle catches truncation after the pin
    cut = tmp / "seam.truncated.jsonl"
    shutil.copyfile(p["seam"], cut)
    lines = cut.read_text(encoding="utf-8").splitlines(keepends=True)
    cut.write_text("".join(lines[:-2]), encoding="utf-8")
    out2 = audit.export_bundle(cut, tmp / "bundle2", system_id="chain-test",
                               witness=str(tmp / "witness.jsonl"),
                               witness_namespace="demo-seam")
    integ2 = json.loads((out2 / "integrity.json").read_text(encoding="utf-8"))
    assert integ2["finding"] == "TRUNCATION_DETECTED" and integ2["verdict"] == V.BROKEN, integ2
    capsys.readouterr()


def test_one_deal_recorded_pinned_disputed_packed(tmp_path, monkeypatch, capsys):
    """The deal lane in one run, all through `arcaeon`: both sides record one
    deal, each ledger is pinned with `arcaeon pin` to a local witness file, the
    deal is disputed against the pins (MATCHED), packed, and then a seller-side
    rewrite in agreement with the buyer's is caught by the pins alone."""
    for var in ("ARCAEON_WITNESS_URL", "ARCAEON_WITNESS_KEY", "ARCAEON_KEY"):
        monkeypatch.delenv(var, raising=False)
    from arcaeon.record.deal import dispute
    from arcaeon.record.row import digest_json
    b, s, w = tmp_path / "buyer.jsonl", tmp_path / "seller.jsonl", tmp_path / "witness.jsonl"
    D = ["deal"]
    common = ["--deal", "d-e2e"]
    item = ["--seller", "acme", "--item", "pens-12:2:9.50", "--total", "19.00",
            "--currency", "USD", "--ship-to", "1 Main St"]
    assert cli.main(D + ["mandate", str(b), *common, "--merchant", "acme", "--cap", "60.00",
                         "--currency", "USD", "--not-after", "2099-12-31T00:00:00Z"]) == 0
    assert cli.main(D + ["commit", str(b), *common, "--party", "buyer", *item]) == 0
    md = C.rows(b)[-1]["shared"]["mandate_digest"]
    assert C.rows(b)[-1]["inside_mandate"] is True
    assert cli.main(D + ["commit", str(s), *common, "--party", "seller", *item,
                         "--mandate-digest", md]) == 0
    for led, party in ((b, "buyer"), (s, "seller")):
        assert cli.main(D + ["pay", str(led), *common, "--party", party, "--rail", "card",
                             "--reference", "ch_9", "--amount", "19.00", "--currency", "USD"]) == 0
    assert cli.main(D + ["ship", str(s), *common, "--carrier", "ups", "--tracking", "1Z9"]) == 0
    assert verify_file(b).ok is True and verify_file(s).ok is True

    assert cli.main(["pin", str(b), "--ns", "e2e-buyer", "--witness", str(w)]) == V.EXIT_GOOD
    assert cli.main(["pin", str(s), "--ns", "e2e-seller", "--witness", str(w)]) == V.EXIT_GOOD

    dispute_args = D + ["dispute", "d-e2e", "--buyer", str(b), "--seller", str(s),
                        "--pins", str(w), "--buyer-ns", "e2e-buyer", "--seller-ns", "e2e-seller"]
    capsys.readouterr()
    assert cli.main(dispute_args + ["--json"]) == V.EXIT_GOOD
    rep = json.loads(capsys.readouterr().out)
    assert rep["verdict"] == V.MATCHED and rep["matched"] == 2, rep
    assert [c["result"] for c in rep["pins_checked"]] == ["agrees", "agrees"]
    assert all(e["pinned"] for e in rep["timeline"])

    out = tmp_path / "DEAL-d-e2e"
    assert cli.main(D + ["pack", "d-e2e", "--buyer", str(b), "--seller", str(s),
                         "--pins", str(w), "--buyer-ns", "e2e-buyer", "--seller-ns", "e2e-seller",
                         "-o", str(out)]) == V.EXIT_GOOD
    assert (out / "timeline.md").read_text(encoding="utf-8").splitlines()[0] == V.MATCHED
    assert json.loads((out / "verdict.json").read_text(encoding="utf-8"))["verdict"] == V.MATCHED

    # both ledgers rewritten in agreement after the pins: the pair alone matches,
    # the pins do not
    for led in (b, s):
        rs = C.rows(led)
        for x in rs:
            if x.get("kind") == "deal.commit":
                x["shared"]["terms"]["total"] = "9.00"
                x["step_digest"] = digest_json(x["shared"])
        C.write_rechained(led, rs)
    assert dispute("d-e2e", b, s).verdict == V.MATCHED
    assert cli.main(dispute_args) == V.EXIT_BAD
    capsys.readouterr()
