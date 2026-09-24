"""Foundation tests: every adapter builds; the body digest catches an edit;
the planted fake citation is flagged; the approval mismatch is flagged; the
authorship paste is counted. Anchors are OFF here (no network in tests);
core_anchor_shape covers the stamped/unstamped branches structurally."""
import json
import subprocess
import sys
from pathlib import Path

import pytest
from arcaeon.record.ledger import digest_bytes

from arcaeon.record.receipt import build_receipt, verify_receipt, render_exhibit, save_receipt, load_receipt
from arcaeon.record.receipt import cite, call, approval, authorship, ballot
from arcaeon.record.receipt.cli import main as cli_main

# A-022 (2026-09-12): this fixture is scoped ONLY to the four citations BRIEF
# below actually mentions -- it must NOT be the same file the full
# tests/fixtures/brief.txt demo uses (tests/fixtures/courtlistener_planted_full.json),
# because check_citations() builds one check per object the transport
# returns, unconditionally, regardless of whether that citation appears in
# the submitted text; a fixture carrying entries for citations absent from
# BRIEF would silently inflate `total` with phantom "found" checks for
# citations never actually in this document.
FIX = Path(__file__).parent / "fixtures" / "courtlistener_planted.json"
# "100 Cal. 200" was retired here (and from tests/fixtures/brief.txt) because
# it turned out to be a real, unambiguous case (Austin v. Dick), not the fake
# it was planted to demonstrate -- see
# memory/FINDING_courtlistener_silently_drops_unrecognized_citations_2026-09-11.md's
# residual. "88 Zzq. 12" replaces it: citation-shaped, no real reporter, and
# never returned by the fixture transport, so it is caught by reconcile()'s
# not_recognized_by_service flag instead of by a status the service returns.
BRIEF = ("Plaintiff relies on Brown v. Board of Education, 347 U.S. 483 (1954), and on "
         "Roe v. Wade, 410 U.S. 113 (1973). Defendant cites Smith v. Nowhere, 999 F.3d 1234 "
         "(9th Cir. 2021), a case that does not exist, and 12 Fak. 34, and 88 Zzq. 12.")


def test_scope_required(tmp_path):
    with pytest.raises(ValueError):
        build_receipt("x", {}, [], {"proves": ["a"]}, ledger_path=tmp_path / "l.jsonl",
                      namespace="t", witness=False, anchor=False)


def test_body_digest_catches_edit(tmp_path):
    rc = build_receipt("x", {"a": 1}, [{"status": "found"}],
                       {"proves": ["p"], "does_not_prove": ["d"]},
                       ledger_path=tmp_path / "l.jsonl", namespace="t", witness=False, anchor=False)
    assert verify_receipt(rc, ledger_path=tmp_path / "l.jsonl")["ok"]
    rc["checks"][0]["status"] = "not_found"
    res = verify_receipt(rc, ledger_path=tmp_path / "l.jsonl")
    assert not res["ok"] and not res["body_digest_ok"]
    # scope edits break it too: the limit sentence is part of the evidence
    rc2 = build_receipt("x", {"a": 1}, [], {"proves": ["p"], "does_not_prove": ["d"]},
                        ledger_path=tmp_path / "l.jsonl", namespace="t", witness=False, anchor=False)
    rc2["scope"]["does_not_prove"] = []
    assert not verify_receipt(rc2)["body_digest_ok"]


def test_ledger_tamper_detected(tmp_path):
    lp = tmp_path / "l.jsonl"
    rc = build_receipt("x", {}, [], {"proves": ["p"], "does_not_prove": ["d"]},
                       ledger_path=lp, namespace="t", witness=False, anchor=False)
    lines = lp.read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[-1]); row["checks"] = 99
    lines[-1] = json.dumps(row)
    lp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    res = verify_receipt(rc, ledger_path=lp)
    assert res["ledger"]["status"] in ("chain_broken", "row_not_found") and not res["ok"]


def test_local_witness_labels_itself(tmp_path, monkeypatch):
    # A-032: explicitly guarantee "no hosted key configured" rather than
    # relying on the ambient shell not happening to have these set --
    # a dev machine or CI environment carrying ARCAEON_WITNESS_URL/KEY in
    # its profile would otherwise silently flip this test onto the hosted
    # path and this assertion would never have exercised the local-file
    # label at all.
    monkeypatch.delenv("ARCAEON_WITNESS_URL", raising=False)
    monkeypatch.delenv("ARCAEON_WITNESS_KEY", raising=False)
    rc = build_receipt("x", {}, [], {"proves": ["p"], "does_not_prove": ["d"]},
                       ledger_path=tmp_path / "l.jsonl", namespace="t", anchor=False)
    assert rc["witness"]["kind"] == "local-file"
    assert "self-controlled" in rc["witness"]["independence"]


def test_cite_planted_fake_is_flagged(tmp_path):
    rc = cite.citation_receipt(BRIEF, ledger_path=tmp_path / "l.jsonl", document_name="brief.txt",
                               transport=cite.fixture_transport(FIX), anchor=False)
    s = rc["extra"]["summary"]
    assert s["total"] == 5
    assert set(s["flagged"]) == {"999 F.3d 1234", "12 Fak. 34", "88 Zzq. 12"}
    assert s["by_status"] == {"found": 2, "not_found": 1, "invalid_reporter": 1,
                              "not_recognized_by_service": 1}
    ex = cite.exhibit(rc)
    assert "DOES NOT PROVE" in ex and "Shepard" in ex
    assert ex.index("DOES NOT PROVE") < ex.index("RESULTS")
    assert "!! not_found" in ex and "Brown v. Board" in ex
    assert "correct" not in " ".join(rc["scope"]["proves"]).lower()


def test_cite_flags_what_the_service_silently_drops(tmp_path):
    # First live run, 2026-09-11: the real API returned nothing at all for an
    # invented reporter and for a cite broken across a line. Silence must be a flag.
    brief = ("Plaintiff relies on Brown v. Board of Education, 347 U.S. 483 (1954). Defendant "
             "cites Smith v. Nowhere, 999 F.3d\n1234 (9th Cir. 2021), and 12 Fak. 34, and "
             "Doe v. Roe, 55 F. Supp. 2d 100 (D. Mass. 1999).")
    only_brown = [{"citation": "347 U.S. 483", "normalized_citations": ["347 U.S. 483"], "start_index": 41,
                   "end_index": 53, "status": 200, "error_message": "", "clusters": [{"case_name": "Brown", "absolute_url": "/x/"}]}]
    checks = cite.check_citations(brief, transport=lambda t: only_brown)
    statuses = {c["citation"]: c["status"] for c in checks}
    assert statuses["347 U.S. 483"] == "found"
    assert statuses["999 F.3d 1234"] == "not_recognized_by_service"
    assert statuses["12 Fak. 34"] == "not_recognized_by_service"
    assert statuses["55 F. Supp. 2d 100"] == "not_recognized_by_service"
    assert cite.summarize(checks)["flagged"] == ["999 F.3d 1234", "12 Fak. 34", "55 F. Supp. 2d 100"]
    # and a service that DID return them produces no duplicate rows
    full = only_brown + [{"citation": "999 F.3d 1234", "normalized_citations": ["999 F.3d 1234"], "status": 404, "clusters": []},
                         {"citation": "12 Fak. 34", "normalized_citations": [], "status": 400, "clusters": []},
                         {"citation": "55 F. Supp. 2d 100", "normalized_citations": ["55 F. Supp. 2d 100"], "status": 200, "clusters": []}]
    checks2 = cite.check_citations(brief, transport=lambda t: full)
    assert len(checks2) == 4 and not any(c["status"] == "not_recognized_by_service" for c in checks2)


def test_mismatched_reporter_not_conflated_with_correct_citation(tmp_path):
    # A-021: a real case name attached to the wrong reporter (same volume and
    # page as the real citation, different reporter token) must stand on its
    # own -- flagged as unrecognized on its own merits, never silently
    # inheriting the real citation's "found" status/clusters just because the
    # volume, page, and surrounding case name look plausible. The reporter
    # token is part of _shape_key()'s identity, so the two are different
    # keys by construction; this test is the regression guard for that.
    brief = ("The real citation is Brown v. Board of Education, 347 U.S. 483 (1954). "
             "A mismatched cite to the same volume and page in the wrong reporter, "
             "347 F.3d 483, also appears in this filing.")
    real_only = [{"citation": "347 U.S. 483", "normalized_citations": ["347 U.S. 483"],
                 "start_index": brief.index("347 U.S. 483"),
                 "end_index": brief.index("347 U.S. 483") + len("347 U.S. 483"),
                 "status": 200, "error_message": "",
                 "clusters": [{"case_name": "Brown v. Board of Education", "absolute_url": "/x/"}]}]
    checks = cite.check_citations(brief, transport=lambda t: real_only)
    by_cite = {c["citation"]: c for c in checks}
    assert by_cite["347 U.S. 483"]["status"] == "found"
    assert by_cite["347 U.S. 483"]["clusters"][0]["case_name"] == "Brown v. Board of Education"
    assert by_cite["347 F.3d 483"]["status"] == "not_recognized_by_service"
    assert by_cite["347 F.3d 483"]["flagged"] is True
    # the mismatched cite must never borrow the real case's clusters or name
    assert by_cite["347 F.3d 483"]["clusters"] == []
    assert cite.summarize(checks)["flagged"] == ["347 F.3d 483"]


def test_cli_help_names_what_it_does_not_prove(capsys):
    """A-034: every receipt-issuing subcommand's --help text must name what
    it does not prove, matching core.py's scope rule -- pulled from the
    adapter's own SCOPE.does_not_prove (cli.py's `_does_not_prove`), so this
    can't say something different from what the issued receipt itself
    states."""
    for subcmd, scope in (("cite", cite.SCOPE), ("ballot", ballot.SCOPE)):
        with pytest.raises(SystemExit) as ei:
            cli_main([subcmd, "--help"])
        assert ei.value.code == 0
        # argparse line-wraps --help text at terminal width, which can split
        # a long does_not_prove sentence across lines; normalize whitespace
        # before checking substrings so the test isn't at the mercy of
        # wherever argparse happened to wrap.
        out = " ".join(capsys.readouterr().out.split())
        assert "Does NOT prove" in out
        for limit in scope["does_not_prove"]:
            assert " ".join(limit.split()) in out


def test_cite_refuses_oversize(tmp_path):
    with pytest.raises(ValueError):
        cite.check_citations("x" * (cite.MAX_TEXT + 1), transport=lambda t: [])


def test_cite_cli_exit_codes(tmp_path):
    b = tmp_path / "brief.txt"; b.write_text(BRIEF, encoding="utf-8")
    out = tmp_path / "r.json"
    rc = cli_main(["cite", str(b), "--fixture", str(FIX), "--ledger", str(tmp_path / "l.jsonl"),
                   "--out", str(out), "--no-anchor"])
    assert rc == 3 and out.exists()
    assert cli_main(["verify", str(out), "--ledger", str(tmp_path / "l.jsonl")]) == 0
    r = load_receipt(out); r["checks"][2]["status"] = "found"; save_receipt(r, out)
    assert cli_main(["verify", str(out)]) == 2
    assert cli_main(["exhibit", str(out)]) == 0


def test_cite_cli_subprocess_exit_3_on_flagged_receipt(tmp_path):
    # A-010: invoked as a real subprocess (`python -m arcaeon_receipt.cli`),
    # not by calling cli_main() directly -- exercises the actual entry point
    # a pre-filing script or CI step would call, matching the pattern
    # test_ballot.py::test_ballot_cli_subprocess_exit_codes already used for
    # ballot's 0/1 pair. `cite` is the only subcommand that can produce exit
    # 3 (a flagged check), which that ballot test could not cover.
    b = tmp_path / "brief.txt"
    b.write_text(BRIEF, encoding="utf-8")
    out = tmp_path / "r.json"
    ledger = tmp_path / "l.jsonl"

    proc = subprocess.run(
        [sys.executable, "-m", "arcaeon.record.receipt.cli", "cite", str(b),
         "--fixture", str(FIX), "--ledger", str(ledger), "--out", str(out), "--no-anchor"],
        capture_output=True, text=True, timeout=30,
    )
    assert proc.returncode == 3, proc.stderr
    assert out.exists()
    rc = load_receipt(out)
    assert rc["extra"]["summary"]["flagged"]

    # a clean run (no fixture -- 400 in the file, no citations detected at
    # all -- has nothing to flag) exits 0 through the same real subprocess.
    clean = tmp_path / "clean.txt"
    clean.write_text("This document cites nothing at all.", encoding="utf-8")
    clean_out = tmp_path / "clean.receipt.json"
    clean_fix = tmp_path / "empty_fixture.json"
    clean_fix.write_text("[]", encoding="utf-8")
    clean_proc = subprocess.run(
        [sys.executable, "-m", "arcaeon.record.receipt.cli", "cite", str(clean),
         "--fixture", str(clean_fix), "--ledger", str(ledger), "--out", str(clean_out), "--no-anchor"],
        capture_output=True, text=True, timeout=30,
    )
    assert clean_proc.returncode == 0, clean_proc.stderr


def test_call_receipt_digests_only(tmp_path):
    rc = call.call_receipt({"method": "POST", "url": "https://x/api", "headers": {"X-PAYMENT": "sig"},
                            "body": {"q": "secret question"}},
                           {"status": 200, "body": {"a": "secret answer"}},
                           ledger_path=tmp_path / "l.jsonl", seller="acme", elapsed_ms=12, witness=False)
    c = rc["checks"][0]
    assert c["payment_header_digest"] and c["request_digest"].startswith("sha256:")
    assert "secret" not in json.dumps(rc)
    wrapped = call.receipted(lambda req: {"status": 200, "body": "ok"}, ledger_path=tmp_path / "l.jsonl")
    resp, rc2 = wrapped({"method": "GET", "url": "https://x/ping"})
    assert resp["body"] == "ok" and rc2["kind"] == call.KIND and rc2["ledger"]["rows"] == 2


def test_approval_sequence_and_mismatch(tmp_path):
    g = approval.ApprovalGate(tmp_path / "l.jsonl", agent="agent-7")
    act = {"kind": "payment", "amount": "49.00", "to": "vendor"}
    p = g.decide(g.propose(act), principal="daniel", decision="approved", note="ok")
    rc = g.executed(p, act)
    assert rc["checks"][0]["executed_as_approved"] and not rc["checks"][0]["flagged"]
    # ran differently than approved
    p2 = g.decide(g.propose(act), principal="daniel", decision="approved")
    rc2 = g.executed(p2, {"kind": "payment", "amount": "4900.00", "to": "vendor"})
    assert not rc2["checks"][0]["executed_as_approved"] and "MISMATCH" in approval.exhibit(rc2)
    # denied and did not run: as approved
    p3 = g.decide(g.propose(act), principal="daniel", decision="denied")
    assert g.executed(p3, None)["checks"][0]["executed_as_approved"]
    # denied but ran anyway: flagged
    p4 = g.decide(g.propose(act), principal="daniel", decision="denied")
    assert g.executed(p4, act)["checks"][0]["flagged"]
    with pytest.raises(ValueError):
        g.decide(g.propose(act), principal="", decision="approved")
    evts = [json.loads(l)["evt"] for l in (tmp_path / "l.jsonl").read_text().splitlines()]
    assert evts[:4] == ["approval_proposed", "approval_decided", "approval_executed", "receipt"]


def test_phone_call_receipt_roundtrip_and_tamper(tmp_path):
    lp = tmp_path / "l.jsonl"
    rc = call.phone_call_receipt(["caller-opaque-1", "dispatcher-opaque-9"],
                                 "2026-09-17T10:00:00Z", "2026-09-17T10:04:30Z",
                                 digest_bytes(b"the full transcript text"),
                                 ledger_path=lp, witness=False)
    c = rc["checks"][0]
    assert c["duration_seconds"] == 270.0
    assert "the full transcript text" not in json.dumps(rc)
    assert verify_receipt(rc, ledger_path=lp)["ok"]

    for field, bad in (("participants", ["caller-opaque-1"]),
                       ("start_time", "2026-09-17T09:00:00Z"),
                       ("end_time", "2026-09-17T11:00:00Z"),
                       ("duration_seconds", 1.0),
                       ("transcript_hash", "sha256:0" * 8)):
        broken = json.loads(json.dumps(rc))
        broken["checks"][0][field] = bad
        assert not verify_receipt(broken, ledger_path=lp)["body_digest_ok"], field

    # scope tamper breaks it too -- the limit sentence is evidence, not decoration
    broken_scope = json.loads(json.dumps(rc))
    broken_scope["scope"]["does_not_prove"] = []
    assert not verify_receipt(broken_scope, ledger_path=lp)["body_digest_ok"]

    # a raw phone number as a participant id is refused at build time
    with pytest.raises(ValueError):
        call.phone_call_receipt(["555-0182-9931"], "2026-09-17T10:00:00Z", "2026-09-17T10:00:05Z",
                                digest_bytes(b"x"), ledger_path=lp, witness=False)
    with pytest.raises(ValueError):
        call.phone_call_receipt(["caller-1"], "2026-09-17T10:05:00Z", "2026-09-17T10:00:00Z",
                                digest_bytes(b"x"), ledger_path=lp, witness=False)
    assert "identity of the humans" in " ".join(rc["scope"]["does_not_prove"]).lower()
    assert call.phone_exhibit(rc)  # renders without raising


def test_artifact_approval_receipt_roundtrip_and_tamper(tmp_path):
    lp = tmp_path / "l.jsonl"
    rc = approval.artifact_approval_receipt(approval.hash_artifact(b"the final PDF bytes"),
                                            "dana-approver-7",
                                            "I approve this release for production",
                                            ledger_path=lp, witness=False)
    c = rc["checks"][0]
    assert "the final PDF bytes" not in json.dumps(rc)
    assert "I approve this release" not in json.dumps(rc)
    assert c["approval_text_hash"] and c["artifact_hash"]
    assert verify_receipt(rc, ledger_path=lp)["ok"]

    for field, bad in (("artifact_hash", "sha256:" + "1" * 64),
                       ("approver_id", "someone-else"),
                       ("timestamp", "2020-01-01T00:00:00Z"),
                       ("approval_text_hash", "sha256:" + "2" * 64)):
        broken = json.loads(json.dumps(rc))
        broken["checks"][0][field] = bad
        assert not verify_receipt(broken, ledger_path=lp)["body_digest_ok"], field

    # scope tamper on an already-issued receipt just breaks the digest, same
    # as any other body field (build_receipt's non-empty rule only guards mint time)
    broken_scope = json.loads(json.dumps(rc))
    broken_scope["scope"]["proves"] = []
    assert not verify_receipt(broken_scope, ledger_path=lp)["body_digest_ok"]

    for bad_args, kw in (
        (("", "dana", "text"), {}),
        (("art-hash", "", "text"), {}),
        (("art-hash", "dana", ""), {}),
    ):
        with pytest.raises(ValueError):
            approval.artifact_approval_receipt(*bad_args, ledger_path=lp, witness=False)
    assert "authority" in " ".join(rc["scope"]["does_not_prove"]).lower()
    assert approval.artifact_exhibit(rc)  # renders without raising


def test_authorship_counts_and_replay(tmp_path):
    s = authorship.AuthorshipSession(tmp_path / "l.jsonl", author="student-a", document="essay")
    events = []
    for i, word in enumerate(["The ", "quick ", "brown "]):
        events.append({"seq": i + 1, "op": "type", "n": len(word), "ts": f"2026-09-11T08:00:0{i}Z",
                       "span_digest": digest_bytes(word.encode())})
        s.event("type", text=word, ts=f"2026-09-11T08:00:0{i}Z")
    pasted = "fox jumps over the lazy dog"
    events.append({"seq": 4, "op": "paste", "n": len(pasted), "ts": "2026-09-11T08:00:05Z",
                   "span_digest": digest_bytes(pasted.encode())})
    s.event("paste", text=pasted, ts="2026-09-11T08:00:05Z")
    rc = s.close("The quick brown fox jumps over the lazy dog", anchor=False)
    c = rc["checks"][0]
    assert c["typed_chars"] == 16 and c["pasted_chars"] == len(pasted) and c["paste_events"] == 1
    assert c["rolling_hash"] == authorship.replay(events)
    assert "fox" not in json.dumps(rc)   # spans are digested, never stored
    assert c["checkpoints"][-1]["events"] == 4
    assert "human" in " ".join(rc["scope"]["does_not_prove"]).lower()


def test_anchor_shape_without_tool(tmp_path, monkeypatch):
    import arcaeon.record.receipt.core as core
    monkeypatch.setattr(core, "ots_exe", lambda: None)
    rc = build_receipt("x", {}, [], {"proves": ["p"], "does_not_prove": ["d"]},
                       ledger_path=tmp_path / "l.jsonl", namespace="t", witness=False, anchor=True)
    assert rc["anchor"]["status"] == "not_stamped" and rc["anchor"]["stamped_sha256"]
    assert core.ots_verify(rc)["status"] == "no_anchor"


def test_anchor_b64_roundtrips_with_no_project_code(tmp_path, monkeypatch):
    """A-033: the README's claim ("the stamped file is reconstructible from
    the receipt alone") means the base64 in `receipt["anchor"]["ots_b64"]`
    must be a plain, stdlib-decodable blob of exactly the bytes `ots stamp`
    produced -- not something only arcaeon_receipt's own helpers know how
    to unpack. No network/real `ots` binary here (tests don't touch the
    network): `core._run_ots` is faked to write a known, fixed byte string
    as the ".anchor.ots" proof, so this test can assert the round trip
    with a value it controls end to end."""
    import base64
    import subprocess as _subprocess

    import arcaeon.record.receipt.core as core

    fake_proof = b"FAKE-OTS-CALENDAR-PROOF-BYTES-0123456789\x00\xff"

    def _fake_run_ots(args, timeout=180):
        target = Path(args[1])
        target.with_suffix(".anchor.ots").write_bytes(fake_proof)
        return _subprocess.CompletedProcess(args, 0, stdout="", stderr="")

    monkeypatch.setattr(core, "ots_exe", lambda: Path("fake-ots-for-test"))
    monkeypatch.setattr(core, "_run_ots", _fake_run_ots)

    rc = build_receipt("x", {"a": 1}, [{"status": "found"}],
                       {"proves": ["p"], "does_not_prove": ["d"]},
                       ledger_path=tmp_path / "l.jsonl", namespace="t",
                       witness=False, anchor=True)

    assert rc["anchor"]["kind"] == "opentimestamps"
    assert rc["anchor"]["status"] == "pending-calendar"

    # stdlib base64 only -- no arcaeon_receipt helper touched to decode it.
    decoded = base64.b64decode(rc["anchor"]["ots_b64"])
    assert decoded == fake_proof

    # the file a stranger reconstructs to run `ots verify` against this
    # proof is exactly body_digest + a newline, derivable from the
    # receipt's own body_digest field and nothing else.
    assert core._anchor_bytes(rc["body_digest"]) == (rc["body_digest"] + "\n").encode("utf-8")
