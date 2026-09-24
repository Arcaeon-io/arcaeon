# SPDX-License-Identifier: MIT
"""Tests for arcaeon_ledger.bundle — the one-command auditor evidence bundle.

Covers: bundle creation (dir and zip), byte-identical ledger copy, manifest
hash correctness (every listed hash re-verified from disk), strict verify
report inclusion (green and red ledgers), witness inclusion via an injected
fetcher, the no-namespace and offline fallbacks (stated, never silent), the
never-mutate-the-input guarantee, and CLI exit codes.
"""
from __future__ import annotations

import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from arcaeon.record.ledger import Ledger
from arcaeon.record.ledger.bundle import build_bundle, main


def _make_ledger(tmp_path: Path, rows: int = 3) -> Path:
    p = tmp_path / "agent.log.jsonl"
    log = Ledger(p)
    for i in range(rows):
        log.append({"tool": "search", "step": i, "ok": True})
    return p


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


FAKE_PIN = json.dumps({"namespace": "ns-x", "rows": 3, "chain": "ab" * 16,
                       "head_state": "content_advanced"}).encode("utf-8")


def _fake_fetcher(url):
    return 200, FAKE_PIN


def _offline_fetcher(url):
    raise OSError("network unreachable (simulated offline)")


# -- creation -----------------------------------------------------------------

def test_bundle_directory_contains_all_core_files(tmp_path):
    src = _make_ledger(tmp_path)
    res = build_bundle(src, out=tmp_path / "bundle")
    assert not res.is_zip
    names = {p.name for p in res.out_path.iterdir()}
    assert names == {"agent.log.jsonl", "verify_report.json", "README.txt",
                     "MANIFEST.json"}


def test_ledger_copy_is_byte_identical_and_sha_stated(tmp_path):
    src = _make_ledger(tmp_path)
    res = build_bundle(src, out=tmp_path / "bundle")
    copy = res.out_path / "agent.log.jsonl"
    assert copy.read_bytes() == src.read_bytes()
    assert res.ledger_sha256 == _sha256(src)
    assert res.manifest["ledger_sha256"] == _sha256(src)
    # the sha is also stated in the auditor-facing README
    assert _sha256(src) in (res.out_path / "README.txt").read_text(encoding="utf-8")


def test_input_ledger_is_never_mutated(tmp_path):
    src = _make_ledger(tmp_path)
    before = src.read_bytes()
    build_bundle(src, out=tmp_path / "bundle", namespace="ns-x",
                 fetcher=_fake_fetcher)
    assert src.read_bytes() == before


def test_missing_ledger_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        build_bundle(tmp_path / "nope.jsonl", out=tmp_path / "bundle")


def test_refuses_non_empty_out_dir(tmp_path):
    src = _make_ledger(tmp_path)
    out = tmp_path / "bundle"
    out.mkdir()
    (out / "junk.txt").write_text("x")
    with pytest.raises(FileExistsError):
        build_bundle(src, out=out)


# -- manifest -----------------------------------------------------------------

def test_manifest_hashes_match_files_on_disk(tmp_path):
    src = _make_ledger(tmp_path)
    res = build_bundle(src, out=tmp_path / "bundle", namespace="ns-x",
                       fetcher=_fake_fetcher)
    manifest = json.loads((res.out_path / "MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["files"], "manifest lists no files"
    for name, meta in manifest["files"].items():
        p = res.out_path / name
        assert p.is_file(), f"manifest lists {name} but it is not in the bundle"
        assert _sha256(p) == meta["sha256"], f"hash mismatch for {name}"
        assert p.stat().st_size == meta["bytes"]
    # every file in the bundle except the manifest itself is listed
    on_disk = {p.name for p in res.out_path.iterdir()} - {"MANIFEST.json"}
    assert on_disk == set(manifest["files"])
    assert manifest["package_version"]
    assert manifest["generated_at"].endswith("Z")
    assert "arcaeon.record.ledger.bundle" in manifest["generation_command"]


def test_manifest_detects_a_tampered_bundle_file(tmp_path):
    src = _make_ledger(tmp_path)
    res = build_bundle(src, out=tmp_path / "bundle")
    victim = res.out_path / "verify_report.json"
    victim.write_bytes(victim.read_bytes() + b" ")
    manifest = json.loads((res.out_path / "MANIFEST.json").read_text(encoding="utf-8"))
    assert _sha256(victim) != manifest["files"]["verify_report.json"]["sha256"]


# -- verify report ------------------------------------------------------------

def test_verify_report_is_strict_and_complete_green(tmp_path):
    src = _make_ledger(tmp_path)
    res = build_bundle(src, out=tmp_path / "bundle")
    report = json.loads((res.out_path / "verify_report.json").read_text(encoding="utf-8"))
    assert report["mode"] == "strict"
    r = report["result"]
    assert r["ok"] is True
    assert r["rows"] == 3 and r["chained"] == 3 and r["prechain"] == 0
    assert r["breaks"] == 0 and r["verified_scope"] == "full"
    assert report["command"] == "python -m arcaeon.record.ledger.cli verify --strict agent.log.jsonl"
    assert res.verify_ok is True


def test_verify_report_states_red_on_tampered_ledger(tmp_path):
    src = _make_ledger(tmp_path)
    lines = src.read_text(encoding="utf-8").splitlines()
    row = json.loads(lines[1])
    row["step"] = 999  # edit content, keep stale chain
    lines[1] = json.dumps(row)
    src.write_text("\n".join(lines) + "\n", encoding="utf-8")
    res = build_bundle(src, out=tmp_path / "bundle")  # still succeeds: evidence of a break
    report = json.loads((res.out_path / "verify_report.json").read_text(encoding="utf-8"))
    assert report["result"]["ok"] is False
    assert report["result"]["breaks"] >= 1
    assert "BROKEN" in (res.out_path / "README.txt").read_text(encoding="utf-8")


def test_empty_ledger_readme_says_empty_not_partially_verified(tmp_path):
    # 2026-09-06 audit: a zero-row ledger (the shape a total wipe leaves) used to
    # get the generic "some rows could not be verified" line, which reads as a
    # minor partial gap. The README must call it what it is.
    src = tmp_path / "empty.jsonl"
    src.write_bytes(b"")
    res = build_bundle(src, out=tmp_path / "bundle")
    report = json.loads((res.out_path / "verify_report.json").read_text(encoding="utf-8"))
    assert report["result"]["ok"] is None
    assert report["result"]["rows"] == 0
    readme = (res.out_path / "README.txt").read_text(encoding="utf-8")
    assert "VERDICT: EMPTY" in readme
    assert "zero rows" in readme
    assert "some rows could not be verified" not in readme
    assert "VERDICT: VERIFIED" not in readme


# -- witness ------------------------------------------------------------------

def test_witness_response_included_verbatim_with_history_url(tmp_path):
    src = _make_ledger(tmp_path)
    res = build_bundle(src, out=tmp_path / "bundle", namespace="ns x/1",
                       fetcher=_fake_fetcher)
    assert (res.out_path / "witness_latest.json").read_bytes() == FAKE_PIN
    w = res.manifest["witness"]
    assert w["included"] is True and w["http_status"] == 200
    # namespace is URL-encoded in both URLs
    assert w["url"].endswith("?ns=ns%20x%2F1")
    assert w["history_url"] == ("https://github.com/dan8433-user/arcaeon-witness-pins"
                                "/commits/main/pins/ns%20x%2F1")
    assert w["history_url"] in (res.out_path / "README.txt").read_text(encoding="utf-8")


def test_no_namespace_is_a_stated_absence_not_silence(tmp_path):
    src = _make_ledger(tmp_path)
    res = build_bundle(src, out=tmp_path / "bundle")
    assert not (res.out_path / "witness_latest.json").exists()
    w = res.manifest["witness"]
    assert w["included"] is False and w["status"] == "not_requested"
    assert "No witness evidence included" in (res.out_path / "README.txt").read_text(encoding="utf-8")


def test_offline_witness_fetch_is_a_stated_failure_not_silence(tmp_path):
    src = _make_ledger(tmp_path)
    res = build_bundle(src, out=tmp_path / "bundle", namespace="ns-x",
                       fetcher=_offline_fetcher)
    assert not (res.out_path / "witness_latest.json").exists()
    w = res.manifest["witness"]
    assert w["included"] is False
    assert w["status"].startswith("fetch_failed: OSError")
    readme = (res.out_path / "README.txt").read_text(encoding="utf-8")
    assert "No witness evidence included" in readme
    # the public history URL survives the failure so a stranger can still look
    assert w["history_url"] in readme


def test_a_namespace_that_cannot_be_url_quoted_fails_bounded_not_a_crash(tmp_path):
    """2026-09-05 audit finding. A namespace carrying a lone surrogate (legal in
    a Python str; reachable via a POSIX argv decoded with surrogateescape)
    could not be url-quoted, and `urllib.parse.quote` used to run BEFORE the
    try/except in `_witness_section` — so the whole bundle build died with a
    raw UnicodeEncodeError instead of the documented, stated failure every
    other witness-fetch problem produces. A second, independent crash site sat
    right behind it: the README template embeds `namespace` verbatim and used
    to `.encode("utf-8")` it strictly. Both must now report a bounded failure."""
    src = _make_ledger(tmp_path)
    hostile_ns = "\udc80bad"
    res = build_bundle(src, out=tmp_path / "bundle", namespace=hostile_ns,
                       fetcher=_fake_fetcher)  # fetcher must never even be reached
    w = res.manifest["witness"]
    assert w["included"] is False
    assert w["status"].startswith("fetch_failed: UnicodeEncodeError")
    assert w["url"] is None and w["history_url"] is None
    # README.txt round-trips as STRICT utf-8 at all -- that alone is the proof
    # the write survived: an unhandled UnicodeEncodeError never gets this far,
    # and any invalid byte sequence would fail this very read.
    readme = (res.out_path / "README.txt").read_text(encoding="utf-8")
    assert "No witness evidence included" in readme
    # the lone surrogate reaches README.txt a second way, unescaped: the
    # auto-built `generation_command` embeds the raw namespace verbatim
    # ("... --namespace \udc80bad"). encode(..., errors="replace") swaps it
    # for the stdlib's on-encode substitute -- "?", not U+FFFD (that
    # replacement is decode-side only) -- rather than raising; the rest of
    # the token survives intact either way.
    assert "--namespace ?bad" in readme
    assert "\udc80" not in readme


def test_witness_http_error_body_is_still_evidence(tmp_path):
    src = _make_ledger(tmp_path)
    body = b'{"error":"no pin for namespace"}'
    res = build_bundle(src, out=tmp_path / "bundle", namespace="ns-x",
                       fetcher=lambda url: (404, body))
    assert (res.out_path / "witness_latest.json").read_bytes() == body
    assert res.manifest["witness"]["http_status"] == 404


# -- zip output ---------------------------------------------------------------

def test_zip_bundle_round_trips_with_valid_manifest(tmp_path):
    src = _make_ledger(tmp_path)
    out = tmp_path / "evidence.zip"
    res = build_bundle(src, out=out, namespace="ns-x", fetcher=_fake_fetcher)
    assert res.is_zip and out.is_file()
    with zipfile.ZipFile(out) as zf:
        names = set(zf.namelist())
        assert names == {"agent.log.jsonl", "verify_report.json",
                         "witness_latest.json", "README.txt", "MANIFEST.json"}
        assert zf.read("agent.log.jsonl") == src.read_bytes()
        manifest = json.loads(zf.read("MANIFEST.json"))
        for name, meta in manifest["files"].items():
            assert hashlib.sha256(zf.read(name)).hexdigest() == meta["sha256"]


def test_zip_refuses_to_overwrite_existing_file(tmp_path):
    src = _make_ledger(tmp_path)
    out = tmp_path / "evidence.zip"
    out.write_bytes(b"precious")
    with pytest.raises(FileExistsError):
        build_bundle(src, out=out)
    assert out.read_bytes() == b"precious"


# -- README honesty -----------------------------------------------------------

def test_readme_never_claims_compliance(tmp_path):
    src = _make_ledger(tmp_path)
    res = build_bundle(src, out=tmp_path / "bundle")
    readme = (res.out_path / "README.txt").read_text(encoding="utf-8").lower()
    for banned in ("ai act compliant", "article 12 compliant", "audit-ready",
                   "audit ready"):
        assert banned not in readme
    assert "does not prove" in readme
    assert "art. 12(1)" in readme and "art. 19(1)" in readme and "art. 26(6)" in readme


def test_anchor_section_is_a_stated_not_included(tmp_path):
    src = _make_ledger(tmp_path)
    res = build_bundle(src, out=tmp_path / "bundle")
    assert res.manifest["anchor"]["included"] is False
    assert "Not included" in res.manifest["anchor"]["statement"]


# -- CLI ----------------------------------------------------------------------

def test_cli_builds_bundle_and_exits_zero(tmp_path, capsys, monkeypatch):
    src = _make_ledger(tmp_path)
    out = tmp_path / "clibundle"
    rc = main([str(src), "--out", str(out)])
    assert rc == 0
    printed = json.loads(capsys.readouterr().out)
    assert printed["verify_ok"] is True
    assert printed["witness"] == "not_requested"
    assert (out / "MANIFEST.json").is_file()
    # the verbatim CLI invocation is recorded in the manifest
    manifest = json.loads((out / "MANIFEST.json").read_text(encoding="utf-8"))
    assert manifest["generation_command"] == \
        f"python -m arcaeon.record.ledger.bundle {src} --out {out}"


def test_cli_usage_errors_exit_one(tmp_path, capsys):
    assert main([]) == 1
    assert main(["--out"]) == 1
    assert main(["a.jsonl", "--bogus"]) == 1
    assert main([str(tmp_path / "missing.jsonl")]) == 1
    assert main(["-h"]) == 0


# ---------------------------------------------------------------------------
# C5 (pre-invite adversarial audit, 2026-08-23): the auditor-facing README
# resolved an UNDECIDABLE question in the log owner's favour.
#
# Unchained leading rows are the expected shape of an honest adoption AND the
# exact shape of a fabricated prepend. This package's own docstring says the
# verifier "cannot tell real legacy history from a fabricated prepend" -- and
# the bundle's README.txt said those rows are "not evidence of alteration",
# while MANIFEST.json honestly carried verify.ok=false. Machine-readable said
# red; the human-readable verdict, which is the artifact's entire purpose, said
# fine. A critic only had to quote our docstring against our own README.
# ---------------------------------------------------------------------------

def _strip_chain(p: Path, keep_chained_from=None):
    """Remove chain links. keep_chained_from=k leaves rows k.. chained."""
    import re
    rows = p.read_text(encoding="utf-8").strip().split("\n")
    out = []
    for i, r in enumerate(rows):
        if keep_chained_from is not None and i >= keep_chained_from:
            out.append(r)
        else:
            out.append(re.sub(r',\s*"chain":\s*"[0-9a-f]+"\s*\}$', "}", r))
    p.write_text("\n".join(out) + "\n", encoding="utf-8")


def _adopted_log(tmp_path, prechain=3, chained=4):
    """A log shaped like a REAL adoption, built the way the README documents it:
    pre-existing legacy rows that carry no chain, then chaining begins.

    (First draft of this helper stripped chains from an already-chained log,
    which leaves the surviving rows pointing at a predecessor that no longer
    has a chain — that is a BROKEN log, not an adopted one, and lenient verify
    correctly returned ok=False. The test failing on it was the test working.)"""
    p = tmp_path / "adopted.jsonl"
    legacy = [json.dumps({"e": f"legacy{i}"}) for i in range(prechain)]
    p.write_text("\n".join(legacy) + "\n", encoding="utf-8")
    lg = Ledger(p)
    for i in range(chained):
        lg.append({"e": i})
    return p


def test_adoption_verdict_states_the_undecidability_instead_of_denying_it(tmp_path):
    src = _adopted_log(tmp_path)
    res = build_bundle(src, out=tmp_path / "b")
    out = res.out_path
    readme = (out / "README.txt").read_text(encoding="utf-8")

    assert "not evidence of alteration" not in readme, (
        "the bundle must not tell an auditor a fabricated prepend is not "
        "evidence of alteration — our own docstring says it is undecidable"
    )
    assert "fabricated prepend" in readme
    assert "cannot tell those apart" in readme
    # was UNVERIFIED; one word for "did not look" since the 2026-09-23 vocabulary pass
    assert "pre-chain region as COULD NOT LOOK, not as vouched for" in readme


def test_adoption_verdict_quotes_how_much_is_unverifiable(tmp_path):
    """A reader must be able to see the size of the unverifiable region."""
    src = _adopted_log(tmp_path, prechain=3, chained=4)
    res = build_bundle(src, out=tmp_path / "b")
    out = res.out_path
    readme = (out / "README.txt").read_text(encoding="utf-8")
    assert "4 of 7" in readme, readme[:400]
    assert "3 row(s) before the first chained row" in readme


def test_a_fully_unchained_log_is_never_called_adopted(tmp_path):
    """THE FLOOR: with zero chained rows there is no 'first chained row', so the
    bundle must not claim a chain holds. It used to take the adoption branch and
    assert exactly that over a file with no verified links at all."""
    p = tmp_path / "all_prechain.jsonl"
    lg = Ledger(p)
    for i in range(5):
        lg.append({"e": i})
    _strip_chain(p)                      # every link gone

    res = build_bundle(p, out=tmp_path / "b")
    out = res.out_path
    report = json.loads((out / "verify_report.json").read_text(encoding="utf-8"))
    assert report["prechain_adoption"] is False, (
        "a 100% unchained log took the adoption branch"
    )
    readme = (out / "README.txt").read_text(encoding="utf-8")
    assert "BROKEN" in readme
    assert "VERIFIED from adoption onward" not in readme


def test_a_genuinely_intact_log_still_reads_intact(tmp_path):
    """Green control: the honest case must not inherit any of the new hedging."""
    p = tmp_path / "clean.jsonl"
    lg = Ledger(p)
    for i in range(4):
        lg.append({"e": i})
    res = build_bundle(p, out=tmp_path / "b")
    out = res.out_path
    readme = (out / "README.txt").read_text(encoding="utf-8")
    assert "VERDICT: VERIFIED." in readme
    assert "fabricated prepend" not in readme
