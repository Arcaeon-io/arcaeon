"""Python leg for web/verify-any.html, the universal checker.

The conformance set itself runs in Node (tests/test_universal_checker.mjs),
because the code under test is browser JavaScript. This file:

  * runs that suite and requires it green (skipped with a reason if `node`
    is not on PATH, like the JS leg of test_verify_page_parity.py);
  * runs the break arm the brief names (a detector that always says our own
    format) and requires it RED;
  * pins web/universal/c14n_pinned.js to the C14N block of
    web/verify-receipt.html, so the canonicalizer has one source, and
    web/universal/crosscheck_pinned.js to its CROSSCHECK block, so the witness
    and attestation-signature checks have one source too;
  * re-verifies the Arcaeon fixtures with the Python verify_receipt, so the
    page's canonicalizer is not the only witness to its own fixture;
  * checks the published fixture set is whole, and the page text carries no
    em or en dashes.
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from arcaeon.record.receipt import verify_receipt

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "tests" / "fixtures" / "universal"
MJS = ROOT / "tests" / "test_universal_checker.mjs"
sys.path.insert(0, str(ROOT / "tools"))
import extract_c14n  # noqa: E402

NODE = shutil.which("node")
needs_node = pytest.mark.skipif(NODE is None, reason="node is not on PATH; the JS conformance leg cannot run")


def _run(*args):
    return subprocess.run([NODE, str(MJS), *args], capture_output=True, text=True, timeout=300)


def test_pinned_c14n_is_the_verify_receipt_block():
    have = (ROOT / "web" / "universal" / "c14n_pinned.js").read_text(encoding="utf-8").replace("\r\n", "\n")
    assert have == extract_c14n.expected(), (
        "web/universal/c14n_pinned.js has drifted from the C14N block in web/verify-receipt.html; "
        "run `py tools/extract_c14n.py` and never edit the pinned file by hand")


def test_pinned_crosscheck_is_the_verify_receipt_block():
    have = (ROOT / "web" / "universal" / "crosscheck_pinned.js").read_text(encoding="utf-8").replace("\r\n", "\n")
    assert have == extract_c14n.expected_crosscheck(), (
        "web/universal/crosscheck_pinned.js has drifted from the CROSSCHECK block in web/verify-receipt.html; "
        "run `py tools/extract_c14n.py` and never edit the pinned file by hand")


def test_verify_any_loads_the_pinned_blocks_and_defines_no_cross_check_of_its_own():
    page = (ROOT / "web" / "verify-any.html").read_text(encoding="utf-8")
    assert page.index('src="universal/c14n_pinned.js"') < page.index('src="universal/crosscheck_pinned.js"')         < page.index('src="universal/fmt_arcaeon.js"')
    for f in (ROOT / "web" / "universal").glob("*.js"):
        if f.name.endswith("_pinned.js"):
            continue
        text = f.read_text(encoding="utf-8")
        for name in ("checkWitness", "checkAttestationSignature", "pyDefaultDumps", "sameValue"):
            assert ("function " + name) not in text, f.name + " defines its own " + name + "; it must come from the pinned block"


@needs_node
def test_node_conformance_suite_is_green():
    proc = _run()
    assert proc.returncode == 0, proc.stdout[-4000:] + proc.stderr[-2000:]
    assert "all ok" in proc.stdout


@needs_node
@pytest.mark.parametrize("arm", ["always-arcaeon", "always-verified", "skip-signature", "claimed-root", "lenient-base64",
                                 "always-consistent"])
def test_break_arm_turns_the_suite_red(arm):
    proc = _run("--red", arm)
    assert proc.returncode == 1, "break arm " + arm + " did NOT turn the suite red:\n" + proc.stdout[-2000:]


def _arc(name):
    text = (FIX / name).read_text(encoding="utf-8")
    return verify_receipt(json.loads(text), source_text=text)


def test_arcaeon_fixture_is_genuine_by_the_python_verifier():
    assert _arc("arc_valid.json")["body_digest_ok"] is True


@pytest.mark.parametrize("name", ["arc_tampered_payload.json", "arc_tampered_seal.json",
                                  "arc_missing_required.json", "arc_duplicate_key.json",
                                  "arc_witness_inconsistent.json", "arc_witness_pin_self_mismatch.json",
                                  "arc_ledger_edited_witnessed.json", "arc_signature_mismatch.json"])
def test_arcaeon_refusals_are_refused_by_the_python_verifier_too(name):
    assert _arc(name)["ok"] is False


def test_unchecked_signature_value_is_could_not_look_in_python_too():
    r = _arc("arc_signature_value_unchecked.json")
    assert r["body_digest_ok"] is True
    assert r["attestation_signature"]["verdict"] == "could_not_look"


def test_manifest_is_whole():
    cases = json.loads((FIX / "manifest.json").read_text(encoding="utf-8"))["cases"]
    ids = [c["id"] for c in cases]
    assert len(ids) == len(set(ids)), "duplicate case ids"
    for c in cases:
        for k in ("file", "publicKeyFile", "preimageFile", "detachedPayloadFile", "receiptKeyFile", "statementFile"):
            if c.get(k):
                assert (FIX / c[k]).exists(), c["id"] + " names a missing file " + c[k]
        assert c["expect"] in ("VERIFIED", "BROKEN", "COULD NOT LOOK")
    refusals = [c for c in cases if c["expect"] != "VERIFIED"]
    assert len(refusals) > len(cases) / 2, "a conformance set that is mostly happy paths proves little"


def test_no_em_or_en_dashes_in_page_text():
    files = [ROOT / "web" / "verify-any.html", FIX / "README.md"] + sorted((ROOT / "web" / "universal").glob("fmt_*.js")) \
        + [ROOT / "web" / "universal" / "detect.js", ROOT / "web" / "universal" / "core.js"]
    for f in files:
        text = f.read_text(encoding="utf-8")
        assert "—" not in text and "–" not in text and "&mdash;" not in text and "&ndash;" not in text, f.name
