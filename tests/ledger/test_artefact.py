# SPDX-License-Identifier: MIT
"""Tests for arcaeon_ledger.artefact — binding a re-fetchable fact to a row.

The load-bearing claims: (1) digests are self-describing and reproducible from the
recipe alone; (2) JSON canonicalization is key-order-independent; (3) verify catches
an internally-inconsistent digest; (4) verify's semantics are HONEST (a non-URL
refetch is 'skipped', never a false 'match'); (5) an artefact chains inside a ledger
row like any field. Run: python test_artefact.py
"""
import hashlib
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from arcaeon.record.ledger import (Ledger, bind_artefact, verify_artefact,
                            digest_bytes, digest_json)


def test_self_describing_digest_shape():
    d = digest_bytes(b"hello world")
    algo, recipe, ver, hexd = d.split(":")
    assert algo == "sha256" and recipe == "raw-bytes" and ver == "v1"
    assert hexd == hashlib.sha256(b"hello world").hexdigest()
    print("PASS self-describing digest carries algo:recipe:ver:hex, reproducible")


def test_json_canon_is_key_order_independent():
    a = digest_json({"b": 2, "a": 1, "nested": {"y": 1, "x": 2}})
    b = digest_json({"a": 1, "nested": {"x": 2, "y": 1}, "b": 2})
    assert a == b, "reordered keys must produce the same json-c14n digest"
    # and it is reproducible from the DOCUMENTED recipe alone
    canon = json.dumps({"a": 1, "b": 2}, sort_keys=True, separators=(",", ":"),
                       ensure_ascii=False, allow_nan=False).encode("utf-8")
    assert digest_json({"b": 2, "a": 1}) == f"sha256:json-c14n:v1:{hashlib.sha256(canon).hexdigest()}"
    print("PASS json-c14n is key-order-independent and reproducible from the recipe")


def test_bind_bytes_and_verify():
    art = bind_artefact(b"the agent read this")
    assert art["subject"]["digest"]["sha256"] == hashlib.sha256(b"the agent read this").hexdigest()
    assert art["recipe"] == "sha256:raw-bytes:v1"
    res = verify_artefact(art)
    assert res["digest_ok"] and res["refetch"] == "skipped", res
    print("PASS bind(bytes) -> verify digest_ok, refetch skipped (offline honest)")


def test_bind_file():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "tool_stdout.txt"
        p.write_bytes(b"exit 0\nrows: 42\n")
        art = bind_artefact(p)
        assert art["source_meta"]["kind"] == "file"
        assert art["subject"]["name"] == "tool_stdout.txt"
        assert verify_artefact(art)["digest_ok"]
    print("PASS bind(file path) hashes file bytes, verifies")


def test_tampered_digest_is_caught():
    art = bind_artefact({"claim": "price is $49"})
    # tamper: change the subject hex so it no longer matches the digest string
    art["subject"]["digest"]["sha256"] = "0" * 64
    res = verify_artefact(art)
    assert not res["digest_ok"], "inconsistent subject/digest must fail verify"
    assert any("does not match" in n for n in res["notes"]), res
    print("PASS verify catches an internally-inconsistent (tampered) digest")


def test_unknown_recipe_fails_honestly():
    art = bind_artefact(b"x")
    art["digest"] = art["digest"].replace("raw-bytes", "made-up-recipe")
    res = verify_artefact(art)
    assert not res["digest_ok"]
    assert res["reason"] == "unknown_recipe", res
    assert any("unknown recipe" in n for n in res["notes"]), res
    print("PASS unknown recipe fails with a typed reason, not a silent pass")


def test_unsupported_labels_are_typed_failures():
    """0.5.2: anything this build cannot REPRODUCE is a hard typed failure. A
    digest we can't recompute is a digest we didn't check."""
    good = bind_artefact({"claim": "price is $49"})
    assert verify_artefact(good)["digest_ok"] and verify_artefact(good)["reason"] is None

    def planted(**swap):
        a = json.loads(json.dumps(good))
        a["digest"] = a["digest"].replace(swap["old"], swap["new"], 1)
        a["recipe"] = a["recipe"].replace(swap["old"], swap["new"], 1)
        return a

    cases = [
        (planted(old="json-c14n", new="json-c14n-drift"), "unknown_recipe"),
        (planted(old=":v1", new=":v9"), "unknown_recipe_version"),
        (planted(old="sha256", new="md5"), "unknown_algorithm"),
        ({**json.loads(json.dumps(good)), "digest": good["digest"][:-20]},
         "malformed_digest"),
    ]
    for art, want in cases:
        res = verify_artefact(art)
        assert res["digest_ok"] is False, (want, res)
        assert res["reason"] == want, (want, res)
    # and a failed digest never reaches refetch — no false 'match' on an
    # unverifiable recipe
    assert verify_artefact(cases[1][0], refetch=True)["refetch"] == "skipped"
    print("PASS unsupported algo/recipe/version/hex -> typed failure, never a pass")


def test_supported_recipes_still_verify():
    """Backward compat: the two shipped recipes verify exactly as before."""
    for art in (bind_artefact(b"raw bytes here"), bind_artefact({"a": 1, "b": [2, 3]})):
        res = verify_artefact(art)
        assert res["digest_ok"] is True and res["reason"] is None, res
        assert res["recipe"] in ("sha256:raw-bytes:v1", "sha256:json-c14n:v1"), res
    print("PASS sha256:raw-bytes:v1 and sha256:json-c14n:v1 unchanged (compat)")


def test_refetch_on_non_url_is_skipped_not_matched():
    # the honesty guard: a non-URL artefact must never report a false 'match'
    art = bind_artefact(b"local bytes")
    res = verify_artefact(art, refetch=True)
    assert res["refetch"] == "skipped", res
    assert any("not a URL" in n for n in res["notes"]), res
    print("PASS refetch on non-URL is 'skipped', never a false 'match'")


def test_deeply_nested_value_fails_digest_json_as_valueerror_not_recursionerror():
    """2026-09-05 audit finding. `__init__.py`'s `_loads` already retypes a
    JSON decoder RecursionError (a ~100k-deep nested line overflows the C
    decoder's stack) into ValueError on the READ side, because every
    `except ValueError` elsewhere in the package would otherwise walk right
    past it. `_canon_json`/`digest_json` take the same shape of input --
    "any JSON-serializable value," explicitly including tool output an agent
    read -- on the ENCODE side, and never got the matching fix. A caller
    passing a pathologically nested value must get a typed failure, not an
    unhandled RecursionError out of a function whose whole contract is a
    bounded digest."""
    deep = []
    cur = deep
    for _ in range(100_000):
        cur.append([])
        cur = cur[0]
    with pytest.raises(ValueError, match="nests too deeply"):
        digest_json(deep)
    print("PASS a pathologically nested value fails digest_json as ValueError, not RecursionError")


class _FakeHTTPResponse:
    """Minimal stand-in for what urlopen() returns, enough for bind_artefact."""
    def __init__(self, body: bytes, url: str, status: int = 200):
        self._body = body
        self._url = url
        self.status = status
        self.headers = {"Content-Type": "application/json"}

    def read(self, n=-1):
        return self._body

    def getcode(self):
        return self.status

    def geturl(self):
        return self._url

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_credentialed_url_userinfo_is_never_stored_in_the_artefact():
    """2026-09-05 audit finding. `bind_artefact` stored a fetched URL VERBATIM
    in `subject.name` and `source_meta.final_url` -- both fields designed to be
    copied byte-for-byte into a ledger row and, from there, into
    `build_bundle`'s shareable evidence bundle. A `user:pass@host` URL is a
    live credential; it must not ride along into either place. The fetch
    itself must still use the real, credentialed URL (asserted below via the
    mock's call args) -- only the STORED copy is scrubbed."""
    credentialed = "https://alice:s3cr3t@example.com/artefact.json"
    fake = _FakeHTTPResponse(b'{"ok": true}', url=credentialed)
    with patch("urllib.request.urlopen", return_value=fake) as mock_urlopen:
        art = bind_artefact(credentialed)
    # the FETCH used the real, credentialed URL
    requested = mock_urlopen.call_args[0][0]
    assert requested.full_url == credentialed
    # but nothing STORED carries the credential
    assert "s3cr3t" not in art["subject"]["name"]
    assert "s3cr3t" not in art["source_meta"]["final_url"]
    assert art["subject"]["name"] == "https://example.com/artefact.json"
    assert art["source_meta"]["final_url"] == "https://example.com/artefact.json"
    print("PASS a URL's userinfo credential is fetched with, never stored")


def test_artefact_chains_inside_a_ledger_row():
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "log.jsonl"
        log = Ledger(p)
        art = bind_artefact({"observed": "status 200", "body_len": 1234})
        log.append({"tool": "web.read", "artefact": art})
        assert log.verify().ok, "row with artefact must chain cleanly"
        # tamper the artefact's digest inside the file -> chain must break
        lines = p.read_text(encoding="utf-8").splitlines()
        obj = json.loads(lines[0])
        obj["artefact"]["digest"] = obj["artefact"]["digest"][:-4] + "dead"
        p.write_text(json.dumps(obj) + "\n", encoding="utf-8")
        assert not log.verify().ok, "editing the bound artefact must break the chain"
    print("PASS artefact chains inside a ledger row and is tamper-protected by it")


if __name__ == "__main__":
    test_self_describing_digest_shape()
    test_json_canon_is_key_order_independent()
    test_bind_bytes_and_verify()
    test_bind_file()
    test_tampered_digest_is_caught()
    test_unknown_recipe_fails_honestly()
    test_unsupported_labels_are_typed_failures()
    test_supported_recipes_still_verify()
    test_refetch_on_non_url_is_skipped_not_matched()
    test_artefact_chains_inside_a_ledger_row()
    print("\nALL PASS — artefact-binding: self-describing reproducible digests, "
          "key-order-independent canon, tamper caught, honest refetch semantics, "
          "chains inside the ledger.")
