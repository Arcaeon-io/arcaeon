"""A hostile did:key cannot hang the verifier (review finding F4, D072).

Base58 decoding is quadratic in the length of the string (a bigint grows one
digit per character), so a megabyte key id in a sidecar or on the command line
used to pin a core for minutes. An Ed25519 did:key is always 56 characters
("did:key:z" + 47 base58 digits); anything else is refused before decoding.

Each hostile case runs in a child process with a hard 5 s bound, so the red run
fails by timeout instead of hanging the suite.
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

from arcaeon import verdict as V
from arcaeon.prove import envelope as E

SRC = str(Path(E.__file__).resolve().parents[2])
HOSTILE = "did:key:z" + "z" * 1_000_000   # ~1 MB; 'z' is the top base58 digit


def _run_bounded(code: str, tmp_path: Path, bound: float = 5.0) -> tuple[dict, float]:
    """Run `code` in a fresh interpreter; it prints one JSON report. Fails the
    test (never hangs it) if the child is still running after `bound` seconds."""
    script = tmp_path / "child.py"
    script.write_text(textwrap.dedent(code), encoding="utf-8")
    env = {**os.environ, "PYTHONPATH": SRC + os.pathsep + os.environ.get("PYTHONPATH", ""),
           "PYTHONDONTWRITEBYTECODE": "1"}
    t0 = time.monotonic()
    try:
        p = subprocess.run([sys.executable, str(script)], capture_output=True, text=True,
                           timeout=bound, env=env, cwd=str(tmp_path))
    except subprocess.TimeoutExpired:
        pytest.fail(f"the verifier was still decoding after {bound} s (hang on a hostile did:key)")
    took = time.monotonic() - t0
    assert p.returncode == 0, p.stderr
    assert "Traceback" not in p.stderr, p.stderr
    return json.loads(p.stdout.strip().splitlines()[-1]), took


def test_every_generated_ed25519_did_key_is_56_chars():
    """The guard length, checked against keys the code itself makes (including
    the extreme public keys), not hard-coded on faith."""
    pytest.importorskip("cryptography", reason="signing needs the [sign] extra")
    from arcaeon.prove.vet import receipts as R
    lengths = {len(R.did_key(R.public_key_from_seed(secrets.token_bytes(32))))
               for _ in range(500)}
    lengths |= {len(R.did_key(b"\x00" * 32)), len(R.did_key(b"\xff" * 32))}
    assert lengths == {E.DID_KEY_ED25519_LEN} == {56}


@pytest.mark.parametrize("did", [
    '"did:key:z" + "1" * 1_000_000',
    '"did:key:z" + "z" * 1_000_000',
    '"did:key:z" + "z" * 46',            # one short
    '"did:key:z" + "z" * 48',            # one long
], ids=["1MB-of-ones", "1MB-of-z", "55-chars", "57-chars"])
def test_wrong_length_did_key_is_refused_fast(did, tmp_path):
    r, _ = _run_bounded(f"""
        import json, time
        from arcaeon.prove import envelope as E
        t0 = time.monotonic()
        try:
            E._pubkey_from_did({did})
            err = None
        except ValueError as e:
            err = str(e)
        print(json.dumps({{"err": err, "took": time.monotonic() - t0}}))
    """, tmp_path)
    assert r["err"] and "not an Ed25519 key" in r["err"], r
    assert r["took"] < 1.0, r


def test_b58decode_itself_is_bounded(tmp_path):
    r, _ = _run_bounded("""
        import json, time
        from arcaeon.prove import envelope as E
        t0 = time.monotonic()
        try:
            E._b58decode("z" * 1_000_000)
            err = None
        except ValueError as e:
            err = str(e)
        print(json.dumps({"err": err, "took": time.monotonic() - t0,
                          "small": E._b58decode("2").hex()}))
    """, tmp_path)
    assert r["err"] and "too long" in r["err"], r
    assert r["took"] < 1.0 and r["small"] == "01", r


def test_hostile_keyid_in_sidecar_is_broken_in_under_a_second(tmp_path):
    """The real attack path: the sidecar's signature keyid is decoded."""
    pytest.importorskip("cryptography", reason="signing needs the [sign] extra")
    f = tmp_path / "grades.csv"
    f.write_bytes(b"name,grade\nunit-a,pass\n")
    payload = b'{"_type":"https://in-toto.io/Statement/v1"}'
    E.envelope_path(f).write_text(json.dumps({"mediaType": E.MEDIA_TYPE, "dsseEnvelope": {
        "payloadType": E.PAYLOAD_TYPE, "payload": base64.b64encode(payload).decode(),
        "signatures": [{"keyid": HOSTILE, "sig": base64.b64encode(b"x" * 64).decode()}]}}),
        encoding="utf-8")
    assert E.envelope_path(f).stat().st_size <= E.MAX_ENVELOPE_BYTES
    r, took = _run_bounded(f"""
        import json, time
        from arcaeon.prove import envelope as E
        t0 = time.monotonic()
        r = E.verify({str(f)!r}, audience="instructor-1", signers=[{"did:key:z6MkX"!r}])
        print(json.dumps({{"verdict": r["verdict"], "sig": r["steps"]["signature"],
                          "findings": r["findings"], "took": time.monotonic() - t0}}))
    """, tmp_path)
    assert r["verdict"] == V.BROKEN and r["sig"] == V.BROKEN, r
    assert any("not an Ed25519 key" in m for m in r["findings"]), r
    assert r["took"] < 1.0, r


def test_hostile_signer_on_the_cli_returns_a_verdict_in_under_a_second(tmp_path):
    """The same 1 MB did passed as --signer: a verdict, no traceback, no hang."""
    pytest.importorskip("cryptography", reason="signing needs the [sign] extra")
    f = tmp_path / "a.txt"
    f.write_text("hello", encoding="utf-8")
    k = tmp_path / "seal.key"
    k.write_text(base64.b64encode(secrets.token_bytes(32)).decode("ascii"), encoding="ascii")
    E.seal(f, key_file=k, label="greeting", audience="r", deal="d-1", purpose="p",
           not_after="1d")
    r, took = _run_bounded(f"""
        import json, time
        from arcaeon.prove import envelope as E
        hostile = "did:key:z" + "1" * 1_000_000
        t0 = time.monotonic()
        r = E.verify({str(f)!r}, audience="r", signers=[hostile])
        print(json.dumps({{"verdict": r["verdict"], "took": time.monotonic() - t0}}))
    """, tmp_path)
    assert r["verdict"] in (V.BROKEN, V.COULD_NOT_LOOK), r
    assert r["took"] < 1.0, r
