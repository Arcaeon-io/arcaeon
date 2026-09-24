"""mcp_vet.badge_cli.seal_badge and `mcp-vet badge --sealed` (board item 84,
2026-09-05) -- the mcp-vet side of the sealed-scan credit debit whose ledger/
witness half lives in `arcaeon_connector.sealed_scan` (tested there, with its
own stubbed ledger and stubbed network).

What THIS file must prove, since it cannot re-prove the connector's own
billing logic: (1) an unsigned badge seals with ARCAEON_KEY alone and is
recorded UNSIGNED, a signed one is recorded SIGNED (seal-for-strangers,
2026-09-24; this used to be "an unsigned badge is never sealed", which meant
no stranger could ever seal); (2) the connector missing is a plain refusal,
never a crash, and the free badge is unaffected; (3) when the connector IS
reachable, `seal_badge` calls it with the receipt's actual payload, not a
reconstruction of it; (4) the CLI wires `--sealed` to a distinct exit code so
a refused paid unit is never confused with a scan failure (exit 1) or a
missing-file error (exit 2).
"""
import sys
from pathlib import Path

import pytest

from arcaeon.prove.vet import badge_cli, receipts
from arcaeon.prove.vet.badge_cli import build_badge, seal_badge

_CLEAN = "def helper(x):\n    return x.upper()\n"

# The connector lives beside this project in the same monorepo checkout. Not
# every environment running mcp-vet's suite will have it (a PyPI install of
# mcp-vet never does) -- tests that need it really importable skip cleanly.
_CONNECTOR_DIR = Path(__file__).resolve().parent.parent / "arcaeon_connector"


def _connector_importable():
    # arcaeon merge: the connector's sealed_scan is arcaeon.remote.sealed_scan, in
    # this package; no sibling checkout to look for.
    if str(_CONNECTOR_DIR) not in sys.path:
        sys.path.insert(0, str(_CONNECTOR_DIR))
    try:
        import arcaeon.remote.sealed_scan  # noqa: F401
    except ImportError:
        return False
    return True


def _write(tmp_path, name, src):
    (tmp_path / name).write_text(src, encoding="utf-8")


def _forget_connector(monkeypatch):
    """Remove any already-imported copy so a later `import arcaeon.mcp`
    is a real re-attempt, not a cache hit from an earlier test in this file."""
    for name in list(sys.modules):
        if name == "arcaeon_connector" or name.startswith("arcaeon_connector."):
            monkeypatch.delitem(sys.modules, name, raising=False)


# --- seal-for-strangers (2026-09-24): the witness's pin is the seal ---------
# The hosted witness's /api/pin takes {namespace, rows, chain} and verifies no
# client signature (arcaeon-witness api/pin.js, lib/_store.js validatePin), so
# an unsigned badge seals with ARCAEON_KEY alone. The network is mocked at
# witness._http_post in every test here: no real call is ever made.

def _no_signing_key(monkeypatch):
    monkeypatch.delenv(receipts.RECEIPT_KEY_ENV, raising=False)
    monkeypatch.setattr(receipts, "RECEIPT_KEY_FILE", None)


def _mock_witness(monkeypatch, tmp_path, response=(201, {"ok": True})):
    from arcaeon.remote import witness
    monkeypatch.setenv("ARCAEON_LEDGER_LOG", str(tmp_path / "agent.log.jsonl"))
    monkeypatch.delenv("ARCAEON_SEALED_SCAN_LOG", raising=False)
    posted = []

    def fake(url, body, key, timeout=20.0):
        posted.append({"url": url, "body": dict(body)})
        return response

    monkeypatch.setattr(witness, "_http_post", fake)
    return posted


def test_unsigned_badge_seals_with_arcaeon_key_alone(monkeypatch, tmp_path):
    _no_signing_key(monkeypatch)
    posted = _mock_witness(monkeypatch, tmp_path)
    monkeypatch.setenv("ARCAEON_KEY", "test-key-not-real")
    _write(tmp_path, "server.py", _CLEAN)
    built = build_badge(str(tmp_path), receipt=True)
    assert built["json"]["receipt"]["signed"] is False

    out = seal_badge(built["json"])

    assert out["sealed"] is True, out
    assert out["signed"] == "UNSIGNED"
    assert len(posted) == 1
    # what the witness receives is the head fingerprint and nothing else
    assert set(posted[0]["body"]) == {"namespace", "rows", "chain"}
    assert posted[0]["url"].endswith("/api/pin")
    import json as _json
    rows = [_json.loads(ln) for ln in
            (tmp_path / "sealed_scans.jsonl").read_text(encoding="utf-8").splitlines()]
    assert rows[-1]["signed"] == "UNSIGNED" and rows[-1]["receipt"] is None


def test_signed_badge_is_recorded_signed_in_addition(monkeypatch, tmp_path, receipt_key):
    if not receipts.RECEIPTS_AVAILABLE:
        pytest.skip("no Ed25519 backend installed (arcaeon[sign])")
    posted = _mock_witness(monkeypatch, tmp_path)
    monkeypatch.setenv("ARCAEON_KEY", "test-key-not-real")
    _write(tmp_path, "server.py", _CLEAN)
    built = build_badge(str(tmp_path), receipt=True)

    out = seal_badge(built["json"])

    assert out["sealed"] is True and out["signed"] == "SIGNED"
    assert len(posted) == 1


def test_no_arcaeon_key_refusal_names_only_the_key(monkeypatch, tmp_path):
    _no_signing_key(monkeypatch)
    posted = _mock_witness(monkeypatch, tmp_path)
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    _write(tmp_path, "server.py", _CLEAN)
    built = build_badge(str(tmp_path), receipt=True)

    out = seal_badge(built["json"])

    assert out["sealed"] is False and posted == []
    assert "no ARCAEON_KEY is set" in out["reason"]
    for other in ("MCP_VET_RECEIPT_KEY", "arcaeon[sign]", "not signed"):
        assert other not in out["reason"], other
    assert not (tmp_path / "sealed_scans.jsonl").exists()


def test_cli_seal_on_base_install_with_only_arcaeon_key_exits_0(monkeypatch, tmp_path, capsys):
    from arcaeon import cli
    _no_signing_key(monkeypatch)
    posted = _mock_witness(monkeypatch, tmp_path)
    monkeypatch.setenv("ARCAEON_KEY", "test-key-not-real")
    _write(tmp_path, "server.py", _CLEAN)

    rc = cli.main(["seal", str(tmp_path / "server.py"), "--ns", "wk-abc-sealed-scans"])

    out = capsys.readouterr().out
    assert rc == 0, out
    assert '"sealed": true' in out and '"signed": "UNSIGNED"' in out
    assert [p["body"]["namespace"] for p in posted] == ["wk-abc-sealed-scans"]


def test_cli_seal_a_foreign_namespace_403_names_ns(monkeypatch, tmp_path, capsys):
    from arcaeon import cli
    _no_signing_key(monkeypatch)
    _mock_witness(monkeypatch, tmp_path, response=(403, {
        "error": 'this key may only pin namespaces starting with "wk-abc-"'}))
    monkeypatch.setenv("ARCAEON_KEY", "test-key-not-real")
    _write(tmp_path, "server.py", _CLEAN)

    rc = cli.main(["seal", str(tmp_path / "server.py")])

    err = capsys.readouterr().err
    assert rc == 3
    assert "--ns" in err and "No credit was spent" in err


def test_cli_seal_ns_without_a_value_is_usage(capsys, tmp_path):
    from arcaeon import cli
    assert cli.main(["seal", str(tmp_path), "--ns"]) == 2


# --- the connector missing is a plain refusal, never a crash ---------------

def test_seal_badge_refuses_cleanly_when_the_connector_cannot_be_imported(monkeypatch, tmp_path, receipt_key):
    if not receipts.RECEIPTS_AVAILABLE:
        pytest.skip("no Ed25519 backend installed (arcaeon[sign])")
    _forget_connector(monkeypatch)
    # Force the import to fail regardless of what is actually on disk: a
    # `None` entry makes `import arcaeon_connector` raise ImportError, the
    # documented Python mechanism for "this name will never resolve".
    monkeypatch.setitem(sys.modules, "arcaeon_connector", None)
    monkeypatch.setitem(sys.modules, "arcaeon.remote.sealed_scan", None)
    _write(tmp_path, "server.py", _CLEAN)
    built = build_badge(str(tmp_path), receipt=True)
    assert built["json"]["receipt"]["signed"] is True

    out = seal_badge(built["json"])

    assert out["sealed"] is False
    assert "not installed" in out["reason"]
    assert "pip install arcaeon" in out["reason"]
    for leak in ("Traceback", 'File "'):
        assert leak not in out["reason"], out["reason"]
    # the badge itself (the free part) is completely unaffected
    assert built["json"]["verdict"] == "no findings in checked classes"


# --- when the connector IS reachable, seal_badge forwards the real receipt -

def test_seal_badge_forwards_the_actual_receipt_payload(monkeypatch, tmp_path, receipt_key):
    if not receipts.RECEIPTS_AVAILABLE:
        pytest.skip("no Ed25519 backend installed (arcaeon[sign])")
    if not _connector_importable():
        pytest.skip("arcaeon_connector not present in this checkout")
    _write(tmp_path, "server.py", _CLEAN)
    built = build_badge(str(tmp_path), receipt=True)

    calls = []

    def fake_seal(record, **kwargs):
        calls.append(record)
        return {"sealed": True, "ledger_head": {"rows": 1, "chain": "deadbeef"},
                "pin": {"ok": True, "status": 201}}

    import arcaeon.remote.sealed_scan as connector_sealed_scan
    monkeypatch.setattr(connector_sealed_scan, "seal", fake_seal)

    out = seal_badge(built["json"])

    assert out["sealed"] is True
    assert len(calls) == 1, calls
    sent = calls[0]
    assert sent["op"] == "mcp_vet_sealed_scan"
    assert sent["target"] == built["json"]["target"]
    assert sent["verdict"] == built["json"]["verdict"]
    assert sent["receipt"] == built["json"]["receipt"]["receipt"], (
        "the connector must receive the SAME receipt object the badge shows, "
        "not a re-derivation of it")


def test_seal_badge_zero_balance_refusal_passes_through_unedited(monkeypatch, tmp_path, receipt_key):
    if not receipts.RECEIPTS_AVAILABLE:
        pytest.skip("no Ed25519 backend installed (arcaeon[sign])")
    if not _connector_importable():
        pytest.skip("arcaeon_connector not present in this checkout")
    _write(tmp_path, "server.py", _CLEAN)
    built = build_badge(str(tmp_path), receipt=True)

    import arcaeon.remote.sealed_scan as connector_sealed_scan
    monkeypatch.setattr(connector_sealed_scan, "seal", lambda record, **kw: {
        "sealed": False,
        "reason": "sealed scan refused: credit balance is zero.",
        "ledger_head": {"rows": 4, "chain": "abc123"},
    })

    out = seal_badge(built["json"])
    assert out["sealed"] is False
    assert "credit balance is zero" in out["reason"]


# --- CLI wiring: --sealed gets its own exit code ----------------------------

def test_cli_sealed_flag_exit_code_when_refused(monkeypatch, tmp_path, capsys):
    """No real key anywhere in this process's environment, so --sealed must
    refuse (whether via the connector's own no-key gate or an ImportError) --
    either way exit code 4, distinct from 0/1/2/3, and the badge still
    printed."""
    from arcaeon.prove.vet.__main__ import main
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    _write(tmp_path, "server.py", _CLEAN)

    code = main(["badge", str(tmp_path), "--sealed"])

    out = capsys.readouterr()
    assert code == 4
    assert "![mcp-vet scan report]" in out.out, "the free badge must still print"
    assert '"sealed": false' in out.out


def test_cli_sealed_flag_implies_receipt(tmp_path, capsys, receipt_key):
    """--sealed without --receipt must still produce a signed badge to seal
    -- the CLI help says --sealed implies --receipt; prove it against the
    CLI's own stdout rather than trust the docstring or a separately built
    badge."""
    if not receipts.RECEIPTS_AVAILABLE:
        pytest.skip("no Ed25519 backend installed (arcaeon[sign])")
    import json
    from arcaeon.prove.vet.__main__ import main
    _write(tmp_path, "server.py", _CLEAN)

    main(["badge", str(tmp_path), "--sealed"])

    out = capsys.readouterr().out
    tail = out.split("\n\n", 1)[1]
    payload = json.loads(tail)
    assert payload["receipt"]["signed"] is True


def test_cli_seal_without_ns_follows_the_keys_prefix(monkeypatch, tmp_path, capsys):
    """ns-from-key: a stranger's key needs no --ns. The witness's 403 names the
    prefix; the seal retries once under <prefix>-sealed-scans and exits 0."""
    from arcaeon import cli
    from arcaeon.remote import witness
    _no_signing_key(monkeypatch)
    _mock_witness(monkeypatch, tmp_path)
    posted = []

    def fake(url, body, key, timeout=20.0):
        posted.append(body["namespace"])
        if body["namespace"].startswith("wk-abc-"):
            return 201, {"ok": True}
        return 403, {"error": 'this key may only pin namespaces starting with "wk-abc-"'}

    monkeypatch.setattr(witness, "_http_post", fake)
    monkeypatch.setenv("ARCAEON_KEY", "test-key-not-real")
    _write(tmp_path, "server.py", _CLEAN)

    rc = cli.main(["seal", str(tmp_path / "server.py")])

    out = capsys.readouterr().out
    assert rc == 0, out
    assert posted == ["mcp-vet-sealed-scans", "wk-abc-sealed-scans"]
    assert '"namespace": "wk-abc-sealed-scans"' in out
