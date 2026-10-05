"""TE-31 / L2-12: check.verdict rows carried in the envelope's checks[].

`envelope seal --checks FILE` (library `checks=`) puts connector rows inside
the signed Statement (predicate.checks), so editing a carried row breaks the
signature. Only rows of kind check.verdict.relayed whose subject.sha256 is the
sealed file's sha256 ride; any other row refuses the seal with its reason,
nothing written. `gate decide` reads the carried rows the way it reads
`--checks FILE` rows (same veto, same reason codes), and the two combine.
Throwaway keys in tmp_path, HOME pointed at tmp_path; nothing reaches the
network."""
from __future__ import annotations

import base64
import hashlib
import json
import secrets
from datetime import datetime, timezone
from pathlib import Path

import pytest

from arcaeon import verdict as V
from arcaeon.connector import core
from arcaeon.prove import envelope as E
from arcaeon.prove import gate as G

pytest.importorskip("cryptography", reason="signing needs the [sign] extra")

AUD = "instructor-1"
BIND = {"label": "week 3 grades", "audience": AUD, "deal": "d-7f3a", "purpose": "grading",
        "not_after": "7d"}
BODY = b"name,grade\nunit-a,pass\n"
SHA = hashlib.sha256(BODY).hexdigest()
NOW = datetime(2026, 10, 5, 12, 0, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    for var in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(var, str(tmp_path / "home"))


def _key(tmp_path: Path) -> Path:
    k = tmp_path / "seal.key"
    k.write_text(base64.b64encode(secrets.token_bytes(32)).decode("ascii"), encoding="ascii")
    return k


def _file(tmp_path: Path, name: str = "grades.csv") -> Path:
    f = tmp_path / "in" / name
    f.parent.mkdir(exist_ok=True)
    f.write_bytes(BODY)
    return f


def _row(sha=SHA, verdict=V.BROKEN, *, vendor="mcp-scan", kind=core.ROW_KIND, **over) -> dict:
    row = core.relayed_row(core.adapter_for("mockscan"), b"{}", "2026-10-05T12:00:00Z")
    row.update(kind=kind, vendor={"name": vendor, "adapter_version": "1"},
               vendor_id="req-1", vendor_word="w", relayed_verdict=verdict,
               mapping={"rule": "table"},
               subject={"name": "grades.csv", "sha256": sha} if sha is not None else None)
    row.update(over)
    return row


def _rows_file(tmp_path: Path, rows, name: str = "checks.jsonl") -> Path:
    p = tmp_path / name
    p.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8", newline="\n")
    return p


def _seal(tmp_path, f, *, checks=None, key=True, **kw):
    k = _key(tmp_path) if key else None
    extra = {} if checks is None else {"checks": checks}
    env = E.seal(f, key_file=k, force=True, now=kw.pop("now", None), **BIND, **extra, **kw)
    sigs = env["dsseEnvelope"]["signatures"]
    return env, (sigs[0]["keyid"] if sigs else None)


def _stmt(env: dict) -> dict:
    return json.loads(base64.b64decode(env["dsseEnvelope"]["payload"]))


def _ex(tmp_path) -> dict:
    return {"deal": "d-7f3a", "purpose": "grading", "ledger": tmp_path / "tape.jsonl",
            "record_dir": tmp_path / "rec"}


# --- seal: what rides, and what does not ----------------------------------------------

def test_no_checks_seals_byte_identical_and_has_no_checks_key(tmp_path):
    f = _file(tmp_path)
    k = _key(tmp_path)
    a = E.seal(f, key_file=k, force=True, now=NOW, **BIND)
    first = E.envelope_path(f).read_bytes()
    b = E.seal(f, key_file=k, force=True, now=NOW, checks=(), **BIND)
    assert E.envelope_path(f).read_bytes() == first
    assert a == b
    assert "checks" not in _stmt(a)["predicate"]
    assert "checks" not in E.verify(f, audience=AUD, signers=[a["dsseEnvelope"]["signatures"][0]["keyid"]],
                                    now=NOW)["sealed"]


def test_rows_ride_inside_the_signed_payload(tmp_path):
    f = _file(tmp_path)
    rows = [_row(verdict=V.BROKEN), _row(verdict=V.VERIFIED, vendor="snyk-agent-scan")]
    env, did = _seal(tmp_path, f, checks=[_rows_file(tmp_path, rows)])
    carried = _stmt(env)["predicate"]["checks"]
    assert carried == rows
    r = E.verify(f, audience=AUD, signers=[did])
    assert r["verdict"] == V.VERIFIED
    assert r["sealed"]["checks"] == rows


def test_library_accepts_row_dicts_and_files_together(tmp_path):
    f = _file(tmp_path)
    one, two = _row(verdict=V.COULD_NOT_LOOK), _row(verdict=V.VERIFIED)
    env, _ = _seal(tmp_path, f, checks=[one, _rows_file(tmp_path, [two])])
    assert _stmt(env)["predicate"]["checks"] == [one, two]


def test_sha_prefix_and_case_are_read_like_the_gate(tmp_path):
    f = _file(tmp_path)
    env, _ = _seal(tmp_path, f, checks=[_row(sha="sha256:" + SHA.upper())])
    assert len(_stmt(env)["predicate"]["checks"]) == 1


@pytest.mark.parametrize("bad,why", [
    (lambda: _row(sha="0" * 64), "sha256"),
    (lambda: _row(sha=None), "subject.sha256"),
    (lambda: _row(kind="check.verdict"), "kind"),
    (lambda: _row(relayed_verdict="PASS"), "relayed_verdict"),
    (lambda: _row(relayed=False), "relayed"),
    (lambda: _row(checked_by_us=True), "checked_by_us"),
], ids=["other-sha", "no-subject", "other-kind", "bad-word", "not-relayed", "checked-by-us"])
def test_a_row_that_cannot_ride_refuses_the_seal_with_its_reason(tmp_path, bad, why):
    f = _file(tmp_path)
    c = _rows_file(tmp_path, [_row(), bad()])
    with pytest.raises(E.SealError) as e:
        _seal(tmp_path, f, checks=[c])
    assert why in str(e.value) and "checks.jsonl" in str(e.value) and "line 2" in str(e.value)
    assert not E.envelope_path(f).exists(), "nothing is written on a refusal"


def test_unreadable_or_empty_checks_file_refuses(tmp_path):
    f = _file(tmp_path)
    (tmp_path / "junk.json").write_text("{not json\n", encoding="utf-8")
    (tmp_path / "empty.json").write_text("", encoding="utf-8")
    for name in ("junk.json", "empty.json", "absent.json"):
        with pytest.raises(E.SealError) as e:
            _seal(tmp_path, f, checks=[tmp_path / name])
        assert name in str(e.value)
        assert not E.envelope_path(f).exists()


def test_count_and_size_are_bounded(tmp_path):
    f = _file(tmp_path)
    many = _rows_file(tmp_path, [_row() for _ in range(E.MAX_CARRIED_CHECKS + 1)])
    with pytest.raises(E.SealError, match="at most"):
        _seal(tmp_path, f, checks=[many])
    big = _row(vendor_payload="x" * (E.MAX_CARRIED_CHECK_BYTES + 1))
    with pytest.raises(E.SealError, match="bytes"):
        _seal(tmp_path, f, checks=[big])
    assert not E.envelope_path(f).exists()
    # the bounds keep a full envelope under verify's own read limit
    assert E.MAX_CARRIED_CHECKS * E.MAX_CARRIED_CHECK_BYTES >= E.MAX_CARRIED_CHECKS_BYTES
    assert E.MAX_CARRIED_CHECKS_BYTES * 4 // 3 + 65536 < E.MAX_ENVELOPE_BYTES


def test_editing_a_carried_row_breaks_the_signature(tmp_path):
    f = _file(tmp_path)
    env, did = _seal(tmp_path, f, checks=[_row(verdict=V.BROKEN)])
    stmt = _stmt(env)
    stmt["predicate"]["checks"][0]["relayed_verdict"] = V.VERIFIED       # the sender's wish
    payload = json.dumps(stmt, sort_keys=True, separators=(",", ":")).encode("utf-8")
    env["dsseEnvelope"]["payload"] = base64.b64encode(payload).decode("ascii")
    E.envelope_path(f).write_text(json.dumps(env, indent=1) + "\n", encoding="utf-8")
    r = E.verify(f, audience=AUD, signers=[did])
    assert r["verdict"] == V.BROKEN and r["steps"]["signature"] == V.BROKEN


def test_cli_seal_checks_is_repeatable(tmp_path, capsys):
    f = _file(tmp_path)
    a = _rows_file(tmp_path, [_row(verdict=V.BROKEN)], "a.jsonl")
    b = _rows_file(tmp_path, [_row(verdict=V.VERIFIED)], "b.jsonl")
    rc = E.main(["seal", str(f), "--label", "l", "--audience", AUD, "--deal", "d-7f3a",
                 "--purpose", "grading", "--not-after", "7d", "--key", str(_key(tmp_path)),
                 "--checks", str(a), "--checks", str(b)])
    assert rc == V.EXIT_GOOD
    out = json.loads(capsys.readouterr().out)
    assert out["carried_checks"] == 2
    assert len(out["statement"]["predicate"]["checks"]) == 2


def test_cli_seal_refused_row_is_exit_2_and_names_it(tmp_path, capsys):
    f = _file(tmp_path)
    c = _rows_file(tmp_path, [_row(sha="1" * 64)])
    rc = E.main(["seal", str(f), "--label", "l", "--audience", AUD, "--deal", "d-7f3a",
                 "--purpose", "grading", "--not-after", "7d", "--checks", str(c)])
    assert rc == V.EXIT_USAGE
    assert "checks.jsonl item 1" in capsys.readouterr().err      # one object: item 1
    assert not E.envelope_path(f).exists()


# --- gate: carried rows read like --checks rows ----------------------------------------

def test_carried_broken_vetoes_like_a_checks_file(tmp_path):
    f = _file(tmp_path)
    _, did = _seal(tmp_path, f, checks=[_row(verdict=V.BROKEN)])
    d = G.decide(f, action="pay", audience=AUD, signers=[did], **_ex(tmp_path))
    assert d.decision == "refuse" and d.verdict == V.VERIFIED
    assert d.veto == G.CHECKER_BROKEN and d.exit_code == V.EXIT_BAD
    assert d.reason.startswith(f"refuse pay: {G.CHECKER_BROKEN}: ")
    assert d.checks["carried"]["rows"] == 1 and d.checks["files"] == []
    assert d.checks["broken"][0]["source"] == "envelope"
    assert "checks[]" in d.reason
    assert d.chain_row["veto"] == G.CHECKER_BROKEN


def test_carried_broken_leaves_read_allowed_with_a_note(tmp_path):
    f = _file(tmp_path)
    _, did = _seal(tmp_path, f, checks=[_row(verdict=V.BROKEN)])
    d = G.decide(f, action="read", audience=AUD, signers=[did])
    assert d.allowed and G.CHECKER_BROKEN in d.reason


@pytest.mark.parametrize("word", [V.VERIFIED, V.COULD_NOT_LOOK])
def test_carried_non_broken_rows_change_nothing(tmp_path, word):
    f = _file(tmp_path)
    _, did = _seal(tmp_path, f, checks=[_row(verdict=word)])
    d = G.decide(f, action="pay", audience=AUD, signers=[did], **_ex(tmp_path))
    assert d.allowed and d.veto is None and d.checks["carried"]["rows"] == 1


def test_carried_and_checks_file_combine(tmp_path):
    f = _file(tmp_path)
    _, did = _seal(tmp_path, f, checks=[_row(verdict=V.VERIFIED)])
    c = _rows_file(tmp_path, [_row(verdict=V.BROKEN, vendor="kyverno")])
    d = G.decide(f, action="pay", audience=AUD, signers=[did], check_files=[c], **_ex(tmp_path))
    assert d.veto == G.CHECKER_BROKEN and d.checks["rows"] == 2
    assert [b["source"] for b in d.checks["broken"]] == ["--checks"]
    # and the other way round
    f2 = _file(tmp_path, "other.csv")
    _, did2 = _seal(tmp_path, f2, checks=[_row(verdict=V.BROKEN)])
    ok = _rows_file(tmp_path, [_row(verdict=V.VERIFIED)], "ok.jsonl")
    d2 = G.decide(f2, action="pay", audience=AUD, signers=[did2], check_files=[ok],
                  **_ex(tmp_path))
    assert d2.veto == G.CHECKER_BROKEN and [b["source"] for b in d2.checks["broken"]] == ["envelope"]


def test_carried_row_never_lifts_a_non_verified_envelope(tmp_path):
    f = _file(tmp_path)
    _seal(tmp_path, f, checks=[_row(verdict=V.VERIFIED)], key=False)    # unsigned
    d = G.decide(f, action="pay", audience=AUD, signers=["did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"],
                 **_ex(tmp_path))
    assert d.verdict == V.COULD_NOT_LOOK and d.decision == "refuse" and d.veto is None
    # and on a changed file the carried rows are not read at all
    f2 = _file(tmp_path, "b.csv")
    _, did = _seal(tmp_path, f2, checks=[_row(verdict=V.VERIFIED)])
    f2.write_bytes(BODY + b"x")
    d2 = G.decide(f2, action="read", audience=AUD, signers=[did])
    assert d2.verdict == V.BROKEN and not d2.allowed and d2.checks is None


def test_carried_row_never_counts_toward_the_nonparty_rule(tmp_path):
    f = _file(tmp_path)
    _, did = _seal(tmp_path, f, checks=[_row(verdict=V.VERIFIED)])
    d = G.decide(f, action="pay", audience=AUD, signers=[did], amount="5000",
                 require_nonparty_check_above="100", **_ex(tmp_path))
    assert d.decision == "refuse" and d.veto == G.NONPARTY_VETO
    # the same row in an unsigned --checks file: the same answer
    f2 = _file(tmp_path, "b.csv")
    _, did2 = _seal(tmp_path, f2)
    c = _rows_file(tmp_path, [_row(verdict=V.VERIFIED)])
    d2 = G.decide(f2, action="pay", audience=AUD, signers=[did2], amount="5000", check_files=[c],
                  require_nonparty_check_above="100", **_ex(tmp_path))
    assert (d2.decision, d2.veto, d2.exit_code) == (d.decision, d.veto, d.exit_code)


def _resign(f: Path, key: Path, mutate) -> str:
    """Re-sign the sidecar after `mutate(statement)`: a sealer writing checks[] by hand."""
    from arcaeon.prove.vet import receipts as R
    env = json.loads(E.envelope_path(f).read_text(encoding="utf-8"))
    stmt = _stmt(env)
    mutate(stmt)
    payload = json.dumps(stmt, sort_keys=True, separators=(",", ":")).encode("utf-8")
    seed = base64.b64decode(key.read_text(encoding="ascii"))
    sig = R._sign_bytes(seed, E.pae(E.PAYLOAD_TYPE, payload))
    env["dsseEnvelope"]["payload"] = base64.b64encode(payload).decode("ascii")
    env["dsseEnvelope"]["signatures"][0]["sig"] = base64.b64encode(sig).decode("ascii")
    E.envelope_path(f).write_text(json.dumps(env, indent=1) + "\n", encoding="utf-8")
    return env["dsseEnvelope"]["signatures"][0]["keyid"]


@pytest.mark.parametrize("value", ["not a list", ["not an object"],
                                   [{"kind": core.ROW_KIND, "pad": "x" * 20000}]],
                         ids=["not-list", "not-object", "too-big"])
def test_malformed_signed_checks_is_checks_unreadable(tmp_path, value):
    f = _file(tmp_path)
    k = _key(tmp_path)
    E.seal(f, key_file=k, **BIND)
    did = _resign(f, k, lambda s: s["predicate"].__setitem__("checks", value))
    assert E.verify(f, audience=AUD, signers=[did])["verdict"] == V.VERIFIED
    d = G.decide(f, action="pay", audience=AUD, signers=[did], **_ex(tmp_path))
    assert d.decision == "refuse" and d.veto == G.CHECKS_UNREADABLE and d.exit_code == 3
    assert G.decide(f, action="read", audience=AUD, signers=[did]).allowed


def test_signed_row_for_another_sha_or_kind_is_ignored_like_checks(tmp_path):
    f = _file(tmp_path)
    k = _key(tmp_path)
    E.seal(f, key_file=k, **BIND)
    did = _resign(f, k, lambda s: s["predicate"].__setitem__(
        "checks", [_row(sha="2" * 64), _row(kind="other.kind")]))
    d = G.decide(f, action="pay", audience=AUD, signers=[did], **_ex(tmp_path))
    assert d.allowed and d.checks["carried"]["rows"] == 1 and d.checks["broken"] == []


def test_cli_gate_reads_carried_checks(tmp_path, capsys):
    f = _file(tmp_path)
    _, did = _seal(tmp_path, f, checks=[_row(verdict=V.BROKEN)])
    rc = G.main(["decide", "--envelope", str(E.envelope_path(f)), "--audience", AUD,
                 "--signer", did, "--action", "pay", "--deal", "d-7f3a", "--purpose",
                 "grading", "--ledger", str(tmp_path / "tape.jsonl"), "--record-dir",
                 str(tmp_path / "rec"), "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == V.EXIT_BAD and out["checks"]["veto"] == G.CHECKER_BROKEN
