"""K040: the submit door. Any AI or person files its own reading, by CLI or by
POST /v1/readings, and compare lines the two ledgers up. Loopback only."""
from __future__ import annotations

import http.client
import io
import json
import threading

import pytest

from arcaeon import verdict as V
from arcaeon.prove import readings as R
from arcaeon.prove.readings_cli import SUBMIT_FORMAT, main, submit
from arcaeon.prove.readings_compare import compare
from arcaeon.record.ledger import verify_file
from arcaeon.serve import auth
from arcaeon.serve import server as S

SENTENCE = "Does the claim state the dispatch time?"
CLAIMS = {"c1": "dispatched at 0412", "c2": "the caller hung up", "c3": "units rolled 0415",
          "c4": "no time given"}


# --- the core and the CLI ------------------------------------------------------

def test_cli_submit_files_a_chained_row_citing_the_frozen_criterion(tmp_path, capsys):
    led, crit, claim = tmp_path / "l.jsonl", tmp_path / "crit.txt", tmp_path / "c1.txt"
    crit.write_text(SENTENCE, encoding="utf-8")
    claim.write_text(CLAIMS["c1"], encoding="utf-8")
    assert main(["criterion", str(crit), "--ledger", str(led)]) == 0
    capsys.readouterr()
    rc = main(["submit", "--ledger", str(led), "--reader-id", "agent-x", "--provider", "acme",
               "--claim-id", "c1", "--claim-file", str(claim), "--reading", "no", "--json"])
    res = json.loads(capsys.readouterr().out)
    assert rc == 0 and res["exit"] == 0 and res["written"] is True
    assert res["format"] == SUBMIT_FORMAT
    assert res["criterion_sha256"] == R.sha256_text(SENTENCE)
    assert res["claim_sha256"] == R.sha256_text(CLAIMS["c1"])
    assert res["reader"] == {"id": "agent-x", "provider": "acme", "model": None,
                             "endpoint_host": None}
    rows = R.load_readings(led)
    assert rows["ok"] and len(rows["readings"]) == 1
    row = rows["readings"][0]
    assert row["reading"] == "no" and row["prompt_sha256"] is None
    assert verify_file(led).ok is True


def test_cli_human_line_says_filed_not_right(tmp_path, capsys):
    led, claim = tmp_path / "l.jsonl", tmp_path / "c.txt"
    R.freeze_criterion(led, SENTENCE)
    claim.write_text("x", encoding="utf-8")
    assert main(["submit", "--ledger", str(led), "--reader-id", "p", "--provider", "person",
                 "--claim-id", "c1", "--claim-file", str(claim), "--reading", "yes"]) == 0
    out = capsys.readouterr().out
    assert out.startswith("reading filed: claim c1 read 'yes' by p")
    for word in ("true", "correct", "verified", "independent"):
        assert word not in out.lower()


def test_no_criterion_is_could_not_look_and_writes_nothing(tmp_path):
    led = tmp_path / "l.jsonl"
    res = submit(led, reader_id="x", provider="p", claim_id="c1", claim_text="t", reading="no")
    assert res["exit"] == V.EXIT_COULD_NOT_LOOK and res["reason_word"] == "name_not_found"
    assert res["written"] is False and not led.exists()
    res = submit(led, reader_id="x", provider="p", claim_id="c1", claim_text="t", reading="no",
                 criterion_sha256="a" * 64)
    assert res["exit"] == V.EXIT_COULD_NOT_LOOK and res["reason_word"] == "name_not_found"
    assert not led.exists()


def test_criterion_text_is_frozen_first_then_cited(tmp_path):
    led = tmp_path / "l.jsonl"
    r1 = submit(led, reader_id="x", provider="p", claim_id="c1", claim_text="t", reading="yes",
                criterion_text=SENTENCE)
    r2 = submit(led, reader_id="x", provider="p", claim_id="c2", claim_text="u", reading="no",
                criterion_text=SENTENCE)
    assert (r1["exit"], r1["criterion_frozen_now"], r2["exit"], r2["criterion_frozen_now"]) == \
        (0, True, 0, False)
    rows = [json.loads(line) for line in led.read_text(encoding="utf-8").splitlines()]
    assert [r["evt"] for r in rows] == ["criterion", "reading", "reading"]


def test_the_latest_criterion_is_cited_when_none_is_named(tmp_path):
    led = tmp_path / "l.jsonl"
    old = R.freeze_criterion(led, "old sentence")["criterion_sha256"]
    new = R.freeze_criterion(led, SENTENCE, supersedes=old)["criterion_sha256"]
    res = submit(led, reader_id="x", provider="p", claim_id="c1", claim_text="t", reading="yes")
    assert res["criterion_sha256"] == new


@pytest.mark.parametrize("kw,needle", [
    ({"reading": "maybe"}, "unknown reading word"),
    ({"reader_id": ""}, "reader_id"),
    ({"provider": " "}, "provider"),
    ({"claim_text": None}, "claim"),
    ({"criterion_sha256": "b" * 64}, "does not match"),
])
def test_bad_submits_are_usage_and_write_nothing(tmp_path, kw, needle):
    led = tmp_path / "l.jsonl"
    R.freeze_criterion(led, SENTENCE)
    before = led.read_bytes()
    args = dict(reader_id="x", provider="p", claim_id="c1", claim_text="t", reading="no",
                criterion_text=SENTENCE)
    args.update(kw)
    res = submit(led, **args)
    assert res["exit"] == V.EXIT_USAGE and needle in res["error"]
    assert led.read_bytes() == before


def test_cli_usage_errors_exit_2(tmp_path, capsys):
    led = tmp_path / "l.jsonl"
    assert main(["submit", "--ledger", str(led)]) == 2
    assert main(["submit", "--ledger", str(led), "--reader-id", "x", "--provider", "p",
                 "--claim-id", "c", "--claim-file", str(tmp_path / "nope.txt"),
                 "--reading", "no"]) == 2


# --- over HTTP: two agents, two ledgers, one compare ----------------------------------

@pytest.fixture()
def srv(tmp_path, monkeypatch):
    monkeypatch.setenv("ARCAEON_HOME", str(tmp_path / "arcaeon-home"))
    monkeypatch.setenv("ARCAEON_JOURNAL", "0")
    monkeypatch.delenv("ARCAEON_KEY", raising=False)
    root = tmp_path / "served"
    root.mkdir()
    monkeypatch.chdir(tmp_path)
    server = S.make_server(port=0, root=root)
    ready = threading.Event()
    t = threading.Thread(target=S.run, args=(server,),
                         kwargs={"ready": ready, "out": io.StringIO()}, daemon=True)
    t.start()
    assert ready.wait(10)
    yield server, root
    server.shutdown()
    t.join(10)


def post(server, path, body):
    c = http.client.HTTPConnection("127.0.0.1", server.server_address[1], timeout=30)
    c.request("POST", path, body=json.dumps(body).encode(),
              headers={"Content-Type": "application/json",
                       "Authorization": f"Bearer {auth.load_or_create()}"})
    r = c.getresponse()
    out = json.loads(r.read())
    c.close()
    return r.status, out


def test_two_agents_submit_over_http_and_compare_is_compared(srv):
    server, root = srv
    a_says = {"c1": "yes", "c2": "no", "c3": "yes", "c4": "no"}
    b_says = {"c1": "yes", "c2": "yes", "c3": "undetermined", "c4": "no"}
    for ledger, rid, prov, says in (("a.jsonl", "agent-a", "vendor-a", a_says),
                                    ("b.jsonl", "agent-b", "vendor-b", b_says)):
        for cid, word in says.items():
            body = {"ledger": ledger, "reader_id": rid, "provider": prov, "claim_id": cid,
                    "claim": CLAIMS[cid], "criterion": SENTENCE, "reading": word}
            if cid == "c3":
                body["near_match_id"] = f"{rid}-near"
            status, res = post(server, "/v1/readings", body)
            assert status == 200 and res["exit"] == 0 and res["written"] is True, res
            assert isinstance(res["chain"], str) and res["chain"]
    status, res = post(server, "/v1/second-read/compare", {"a": "a.jsonl", "b": "b.jsonl"})
    assert status == 200 and res["verdict"] == V.COMPARED and res["exit"] == 0
    assert res["summary"]["disagreed"] == 2 and res["summary"]["read"] == 4
    assert res["summary"]["not_yet_informative"] is True
    assert res["independence"] == "distinct_provider_self_asserted"
    dis = {c["claim_id"]: c for c in res["claims"] if c["status"] == "DISAGREED"}
    assert set(dis) == {"c2", "c3"}
    c3 = dis["c3"]
    assert (c3["a"]["reading"], c3["b"]["reading"]) == ("yes", "undetermined")
    assert (c3["a"]["reader_id"], c3["b"]["reader_id"]) == ("agent-a", "agent-b")
    assert (c3["a"]["near_match_id"], c3["b"]["near_match_id"]) == ("agent-a-near", "agent-b-near")
    assert "independent" not in json.dumps(res)
    # the same answer the local compare gives, and both ledgers chain
    local = compare(root / "a.jsonl", root / "b.jsonl")
    assert local["summary"] == res["summary"]
    assert verify_file(root / "a.jsonl").ok is True and verify_file(root / "b.jsonl").ok is True


def test_compare_handler_takes_content_in(srv):
    # The handler reads content_a / content_b (K007's rule); the route table still
    # lists a and b as required, so over HTTP this waits on lane A's schema line.
    from arcaeon.serve import h_readings
    server, root = srv
    for ledger, rid, prov in (("a.jsonl", "a", "pa"), ("b.jsonl", "b", "pb")):
        post(server, "/v1/readings", {"ledger": ledger, "reader_id": rid, "provider": prov,
                                      "claim_id": "c1", "claim": "t", "criterion": SENTENCE,
                                      "reading": "yes"})
    res = h_readings.compare({"content_a": (root / "a.jsonl").read_text(encoding="utf-8"),
                              "b": str(root / "b.jsonl")})
    assert res["verdict"] == V.COMPARED and res["exit"] == 0
    assert (res["summary"]["disagreed"], res["summary"]["read"]) == (0, 1)
    assert "(content)" in json.dumps(res) and "arcaeon-content-" not in json.dumps(res)


def test_http_submit_bad_usage_is_400_and_no_criterion_is_200_could_not_look(srv):
    server, root = srv
    status, res = post(server, "/v1/readings", {"ledger": "x.jsonl", "reader_id": "a",
                                                "claim_id": "c1", "claim": "t", "reading": "no"})
    assert status == 400 and "provider" in res["error"]
    status, res = post(server, "/v1/readings", {"ledger": "x.jsonl", "reader_id": "a",
                                                "provider": "p", "claim_id": "c1",
                                                "claim": "t", "reading": "no"})
    assert status == 200 and res["exit"] == V.EXIT_COULD_NOT_LOOK
    assert res["reason_word"] == "name_not_found" and not (root / "x.jsonl").exists()
    status, res = post(server, "/v1/readings", {"ledger": "../out.jsonl", "reader_id": "a",
                                                "provider": "p", "claim_id": "c1",
                                                "claim": "t", "reading": "no"})
    assert status == 400 and "outside the served root" in res["error"]
