"""Bulk verification: a whole class's paper checked in one pass.

The mirror of test_ballot_cohort.py. That file proves a roster of twenty
becomes twenty sealed receipts in one command; this one proves those
receipts become ONE answer in one command, and that the answer is honest
about its own edges.

Five things are proven here, four of them by sabotage rather than by
assertion:

  1. The eleven committed examples all verify in a single pass, against the
     shared ledger each one names on its own face.
  2. ONE edited receipt in a batch shows exactly ONE FAIL and a nonzero
     exit -- the other ten are not dragged down with it, and the bad one is
     not lost in the crowd.
  3. ONE unreadable file shows exactly ONE UNDETERMINED, counted separately
     from both `ok` and `FAIL`. The third verdict is the point: "I could not
     check this" is not "this is bad" and is certainly not "this is fine".
  4. 21 files are REFUSED, naming the cap and the count, with NOTHING
     verified. Refuse means refuse: no rows, no summary, no partial answer
     wearing a finished answer's clothes.
  5. The cap can actually fail. Proven by sabotage in this file's own
     record: raising CAP to 100 turns test 4 red, restoring it turns it
     green. A cap test that passes because the fixture can never exceed the
     limit is a fixture with a sealed prediction, not a test.
"""
from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from arcaeon.record.receipt import verify_batch

ROOT = Path(__file__).resolve().parent.parent
EXAMPLES = ROOT / "examples" / "ballots"
HTML_PATH = ROOT / "web" / "verify-receipt.html"

#: The eleven numbered committed examples. The anchored twin of 01 is
#: deliberately excluded: it lives in the same directory but carries its own
#: separate ledger, and mixing it in would be testing the directory listing
#: rather than the class.
def example_receipts():
    return sorted(p for p in EXAMPLES.glob("*.receipt.json") if "anchored" not in p.name)


def run_cli(*args, cwd=None):
    return subprocess.run(
        [sys.executable, "-m", "arcaeon.record.receipt.cli", *[str(a) for a in args]],
        capture_output=True, text=True, timeout=300, cwd=str(cwd or ROOT),
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )


def stage_class(tmp_path: Path) -> Path:
    """Copy the eleven examples AND their shared ledger into a scratch
    directory -- the shape a vendor's bulk export actually has."""
    out = tmp_path / "class"
    out.mkdir()
    for p in example_receipts():
        shutil.copy2(p, out / p.name)
    shutil.copy2(EXAMPLES / "ledger.jsonl", out / "ledger.jsonl")
    return out


def verdicts(stdout: str) -> dict:
    """{receipt file name: verdict} from the rendered per-receipt lines.
    The printed words are VERIFIED / BROKEN / COULD NOT LOOK (vocabulary pass
    2026-09-23); the third is three tokens, so it is read as one."""
    out = {}
    for line in stdout.strip().splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].endswith(".json"):
            word = parts[1]
            if parts[1:4] == ["COULD", "NOT", "LOOK"]:
                word = "COULD NOT LOOK"
            out[parts[0]] = word
    return out


# --------------------------------------------------------------------------
# 1. the eleven examples, one pass
# --------------------------------------------------------------------------

def test_the_eleven_committed_examples_are_actually_there():
    assert len(example_receipts()) == 11, [p.name for p in example_receipts()]


def test_eleven_example_receipts_verify_in_one_pass():
    proc = run_cli("verify", "--batch", *example_receipts())
    assert proc.returncode == 0, proc.stdout + proc.stderr
    lines = [ln for ln in proc.stdout.strip().splitlines() if ln.strip()]
    assert len(lines) == 12, proc.stdout  # eleven receipts, ONE summary
    assert lines[-1] == "11 receipts: 11 VERIFIED, 0 BROKEN, 0 COULD NOT LOOK", lines[-1]
    v = verdicts(proc.stdout)
    assert len(v) == 11 and set(v.values()) == {"VERIFIED"}, v
    # the ledger was genuinely walked, not skipped: every line says so
    assert proc.stdout.count("ledger=consistent") == 11, proc.stdout


def test_a_directory_target_finds_the_receipts_and_not_the_ledger():
    """`--batch <dir>` must not sweep in ledger.jsonl, the witness sidecar,
    the exhibits, or the raw ballot inputs one directory down."""
    found = verify_batch.collect_paths([EXAMPLES])
    names = [p.name for p in found]
    assert all(n.endswith(".receipt.json") for n in names), names
    assert len(names) == 12, names  # the eleven plus the anchored twin
    assert not any("witness" in n or n.endswith(".jsonl") for n in names), names


def test_an_explicit_ledger_applies_to_the_whole_batch(tmp_path):
    proc = run_cli("verify", "--batch", *example_receipts(),
                   "--ledger", EXAMPLES / "ledger.jsonl")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.strip().splitlines()[-1] == \
        "11 receipts: 11 VERIFIED, 0 BROKEN, 0 COULD NOT LOOK"


# --------------------------------------------------------------------------
# 2. one edited receipt: exactly one FAIL, and the exit code says so
# --------------------------------------------------------------------------

def test_one_edited_receipt_in_a_batch_is_exactly_one_fail(tmp_path):
    staged = stage_class(tmp_path)
    target = staged / "05_call_taking_weak.receipt.json"
    rc = json.loads(target.read_text(encoding="utf-8"))
    # One word of one scope sentence -- the smallest edit a reader would
    # never notice and the digest cannot miss.
    rc["scope"]["does_not_prove"][0] = rc["scope"]["does_not_prove"][0] + " (edited)"
    target.write_text(json.dumps(rc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")

    proc = run_cli("verify", "--batch", staged)
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert proc.stdout.strip().splitlines()[-1] == \
        "11 receipts: 10 VERIFIED, 1 BROKEN, 0 COULD NOT LOOK"
    v = verdicts(proc.stdout)
    assert [name for name, verdict in v.items() if verdict == "BROKEN"] == \
        ["05_call_taking_weak.receipt.json"], v
    assert "body digest mismatch" in proc.stdout


def test_restoring_the_edited_receipt_makes_the_batch_green_again(tmp_path):
    """The other half of the sabotage: the FAIL above is caused by the edit
    and nothing else. Without this, a batch that fails for an unrelated
    reason would read as a successful detection."""
    staged = stage_class(tmp_path)
    target = staged / "05_call_taking_weak.receipt.json"
    original = target.read_bytes()
    rc = json.loads(target.read_text(encoding="utf-8"))
    rc["scope"]["does_not_prove"][0] += " (edited)"
    target.write_text(json.dumps(rc, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    assert run_cli("verify", "--batch", staged).returncode == 2

    target.write_bytes(original)
    proc = run_cli("verify", "--batch", staged)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.strip().splitlines()[-1] == \
        "11 receipts: 11 VERIFIED, 0 BROKEN, 0 COULD NOT LOOK"


# --------------------------------------------------------------------------
# 3. the third verdict
# --------------------------------------------------------------------------

def test_one_unreadable_file_is_exactly_one_undetermined(tmp_path):
    staged = stage_class(tmp_path)
    (staged / "07_seq_strong.receipt.json").write_text(
        '{"receipt_version": "arcaeon-receipt/0.1", "kind": ',  # truncated mid-object
        encoding="utf-8")

    proc = run_cli("verify", "--batch", staged)
    assert proc.returncode != 0, proc.stdout
    assert proc.returncode == 4, (proc.returncode, proc.stdout)
    assert proc.stdout.strip().splitlines()[-1] == \
        "11 receipts: 10 VERIFIED, 0 BROKEN, 1 COULD NOT LOOK"
    v = verdicts(proc.stdout)
    assert [name for name, verdict in v.items() if verdict == "COULD NOT LOOK"] == \
        ["07_seq_strong.receipt.json"], v
    assert "not readable JSON" in proc.stdout


def test_an_undetermined_receipt_is_never_counted_as_ok_or_failed(tmp_path):
    staged = stage_class(tmp_path)
    (staged / "07_seq_strong.receipt.json").write_text("[1, 2, 3]", encoding="utf-8")
    result = verify_batch.verify_batch([staged])
    assert (result["verified"], result["failed"], result["undetermined"]) == (10, 0, 1)
    assert result["verified"] + result["failed"] + result["undetermined"] == 11


def test_a_receipt_whose_ledger_is_missing_is_undetermined_not_ok(tmp_path):
    """A receipt claims a row in a ledger. With no ledger to walk, that claim
    is UNCHECKED -- which is neither a pass nor an accusation. Reporting it as
    `ok` would be the overclaim this product exists to not make."""
    bare = tmp_path / "bare"
    bare.mkdir()
    for p in example_receipts():
        shutil.copy2(p, bare / p.name)  # receipts only, no ledger.jsonl

    result = verify_batch.verify_batch([bare])
    assert (result["verified"], result["failed"], result["undetermined"]) == (0, 0, 11)
    assert verify_batch.exit_code(result) == 4
    assert all(r["ledger"] == "not_checked" for r in result["rows"])
    assert all("ledger sequence claim is unchecked" in r["reason"] for r in result["rows"])


def test_a_definite_failure_outranks_an_undetermined_ledger(tmp_path):
    """Body digest broken AND no ledger present. The verdict is FAIL, because
    that one IS determined; `undetermined` must never launder a receipt that
    was actually caught."""
    bare = tmp_path / "bare"
    bare.mkdir()
    src = EXAMPLES / "05_call_taking_weak.receipt.json"
    rc = json.loads(src.read_text(encoding="utf-8"))
    rc["issued_at"] = "1999-01-01T00:00:00Z"
    (bare / src.name).write_text(json.dumps(rc, indent=1), encoding="utf-8")

    result = verify_batch.verify_batch([bare])
    assert result["rows"][0]["verdict"] == verify_batch.FAIL
    assert (result["verified"], result["failed"], result["undetermined"]) == (0, 1, 0)
    assert verify_batch.exit_code(result) == 2


# --------------------------------------------------------------------------
# 4. the cap is a refusal, not a truncation
# --------------------------------------------------------------------------

def stage_n(tmp_path: Path, n: int) -> Path:
    out = tmp_path / f"n{n}"
    out.mkdir()
    src = EXAMPLES / "05_call_taking_weak.receipt.json"
    shutil.copy2(EXAMPLES / "ledger.jsonl", out / "ledger.jsonl")
    for i in range(n):
        shutil.copy2(src, out / f"r{i:03d}.receipt.json")
    return out


def test_twenty_one_receipts_are_refused_and_nothing_is_verified(tmp_path):
    staged = stage_n(tmp_path, 21)
    proc = run_cli("verify", "--batch", staged)

    assert proc.returncode == 1, (proc.returncode, proc.stdout, proc.stderr)
    # the message names the cap AND the count
    assert "21 receipts" in proc.stderr, proc.stderr
    assert f"cap is {verify_batch.CAP} per pass" in proc.stderr, proc.stderr
    assert "Nothing was verified" in proc.stderr, proc.stderr
    # NOTHING verified: no rows, no summary, no partial answer
    assert proc.stdout.strip() == "", proc.stdout
    assert "VERIFIED," not in proc.stdout
    assert verdicts(proc.stdout) == {}


def test_the_refusal_happens_before_any_file_is_opened(tmp_path):
    """Proven, not asserted: one of the 21 files is unreadable garbage. If
    the cap check ran after the reads, that file would produce an
    undetermined row. It produces nothing, because nothing was read."""
    staged = stage_n(tmp_path, 21)
    (staged / "r007.receipt.json").write_text("not json at all", encoding="utf-8")
    proc = run_cli("verify", "--batch", staged)
    assert proc.returncode == 1
    assert "COULD NOT LOOK" not in proc.stdout
    assert proc.stdout.strip() == ""


def test_exactly_the_cap_is_accepted(tmp_path):
    """The boundary, from the accepting side: 20 is a pass, so the refusal
    above is the cap doing its job and not an off-by-one swallowing a legal
    batch."""
    staged = stage_n(tmp_path, verify_batch.CAP)
    proc = run_cli("verify", "--batch", staged)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert proc.stdout.strip().splitlines()[-1] == \
        f"{verify_batch.CAP} receipts: {verify_batch.CAP} VERIFIED, 0 BROKEN, 0 COULD NOT LOOK"


def test_cap_is_the_published_number():
    """docs/VENDOR_PACKAGE_SPEC.md 2.5 publishes 20 next to the words "free
    to verify". The code and the sales sheet are the same number or one of
    them is a lie."""
    assert verify_batch.CAP == 20
    spec = (ROOT / "docs" / "VENDOR_PACKAGE_SPEC.md").read_text(encoding="utf-8")
    assert "cap on free bulk verification is 20 receipts in one pass" in spec


def test_an_empty_batch_target_is_refused_not_reported_as_a_clean_run(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    proc = run_cli("verify", "--batch", empty)
    assert proc.returncode == 1
    assert "no receipts matched" in proc.stderr
    assert "VERIFIED," not in proc.stdout


def test_batch_and_a_single_path_together_are_refused(tmp_path):
    proc = run_cli("verify", EXAMPLES / "05_call_taking_weak.receipt.json",
                   "--batch", EXAMPLES)
    assert proc.returncode == 1
    assert "--batch takes its own target list" in proc.stderr


def test_single_verify_still_works_unchanged():
    """The one-receipt path is the one everything else already depends on.
    Adding --batch must not have moved it."""
    proc = run_cli("verify", EXAMPLES / "05_call_taking_weak.receipt.json",
                   "--ledger", EXAMPLES / "ledger.jsonl")
    assert proc.returncode == 0, proc.stderr
    res = json.loads(proc.stdout)
    assert res["ok"] is True and res["ledger"]["status"] == "consistent"


def test_verify_with_no_path_at_all_is_refused_not_crashed():
    proc = run_cli("verify")
    assert proc.returncode == 1
    assert "verify needs a receipt path" in proc.stderr


# --------------------------------------------------------------------------
# 5. the web page: same cap, same three verdicts, hashing untouched
# --------------------------------------------------------------------------

START_MARK = "// C14N-START"
END_MARK = "// C14N-END"

#: sha256 of the page's canonicalizer block, exactly as it stood when bulk
#: verification was added. The batch UI was required to add rows and a cap
#: and to change NOTHING about how a digest is computed. This pin makes that
#: a checked fact: a UI change cannot silently reach into the hashing. A
#: deliberate canonicalizer fix updates this line on purpose, with the parity
#: test in tests/test_verify_page_parity.py as the correctness guard.
C14N_BLOCK_SHA256 = "33806fbcf616c2bf2ddcf2562d53815a4346da83945da4df1e50af8bea0086ab"


def page_text() -> str:
    return HTML_PATH.read_text(encoding="utf-8")


def c14n_block(text: str) -> str:
    return text[text.index(START_MARK):text.index(END_MARK)]


def test_page_canonicalizer_block_is_byte_for_byte_unchanged():
    block = c14n_block(page_text())
    assert hashlib.sha256(block.encode("utf-8")).hexdigest() == C14N_BLOCK_SHA256, (
        "web/verify-receipt.html's canonicalizer changed. Bulk verification was "
        "allowed to add UI and nothing else; if this change is deliberate, say so "
        "and re-pin, and make sure test_verify_page_parity.py still passes."
    )


def test_batch_code_lives_entirely_outside_the_canonicalizer():
    block = c14n_block(page_text())
    for token in ("runBatch", "BATCH_CAP", "renderBatch", "verifyOneText",
                  "handleDroppedFiles", "document", "FileReader"):
        assert token not in block, (
            f"{token!r} appears inside the C14N block; that block must stay pure "
            "and synchronous so it evaluates identically in Node and the browser"
        )


def test_page_accepts_multiple_files_and_publishes_the_same_cap():
    text = page_text()
    assert 'id="file-input"' in text and "multiple" in text
    assert f"const BATCH_CAP = {verify_batch.CAP};" in text, (
        "the page's cap and the CLI's cap must be the same published number"
    )
    assert "dataTransfer.files[0]" not in text, (
        "the drop handler still takes only the first file"
    )
    assert "handleDroppedFiles(e.dataTransfer && e.dataTransfer.files)" in text


def test_page_carries_all_three_verdicts_and_refuses_past_the_cap():
    text = page_text()
    for verdict in ("VERIFIED", "BROKEN", "COULD NOT LOOK"):
        assert f'"{verdict}"' in text, verdict
    # the retired words are gone from what the page can print
    for retired in ('"PASS"', '"FAIL"', '"UNDETERMINED"', '" undetermined"'):
        assert retired not in text, retired
    assert "Refusing this batch:" in text
    assert "cap is " in text and "per pass" in text
    # the page's summary line reads the same way the CLI's does
    assert '" VERIFIED, "' in text and '" BROKEN, "' in text and '" COULD NOT LOOK"' in text


# --------------------------------------------------------------------------
# 6. the page's batch logic, actually RUN -- not asserted from its source
# --------------------------------------------------------------------------
# Grepping a HTML file for the word "UNDETERMINED" proves the word is in the
# file. It does not prove a dropped batch produces that verdict. So the whole
# shipped <script> is extracted and executed under Node against a ~40-line DOM
# shim, and the same four cases the CLI is held to are run through it: eleven
# good receipts, one edited, one unreadable, and twenty-one.

DOM_SHIM = r"""
const fs = require('fs');
class N {
  constructor(id) {
    this.id = id; this.children = []; this.style = {}; this.textContent = "";
    this.className = ""; this.hidden = false; this.value = "";
    this.classList = { add: function () {}, remove: function () {} };
  }
  get firstChild() { return this.children.length ? this.children[0] : null; }
  appendChild(c) { this.children.push(c); return c; }
  removeChild(c) { const i = this.children.indexOf(c); if (i >= 0) { this.children.splice(i, 1); } return c; }
  addEventListener() {}
  click() {}
}
const reg = {};
global.document = {
  getElementById: function (id) { return reg[id] || (reg[id] = new N(id)); },
  createElement: function (tag) { return new N(tag); },
  addEventListener: function () {}
};
global.window = { crypto: require("crypto").webcrypto };
global.FileReader = class {
  readAsText(f) {
    const self = this;
    setTimeout(function () {
      if (f.__fail) { self.error = { message: "simulated read error" }; if (self.onerror) { self.onerror(); } }
      else { self.result = f.__text; if (self.onload) { self.onload(); } }
    }, 0);
  }
};
"""

DOM_HARNESS = r"""
function tableRows() {
  const table = reg["batch-table"];
  const tbody = table.children.filter(function (c) { return c.id === "tbody"; })[0];
  if (!tbody) { return []; }
  return tbody.children.map(function (tr) {
    return { name: tr.children[0].textContent,
             verdict: tr.children[1].children[0].textContent,
             reason: tr.children[2].textContent };
  });
}
(async function () {
  const cases = JSON.parse(fs.readFileSync(process.argv[2], "utf8"));
  const out = {};
  for (const c of cases) {
    reg["error"].textContent = "";
    reg["batch-summary"].textContent = "";
    reg["batch-table"].children = [];
    await runBatch(c.files.map(function (f) { return { name: f.name, __text: f.text }; }));
    out[c.name] = { summary: reg["batch-summary"].textContent,
                    error: reg["error"].textContent,
                    hidden: reg["section-batch"].hidden,
                    cap: BATCH_CAP,
                    rows: tableRows() };
  }
  fs.writeFileSync(process.argv[3], JSON.stringify(out), "utf8");
})();
"""


def page_script() -> str:
    text = page_text()
    return text[text.index("<script>") + len("<script>"):text.index("</script>")]


@pytest.fixture(scope="module")
def page_batch_results():
    """Run the page's own batch code over four cases, once, under Node."""
    node = shutil.which("node")
    if node is None:
        pytest.skip("node is not on PATH; cannot run the page's batch logic")
    import tempfile

    good = [{"name": p.name, "text": p.read_text(encoding="utf-8")}
            for p in example_receipts()]

    edited = [dict(f) for f in good]
    rc = json.loads(edited[4]["text"])
    rc["scope"]["does_not_prove"][0] += " (edited)"
    edited[4] = {"name": edited[4]["name"], "text": json.dumps(rc, ensure_ascii=False)}

    broken = [dict(f) for f in good]
    broken[6] = {"name": broken[6]["name"], "text": '{"kind": '}

    over = [{"name": f"r{i:03d}.receipt.json", "text": good[0]["text"]} for i in range(21)]

    cases = [{"name": "good", "files": good}, {"name": "edited", "files": edited},
             {"name": "broken", "files": broken}, {"name": "over_cap", "files": over}]

    with tempfile.TemporaryDirectory() as td:
        script = Path(td) / "page_harness.js"
        cases_path = Path(td) / "cases.json"
        out_path = Path(td) / "out.json"
        # The shipped page script verbatim, between the shim and the driver.
        script.write_text(DOM_SHIM + page_script() + DOM_HARNESS, encoding="utf-8")
        cases_path.write_text(json.dumps(cases, ensure_ascii=False), encoding="utf-8")
        proc = subprocess.run([node, str(script), str(cases_path), str(out_path)],
                              capture_output=True, text=True, timeout=120)
        assert proc.returncode == 0, proc.stderr
        return json.loads(out_path.read_text(encoding="utf-8"))


def test_page_verifies_eleven_receipts_in_one_drop(page_batch_results):
    r = page_batch_results["good"]
    assert r["summary"] == "11 receipts: 11 VERIFIED, 0 BROKEN, 0 COULD NOT LOOK"
    assert r["hidden"] is False
    assert len(r["rows"]) == 11
    assert {row["verdict"] for row in r["rows"]} == {"VERIFIED"}


def test_page_shows_exactly_one_fail_for_one_edited_receipt(page_batch_results):
    r = page_batch_results["edited"]
    assert r["summary"] == "11 receipts: 10 VERIFIED, 1 BROKEN, 0 COULD NOT LOOK"
    failed = [row for row in r["rows"] if row["verdict"] == "BROKEN"]
    assert len(failed) == 1 and failed[0]["name"] == "05_call_taking_weak.receipt.json"
    assert "body digest mismatch" in failed[0]["reason"]


def test_page_shows_exactly_one_undetermined_for_one_unreadable_file(page_batch_results):
    r = page_batch_results["broken"]
    assert r["summary"] == "11 receipts: 10 VERIFIED, 0 BROKEN, 1 COULD NOT LOOK"
    und = [row for row in r["rows"] if row["verdict"] == "COULD NOT LOOK"]
    assert len(und) == 1 and und[0]["name"] == "07_seq_strong.receipt.json"
    assert "not readable JSON" in und[0]["reason"]


def test_page_refuses_twenty_one_files_and_renders_no_rows(page_batch_results):
    r = page_batch_results["over_cap"]
    assert r["cap"] == 20
    assert "21 receipts" in r["error"] and "cap is 20 per pass" in r["error"]
    assert "Nothing was verified" in r["error"]
    assert r["rows"] == [], r["rows"]
    assert r["summary"] == "", r["summary"]
    assert r["hidden"] is True


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not on PATH")
def test_page_canonicalizer_still_loads_and_runs_under_node():
    """A cheap smoke test that the UI edits did not break the extracted block
    the parity test depends on. The real parity check is
    tests/test_verify_page_parity.py, which is untouched by this change."""
    import tempfile
    block = c14n_block(page_text())
    with tempfile.TemporaryDirectory() as td:
        script = Path(td) / "h.js"
        out = Path(td) / "o.txt"
        script.write_text(block + "\nrequire('fs').writeFileSync(process.argv[2], "
                          "c14nCanonicalize('{\"b\":1,\"a\":2}'), 'utf8');\n",
                          encoding="utf-8")
        proc = subprocess.run([shutil.which("node"), str(script), str(out)],
                              capture_output=True, text=True, timeout=30)
        assert proc.returncode == 0, proc.stderr
        assert out.read_text(encoding="utf-8") == '{"a":2,"b":1}'
