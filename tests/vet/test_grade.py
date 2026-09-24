"""Grade artifact tests — prove re-testability is real, not a slogan."""
import sys, json
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from arcaeon.prove.vet.grade import grade_source, verify, BLIND_SPOTS

CLEAN = "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\nmcp.run(transport='stdio')\n"
DIRTY = "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n@mcp.tool()\ndef f(url):\n    import urllib.request\n    return urllib.request.urlopen(url).read()\n"

def test_grade_pins_source_hash_and_carries_blindspots():
    g = grade_source(CLEAN, "clean.py")
    assert len(g.source_sha256) == 64
    assert g.blind_spots == BLIND_SPOTS and g.blind_spots, "grade must carry its own blind spots"
    assert g.verdict == "no findings in checked classes"

def test_dirty_source_grades_high():
    g = grade_source(DIRTY, "dirty.py")
    assert g.verdict == "high-severity findings", g.verdict
    assert any(f["check"] == "ssrf" for f in g.findings)

def test_verify_reproduces_same_bytes():
    g = grade_source(DIRTY, "dirty.py")
    r = verify(json.loads(g.to_json()), DIRTY)
    assert r["reproduced"] is True, r

def test_verify_rejects_different_bytes():
    # planted red: a grade claiming to be of DIRTY, checked against CLEAN, must NOT reproduce
    g = grade_source(DIRTY, "dirty.py")
    r = verify(json.loads(g.to_json()), CLEAN)
    assert r["reproduced"] is False, "different bytes must fail reproduction"
    assert any("not the same file" in x for x in r["reasons"]), r

def test_verify_rejects_tampered_findings():
    # a grade whose findings were edited to hide a real one must fail on re-run
    g = json.loads(grade_source(DIRTY, "dirty.py").to_json())
    g["findings"] = []          # attacker scrubs the ssrf finding but keeps the hash
    r = verify(g, DIRTY)
    assert r["reproduced"] is False, "scrubbed findings must not reproduce"
    assert any("findings differ" in x for x in r["reasons"]), r

if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    p = 0
    for fn in fns:
        try: fn(); print("PASS", fn.__name__); p += 1
        except Exception: print("FAIL", fn.__name__); traceback.print_exc()
    print(f"\n{p}/{len(fns)} passed"); sys.exit(0 if p == len(fns) else 1)
