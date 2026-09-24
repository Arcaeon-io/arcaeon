"""MCP01 secret-in-code tests (board F4, 2026-08-30).

Design: `design/MCP01_secret_in_code.md`. Written BEFORE the check exists, so
the red is real. Every positive class gets a planted red AND the negatives the
design promised would stay silent -- this is the class most exposed to noise
(a false red on a stranger's repo over a `sk_test_` fixture key costs the
reputation the whole line is built on), so the precision cases outnumber the
detection cases on purpose.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from arcaeon.prove.vet.checks import scan_source, check_names

HDR = "from mcp.server.fastmcp import FastMCP\nmcp = FastMCP('x')\n"
FIXTURE = Path(__file__).resolve().parent / "tests" / "fixtures" / "secret_in_code_server.py"


def _kinds(src):
    return sorted({f.check for f in scan_source(src, "t.py")})


def _secrets(src):
    return [f for f in scan_source(src, "t.py") if f.check == "secret-in-code"]


# --- registration ------------------------------------------------------------

def test_check_is_registered():
    assert "secret-in-code" in check_names(), check_names()


# --- class 1: known-vendor key shapes ---------------------------------------

def test_vendor_key_shapes_fire_high():
    for label, src in (
        ("aws-akia", 'AWS_ACCESS_KEY_ID = "AKIAFAKEFAKEFAKE1234"'),
        ("aws-asia", 'AWS_SESSION_ID = "ASIAFAKEFAKEFAKE1234"'),
        ("stripe-sk-live", 'STRIPE_SECRET_KEY = "sk_live_FAKEFAKEFAKEFAKEFAKEFAKEFAKE"'),
        ("stripe-rk-live", 'STRIPE_RESTRICTED = "rk_live_FAKEFAKEFAKEFAKEFAKEFAKE"'),
        ("stripe-whsec", 'WEBHOOK_SECRET = "whsec_FAKEFAKEFAKEFAKEFAKEFAKE"'),
        ("openai", 'OPENAI_API_KEY = "sk-FAKEfake1234FAKEfake5678"'),
        ("openai-proj", 'OPENAI_API_KEY = "sk-proj-FAKEfake1234FAKEfake5678"'),
        ("github-pat-classic", 'GITHUB_TOKEN = "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"'),
        ("github-pat-fine", 'GITHUB_TOKEN = "github_pat_11FAKEFAKE0FAKEFAKEFAKEFAKE"'),
    ):
        fs = _secrets(src)
        assert fs, f"{label}: no finding for {src!r}"
        assert fs[0].severity == "high", f"{label}: a vendor prefix is a fingerprint, not a guess: {fs}"


def test_vendor_shape_fires_regardless_of_variable_name():
    """The prefix is the evidence; the name adds nothing."""
    src = 'notes = "AKIAFAKEFAKEFAKE1234"'
    assert _secrets(src), "vendor shape must not depend on the assignment name"


def test_aws_secret_access_key_is_name_gated():
    """A bare 40-char base64-ish blob is base64 of anything -- too common to
    flag alone. It fires only as the value of an aws-secret-shaped name."""
    val = "FAKEwJalrXUtnFEMIK7MDENGbPxRfiCYFAKEKEY1"
    assert len(val) == 40, len(val)
    assert _secrets('AWS_SECRET_ACCESS_KEY = "%s"' % val), "name-gated AWS secret must fire"
    assert not _secrets('CACHE_BUCKET = "%s"' % val), "bare 40-char blob must NOT fire"


def test_finding_does_not_echo_the_whole_secret():
    """The scanner's own output must not become the leak."""
    key = "ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE"
    fs = _secrets('GITHUB_TOKEN = "%s"' % key)
    assert fs, "no finding"
    assert key not in fs[0].detail, fs[0].detail


# --- class 2: entropy-gated literal on a secret-shaped name ------------------

def test_high_entropy_literal_on_secret_name_is_medium():
    for src in ('DATABASE_PASSWORD = "hV3kQ9zLm2Xp7Rt4Ws8Ny6"',
                'SERVICE_TOKEN = "hV3kQ9zLm2Xp7Rt4Ws8Ny6"',
                'CLIENT_SECRET = "hV3kQ9zLm2Xp7Rt4Ws8Ny6"',
                'SIGNING_KEY = "hV3kQ9zLm2Xp7Rt4Ws8Ny6"'):
        fs = _secrets(src)
        assert fs, src
        assert fs[0].severity == "medium", "entropy is a heuristic, not a fingerprint: %r" % fs


def test_secret_shaped_dict_key_and_kwarg_count():
    """headers = {"Authorization": "..."} is a realistic leak site and does not
    require a bare variable."""
    assert _secrets('headers = {"Authorization": "hV3kQ9zLm2Xp7Rt4Ws8Ny6"}')
    assert _secrets('client = Thing(api_key="hV3kQ9zLm2Xp7Rt4Ws8Ny6")')


def test_entropy_class_silent_without_a_secret_shaped_name():
    assert not _secrets('GREETING = "hV3kQ9zLm2Xp7Rt4Ws8Ny6"')


def test_entropy_class_silent_on_placeholders_and_low_entropy():
    for src in ('API_KEY = "your_api_key_here"',
                'API_KEY = "changeme"',
                'API_KEY = "REPLACE_ME_WITH_YOUR_KEY"',
                'API_KEY = "xxxxxxxxxxxxxxxx"',
                'API_KEY = "<KEY>"',
                'API_KEY = "${OPENAI_API_KEY}"',
                'API_KEY = ""',
                'API_KEY = "example-value-goes-here"',
                'AUTH_TOKEN = "Bearer token goes in this header"'):
        assert not _secrets(src), "placeholder must stay silent: %s" % src


# --- class 3: .env-shaped literal embedded in source -------------------------

def test_env_shaped_line_in_docstring_fires():
    src = '"""Setup:\n\nSTRIPE_SECRET_KEY=sk_live_FAKEFAKEFAKEFAKEFAKEFAKEFAKE\n"""\n'
    fs = _secrets(src)
    assert fs, "a quoted key leaks exactly as hard as an assigned one"
    assert fs[0].line == 3, "must point at the leaking line, not the docstring start: %r" % fs


def test_env_shaped_line_in_comment_fires():
    src = "# example .env:\n# GITHUB_TOKEN=ghp_FAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKEFAKE\n"
    fs = _secrets(src)
    assert fs and fs[0].line == 2, fs


def test_env_shaped_line_needs_a_real_value():
    for src in ('"""\nAPI_KEY=your_key_here\n"""\n',
                '"""\nAPI_KEY=\n"""\n',
                '"""\nDEBUG=true\n"""\n',
                "# LOG_LEVEL=info\n"):
        assert not _secrets(src), src


# --- the design's deliberate non-catches (precision, not oversight) ---------

def test_test_and_publishable_keys_never_fire():
    for src in ('STRIPE_SECRET_KEY = "sk_test_FAKEFAKEFAKEFAKEFAKEFAKEFAKE"',
                'STRIPE_PUBLISHABLE_KEY = "pk_test_FAKEFAKEFAKEFAKEFAKEFAKEFAKE"',
                'STRIPE_PUBLIC_KEY = "pk_live_FAKEFAKEFAKEFAKEFAKEFAKEFAKE"'):
        assert not _secrets(src), "test/publishable keys are meant to be hardcoded: %s" % src


def test_env_loaded_secret_never_fires():
    for src in ('import os\nAPI_KEY = os.environ["OPENAI_API_KEY"]\n',
                'import os\nAPI_KEY = os.environ.get("OPENAI_API_KEY", "")\n',
                'import os\nAPI_KEY = os.getenv("OPENAI_API_KEY")\n'):
        assert not _secrets(src), "the correct pattern must never be flagged: %s" % src


def test_runtime_concatenated_secret_does_not_fire():
    """Known evasion, out of scope for the first pass -- and confessed in
    BLIND_SPOTS rather than left implicit."""
    src = ('_A = "ghp_FAKEFAKEFAKEFAKE"\n_B = "FAKEFAKEFAKEFAKEFAKE"\n'
           'GITHUB_TOKEN = _A + _B\n')
    assert not _secrets(src), _secrets(src)


# --- the planted fixture -----------------------------------------------------

def test_planted_fixture_yields_exactly_three_findings_at_the_planted_lines():
    src = FIXTURE.read_text(encoding="utf-8")
    fs = scan_source(src, "secret_in_code_server.py")
    assert [f.check for f in fs] == ["secret-in-code"] * 3, fs
    assert sorted(f.line for f in fs) == [23, 27, 31], [(f.line, f.detail) for f in fs]
    assert all(f.severity == "high" for f in fs), fs


def test_planted_fixture_negative_control_stays_silent():
    """Line 38 loads OPENAI_API_KEY from the environment -- the correct
    pattern. A finding there would be the false red this check must not cry."""
    src = FIXTURE.read_text(encoding="utf-8")
    lines = src.splitlines()
    assert "os.environ.get" in lines[37], lines[37]
    assert not [f for f in scan_source(src, "f.py") if f.line == 38], "negative control fired"


if __name__ == "__main__":
    import traceback
    fns = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    p = 0
    for fn in fns:
        try:
            fn(); print("PASS", fn.__name__); p += 1
        except Exception:
            print("FAIL", fn.__name__); traceback.print_exc()
    print("\n%d/%d passed" % (p, len(fns)))
    sys.exit(0 if p == len(fns) else 1)
