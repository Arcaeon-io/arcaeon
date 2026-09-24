"""mcp_vet.badge — the badge report schema (R12, 2026-09-01).

A TargetGrade (service.scan_target) is the raw scan. A BADGE report is the
public, receipt-ready statement built from it — and it is governed, field for
field, by BADGE_CLAIM_LANGUAGE_SPEC: the one sentence a badge may mean is
"these specific checks ran against this exact artifact on this date and
produced this result, and here is a receipt you can recompute."

Two disciplines are enforced structurally here, not left to marketing:
  1. REQUIRED fields (checks_run, artifact_digest, scanned_at, result,
     battery_digest, receipt_id, verify_url) are all present — a badge that omits any of them
     is not a lab report, it is a mood.
  2. BANNED shapes: the badge carries NO safety/endorsement verdict. `result`
     restates the scan's own terms (finding counts by severity), never "safe",
     "certified", "approved". `assert_no_banned_language` is the runnable
     gate that proves a rendered badge/copy string does not overclaim.

`scanned_at` and the receipt fields are passed IN (not generated here) so the
report is a pure, testable transform: same grade + same timestamp + same
receipt = same bytes. The timestamp's non-determinism lives at the call site,
never inside the schema.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, asdict, field
from pathlib import Path

from . import __version__

# --- battery digest (R16b, 2026-09-01) ---------------------------------------
# colonist-one's attack on the R1 theorycraft post: "nothing binds the battery."
# A badge said WHICH check names ran, but two builds of mcp-vet with the same
# version string and different check bodies would have produced byte-identical
# `checks_run` fields. So the report now carries a digest of the battery ITSELF:
# sha256 over the tool version plus the exact bytes of every module that
# defines or registers a check. Change one byte of one check and the digest
# moves; a verifier recomputes it from the wheel it holds. Modules listed
# explicitly, not globbed, so a stray file cannot silently join the battery.
_BATTERY_MODULES = ("checks.py", "grade.py", "service.py", "ts_checks.py")  # ts_checks joined 0.0.16


def battery_digest() -> str:
    h = hashlib.sha256()
    h.update(("mcp-vet " + __version__ + "\n").encode("utf-8"))
    here = Path(__file__).resolve().parent
    for name in _BATTERY_MODULES:
        fp = here / name
        h.update((name + "\n").encode("utf-8"))
        h.update(fp.read_bytes() if fp.exists() else b"<missing>")
        h.update(b"\n")
    return h.hexdigest()

# Words a badge must never use as a verdict on the scanned server. Matched
# case-insensitively as whole words. "verified" is allowed ONLY in the process
# sense ("checks verified to have run"), so it is not banned outright here —
# the copy test (assert_no_banned_language) flags the dangerous STANDALONE uses.
_BANNED_VERDICT_WORDS = (
    "certified", "certification", "safe", "secure", "trusted", "approved",
    "endorsed", "vetted", "guaranteed",
)
_BANNED_RE = re.compile(
    r"\b(" + "|".join(re.escape(w) for w in _BANNED_VERDICT_WORDS) + r")\b",
    re.IGNORECASE,
)


class BadgeClaimError(ValueError):
    """Raised when a badge would overclaim (missing required field or banned
    language). A badge that cannot be built honestly must not be built."""


# --- what the mark means, in one phrase (M37, 2026-09-02) --------------------
# The badge records WHICH CHECKS RAN on WHICH BYTES. It does not say a human
# reviewed the server, and it must not read as if one did. The phrase below is
# drawn on the SVG footer and printed at the top of the verify page, and the
# copy test in test_badge.py asserts it verbatim in both places, so the wording
# cannot drift apart between the picture and the page that explains it.
RECEIPTED_NOT_REVIEWED = "receipted, not reviewed"

# The two footer lines drawn under the rows. Chosen to fit a 460px-wide badge at
# 9px sans (about 90 characters per line); the exact phrase leads line one.
FOOTER_LINE_1 = (RECEIPTED_NOT_REVIEWED
                 + ": this mark records which checks ran on which bytes.")
FOOTER_LINE_2 = ("No human reviewed this server. Not a safety certification. "
                 "Verify the receipt.")

# --- the runtime line: never merged with the static line (M35) ---------------
# A grade carries `record_static` (what the scanner INFERRED from bytes) and
# `record_dynamic` (what a runner OBSERVED, or None). The badge renders them as
# two separate strings and never folds one into the other: a static-only grade
# draws "runtime: not confirmed" no matter how good its static inference looks.
_RUNTIME_NOT_CONFIRMED = "runtime: not confirmed (no runner ran)"
_RUNTIME_OBSERVED = "runtime: record observed by runner"
_RUNTIME_ABSENT = "runtime: no record observed by runner"

# Words that CLAIM runtime confirmation. A badge built from a static-only grade
# must not contain any of these in its static line, and `_assert_no_runtime_claim`
# proves it on every build rather than trusting the string builders.
_RUNTIME_CLAIM_RE = re.compile(
    r"\b(observed|confirmed|runner|launched|executed)\b", re.IGNORECASE)


def _static_line(record_static) -> str:
    """`record_static` -> one sentence in the scanner's own terms. Says
    'inferred' in every branch, because that is all a static read can be."""
    rs = record_static if isinstance(record_static, dict) else {}
    if not rs:
        return "static: not inferred (grade carries no record_static)"
    if not rs.get("asked"):
        return "static: not asked (no served handler in the graded bytes)"
    met = rs.get("gates_met")
    if rs.get("presence"):
        return f"static: record write inferred from bytes ({met}/4 gates)"
    return "static: no record write inferred from bytes (0/4 gates)"


def _dynamic_line(record_dynamic) -> str:
    """`record_dynamic` -> one sentence. None (the static-only case) is the
    ONLY input that yields the not-confirmed line, and it is the default."""
    if not isinstance(record_dynamic, dict) or not record_dynamic:
        return _RUNTIME_NOT_CONFIRMED
    if record_dynamic.get("evidence") != "dynamic" or "observed" not in record_dynamic:
        raise BadgeClaimError(
            "record_dynamic is present but is not a runner observation "
            "(evidence != 'dynamic' or no 'observed' key) — refusing to draw it")
    return _RUNTIME_OBSERVED if record_dynamic["observed"] else _RUNTIME_ABSENT


def _assert_no_runtime_claim(static_line: str) -> None:
    hits = sorted(set(m.group(0).lower() for m in _RUNTIME_CLAIM_RE.finditer(static_line)))
    if hits:
        raise BadgeClaimError(
            "static record line claims runtime evidence (%s) — the static and "
            "dynamic record fields are never merged" % ", ".join(hits))


@dataclass
class BadgeReport:
    # --- REQUIRED by the claim-language spec ---
    checks_run: str            # human string: "mcp-vet <ver>: <check names>"
    artifact_digest: str       # sha256 of the exact scanned source/tree
    scanned_at: str            # ISO-8601 date/time the scan ran (passed in)
    result: str                # the scan's OWN terms, never a safety verdict
    battery_digest: str        # sha256 binding the exact check battery (R16b)
    receipt_id: str            # ledger receipt id (empty until R13 chains it)
    verify_url: str            # public recompute URL (empty until R15)
    # --- context (not a claim, just provenance) ---
    tool: str = "mcp-vet"
    tool_version: str = __version__
    target: str = ""
    findings_by_severity: dict = field(default_factory=dict)
    # --- record evidence, two lines, never merged (M35, 2026-09-02) ---
    record_static: str = ""    # what the scanner inferred from bytes
    record_dynamic: str = ""   # what a runner observed; "not confirmed" by default
    schema: int = 3            # 3 = record_static / record_dynamic (2026-09-02)

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(asdict(self), indent=indent, ensure_ascii=False)


_REQUIRED = ("checks_run", "artifact_digest", "scanned_at", "result", "battery_digest")


def _result_line(findings: list, verdict: str) -> str:
    """The scan's outcome in ITS OWN terms — severity counts + the neutral
    verdict string. Never a safety claim. 'no findings in checked classes' is
    the strongest thing sayable, and it already means exactly, and only, itself."""
    counts: dict = {}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    if not findings:
        return verdict  # e.g. "no findings in checked classes"
    parts = ", ".join(f"{counts[s]} {s}" for s in ("high", "medium", "low", "info") if s in counts)
    return f"{verdict} ({parts})"


def badge_report(target_grade, *, scanned_at: str,
                 receipt_id: str = "", verify_url: str = "") -> BadgeReport:
    """Build the canonical badge report from a TargetGrade. `scanned_at` is
    required and passed in (keeps the transform pure). receipt_id/verify_url are
    filled once the ledger receipt (R13) and verify surface (R15) exist; until
    then they are honestly empty, which the badge states rather than fakes."""
    g = target_grade
    checks = ", ".join(g.checks_run)
    # Read with getattr: a TargetGrade (service.py) predates the two record
    # fields and a Grade (grade.py) carries them. Absent means "not inferred"
    # and "not confirmed" — never a guess in either direction.
    static_line = _static_line(getattr(g, "record_static", None))
    dynamic_line = _dynamic_line(getattr(g, "record_dynamic", None))
    rep = BadgeReport(
        checks_run=f"mcp-vet {g.tool_version}: {checks}",
        artifact_digest=g.source_sha256,
        scanned_at=scanned_at,
        result=_result_line(g.findings, g.verdict),
        battery_digest=battery_digest(),
        receipt_id=receipt_id,
        verify_url=verify_url,
        target=g.target,
        findings_by_severity=_severity_counts(g.findings),
        record_static=static_line,
        record_dynamic=dynamic_line,
    )
    _assert_required(rep)
    # The result line is machine-built from the scan; still, prove it never
    # overclaims — a check that costs nothing and guards the one thing that
    # kills the product.
    assert_no_banned_language(rep.result, where="result")
    _assert_no_runtime_claim(rep.record_static)
    return rep


def _severity_counts(findings: list) -> dict:
    out: dict = {}
    for f in findings:
        out[f["severity"]] = out.get(f["severity"], 0) + 1
    return out


def _assert_required(rep: BadgeReport) -> None:
    d = asdict(rep)
    missing = [k for k in _REQUIRED if not str(d.get(k, "")).strip()]
    if missing:
        raise BadgeClaimError(
            f"badge missing required field(s): {', '.join(missing)} — "
            "a badge that omits what/when/which-bytes is not a lab report")


def assert_no_banned_language(text: str, where: str = "text") -> None:
    """Runnable copy test: raise if `text` uses a banned verdict word. Use on
    every rendered badge string AND on page/marketing copy before it ships.
    The single exception the spec allows — 'verified' meaning 'checks verified
    to have run' — is not in the banned set; the standalone status words are."""
    hits = sorted(set(m.group(0).lower() for m in _BANNED_RE.finditer(text)))
    if hits:
        raise BadgeClaimError(
            f"{where} overclaims — banned verdict word(s): {', '.join(hits)}. "
            "A badge states what was checked, not that the server is safe/endorsed.")


# --- SVG render (R14, 2026-09-01) --------------------------------------------
# A badge people can SEE. Pure function of a BadgeReport — no network, no fonts
# to fetch (system sans stack), deterministic given the same report. The visual
# NEVER carries a word the report can't: it renders the same governed fields,
# runs the copy test on every drawn string, and colors by the scan's OWN result
# (clean / findings), never a safety verdict. Colors are status-neutral: slate
# for clean, amber for findings — not green="safe"/red="danger", which would
# smuggle the banned verdict back in through the palette.

def _esc(s: str) -> str:
    return (str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            .replace('"', "&quot;"))


# The third accent (R-badge, 2026-09-05, item 85): a target with ZERO
# gradeable files (service.NO_GRADEABLE_FILES) is not the same claim as a
# target that was scanned and came back clean, and drawing them the same
# color would let a tests-only repo borrow the visual weight of a real pass.
# Imported lazily inside render_svg to avoid a badge<->service import cycle at
# module load time (service does not import badge, but there is no reason to
# risk it as the package grows).
_NO_GRADEABLE_ACCENT = "#6b7280"   # neutral grey, distinct from clean-slate and findings-amber


def render_svg(rep: BadgeReport, *, width: int = 460) -> str:
    """Render a BadgeReport to a self-contained SVG string. Deterministic; every
    drawn text run passes assert_no_banned_language first, so a badge image can
    never overclaim where the JSON did not."""
    from .service import NO_GRADEABLE_FILES
    clean = not rep.findings_by_severity
    if rep.result == NO_GRADEABLE_FILES:
        accent = _NO_GRADEABLE_ACCENT              # grey: nothing was gradeable, never a pass
    else:
        accent = "#64748b" if clean else "#d97706"  # slate / amber, NOT green/red
    # lines rendered, each gated
    result_line = rep.result
    # The record lines default to the honest empties when a report predates
    # them (schema 2), so an old report still draws without implying a runner.
    static_line = rep.record_static or _static_line(None)
    dynamic_line = rep.record_dynamic or _RUNTIME_NOT_CONFIRMED
    for drawn in (result_line, rep.checks_run, static_line, dynamic_line):
        assert_no_banned_language(drawn, where="svg")
    _assert_no_runtime_claim(static_line)
    digest_short = rep.artifact_digest[:12] if rep.artifact_digest else "?"
    receipt = rep.receipt_id or "(unchained)"
    rows = [
        ("checks", rep.checks_run),
        ("artifact", f"sha256:{digest_short}…"),
        ("scanned", rep.scanned_at),
        ("battery", f"sha256:{rep.battery_digest[:12]}…" if rep.battery_digest else "?"),
        ("result", result_line),
        ("record", static_line),      # two rows, two facts, never one
        ("record", dynamic_line),
        ("receipt", receipt),
    ]
    h = 34 + len(rows) * 20 + 26      # two footer lines (M37)
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{h}" '
        f'viewBox="0 0 {width} {h}" role="img" aria-label="mcp-vet scan report">',
        f'<rect x="0.5" y="0.5" width="{width-1}" height="{h-1}" rx="8" '
        f'fill="#0f172a" stroke="{accent}"/>',
        f'<rect x="0" y="0" width="6" height="{h}" rx="0" fill="{accent}"/>',
        f'<text x="18" y="24" font-family="system-ui,Segoe UI,Helvetica,Arial,sans-serif" '
        f'font-size="13" font-weight="700" fill="#e2e8f0">mcp-vet scan report</text>',
    ]
    y = 46
    for label, val in rows:
        parts.append(
            f'<text x="18" y="{y}" font-family="system-ui,Segoe UI,Helvetica,Arial,sans-serif" '
            f'font-size="11" fill="#94a3b8">{_esc(label)}</text>')
        parts.append(
            f'<text x="96" y="{y}" font-family="ui-monospace,Consolas,monospace" '
            f'font-size="11" fill="#e2e8f0">{_esc(val)}</text>')
        y += 20
    # Footer (M37): two lines, the exact phrase first. Drawn verbatim from the
    # module constants so a copy-test on the constants is a test on the badge.
    for i, line in enumerate((FOOTER_LINE_1, FOOTER_LINE_2)):
        parts.append(
            f'<text x="18" y="{h - 20 + i * 12}" font-family="system-ui,sans-serif" '
            f'font-size="9" fill="#64748b">{_esc(line)}</text>')
    parts.append("</svg>")
    return "\n".join(parts)
