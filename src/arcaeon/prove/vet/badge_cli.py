"""mcp_vet badge_cli -- the free `mcp-vet badge <path>` command (batch-100 item
85, 2026-09-05, PRODUCT_BRIEF_test_honesty_audit_2026-09-04.md step 2 of 5).

Ships THREE things a stranger can act on without paying anything or trusting
our word: (1) a self-contained Markdown badge line (an inline `data:` SVG --
no host, no network, so it renders the moment it is pasted into a README),
(2) a JSON block naming exactly what ran, on what, and how well THAT check
battery has been proven against its own fixtures, and (3) the origin note the
9/4 product brief asked to travel with the free CLI, verbatim, so credit rides
with the tool rather than living in a file nobody outside this repo opens.

Per `daniel_adoption_first_pricing_absorb_cost_2026-09-01`: this command is the
free, land-grab half of the sealed-scan plan (item 84) -- issuance free, grade
hard, failures public. It costs a few seconds of local CPU and no network call
and no LLM, so the per-run cost is effectively zero and there is nothing here
to absorb.

This is a self-report, not a certification -- same discipline `mcp_vet.badge`
already enforces structurally (REQUIRED fields, banned-verdict-word gate). The
`--receipt` flag adds attribution and tamper-evidence on top; it does not add
authority the scan did not already have.
"""
from __future__ import annotations

import base64
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from . import service as _service
from .badge import badge_report, render_svg, BadgeClaimError
from .checks import check_names
from .fixture_census import fixture_coverage

# --- the origin note (PRODUCT_BRIEF_test_honesty_audit_2026-09-04.md, section
# 8, "Proposed origin note"), reproduced VERBATIM, unedited. The brief itself
# The attribution reads "Nora / Arcaeon" here on purpose: the badge JSON is a
# public vendor surface, and Daniel already made this call for this package
# on 2026-09-04 when ORIGIN.md's wording was settled (his words, the public
# alias). The brief's private-name text is the same note before that call;
# this file follows ORIGIN.md, which is the version he approved.
ORIGIN_NOTE = (
    'Origin note, September 2026. The "third verdict" (a check with only two '
    'outcomes cannot report that it could not look, and converts its own '
    'failure into a finding) and the "wrong-layer positive control" (a '
    'passing control that exercises the channel but not the binding launders '
    'a false absence) were first stated and instrumented by Nora / '
    'Arcaeon on 2026-09-03 and 2026-09-04, in the theory note '
    'THIRD_VERDICT_THEORY_2026-09-03 and scar 161, with the detectors '
    'negative_control_audit.py and vacuous_pass_lint.py. The borrowed-index '
    'principle (an index that has to already know what it is hunting is the '
    'wrong index) was arrived at jointly with colonist-one and deep-seeker '
    'in the same week, and is credited to that exchange.'
)

# What this mark is and is not, printed at the foot of the JSON, not just of
# the SVG -- a reader who never opens the picture still gets the disclaimer.
NOT_A_CERTIFICATION = (
    "This badge is a self-report of mcp-vet's own checks against this exact "
    "artifact on this date. It is not a security certification and no human "
    "reviewed this server. Verify the receipt; do not trust the color."
)


def _count_pruned_test_fixture_files(root: Path) -> int:
    """How many otherwise-gradeable files (.py / .ts / .js) this scan excluded
    because they sit in a test/fixture directory or carry a test/fixture
    filename (service.PRUNE_DIRS / service._is_test_or_fixture, item 146).
    Distinct from `files_skipped`, which also carries non-gradeable files
    (.md, .json, ...) that were never in scope at all -- this count answers
    the narrower question the badge owes a reader: how much of THIS tree did
    the parity fix decide was the target's own test suite, not its product."""
    root = Path(root)
    if root.is_file():
        return 0
    n = 0
    for p in root.rglob("*"):
        if not p.is_file() or not _service._gradeable(p):
            continue
        rel = p.relative_to(root)
        if _service._is_test_or_fixture(rel.parts, p.name):
            n += 1
    return n


def _key_source() -> str:
    """Where the receipt signing key comes from: the env var, or an explicit
    key file a caller set. There is no default path and no ephemeral stand-in
    on this surface; with no key the badge is UNSIGNED and says so."""
    from . import receipts
    return receipts.key_source() or "none"


def _receipt_block(target_grade) -> dict:
    """Never returns an object that LOOKS signed when it is not. On any
    failure to actually produce a signature, `signed` is False and `status`
    says UNSIGNED plus the reason -- the same discipline `receipts.py` itself
    enforces (`sign_grade()` raises rather than degrading), carried through to
    this CLI's output instead of being allowed to become a bare exception."""
    from . import receipts
    grade_dict = json.loads(target_grade.to_json())
    if not receipts.RECEIPTS_AVAILABLE:          # backend first: the install hint
        return {"signed": False, "status": "UNSIGNED (%s)" % receipts.receipts_status_line()}
    try:
        seed = receipts.load_seed(ephemeral_ok=False)
    except receipts.NoReceiptKey as exc:
        return {"signed": False, "status": "UNSIGNED (%s)" % exc}
    except ValueError as exc:
        return {"signed": False, "status": "UNSIGNED (bad receipt key: %s)" % exc}
    try:
        rec = receipts.sign_grade(grade_dict, seed=seed)
    except receipts.ReceiptsUnavailable as exc:
        return {"signed": False, "status": "UNSIGNED (%s)" % exc}
    return {
        "signed": True,
        "status": "SIGNED",
        "format": rec["format"],
        "alg": rec["alg"],
        "signer_did": rec["payload"]["iss"],
        "key_source": _key_source(),
        "signature_b64": rec["signature_b64"],
        "pubkey_b64": rec["pubkey_b64"],
        "receipt": rec,
    }


def build_badge(path: str, *, receipt: bool = False,
                scanned_at: str | None = None) -> dict[str, Any]:
    """Scan `path` with the parity-fixed grader and build the full free-CLI
    badge payload: the governed BadgeReport fields, the pruned-fixture count,
    this repo's own must-hit/must-miss fixture census per check, the origin
    note, the honest-limits sentence, a Markdown badge line, and (if asked)
    a receipt block that is never silently absent."""
    ts = scanned_at or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    g = _service.scan_target(path)
    rep = badge_report(g, scanned_at=ts)
    svg = render_svg(rep)
    data_uri = "data:image/svg+xml;base64," + base64.b64encode(
        svg.encode("utf-8")).decode("ascii")
    markdown = "![mcp-vet scan report](%s)" % data_uri

    census = fixture_coverage(check_names())

    payload: dict[str, Any] = {
        "tool": "mcp-vet",
        "tool_version": __version__,
        "target": rep.target,
        "verdict": g.verdict,
        "checks_run": g.checks_run,
        "files_scanned": g.files_scanned,
        "files_scanned_count": len(g.files_scanned),
        "fixture_test_files_pruned": _count_pruned_test_fixture_files(path),
        "result": rep.result,
        "findings_by_severity": rep.findings_by_severity,
        "record_static": rep.record_static,
        "record_dynamic": rep.record_dynamic,
        "artifact_digest": rep.artifact_digest,
        "battery_digest": rep.battery_digest,
        "scanned_at": rep.scanned_at,
        "fixture_coverage": census,
        "origin_note": ORIGIN_NOTE,
        "not_a_certification": NOT_A_CERTIFICATION,
        "receipt": (_receipt_block(g) if receipt
                   else {"signed": False, "status": "UNSIGNED (--receipt not passed)"}),
    }
    return {"markdown": markdown, "svg": svg, "json": payload}


def seal_badge(badge_json: dict[str, Any], *,
               namespace: str | None = None) -> dict[str, Any]:
    """The paid half of `--sealed` (batch-100 item 84): witness the badge
    through the EXISTING ARCAEON_KEY credit lane
    (`arcaeon.remote.sealed_scan.seal`) -- one credit, no new billing rail.

    THE WITNESS'S PIN IS THE SEAL (seal-for-strangers, 2026-09-24). The hosted
    witness's POST /api/pin accepts {namespace, rows, chain} and nothing else
    (arcaeon-witness api/pin.js lines 5 and 486, lib/_store.js validatePin); it
    never receives, let alone verifies, a local Ed25519 signature. So a local
    signature is not what makes a seal a seal, and refusing to seal an
    unsigned badge only meant `seal` never worked for anyone without the
    maintainer's private key. An unsigned badge is now sealed and recorded as
    UNSIGNED; a badge signed with the caller's own MCP_VET_RECEIPT_KEY is
    recorded as SIGNED in addition, receipt and all.

    LAZY IMPORT, on purpose: `mcp-vet` must keep working with the connector
    not installed at all. A caller who never asked for `--sealed` never pays
    this import cost or this dependency."""
    receipt = badge_json.get("receipt") or {}
    signed = bool(receipt.get("signed"))
    try:
        from arcaeon.remote.sealed_scan import seal
    except ImportError as exc:
        return {
            "sealed": False,
            "reason": (
                "sealed scan refused: the arcaeon connector is not installed "
                "(%s). `pip install arcaeon` to use --sealed; the free badge "
                "above is unaffected and unchanged." % exc),
        }
    record = {
        "op": "mcp_vet_sealed_scan",
        "tool_version": badge_json.get("tool_version"),
        "target": badge_json.get("target"),
        "verdict": badge_json.get("verdict"),
        "artifact_digest": badge_json.get("artifact_digest"),
        "battery_digest": badge_json.get("battery_digest"),
        "scanned_at": badge_json.get("scanned_at"),
        "signed": "SIGNED" if signed else "UNSIGNED",
        "receipt": receipt.get("receipt") if signed else None,
    }
    # None = let seal() pick: mcp-vet-sealed-scans, else the key's own
    # <prefix>-sealed-scans once the witness names the prefix (ns-from-key).
    out = seal(record, namespace=namespace or None)
    out["signed"] = record["signed"]
    return out


def render_badge_text(built: dict[str, Any]) -> str:
    """The two things the CLI prints: the Markdown line, then the JSON block."""
    return built["markdown"] + "\n\n" + json.dumps(built["json"], indent=2,
                                                    ensure_ascii=False)
