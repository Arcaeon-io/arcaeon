"""Item 144 (2026-09-05): the receipt signer's did:key must actually be
published, not just mintable. `mcp_vet.receipts` can sign a receipt with the
persistent key at any time; that is worthless to a stranger unless the
PUBLIC half of that same key shows up somewhere they did not have to trust
our word to find. This test is the tripwire: a fresh `badge --receipt` run
must name a signer_did that is present, as an active mcp_vet_receipt entry,
in the published .well-known key document -- read from the repo path, the
same file arcaeon_site serves.

Deliberately reads the FILE, not a copy pasted into this test: a rotation
that updates the persistent key but forgets to republish the doc (or a typo
in the copy) is exactly the gap this exists to catch, and a hard-coded
expected did:key would not catch it.
"""
import json

import pytest
from pathlib import Path

from arcaeon.prove.vet.badge_cli import build_badge

# arcaeon merge: the published key doc lives in the site checkout, not in this
# repo. ARCAEON_SITE_ROOT names that checkout; unset, every test here skips.
import os as _os
_SITE_ROOT = _os.environ.get("ARCAEON_SITE_ROOT")
_WELL_KNOWN = (Path(_SITE_ROOT or ".") / ".well-known" / "arcaeon"
               / "snapshot-signing-keys.json")
pytestmark = pytest.mark.skipif(
    not _SITE_ROOT, reason="ARCAEON_SITE_ROOT is not set (no site checkout holding the key doc)")

_CLEAN = "def helper(x):\n    return x.upper()\n"


def _published_mcp_vet_receipt_dids() -> list[str]:
    if not _WELL_KNOWN.exists():
        return []
    doc = json.loads(_WELL_KNOWN.read_text(encoding="utf-8"))
    return [
        entry.get("did_key")
        for entry in doc.get("keys", [])
        if entry.get("purpose") == "mcp_vet_receipt"
        and entry.get("status") == "active"
        and entry.get("did_key")
    ]


def test_well_known_doc_is_present_and_has_an_active_mcp_vet_receipt_entry():
    assert _WELL_KNOWN.exists(), (
        "%s does not exist -- item 144 was supposed to publish the mcp_vet "
        "receipt signer's public key here" % _WELL_KNOWN)
    assert _published_mcp_vet_receipt_dids(), (
        "the .well-known doc has no active entry with "
        "purpose=='mcp_vet_receipt'")


def test_fresh_badge_receipt_signer_id_is_in_the_published_key_doc(tmp_path):
    # The signer key lives OUTSIDE the repo (env var, else
    # an explicit key file). Without it, build_badge
    # signs with a fresh ephemeral key whose DID is correctly not in the
    # published doc -- an environment gap, not a stale key doc. Skip precisely
    # on that precondition instead of asserting into it (mirror CI, 2026-09-06).
    import os

    from arcaeon.prove.vet.receipts import RECEIPT_KEY_ENV, RECEIPT_KEY_FILE
    if not os.environ.get(RECEIPT_KEY_ENV) and not (RECEIPT_KEY_FILE and RECEIPT_KEY_FILE.exists()):
        pytest.skip("no receipt signing key on this machine (env unset, key file "
                    "absent): a fresh ephemeral signer is expected to be unpublished")
    (tmp_path / "server.py").write_text(_CLEAN, encoding="utf-8")
    built = build_badge(str(tmp_path), receipt=True)
    receipt = built["json"]["receipt"]
    assert receipt["signed"] is True, (
        "badge --receipt did not sign: %s" % receipt.get("status"))
    signer_did = receipt["signer_did"]

    published = _published_mcp_vet_receipt_dids()
    assert signer_did in published, (
        "fresh receipt signer %r is not among the published mcp_vet_receipt "
        "did:key entries %r in %s -- the persistent key rotated (or was "
        "never provisioned) without the .well-known doc being republished"
        % (signer_did, published, _WELL_KNOWN))
