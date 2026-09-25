"""B042: the bundled offers.json snapshot carries the site's corrected note on
the Witnessed plan. The site copy said the credit packs went live on
2026-08-16; the package still said "NOT yet purchasable" a month later.

The comparison needs the site checkout: ARCAEON_SITE_ROOT, or a sibling
checkout at ../<any>/projects/arcaeon_site. With neither, it skips and says
why. The stale-phrase check runs everywhere.
"""
import json
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "src" / "arcaeon" / "remote" / "offers.json"


def _site_offers() -> Path | None:
    root = os.environ.get("ARCAEON_SITE_ROOT")
    candidates = [Path(root)] if root else sorted(ROOT.parent.glob("*/projects/arcaeon_site"))
    for c in candidates:
        p = c / ".well-known" / "offers.json"
        if p.is_file():
            return p
    return None


def _witnessed_note(cat: dict) -> str:
    prod = next((p for p in cat["products"] if p.get("id") == "hosted-witness"), None)
    assert prod is not None, "hosted-witness is gone from offers.json"
    tier = next((t for t in prod["tiers"] if t.get("plan") == "witnessed"), None)
    assert tier is not None, "the Witnessed tier is gone from hosted-witness"
    return tier["note"]


def test_the_package_no_longer_says_not_yet_purchasable():
    assert "NOT yet purchasable" not in PACKAGE.read_text(encoding="utf-8")


def test_the_package_note_matches_the_site_note():
    site = _site_offers()
    if site is None:
        pytest.skip("no site checkout: set ARCAEON_SITE_ROOT (or keep one at "
                    "../<any>/projects/arcaeon_site) to compare the notes")
    ours = _witnessed_note(json.loads(PACKAGE.read_text(encoding="utf-8")))
    theirs = _witnessed_note(json.loads(site.read_text(encoding="utf-8")))
    assert ours == theirs
