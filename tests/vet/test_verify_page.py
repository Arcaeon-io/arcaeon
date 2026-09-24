"""M38 (2026-09-02): the verify page tells a stranger what the badge cannot
prove, and its blind-spot list is the scanner's own list, word for word."""
import html
import re

from arcaeon.prove.vet.grade import BLIND_SPOTS
from arcaeon.prove.vet.badge import RECEIPTED_NOT_REVIEWED
from arcaeon.prove.vet.verify_page import (render_verify_page, blind_spot_items, CANNOT_PROVE,
                                 BLIND_SPOTS_BEGIN, BLIND_SPOTS_END)


def _rendered_blind_spots(page: str) -> list[str]:
    block = page.split(BLIND_SPOTS_BEGIN, 1)[1].split(BLIND_SPOTS_END, 1)[0]
    return [html.unescape(m) for m in re.findall(r"<li>(.*?)</li>", block, re.DOTALL)]


def test_blind_spot_list_is_grade_blind_spots_word_for_word():
    page = render_verify_page(rendered_on="2026-09-02")
    assert _rendered_blind_spots(page) == list(BLIND_SPOTS)
    assert blind_spot_items() == list(BLIND_SPOTS)
    assert len(BLIND_SPOTS) > 0


def test_page_states_the_four_things_it_cannot_prove():
    page = render_verify_page(rendered_on="2026-09-02")
    titles = [t for t, _ in CANNOT_PROVE]
    # "Two checks on TypeScript" since 2026-09-04: except-returns-success got a
    # TS front end, so the old "one check" line stopped being true. The count in
    # the title is the claim being asserted, which is why it is spelled out.
    assert titles == ["Static read only", "Two checks on TypeScript",
                      "Blind spots are real and listed", "No runtime evidence"]
    for title, body in CANNOT_PROVE:
        assert html.escape(title) in page
        assert html.escape(body) in page


def test_page_leads_with_receipted_not_reviewed():
    page = render_verify_page(rendered_on="2026-09-02")
    assert RECEIPTED_NOT_REVIEWED in page
    assert "No human reviewed" in page
    assert "audit-record" in page                 # names the one TS check


def test_page_is_self_contained_and_deterministic():
    a = render_verify_page(receipt_id="r-1", artifact_digest="ab" * 32, rendered_on="2026-09-02")
    b = render_verify_page(receipt_id="r-1", artifact_digest="ab" * 32, rendered_on="2026-09-02")
    assert a == b
    assert "<script" not in a and "http://" not in a and "https://" not in a
    assert "r-1" in a and "sha256:" + "ab" * 32 in a


def test_page_without_receipt_says_so():
    page = render_verify_page(rendered_on="2026-09-02")
    assert "No receipt identifier was supplied" in page


def test_hostile_receipt_id_is_escaped_not_injected():
    """RED CONTROL (item 33, 2026-09-04): render_verify_page echoes receipt_id
    and artifact_digest as-is except for html.escape(). Nothing ever proved
    that escaping fires on hostile input -- and this page is served to a
    stranger who followed a badge's verify link, so receipt_id is effectively
    attacker-influenced. Plant a script tag and confirm it comes back escaped,
    not live."""
    hostile = "<script>alert(1)</script>"
    page = render_verify_page(receipt_id=hostile, rendered_on="2026-09-02")
    assert hostile not in page, "hostile receipt_id was NOT escaped -- injectable"
    assert html.escape(hostile) in page, "escaped form of the planted receipt_id is missing"
