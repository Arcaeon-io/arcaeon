"""The front door: the one object an agent reads first.

`arcaeon_front_door` (the MCP tool) and `arcaeon mcp --print-front-door` (the
CLI) both return `front_door()`, so an agent and a human checking it without an
MCP client see the same thing. It says what works here with no key, what a key
adds and what that costs, where a key comes from, what these tools can and
cannot prove, and where the offers document lives.

EVERY PRICE IS READ, NONE IS TYPED. The per pin price, the smallest pack and
the grant sentence come from the offers document (`arcaeon.remote.load_offers`:
the one handed in, else `$ARCAEON_OFFERS_FILE`, else the bundled snapshot). The
offers document carries no calendar window and neither does this.

REGISTRATION IS DARK until the offers document switches it on
(`arcaeon.remote.registration`). Dark, the key comes from the pricing page and
the object carries no word of registering; on, it carries the one link.

THE CAN AND CANNOT LIST is a copy of the site's can-and-cannot page, item for
item. The package has no file the site builds from, so the copy lives here and
`tests/test_front_door.py` holds it to the site page (named by
`$ARCAEON_SITE_CAN_AND_CANNOT`), naming the first item that differs.

Imports nothing from the MCP SDK and opens no connection, so the CLI print
works on the base install.
"""
from __future__ import annotations

from typing import Any

SCHEMA = "arcaeon-front-door/v1"
TOOL_NAME = "arcaeon_front_door"
CAN_AND_CANNOT_URL = "https://arcaeon.io/can-and-cannot"

# The free tools, grouped by what an agent wants from them. Every free tool on
# the server appears exactly once (tests/test_front_door.py holds this to
# arcaeon.mcp.server.FREE_TOOLS).
NO_KEY_GROUPS: dict[str, dict[str, Any]] = {
    "record": {
        "what": "Write a hash chained record of what an agent did, or of a deal and its mandate.",
        "tools": ["ledger_append", "ledger_prove_my_conduct", "ledger_declare_break",
                  "deal_mandate", "deal_commit"],
    },
    "verify": {
        "what": ("Check a record: yours, or an exported log another agent hands you. Check a "
                 "deal, a mandate, or MCP server source before you connect to it."),
        "tools": ["ledger_verify", "ledger_verify_peer_ledger", "deal_dispute",
                  "mandate_check", "vet_scan", "vet_grade", "vet_audit_verify"],
    },
    "evidence_pack": {
        "what": "Build an evidence pack from a record, and verify a pack someone hands you.",
        "tools": ["evidence_pack_build", "evidence_pack_verify"],
    },
    "second_reader": {
        "what": "Record a second reading of a claim, and compare two readings.",
        "tools": ["second_read_submit", "second_read_compare"],
    },
    "about": {
        "what": "This object, and the versions, paths and free and paid split of this server.",
        "tools": [TOOL_NAME, "arcaeon_status"],
    },
}

KEY_TOOLS = ["witness_pin", "witness_renew"]
KEY_ENV_VAR = "ARCAEON_KEY"

# Copied item for item from the site's can-and-cannot page (tags stripped).
CAN_AND_CANNOT: dict[str, Any] = {
    "cannot": [
        {"heading": "The record and the witness",
         "items": [
             "That a record was never rewritten. Anyone who can write the file can still "
             "change it. An edit to one row breaks the chain, and the check names the line. "
             "Rewrite every row from the edited one onward and the chain checks out again, "
             "unless a pin holds the old head.",
             "That the rows are true. The chain records whatever was written, true or not. "
             "To tie a row to a fact someone can fetch again, store the fact's digest in the row.",
             "That nothing was cut off the end. Cut the newest rows off and what is left still "
             "checks out. No chain catches that alone. A pin does, as of the last pin.",
             "Who wrote a row. That is data in the row, not a signature. Someone who rewrites "
             "the whole log from the first row can rewrite that too.",
             "A second, unrelated party. The hosted witness is one witness, and we operate it. "
             "A pin there is not a stranger vouching for you.",
             "Who ran the witness at the time of a pin. Today you take our word for it. That "
             "stays true until we publish a custody record, and we have not yet.",
             "That the daily anchor checked anything. It is a clock, not a party. It fixes when "
             "the pins existed, not whether they were right.",
             "That you can rerun the session. That takes the model, the tool server and their "
             "state at the time. You get the request and response digests instead, so you can "
             "check given bytes are the ones that crossed.",
         ]},
        {"heading": "Two records of the same work",
         "items": [
             "MATCHED means two recorders agree. A colluding agent side and tool side can write "
             "two agreeing tapes of a lie.",
             "A call that crossed neither recorded seam leaves no row on either tape.",
             "Without a pin, both tapes cut short or rewritten in agreement still match.",
         ]},
        {"heading": "The evidence pack, the second reader and the mandate gate",
         "items": [
             "A pack is not a statement that any law or standard is met, and it does not show "
             "the agent behaved well. It shows what was written was not changed after pinning.",
             "When two readers read a sentence the same way, that does not make the claim "
             "right. Two models from one family, or one vendor, agree more for that reason alone.",
             "The mandate gate records who a mandate speaks for and does not check it: the proxy "
             "cannot see who is behind the agent. A call that goes around the proxy is not "
             "checked.",
             "vet and badge report what their own checks found in the bytes they read. They are "
             "not a review by a person and not a safety certification.",
         ]},
    ],
    "can": [
        "Nothing was changed in the middle. An edit, a deletion or a reorder breaks every later "
        "link, and the check names the first broken line.",
        "Nothing was cut after a pin. Once a witness holds your head, a shorter or rewritten log "
        "no longer matches it. The longest gap between pins is your real exposure.",
        "Two tapes line up, or where they do not. Each step both tapes should hold comes back "
        "MATCHED, MISSING or ALTERED, with the fields that differ.",
        "What could not be looked at. A missing, unreadable or empty file is COULD NOT LOOK. It "
        "is never a pass.",
    ],
}


def _offers(offers: dict | None) -> dict | None:
    if offers is not None:
        return offers
    from arcaeon.remote import load_offers
    try:
        doc = load_offers()
    except (OSError, ValueError):
        return None
    return doc if isinstance(doc, dict) else None


def _hosted_witness(doc: dict | None) -> dict:
    for prod in (doc or {}).get("products", []) or []:
        if isinstance(prod, dict) and prod.get("id") == "hosted-witness":
            return prod
    return {}


def _mini(witness: dict) -> dict:
    for tier in witness.get("tiers", []) or []:
        if isinstance(tier, dict) and tier.get("plan") == "mini":
            return tier
    return {}


def front_door(offers: dict | None = None) -> dict:
    """The front door object. Pure: reads the offers document, opens nothing."""
    from arcaeon import __version__
    from arcaeon.remote.offers import CATALOG_URL, PRICING_URL, WITNESS_ENDPOINT
    from arcaeon.remote.registration import registration_line, registration_link

    doc = _offers(offers)
    witness = _hosted_witness(doc)
    mini = _mini(witness)
    grant = witness.get("registration_grant")
    grant = grant if isinstance(grant, dict) else {}
    endpoint = witness.get("endpoint") or WITNESS_ENDPOINT

    with_a_key: dict[str, Any] = {
        "key_env_var": KEY_ENV_VAR,
        "tools": list(KEY_TOOLS),
        "what_it_does": (f"Pins your ledger head with the hosted witness at {endpoint}, a party "
                         "you cannot advance. A pin is the one thing that catches a record cut "
                         "short, as of the last pin."),
        "price_per_pin_usd": mini.get("price_per_pin_usd"),
    }
    if mini:
        with_a_key["smallest_pack"] = {
            "plan": mini.get("plan"),
            "price_usd": mini.get("price_usd"),
            "pins": mini.get("cap"),
            "checkout": mini.get("checkout"),
        }
    statement = grant.get("statement")
    if isinstance(statement, str) and statement.strip():
        with_a_key["grant"] = f"Every new key comes with {statement.strip()}. A credit is one pin."
        if isinstance(grant.get("status"), str):
            with_a_key["grant_status"] = grant["status"]

    link = registration_link(doc) if doc is not None else None
    if link is not None:
        get_a_key = {
            "url": link,
            "how": (f"{registration_line(doc)} Then set {KEY_ENV_VAR} in this server's "
                    "environment and call again."),
        }
    else:
        get_a_key = {
            "url": PRICING_URL,
            "how": (f"Keys and credit packs are on the pricing page; you pay on Stripe's page. "
                    f"Then set {KEY_ENV_VAR} in this server's environment and call again."),
        }

    no_key: dict[str, Any] = {
        "summary": ("The local core is free, needs no key and no account, and every check "
                    "runs on this machine."),
        "network": ("None of these tools opens a connection, except evidence_pack_verify "
                    "when you pass remote true, which reads the public witness."),
    }
    for name, group in NO_KEY_GROUPS.items():
        no_key[name] = {"what": group["what"], "tools": list(group["tools"])}

    return {
        "schema": SCHEMA,
        "arcaeon_version": __version__,
        "no_key": no_key,
        "with_a_key": with_a_key,
        "get_a_key": get_a_key,
        "can_and_cannot": {
            "source": CAN_AND_CANNOT_URL,
            "cannot": [{"heading": s["heading"], "items": list(s["items"])}
                       for s in CAN_AND_CANNOT["cannot"]],
            "can": list(CAN_AND_CANNOT["can"]),
        },
        "offers_url": CATALOG_URL,
    }
