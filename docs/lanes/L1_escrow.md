# L1: agent escrow, released only on a verified receipt

Mock rail: nothing is held or moved. Every hold, release and refund is a row
on each side's own deal ledger, saying what the rule decided. No money is
authorized, captured, held or returned anywhere.

## Who buys it

Tool sellers and buying agents on agent-payment marketplaces: a buying agent
pays a few cents for one tool call and wants that payment to go through only
when the call it paid for actually happened as recorded. The seller wants the
same rule, so a clean delivery is paid without argument.

## Price shape (credits)

The hold itself is free. The charge is per settled hold: the release decision
(look at the seller's receipt, apply the rule) costs a fraction of a credit.
It settles on credits today, and on an agent payment rail when one is real.
No numbers here: exact credit counts are for the pricing council.

## What the demo proves

`py examples/escrow_two_agents_demo.py` runs two local agents in one process,
with no network and everything under a throwaway directory.

1. The buyer records a mandate with a recourse tier, both sides commit, and
   both hold the price with the release criteria frozen at hold time.
2. The seller answers the call and issues a call receipt on its own ledger.
3. Run 1, clean response: each side's settle finds the receipt matching and
   the hold is RELEASED (MATCHED) on both tapes.
4. Run 2, the seller doctors the response after the receipt was issued: the
   receipt no longer recomputes, and the hold is REFUNDED (ALTERED) on both
   tapes.

So: a release happens only on a receipt the rule itself verified, and a
one-field edit after the fact flips it to a refund. Each step is a deal row
both sides can check, and `arcaeon deal dispute` compares the two tapes.

What it does not prove: a receipt is delivery evidence, not quality evidence.
A release says the named call happened as recorded, not that its answer was
right.

## How it fails

- The marketplaces bundle it. If agent-payment platforms ship their own
  configurable escrow, a separate release rule has no buyer.
- We drift into holding funds. Holding other people's money is custody, and
  custody is a licensing question for the owner and a lawyer, not for this
  package. The rule ships; the vault does not.

## Mock rail

Nothing is held or moved. Rail adapters (card manual-capture, settle on
release over an agent payment rail) are separate work, also mock until a
decision says otherwise.
