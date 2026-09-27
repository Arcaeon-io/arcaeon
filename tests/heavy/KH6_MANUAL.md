# KH6 manual check (Chrome, five lines)

1. In a folder holding a ledger, an evidence pack, two readings ledgers and a mandate file, run `arcaeon open`; Chrome opens `http://127.0.0.1:8787/?t=<code>` and lands on `http://127.0.0.1:8787/` with no `?t=` left in the address bar (paste the same link again: it must say the link was already used).
2. Click Status, Verify, Evidence packs, Second read and Mandate in the top bar; each loads, the current one is marked, and DevTools Console shows no CSP violation and Network shows only 127.0.0.1 requests.
3. On Verify pick an empty or unreadable `.jsonl` and click Check it: COULD NOT LOOK must be visible, not green, with its reason; a good ledger shows VERIFIED in green; no `C:\` path appears anywhere on the page.
4. On Evidence packs click Check this pack for each pack: the three counts VERIFIED, BROKEN, COULD NOT LOOK sit side by side; on Second read compare two ledgers and see both reader ids per disagreement; on Mandate pick the mandate and its ledger and see the sentences plus the outside and COULD NOT LOOK rows.
5. Back on Status, "Open COULD NOT LOOKs" shows the count from steps 3 and 4 in the not-green style, and View Source shows no inline `<script>` body, no `style=` and no `on...=` attribute.
