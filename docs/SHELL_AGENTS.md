# Shell agents: one command for a sealed record of the memory folder

An agent that runs in a shell (a coding agent, a scripted loop, anything that
can run a command) usually keeps what it remembers in a folder of files. This
page is the front door for that agent: one command, pointed at that folder,
starts a record of it that the agent cannot quietly rewrite.

## The three lines

```console
pip install "arcaeon>=0.11.0"
arcaeon start ./memory
arcaeon start ./memory
```

The second line starts the record. The third is the same command again, run
after the next session: it adds a row only when a file changed, and writes
nothing when none did. `./memory` stands for whatever folder your agent keeps
its memory in. No key, no account, no network.

## What it does

`arcaeon start <memory folder>` reads every file in the folder, hashes it
(the bytes are never copied), and writes one row to a hash-chained record: each
file's path and sha256, and what was added, changed or removed since the row
before. Then it pins the record's head in a local pin file. That is what
"sealed" means on this page: chained row to row, with the head pinned, so a row
changed later, or rows cut off the end, are found. It is not the paid `seal`
verb, and nothing is sent anywhere.

- **Safe to run twice.** No change in the folder, no row. Run it from a hook at
  the end of every session, or by hand, or twice by mistake.
- **Checks before it writes.** A record that does not verify, or one cut short
  against its own pins, is BROKEN, exit 1, and nothing is added on top. Keep it
  as evidence; move its folder aside to start a new record.
- **Out of the agent's way.** The record and its pins live under
  `~/.arcaeon/memory/<id>/` (`ARCAEON_HOME` moves `~/.arcaeon`), never inside
  the memory folder, so the agent does not read its own record as memory.
- **Plain words.** It prints sentences, not JSON, and the exit code is the one
  table every verb uses: 0 kept, 1 BROKEN, 2 bad usage, 3 COULD NOT LOOK.
- **Anyone can check it.** The last line it prints is the `arcaeon verify`
  command that checks the record against its pins.

What it does not do: it does not say whether the memory is true, or who wrote
a file. It records what the folder held each time it ran; a change made and
undone between two runs leaves no row. The pin file sits next to the record,
under the same user, so it shows the mechanism works and catches a cut or an
edit made without care; it is not an outside party. For that, `arcaeon pin
--remote` hands the head to the hosted witness (paid, needs `ARCAEON_KEY`).

## What a shell agent had to type before (0.10.0)

Written down for plan item 4, step 1. On 0.10.0 the pip package has no verb
that reads a folder. The free parts that exist are `log`, `verify` and `pin
--witness`, so a shell agent had to build the record by hand, one shell at a
time. In a POSIX shell:

```sh
pip install arcaeon
find memory -type f | sort | while read -r f; do
  arcaeon log memory-record.jsonl --field file="$f" \
    --field sha256="$(sha256sum "$f" | cut -d' ' -f1)"
done
arcaeon verify memory-record.jsonl
arcaeon pin memory-record.jsonl --witness memory-pins.jsonl --ns memory
```

In PowerShell the loop is another script again (`Get-ChildItem -Recurse -File`
and `Get-FileHash`), and in cmd another. What that left the agent with:

- **Not safe to run twice.** Every run logs every file again, so the record
  grows with no change in the folder, and a removed file leaves no trace.
- **Several commands, and a choice at each one.** Where the record goes (often
  inside the memory folder, where the agent then reads it as memory), what to
  name the pin namespace, and to remember the pin step at all.
- **JSON to read.** `verify` and `pin` answer in JSON; a person watching the
  shell gets braces, not a sentence.
- **The MCP way is not a shell way.** `pip install "arcaeon[mcp]"` plus
  `arcaeon connect <client> --write` gives an agent the ledger tools, but it
  pulls in about 30 packages and needs a client that speaks MCP. `witness_pin`
  there is paid and needs `ARCAEON_KEY`.

From 0.11.0 all of that is `arcaeon start <memory folder>`.
