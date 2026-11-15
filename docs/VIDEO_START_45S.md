# Video: one command for a sealed record of an agent's memory (45 seconds)

A screen recording of one terminal, with a voice over. It shows only what
`arcaeon start` does in 0.11.0: install, start, run again, a change, a cut
record. Every line on screen below is the command's real output, from a run
of this exact sequence; the long paths it prints are cropped in the edit.

Rules for the cut: no company or product names (the agent is "your agent"),
no dates or clocks on screen (hide the shell's clock, keep the prompt to `$`,
never open the record file itself, whose rows carry timestamps), and nothing
the package does not do in 0.11.0. Do not publish the video before 0.11.0 is
on PyPI: the install line asks for it.

## Setup before recording

- A clean user account with a generic name, and a folder `~/agent/memory`
  holding two files: `MEMORY.md` ("The user likes short answers.") and
  `notes/plan.md` ("Ship the front door first.").
- `arcaeon` not installed yet. A dark terminal, large font, prompt `$ `. Record on
  Linux: the `sed -i` in shot 5 is GNU sed.
- For shot 5, a variable set off camera: `R=$(echo ~/.arcaeon/memory/*)`.

## Script and shot list

| # | time | on screen | voice over |
|---|---|---|---|
| 1 | 0:00 to 0:05 | `$ ls memory` shows `MEMORY.md  notes`. | "Your agent keeps what it remembers in a folder. Change a file there, and nothing says so." |
| 2 | 0:05 to 0:13 | `$ pip install "arcaeon>=0.11.0"` (sped up), then `$ arcaeon start ./memory`. Hold on: `First look: 2 files. Written as row 1 and sealed.` | "One install. One command, pointed at the folder it already has. No key, no account." |
| 3 | 0:13 to 0:19 | `$ arcaeon start ./memory` again. Hold on: `No change since row 1: 2 files, the same as last time. Nothing written.` | "Run it again after every session. Nothing changed, nothing written. Safe to run twice." |
| 4 | 0:19 to 0:27 | `$ echo "The user likes long answers." > memory/MEMORY.md`, then `$ arcaeon start ./memory`. Hold on: `Changed since row 1: 1 changed. Written as row 2 and sealed.` and `changed: MEMORY.md`. | "When a file changes, it writes one row that names it, chained to the row before." |
| 5 | 0:27 to 0:37 | `$ sed -i '$d' "$R/record.jsonl"` (the last row cut off), then `$ arcaeon start ./memory`. Hold on: `BROKEN: rows were cut off the end of the record: it holds 1, its pin says 2` and `Nothing was added.` | "Cut a row out of that history, and the next run says BROKEN, and adds nothing on top." |
| 6 | 0:37 to 0:42 | Back up to the first run's last line, highlighted: `Anyone can check it: arcaeon verify ...`. | "Hand the record to anyone. One more command checks it." |
| 7 | 0:42 to 0:45 | End card, two lines: `pip install "arcaeon>=0.11.0"` and `arcaeon start ./memory`. Small line under them: "Shows what changed. Does not say the memory is true." | "arcaeon start. Point it at your agent's memory." |

About 95 words of voice over, an easy pace for 45 seconds.

## What the video must not claim

- That the record proves the memory is true, or who wrote a file. It records
  what the folder held each time the command ran.
- That the pin is an outside party. In this video the pin file sits next to
  the record on the same machine.
- That it watches the folder all the time. It looks when it is run.
