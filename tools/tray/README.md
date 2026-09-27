# Tray stub (not packaged)

TODO(design-system): the tray icon, its menu and its colors come from the Claude Design system (navy #0C1828 / gold, C2 chevron mark) before any tray face ships. Nothing here is a design.

## What this is

A planned `arcaeon[desktop]` extra would put a small icon in the system tray. Clicking it opens the local dashboard, the same pages `arcaeon serve` already serves on 127.0.0.1. That click is exactly one command, `arcaeon open`, and `tray_stub.py` is that click written as a script so the behavior can be tried and tested before any native code exists.

```console
$ py tools/tray/tray_stub.py --dry-run
would run: <this python> -m arcaeon open
nothing was run (dry run)
```

Without `--dry-run` it runs `arcaeon open` and returns its exit code. `--no-browser` is passed through, so the link with its one-time code is printed instead of opened.

## What it is not

- Not in the wheel. It lives in `tools/`, which `MANIFEST.in` prunes and `packages.find` never reaches (`where = ["src"]`). `py tools/release_check.py --offline` prints the `surface tools not in wheel` line that confirms it.
- Not an extra yet. `arcaeon[desktop]` is planned, not declared in `pyproject.toml`. Declaring it is a later item, after the design pass. `dependencies = []` stays empty either way; a tray toolkit would be imported lazily inside the extra, never by the base package.
- No native app code. No icon is drawn, no GUI toolkit is imported, nothing is installed to start at login.
- No login and no account. The tray has no sign-in of its own. It reads nothing directly: every page it opens is read through the local server's token and fence, the same way the browser dashboard reads.

## What the tray face may show later

Only what the dashboard shows, and only from the local server:

- the status sentence from `GET /v1/status`, in the words from `arcaeon.words`;
- a dot for the last check, colored by `arcaeon.words.tone`: green only for a good verdict inside its freshness window, red for BROKEN, MISSING or ALTERED, grey for COULD NOT LOOK, no reading, or anything stale. COULD NOT LOOK is never green.

It must never show the token, the one-time code after it is used, file contents, full local paths, or anything from an account. The rules for every face are in `docs/design/HUD_TILES_SPEC.md`.
