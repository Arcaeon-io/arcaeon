# Your first five minutes

Your AI agent did something while you were away. How would you know if its record of that was changed afterwards?

Arcaeon keeps that record and checks it. It came out of a 911 dispatch floor. There, the timeline of a call gets read long after the call ends. A record nobody can check is only a story.

You do not need to know the terminal for this page. You will paste a few lines, and each one says what it did.

In the boxes below, a line that starts with `$` is one to paste. Paste what comes after the `$`, not the `$` itself. The lines under it are what you should see. A line in `<...>` differs on every computer.

## What it cannot do

Read this part first. It is short.

- It does not tell you what your agent did was right. It tells you every row still hashes to the next, and, with a pin, that the rows up to the pinned head have not changed since the pin.
- Anyone who can write the file can still change it. What they cannot do is change it without the check naming the line.
- Cutting the newest lines off the end needs a pin to catch. The five minutes here make no pin.
- The full list is in [What it can and cannot prove](WHAT_IT_CAN_AND_CANNOT_PROVE.md).

## Minute one: run the installer

You need Python 3.10 or newer. On Windows, get it from python.org and keep "py launcher" ticked.

The installer is a short script you can read before you run it. It lands on the Arcaeon get page in the next release of the site. Until then, skip to "No installer yet" below. Once it is there, save it in any folder.

On Windows, open that folder. Hold Shift, right-click an empty spot, and pick "Open PowerShell window here". Paste this line first. It only prints the steps and changes nothing:

```console
$ powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1
arcaeon installer: dry run, nothing changes (add -Apply to run these steps)
<step 1: found the py launcher at ...>
step 2: py -m pip install --user "arcaeon[mcp]"
step 3: py -m arcaeon doctor
dry run done: nothing was installed, nothing was downloaded.
```

If those steps look right, paste this one. It installs Arcaeon for your user alone and runs a checkup:

```console
$ powershell -NoProfile -ExecutionPolicy Bypass -File install.ps1 -Apply
arcaeon installer: applying
step 2: py -m pip install --user "arcaeon[mcp]"
<pip installs arcaeon>
step 3: py -m arcaeon doctor
<one line per check>
```

On a Mac or on Linux, open Terminal in that folder and do the same:

```console
$ sh install.sh
arcaeon installer: dry run, nothing changes (add --apply to run these steps)
dry run done: nothing was installed, nothing was downloaded.
$ sh install.sh --apply
arcaeon installer: applying
<step 2: pipx or pip installs arcaeon>
<step 3: arcaeon doctor prints one line per check>
```

### No installer yet: the same two steps by hand

After it finds Python, the installer runs two lines. You can run them yourself today.

On Windows, open PowerShell. Paste these two lines, one at a time:

```console
py -m pip install --user "arcaeon[mcp]"
py -m arcaeon doctor
```

On a Mac or on Linux, open Terminal. Paste these four lines, one at a time:

```console
python3 -m venv ~/.venvs/arcaeon
. ~/.venvs/arcaeon/bin/activate
pip install "arcaeon[mcp]"
arcaeon doctor
```

The first line makes a folder that keeps Arcaeon apart from the rest of your computer. The second turns it on for this window. In a new window, paste the second line again first. If Linux answers the first line with "ensurepip is not available", paste the `apt install` line it prints. Then paste the first line again.

### On Windows, one change for the rest of this page

The pip step puts the `arcaeon` command in a folder Windows does not search. So Windows answers `arcaeon` with "not recognized". Wherever this page says `arcaeon`, type `py -m arcaeon` instead. The installer does the same.

## Minute two: watch it catch a change

This makes a tiny record in a scratch folder. Then it changes one word and checks again:

```console
$ arcaeon demo
Check the record: VERIFIED, 2 rows, every link holds.
Check the record again. The link on line 1 no longer fits:
BROKEN: line 1: chain mismatch
```

VERIFIED means every line checked out. BROKEN means a line was changed, and it names the line. The page [The words](WORDS.md) says what each answer means.

## Minute three: check this computer

The installer already ran this once. Run it again whenever something seems off:

```console
$ arcaeon doctor
every check was read (exit 0)
```

Each line is one check. A "no" is not an error. It says what is not set up yet.

## Minute four: open your dashboard

```console
$ arcaeon open
<your browser opens the dashboard on this computer>
```

The dashboard runs on your own computer only. Nothing on it is sent anywhere. If no browser opens, the window shows a link. Paste that link into your browser.

The window keeps the dashboard running while you look. When you are done, click the window and press Ctrl+C. That stops it.

## Minute five: ask your AI

First, tell your AI app where Arcaeon is. This line only shows what it would add, and to which file. It writes nothing:

```console
$ arcaeon connect claude-desktop
nothing written (add --write to apply)
```

If that looks right, this line adds it. It keeps a copy of the file first. `arcaeon connect claude-desktop --undo` puts the copy back:

```console
$ arcaeon connect claude-desktop --write
written
```

Run it twice and the second time says the entry is already there. The desktop app runs on Windows and Mac, so on Linux pick another app from the list below.

Other apps have their own names. This line shows them all:

```console
$ arcaeon connect --list
<one line per app, with the file it uses>
```

Quit the app fully, then open it again. It reads the file only when it starts. Then ask it, in plain words:

> check my agent log with arcaeon

It answers with one of the same words. COULD NOT LOOK means something could not be read. That is never a pass.
