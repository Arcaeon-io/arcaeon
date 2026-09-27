# Your first five minutes

Your AI agent did something while you were away. How would you know if its record of that was changed afterwards?

Arcaeon keeps that record and checks it. It came out of a 911 dispatch floor. There, the timeline of a call gets read long after the call ends. A record nobody can check is only a story.

You do not need to know the terminal for this page. You will paste a few lines, and each one says what it did.

## What it cannot do

Read this part first. It is short.

- It does not tell you what your agent did was right. It tells you the record was not changed after it was written.
- Anyone who can write the file can still change it. What they cannot do is change it without the check naming the line.
- Cutting the newest lines off the end needs a pin to catch. The five minutes here make no pin.
- The full list is in [What it can and cannot prove](WHAT_IT_CAN_AND_CANNOT_PROVE.md).

## Minute one: run the installer

You need Python 3.10 or newer. On Windows, get it from python.org and keep "py launcher" ticked.

The installer is a short script you can read before you run it. It lands on the Arcaeon get page in the next release of the site. Save it in any folder.

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

The dashboard runs on your own computer only. Nothing on it is sent anywhere.

## Minute five: ask your AI

First, tell your AI app where Arcaeon is. This prints the lines to add and the file they go in. It writes nothing:

```console
$ arcaeon connect claude-desktop
nothing written (add --write to apply)
```

Other apps have their own names. This line shows them all:

```console
$ arcaeon connect --list
<one line per app, with the file it uses>
```

Restart the app. Then ask it, in plain words:

> check my agent log with arcaeon

It answers with one of the same words. COULD NOT LOOK means something could not be read. That is never a pass.
