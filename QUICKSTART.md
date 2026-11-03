# Quickstart: buy and your key

Every command is shown twice: first for bash (Linux, macOS, Git Bash), then
for PowerShell (Windows). Nothing here needs an account until the step that
sets `ARCAEON_KEY`.

## 1. Install

```bash
python3 -m pip install arcaeon
```

```powershell
py -m pip install arcaeon
```

Check it installed:

```bash
arcaeon version --short
```

```powershell
arcaeon version --short
```

## 2. See what is on sale

```bash
arcaeon buy
```

```powershell
arcaeon buy
```

`arcaeon buy` makes one request to arcaeon.io for the price list and prints
only the plans that list marks as on sale, each with its checkout link. A good
answer is kept for 10 minutes, so running it again inside that time makes no
request. If the request fails, or takes more than 3 seconds, it prints one
line naming the pricing page and nothing else. It opens no browser and takes
no card: you pay on the checkout page.

For one plan's checkout link, use a plan name from that list:

```bash
arcaeon buy <plan>
```

```powershell
arcaeon buy <plan>
```

## 3. Or ask for no request at all

With `ARCAEON_OFFERS_OFFLINE=1`, `arcaeon buy` makes no request and prints
only the pricing page line.

For one command:

```bash
ARCAEON_OFFERS_OFFLINE=1 arcaeon buy
```

```powershell
$env:ARCAEON_OFFERS_OFFLINE = "1"; arcaeon buy; Remove-Item Env:ARCAEON_OFFERS_OFFLINE
```

For the rest of this shell:

```bash
export ARCAEON_OFFERS_OFFLINE=1
```

```powershell
$env:ARCAEON_OFFERS_OFFLINE = "1"
```

## 4. Set your key

`ARCAEON_KEY` is the one setting the hosted verbs read. Treat it like a
password: anyone holding it can pin in your name. Type it at a hidden prompt
so it stays out of your shell history and off your screen. This sets it for
the current shell only.

```bash
read -rsp "ARCAEON_KEY: " ARCAEON_KEY && export ARCAEON_KEY && echo
```

```powershell
$env:ARCAEON_KEY = Read-Host -Prompt "ARCAEON_KEY" -MaskInput
```

`-MaskInput` needs PowerShell 7.1 or newer. On Windows PowerShell 5.1:

```powershell
$s = Read-Host -Prompt "ARCAEON_KEY" -AsSecureString; $env:ARCAEON_KEY = [System.Net.NetworkCredential]::new("", $s).Password; Remove-Variable s
```

## 5. Check the key

```bash
arcaeon credits
```

```powershell
arcaeon credits
```

It prints your key's balance as one sentence. Looking spends nothing. With
no key set it sends nothing and says so (exit 2); if the witness cannot be
reached it says COULD NOT LOOK (exit 3).

## 6. Forget the key

```bash
unset ARCAEON_KEY
```

```powershell
Remove-Item Env:ARCAEON_KEY
```

## Where to go next

- README.md, "The hosted door": every hosted verb and what it sends.
- docs/VERBS.md: each verb's usage and exit codes.
