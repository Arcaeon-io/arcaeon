# K146: fresh-venv read-back. Local only: builds the wheel from a copy of
# this checkout (no upload, no index), installs ONLY that wheel into a new
# venv in a temp dir, and runs the installed `arcaeon` the way a stranger
# would: `demo`, a `serve` smoke on loopback, `connect claude-desktop`
# (print only, nothing written), and an evidence pack build plus verify.
#
# Every step runs with PYTHONPATH cleared, ARCAEON_HOME and the connect home
# in the temp dir, and the working directory outside the repo, so a pass
# means the wheel works, not the checkout. Nothing touches the real home.
#
# Usage (Windows PowerShell 5.1 or pwsh):
#   powershell -NoProfile -ExecutionPolicy Bypass -File tools\fresh_venv_check.ps1
#   ... -Python "C:\path\to\python.exe"   (default: py)
#   ... -Keep                             (leave the temp dir for inspection)
#
# The last line is `fresh venv: all steps passed` (exit 0) or
# `fresh venv: FAILED at <step>` (exit 1).

param(
    [string]$Python = "py",
    [switch]$Keep
)

$ErrorActionPreference = "Stop"
$Repo = Split-Path -Parent $PSScriptRoot
$Work = Join-Path ([System.IO.Path]::GetTempPath()) ("arcaeon_fresh_venv_" + [guid]::NewGuid().ToString("N").Substring(0, 12))
New-Item -ItemType Directory -Path $Work | Out-Null
$script:Step = "setup"
$script:ServeProc = $null
$Saved = @{}
foreach ($k in @("PYTHONPATH", "ARCAEON_HOME", "ARCAEON_CONNECT_HOME", "ARCAEON_KEY", "HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")) {
    $Saved[$k] = [Environment]::GetEnvironmentVariable($k, "Process")
}

function Say([string]$msg) { Write-Output ("[" + $script:Step + "] " + $msg) }

function Fail([string]$why) {
    Say ("FAIL: " + $why)
    throw ("step failed: " + $script:Step)
}

function Quote([string]$a) {
    if ($a -match '[\s"]') { return '"' + ($a -replace '"', '\"') + '"' }
    return $a
}

# Runs an executable, waits, returns @{ code; out } with stdout and stderr joined.
function Run([string]$exe, [string[]]$argv, [int]$timeoutSec = 600) {
    $o = Join-Path $Work ("run_" + [guid]::NewGuid().ToString("N") + ".out")
    $e = $o + ".err"
    $argline = ($argv | ForEach-Object { Quote $_ }) -join " "
    $p = Start-Process -FilePath $exe -ArgumentList $argline -WorkingDirectory $Work -NoNewWindow -PassThru `
        -RedirectStandardOutput $o -RedirectStandardError $e
    $null = $p.Handle  # PowerShell 5.1 reports no ExitCode unless the handle is taken before exit
    if (-not $p.WaitForExit($timeoutSec * 1000)) {
        try { $p.Kill() } catch {}
        Fail ("timed out after " + $timeoutSec + " s: " + $exe + " " + $argline)
    }
    $p.WaitForExit()
    $text = ""
    if (Test-Path $o) { $text += [System.IO.File]::ReadAllText($o) }
    if (Test-Path $e) { $text += [System.IO.File]::ReadAllText($e) }
    return @{ code = $p.ExitCode; out = $text }
}

function Expect($r, [int]$code, [string]$what) {
    if ($r.code -ne $code) {
        Write-Output $r.out
        Fail ($what + ": exit " + $r.code + ", expected " + $code)
    }
}

# One loopback HTTP request; returns @{ status; body }. A 4xx is an answer,
# not an error: its status and body come back like a 200's.
function Http([string]$method, [string]$url, [string]$token, [string]$json) {
    $headers = @{}
    if ($token) { $headers["Authorization"] = "Bearer " + $token }
    $args2 = @{ UseBasicParsing = $true; Method = $method; Uri = $url; Headers = $headers; TimeoutSec = 30 }
    if ($json) { $args2["Body"] = [System.Text.Encoding]::UTF8.GetBytes($json); $args2["ContentType"] = "application/json" }
    try {
        $resp = Invoke-WebRequest @args2
        return @{ status = [int]$resp.StatusCode; body = [string]$resp.Content }
    }
    catch [System.Net.WebException] {
        $resp = $_.Exception.Response
        if ($null -eq $resp) { throw }
        $reader = New-Object System.IO.StreamReader($resp.GetResponseStream())
        $body = $reader.ReadToEnd(); $reader.Close()
        return @{ status = [int]$resp.StatusCode; body = $body }
    }
}

$ok = $false
try {
    # --- 1. wheel, built from a copy so the checkout gets no build/ or egg-info
    $script:Step = "wheel"
    $copy = Join-Path $Work "src_copy"
    New-Item -ItemType Directory -Path $copy | Out-Null
    foreach ($f in @("pyproject.toml", "README.md", "LICENSE", "MANIFEST.in")) {
        Copy-Item -LiteralPath (Join-Path $Repo $f) -Destination $copy
    }
    Copy-Item -LiteralPath (Join-Path $Repo "src") -Destination (Join-Path $copy "src") -Recurse
    Get-ChildItem -LiteralPath (Join-Path $copy "src") -Recurse -Directory -Filter "__pycache__" | Remove-Item -Recurse -Force
    Get-ChildItem -LiteralPath (Join-Path $copy "src") -Directory -Filter "*.egg-info" | Remove-Item -Recurse -Force
    $dist = Join-Path $Work "dist"
    $env:PYTHONPATH = $null
    $r = Run $Python @("-m", "pip", "wheel", $copy, "--no-deps", "--no-build-isolation", "--no-index", "-w", $dist)
    Expect $r 0 "pip wheel"
    $wheel = Get-ChildItem -LiteralPath $dist -Filter "arcaeon-*.whl" | Select-Object -First 1
    if ($null -eq $wheel) { Fail "no arcaeon wheel in dist" }
    Say ("built " + $wheel.Name)

    # --- 2. a fresh venv holding only that wheel
    $script:Step = "venv"
    $venv = Join-Path $Work "venv"
    $r = Run $Python @("-m", "venv", $venv)
    Expect $r 0 "venv"
    $vpy = Join-Path $venv "Scripts\python.exe"
    $exe = Join-Path $venv "Scripts\arcaeon.exe"
    $r = Run $vpy @("-m", "pip", "install", "--no-index", "--no-cache-dir", "--find-links", $dist, "arcaeon")
    Expect $r 0 "pip install"
    if (-not (Test-Path -LiteralPath $exe)) { Fail "the venv has no arcaeon.exe" }
    $r = Run $vpy @("-c", "import arcaeon, sys; print(arcaeon.__file__)")
    Expect $r 0 "import"
    if ($r.out -notlike ("*" + $venv + "*")) { Fail ("arcaeon imported from outside the venv: " + $r.out.Trim()) }
    Say ("installed into " + $venv)

    # the stranger's environment: temp homes, no PYTHONPATH, no key, no proxy
    $home1 = Join-Path $Work "arcaeon_home"
    $chome = Join-Path $Work "connect_home"
    New-Item -ItemType Directory -Path $home1, $chome | Out-Null
    $env:ARCAEON_HOME = $home1
    $env:ARCAEON_CONNECT_HOME = $chome
    foreach ($k in @("ARCAEON_KEY", "HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy")) {
        [Environment]::SetEnvironmentVariable($k, $null, "Process")
    }

    # --- 3. demo
    $script:Step = "demo"
    $r = Run $exe @("demo")
    Expect $r 0 "arcaeon demo"
    if ($r.out -notmatch "VERIFIED" -or $r.out -notmatch "BROKEN") { Write-Output $r.out; Fail "demo did not show VERIFIED then BROKEN" }
    Say "VERIFIED then BROKEN, exit 0"

    # --- 4. serve smoke on loopback
    $script:Step = "serve"
    $root = Join-Path $Work "served_root"
    New-Item -ItemType Directory -Path $root | Out-Null
    $r = Run $exe @("log", (Join-Path $root "calls.jsonl"), "--field", "tool=search", "--field", "query=weather")
    Expect $r 0 "arcaeon log"
    $r = Run $exe @("serve", "--host", "0.0.0.0", "--port", "0")
    Expect $r 2 "serve --host 0.0.0.0 refuses"
    $sout = Join-Path $Work "serve.out"
    $script:ServeProc = Start-Process -FilePath $exe -ArgumentList ("serve --port 0 --root " + (Quote $root)) `
        -WorkingDirectory $Work -NoNewWindow -PassThru -RedirectStandardOutput $sout -RedirectStandardError ($sout + ".err")
    $state = Join-Path $home1 "serve.json"
    $port = $null
    for ($i = 0; $i -lt 150 -and $null -eq $port; $i++) {
        if ($script:ServeProc.HasExited) { Fail ("serve exited early, code " + $script:ServeProc.ExitCode) }
        if (Test-Path -LiteralPath $state) {
            try { $port = (Get-Content -LiteralPath $state -Raw | ConvertFrom-Json).port } catch { $port = $null }
        }
        if ($null -eq $port) { Start-Sleep -Milliseconds 200 }
    }
    if ($null -eq $port) { Fail "serve.json never named a port" }
    $base = "http://127.0.0.1:" + $port
    $h = Http "GET" ($base + "/health") $null $null
    if ($h.status -ne 200 -or $h.body -notmatch '"ok":\s*true') { Fail ("/health: " + $h.status + " " + $h.body) }
    $n = Http "POST" ($base + "/v1/verify") $null '{"ledger": "calls.jsonl"}'
    if ($n.status -ne 401) { Fail ("no token should be 401, got " + $n.status) }
    $r = Run $exe @("serve", "--print-token")
    Expect $r 0 "serve --print-token"
    $token = $r.out.Trim()
    $v = Http "POST" ($base + "/v1/verify") $token '{"ledger": "calls.jsonl"}'
    if ($v.status -ne 200 -or $v.body -notmatch '"VERIFIED"' -or $v.body -notmatch '"exit":\s*0') {
        Fail ("verify with token: " + $v.status + " " + $v.body)
    }
    if ($v.body.Contains($token)) { Fail "the token appeared in a response body" }
    Stop-Process -Id $script:ServeProc.Id -Force
    $script:ServeProc = $null
    Say ("port " + $port + ": /health 200, no token 401, verify 200 VERIFIED exit 0, 0.0.0.0 refused")

    # --- 5. connect claude-desktop, print only
    $script:Step = "connect"
    $r = Run $exe @("connect", "claude-desktop")
    Expect $r 0 "connect claude-desktop"
    if ($r.out -notmatch "nothing written") { Write-Output $r.out; Fail "connect did not say nothing written" }
    $left = @(Get-ChildItem -LiteralPath $chome -Recurse -Force)
    if ($left.Count -ne 0) { Fail ("connect wrote into the home: " + ($left | ForEach-Object { $_.FullName }) -join ", ") }
    Say "printed, nothing written, the connect home is still empty"

    # --- 6. evidence pack build plus verify
    $script:Step = "evidence-pack"
    $ledger = Join-Path $Work "agent.jsonl"
    $r = Run $exe @("log", $ledger, "--field", "tool=search", "--field", "query=weather")
    Expect $r 0 "log row 1"
    $r = Run $exe @("log", $ledger, "--field", "tool=fetch", "--field", "url=local")
    Expect $r 0 "log row 2"
    $pack = Join-Path $Work "pack"
    $builtAt = (Get-Date).ToUniversalTime().AddMinutes(1).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $r = Run $exe @("evidence-pack", "--ledger", $ledger, "--out", $pack, "--zip", "--built-at", $builtAt)
    Expect $r 0 "evidence-pack build"
    $r = Run $exe @("evidence-pack", "verify", $pack)
    Expect $r 0 "evidence-pack verify (folder)"
    $r = Run $exe @("evidence-pack", "verify", ($pack + ".zip"))
    Expect $r 0 "evidence-pack verify (zip)"
    Say "built, folder verify exit 0, zip verify exit 0"

    $ok = $true
}
catch {
    if ($_.Exception.Message -notlike "step failed:*") { Say ("FAIL: " + $_.Exception.Message) }
}
finally {
    if ($null -ne $script:ServeProc) { try { Stop-Process -Id $script:ServeProc.Id -Force } catch {} }
    foreach ($k in $Saved.Keys) { [Environment]::SetEnvironmentVariable($k, $Saved[$k], "Process") }
    if ($Keep) { Write-Output ("kept: " + $Work) }
    else {
        Start-Sleep -Milliseconds 300
        try { Remove-Item -LiteralPath $Work -Recurse -Force } catch { Write-Output ("could not remove " + $Work) }
    }
}

if ($ok) {
    Write-Output "fresh venv: all steps passed"
    exit 0
}
Write-Output ("fresh venv: FAILED at " + $script:Step)
exit 1
