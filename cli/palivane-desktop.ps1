<#
palivane-desktop.ps1 — govern *desktop* AI apps (Claude/ChatGPT desktop, pinned IDE
assistants) and AI CLIs on Windows. The PowerShell port of `palivane-desktop` (bash), so a
Windows endpoint gets the same egress-governance plane with no admin rights and no Python.

It runs a LOCAL mitmproxy on 127.0.0.1:8081 with Palivane's addon, trusts its CA in the
*CurrentUser* Root store, and points the per-user WinINET proxy at it — so those apps'
traffic is inspected and (in enforce mode) blocked before it leaves. Reuses the per-user
token that `palivane connect` already stored, so no separate sign-in.

    powershell -ExecutionPolicy Bypass -File palivane-desktop.ps1 install            # desktop apps + CLIs
    powershell -ExecutionPolicy Bypass -File palivane-desktop.ps1 install -CliOnly   # CLIs only (Claude Code, Codex, Gemini)
    powershell -ExecutionPolicy Bypass -File palivane-desktop.ps1 uninstall          # remove proxy, CA trust, task, shims
    powershell -ExecutionPolicy Bypass -File palivane-desktop.ps1 status

Windows-specific notes (deliberate choices, mirrored from the bash version's posture):
  * Everything is PER-USER — no admin/UAC needed. The CA goes into the CurrentUser Root
    store (not LocalMachine; Windows shows a one-time security confirmation dialog for
    user-root installs — click Yes). The proxy is the WinINET *user* proxy
    (HKCU\...\Internet Settings), which browsers, Electron apps (Claude/ChatGPT desktop)
    and most native apps honor. Services and anything using WinHTTP
    (`netsh winhttp set proxy`) are NOT covered — push that via MDM if you need it
    (see docs/mdm-policy-pack.md).
  * The proxy persists as a per-user Scheduled Task (run at logon, hidden via a wscript
    launcher so no console window flashes). Scheduled tasks can't carry env vars, so a
    generated palivane-proxy.cmd sets PALIVANE_URL/PALIVANE_TOKEN/PALIVANE_PROXY_ENFORCE/
    PALIVANE_PROXY_USER and starts mitmdump.
  * AI CLIs (Claude Code, Codex, Gemini) are Node tools with their own HTTP client — they
    ignore the WinINET proxy AND the Windows cert store. They're captured via .cmd shims
    in %USERPROFILE%\.palivane\bin that set HTTPS_PROXY + NODE_EXTRA_CA_CERTS before the
    real tool starts (same trick as the bash wire_cli_capture). Shims are wired in BOTH
    modes; -CliOnly just skips the CA-store trust + system proxy.
  * mitmproxy installs as the self-contained Windows binary (bundles its own Python).
    Pin with $env:PALIVANE_MITM_VERSION.
  * The endpoint credential scan (`palivane-secrets`, secrets at rest) IS stdlib Python, and
    mitmproxy's bundled interpreter isn't callable, so it needs Python 3 on the box. When
    one is found the scan is installed as a second daily task (03:00) driven by a generated
    palivane-secrets.cmd; when none is found it's skipped with a message — never a scheduled
    task pointing at a binary that doesn't exist. On Windows the scanner reads NTFS ACLs
    via icacls (mode bits don't apply) and also sweeps %APPDATA%\gcloud, PowerShell
    history, Git Credential Manager, and .ppk/.pfx exports.

Config (env): PALIVANE_URL, PALIVANE_PROXY_PORT (8081), PALIVANE_PROXY_ENFORCE (false),
PALIVANE_MITM_VERSION, PALIVANE_CLI_TOOLS ("claude codex gemini"),
PALIVANE_SECRETS_ENGINE (trufflehog|gitleaks; default = built-in patterns).
Corporate-proxy chaining: PALIVANE_UPSTREAM_PROXY (http://corp:port; auto-adopts the
machine's WinINET/HTTPS_PROXY when unset), PALIVANE_UPSTREAM_CA, PALIVANE_UPSTREAM_AUTH,
PALIVANE_UPSTREAM_INSECURE.
PowerShell 5.1+ (ships with Windows 10/11); no modules beyond the in-box ones.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet("install", "uninstall", "status")]
    [string]$Command = "install",
    [switch]$CliOnly
)

$ErrorActionPreference = "Stop"
# PS 5.1 can still default to a TLS the download hosts won't accept; pin TLS 1.2.
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

$Port      = if ($env:PALIVANE_PROXY_PORT) { [int]$env:PALIVANE_PROXY_PORT } else { 8081 }
$HomeDir   = $env:USERPROFILE
$WDir      = Join-Path $HomeDir ".palivane"
$Addon     = Join-Path $WDir "palivane_addon.py"
$CA        = Join-Path $HomeDir ".mitmproxy\mitmproxy-ca-cert.pem"
$ShimDir   = Join-Path $WDir "bin"
# mitmproxy is installed here as a self-contained binary (bundles its own Python) so the
# install needs no system Python. Pin with PALIVANE_MITM_VERSION.
$MitmDir   = Join-Path $WDir "mitmproxy"
$MitmFallbackVersion = "12.2.3"   # used only if the latest-version lookup fails
# CLIs captured via a PATH shim — they use their own HTTP client and ignore the WinINET
# proxy + Windows cert store, so the user proxy alone never sees them.
$CliShimTools = if ($env:PALIVANE_CLI_TOOLS) { $env:PALIVANE_CLI_TOOLS -split "\s+" } else { @("claude", "codex", "gemini") }
$TaskName    = "PalivaneProxy"
$LauncherCmd = Join-Path $WDir "palivane-proxy.cmd"
$LauncherVbs = Join-Path $WDir "palivane-proxy.vbs"
# Endpoint credential scan (secrets at rest) — stdlib Python, so it needs an interpreter on
# the box (mitmproxy's bundled one isn't callable). Installed best-effort: no Python means
# the scan is skipped with a clear message, never a scheduled task pointing at nothing.
$SecretsTaskName = "PalivaneCredentialScan"
$SecretsScript   = Join-Path $WDir "palivane-secrets"
$SecretsCmd      = Join-Path $ShimDir "palivane-secrets.cmd"
$SecretsEngine   = if ($env:PALIVANE_SECRETS_ENGINE) { $env:PALIVANE_SECRETS_ENGINE } else { "" }
$InetKey     = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings"
$ShimMarker  = "palivane-desktop CLI capture shim"
# Corporate-proxy chaining. On a fleet behind a mandatory egress proxy (Zscaler/Netskope/
# corp SWG) mitmdump can't reach the internet directly — it must forward through that proxy.
# Set PALIVANE_UPSTREAM_PROXY=http://corp:port to run mitmdump in `--mode upstream:`; point
# PALIVANE_UPSTREAM_CA at the corp root bundle if it TLS-inspects. When unset, Invoke-Install
# auto-adopts the machine's existing WinINET / HTTPS_PROXY setting.
$UpstreamProxy    = $env:PALIVANE_UPSTREAM_PROXY
$UpstreamAuth     = $env:PALIVANE_UPSTREAM_AUTH
$UpstreamCA       = $env:PALIVANE_UPSTREAM_CA
$UpstreamInsecure = $env:PALIVANE_UPSTREAM_INSECURE

# Extra mitmdump flags for corporate-proxy chaining, appended to the launcher command line.
function Get-UpstreamArgs {
    if (-not $UpstreamProxy) { return "" }
    $a = " --mode upstream:$UpstreamProxy"
    if ($UpstreamAuth)     { $a += " --upstream-auth $UpstreamAuth" }
    if ($UpstreamCA)       { $a += ' --set "ssl_verify_upstream_trusted_ca=' + $UpstreamCA + '"' }
    if ($UpstreamInsecure) { $a += " --ssl-insecure" }
    return $a
}

function Log([string]$msg) { Write-Host "[palivane-desktop] $msg" -ForegroundColor Cyan }
function Die([string]$msg) { Write-Host "[palivane-desktop] $msg" -ForegroundColor Red; exit 1 }

# The per-user token + URL palivane-connect wrote into Claude Code's settings
# (~/.claude/settings.json, env block). Same source as the bash read_token.
function Read-PalivaneSettings {
    $f = Join-Path $HomeDir ".claude\settings.json"
    if (-not (Test-Path -LiteralPath $f -PathType Leaf)) {
        Die "No Palivane token found ($f is missing). Run 'palivane-connect' first, then re-run this."
    }
    try { $data = Get-Content -LiteralPath $f -Raw | ConvertFrom-Json }
    catch { Die "Could not parse $f — run 'palivane-connect' again, then re-run this." }
    $envBlock = $null
    if ($data -and $data.PSObject.Properties["env"]) { $envBlock = $data.env }
    $tok = ""; $url = ""; $user = ""
    if ($envBlock) {
        if ($envBlock.PSObject.Properties["PALIVANE_TOKEN"]) { $tok = "$($envBlock.PALIVANE_TOKEN)" }
        if (-not $tok -and $envBlock.PSObject.Properties["ANTHROPIC_AUTH_TOKEN"]) { $tok = "$($envBlock.ANTHROPIC_AUTH_TOKEN)" }
        if ($envBlock.PSObject.Properties["PALIVANE_URL"]) { $url = "$($envBlock.PALIVANE_URL)" }
        if ($envBlock.PSObject.Properties["PALIVANE_USER"]) { $user = "$($envBlock.PALIVANE_USER)" }
    }
    if (-not $tok) {
        Die "No Palivane token in $f. Run 'palivane-connect' first (browser sign-in), then re-run this."
    }
    if (-not $user) { $user = "$($env:USERNAME)@$($env:COMPUTERNAME)" }
    return [pscustomobject]@{ Token = $tok; Url = $url; User = $user }
}

# Effective backend URL: explicit env > what palivane-connect stored > the public default.
function Resolve-PalivaneUrl([object]$settings) {
    $url = $env:PALIVANE_URL
    if (-not $url -and $settings) { $url = $settings.Url }
    if (-not $url) { $url = "https://app.palivane.io" }
    return $url.TrimEnd("/")
}

# ---------- mitmproxy (self-contained Windows binary) ----------

# Latest published version (strip the leading v); PALIVANE_MITM_VERSION pins it, and a baked
# fallback keeps install working if GitHub is unreachable.
function Get-MitmVersion {
    if ($env:PALIVANE_MITM_VERSION) { return $env:PALIVANE_MITM_VERSION }
    try {
        $rel = Invoke-RestMethod -Uri "https://api.github.com/repos/mitmproxy/mitmproxy/releases/latest" `
            -Headers @{ "User-Agent" = "palivane-desktop/1.0" } -TimeoutSec 15 -UseBasicParsing
        $v = "$($rel.tag_name)" -replace "^v", ""
        if ($v -match "^[0-9][0-9.]*$") { return $v }
    } catch {}
    return $MitmFallbackVersion
}

function Get-Mitmdump {
    $exe = Join-Path $MitmDir "mitmdump.exe"
    if (Test-Path -LiteralPath $exe -PathType Leaf) { return $exe }
    if (Test-Path -LiteralPath $MitmDir) {
        # Some archive layouts nest the exes one level down.
        $found = Get-ChildItem -LiteralPath $MitmDir -Recurse -Filter "mitmdump.exe" -ErrorAction SilentlyContinue |
            Select-Object -First 1
        if ($found) { return $found.FullName }
    }
    $cmd = Get-Command "mitmdump.exe" -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

function Install-Mitm {
    $existing = Get-Mitmdump
    if ($existing) { return $existing }
    # mitmproxy only publishes windows-x86_64; on ARM64 Windows it runs via x64 emulation.
    $arch = "$env:PROCESSOR_ARCHITECTURE"
    if ($arch -eq "ARM64") { Log "note: ARM64 Windows — using the x86_64 mitmproxy build (runs under x64 emulation)." }
    elseif ($arch -ne "AMD64") { Die "unsupported architecture: $arch (mitmproxy ships windows-x86_64 only)." }
    $ver = Get-MitmVersion
    $url = "https://downloads.mitmproxy.org/$ver/mitmproxy-$ver-windows-x86_64.zip"
    Log "downloading mitmproxy $ver (windows-x86_64); no Python required..."
    New-Item -ItemType Directory -Force -Path $MitmDir | Out-Null
    $zip = Join-Path $env:TEMP "palivane-mitmproxy-$ver.zip"
    try {
        Invoke-WebRequest -Uri $url -OutFile $zip -TimeoutSec 600 -UseBasicParsing
        Expand-Archive -LiteralPath $zip -DestinationPath $MitmDir -Force
    } catch {
        Die "could not download/extract mitmproxy from $url ($($_.Exception.Message)); install it from https://mitmproxy.org/downloads/ into $MitmDir and re-run."
    } finally {
        Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
    }
    $exe = Get-Mitmdump
    if (-not $exe) { Die "mitmproxy extracted but mitmdump.exe was not found under $MitmDir." }
    return $exe
}

function Fetch-Addon([string]$palivaneUrl) {
    New-Item -ItemType Directory -Force -Path $WDir | Out-Null
    Log "fetching capture addon..."
    try {
        Invoke-WebRequest -Uri "$palivaneUrl/cli/palivane_addon.py" -OutFile $Addon -TimeoutSec 60 -UseBasicParsing
    } catch {
        Die "could not download palivane_addon.py from $palivaneUrl ($($_.Exception.Message))"
    }
}

# ---------- CA (generate + trust in the CurrentUser Root store) ----------

function Bootstrap-CA([string]$mitmdump) {
    if (Test-Path -LiteralPath $CA -PathType Leaf) { return }
    Log "generating mitmproxy CA (first run)..."
    $p = Start-Process -FilePath $mitmdump -ArgumentList @("-q", "--listen-port", "$Port") `
        -WindowStyle Hidden -PassThru
    try {
        for ($i = 0; $i -lt 20; $i++) {
            if (Test-Path -LiteralPath $CA -PathType Leaf) { break }
            Start-Sleep -Milliseconds 500
        }
    } finally {
        try { Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue } catch {}
    }
    if (-not (Test-Path -LiteralPath $CA -PathType Leaf)) { Die "mitmproxy CA was not generated at $CA" }
}

function Get-CACert {
    # X509Certificate2(file) on .NET Framework loads both DER and Base64/PEM certs.
    return New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($CA)
}

function Trust-CA {
    $cert = Get-CACert
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "CurrentUser")
    $store.Open("ReadWrite")
    try {
        $already = $store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
        if ($already) { Log "CA already trusted in the CurrentUser Root store."; return }
        Log "trusting the CA in the CurrentUser Root store (no admin needed)..."
        Log "Windows shows a one-time security confirmation for user-root CAs - click Yes."
        $store.Add($cert)   # user-consent dialog pops here
        $now = $store.Certificates | Where-Object { $_.Thumbprint -eq $cert.Thumbprint }
        if (-not $now) { Die "the CA was not added (did you decline the confirmation dialog?). Re-run and click Yes." }
    } finally { $store.Close() }
}

function Untrust-CA {
    $thumb = $null
    if (Test-Path -LiteralPath $CA -PathType Leaf) {
        try { $thumb = (Get-CACert).Thumbprint } catch {}
    }
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "CurrentUser")
    $store.Open("ReadWrite")
    try {
        # Match by thumbprint when the pem still exists; otherwise fall back to the
        # mitmproxy subject so uninstall works even after ~/.mitmproxy was deleted.
        $victims = $store.Certificates | Where-Object {
            ($thumb -and $_.Thumbprint -eq $thumb) -or
            (-not $thumb -and $_.Subject -match "mitmproxy")
        }
        foreach ($c in @($victims)) {
            $store.Remove($c)
            Log "removed CA $($c.Thumbprint) from the CurrentUser Root store."
        }
        if (-not $victims) { Log "no Palivane/mitmproxy CA found in the CurrentUser Root store." }
    } finally { $store.Close() }
}

function Test-CATrusted {
    $store = New-Object System.Security.Cryptography.X509Certificates.X509Store("Root", "CurrentUser")
    $store.Open("ReadOnly")
    try {
        if (Test-Path -LiteralPath $CA -PathType Leaf) {
            try {
                $thumb = (Get-CACert).Thumbprint
                return [bool]($store.Certificates | Where-Object { $_.Thumbprint -eq $thumb })
            } catch {}
        }
        return [bool]($store.Certificates | Where-Object { $_.Subject -match "mitmproxy" })
    } finally { $store.Close() }
}

# ---------- WinINET user proxy ----------

# Tell WinINET the proxy settings changed so running apps re-read them (otherwise the
# registry edit only applies to newly started processes).
function Refresh-WinInet {
    if (-not ("Palivane.WinInet" -as [type])) {
        Add-Type -Namespace Palivane -Name WinInet -MemberDefinition @'
[DllImport("wininet.dll", SetLastError = true)]
public static extern bool InternetSetOption(IntPtr hInternet, int dwOption, IntPtr lpBuffer, int dwBufferLength);
'@
    }
    [Palivane.WinInet]::InternetSetOption([IntPtr]::Zero, 39, [IntPtr]::Zero, 0) | Out-Null  # SETTINGS_CHANGED
    [Palivane.WinInet]::InternetSetOption([IntPtr]::Zero, 37, [IntPtr]::Zero, 0) | Out-Null  # REFRESH
}

function Set-UserProxy {
    Log "pointing the WinINET user proxy at 127.0.0.1:$Port (HKCU Internet Settings)..."
    Set-ItemProperty -Path $InetKey -Name ProxyServer -Value "127.0.0.1:$Port" -Type String
    Set-ItemProperty -Path $InetKey -Name ProxyOverride -Value "localhost;127.0.0.1;<local>" -Type String
    Set-ItemProperty -Path $InetKey -Name ProxyEnable -Value 1 -Type DWord
    Refresh-WinInet
}

function Unset-UserProxy {
    $cur = Get-ItemProperty -Path $InetKey -ErrorAction SilentlyContinue
    if ($cur -and $cur.PSObject.Properties["ProxyServer"] -and $cur.ProxyServer -eq "127.0.0.1:$Port") {
        # Only clear settings we set — an unrelated corporate proxy is left alone.
        Set-ItemProperty -Path $InetKey -Name ProxyEnable -Value 0 -Type DWord
        Remove-ItemProperty -Path $InetKey -Name ProxyServer -ErrorAction SilentlyContinue
        Remove-ItemProperty -Path $InetKey -Name ProxyOverride -ErrorAction SilentlyContinue
        Refresh-WinInet
        Log "WinINET user proxy removed."
    } elseif ($cur -and $cur.PSObject.Properties["ProxyServer"] -and $cur.ProxyServer) {
        Log "WinINET proxy is $($cur.ProxyServer) (not ours) — left untouched."
    }
}

# ---------- service persistence (per-user Scheduled Task) ----------

function Write-Launcher([string]$mitmdump, [string]$palivaneUrl, [string]$token, [string]$user) {
    # Honor an existing enforce stance, default to monitor — same as the bash units.
    $enforce = if ($env:PALIVANE_PROXY_ENFORCE) { $env:PALIVANE_PROXY_ENFORCE } else { "false" }
    # Scheduled tasks can't carry env vars, so a .cmd wrapper sets them. Contains the
    # per-user token — kept under the user profile, same posture as the systemd unit.
    $cmd = @(
        "@echo off",
        "rem Palivane desktop egress proxy launcher (auto-generated by palivane-desktop.ps1;",
        "rem 'palivane-desktop.ps1 uninstall' removes it).",
        "set ""PALIVANE_URL=$palivaneUrl""",
        "set ""PALIVANE_TOKEN=$token""",
        "set ""PALIVANE_PROXY_ENFORCE=$enforce""",
        "set ""PALIVANE_PROXY_USER=$user""",
        """$mitmdump"" -q -s ""$Addon"" --listen-port $Port$(Get-UpstreamArgs)"
    ) -join "`r`n"
    Set-Content -LiteralPath $LauncherCmd -Value $cmd -Encoding ascii
    # wscript launcher: runs the .cmd with window style 0, so no console window flashes
    # at logon (an interactive per-user task would otherwise pop a console).
    $vbs = "CreateObject(""WScript.Shell"").Run """"""$LauncherCmd"""""", 0, False"
    Set-Content -LiteralPath $LauncherVbs -Value $vbs -Encoding ascii
    return $enforce
}

function Start-ProxyTask {
    $action   = New-ScheduledTaskAction -Execute "wscript.exe" -Argument "//B ""$LauncherVbs"""
    $trigger  = New-ScheduledTaskTrigger -AtLogOn -User "$env:USERDOMAIN\$env:USERNAME"
    # ExecutionTimeLimit 0 = unlimited (the default 3-day cap would kill the proxy).
    $settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1)
    try {
        Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Settings $settings `
            -Description "Palivane desktop egress proxy (mitmdump + palivane_addon.py)" -Force | Out-Null
    } catch {
        Die "could not register the scheduled task '$TaskName': $($_.Exception.Message)"
    }
    # Stop a previous instance so a re-install picks up new config, then start fresh.
    try { Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue } catch {}
    Start-ScheduledTask -TaskName $TaskName
    Log "scheduled task '$TaskName' registered (runs at logon, hidden) and started."
    # Don't proceed to system-proxy changes until the proxy is actually accepting
    # connections — pointing WinINET at a dead port would break the user's browsing.
    for ($i = 0; $i -lt 30; $i++) {
        if (Test-ProxyListening) { return }
        Start-Sleep -Milliseconds 500
    }
    try { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    Die "the proxy never started listening on 127.0.0.1:$Port — removed the task; nothing else was changed. Check '$LauncherCmd' by running it in a terminal to see the error."
}

function Test-ProxyListening {
    try {
        return [bool](Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue)
    } catch {
        # Get-NetTCPConnection missing (stripped-down SKU) — fall back to a connect probe.
        try {
            $c = New-Object System.Net.Sockets.TcpClient
            $ok = $c.ConnectAsync("127.0.0.1", $Port).Wait(1000)
            $c.Close()
            return $ok
        } catch { return $false }
    }
}

function Remove-ProxyTask {
    # Both brand generations: "PalivaneProxy" is the pre-rebrand task name.
    foreach ($tn in @($TaskName, "PalivaneProxy")) {
        $t = Get-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue
        if ($t) {
            try { Stop-ScheduledTask -TaskName $tn -ErrorAction SilentlyContinue } catch {}
            Unregister-ScheduledTask -TaskName $tn -Confirm:$false
            Log "scheduled task '$tn' removed."
        }
    }
    # Best-effort: stop a still-running mitmdump we launched (ours runs from $MitmDir).
    Get-Process -Name "mitmdump" -ErrorAction SilentlyContinue | Where-Object {
        try { $_.Path -like "$MitmDir*" } catch { $false }
    } | ForEach-Object { try { Stop-Process -Id $_.Id -Force } catch {} }
    Remove-Item -LiteralPath $LauncherCmd, $LauncherVbs -Force -ErrorAction SilentlyContinue
}

# ---------- CLI capture shims (claude / codex / gemini) ----------

# Resolve the real executable for a tool, skipping our own shim dir so a shim never
# calls itself. Node CLIs land as .cmd (npm) — .ps1 launchers are skipped because a
# .cmd shim can't chain to them cleanly.
function Find-RealTool([string]$name) {
    $shimFull = $ShimDir.TrimEnd("\")
    foreach ($dir in ($env:Path -split ";")) {
        if (-not $dir) { continue }
        if ($dir.TrimEnd("\") -ieq $shimFull) { continue }
        foreach ($ext in @(".cmd", ".bat", ".exe")) {
            $cand = Join-Path $dir "$name$ext"
            if (Test-Path -LiteralPath $cand -PathType Leaf) { return $cand }
        }
    }
    return $null
}

# CLIs (Claude Code, Codex, Gemini) are Node/own-HTTP-client tools that ignore the
# WinINET proxy and Windows cert store — so the user proxy never captures them. Drop a
# PATH shim that sets HTTPS_PROXY + NODE_EXTRA_CA_CERTS *before* the tool starts
# (NODE_EXTRA_CA_CERTS is read once at Node startup), then chain to the real binary.
function Wire-CliCapture {
    New-Item -ItemType Directory -Force -Path $ShimDir | Out-Null
    Add-ShimDirToUserPath
    $wired = @()
    foreach ($name in $CliShimTools) {
        $real = Find-RealTool $name
        if (-not $real) { continue }
        $shim = Join-Path $ShimDir "$name.cmd"
        $body = @(
            "@echo off",
            "rem $ShimMarker (auto-generated; 'palivane-desktop.ps1 uninstall' removes it).",
            "set ""HTTPS_PROXY=http://127.0.0.1:$Port""",
            "set ""HTTP_PROXY=http://127.0.0.1:$Port""",
            "set ""NODE_EXTRA_CA_CERTS=$CA""",
            """$real"" %*"
        ) -join "`r`n"
        Set-Content -LiteralPath $shim -Value $body -Encoding ascii
        $wired += $name
    }
    if ($wired.Count -gt 0) {
        Log "CLI capture wired: $($wired -join ' ') (shims in $ShimDir -> 127.0.0.1:$Port)."
        Log "Open a NEW terminal for the shims (and PATH change) to take effect."
    } else {
        Log "no target CLIs found on PATH to wire (looked for: $($CliShimTools -join ' '))."
    }
}

function Add-ShimDirToUserPath {
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($userPath -and (($userPath -split ";") | Where-Object { $_.TrimEnd("\") -ieq $ShimDir.TrimEnd("\") })) { return }
    # Prepend so the shims win over the npm dir (both live in the user half of PATH).
    $newPath = if ($userPath) { "$ShimDir;$userPath" } else { $ShimDir }
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
    Log "added $ShimDir to the user PATH (new terminals pick it up)."
}

function Remove-ShimDirFromUserPath {
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if (-not $userPath) { return }
    $parts = ($userPath -split ";") | Where-Object { $_ -and ($_.TrimEnd("\") -ine $ShimDir.TrimEnd("\")) }
    [Environment]::SetEnvironmentVariable("Path", ($parts -join ";"), "User")
}

function Unwire-CliCapture {
    # Sweep the current shim dir AND the pre-rebrand one (.palivane\bin); match either
    # generation's marker so an old shim never survives an uninstall.
    $removed = @()
    foreach ($dir in @($ShimDir, (Join-Path $HomeDir ".palivane\bin"))) {
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        foreach ($name in $CliShimTools) {
            $shim = Join-Path $dir "$name.cmd"
            if ((Test-Path -LiteralPath $shim -PathType Leaf) -and
                (Select-String -LiteralPath $shim -Pattern "(palivane|palivane)-desktop CLI capture shim" -Quiet)) {
                Remove-Item -LiteralPath $shim -Force
                $removed += $name
            }
        }
    }
    if ($removed.Count -gt 0) { Log "removed CLI capture shims: $($removed -join ' ')" }
    Remove-ShimDirFromUserPath
}

function Get-ActiveShims {
    $active = @()
    foreach ($name in $CliShimTools) {
        $shim = Join-Path $ShimDir "$name.cmd"
        if ((Test-Path -LiteralPath $shim -PathType Leaf) -and
            (Select-String -LiteralPath $shim -Pattern $ShimMarker -Quiet)) {
            $active += $name
        }
    }
    return $active
}

# ---------- subcommands ----------

# ---------- endpoint credential scan (secrets at rest) ----------

function Find-Python {
    # `py -3` first (the official launcher), then python/python3 on PATH. Skip the WindowsApps
    # stub, which is a Store redirector that exits instead of running anything.
    $pyLauncher = Get-Command "py.exe" -ErrorAction SilentlyContinue
    if ($pyLauncher) {
        try {
            $v = & $pyLauncher.Source -3 -c "import sys;print(sys.version_info[0])" 2>$null
            if ($LASTEXITCODE -eq 0 -and "$v".Trim() -eq "3") {
                return [pscustomobject]@{ Exe = $pyLauncher.Source; Args = "-3" }
            }
        } catch {}
    }
    foreach ($name in @("python.exe", "python3.exe")) {
        foreach ($c in @(Get-Command $name -All -ErrorAction SilentlyContinue)) {
            if ($c.Source -like "*\WindowsApps\*") { continue }
            try {
                $v = & $c.Source -c "import sys;print(sys.version_info[0])" 2>$null
                if ($LASTEXITCODE -eq 0 -and "$v".Trim() -eq "3") {
                    return [pscustomobject]@{ Exe = $c.Source; Args = "" }
                }
            } catch {}
        }
    }
    return $null
}

function Install-SecretsScan([string]$palivaneUrl, [string]$token, [string]$user) {
    $py = Find-Python
    if (-not $py) {
        Log "credential scan skipped: no Python 3 found (it is a stdlib Python script)."
        Log "  Install Python 3 (winget install Python.Python.3.12) and re-run, or deploy a"
        Log "  packaged palivane-secrets.exe and point the MDM task at it."
        return
    }
    try {
        Invoke-WebRequest -Uri "$palivaneUrl/cli/palivane-secrets" -OutFile $SecretsScript `
            -TimeoutSec 60 -UseBasicParsing
    } catch {
        Log "credential scan skipped: could not download palivane-secrets ($($_.Exception.Message))."
        return
    }
    New-Item -ItemType Directory -Force -Path $ShimDir | Out-Null
    $engineArg = if ($SecretsEngine) { " --engine $SecretsEngine" } else { "" }
    $pyArgs = if ($py.Args) { "$($py.Args) " } else { "" }
    # Same launcher shape as the proxy: a .cmd carrying the env, so the scheduled task (and
    # the MDM-generated palivane-secrets-task.xml) can invoke one stable path.
    $cmd = @(
        "@echo off",
        "rem Palivane endpoint credential scan (auto-generated by palivane-desktop.ps1;",
        "rem 'palivane-desktop.ps1 uninstall' removes it).",
        "set ""PALIVANE_URL=$palivaneUrl""",
        "set ""PALIVANE_TOKEN=$token""",
        "set ""PALIVANE_USER=$user""",
        """$($py.Exe)"" $pyArgs""$SecretsScript""$engineArg %*"
    ) -join "`r`n"
    Set-Content -LiteralPath $SecretsCmd -Value $cmd -Encoding ascii

    $action  = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "/c """"$SecretsCmd"""""
    $trigger = New-ScheduledTaskTrigger -Daily -At 3am
    $settings = New-ScheduledTaskSettingsSet -Hidden -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries -StartWhenAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Hours 2)
    try {
        Register-ScheduledTask -TaskName $SecretsTaskName -Action $action -Trigger $trigger `
            -Settings $settings -Description "Palivane endpoint credential scan (secrets at rest)" `
            -Force | Out-Null
        Log "credential scan scheduled daily at 03:00 (task '$SecretsTaskName', via $($py.Exe))."
    } catch {
        Log "credential scan: could not register '$SecretsTaskName': $($_.Exception.Message)"
    }
}

function Remove-SecretsScan {
    # Both brand generations: "PalivaneCredentialScan" is the pre-rebrand task name.
    foreach ($tn in @($SecretsTaskName, "PalivaneCredentialScan")) {
        try { Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction SilentlyContinue } catch {}
    }
    foreach ($p in @($SecretsCmd, $SecretsScript)) {
        if (Test-Path -LiteralPath $p) { Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue }
    }
}

function Invoke-Install {
    $settings  = Read-PalivaneSettings
    $palivaneUrl = Resolve-PalivaneUrl $settings
    $mitmdump  = Install-Mitm
    Fetch-Addon $palivaneUrl
    Bootstrap-CA $mitmdump    # generates the CA (also the one NODE_EXTRA_CA_CERTS points at)
    if ($CliOnly) {
        Log "CLI-only mode: skipping CA-store trust + WinINET user proxy."
    } else {
        Trust-CA
    }
    # If the machine is already behind a corporate egress proxy and no explicit upstream was
    # set, adopt it — so a Zscaler/Netskope-configured device works out of the box. Prefer an
    # HTTPS_PROXY env var, else the WinINET user proxy (skip loopback = us from a prior run).
    if (-not $UpstreamProxy -and -not $CliOnly) {
        $amb = $env:HTTPS_PROXY; if (-not $amb) { $amb = $env:https_proxy }
        if (-not $amb) {
            try {
                $cur = Get-ItemProperty -Path $InetKey -ErrorAction SilentlyContinue
                if ($cur.ProxyEnable -eq 1 -and $cur.ProxyServer) { $amb = $cur.ProxyServer }
            } catch {}
        }
        # WinINET may store a per-protocol list ("http=h:p;https=h:p"); pull the https entry.
        if ($amb -match "https=([^;]+)") { $amb = $Matches[1] }
        if ($amb -and $amb -notmatch "127\.0\.0\.1|localhost|::1") {
            if ($amb -notmatch "^\w+://") { $amb = "http://$amb" }   # mitmproxy wants a URL
            $script:UpstreamProxy = $amb
            Log "detected an existing egress proxy ($amb) — chaining through it."
        }
    }
    if ($UpstreamProxy) {
        Log "chaining egress through upstream proxy: $UpstreamProxy$(if ($UpstreamCA) { " (trusting $UpstreamCA upstream)" })"
    }
    $enforce = Write-Launcher $mitmdump $palivaneUrl $settings.Token $settings.User
    Start-ProxyTask           # dies (and rolls the task back) if the proxy never comes up
    if (-not $CliOnly) { Set-UserProxy }   # only after the proxy is confirmed listening
    Wire-CliCapture           # both modes — Node CLIs ignore the WinINET proxy/cert store
    Install-SecretsScan $palivaneUrl $settings.Token $settings.User
    if ($CliOnly) {
        Log "done. CLIs ($($CliShimTools -join ' ')) now route through Palivane. Enforce mode: $enforce."
        Log "Verify: open a NEW terminal and run 'claude'; check findings in the console."
    } else {
        Log "done. Desktop AI apps + CLIs now route through Palivane. Enforce mode: $enforce."
        Log "Verify: CLIs work in a new terminal now; desktop apps (Claude/ChatGPT) pick up the"
        Log "        WinINET proxy on next launch — quit and reopen them."
    }
}

function Invoke-Uninstall {
    Unwire-CliCapture
    Unset-UserProxy
    Remove-ProxyTask
    Remove-SecretsScan
    Untrust-CA
    Log "stopped. (mitmproxy binaries and ~/.mitmproxy keys left under $WDir / $HomeDir\.mitmproxy;"
    Log "         delete them manually to fully revert.)"
}

function Invoke-Status {
    $t = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($t) {
        Write-Host "proxy task: $($t.State)"
    } else {
        Write-Host "proxy task: not installed"
    }
    if (Test-ProxyListening) {
        Write-Host "proxy port: listening on 127.0.0.1:$Port"
    } else {
        Write-Host "proxy port: NOT listening on 127.0.0.1:$Port"
    }
    $cur = Get-ItemProperty -Path $InetKey -ErrorAction SilentlyContinue
    $enable = 0; $server = ""
    if ($cur -and $cur.PSObject.Properties["ProxyEnable"]) { $enable = $cur.ProxyEnable }
    if ($cur -and $cur.PSObject.Properties["ProxyServer"]) { $server = $cur.ProxyServer }
    if ($enable -eq 1 -and $server -eq "127.0.0.1:$Port") {
        Write-Host "user proxy: enabled -> $server"
    } elseif ($enable -eq 1) {
        Write-Host "user proxy: enabled -> $server (not Palivane's)"
    } else {
        Write-Host "user proxy: disabled"
    }
    if (Test-CATrusted) {
        Write-Host "ca trust:   mitmproxy CA present in CurrentUser Root store"
    } else {
        Write-Host "ca trust:   not trusted"
    }
    $active = Get-ActiveShims
    if ($active.Count -gt 0) {
        Write-Host "cli shims:  $($active -join ' ')"
    } else {
        Write-Host "cli shims:  none"
    }
    $st = Get-ScheduledTask -TaskName $SecretsTaskName -ErrorAction SilentlyContinue
    if ($st) {
        $info = Get-ScheduledTaskInfo -TaskName $SecretsTaskName -ErrorAction SilentlyContinue
        $last = if ($info -and $info.LastRunTime) { $info.LastRunTime } else { "never" }
        Write-Host "cred scan:  $($st.State) (daily 03:00; last run: $last)"
    } else {
        Write-Host "cred scan:  not scheduled"
    }
}

switch ($Command) {
    "install"   { Invoke-Install }
    "uninstall" { Invoke-Uninstall }
    "status"    { Invoke-Status }
}
