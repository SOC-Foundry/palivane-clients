<#
palivane-reenroll.ps1 — Windows-native (Python-free) Claude Code apiKeyHelper that
self-enrolls a per-device key. A PowerShell port of the `palivane-reenroll` script so a
Windows fleet doesn't need Python on PATH — Windows PowerShell 5.1 ships with the OS.

Same contract as the Python version: on each call it returns a live device key. It
validates the cached key and, if that key is gone (revoked/rotated), redeems the fleet
enrollment token for a fresh one — so a device self-heals within one apiKeyHelper TTL,
no admin action or re-push required.

Claude Code invokes this with no args and uses stdout as the credential, so stdout carries
ONLY the key; every diagnostic goes to stderr.

Config (first found wins), shape {"url","enroll_token","device"}:
    $env:PALIVANE_URL / $env:PALIVANE_ENROLL_TOKEN   (env overrides, device defaults to user@host)
    %USERPROFILE%\.palivane\enroll.json            (per-user)
    %PROGRAMDATA%\Palivane\enroll.json             (system-wide, written by the device installer)

    palivane-reenroll.ps1                   # print a live device key (apiKeyHelper mode)
    palivane-reenroll.ps1 -Refresh          # force a fresh enrollment, ignoring the cache
    palivane-reenroll.ps1 -Setup URL TOKEN  # write %USERPROFILE%\.palivane\enroll.json
#>
[CmdletBinding()]
param(
    [switch]$Refresh,
    [switch]$Setup,
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Rest
)

$ErrorActionPreference = "Stop"
# PS 5.1 can still default to a TLS the backend won't accept; pin TLS 1.2.
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

$UserCfg = Join-Path $env:USERPROFILE ".palivane\enroll.json"
$SysCfg  = if ($env:PROGRAMDATA) { Join-Path $env:PROGRAMDATA "Palivane\enroll.json" } else { "" }
$KeyCache = Join-Path $env:USERPROFILE ".palivane\device-key"
$TimeoutSec = 8

function Write-Log([string]$msg) { [Console]::Error.WriteLine("palivane-reenroll: $msg") }
function Die([string]$msg) { Write-Log $msg; exit 1 }

function Get-DeviceId {
    $user = if ($env:USERNAME) { $env:USERNAME } else { "user" }
    $host = if ($env:COMPUTERNAME) { $env:COMPUTERNAME } else { "device" }
    return "$user@$host"
}

function Load-Config {
    $cfg = $null
    foreach ($path in @($UserCfg, $SysCfg)) {
        if ($path -and (Test-Path -LiteralPath $path -PathType Leaf)) {
            try { $cfg = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json; break }
            catch { continue }
        }
    }
    $url = $env:PALIVANE_URL
    if (-not $url -and $cfg) { $url = $cfg.url }
    $url = ("$url").TrimEnd("/")
    $token = $env:PALIVANE_ENROLL_TOKEN
    if (-not $token -and $cfg) { $token = $cfg.enroll_token }
    $device = if ($cfg -and $cfg.device) { $cfg.device } else { Get-DeviceId }
    if (-not $url -or -not $token) {
        Die "no enrollment config (set PALIVANE_URL + PALIVANE_ENROLL_TOKEN, or write $UserCfg)."
    }
    return [pscustomobject]@{ url = $url; enroll_token = $token; device = $device }
}

function Read-CachedKey {
    if (Test-Path -LiteralPath $KeyCache -PathType Leaf) {
        try { return (Get-Content -LiteralPath $KeyCache -Raw).Trim() } catch { return "" }
    }
    return ""
}

function Write-CachedKey([string]$key) {
    $dir = Split-Path -Parent $KeyCache
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    Set-Content -LiteralPath $KeyCache -Value $key -NoNewline -Encoding ascii
    # Lock down to the current user (rough equivalent of chmod 600).
    try {
        $acl = Get-Acl -LiteralPath $KeyCache
        $acl.SetAccessRuleProtection($true, $false)
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
            "$env:USERDOMAIN\$env:USERNAME", "FullControl", "Allow")
        $acl.AddAccessRule($rule)
        Set-Acl -LiteralPath $KeyCache -AclObject $acl
    } catch {}
}

# True if $key still authenticates. On a network error, assume live (fail-safe: a transient
# blip shouldn't force a needless re-enroll / lock the dev out).
function Test-KeyLive([object]$cfg, [string]$key) {
    try {
        Invoke-WebRequest -Uri ($cfg.url + "/api/enroll/check") -Method Get `
            -Headers @{ "X-Palivane-Token" = $key; "User-Agent" = "palivane-reenroll/1.0" } `
            -TimeoutSec $TimeoutSec -UseBasicParsing | Out-Null
        return $true
    } catch {
        $code = $null
        try { $code = [int]$_.Exception.Response.StatusCode } catch {}
        if ($code -eq 401 -or $code -eq 403) { return $false }
        return $true
    }
}

function Invoke-Enroll([object]$cfg) {
    $body = @{ token = $cfg.enroll_token; device = $cfg.device } | ConvertTo-Json -Compress
    $resp = Invoke-RestMethod -Uri ($cfg.url + "/api/enroll") -Method Post `
        -ContentType "application/json" `
        -Headers @{ "User-Agent" = "palivane-reenroll/1.0" } `
        -Body $body -TimeoutSec $TimeoutSec
    $key = $resp.token
    if (-not $key) { Die "enrollment returned no key: $($resp | ConvertTo-Json -Compress)" }
    Write-CachedKey $key
    Write-Log "enrolled device $($cfg.device) (new device key cached)"
    return $key
}

function Resolve-Key([object]$cfg, [bool]$force) {
    if (-not $force) {
        $cached = Read-CachedKey
        if ($cached -and (Test-KeyLive $cfg $cached)) { return $cached }
    }
    return Invoke-Enroll $cfg
}

function Invoke-Setup([string]$url, [string]$token) {
    $dir = Split-Path -Parent $UserCfg
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    @{ url = $url.TrimEnd("/"); enroll_token = $token; device = (Get-DeviceId) } |
        ConvertTo-Json | Set-Content -LiteralPath $UserCfg -Encoding UTF8
    Write-Log "wrote $UserCfg"
}

# --- main ---
if ($Setup) {
    if (-not $Rest -or $Rest.Count -ne 2) { Die "usage: palivane-reenroll.ps1 -Setup URL ENROLL_TOKEN" }
    Invoke-Setup $Rest[0] $Rest[1]
    return
}

$cfg = Load-Config
try {
    $key = Resolve-Key $cfg ([bool]$Refresh)
} catch {
    # Network down: fall back to a cached key if we have one, so Claude Code keeps working
    # offline; only hard-fail when there's nothing cached to fall back to.
    $cached = Read-CachedKey
    if ($cached) { [Console]::Out.Write($cached); return }
    Die "cannot reach $($cfg.url): $($_.Exception.Message)"
}
[Console]::Out.Write($key)  # stdout = the credential (apiKeyHelper contract)
